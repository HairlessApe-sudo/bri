"""Opt-in integration tests for the durable configuration repositories.

Set BRI_DURABLE_TEST_ADMIN_DSN and BRI_DURABLE_TEST_APP_DSN only for a fresh,
loopback disposable PostgreSQL database migrated through scripts/db/migrate.py.
"""
from __future__ import annotations

import os
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime, timezone
from threading import Barrier
from uuid import uuid4

import psycopg

from bri.access.policy import AccessGrant, Principal
from bri.api.configuration import build_trusted_request_context, tenant_connection_scope
from bri.api.database import Database
from bri.privacy.postgres import PostgresShieldConfigurationStore, PostgresSignatureConfigurationProvider, PostgresSignaturePackageStore, PostgresTenantSignatureStore
from bri.privacy.regional import (
    ManagedTenantSignature, PrivacyShieldConfigurationManager, RegionalSignatureRegistry,
    SignaturePackage, TenantSignatureManager,
)
from bri.prompts.management import PromptLayer, PromptManager, PromptVersion, PromptVersionConflict
from bri.prompts.postgres import PostgresPromptRepository

ADMIN_DSN = os.environ.get("BRI_DURABLE_TEST_ADMIN_DSN")
APP_DSN = os.environ.get("BRI_DURABLE_TEST_APP_DSN")


@unittest.skipUnless(ADMIN_DSN and APP_DSN, "requires explicitly configured disposable PostgreSQL")
class DurableRepositoryIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tenant_a = "durable-a-" + uuid4().hex[:12]
        self.tenant_b = "durable-b-" + uuid4().hex[:12]
        self.platform_principal_id = str(uuid4())
        self.platform_auth_user_id = str(uuid4())
        self.tenant_principal_id = str(uuid4())
        self.tenant_auth_user_id = str(uuid4())
        self.role_id = "a08-admin-" + uuid4().hex[:8]
        self.scope_id = "a08-scope-" + uuid4().hex[:8]
        self.package_id = "a08-package-" + uuid4().hex[:8]
        with psycopg.connect(ADMIN_DSN) as conn:
            for tenant in (self.tenant_a, self.tenant_b):
                conn.execute("INSERT INTO bri.tenants(tenant_id,display_name,sector) VALUES (%s,%s,'test')", (tenant, "Synthetic fixture"))
            conn.execute("INSERT INTO bri.auth_principals(principal_id,status) VALUES (%s,'active')", (self.platform_principal_id,))
            conn.execute("INSERT INTO bri.auth_identity_links(auth_user_id,principal_id,auth_issuer,auth_subject,provider_type,provider_issuer,provider_subject) VALUES (%s,%s,'https://synthetic.invalid/auth/v1',%s,'native','https://synthetic.invalid/auth/v1',%s)", (self.platform_auth_user_id,self.platform_principal_id,self.platform_auth_user_id,self.platform_auth_user_id))
            conn.execute("INSERT INTO bri.platform_superadmins(principal_id,status) VALUES (%s,'active')", (self.platform_principal_id,))
            conn.execute("INSERT INTO bri.auth_principals(principal_id,status) VALUES (%s,'active')", (self.tenant_principal_id,))
            conn.execute("INSERT INTO bri.auth_identity_links(auth_user_id,principal_id,auth_issuer,auth_subject,provider_type,provider_issuer,provider_subject) VALUES (%s,%s,'https://synthetic.invalid/auth/v1',%s,'native','https://synthetic.invalid/auth/v1',%s)", (self.tenant_auth_user_id,self.tenant_principal_id,self.tenant_auth_user_id,self.tenant_auth_user_id))
            conn.execute("INSERT INTO bri.auth_tenant_memberships(tenant_id,principal_id,membership_type,status) VALUES (%s,%s,'admin','active')", (self.tenant_a,self.tenant_principal_id))
            conn.execute("INSERT INTO bri.org_nodes(tenant_id,node_id,node_type,display_name) VALUES (%s,%s,'tenant','Synthetic scope')", (self.tenant_a,self.scope_id))
            conn.execute("INSERT INTO bri.app_roles(tenant_id,role_id,display_name) VALUES (%s,%s,'Synthetic Admin')", (self.tenant_a,self.role_id))
            for permission in ('prompt:client:read','prompt:client:manage','prompt:platform:read','privacy:configuration:read','privacy:configuration:manage','privacy:signature:manage'):
                conn.execute("INSERT INTO bri.role_permissions(tenant_id,role_id,permission) VALUES (%s,%s,%s)", (self.tenant_a,self.role_id,permission))
            conn.execute("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id,status) VALUES (%s,%s,%s,%s,'active')", (self.tenant_a,self.tenant_principal_id,self.role_id,self.scope_id))

    def tearDown(self):
        with psycopg.connect(ADMIN_DSN) as conn:
            conn.execute("DELETE FROM bri.signature_package_activation WHERE package_id=%s", (self.package_id,))
            conn.execute("DELETE FROM bri.signature_package_versions WHERE package_id=%s", (self.package_id,))
            conn.execute("DELETE FROM bri.configuration_audit_events WHERE actor_id=%s", (self.platform_principal_id,))
            conn.execute("DELETE FROM bri.prompt_active_versions WHERE layer='platform' AND version_id IN (SELECT version_id FROM bri.prompt_versions WHERE tenant_id IS NULL AND author_id=%s)", (self.platform_principal_id,))
            conn.execute("DELETE FROM bri.prompt_lifecycle_events WHERE tenant_id IS NULL AND actor_id=%s", (self.platform_principal_id,))
            conn.execute("DELETE FROM bri.prompt_versions WHERE tenant_id IS NULL AND author_id=%s", (self.platform_principal_id,))
            for table in ("prompt_active_versions", "prompt_lifecycle_events", "prompt_versions", "tenant_signature_revisions", "shield_config_revisions", "configuration_audit_events"):
                conn.execute(f"DELETE FROM bri.{table} WHERE tenant_id = ANY(%s)", ([self.tenant_a, self.tenant_b],))
            conn.execute("DELETE FROM bri.auth_role_assignments WHERE tenant_id=%s AND principal_id=%s", (self.tenant_a,self.tenant_principal_id))
            conn.execute("DELETE FROM bri.auth_tenant_memberships WHERE tenant_id=%s AND principal_id=%s", (self.tenant_a,self.tenant_principal_id))
            conn.execute("DELETE FROM bri.auth_tenant_memberships WHERE principal_id=%s", (self.platform_principal_id,))
            conn.execute("DELETE FROM bri.role_permissions WHERE tenant_id=%s AND role_id=%s", (self.tenant_a,self.role_id))
            conn.execute("DELETE FROM bri.app_roles WHERE tenant_id=%s AND role_id=%s", (self.tenant_a,self.role_id))
            conn.execute("DELETE FROM bri.org_nodes WHERE tenant_id=%s AND node_id=%s", (self.tenant_a,self.scope_id))
            conn.execute("DELETE FROM bri.auth_identity_links WHERE auth_user_id IN (%s,%s)", (self.platform_auth_user_id,self.tenant_auth_user_id))
            conn.execute("DELETE FROM bri.platform_superadmins WHERE principal_id=%s", (self.platform_principal_id,))
            conn.execute("DELETE FROM bri.auth_principals WHERE principal_id IN (%s,%s)", (self.platform_principal_id,self.tenant_principal_id))
            conn.execute("DELETE FROM bri.tenants WHERE tenant_id = ANY(%s)", ([self.tenant_a, self.tenant_b],))

    @contextmanager
    def _scope(self, tenant_id: str | None):
        with psycopg.connect(APP_DSN) as conn:
            auth_user_id = self.platform_auth_user_id if tenant_id is None else self.tenant_auth_user_id
            conn.execute("SELECT set_config('bri.auth_user_id',%s,true)", (auth_user_id,))
            if tenant_id is not None:
                conn.execute("SELECT set_config('bri.tenant_id',%s,true)", (tenant_id,))
            yield conn

    def _manager(self):
        repository = PostgresPromptRepository(self._scope)
        principal = Principal(self.tenant_principal_id, frozenset({self.tenant_a}), (
            AccessGrant(self.tenant_a, "prompt:client:read", self.tenant_a),
            AccessGrant(self.tenant_a, "prompt:client:manage", self.tenant_a),
            AccessGrant(self.tenant_a, "prompt:platform:read", self.tenant_a),
        ))
        return repository, PromptManager(repository, clock=lambda: datetime.now(timezone.utc)), principal

    def test_prompt_history_survives_repository_reinitialization_and_restore(self):
        repository, manager, principal = self._manager()
        first = manager.create_client_version(principal, self.tenant_a, "synthetic one", "first", expected_latest_version=0)
        manager.approve_client_version(principal, self.tenant_a, first.version)
        manager.activate_client_version(principal, self.tenant_a, first.version, expected_active_version=0)
        second = manager.create_client_version(principal, self.tenant_a, "synthetic two", "second", expected_latest_version=1)
        restored = manager.restore_client_version(principal, self.tenant_a, first.version, expected_latest_version=2)
        restarted = PostgresPromptRepository(self._scope)
        self.assertEqual([item.version for item in restarted.versions(PromptLayer.CLIENT, self.tenant_a)], [1, 2, 3])
        self.assertEqual(restarted.version(PromptLayer.CLIENT, self.tenant_a, 1), first)
        self.assertEqual(restored.content, first.content)
        self.assertEqual(restored.previous_version_ref, second.version_id)
        self.assertEqual(restored.restored_from_version_id, first.version_id)

    def test_concurrent_prompt_writers_use_atomic_compare_and_swap(self):
        _, manager, principal = self._manager()
        manager.create_client_version(principal, self.tenant_a, "synthetic base", "base", expected_latest_version=0)
        barrier = Barrier(2)
        def create(content):
            barrier.wait()
            try:
                return manager.create_client_version(principal, self.tenant_a, content, "parallel", expected_latest_version=1)
            except PromptVersionConflict:
                return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(create, ("synthetic concurrent a", "synthetic concurrent b")))
        self.assertEqual(sum(item is not None for item in results), 1)
        self.assertEqual(sum(item is None for item in results), 1)

    def test_failed_append_rolls_back_version_and_created_event(self):
        def failing_scope(tenant_id):
            @contextmanager
            def run():
                conn = psycopg.connect(APP_DSN)
                try:
                    conn.execute("SELECT set_config('bri.tenant_id',%s,true)", (tenant_id,))
                    yield conn
                    raise RuntimeError("synthetic_failure_after_writes")
                except BaseException:
                    conn.rollback()
                    raise
                finally:
                    conn.close()
            return run()
        value = PromptVersion(PromptLayer.CLIENT, self.tenant_a, 1, "rollback-"+uuid4().hex,
            "synthetic-admin", datetime.now(timezone.utc), "rollback test", None,
            "1"*64, "synthetic rollback prompt", None)
        with self.assertRaisesRegex(RuntimeError, "synthetic_failure_after_writes"):
            PostgresPromptRepository(failing_scope).append_version(value, 0)
        self.assertEqual(PostgresPromptRepository(self._scope).versions(PromptLayer.CLIENT, self.tenant_a), ())
        with self._scope(self.tenant_a) as conn:
            grants = conn.execute("SELECT has_table_privilege(current_user,'bri.prompt_versions','update'), has_table_privilege(current_user,'bri.prompt_versions','delete')").fetchone()
            self.assertEqual(grants, (False, False))

    def test_explicit_tenant_policy_assembles_both_active_prompt_layers(self):
        platform = Principal(self.platform_principal_id, frozenset(), (
            AccessGrant("brs-platform", "prompt:platform:manage", "platform-prompt"),
        ))
        platform_manager = PromptManager(PostgresPromptRepository(self._scope))
        platform_version = platform_manager.create_platform_version(platform, "synthetic platform", "initial", expected_latest_version=0)
        platform_manager.approve_platform_version(platform, platform_version.version)
        platform_manager.activate_platform_version(platform, platform_version.version, expected_active_version=0)
        repository, client_manager, tenant_admin = self._manager()
        client_version = client_manager.create_client_version(tenant_admin, self.tenant_a, "synthetic tenant", "initial", expected_latest_version=0)
        client_manager.approve_client_version(tenant_admin, self.tenant_a, client_version.version)
        client_manager.activate_client_version(tenant_admin, self.tenant_a, client_version.version, expected_active_version=0)
        assembled = client_manager.assemble(tenant_admin, self.tenant_a)
        self.assertEqual(assembled.provenance.platform_version_id, platform_version.version_id)
        self.assertEqual(assembled.provenance.client_version_id, client_version.version_id)
        self.assertEqual(tuple(section.content for section in assembled.sections), ("synthetic platform", "synthetic tenant"))

    def test_platform_configuration_is_superadmin_only_at_rls_boundary(self):
        platform = Principal(self.platform_principal_id, frozenset(), (
            AccessGrant("brs-platform", "prompt:platform:manage", "platform-prompt"),
        ))
        repository = PostgresPromptRepository(self._scope)
        manager = PromptManager(repository)
        manager.create_platform_version(platform, "synthetic platform rules", "initial", expected_latest_version=0)
        self.assertEqual(len(repository.versions(PromptLayer.PLATFORM, None)), 1)
        packages = PostgresSignaturePackageStore(self._scope)
        package = SignaturePackage(self.package_id, "1", "NZ")
        packages.append_version(package, None, actor_id=self.platform_principal_id, metadata={"synthetic": True})
        packages.activate(self.package_id, "1", None, actor_id=self.platform_principal_id)
        active_versions = packages.active_versions()
        self.assertEqual(active_versions[self.package_id], "1")
        self.assertEqual({active_versions[key] for key in ("global", "netherlands", "australia")}, {"1"})
        with self.assertRaisesRegex(RuntimeError, "signature_package_active_version_conflict"):
            packages.activate(self.package_id, "1", None, actor_id=self.platform_principal_id)
        self.assertEqual(packages.history(self.package_id), (package,))
        with self._scope(self.tenant_a) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM bri.prompt_versions WHERE layer='platform'").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM bri.signature_package_versions WHERE package_id=%s", (self.package_id,)).fetchone()[0], 1)
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                with conn.transaction():
                    conn.execute("INSERT INTO bri.signature_package_versions(package_id,version,jurisdiction) VALUES (%s,'2','NZ')", (self.package_id,))
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                with conn.transaction():
                    conn.execute("INSERT INTO bri.prompt_versions(layer,tenant_id,version,version_id,author_id,created_at,change_description,content_hash,content) VALUES ('platform',NULL,1,%s,'synthetic',now(),'denied',%s,'synthetic')", (uuid4().hex,"0"*64))

    def test_privacy_revisions_audit_metadata_and_rls_are_tenant_scoped(self):
        sig_store = PostgresTenantSignatureStore(self._scope)
        sig_mgr = TenantSignatureManager(sig_store)
        admin = Principal(self.tenant_principal_id, frozenset({self.tenant_a}), (
            AccessGrant(self.tenant_a, "privacy:signature:manage", self.tenant_a),
            AccessGrant(self.tenant_a, "privacy:configuration:manage", self.tenant_a),
        ))
        sig_mgr.create(admin, self.tenant_a, ManagedTenantSignature("synthetic-tag", "synthetic-pattern"))
        self.assertEqual(PostgresTenantSignatureStore(self._scope).current(self.tenant_a).version, 1)
        config_store = PostgresShieldConfigurationStore(self._scope)
        config_mgr = PrivacyShieldConfigurationManager(config_store)
        original = config_mgr.configure(admin, self.tenant_a, "NL")
        config_mgr.configure(admin, self.tenant_a, "NL", ("AU",))
        restored = config_mgr.restore(admin, self.tenant_a, original.version)
        self.assertEqual(restored.version, 3)
        self.assertEqual(PostgresShieldConfigurationStore(self._scope).current(self.tenant_a), restored)
        provider = PostgresSignatureConfigurationProvider(self._scope, RegionalSignatureRegistry.with_defaults())
        resolved = provider.load(self.tenant_a)
        self.assertIsNotNone(resolved)
        assert resolved is not None
        self.assertEqual(resolved.effective.tenant_signature_version, "1")
        self.assertEqual(resolved.effective.package_versions["netherlands"], "1")
        with self._scope(self.tenant_a) as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM bri.shield_config_revisions WHERE tenant_id=%s", (self.tenant_b,)).fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM bri.configuration_audit_events WHERE tenant_id=%s", (self.tenant_b,)).fetchone()[0], 0)
            audit_columns = {row[0] for row in conn.execute("SELECT column_name FROM information_schema.columns WHERE table_schema='bri' AND table_name='configuration_audit_events'").fetchall()}
            self.assertNotIn("content", audit_columns)
            self.assertNotIn("pattern", audit_columns)
    def test_authenticated_principal_requires_active_platform_superadmin_record(self):
        with psycopg.connect(ADMIN_DSN) as conn:
            conn.execute(
                "INSERT INTO bri.auth_tenant_memberships(tenant_id,principal_id,membership_type,status) "
                "VALUES (%s,%s,'platform_superadmin','active')",
                (self.tenant_a, self.platform_principal_id),
            )

        class DisposableDatabase(Database):
            def _connect(self):
                return psycopg.connect(APP_DSN)

        database = DisposableDatabase(
            "https://bwqdyibvuecgthtatrtv.supabase.co",
            "postgresql://bri_app@db.bwqdyibvuecgthtatrtv.supabase.co:5432/postgres",
        )
        active = database.resolve_authenticated_principal(
            self.platform_auth_user_id,
            "https://synthetic.invalid/auth/v1",
            self.platform_auth_user_id,
        )
        self.assertIsNotNone(active)
        assert active is not None
        self.assertTrue(active.platform_superadmin)
        self.assertEqual(active.tenant_ids, frozenset({self.tenant_a}))

        with psycopg.connect(ADMIN_DSN) as conn:
            conn.execute(
                "UPDATE bri.platform_superadmins SET status='suspended' WHERE principal_id=%s",
                (self.platform_principal_id,),
            )
        suspended = database.resolve_authenticated_principal(
            self.platform_auth_user_id,
            "https://synthetic.invalid/auth/v1",
            self.platform_auth_user_id,
        )
        self.assertIsNotNone(suspended)
        assert suspended is not None
        self.assertFalse(suspended.platform_superadmin)
        self.assertEqual(suspended.tenant_ids, frozenset())
        self.assertFalse(any(grant.tenant_id == "brs-platform" for grant in suspended.grants))

    def test_trusted_configuration_scope_binds_identity_tenant_and_read_only_mode(self):
        principal = Principal(
            "synthetic-admin",
            frozenset({self.tenant_a}),
            (AccessGrant(self.tenant_a, "prompt:client:read", self.tenant_a),),
            role_bindings=((self.tenant_a, "admin"),),
        )
        context = build_trusted_request_context(
            principal,
            request_id="synthetic-request-09",
            identity_source="synthetic",
            assurance_level="development-synthetic",
        )
        class DisposableDatabase(Database):
            def _connect(self):
                return psycopg.connect(APP_DSN)

        database = DisposableDatabase(
            "https://bwqdyibvuecgthtatrtv.supabase.co",
            "postgresql://bri_app@db.bwqdyibvuecgthtatrtv.supabase.co:5432/postgres",
        )
        scope = tenant_connection_scope(database, context, read_only=True)

        with scope(self.tenant_a) as conn:
            self.assertEqual(conn.execute("SELECT current_user").fetchone()[0], "bri_app")
            self.assertEqual(conn.execute("SELECT current_setting('bri.tenant_id',true)").fetchone()[0], self.tenant_a)
            self.assertEqual(conn.execute("SELECT current_setting('bri.synthetic_principal_id',true)").fetchone()[0], "synthetic-admin")
            self.assertEqual(conn.execute("SELECT current_setting('transaction_read_only')").fetchone()[0], "on")
            self.assertEqual(conn.execute("SELECT tenant_id FROM bri.tenants ORDER BY tenant_id").fetchall(), [(self.tenant_a,)])

        with self.assertRaisesRegex(PermissionError, "configuration_tenant_scope_mismatch"):
            with scope(self.tenant_b):
                self.fail("a repository could not enter another tenant's scope")


if __name__ == "__main__":
    unittest.main()
