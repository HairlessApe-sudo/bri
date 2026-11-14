from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MIGRATION_PATH = ROOT / "db/migrations/0006_auth_identity_and_sessions.sql"
PROTECTED_TABLES = (
    "auth_principals",
    "auth_identity_links",
    "auth_tenant_memberships",
    "auth_role_assignments",
    "platform_superadmins",
    "tenant_admin_policies",
)


class IdentityMigrationTests(unittest.TestCase):
    def test_migration_defines_provider_independent_principals_and_tenant_governance(self) -> None:
        self.assertTrue(MIGRATION_PATH.is_file(), "identity migration must be added")
        sql = " ".join(MIGRATION_PATH.read_text(encoding="utf-8").lower().split())
        for table in (*PROTECTED_TABLES, "auth_sessions", "security_audit_events"):
            with self.subTest(table=table):
                self.assertIn(f"create table bri.{table}", sql)
        self.assertRegex(sql, r"unique\s*\(\s*auth_issuer\s*,\s*auth_subject\s*\)")
        self.assertRegex(sql, r"unique\s*\(\s*provider_issuer\s*,\s*provider_subject\s*\)")
        self.assertIn("membership_type in ('user', 'superuser', 'admin', 'platform_superadmin')", sql)
        self.assertIn(
            "create unique index auth_one_client_org_per_principal "
            "on bri.auth_tenant_memberships (principal_id) "
            "where membership_type in ('user', 'superuser', 'admin')",
            sql,
        )
        self.assertIn("provider_issuer = auth_issuer", sql)
        self.assertIn("provider_subject = auth_subject", sql)
        self.assertIn("create trigger platform_superadmin_membership_requires_grant", sql)
        self.assertIn("membership_type <> 'platform_superadmin'", sql)
        self.assertIn("from bri.platform_superadmins s", sql)
        self.assertIn("min_emergency_admins integer not null default 2", sql)
        self.assertIn("max_client_admins integer", sql)

    def test_identity_tables_force_rls_and_application_cannot_assign_roles(self) -> None:
        self.assertTrue(MIGRATION_PATH.is_file(), "identity migration must be added")
        sql = " ".join(MIGRATION_PATH.read_text(encoding="utf-8").lower().split())
        identity_tables = (*PROTECTED_TABLES, "auth_sessions", "security_audit_events")
        loop_start = sql.index("foreach table_name in array array[")
        loop_end = sql.index("] loop execute format", loop_start)
        rls_tables = sql[loop_start:loop_end]
        self.assertIn("execute format('alter table bri.%i enable row level security', table_name)", sql)
        self.assertIn("execute format('alter table bri.%i force row level security', table_name)", sql)
        for table in identity_tables:
            with self.subTest(table=table):
                self.assertIn(f"'{table}'", rls_tables)
        for table in PROTECTED_TABLES:
            with self.subTest(table=table):
                self.assertIn(f"grant select on bri.{table} to bri_app", sql)
                self.assertNotRegex(sql, rf"grant (?:insert|update|delete|all).*bri\.{table}.*to bri_app")

    def test_memberships_and_role_assignments_use_composite_tenant_foreign_keys(self) -> None:
        self.assertTrue(MIGRATION_PATH.is_file(), "identity migration must be added")
        sql = " ".join(MIGRATION_PATH.read_text(encoding="utf-8").lower().split())
        self.assertIn("foreign key (tenant_id, principal_id) references bri.auth_tenant_memberships (tenant_id, principal_id)", sql)
        self.assertIn("foreign key (tenant_id, role_id) references bri.app_roles (tenant_id, role_id)", sql)
        self.assertIn("foreign key (tenant_id, scope_node_id) references bri.org_nodes (tenant_id, node_id)", sql)
        self.assertIn("tenant_id = nullif(current_setting('bri.tenant_id', true)", sql)
        self.assertIn("from bri.auth_tenant_memberships m where m.tenant_id = bri.auth_role_assignments.tenant_id", sql)
        self.assertIn("m.principal_id = bri.auth_role_assignments.principal_id", sql)

    def test_tenant_governance_seed_uses_temporary_migration_read_policy(self) -> None:
        sql = " ".join(MIGRATION_PATH.read_text(encoding="utf-8").lower().split())
        create_policy = sql.index(
            "create policy migration_seed_tenant_admin_policies on bri.tenants "
            "for select to bri_migrator using (true)"
        )
        seed = sql.index("insert into bri.tenant_admin_policies (tenant_id)")
        drop_policy = sql.index(
            "drop policy migration_seed_tenant_admin_policies on bri.tenants"
        )
        self.assertLess(create_policy, seed)
        self.assertLess(seed, drop_policy)

    def test_session_expiration_is_database_generated_and_cannot_be_extended_by_bri_app(self) -> None:
        self.assertTrue(MIGRATION_PATH.is_file(), "identity migration must be added")
        sql = " ".join(MIGRATION_PATH.read_text(encoding="utf-8").lower().split())
        self.assertRegex(sql, r"expires_at timestamptz not null default \(now\(\) \+ interval '8 hours'\)")
        self.assertIn("grant insert (auth_user_id, principal_id, session_id) on bri.auth_sessions to bri_app", sql)
        self.assertIn("grant update (revoked_at) on bri.auth_sessions to bri_app", sql)
        self.assertIn("create trigger auth_session_revocation_is_one_way", sql)

    def test_audit_authorization_uses_permission_rows_not_membership_role_names(self) -> None:
        sql = " ".join(MIGRATION_PATH.read_text(encoding="utf-8").lower().split())
        insert_policy = sql[sql.index("create policy security_audit_self_insert"):sql.index("create policy security_audit_admin_read")]
        read_policy = sql[sql.index("create policy security_audit_admin_read"):sql.index("revoke all on bri.auth_principals")]
        self.assertIn("rp.permission = 'security:audit:write'", insert_policy)
        self.assertIn("rp.permission = 'security:audit:read'", read_policy)
        self.assertNotIn("membership_type", insert_policy + read_policy)

    def test_runner_owns_atomic_transaction_and_checksum_ledger(self) -> None:
        self.assertTrue(MIGRATION_PATH.is_file(), "identity migration must be added")
        sql = " ".join(MIGRATION_PATH.read_text(encoding="utf-8").lower().split())
        self.assertNotRegex(sql, r"(^|\s)begin\s*;")
        self.assertNotRegex(sql, r"(^|\s)commit\s*;")
        self.assertNotIn("insert into bri.schema_migrations", sql)

    def test_security_audit_is_secret_free_and_immutable_to_runtime_role(self) -> None:
        self.assertTrue(MIGRATION_PATH.is_file(), "identity migration must be added")
        sql = " ".join(MIGRATION_PATH.read_text(encoding="utf-8").lower().split())
        self.assertNotRegex(sql, r"create table bri\.security_audit_events\s*\([^)]*\b(password|token|secret|payload|details)\b")
        self.assertIn("grant select on bri.security_audit_events to bri_app", sql)
        self.assertRegex(
            sql,
            r"grant insert\s*\(\s*tenant_id,\s*actor_principal_id,\s*subject_principal_id,\s*"
            r"event_type,\s*outcome,\s*request_id\s*\)\s*on bri\.security_audit_events to bri_app",
        )
        self.assertNotIn("grant select, insert on bri.security_audit_events to bri_app", sql)
        self.assertNotIn("grant update on bri.security_audit_events to bri_app", sql)
        self.assertNotIn("grant delete on bri.security_audit_events to bri_app", sql)


if __name__ == "__main__":
    unittest.main()
