from __future__ import annotations

from contextlib import contextmanager
from typing import Any, cast
import unittest

from fastapi import FastAPI
from fastapi.testclient import TestClient

from bri.access.policy import AccessGrant, Principal
from bri.api.app import ApiSettings, create_app
from bri.api.configuration import (
    ConfigurationServices,
    TrustedRequestContext,
    build_trusted_request_context,
    create_configuration_router,
    tenant_connection_scope,
)
from bri.api.catalog import load_catalog
from bri.api.database import TenantSession
from bri.privacy.models import DetectionCategory
from bri.privacy.regional import (
    InMemoryShieldConfigurationStore,
    InMemoryTenantSignatureStore,
    ManagedTenantSignature,
    MappingSignatureConfigurationProvider,
    PrivacyShieldConfigurationManager,
    RegionalSignatureRegistry,
    TenantSignatureManager,
)
from bri.prompts.management import InMemoryPromptRepository, PromptManager


class ConfigurationApiAuthenticationTests(unittest.TestCase):
    def test_user_cannot_gain_configuration_access_from_client_role_header(self) -> None:
        app = create_app(
            settings=ApiSettings(environment="development", dev_auth_enabled=True),
            database=cast(Any, object()),
        )
        response = TestClient(app, client=("127.0.0.1", 51000)).post(
            "/v1/configuration/prompts/versions",
            headers={
                "X-Dev-Identity": "user-noordlicht-reader",
                "X-Role": "Admin",
                "X-Principal-ID": "user-noordlicht-admin",
                "X-User-ID": "user-noordlicht-admin",
            },
            json={
                "content": "synthetic unauthorized prompt",
                "change_description": "must be denied",
                "expected_latest_version": 0,
            },
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()["detail"], "Configuration permission denied")

    def test_client_tenant_header_is_rejected_not_used_as_authority(self) -> None:
        app = create_app(
            settings=ApiSettings(environment="development", dev_auth_enabled=True),
            database=cast(Any, object()),
        )
        response = TestClient(app, client=("127.0.0.1", 51000)).get(
            "/v1/configuration/prompts/active",
            headers={
                "X-Dev-Identity": "user-noordlicht-admin",
                "X-Tenant-ID": "tenant-synth-zilvermeer",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "Tenant selection is server-controlled")

    def test_configuration_endpoint_rejects_unauthenticated_request(self) -> None:
        app = create_app(
            settings=ApiSettings(environment="development", dev_auth_enabled=True),
            database=cast(Any, object()),
        )
        response = TestClient(app, client=("127.0.0.1", 51000)).get(
            "/v1/configuration/prompts/active"
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["detail"], "A synthetic development identity is required")

    def test_role_ceiling_removes_configuration_grants_from_user_context(self) -> None:
        principal = Principal(
            subject_id="synthetic-user",
            tenant_ids=frozenset({"tenant-synth-noordlicht"}),
            grants=(AccessGrant("tenant-synth-noordlicht", "prompt:client:manage", "tenant-synth-noordlicht"),),
            role_bindings=(("tenant-synth-noordlicht", "user"),),
        )
        context = build_trusted_request_context(
            principal,
            request_id="req-1",
            identity_source="synthetic",
            assurance_level="development-synthetic",
        )
        self.assertEqual(context.effective_role, "user")
        self.assertNotIn("prompt:client:manage", context.permissions)
        self.assertEqual(context.principal.grants, ())

    def test_remote_configuration_mutation_is_disabled_before_production_auth_is_approved(self) -> None:
        tenant = "tenant-synth-noordlicht"
        principal = Principal(
            subject_id="principal-remote",
            tenant_ids=frozenset({tenant}),
            grants=(AccessGrant(tenant, "prompt:client:manage", tenant),),
            role_bindings=((tenant, "admin"),),
        )
        context = build_trusted_request_context(
            principal,
            request_id="request-remote",
            identity_source="supabase",
            auth_user_id="00000000-0000-0000-0000-000000000001",
            session_id="00000000-0000-0000-0000-000000000002",
            assurance_level="aal2",
            assurance_methods=("totp",),
        )
        app = FastAPI()
        app.include_router(create_configuration_router(
            context_dependency=lambda: context,
            database=cast(Any, object()),
            services_factory=lambda _context, _write: self.fail("remote mutation must not reach services"),
        ))
        response = TestClient(app).post(
            "/v1/configuration/prompts/versions",
            json={
                "content": "remote write attempt",
                "change_description": "should remain unavailable",
                "expected_latest_version": 0,
            },
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.json()["detail"],
            "Configuration writes require the local development identity mechanism",
        )

    def test_remote_context_requires_verified_aal2_and_carries_session_assurance(self) -> None:
        tenant = "tenant-synth-noordlicht"
        principal = Principal(
            subject_id="principal-1",
            tenant_ids=frozenset({tenant}),
            grants=(AccessGrant(tenant, "prompt:client:manage", tenant),),
            role_bindings=((tenant, "admin"),),
        )
        context = build_trusted_request_context(
            principal,
            request_id="request-123",
            identity_source="supabase",
            auth_user_id="00000000-0000-0000-0000-000000000001",
            session_id="00000000-0000-0000-0000-000000000002",
            assurance_level="aal2",
            assurance_methods=("totp",),
        )
        self.assertEqual(context.tenant_id, tenant)
        self.assertEqual(context.auth_user_id, "00000000-0000-0000-0000-000000000001")
        self.assertEqual(context.session_id, "00000000-0000-0000-0000-000000000002")
        self.assertEqual(context.assurance_methods, ("totp",))
        with self.assertRaisesRegex(ValueError, "verified_authentication_context_required"):
            build_trusted_request_context(
                principal,
                request_id="request-123",
                identity_source="supabase",
                auth_user_id="00000000-0000-0000-0000-000000000001",
                session_id=None,
                assurance_level="aal1",
            )

    def test_platform_superadmin_gets_platform_permissions_but_tenant_admin_does_not(self) -> None:
        tenant = "tenant-synth-noordlicht"
        platform_grants = (
            AccessGrant("brs-platform", "prompt:platform:manage", "platform-prompt"),
            AccessGrant("brs-platform", "signature_package:manage", "platform-signature-packages"),
        )
        superadmin = Principal(
            subject_id="platform-admin",
            tenant_ids=frozenset({tenant}),
            grants=platform_grants,
            role_bindings=((tenant, "platform_superadmin"),),
            platform_superadmin=True,
        )
        context = build_trusted_request_context(
            superadmin,
            request_id="request-platform",
            identity_source="synthetic",
            assurance_level="development-synthetic",
        )
        self.assertEqual(context.effective_role, "platform_superadmin")
        self.assertIn("prompt:platform:manage", context.permissions)
        self.assertIn("signature_package:manage", context.permissions)

        client_admin = Principal(
            subject_id="tenant-admin",
            tenant_ids=frozenset({tenant}),
            grants=platform_grants + (
                AccessGrant(tenant, "platform:prompt:tenant:manage", tenant),
            ),
            role_bindings=((tenant, "admin"),),
        )
        restricted = build_trusted_request_context(
            client_admin,
            request_id="request-client-admin",
            identity_source="synthetic",
            assurance_level="development-synthetic",
        )
        self.assertNotIn("prompt:platform:manage", restricted.permissions)
        self.assertNotIn("platform:prompt:tenant:manage", restricted.permissions)
        self.assertNotIn("signature_package:manage", restricted.permissions)

        unverified_superadmin = Principal(
            subject_id="stale-platform-admin",
            tenant_ids=frozenset({tenant}),
            grants=(
                AccessGrant("brs-platform", "prompt:platform:manage", "platform-prompt"),
                AccessGrant(tenant, "platform:prompt:tenant:manage", tenant),
            ),
            role_bindings=((tenant, "platform_superadmin"),),
            platform_superadmin=False,
        )
        stale_context = build_trusted_request_context(
            unverified_superadmin,
            request_id="request-stale-platform-admin",
            identity_source="synthetic",
            assurance_level="development-synthetic",
        )
        self.assertNotEqual(stale_context.effective_role, "platform_superadmin")
        self.assertNotIn("prompt:platform:manage", stale_context.permissions)
        self.assertNotIn("platform:prompt:tenant:manage", stale_context.permissions)

    def test_database_scope_uses_only_trusted_tenant_context(self) -> None:
        tenant = "tenant-synth-noordlicht"
        principal = load_catalog().principals["user-noordlicht-admin"]
        context = build_trusted_request_context(
            principal,
            request_id="request-456",
            identity_source="synthetic",
            assurance_level="development-synthetic",
        )

        class ScopeDatabase:
            def __init__(self) -> None:
                self.calls: list[tuple[str, str | None, str | None, bool]] = []
                self.connection = object()

            @contextmanager
            def configuration_context(
                self,
                tenant_id: str,
                *,
                auth_user_id: str | None,
                synthetic_principal_id: str | None,
                read_only: bool,
            ):
                self.calls.append((tenant_id, auth_user_id, synthetic_principal_id, read_only))
                yield TenantSession(tenant_id, self.connection)

        database = ScopeDatabase()
        scope = tenant_connection_scope(database, context, read_only=True)
        with scope(tenant) as connection:
            self.assertIs(connection, database.connection)
        self.assertEqual(database.calls, [(tenant, None, "user-noordlicht-admin", True)])
        with self.assertRaisesRegex(PermissionError, "configuration_tenant_scope_mismatch"):
            with scope("tenant-synth-zilvermeer"):
                self.fail("mismatched tenant scope was entered")
        self.assertEqual(len(database.calls), 1)

class ConfigurationApiServiceTests(unittest.TestCase):
    TENANT_ID = "tenant-synth-noordlicht"
    ADMIN_ID = "user-noordlicht-admin"

    def setUp(self) -> None:
        self.catalog = load_catalog()
        self.admin = self.catalog.principals[self.ADMIN_ID]
        self.prompt_repository = InMemoryPromptRepository()
        self.prompts = PromptManager(self.prompt_repository)
        first = self.prompts.create_client_version(
            self.admin, self.TENANT_ID, "initial tenant prompt", "seed", expected_latest_version=0
        )
        self.prompts.approve_client_version(self.admin, self.TENANT_ID, first.version)
        self.prompts.activate_client_version(
            self.admin, self.TENANT_ID, first.version, expected_active_version=0
        )

        self.signature_store = InMemoryTenantSignatureStore()
        self.signatures = TenantSignatureManager(self.signature_store)
        self.signatures.create(
            self.admin,
            self.TENANT_ID,
            ManagedTenantSignature("tenant-pattern", "NOORDLICHT", DetectionCategory.TENANT_SENSITIVE),
        )
        self.configuration_store = InMemoryShieldConfigurationStore()
        self.privacy_configuration = PrivacyShieldConfigurationManager(self.configuration_store)
        self.privacy_configuration.configure(self.admin, self.TENANT_ID, "NL")
        self.signature_provider = MappingSignatureConfigurationProvider(
            self.configuration_store, RegionalSignatureRegistry.with_defaults(), self.signature_store
        )
        self.factory_calls: list[tuple[TrustedRequestContext, bool]] = []

        def factory(context: TrustedRequestContext, write: bool) -> ConfigurationServices:
            self.factory_calls.append((context, write))
            return ConfigurationServices(
                self.prompts,
                self.signatures,
                self.privacy_configuration,
                self.signature_provider,
            )

        self.app = create_app(
            settings=ApiSettings(environment="development", dev_auth_enabled=True),
            database=cast(Any, object()),
            catalog=self.catalog,
            configuration_services_factory=factory,
        )
        self.client = TestClient(self.app, client=("127.0.0.1", 51000))
        self.headers = {"X-Dev-Identity": self.ADMIN_ID}

    def test_prompt_history_create_and_restore_use_prompt_manager(self) -> None:
        active = self.client.get("/v1/configuration/prompts/active", headers=self.headers)
        self.assertEqual(active.status_code, 200)
        self.assertEqual(active.json()["content"], "initial tenant prompt")
        self.assertTrue(active.headers["X-Request-ID"])
        request_context = self.factory_calls[-1][0]
        self.assertEqual(request_context.tenant_id, self.TENANT_ID)
        self.assertEqual(request_context.effective_role, "admin")
        self.assertEqual(request_context.identity_source, "synthetic")
        self.assertEqual(request_context.synthetic_principal_id, self.ADMIN_ID)
        self.assertEqual(request_context.request_id, active.headers["X-Request-ID"])

        created = self.client.post(
            "/v1/configuration/prompts/versions",
            headers=self.headers,
            json={
                "content": "replacement tenant prompt",
                "change_description": "approved content update",
                "expected_latest_version": 1,
            },
        )
        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.json()["version"], 2)

        restored = self.client.post(
            "/v1/configuration/prompts/versions/1/restore",
            headers=self.headers,
            json={"expected_latest_version": 2},
        )
        self.assertEqual(restored.status_code, 200)
        self.assertEqual(restored.json()["version"], 3)
        self.assertEqual(restored.json()["content"], "initial tenant prompt")
        self.assertEqual(restored.json()["restored_from_version_id"], created.json()["previous_version_ref"])

        history = self.client.get("/v1/configuration/prompts/versions", headers=self.headers)
        self.assertEqual(history.status_code, 200)
        self.assertEqual([item["version"] for item in history.json()], [1, 2, 3])

    def test_signature_configuration_read_create_and_update(self) -> None:
        active = self.client.get("/v1/configuration/privacy-signatures/active", headers=self.headers)
        self.assertEqual(active.status_code, 200)
        self.assertEqual(active.json()["primary_jurisdiction"], "NL")
        self.assertEqual(active.json()["signatures"][0]["signature_id"], "tenant-pattern")

        created = self.client.post(
            "/v1/configuration/privacy-signatures",
            headers=self.headers,
            json={"signature_id": "second-pattern", "pattern": "PRIVATE-REF", "active": True},
        )
        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.json()["version"], 2)

        updated = self.client.put(
            "/v1/configuration/privacy-signatures/second-pattern",
            headers=self.headers,
            json={"signature_id": "second-pattern", "pattern": "PRIVATE-REF", "active": False},
        )
        self.assertEqual(updated.status_code, 200)
        self.assertFalse(next(
            item["active"] for item in updated.json()["signatures"]
            if item["signature_id"] == "second-pattern"
        ))

    def test_user_and_superuser_cannot_write_configuration(self) -> None:
        user = self.client.post(
            "/v1/configuration/prompts/versions",
            headers={"X-Dev-Identity": "user-noordlicht-reader"},
            json={"content": "denied", "change_description": "denied", "expected_latest_version": 0},
        )
        self.assertEqual(user.status_code, 403)

        original = self.catalog.principals["user-noordlicht-reader"]
        superuser = Principal(
            subject_id="synthetic-superuser",
            tenant_ids=original.tenant_ids,
            grants=original.grants + (AccessGrant(self.TENANT_ID, "prompt:client:manage", self.TENANT_ID),),
            role_bindings=((self.TENANT_ID, "superuser"),),
        )
        from dataclasses import replace
        catalog = replace(
            self.catalog,
            principals={**self.catalog.principals, "synthetic-superuser": superuser},
        )
        superuser_app = create_app(
            settings=ApiSettings(environment="development", dev_auth_enabled=True),
            database=cast(Any, object()),
            catalog=catalog,
            configuration_services_factory=lambda context, write: ConfigurationServices(
                self.prompts, self.signatures, self.privacy_configuration, self.signature_provider
            ),
        )
        denied = TestClient(superuser_app, client=("127.0.0.1", 51000)).post(
            "/v1/configuration/prompts/versions",
            headers={"X-Dev-Identity": "synthetic-superuser"},
            json={"content": "denied", "change_description": "denied", "expected_latest_version": 1},
        )
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(denied.json()["detail"], "Configuration permission denied")


if __name__ == "__main__":
    unittest.main()
