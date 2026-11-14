from __future__ import annotations

import datetime as dt
import unittest
from contextlib import contextmanager
from typing import Iterator
from uuid import uuid4

from fastapi.testclient import TestClient

from bri.access.policy import AccessGrant, Principal
from bri.api.authentication import AuthenticatedIdentity, AuthenticationRejected
from bri.api.app import ApiSettings, create_app
from bri.api.database import DatabaseUnavailable, TenantSession


ISSUER = "https://bwqdyibvuecgthtatrtv.supabase.co/auth/v1"
AUTH_USER_ID = "1d99454f-7af6-4d88-9f89-8a8c028ff2a7"
SESSION_ID = "a82f2916-26f1-42c5-a430-78ee5aac4e49"
TENANT_ID = "tenant-synth-noordlicht"


class FakeVerifier:
    def __init__(self) -> None:
        self.tokens: list[str] = []

    async def verify(self, token: str) -> AuthenticatedIdentity:
        self.tokens.append(token)
        if token != "valid-supabase-token":
            raise AuthenticationRejected("invalid")
        return AuthenticatedIdentity(AUTH_USER_ID, SESSION_ID, ISSUER, "aal2", ("totp",))


class FakeRemoteDatabase:
    def __init__(
        self,
        principal: Principal | None = None,
        *,
        active_session: bool = True,
        ready: bool = True,
    ) -> None:
        self.principal = principal
        self.active_session = active_session
        self.ready = ready
        self.contexts: list[str] = []
        self.write_contexts: list[str] = []

    def healthcheck(self) -> None:
        if not self.ready:
            raise DatabaseUnavailable("test database unavailable")

    def resolve_authenticated_principal(self, auth_user_id: str, issuer: str, subject: str) -> Principal | None:
        if (auth_user_id, issuer, subject) != (AUTH_USER_ID, ISSUER, AUTH_USER_ID):
            return None
        return self.principal

    def auth_session_is_active(self, auth_user_id: str, session_id: str) -> bool:
        return auth_user_id == AUTH_USER_ID and session_id == SESSION_ID and self.active_session

    def start_auth_session(self, auth_user_id: str, issuer: str, subject: str, session_id: str):
        if (auth_user_id, issuer, subject, session_id) != (AUTH_USER_ID, ISSUER, AUTH_USER_ID, SESSION_ID):
            return None
        self.active_session = True
        return dt.datetime(2026, 11, 13, 12, 0, tzinfo=dt.timezone.utc)

    def revoke_auth_session(self, auth_user_id: str, session_id: str) -> bool:
        if auth_user_id != AUTH_USER_ID or session_id != SESSION_ID:
            return False
        self.active_session = False
        return True

    @contextmanager
    def tenant_context(self, tenant_id: str) -> Iterator[TenantSession]:
        self.contexts.append(tenant_id)
        yield TenantSession(tenant_id, None)

    @contextmanager
    def write_tenant_context(self, tenant_id: str) -> Iterator[TenantSession]:
        self.write_contexts.append(tenant_id)
        yield TenantSession(tenant_id, None)


def make_app(
    *,
    principal: Principal | None = None,
    active_session: bool = True,
    ready: bool = True,
):
    verifier = FakeVerifier()
    database = FakeRemoteDatabase(principal, active_session=active_session, ready=ready)
    settings = ApiSettings(
        environment="hosted-development",
        auth_mode="supabase",
        dev_auth_enabled=False,
        supabase_url="https://bwqdyibvuecgthtatrtv.supabase.co",
        supabase_publishable_key="sb_publishable_test_only",
    )
    app = create_app(settings=settings, database=database, token_verifier=verifier)
    client = TestClient(app, client=("127.0.0.1", 51000))
    return client, verifier, database


class RemoteAuthenticationApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.principal = Principal(
            subject_id=str(uuid4()),
            tenant_ids=frozenset({TENANT_ID}),
            grants=(AccessGrant(TENANT_ID, "organisation:read", "org-noordlicht-root"),),
        )

    def test_liveness_is_independent_of_database_readiness(self) -> None:
        client, _, _ = make_app(principal=self.principal, ready=False)
        liveness = client.get("/live")
        readiness = client.get("/ready")
        self.assertEqual(liveness.status_code, 200)
        self.assertEqual(liveness.json(), {"status": "ok"})
        self.assertEqual(readiness.status_code, 503)
        self.assertEqual(readiness.json(), {"status": "unavailable", "database": "unavailable"})

    def test_production_supabase_mode_is_rejected_without_a_production_project(self) -> None:
        with self.assertRaisesRegex(ValueError, "hosted-development only"):
            ApiSettings(
                environment="production",
                dev_auth_enabled=False,
                auth_mode="supabase",
                supabase_url="https://bwqdyibvuecgthtatrtv.supabase.co",
                supabase_publishable_key="test-publishable-key",
                database_url="postgresql://bri_app:unused@db.bwqdyibvuecgthtatrtv.supabase.co:5432/postgres?sslmode=require",
            )

    def test_api_identity_label_matches_hosted_environment(self) -> None:
        client, _, _ = make_app(principal=self.principal)
        response = client.get("/openapi.json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["info"]["title"], "BRI Hosted Development API")

    def test_unauthenticated_remote_request_is_rejected(self) -> None:
        client, verifier, _ = make_app(principal=self.principal)
        response = client.get("/v1/me/tenants")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(verifier.tokens, [])

    def test_remote_request_uses_verified_subject_mapping_and_only_its_memberships(self) -> None:
        client, verifier, _ = make_app(principal=self.principal)
        response = client.get(
            "/v1/me/tenants",
            headers={"Authorization": "Bearer valid-supabase-token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"tenant_ids": [TENANT_ID]})
        self.assertEqual(verifier.tokens, ["valid-supabase-token"])

    def test_unknown_supabase_subject_has_no_bri_access(self) -> None:
        client, _, _ = make_app(principal=None)
        response = client.get(
            "/v1/me/tenants",
            headers={"Authorization": "Bearer valid-supabase-token"},
        )
        self.assertEqual(response.status_code, 403)

    def test_remote_api_never_accepts_development_identity_header(self) -> None:
        client, verifier, _ = make_app(principal=self.principal)
        response = client.get(
            "/v1/me/tenants",
            headers={
                "Authorization": "Bearer valid-supabase-token",
                "X-Dev-Identity": "user-noordlicht-reader",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(verifier.tokens, [])

    def test_client_cannot_select_tenant_context_with_bri_header(self) -> None:
        client, verifier, database = make_app(principal=self.principal)
        response = client.get(
            "/v1/me/tenants",
            headers={
                "Authorization": "Bearer valid-supabase-token",
                "X-BRI-Tenant-Context": TENANT_ID,
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(verifier.tokens, [])
        self.assertEqual(database.contexts, [])

    def test_membership_discovery_returns_all_active_tenants(self) -> None:
        other_tenant = "tenant-synth-zilvermeer"
        multi_tenant_principal = Principal(
            subject_id="principal-multi-tenant",
            tenant_ids=frozenset({TENANT_ID, other_tenant}),
            grants=(),
        )
        client, _, _ = make_app(principal=multi_tenant_principal)
        response = client.get(
            "/v1/me/tenants",
            headers={"Authorization": "Bearer valid-supabase-token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"tenant_ids": [TENANT_ID, other_tenant]})

    def test_multitenant_data_access_requires_server_side_tenant_context(self) -> None:
        other_tenant = "tenant-synth-zilvermeer"
        multi_tenant_principal = Principal(
            subject_id="principal-multi-tenant",
            tenant_ids=frozenset({TENANT_ID, other_tenant}),
            grants=(AccessGrant(TENANT_ID, "organisation:read", "org-noordlicht-root"),),
        )
        client, _, database = make_app(principal=multi_tenant_principal)
        headers = {"Authorization": "Bearer valid-supabase-token"}
        unselected = client.get("/v1/organizations/nodes/not-visible", headers=headers)
        self.assertEqual(unselected.status_code, 403)
        self.assertEqual(
            unselected.json()["detail"],
            "A server-resolved tenant context is required for this identity",
        )
        spoofed = client.get(
            "/v1/organizations/nodes/not-visible",
            headers={**headers, "X-BRI-Tenant-Context": TENANT_ID},
        )
        self.assertEqual(spoofed.status_code, 400)
        self.assertEqual(database.contexts, [])

    def test_client_cannot_supply_unverified_tenant_header(self) -> None:
        client, verifier, _ = make_app(principal=self.principal)
        response = client.get(
            "/v1/me/tenants",
            headers={
                "Authorization": "Bearer valid-supabase-token",
                "X-Tenant-ID": "tenant-synth-zilvermeer",
            },
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(verifier.tokens, [])

    def test_revoked_bri_session_is_rejected_even_when_supabase_token_is_valid(self) -> None:
        client, _, _ = make_app(principal=self.principal, active_session=False)
        response = client.get(
            "/v1/me/tenants",
            headers={"Authorization": "Bearer valid-supabase-token"},
        )
        self.assertEqual(response.status_code, 401)

    def test_remote_session_start_requires_supabase_mfa_and_enables_bri_access(self) -> None:
        client, _, _ = make_app(principal=self.principal, active_session=False)
        response = client.post(
            "/v1/auth/session",
            headers={"Authorization": "Bearer valid-supabase-token"},
        )
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.json()["status"], "active")
        self.assertEqual(
            client.get("/v1/me/tenants", headers={"Authorization": "Bearer valid-supabase-token"}).status_code,
            200,
        )

    def test_remote_logout_revokes_the_bri_session(self) -> None:
        client, _, _ = make_app(principal=self.principal)
        response = client.delete(
            "/v1/auth/session",
            headers={"Authorization": "Bearer valid-supabase-token"},
        )
        self.assertEqual(response.status_code, 204)
        self.assertEqual(
            client.get("/v1/me/tenants", headers={"Authorization": "Bearer valid-supabase-token"}).status_code,
            401,
        )

    def test_remote_development_is_read_only_even_for_a_mapped_write_grant(self) -> None:
        proposer = Principal(
            subject_id=str(uuid4()),
            tenant_ids=frozenset({TENANT_ID}),
            grants=(AccessGrant(TENANT_ID, "knowledge:propose", "org-noordlicht-root"),),
        )
        client, _, database = make_app(principal=proposer)
        response = client.post(
            "/v1/knowledge/proposals",
            json={"extraction_id": "synthetic-extraction"},
            headers={"Authorization": "Bearer valid-supabase-token"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(database.write_contexts, [])

    def test_principal_without_memberships_lists_no_client_tenants(self) -> None:
        client, _, _ = make_app(principal=Principal("unassigned-principal", frozenset(), ()))
        response = client.get(
            "/v1/me/tenants",
            headers={"Authorization": "Bearer valid-supabase-token"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"tenant_ids": []})


    def test_request_logs_exclude_query_values_and_authentication_tokens(self) -> None:
        client, _, _ = make_app(principal=self.principal)
        token = "valid-supabase-token"
        private_query = "confidential-search-phrase"
        with self.assertLogs("bri.api.request", level="INFO") as captured:
            response = client.get(
                f"/v1/me/tenants?search={private_query}",
                headers={"Authorization": f"Bearer {token}"},
            )
        log_text = "\n".join(captured.output)
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.headers.get("X-Request-ID"))
        self.assertIn("GET", log_text)
        self.assertNotIn(private_query, log_text)
        self.assertNotIn(token, log_text)

    def test_unassigned_principal_has_no_implicit_tenant_data_access(self) -> None:
        unassigned = Principal("unassigned-principal", frozenset(), ())
        client, _, database = make_app(principal=unassigned)
        response = client.get(
            "/v1/organizations/structure",
            headers={"Authorization": "Bearer valid-supabase-token"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(database.contexts, [])

    def test_admin_provisioning_and_sso_jit_routes_are_not_exposed(self) -> None:
        client, _, _ = make_app(principal=self.principal)
        for path in (
            "/v1/admin/client-admins",
            "/v1/platform/superadmins",
            "/v1/auth/signup",
            "/v1/sso/provision",
        ):
            with self.subTest(path=path):
                response = client.post(path)
                self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()
