from __future__ import annotations

import datetime as dt
import unittest
from unittest.mock import patch
from contextlib import contextmanager
from typing import Iterator
from uuid import uuid4

from fastapi.testclient import TestClient

from bri.access.policy import AccessGrant, Principal
from bri.api.authentication import AuthenticatedIdentity, AuthenticationRejected
from bri.api.app import ApiSettings, RecoveryOperation, create_app
from bri.api.database import DatabaseUnavailable, ProtectedAccessDenied, TenantSession


ISSUER = "https://bwqdyibvuecgthtatrtv.supabase.co/auth/v1"
AUTH_USER_ID = "1d99454f-7af6-4d88-9f89-8a8c028ff2a7"
SESSION_ID = "a82f2916-26f1-42c5-a430-78ee5aac4e49"
TENANT_ID = "tenant-synth-noordlicht"


class FakeVerifier:
    def __init__(self) -> None:
        self.tokens: list[str] = []
        self.identity = AuthenticatedIdentity(AUTH_USER_ID, SESSION_ID, ISSUER, "aal2", ("totp",))

    async def verify(self, token: str) -> AuthenticatedIdentity:
        self.tokens.append(token)
        if token != "valid-supabase-token":
            raise AuthenticationRejected("invalid")
        return self.identity


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
        self.correlation_id = None
        self.recovery_authenticated_at = None
        self.denials = []
        self.protected_scopes = []
        self.operational = True

    def record_boundary_denial(self, *event):
        self.denials.append(event)

    def healthcheck(self) -> None:
        if not self.ready:
            raise DatabaseUnavailable("test database unavailable")

    def resolve_authenticated_principal(self, auth_user_id: str, issuer: str, subject: str) -> Principal | None:
        if (auth_user_id, issuer, subject) != (AUTH_USER_ID, ISSUER, AUTH_USER_ID):
            return None
        return self.principal

    def invalidate_for_password_recovery(self, auth_user_id: str, session_id: str, *, correlation_id: str,
                                         recovery_authenticated_at: int | None) -> bool:
        self.recovery_authenticated_at = recovery_authenticated_at
        if (auth_user_id, session_id) != (AUTH_USER_ID, SESSION_ID):
            return False
        self.correlation_id = correlation_id
        self.active_session = False
        return True

    @contextmanager
    def protected_tenant_context(self, tenant_id, *, auth_user_id, session_id, principal_id, issuer):
        self.protected_scopes.append((tenant_id,auth_user_id,session_id,principal_id,issuer))
        if (not self.operational or self.principal is None or tenant_id not in self.principal.tenant_ids
                or (auth_user_id,session_id,principal_id,issuer) != (AUTH_USER_ID,SESSION_ID,self.principal.subject_id,ISSUER)):
            raise ProtectedAccessDenied("access denied")
        yield TenantSession(tenant_id, None)

    def auth_session_is_active(self, auth_user_id: str, session_id: str) -> bool:
        return auth_user_id == AUTH_USER_ID and session_id == SESSION_ID and self.active_session

    def start_auth_session(self, auth_user_id: str, issuer: str, subject: str, session_id: str, *, correlation_id: str, primary_authenticated_at: int | None, totp_authenticated_at: int | None):
        self.correlation_id = correlation_id
        if (auth_user_id, issuer, subject, session_id) != (AUTH_USER_ID, ISSUER, AUTH_USER_ID, SESSION_ID):
            return None
        self.active_session = True
        return dt.datetime(2026, 11, 13, 12, 0, tzinfo=dt.timezone.utc)

    def revoke_auth_session(self, auth_user_id: str, session_id: str, *, correlation_id: str) -> bool:
        self.correlation_id = correlation_id
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
    recovery_binding=None,
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
    app = create_app(settings=settings, database=database, token_verifier=verifier, recovery_binding=recovery_binding)
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

    def test_normal_app_mounts_but_never_enables_privileged_approvals(self) -> None:
        client, verifier, _ = make_app(principal=self.principal)
        path = '/v1/privileged-approvals'
        self.assertIn('post', client.get('/openapi.json').json()['paths'].get(path, {}))
        result = client.post(path, json={'target':str(uuid4()), 'reason':'LOST_FACTOR', 'request_id':str(uuid4())},
                             headers={'Authorization':'Bearer valid-supabase-token'})
        self.assertEqual(result.status_code, 403)
        self.assertEqual(verifier.tokens, [])

    def test_normal_app_disables_provisioning_before_parsing_or_authentication(self) -> None:
        client, verifier, _ = make_app(principal=self.principal)
        path = '/v1/users/provisioning'
        for method, route in [('POST', path), ('GET', f'{path}/{uuid4()}'), ('POST', f'{path}/activate')]:
            with self.subTest(method=method, route=route):
                response = client.request(method, route, content=b'{', headers={
                    'Content-Type': 'application/json', 'Authorization': 'Bearer test-token',
                })
                self.assertEqual(response.status_code, 403)
                self.assertEqual(response.json(), {'detail': 'Provisioning stage is disabled'})
                self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(verifier.tokens, [])

    def test_normal_app_disables_lifecycle_before_parsing_or_authentication(self) -> None:
        client, verifier, _ = make_app(principal=self.principal)
        path = f'/v1/users/{uuid4()}/lifecycle'
        for method in ('GET', 'PATCH'):
            with self.subTest(method=method):
                response = client.request(method, path, content=b'{', headers={
                    'Content-Type': 'application/json', 'Authorization': 'Bearer test-token',
                })
                self.assertEqual(response.status_code, 403)
                self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(verifier.tokens, [])

    def test_api_identity_label_matches_hosted_environment(self) -> None:
        client, _, _ = make_app(principal=self.principal)
        response = client.get("/openapi.json")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["info"]["title"], "BRI Hosted Development API")

    def test_logout_does_not_acknowledge_an_unpersisted_denial(self) -> None:
        client, _, database = make_app(principal=self.principal)
        with patch.object(database, 'revoke_auth_session', return_value=False):
            response = client.delete('/v1/auth/session',headers={'Authorization':'Bearer valid-supabase-token'})
        self.assertEqual(response.status_code,403)

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

    def test_denial_boundary_actions_and_phases(self) -> None:
        client, _, db = make_app(principal=self.principal, active_session=False)
        headers = {"Authorization": "Bearer valid-supabase-token"}
        for method, url, supplied, code, action, phase, user in [
            ("GET", "/v1/me/tenants", {}, 401, "authenticate", "authentication", None),
            ("POST", "/v1/auth/session", {}, 401, "session_start", "authentication", None),
            ("DELETE", "/v1/auth/session", {}, 401, "session_end", "authentication", None),
            ("GET", "/v1/me/tenants", headers, 401, "authenticate", "session", AUTH_USER_ID),
            ("POST", "/v1/auth/recovery/invalidate", headers, 403, "recovery", "mfa", AUTH_USER_ID),
            ("POST", "/v1/privileged-approvals", {}, 403, "approval_request", "authority", None),
        ]:
            with self.subTest(action=action, phase=phase):
                response = client.request(method, url, headers={**supplied, "X-Request-ID": "incoming"})
                self.assertEqual(response.status_code, code)
                self.assertNotEqual(response.headers["X-Request-ID"], "incoming")
                self.assertEqual(db.denials, [(action, phase, "denied", response.headers["X-Request-ID"],
                                               user, ISSUER if user else None)])
                db.denials.clear()

    def test_session_mutations_use_server_correlation_id(self) -> None:
        client, _, database = make_app(principal=self.principal)
        for verb in (client.post, client.delete):
            response = verb('/v1/auth/session', headers={
                'Authorization': 'Bearer valid-supabase-token', 'X-Request-ID': 'browser-value',
            })
            self.assertIn(response.status_code, (201, 204))
            self.assertEqual(database.correlation_id, response.headers['X-Request-ID'])
            self.assertNotEqual(database.correlation_id, 'browser-value')

    def test_recovery_barrier_rejects_missing_recent_provider_mfa(self) -> None:
        client, _, database = make_app(principal=self.principal)
        response = client.post('/v1/auth/recovery/invalidate', headers={
            'Authorization': 'Bearer valid-supabase-token',
            'X-MFA-Time': 'now',
        })
        self.assertEqual(response.status_code, 403)
        self.assertTrue(database.active_session)

    def test_recovery_barrier_is_bound_to_verified_subject_and_correlation(self) -> None:
        pinned = []
        class IsolatedBinding:
            def pin(self, operation):
                pinned.append(operation)
                return operation
        client, verifier, database = make_app(principal=self.principal, recovery_binding=IsolatedBinding())
        object.__setattr__(verifier.identity, 'recovery_authenticated_at', 123)
        object.__setattr__(verifier.identity, 'totp_authenticated_at', int(dt.datetime.now().timestamp()))
        response = client.post('/v1/auth/recovery/invalidate', headers={'Authorization': 'Bearer valid-supabase-token'})
        self.assertEqual(response.status_code, 204)
        self.assertFalse(database.active_session)
        self.assertEqual(database.recovery_authenticated_at, 123)
        self.assertEqual(database.correlation_id, response.headers['X-Request-ID'])
        self.assertEqual(pinned, [RecoveryOperation(ISSUER,AUTH_USER_ID,SESSION_ID,database.correlation_id)])

    def test_recovery_is_unavailable_without_a_bound_confirmation_source(self) -> None:
        class WrongBinding:
            def pin(self, op):
                return RecoveryOperation(op.issuer,op.auth_user_id,op.session_id,str(uuid4()))
        for binding in (None, WrongBinding()):
            with self.subTest(binding=type(binding).__name__):
                client, verifier, db = make_app(principal=self.principal, recovery_binding=binding)
                object.__setattr__(verifier.identity, 'totp_authenticated_at', int(dt.datetime.now().timestamp()))
                response = client.post('/v1/auth/recovery/invalidate', headers={
                    'Authorization':'Bearer valid-supabase-token','X-Recovery-Confirmed':'true',
                })
                self.assertEqual(response.status_code,503)
                self.assertTrue(db.active_session)
                self.assertIsNone(db.correlation_id)
        synthetic = create_app(settings=ApiSettings(environment='development',dev_auth_enabled=True), database=db)
        self.assertEqual(TestClient(synthetic).post('/v1/auth/recovery/invalidate').status_code,503)
        self.assertTrue(db.active_session)

    def test_recovery_without_own_membership_never_pins_or_reserves(self) -> None:
        class NotCalled:
            def pin(self, operation):
                raise AssertionError('unauthorized pin')
        principal = Principal(subject_id=str(uuid4()), tenant_ids=frozenset(), grants=())
        client, verifier, db = make_app(principal=principal, recovery_binding=NotCalled())
        object.__setattr__(verifier.identity, 'totp_authenticated_at', int(dt.datetime.now().timestamp()))
        result = client.post('/v1/auth/recovery/invalidate',headers={'Authorization':'Bearer valid-supabase-token'})
        self.assertEqual(result.status_code,403)
        self.assertIsNone(db.correlation_id)

    def test_recovery_barrier_rejects_target_in_body(self) -> None:
        client, _, database = make_app(principal=self.principal)
        response = client.post('/v1/auth/recovery/invalidate', json={'subject': 'someone-else'},
                               headers={'Authorization': 'Bearer valid-supabase-token'})
        self.assertEqual(response.status_code, 400)
        self.assertTrue(database.active_session)

    def test_provisioning_tenant_cannot_access_client_data(self) -> None:
        client, _, database = make_app(principal=self.principal)
        database.operational = False
        response = client.get('/v1/organizations/structure', headers={'Authorization': 'Bearer valid-supabase-token'})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(database.protected_scopes, [(TENANT_ID, AUTH_USER_ID, SESSION_ID, self.principal.subject_id, ISSUER)])
        self.assertEqual(database.contexts, [])

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

    def test_resource_is_not_read_on_a_preflight_only_context(self) -> None:
        client, _, database = make_app(principal=self.principal)
        @contextmanager
        def protected(tenant_id, *, auth_user_id, session_id, principal_id, issuer):
            self.assertEqual((tenant_id,auth_user_id,session_id,principal_id,issuer),
                             (TENANT_ID,AUTH_USER_ID,SESSION_ID,self.principal.subject_id,ISSUER))
            raise ProtectedAccessDenied("access changed")
            yield
        database.protected_tenant_context = protected
        response = client.get('/v1/organizations/structure', headers={'Authorization': 'Bearer valid-supabase-token'})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(database.contexts, [])

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
