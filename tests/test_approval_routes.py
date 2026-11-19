"""Actual HTTP, restricted PG roles and verified token path. No network provider."""

import asyncio
import os
import time
import unittest
from uuid import UUID, uuid4

import httpx
import psycopg

# Reuse the existing private-cluster fixture without collecting its test cases twice.
import test_privileged_approvals_pg as pg
from fastapi import FastAPI
from fastapi.testclient import TestClient
from test_authentication import ISSUER, auth_server_response, make_token

from bri.access.approvals import ApprovalContext
from bri.api.approval_routes import (
    PREFIX,
    create_approval_router,
    create_staged_approval_app,
)
from bri.api.authentication import SupabaseTokenVerifier


class DisabledApprovalRoutes(unittest.TestCase):
    def test_normal_mount_has_no_write_or_status_capability(self):
        def never():
            self.fail("disabled runtime must not consult an auth service or database")

        app = FastAPI()
        app.include_router(create_approval_router(principal_dependency=never))
        client = TestClient(
            app, base_url="http://127.0.0.1", client=("127.0.0.1", 50000)
        )
        aid = str(uuid4())
        for endpoint, body in [
            (PREFIX, {"target": aid, "reason": "LOST_FACTOR", "request_id": aid}),
            (f"{PREFIX}/{aid}/decision", {"decision": "APPROVE"}),
        ]:
            self.assertEqual(client.post(endpoint, json=body).status_code, 403)
        self.assertEqual(client.get(f"{PREFIX}/{aid}").status_code, 403)


@unittest.skipUnless(
    os.getenv("BRI_APPROVAL_PG_BIN"), "requires private disposable PG16 binaries"
)
class StagedApprovalRoutes(unittest.TestCase):
    setUpClass = classmethod(pg.ApprovalDatabase.setUpClass.__func__)
    connect = classmethod(pg.ApprovalDatabase.connect.__func__)

    def setUp(self):
        self.t, self.actors = pg.seed_approval_tenant(self.connect)
        self.key = uuid4()
        self.factor = str(uuid4())
        self.present = True
        self.deletes = 0
        self.tokens = {}
        self.lookups = 0

        def auth(request):
            self.lookups += 1
            token = request.headers["authorization"].removeprefix("Bearer ")
            return auth_server_response(request, user_id=self.tokens.get(token, ""))

        self.auth = httpx.MockTransport(auth)

        def provider(request):
            subject = str(self.actors[2][1])
            base = f"/auth/v1/admin/users/{subject}/factors"
            if request.method == "GET" and request.url.path == base:
                return httpx.Response(
                    200,
                    json=[
                        {"id": self.factor, "factor_type": "totp", "status": "verified"}
                    ]
                    if self.present
                    else [],
                )
            if (
                request.method == "DELETE"
                and request.url.path == f"{base}/{self.factor}"
            ):
                self.deletes += 1
                self.present = False
                return httpx.Response(204)
            self.fail("unexpected provider call")

        self.stage = create_staged_approval_app(
            app_scope=lambda: self.connect("bri_app"),
            worker_scope=lambda: self.connect("bri_approval_worker"),
            private_socket=self.sock,
            auth_transport=self.auth,
            factor_transport=httpx.MockTransport(provider),
        )
        self.client = TestClient(
            self.stage, base_url="http://127.0.0.1", client=("127.0.0.1", 50000)
        )
        self.addCleanup(self.client.close)
        self.body = {
            "target": str(self.actors[2][0]),
            "reason": "LOST_FACTOR",
            "request_id": str(self.key),
        }
        self.url = f"{PREFIX}/{self.key}"

    def headers(self, index, **kwargs):
        return self.actor_headers(self.actors[index], **kwargs)

    def actor_headers(self, actor, **kwargs):
        _, user, session = actor
        token = make_token(sub=str(user), session_id=str(session), **kwargs)
        self.tokens[token] = str(user)
        return {"Authorization": "Bearer " + token}

    def test_other_tenant_admins_cannot_request_or_decide_for_this_client(self):
        tenant_b, actors_b = pg.seed_approval_tenant(self.connect)
        b_requester, b_reviewer = (self.actor_headers(actor) for actor in actors_b[:2])
        b_key = str(uuid4())
        b_body = {**self.body, "target": str(actors_b[2][0]), "request_id": b_key}

        # B's requester has a live session and an explicit request grant. Only
        # the target differs from the successful B request below.
        denied = self.client.post(PREFIX, json={**b_body, "target": self.body["target"]}, headers=b_requester)
        self.assertEqual(denied.status_code, 403, denied.text)
        with self.connect("postgres") as db:
            self.assertEqual(db.execute(
                "SELECT count(*) FROM bri.privileged_approvals WHERE tenant_id IN (%s,%s)",
                (self.t, tenant_b),
            ).fetchone(), (0,))

        for body, headers in ((self.body, self.headers(0)), (b_body, b_requester)):
            result = self.client.post(PREFIX, json=body, headers=headers)
            self.assertEqual(result.status_code, 200, result.text)
            self.assertEqual(result.json()["state"], "PENDING")

        # B's reviewer is not A's requester (nor a platform admin). No tenant
        # selector is sent: only the resource ID changes between these calls.
        def decide(key, headers):
            return self.client.post(f"{PREFIX}/{key}/decision", json={"decision": "APPROVE"}, headers=headers)

        denied = decide(self.key, b_reviewer)
        self.assertEqual(denied.status_code, 403, denied.text)
        with self.connect("postgres") as db:
            for key, tenant, actors in ((self.key, self.t, self.actors), (b_key, tenant_b, actors_b)):
                self.assertEqual(db.execute(
                    "SELECT tenant_id,target,requester,reviewer,state FROM bri.privileged_approvals WHERE approval_id=%s",
                    (key,),
                ).fetchone(), (tenant, actors[2][0], actors[0][0], None, "PENDING"))
                self.assertEqual(db.execute(
                    "SELECT actor,decision FROM bri.approval_votes WHERE approval_id=%s", (key,),
                ).fetchall(), [(actors[0][0], "REQUEST")])
                self.assertEqual(db.execute(
                    "SELECT state FROM bri.approval_events WHERE approval_id=%s", (key,),
                ).fetchall(), [("PENDING",)])
        for key, headers in ((b_key, b_reviewer), (self.key, self.headers(1))):
            result = decide(key, headers)
            self.assertEqual(result.status_code, 200, result.text)
            self.assertEqual(result.json()["state"], "APPROVED")
        self.assertEqual(self.deletes, 0)

    def test_record_decide_status_and_separate_execution(self):
        requester = self.headers(0)
        reviewer = self.headers(1)
        first = self.client.post(PREFIX, json=self.body, headers=requester)
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(
            first.json(),
            {
                "approval_id": str(self.key),
                "state": "PENDING",
                "correlation_id": first.headers["X-Request-ID"],
            },
        )
        decision = self.client.post(
            self.url + "/decision", json={"decision": "APPROVE"}, headers=reviewer
        )
        self.assertEqual(decision.json()["state"], "APPROVED")
        self.assertEqual(self.deletes, 0)
        self.assertEqual(
            self.client.get(self.url, headers=requester).json()["state"], "APPROVED"
        )
        execution = uuid4()

        async def execute():
            async with httpx.AsyncClient(transport=self.auth) as client:
                verifier = SupabaseTokenVerifier(
                    ISSUER.removesuffix("/auth/v1"), "stage-only", client=client
                )
                identity = await verifier.verify(reviewer["Authorization"][7:])
            return await self.stage.state.approval_worker.execute(
                ApprovalContext(self.t, identity, execution), self.key
            )

        self.assertEqual(asyncio.run(execute()), "COMPLETED")
        self.assertEqual(
            self.client.get(self.url, headers=reviewer).json()["state"], "COMPLETED"
        )
        with self.connect("postgres") as db:
            self.assertEqual(db.execute(
                "SELECT event_type,outcome,tenant_id,actor_principal_id,subject_principal_id "
                "FROM bri.security_audit_events WHERE request_id=%s", (decision.headers["X-Request-ID"],)
            ).fetchall(), [("auth.approval.approved", "success", self.t, self.actors[1][0], self.actors[2][0])])
            states = db.execute(
                "SELECT state,correlation_id FROM bri.approval_events WHERE approval_id=%s ORDER BY event_id",
                (self.key,),
            ).fetchall()
            self.assertEqual(
                states,
                [
                    ("PENDING", UUID(first.headers["X-Request-ID"])),
                    ("APPROVED", UUID(decision.headers["X-Request-ID"])),
                    ("EXECUTING", execution),
                    ("COMPLETED", execution),
                ],
            )
            self.assertEqual(
                db.execute(
                    "SELECT confirmed_at FROM bri.credential_operations WHERE operation_id=%s",
                    (self.key,),
                ).fetchone(),
                (None,),
            )
        self.assertEqual(self.deletes, 1)
        # 0011 factor logs cannot unlock the subject. Exercise both *independent*
        # 0012 private attestors, provisioned solely inside this disposable DB.
        with self.connect("postgres") as db:
            db.execute(
                "INSERT INTO bri.provider_event_source VALUES(true,%s) ON CONFLICT DO NOTHING",
                (ISSUER,),
            )
            for side in ("platform", "provider"):
                role = "bri_reenrollment_" + side
                db.execute(
                    psycopg.sql.SQL("CREATE ROLE {} LOGIN NOINHERIT").format(
                        psycopg.sql.Identifier(role)
                    )
                )
                db.execute(
                    psycopg.sql.SQL(
                        "GRANT USAGE ON SCHEMA bri TO {}; GRANT EXECUTE ON FUNCTION bri.record_reenrollment_proof(text,uuid,text,uuid,uuid,uuid,uuid,timestamptz,timestamptz) TO {}"
                    ).format(*[psycopg.sql.Identifier(role)] * 2)
                )
        case, replacement = uuid4(), uuid4()
        user = self.actors[2][1]
        with self.connect("bri_reenrollment_platform") as db:
            self.assertEqual(
                db.execute(
                    "SELECT bri.record_reenrollment_proof(%s,%s,%s,%s,%s,%s,%s,statement_timestamp(),NULL)",
                    (self.t, self.key, ISSUER, user, replacement, case, case),
                ).fetchone()[0],
                "awaiting_provider",
            )
        with self.connect("postgres") as db:
            self.assertEqual(
                db.execute(
                    "SELECT confirmed_at IS NULL FROM bri.credential_operations WHERE operation_id=%s",
                    (self.key,),
                ).fetchone(),
                (True,),
            )
        with self.connect("bri_reenrollment_provider") as db:
            self.assertEqual(
                db.execute(
                    "SELECT bri.record_reenrollment_proof(%s,%s,%s,%s,%s,%s,%s,statement_timestamp(),statement_timestamp())",
                    (self.t, self.key, ISSUER, user, replacement, case, uuid4()),
                ).fetchone()[0],
                "confirmed",
            )
        with self.connect("bri_app") as db:
            db.execute("SELECT set_config('bri.auth_user_id',%s,true)", (str(user),))
            self.assertIsNotNone(
                db.execute(
                    "SELECT bri.start_security_session(%s,%s,clock_timestamp(),%s)",
                    (ISSUER, uuid4(), uuid4()),
                ).fetchone()[0]
            )

    def test_main_app_auth_session_and_recovery_denials_commit(self):
        from bri.api.app import ApiSettings, create_app
        from bri.api.database import Database

        origin = ISSUER.removesuffix("/auth/v1")
        connect = self.connect

        class PrivateDatabase(Database):
            def _connect(self):
                return connect("bri_app")

        with self.connect("postgres") as db:
            db.execute("UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() WHERE session_id=%s",
                       (self.actors[0][2],))
        # Real token verifier, mocked provider response; no outbound client.
        async def exercise():
            async with httpx.AsyncClient(transport=self.auth) as provider:
                api = create_app(settings=ApiSettings(environment="hosted-development", auth_mode="supabase",
                                 dev_auth_enabled=False, supabase_url=origin, supabase_publishable_key="test-only"),
                                 database=PrivateDatabase(origin, ""),
                                 token_verifier=SupabaseTokenVerifier(origin, "test-only", client=provider))
                async with httpx.AsyncClient(transport=httpx.ASGITransport(app=api), base_url="http://test") as client:
                    known, unknown = self.headers(0), self.actor_headers((None, uuid4(), uuid4()))
                    actor = self.actors[0][0]
                    for method, path, headers, code, action, phase, who in [
                        ("GET", "/v1/me/tenants", {}, 401, "authenticate", "authentication", None),
                        ("POST", "/v1/auth/session", unknown, 403, "session_start", "membership", None),
                        ("POST", "/v1/auth/session", known, 403, "session_start", "session", actor),
                        ("GET", "/v1/me/tenants", known, 401, "authenticate", "session", actor),
                        ("POST", "/v1/auth/recovery/invalidate", self.headers(0, aal="aal1"),
                         401, "recovery", "mfa", None),
                        ("POST", "/v1/auth/recovery/invalidate", known, 503, "recovery", "operation", actor),
                    ]:
                        with self.subTest(path=path, phase=phase):
                            result = await client.request(method, path, headers=headers)
                            self.assertEqual(result.status_code, code)
                            with self.connect("postgres") as db:
                                self.assertEqual(db.execute(
                                    "SELECT event_type,boundary_phase,outcome,actor_principal_id,subject_principal_id,tenant_id "
                                    "FROM bri.security_audit_events WHERE request_id=%s", (result.headers["X-Request-ID"],)
                                ).fetchall(), [("auth.boundary." + action, phase, "failure" if code == 503 else "denied",
                                                who, who, self.t if who else None)])
        asyncio.run(exercise())

    def test_unavailable_denial_writer_fails_closed(self):
        # Change only this suite's private cluster, and restore before the next test.
        function = "bri.record_boundary_denial(text,text,text,uuid,uuid,text)"
        with self.connect("postgres") as db:
            db.execute(f"REVOKE EXECUTE ON FUNCTION {function} FROM bri_app")
        try:
            response = self.client.post(PREFIX, json=self.body)
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json(), {"detail": "Security audit unavailable"})
            with self.connect("postgres") as db:
                self.assertEqual(db.execute("SELECT count(*) FROM bri.security_audit_events WHERE request_id=%s",
                                            (response.headers["X-Request-ID"],)).fetchone(), (0,))
                self.assertFalse(db.execute("SELECT 1 FROM bri.privileged_approvals WHERE approval_id=%s",
                                            (self.key,)).fetchone())
        finally:
            with self.connect("postgres") as db:
                db.execute(f"GRANT EXECUTE ON FUNCTION {function} TO bri_app")

    def test_audit_catalog_keeps_runtime_privileges_narrow(self):
        with self.connect("bri_app") as db:
            denial = "bri.record_boundary_denial(text,text,text,uuid,uuid,text)"
            self.assertEqual(db.execute(
                "SELECT has_function_privilege(current_user,%s,'EXECUTE'), "
                "has_function_privilege('bri_approval_worker',%s,'EXECUTE'), "
                "has_function_privilege(current_user,'bri.audit_approval_outcome()','EXECUTE'), "
                "has_table_privilege(current_user,'bri.security_audit_events','UPDATE,DELETE,TRUNCATE'), "
                "has_column_privilege(current_user,'bri.security_audit_events','boundary_phase','INSERT')",
                (denial, denial),
            ).fetchone(), (True, False, False, False, False))
            self.assertEqual(db.execute(
                "SELECT count(*) FROM pg_trigger WHERE tgrelid='bri.security_audit_events'::regclass "
                "AND tgname='immutable_security_history' AND tgenabled='O'"
            ).fetchone(), (1,))

    def test_anonymous_phase_is_bounded_without_claims_or_selectors(self):
        for headers, phase, code in [(self.headers(0, aal="aal1"), "mfa", 401),
                                     ({"X-Tenant-ID": self.t}, "authority", 400),
                                     ({}, "authentication", 401)]:
            response = self.client.post(PREFIX, headers=headers, json=self.body)
            self.assertEqual(response.status_code, code)
            with self.connect("postgres") as db:
                self.assertEqual(db.execute(
                    "SELECT event_type,boundary_phase,outcome,tenant_id,actor_principal_id,subject_principal_id,"
                    "session_audit_key FROM bri.security_audit_events WHERE request_id=%s",
                    (response.headers["X-Request-ID"],)
                ).fetchall(), [("auth.boundary.approval_request", phase, "denied", None, None, None, None)])

    def test_approval_outcome_is_atomic_and_replays_do_not_append(self):
        self.assertEqual(self.client.post(PREFIX, json=self.body, headers=self.headers(0)).status_code, 200)
        with self.connect("postgres") as db:
            db.execute("CREATE TRIGGER fixture_block_approval BEFORE INSERT ON bri.security_audit_events "
                       "FOR EACH ROW WHEN (NEW.event_type='auth.approval.rejected') "
                       "EXECUTE FUNCTION bri.deny_audit_mutation()")
        def reject():
            return self.client.post(self.url + "/decision", json={"decision": "REJECT"}, headers=self.headers(1))
        try:
            result = reject()
            self.assertEqual(result.status_code, 503)
            with self.connect("postgres") as db:
                self.assertEqual(db.execute("SELECT state,reviewer FROM bri.privileged_approvals WHERE approval_id=%s",
                                            (self.key,)).fetchone(), ("PENDING", None))
                self.assertEqual(db.execute("SELECT decision FROM bri.approval_votes WHERE approval_id=%s",
                                            (self.key,)).fetchall(), [("REQUEST",)])
                self.assertEqual(db.execute("SELECT event_type,outcome FROM bri.security_audit_events WHERE request_id=%s",
                                            (result.headers["X-Request-ID"],)).fetchall(),
                                 [("auth.boundary.approval_decision", "failure")])
        finally:
            with self.connect("postgres") as db:
                db.execute("DROP TRIGGER fixture_block_approval ON bri.security_audit_events")
        result, replay = reject(), reject()
        self.assertEqual([r.json()["state"] for r in (result, replay)], ["REJECTED", "REJECTED"])
        with self.connect("postgres") as db:
            self.assertEqual(db.execute(
                "SELECT actor_principal_id,subject_principal_id,request_id FROM bri.security_audit_events "
                "WHERE event_type='auth.approval.rejected' AND tenant_id=%s AND outcome='success'", (self.t,)
            ).fetchall(), [(self.actors[1][0], self.actors[2][0], UUID(result.headers["X-Request-ID"]))])

    def test_denied_decision_survives_rollback_without_trusting_request_ids(self):
        self.assertEqual(self.client.post(PREFIX, json=self.body, headers=self.headers(0)).status_code, 200)
        incoming = str(uuid4())
        result = self.client.post(self.url + "/decision", json={"decision": "APPROVE"},
                                  headers={**self.headers(0), "X-Request-ID": incoming})
        self.assertEqual(result.status_code, 403)
        correlation = UUID(result.headers["X-Request-ID"])
        self.assertNotEqual(str(correlation), incoming)
        with self.connect("postgres") as db:
            self.assertEqual(db.execute("SELECT state FROM bri.privileged_approvals WHERE approval_id=%s",
                                        (self.key,)).fetchone(), ("PENDING",))
            self.assertEqual(db.execute(
                "SELECT event_type,outcome,actor_principal_id,tenant_id,subject_principal_id "
                "FROM bri.security_audit_events WHERE request_id=%s", (correlation,)
            ).fetchall(), [("auth.boundary.approval_decision", "denied", self.actors[0][0], self.t, None)])

    def test_verified_auth_and_tenant_binding_denials(self):
        for h, code in [
            ({"X-Dev-Identity": "fixture"}, 400),
            ({}, 401),
            ({"authorization": "Bearer invalid"}, 401),
            (self.headers(2), 403),
            (self.headers(3), 403),
            (
                self.headers(
                    0, amr=[{"method": "totp", "timestamp": int(time.time()) - 1000}]
                ),
                403,
            ),
            ({**self.headers(0), "X-Tenant-Id": "other"}, 400),
        ]:
            self.assertEqual(
                self.client.post(PREFIX, json=self.body, headers=h).status_code, code
            )
        bad = self.client.post(
            PREFIX,
            json={**self.body, "secret": "do-not-reflect"},
            headers=self.headers(0),
        )
        self.assertEqual(bad.status_code, 422)
        self.assertNotIn("do-not-reflect", bad.text)
        self.assertEqual(
            self.client.post(
                PREFIX, json=self.body, headers=self.headers(0)
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.post(
                self.url + "/decision",
                json={"decision": "APPROVE"},
                headers=self.headers(0),
            ).status_code,
            403,
        )
        with self.connect("postgres") as db:
            db.execute(
                "UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() WHERE session_id=%s",
                (self.actors[1][2],),
            )
        self.assertEqual(
            self.client.post(
                self.url + "/decision",
                json={"decision": "APPROVE"},
                headers=self.headers(1),
            ).status_code,
            403,
        )

    def test_provider_exception_after_dispatch_is_durable(self):
        from bri.access.approvals import ApprovalWorker

        self.assertEqual(
            self.client.post(
                PREFIX, json=self.body, headers=self.headers(0)
            ).status_code,
            200,
        )
        headers = self.headers(1)
        self.assertEqual(
            self.client.post(
                self.url + "/decision", json={"decision": "APPROVE"}, headers=headers
            ).status_code,
            200,
        )
        case = self

        class BrokenProvider:
            async def list_totp_factor_ids(self, user_id):
                return [case.factor]

            async def remove_totp_factor(self, user_id, factor_id):
                raise RuntimeError("private provider detail")

        async def execute():
            async with httpx.AsyncClient(transport=self.auth) as client:
                identity = await SupabaseTokenVerifier(
                    ISSUER.removesuffix("/auth/v1"), "stage-only", client=client
                ).verify(headers["Authorization"][7:])
            return await ApprovalWorker(
                lambda: self.connect("bri_approval_worker"), BrokenProvider()
            ).execute(ApprovalContext(self.t, identity, correlation), self.key)

        correlation = uuid4()
        self.assertEqual(asyncio.run(execute()), "FAILED")
        with self.connect("postgres") as db:
            self.assertEqual(
                db.execute(
                    "SELECT state,correlation_id FROM bri.approval_events WHERE approval_id=%s ORDER BY event_id DESC LIMIT 1",
                    (self.key,),
                ).fetchone(),
                ("FAILED", correlation),
            )

    @classmethod
    def provision_observer(cls):
        with cls.connect("postgres") as db:
            if not db.execute(
                "SELECT EXISTS(SELECT FROM pg_roles WHERE rolname='bri_approval_observer')"
            ).fetchone()[0]:
                db.execute(
                    "CREATE ROLE bri_approval_observer LOGIN NOINHERIT; GRANT USAGE ON SCHEMA bri TO bri_approval_observer; GRANT EXECUTE ON FUNCTION bri.approval_observe(uuid,text,uuid,uuid[],uuid[]), bri.approval_observation_queue(uuid,integer) TO bri_approval_observer"
                )

    def test_late_observer_needs_no_human_session_and_cannot_dispatch(self):
        self.provision_observer()
        self.assertEqual(
            self.client.post(
                PREFIX, json=self.body, headers=self.headers(0)
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.post(
                self.url + "/decision",
                json={"decision": "APPROVE"},
                headers=self.headers(1),
            ).status_code,
            200,
        )
        with self.connect("bri_approval_worker") as db:
            pg.ApprovalDatabase.ctx(self, 1).bind(db)
            for op, ids in [
                ("BEGIN", None),
                ("PIN", [self.factor]),
                ("DISPATCH", [self.factor]),
            ]:
                db.execute(
                    "SELECT * FROM bri.approval_work(%s,%s,%s,%s,%s::uuid[])",
                    (self.t, "USER_MFA_RESET", self.key, op, ids),
                )
        with self.connect("postgres") as db:
            db.execute(
                "UPDATE bri.privileged_approvals SET created_at=created_at-interval '25 hours',expires_at=expires_at-interval '25 hours' WHERE approval_id=%s",
                (self.key,),
            )
        with self.connect("bri_approval_worker") as db:
            pg.ApprovalDatabase.ctx(self, 1).bind(db)
            self.assertEqual(
                db.execute(
                    "SELECT stage,permit FROM bri.approval_work(%s,'USER_MFA_RESET',%s,'DISPATCH',%s::uuid[])",
                    (self.t, self.key, [self.factor]),
                ).fetchone(),
                ("FAILED", False),
            )
        with self.connect("postgres") as db:
            db.execute(
                "UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() WHERE session_id IN (%s,%s)",
                (self.actors[0][2], self.actors[1][2]),
            )
        with self.connect("bri_approval_observer") as db:
            self.assertFalse(
                db.execute(
                    "SELECT has_function_privilege(current_user,'bri.approval_work(text,text,uuid,text,uuid[])','EXECUTE')"
                ).fetchone()[0]
            )
            cid = uuid4()
            db.execute(
                "SELECT * FROM bri.approval_observe(%s,'PLAN',%s,NULL,NULL)",
                (self.key, cid),
            )
            state = db.execute(
                "SELECT stage FROM bri.approval_observe(%s,'RECORD',%s,ARRAY[]::uuid[],ARRAY[]::uuid[])",
                (self.key, cid),
            ).fetchone()[0]
            self.assertEqual(state, "COMPLETED")

    def test_safe_handoff_retains_barrier_and_requires_new_votes(self):
        from bri.access.approvals import ApprovalObserver, FactorInventoryReader

        self.provision_observer()
        self.assertEqual(
            self.client.post(
                PREFIX, json=self.body, headers=self.headers(0)
            ).status_code,
            200,
        )
        self.assertEqual(
            self.client.post(
                self.url + "/decision",
                json={"decision": "APPROVE"},
                headers=self.headers(1),
            ).status_code,
            200,
        )

        def work(key, op, ids=None):
            with self.connect("bri_approval_worker") as db:
                pg.ApprovalDatabase.ctx(self, 1).bind(db)
                return db.execute(
                    "SELECT stage,permit FROM bri.approval_work(%s,%s,%s,%s,%s::uuid[])",
                    (self.t, "USER_MFA_RESET", key, op, ids),
                ).fetchone()

        work(self.key, "BEGIN")
        work(self.key, "PIN", [self.factor])
        work(self.key, "DISPATCH", [self.factor])
        inventory = [self.factor]

        def handler(req):
            self.assertEqual(req.method, "GET")
            return httpx.Response(
                200,
                json=[
                    {"id": fid, "factor_type": "totp", "status": "verified"}
                    for fid in inventory
                ],
            )

        observer = ApprovalObserver(
            lambda: self.connect("bri_approval_observer"),
            FactorInventoryReader(test_transport=httpx.MockTransport(handler)),
        )
        self.assertIn(self.key, observer.pending())

        def observe():
            return asyncio.run(observer.observe(self.key, correlation_id=uuid4()))

        self.assertEqual(observe(), "FAILED")
        fresh = uuid4()
        body = {**self.body, "request_id": str(fresh)}
        self.assertNotEqual(
            self.client.post(PREFIX, json=body, headers=self.headers(0)).status_code,
            200,
        )
        inventory[:] = [
            str(uuid4())
        ]  # prior dispatched ID now gone; replacement is not covered
        self.assertEqual(observe(), "FAILED")
        self.assertEqual(work(self.key, "BEGIN"), ("FAILED", False))
        self.assertNotIn(self.key, observer.pending())
        self.assertEqual(
            self.client.post(PREFIX, json=body, headers=self.headers(0)).json()[
                "state"
            ],
            "PENDING",
        )
        self.assertEqual(
            self.client.post(
                f"{PREFIX}/{fresh}/decision",
                json={"decision": "APPROVE"},
                headers=self.headers(0),
            ).status_code,
            403,
        )
        self.assertEqual(
            self.client.post(
                f"{PREFIX}/{fresh}/decision",
                json={"decision": "APPROVE"},
                headers=self.headers(1),
            ).json()["state"],
            "APPROVED",
        )
        self.assertEqual(work(fresh, "BEGIN"), ("EXECUTING", False))
        with self.connect("postgres") as db:
            self.assertEqual(
                db.execute(
                    "SELECT operation_id,confirmed_at FROM bri.credential_operations WHERE principal_id=%s",
                    (self.actors[2][0],),
                ).fetchall(),
                [(fresh, None)],
            )
            self.assertEqual(
                db.execute(
                    "SELECT retry_of FROM bri.privileged_approvals WHERE approval_id=%s",
                    (fresh,),
                ).fetchone()[0],
                self.key,
            )
        work(fresh, "PIN", inventory)
        self.assertEqual(work(fresh, "DISPATCH", inventory), ("EXECUTING", True))
        inventory.clear()
        self.assertEqual(
            asyncio.run(observer.observe(fresh, correlation_id=uuid4())), "COMPLETED"
        )
        self.assertEqual(self.deletes, 0)  # observer has no mutation capability

    def test_runtime_cannot_delete_reset_permissions(self):
        with self.connect("bri_app") as db:
            db.execute("SELECT set_config('bri.tenant_id',%s,true)", (self.t,))
            self.assertEqual(
                db.execute(
                    "DELETE FROM bri.role_permissions WHERE tenant_id=%s AND permission='user:mfa_reset:decide'",
                    (self.t,),
                ).rowcount,
                0,
            )
        with self.connect("postgres") as db:
            self.assertTrue(
                db.execute(
                    "SELECT EXISTS(SELECT FROM bri.role_permissions WHERE tenant_id=%s AND permission='user:mfa_reset:decide')",
                    (self.t,),
                ).fetchone()[0]
            )

    def test_outer_loopback_gate_before_identity(self):
        for url, peer, headers in [
            ("http://127.0.0.1", "192.0.2.1", {}),
            ("http://outside.invalid", "127.0.0.1", {}),
            ("http://127.0.0.1", "127.0.0.1", {"X-Forwarded-For": "127.0.0.1"}),
        ]:
            with TestClient(self.stage, base_url=url, client=(peer, 50000)) as client:
                self.assertEqual(
                    client.post(
                        PREFIX, json=self.body, headers={**self.headers(0), **headers}
                    ).status_code,
                    403,
                )
        self.assertEqual(self.lookups, 0)
