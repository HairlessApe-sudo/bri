"""A11.8 regressions on the private PG16 fixture, using a real bri_app login."""

import os
import time
import unittest
from uuid import uuid4

import psycopg
import test_privileged_approvals_pg as fixtures

from bri.access.approvals import ACTION, ApprovalContext, ApprovalRepository
from bri.api.authentication import AuthenticatedIdentity

ISSUER = fixtures.ISSUER

READ = "SELECT * FROM bri.read_mfa_reset_queue(%s,%s,%s,%s,%s,%s,%s)"
CHECK = "SELECT bri.can_request_mfa_reset(%s,%s,%s,%s,%s)"
PERMISSION = "account:mfa-reset:queue:read"
COLUMNS = (
    "approval_id",
    "target_id",
    "target_name",
    "reason",
    "requested_at",
    "expires_at",
    "state",
    "reconciliation",
    "can_decide",
)


@unittest.skipUnless(os.getenv("BRI_APPROVAL_PG_BIN"), "requires private PostgreSQL 16")
class MfaResetAdministrationTests(unittest.TestCase):
    @classmethod
    def connect(cls, role, **kwargs):
        return fixtures.ApprovalDatabase.connect.__func__(cls, role, **kwargs)

    @classmethod
    def setUpClass(cls):
        fixtures.ApprovalDatabase.setUpClass.__func__(cls)
        with cls.connect("postgres") as db:
            db.execute(
                "CREATE ROLE bri_approval_observer LOGIN NOINHERIT; "
                "GRANT USAGE ON SCHEMA bri TO bri_approval_observer; "
                "GRANT EXECUTE ON FUNCTION bri.approval_observe(uuid,text,uuid,uuid[],uuid[]) TO bri_approval_observer"
            )

    def setUp(self):
        self.tenant, self.actors = fixtures.seed_approval_tenant(self.connect)
        self.foreign, self.foreign_actors = fixtures.seed_approval_tenant(self.connect)
        self.target = self.actors[2][0]
        with self.connect("postgres") as db:
            for tenant, actors in (
                (self.tenant, self.actors),
                (self.foreign, self.foreign_actors),
            ):
                db.execute(
                    "INSERT INTO bri.app_roles VALUES (%s,'queue','queue')", (tenant,)
                )
                db.execute(
                    "INSERT INTO bri.role_permissions VALUES (%s,'queue',%s)",
                    (tenant, PERMISSION),
                )
                db.execute(
                    "INSERT INTO bri.role_permissions VALUES (%s,'reset','user:directory:read')",
                    (tenant,),
                )
                db.execute(
                    "INSERT INTO bri.org_nodes VALUES (%s,'leaf','team','Leaf','root')",
                    (tenant,),
                )
                db.execute(
                    "INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) "
                    "VALUES (%s,%s,'queue','root')",
                    (tenant, actors[1][0]),
                )
                for i in (0, 1):
                    self.refresh(db, actors, i)
            db.execute(
                "UPDATE bri.auth_principals SET display_name='Visible account' WHERE principal_id=%s",
                (self.target,),
            )
        self.key = self.request(self.tenant, self.actors)
        self.foreign_key = self.request(self.foreign, self.foreign_actors)

    @staticmethod
    def refresh(db, actors, index):
        actors[index] = (*actors[index][:2], uuid4())
        db.execute(
            "INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) "
            "VALUES (%s,%s,%s,clock_timestamp())",
            actors[index],
        )

    @staticmethod
    def context(tenant, actor):
        _, uid, sid = actor
        identity = AuthenticatedIdentity(str(uid), str(sid), ISSUER, "aal2", ("totp",))
        object.__setattr__(identity, "totp_authenticated_at", int(time.time()))
        return ApprovalContext(tenant, identity, uuid4())

    def request(self, tenant, actors):
        key = uuid4()
        repo = ApprovalRepository(lambda: self.connect("bri_app"))
        self.assertEqual(
            repo.request(
                self.context(tenant, actors[0]),
                target=actors[2][0],
                reason="LOST_FACTOR",
                request_id=key,
            ),
            "PENDING",
        )
        return key

    def query(
        self,
        sql,
        tail,
        *,
        index=0,
        issuer=ISSUER,
        tenant=None,
        actors=None,
        bound_uid=None,
    ):
        principal, uid, sid = (actors or self.actors)[index]
        tenant = tenant or self.tenant
        with self.connect("bri_app") as db:
            db.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            db.execute(
                "SELECT set_config('bri.tenant_id',%s,true),set_config('bri.auth_user_id',%s,true)",
                (tenant, str(bound_uid or uid)),
            )
            cur = db.execute(sql, (tenant, principal, sid, issuer, *tail))
            if sql == READ:
                self.assertEqual(tuple(col.name for col in cur.description), COLUMNS)
            return cur.fetchall()

    def read(self, *, size=10, cursor=None, item=None, **kwargs):
        return self.query(READ, (size, cursor, item), **kwargs)

    def can_request(self, target, **kwargs):
        return self.query(CHECK, (target,), **kwargs)[0][0]

    def assert_sqlstate(self, expected, func, **kwargs):
        with self.assertRaises(psycopg.Error) as error:
            func(**kwargs)
        self.assertEqual(error.exception.sqlstate, expected)

    def historic(self, db, *, index=1):
        key = uuid4()
        db.execute(
            "INSERT INTO bri.privileged_approvals(approval_id,tenant_id,action,target,target_auth,requester,reviewer,reason,state,created_at,expires_at) "
            "SELECT %s,%s,'USER_MFA_RESET',%s,%s,%s,%s,'REPLACED_DEVICE','REJECTED',created,created+interval '24 hours' "
            "FROM (SELECT '2024-01-01 00:00:00+00'::timestamptz AS created) stamp",
            (
                key,
                self.tenant,
                self.target,
                self.actors[2][1],
                self.actors[index][0],
                self.actors[1 - index][0],
            ),
        )
        return key

    def test_exact_mask_and_review_scope(self):
        with self.connect("postgres") as db:
            other = self.historic(db)
        (own,) = self.read()
        self.assertEqual(
            own[:4], (self.key, self.target, "Visible account", "LOST_FACTOR")
        )
        self.assertEqual(own[6:], ("PENDING", "NONE", False))
        review = self.read(index=1)
        self.assertEqual([row[0] for row in review], [self.key, other])
        self.assertEqual(review[0][6:], ("PENDING", "NONE", True))
        self.assertEqual(review[1][6:], ("REJECTED", "NONE", False))
        for item in (other, self.foreign_key, uuid4()):
            self.assertEqual(self.read(item=item), [])
        self.assertEqual(self.read(index=1, item=self.foreign_key), [])
        self.assertEqual(
            [
                row[0]
                for row in self.read(
                    tenant=self.foreign, actors=self.foreign_actors, index=1
                )
            ],
            [self.foreign_key],
        )

    def test_stable_cursor_is_resolved_only_among_visible_rows(self):
        with self.connect("postgres") as db:
            other = [self.historic(db, index=0) for _ in range(3)]
            hidden = self.historic(db)
        ordered = [self.key, *sorted(other, reverse=True)]
        self.assertEqual([row[0] for row in self.read(size=1)], ordered[:2])
        self.assertEqual(
            [row[0] for row in self.read(size=1, cursor=ordered[1])], ordered[2:]
        )
        self.assertEqual(self.read(cursor=ordered[-1]), [])
        for cursor in (self.foreign_key, hidden, uuid4()):
            self.assert_sqlstate("22023", self.read, cursor=cursor)
        for size in (None, 0, 101):
            self.assert_sqlstate("22023", self.read, size=size)
        self.assert_sqlstate("22023", self.read, cursor=self.key, item=self.key)

    def test_new_request_affordance_only_for_active_native_ordinary_user(self):
        self.assertTrue(self.can_request(self.target))
        for target in (
            None,
            uuid4(),
            self.foreign_actors[2][0],
            self.actors[1][0],
            self.actors[3][0],
        ):
            self.assertFalse(self.can_request(target))
        with self.connect("postgres") as db:
            db.execute(
                "UPDATE bri.auth_identity_links SET provider_type='enterprise_sso',provider_connection_id='fixture' "
                "WHERE auth_user_id=%s",
                (self.actors[2][1],),
            )
        self.assertFalse(self.can_request(self.target))
        self.assertFalse(self.read(index=1)[0][-1])
        with self.connect("postgres") as db:
            db.execute(
                "UPDATE bri.auth_identity_links SET provider_type='native',provider_connection_id=NULL "
                "WHERE auth_user_id=%s",
                (self.actors[2][1],),
            )
            db.execute(
                "UPDATE bri.auth_principals SET status='suspended' WHERE principal_id=%s",
                (self.target,),
            )
        self.assertFalse(self.can_request(self.target))
        self.assertFalse(self.read(index=1)[0][-1])

    def test_target_visibility_masks_approval_even_for_reviewer(self):
        self.assertTrue(self.read(index=1, item=self.key)[0][-1])
        with self.connect("postgres") as db:
            db.execute(
                "UPDATE bri.auth_tenant_memberships SET membership_type='superuser' "
                "WHERE principal_id=%s AND tenant_id=%s",
                (self.target, self.tenant),
            )
        self.assertFalse(self.can_request(self.target))
        self.assertFalse(self.read(index=1, item=self.key)[0][-1])
        with self.connect("postgres") as db:
            db.execute(
                "UPDATE bri.auth_tenant_memberships SET membership_type='admin' "
                "WHERE principal_id=%s AND tenant_id=%s",
                (self.target, self.tenant),
            )
        self.assertEqual(self.read(index=1, item=self.key), [])
        self.assertEqual(self.read(), [])
        self.assert_sqlstate("22023", self.read, index=1, cursor=self.key)

    def test_live_reviewer_and_original_request_session_are_independent(self):
        self.assertTrue(self.read(index=1)[0][-1])
        with self.connect("postgres") as db:
            db.execute(
                "UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() WHERE session_id=%s",
                (self.actors[0][2],),
            )
            self.refresh(db, self.actors, 0)
        self.assertFalse(self.read(index=1)[0][-1])
        self.assertEqual(
            len(self.read()), 1
        )  # current session may still inspect its own history
        with self.connect("postgres") as db:
            db.execute(
                "DELETE FROM bri.role_permissions WHERE tenant_id=%s AND role_id='reset' AND permission='user:mfa_reset:decide'",
                (self.tenant,),
            )
            self.refresh(db, self.actors, 1)
        self.assertEqual(self.read(index=1), [])

    def dispatch(self, factor):
        repo = ApprovalRepository(lambda: self.connect("bri_app"))
        ctx = self.context(self.tenant, self.actors[1])
        self.assertEqual(repo.decide(ctx, self.key, "APPROVE"), "APPROVED")
        with self.connect("bri_approval_worker") as db:
            ctx.bind(db)
            for op, ids in (
                ("BEGIN", None),
                ("PIN", [factor]),
                ("DISPATCH", [factor]),
            ):
                db.execute(
                    "SELECT * FROM bri.approval_work(%s,%s,%s,%s,%s::uuid[])",
                    (self.tenant, ACTION, self.key, op, ids),
                ).fetchone()

    def observe(self, result, present=None, verified=None):
        with self.connect("bri_approval_observer") as db:
            cid = uuid4()
            sql = "SELECT stage FROM bri.approval_observe(%s,%s,%s,%s::uuid[],%s::uuid[])"
            db.execute(sql, (self.key, "PLAN", cid, None, None)).fetchone()
            return db.execute(
                sql, (self.key, result, cid, present, verified)
            ).fetchone()[0]

    def test_reconciliation_labels_follow_a10_worker_and_observer(self):
        factor = uuid4()
        self.assertEqual(self.read(index=1)[0][6:], ("PENDING", "NONE", True))
        self.dispatch(factor)
        self.assertEqual(self.read(index=1)[0][6:], ("EXECUTING", "PENDING", False))
        self.assertFalse(self.can_request(self.target))

        self.assertEqual(self.observe("UNAVAILABLE"), "FAILED")
        unavailable = self.read(index=1)[0]
        self.assertEqual(unavailable[6:], ("FAILED", "UNRESOLVED", False))
        self.assertEqual(self.observe("RECORD", [factor], [factor]), "FAILED")
        self.assertEqual(self.read(index=1)[0], unavailable)
        self.assertEqual(self.observe("RECORD", [], []), "COMPLETED")
        self.assertEqual(
            self.read(index=1)[0][6:], ("COMPLETED", "VERIFIED_ABSENT", False)
        )

    def request_safe_handoff_continuation(self):
        factor, replacement = uuid4(), uuid4()
        self.dispatch(factor)
        self.assertEqual(
            self.observe("RECORD", [replacement], [replacement]), "FAILED"
        )
        (parent,) = self.read(index=1, item=self.key)
        self.assertEqual(parent[6:], ("FAILED", "SAFE_HANDOFF", False))
        self.assertFalse(self.can_request(self.target))
        return self.request(self.tenant, self.actors)

    def test_active_quarantined_safe_handoff_continuation_can_be_decided(self):
        continuation = self.request_safe_handoff_continuation()
        (review,) = self.read(index=1, item=continuation)
        self.assertEqual(
            review[:4], (continuation, self.target, "Visible account", "LOST_FACTOR")
        )
        self.assertEqual(self.read(item=continuation), [(*review[:-1], False)])
        self.assertEqual(
            self.read(
                tenant=self.foreign, actors=self.foreign_actors, index=1, item=continuation
            ),
            [],
        )
        self.assertFalse(self.can_request(self.target))

        repo = ApprovalRepository(lambda: self.connect("bri_app"))
        # Check the real A10 decision even if the earlier queue hint was wrong.
        self.assertEqual(
            repo.decide(
                self.context(self.tenant, self.actors[1]), continuation, "APPROVE"
            ),
            "APPROVED",
        )
        self.assertEqual(review[6:], ("PENDING", "NONE", True))

    def test_independent_suspension_blocks_safe_handoff_continuation(self):
        continuation = self.request_safe_handoff_continuation()
        with self.connect("postgres") as db:
            db.execute(
                "UPDATE bri.auth_principals SET status='suspended' WHERE principal_id=%s",
                (self.target,),
            )
        (review,) = self.read(index=1, item=continuation)
        self.assertFalse(self.can_request(self.target))
        repo = ApprovalRepository(lambda: self.connect("bri_app"))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            repo.decide(
                self.context(self.tenant, self.actors[1]), continuation, "APPROVE"
            )
        self.assertEqual(review[6:], ("PENDING", "NONE", False))

    def test_helpers_and_existing_worker_routines_are_not_app_callable(self):
        with self.connect("bri_app") as db:
            for routine in (
                "bri.mfa_reset_read_authority(text,uuid,uuid,text)",
                "bri.mfa_reset_eligible_identity(text,uuid,text,boolean)",
                "bri.mfa_reset_visible_page(text,uuid,uuid,text,boolean,boolean,uuid,timestamptz,uuid,integer)",
                "bri.approval_work(text,text,uuid,text,uuid[])",
                "bri.approval_observe(uuid,text,uuid,uuid[],uuid[])",
                "bri.approval_observation_queue(uuid,integer)",
            ):
                self.assertEqual(
                    db.execute(
                        "SELECT has_function_privilege(current_user,%s,'EXECUTE')",
                        (routine,),
                    ).fetchone(),
                    (False,),
                    routine,
                )

    def test_fail_closed_on_authority_and_current_quarantine(self):
        for kwargs in (
            {"index": 2},
            {"issuer": "wrong"},
            {"bound_uid": self.actors[1][1]},
            {"tenant": self.foreign},
        ):
            self.assert_sqlstate("42501", self.read, **kwargs)
            self.assert_sqlstate(
                "42501", self.can_request, target=self.target, **kwargs
            )
        with self.connect("postgres") as db:
            db.execute(
                "UPDATE bri.auth_role_assignments SET scope_node_id='leaf' WHERE principal_id=%s AND role_id='queue'",
                (self.actors[1][0],),
            )
            self.refresh(db, self.actors, 1)
        self.assertEqual(
            self.read(index=1), []
        )  # still a requester, but not a wide reviewer
        with self.connect("postgres") as db:
            p, u, _ = self.actors[0]
            db.execute(
                "INSERT INTO bri.credential_operations(operation_id,principal_id,auth_user_id,auth_issuer,kind) "
                "VALUES (%s,%s,%s,%s,'password_reset')",
                (uuid4(), p, u, ISSUER),
            )
            self.refresh(db, self.actors, 0)
        self.assert_sqlstate("42501", self.read)
        self.assert_sqlstate("42501", self.can_request, target=self.target)
        self.assertEqual(self.read(index=1), [])

    def test_expiry_is_projected_without_writing(self):
        with self.connect("postgres") as db:
            db.execute(
                "UPDATE bri.privileged_approvals SET state='APPROVED',reviewer=%s,"
                "created_at=now()-interval '25 hours',expires_at=now()-interval '1 hour' WHERE approval_id=%s",
                (self.actors[1][0], self.key),
            )
        self.assertEqual(self.read(index=1)[0][6:], ("EXPIRED", "NONE", False))
        with self.connect("postgres") as db:
            self.assertEqual(
                db.execute(
                    "SELECT state FROM bri.privileged_approvals WHERE approval_id=%s",
                    (self.key,),
                ).fetchone(),
                ("APPROVED",),
            )
            db.execute(
                "UPDATE bri.privileged_approvals SET state='PENDING',reviewer=NULL WHERE approval_id=%s",
                (self.key,),
            )
        self.assertEqual(self.read()[0][6:], ("EXPIRED", "NONE", False))
        with self.connect("postgres") as db:
            self.assertEqual(
                db.execute(
                    "SELECT state FROM bri.privileged_approvals WHERE approval_id=%s",
                    (self.key,),
                ).fetchone(),
                ("PENDING",),
            )
            self.assertEqual(
                db.execute(
                    "SELECT count(*) FROM bri.approval_events WHERE approval_id=%s",
                    (self.key,),
                ).fetchone(),
                (1,),
            )
