"""A11.5 integration tests: private PostgreSQL 16, no external DSN."""
import os
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

import psycopg
from psycopg import sql
import test_permission_delegation_postgres as delegation
import test_privileged_approvals_pg as fixtures

ISSUER = fixtures.ISSUER
READ = 'SELECT * FROM bri.read_user_deactivation(%s,%s,%s,%s,%s)'
CHANGE = 'SELECT * FROM bri.deactivate_user_account(%s,%s,%s,%s,%s,%s,%s,%s,%s)'
ROUTINES = (
    'bri.read_user_deactivation(text,uuid,uuid,text,uuid)',
    'bri.deactivate_user_account(text,uuid,uuid,text,uuid,bigint,text,timestamptz,uuid)',
)


@unittest.skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16')
class UserDeactivationTests(unittest.TestCase):
    @classmethod
    def connect(cls, role, **kwargs):
        return fixtures.ApprovalDatabase.connect.__func__(cls, role, options='-c timezone=UTC', **kwargs)

    @classmethod
    def setUpClass(cls):
        # Applies and verifies the complete checksummed ledger, then proves replay is a no-op.
        with patch.dict(os.environ, BRI_APPROVAL_PG_BIN=os.environ['BRI_TEST_PG_BIN']):
            fixtures.ApprovalDatabase.setUpClass.__func__(cls)
        with cls.connect('bri_app') as db:
            for routine in (*ROUTINES, *delegation.ROUTINES):
                assert db.execute("SELECT has_function_privilege(current_user,%s,'EXECUTE')",
                                  (routine,)).fetchone() == (False,), routine
                assert db.execute("SELECT NOT EXISTS (SELECT FROM pg_proc p, "
                                  "aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a "
                                  "WHERE p.oid=%s::regprocedure AND a.grantee=0 AND a.privilege_type='EXECUTE')",
                                  (routine,)).fetchone() == (True,), routine
        with cls.connect('postgres') as db:
            db.execute('INSERT INTO bri.provider_event_source (issuer) VALUES (%s)', (ISSUER,))
            assert db.execute("SELECT count(*) FROM bri.role_permissions WHERE permission='user:deactivate'").fetchone() == (0,)
            protected = ['auth_principals', 'auth_tenant_memberships', 'auth_role_assignments', 'auth_sessions',
                         'security_audit_events', 'user_lifecycle_state', 'user_delegation_state']
            assert db.execute("SELECT count(*) FROM pg_class WHERE relnamespace='bri'::regnamespace "
                              'AND relname=ANY(%s) AND relrowsecurity AND relforcerowsecurity',
                              (protected,)).fetchone() == (len(protected),)
            for routine in (*ROUTINES, *delegation.ROUTINES):
                db.execute(f'GRANT EXECUTE ON FUNCTION {routine} TO bri_app')
            db.execute('CREATE ROLE bri_provision_activator LOGIN NOINHERIT; '
                       'GRANT USAGE ON SCHEMA bri TO bri_provision_activator; '
                       'GRANT EXECUTE ON FUNCTION bri.activate_user_provisioning(text,uuid,timestamptz,timestamptz,uuid) '
                       'TO bri_provision_activator')

    def setUp(self):
        self.tenant, self.actors = fixtures.seed_approval_tenant(self.connect)
        self.foreign_tenant, self.foreign_actors = fixtures.seed_approval_tenant(self.connect)
        with self.connect('postgres') as db:
            self.grant_deactivation(db, self.tenant, self.actors[0][0])
            for actors in (self.actors, self.foreign_actors):
                for index, (principal, uid, _) in enumerate(actors):
                    actors[index] = (principal, uid, uuid4())
                    db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                               'VALUES (%s,%s,%s,clock_timestamp())', actors[index])
        self.actor = self.actors[0]
        self.target, self.target_uid, self.target_sid = self.actors[2]

    @staticmethod
    def grant_deactivation(db, tenant, actor):
        db.execute("INSERT INTO bri.app_roles VALUES (%s,'deactivation','Deactivation')", (tenant,))
        db.execute("INSERT INTO bri.role_permissions VALUES (%s,'deactivation','user:deactivate')", (tenant,))
        db.execute("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) "
                   "VALUES (%s,%s,'deactivation','root')", (tenant, actor))

    def args(self, db, *, tenant=None, actor=None, target=None, issuer=ISSUER):
        tenant = self.tenant if tenant is None else tenant
        principal, uid, sid = actor or self.actor
        db.execute("SELECT set_config('bri.tenant_id',%s,true),set_config('bri.auth_user_id',%s,true)",
                   (tenant, str(uid)))
        return tenant, principal, sid, issuer, self.target if target is None else target

    def read(self, **kwargs):
        with self.connect('bri_app') as db:
            db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            return db.execute(READ, self.args(db, **kwargs)).fetchone()

    def run_change(self, db, version, *, reason='account_closed', stamp=True, correlation=True, **kwargs):
        return db.execute(CHANGE, (*self.args(db, **kwargs), version, reason,
                                  datetime.now(UTC) if stamp is True else stamp,
                                  uuid4() if correlation is True else correlation)).fetchone()

    def change(self, version, **kwargs):
        with self.connect('bri_app') as db:
            return self.run_change(db, version, **kwargs)

    def test_deactivate_ordinary_account(self):
        before, status = self.read()
        self.assertEqual(status, 'active')
        after, status = self.change(before)
        self.assertEqual(status, 'deactivated')
        self.assertGreater(after, before)
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT p.status,m.status FROM bri.auth_principals p '
                                       'JOIN bri.auth_tenant_memberships m USING (principal_id) '
                                       'WHERE p.principal_id=%s', (self.target,)).fetchone(),
                             ('deactivated', 'deactivated'))
        self.assertEqual(self.read(), (after, 'deactivated'))
        with self.assertRaises(psycopg.errors.SerializationFailure):
            self.change(before)
        with self.assertRaises(psycopg.errors.ObjectNotInPrerequisiteState):
            self.change(after)

    def test_wrong_authority_and_unavailable_targets(self):
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.read(tenant=self.foreign_tenant, actor=self.foreign_actors[0], target=self.foreign_actors[2][0])
        for actor in (self.foreign_actors[0], self.actors[2], self.actors[3]):
            with self.subTest(actor=actor), self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self.read(actor=actor)
        for target in (uuid4(), self.foreign_actors[2][0], self.actor[0], self.actors[1][0], self.actors[3][0]):
            with self.subTest(target=target):
                self.assertIsNone(self.read(target=target))
                self.assertIsNone(self.change(-1, target=target))
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT count(*) FROM bri.governance_eligible WHERE tenant_id=%s',
                                        (self.tenant,)).fetchone(), (2,))
            db.execute("INSERT INTO bri.org_nodes VALUES (%s,'leaf','team','Leaf','root')", (self.tenant,))
            db.execute("UPDATE bri.auth_role_assignments SET scope_node_id='leaf' "
                       "WHERE principal_id=%s AND role_id='deactivation'", (self.actor[0],))
            self.actor = self.refresh_session(db, self.actor)
        with self.connect('bri_app') as db:
            self.args(db)
            self.assertEqual(db.execute('SELECT bri.client_is_operational(%s)', (self.tenant,)).fetchone(), (True,))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.read()

    def test_two_tenants_with_independent_authority(self):
        foreign_target = self.foreign_actors[2][0]
        with self.connect('postgres') as db:
            self.grant_deactivation(db, self.foreign_tenant, self.foreign_actors[0][0])
            foreign_actor = self.refresh_session(db, self.foreign_actors[0])
        local = self.read()
        args = dict(tenant=self.foreign_tenant, actor=foreign_actor, target=foreign_target)
        version, status = self.read(**args)
        self.assertEqual(status, 'active')
        self.assertIsNone(self.change(-1, **{**args, 'target': self.target}))
        self.assertEqual(self.change(version, **args)[1], 'deactivated')
        self.assertEqual(self.read(), local)

    def test_exact_session_and_freshness(self):
        actor, uid, sid = self.actor
        for kwargs in ({'issuer': ISSUER + '/wrong'}, {'actor': (actor, uid, uuid4())},
                       {'actor': (self.actors[1][0], uid, sid)}, {'tenant': self.foreign_tenant}):
            with self.subTest(kwargs=kwargs), self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self.read(**kwargs)
        version, _ = self.read()
        now = datetime.now(UTC)
        for stamp in (None, 'infinity', now - timedelta(minutes=15), now + timedelta(minutes=1)):
            with self.subTest(stamp=stamp), self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self.change(version, stamp=stamp)
        with self.connect('postgres') as db:
            db.execute('UPDATE bri.session_guards SET latest_provider_change=clock_timestamp() WHERE principal_id=%s', (actor,))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.change(version, stamp=now)
        self.assertEqual(self.read(), (version, 'active'))
        with self.connect('postgres') as db:
            db.execute('UPDATE bri.session_guards SET primary_after=clock_timestamp() WHERE principal_id=%s', (actor,))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.read()

    def test_invalid_input_and_revision_change(self):
        version, _ = self.read()
        for kwargs in ({'reason': 'personally identifying free text'}, {'reason': None}, {'correlation': None}):
            with self.subTest(kwargs=kwargs), self.assertRaises(psycopg.errors.InvalidParameterValue):
                self.change(version, **kwargs)
        with self.connect('bri_app') as db:
            db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
            with self.assertRaises(psycopg.errors.ObjectNotInPrerequisiteState), db.transaction():
                self.run_change(db, version)
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_principals SET display_name='Changed' WHERE principal_id=%s", (self.target,))
        with self.assertRaises(psycopg.errors.SerializationFailure):
            self.change(version)
        latest, status = self.read()
        self.assertEqual(status, 'active')
        self.assertGreater(latest, version)
        self.assertEqual(self.change(latest, reason='policy_violation')[1], 'deactivated')

    def refresh_session(self, db, actor):
        result = (*actor[:2], uuid4())
        db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                   'VALUES (%s,%s,%s,clock_timestamp())', result)
        return result

    def lifecycle(self, action, version, reason, *, target=None):
        with self.connect('bri_app') as db:
            args = self.args(db, target=target)
            return db.execute('SELECT * FROM bri.change_user_lifecycle(%s,%s,%s,%s,%s,%s,%s,NULL,%s,%s,%s)',
                              (*args, action, version, reason, datetime.now(UTC), uuid4())).fetchone()

    def test_only_normal_administrative_suspension_is_eligible(self):
        foreign = self.foreign_actors[2][0]
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.role_permissions VALUES (%s,'reset','user:suspend'),"
                       "(%s,'reset','user:reactivate')", (self.tenant, self.tenant))
            self.actor = self.refresh_session(db, self.actor)
            db.execute("UPDATE bri.auth_tenant_memberships SET membership_type='superuser' WHERE principal_id=%s", (self.target,))
            db.execute("UPDATE bri.auth_principals SET status='suspended' WHERE principal_id=%s", (self.target,))
        self.assertIsNone(self.read())
        self.assertIsNone(self.change(-1))
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_principals SET status='active' WHERE principal_id=%s", (self.target,))
        version, _ = self.read()
        suspended = self.lifecycle('suspend', version, 'temporary_leave')
        self.assertEqual(self.read(), (suspended[4], 'suspended'))
        # Existing nonterminal A11.3 transitions must still work normally.
        restored = self.lifecycle('reactivate', suspended[4], 'access_restored')
        self.assertEqual(restored[2], 'active')
        suspended = self.lifecycle('suspend', restored[4], 'temporary_leave')
        terminal = self.change(suspended[4], reason='access_review')
        self.assertEqual(terminal[1], 'deactivated')
        self.assertIsNone(self.lifecycle('reactivate', terminal[0], 'access_restored'))
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT status FROM bri.auth_principals WHERE principal_id=%s', (foreign,)).fetchone(), ('active',))
            self.assertEqual(db.execute('SELECT suspension_tenant FROM bri.user_lifecycle_state WHERE principal_id=%s',
                                        (self.target,)).fetchone(), (None,))

    def test_pending_deletion_external_and_quarantine_are_unavailable(self):
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_principals SET status='pending' WHERE principal_id=%s", (self.target,))
        self.assertIsNone(self.read())
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_principals SET status='active',deletion_requested_at=clock_timestamp() WHERE principal_id=%s",
                       (self.target,))
        self.assertIsNone(self.change(-1))
        with self.connect('postgres') as db:
            db.execute('UPDATE bri.auth_principals SET deletion_requested_at=NULL WHERE principal_id=%s', (self.target,))
            db.execute("UPDATE bri.auth_identity_links SET provider_type='enterprise_sso',provider_connection_id='external' "
                       'WHERE principal_id=%s', (self.target,))
        self.assertIsNone(self.change(-1))
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_identity_links SET provider_type='native',provider_connection_id=NULL "
                       'WHERE principal_id=%s', (self.target,))
            db.execute("INSERT INTO bri.credential_operations(operation_id,principal_id,auth_user_id,auth_issuer,kind) "
                       "VALUES (%s,%s,%s,%s,'factor_reenrollment')", (uuid4(), self.target, self.target_uid, ISSUER))
        self.assertIsNone(self.read())
        self.assertIsNone(self.change(-1))

    def run_delegation(self, action, version, permission=delegation.ORG):
        with self.connect('bri_app') as db:
            args = self.args(db)
            return db.execute(delegation.CHANGE, (*args, 'leaf', permission, action, version,
                                                 datetime.now(UTC), uuid4())).fetchone()

    def seed_grants(self):
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.org_nodes VALUES (%s,'leaf','team','Leaf','root')", (self.tenant,))
            delegation.seed_delegation_catalog(db, self.tenant, self.actor[0])
            db.execute("INSERT INTO bri.app_roles VALUES (%s,'legacy','Legacy'),(%s,'history','History')", (self.tenant,)*2)
            db.execute("INSERT INTO bri.role_permissions VALUES (%s,'legacy','document:read')", (self.tenant,))
            db.execute("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id,status,assigned_by_principal_id) "
                       "VALUES (%s,%s,'legacy','leaf','active',%s),(%s,%s,'history','leaf','revoked',%s)",
                       (self.tenant, self.target, self.actor[0])*2)
        self.assertEqual(self.run_delegation('grant', 0), (1, True))
        self.assertEqual(self.run_delegation('grant', 0, delegation.KNOWLEDGE), (1, True))
        self.assertEqual(self.run_delegation('revoke', 1, delegation.KNOWLEDGE), (2, False))
        with self.connect('postgres') as db:
            _, _, self.target_sid = self.refresh_session(db, self.actors[2])

    def observed_state(self):
        with self.connect('postgres') as db:
            return tuple(db.execute(query, (self.target,)).fetchall() for query in (
                'SELECT * FROM bri.auth_principals WHERE principal_id=%s',
                'SELECT * FROM bri.auth_tenant_memberships WHERE principal_id=%s',
                'SELECT * FROM bri.auth_identity_links WHERE principal_id=%s',
                'SELECT * FROM bri.user_lifecycle_state WHERE principal_id=%s',
                'SELECT * FROM bri.session_guards WHERE principal_id=%s',
                'SELECT * FROM bri.auth_sessions WHERE principal_id=%s ORDER BY session_id',
                'SELECT * FROM bri.auth_role_assignments WHERE principal_id=%s ORDER BY role_id,scope_node_id',
                'SELECT * FROM bri.user_delegation_state WHERE principal_id=%s ORDER BY permission',
                'SELECT * FROM bri.security_audit_events WHERE subject_principal_id=%s ORDER BY event_id',
            ))

    def test_retirement_preserves_native_rows_and_reconciles_delegation(self):
        self.seed_grants()
        with self.connect('bri_app') as db:
            self.args(db, actor=(self.target, self.target_uid, self.target_sid))
            self.assertEqual(db.execute("SELECT role_id FROM bri.auth_role_assignments WHERE status='active' ORDER BY role_id").fetchall(),
                             [('delegation-org',), ('legacy',)])
        before = self.observed_state()
        correlation = uuid4()
        terminal = self.change(self.read()[0], correlation=correlation)
        after = self.observed_state()
        self.assertEqual(before[2], after[2])  # identity binding retained byte-for-byte
        self.assertEqual([(r[:4], r[5:]) for r in before[6]], [(r[:4], r[5:]) for r in after[6]])
        self.assertEqual([(r[2], r[4]) for r in after[6]],
                         [('delegation-org', 'revoked'), ('history', 'revoked'), ('legacy', 'revoked')])
        self.assertEqual([(r[3], r[4], r[5]) for r in after[7]],
                         [('knowledge:read', 2, False), ('organisation:read', 2, False)])
        self.assertTrue(set(before[8]).issubset(after[8]))
        with self.connect('postgres') as db:
            events = db.execute('SELECT tenant_id,actor_principal_id,subject_principal_id,event_type,outcome,lifecycle_reason '
                                'FROM bri.security_audit_events WHERE request_id=%s', (correlation,)).fetchall()
            self.assertEqual([event for event in events if event[3] == 'tenant.user.lifecycle.deactivated'],
                             [(self.tenant, self.actor[0], self.target, 'tenant.user.lifecycle.deactivated', 'success', 'account_closed')])
            self.assertEqual(sum(e[3] == 'auth.session.revoked' for e in events), 1)
            self.assertTrue(all(e[:3] == (self.tenant, self.actor[0], self.target) for e in events))
            self.assertEqual(db.execute('SELECT revoked_at IS NOT NULL FROM bri.auth_sessions WHERE session_id=%s',
                                        (self.target_sid,)).fetchone(), (True,))
            self.assertEqual(db.execute('SELECT count(*) FROM bri.governance_eligible WHERE tenant_id=%s',
                                        (self.tenant,)).fetchone(), (2,))
            with self.assertRaisesRegex(psycopg.errors.RaiseException, 'immutable'), db.transaction():
                db.execute('DELETE FROM bri.security_audit_events WHERE request_id=%s', (correlation,))
        self.assertIsNone(self.run_delegation('grant', 2))
        self.assertEqual(self.read(), terminal)
        with self.connect('bri_app') as db:
            self.args(db, actor=(self.target, self.target_uid, self.target_sid))
            self.assertFalse(db.execute('SELECT bri.client_is_operational(%s)', (self.tenant,)).fetchone()[0])
            self.assertEqual(db.execute('SELECT role_id FROM bri.auth_role_assignments').fetchall(), [])

    def test_permission_is_not_delegable(self):
        self.seed_grants()
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.run_delegation('grant', 0, 'user:deactivate')
        with self.connect('bri_app') as db:
            self.args(db)
            with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                db.execute("INSERT INTO bri.role_permissions VALUES (%s,'reset','user:deactivate')", (self.tenant,))
            db.execute("INSERT INTO bri.org_nodes VALUES (%s,'new-team','team','Team','root')", (self.tenant,))
            with self.assertRaisesRegex(psycopg.errors.InsufficientPrivilege, 'deactivation root topology'), db.transaction():
                db.execute("INSERT INTO bri.org_nodes VALUES (%s,'another-root','root','Root',NULL)", (self.tenant,))

    def test_retired_deactivation_grant_does_not_freeze_root_topology(self):
        insert_root = "INSERT INTO bri.org_nodes VALUES (%s,'another-root','root','Root',NULL)"
        with self.connect('bri_app') as db:
            self.args(db)
            with self.assertRaisesRegex(psycopg.errors.InsufficientPrivilege, 'deactivation root topology'), db.transaction():
                db.execute(insert_root, (self.tenant,))
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_role_assignments SET status='revoked' WHERE tenant_id=%s "
                       "AND principal_id=%s AND role_id='deactivation'", (self.tenant, self.actor[0]))
        with self.connect('bri_app') as db:
            self.args(db)
            with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                db.execute(insert_root, (self.foreign_tenant,))
            db.execute(insert_root, (self.tenant,))
            with self.assertRaises(psycopg.errors.ForeignKeyViolation), db.transaction():
                db.execute("DELETE FROM bri.org_nodes WHERE tenant_id=%s AND node_id='root'", (self.tenant,))
        with self.connect('postgres') as db:
            self.assertEqual(db.execute("SELECT scope_node_id,status FROM bri.auth_role_assignments "
                                        "WHERE tenant_id=%s AND principal_id=%s AND role_id='deactivation'",
                                        (self.tenant, self.actor[0])).fetchall(), [('root', 'revoked')])

    def test_terminal_rows_reject_restoration_and_alternate_starts(self):
        self.seed_grants()
        with self.connect('bri_app') as db:
            self.assertIsNotNone(self.start(db, uuid4(), structured=True))
        self.change(self.read()[0])
        for statement, args in (
            ("UPDATE bri.auth_principals SET status='active' WHERE principal_id=%s", (self.target,)),
            ("UPDATE bri.auth_tenant_memberships SET status='pending' WHERE principal_id=%s", (self.target,)),
            ("INSERT INTO bri.auth_tenant_memberships(tenant_id,principal_id,status) VALUES (%s,%s,'active')",
             (self.foreign_tenant, self.target)),
            ("UPDATE bri.auth_role_assignments SET status='active' WHERE principal_id=%s", (self.target,)),
            ("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) VALUES (%s,%s,'reset','root')",
             (self.tenant, self.target)),
            ('DELETE FROM bri.auth_role_assignments WHERE principal_id=%s', (self.target,)),
            ('INSERT INTO bri.platform_superadmins(principal_id) VALUES (%s)', (self.target,)),
        ):
            with self.subTest(statement=statement), self.connect('postgres') as db:
                with self.assertRaises(psycopg.errors.ObjectNotInPrerequisiteState), db.transaction():
                    db.execute(statement, args)
        with self.connect('bri_app') as db:
            for structured in (True, False):
                for sid in (self.target_sid, uuid4()):
                    self.assertIsNone(self.start(db, sid, structured=structured))
            self.assertEqual(db.execute('SELECT bri.reserve_password_recovery(%s,%s,%s)',
                                        (uuid4(), uuid4(), datetime.now(UTC))).fetchone(), (False,))
            with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                db.execute('INSERT INTO bri.auth_sessions(auth_user_id,principal_id,session_id) VALUES (%s,%s,%s)',
                           (self.target_uid, self.target, uuid4()))

    def test_provisioning_history_survives_and_cannot_restore(self):
        with self.connect('postgres') as db:
            db.execute('INSERT INTO bri.user_provisioning(tenant_id,request_key,principal_id,actor_id,actor_user,'
                       'actor_session,actor_totp_at,expected_issuer,email_digest,status,dispatch_at,attempt_id,provider_user) '
                       "VALUES (%s,%s,%s,%s,%s,%s,clock_timestamp(),%s,decode('ab','hex'),'active',"
                       "clock_timestamp()-interval '1 minute',gen_random_uuid(),%s)",
                       (self.tenant, uuid4(), self.target, *self.actor, ISSUER, self.target_uid))
            before = db.execute('SELECT * FROM bri.user_provisioning WHERE principal_id=%s', (self.target,)).fetchone()

        def replay_activation():
            with self.connect('bri_provision_activator') as db:
                stamp = datetime.now(UTC)
                return db.execute('SELECT * FROM bri.activate_user_provisioning(%s,%s,%s,%s,%s)',
                                  (ISSUER, self.target_uid, stamp, stamp, uuid4())).fetchone()

        self.assertEqual(replay_activation(), (self.target, 'active'))
        final = self.change(self.read()[0])
        self.assertIsNone(replay_activation())
        self.assertEqual(self.read(), final)
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT * FROM bri.user_provisioning WHERE principal_id=%s',
                                        (self.target,)).fetchone(), before)

    def start(self, db, sid, *, structured):
        self.args(db, actor=(self.target, self.target_uid, self.target_sid))
        primary = datetime.now(UTC)
        if structured:
            return db.execute('SELECT bri.start_security_session(%s,%s,%s,%s,%s)',
                              (ISSUER, sid, primary, primary, uuid4())).fetchone()[0]
        return db.execute('SELECT bri.start_security_session(%s,%s,%s,%s)', (ISSUER, sid, primary, uuid4())).fetchone()[0]

    def test_audit_failure_rolls_back_all_changes(self):
        self.seed_grants()
        before = self.observed_state()
        version = self.read()[0]
        correlation = uuid4()
        with self.connect('postgres') as db:
            # Fail only the final event, after A10 session/access audit and all state changes.
            db.execute(sql.SQL("ALTER TABLE bri.security_audit_events ADD CONSTRAINT fixture_deny_deactivation "
                               "CHECK (event_type <> 'tenant.user.lifecycle.deactivated' OR request_id <> {}) NOT VALID")
                       .format(sql.Literal(correlation)))
        with self.assertRaises(psycopg.errors.CheckViolation) as failure:
            self.change(version, correlation=correlation)
        self.assertEqual(failure.exception.diag.constraint_name, 'fixture_deny_deactivation')
        self.assertEqual(self.observed_state(), before)
        with self.connect('postgres') as db:
            db.execute('ALTER TABLE bri.security_audit_events DROP CONSTRAINT fixture_deny_deactivation')
        self.assertEqual(self.change(version, correlation=correlation)[1], 'deactivated')

    def await_blocked(self, observer, writer, waiter):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if observer.execute('SELECT %s = ANY(pg_blocking_pids(%s))',
                                (writer.info.backend_pid, waiter.info.backend_pid)).fetchone()[0]:
                return
            time.sleep(0.02)
        writer.rollback()
        self.fail('waiter did not block on the expected transaction')

    def test_role_keys_are_acquired_before_session_guards(self):
        self.seed_grants()
        initial = self.read()[0]
        with self.connect('postgres') as locker, self.connect('bri_app') as contender, \
             self.connect('postgres', autocommit=True) as observer:
            # Hold the last sorted role key. Starting a session while the
            # deactivation waits on that key must not wait on its target guard.
            locker.execute('SELECT pg_advisory_xact_lock(max(hashtextextended(json_build_array(tenant_id,role_id)::text,17811))) '
                           'FROM bri.auth_role_assignments WHERE principal_id=%s', (self.target,))
            contender.execute("SET LOCAL statement_timeout='10s'")
            with ThreadPoolExecutor(max_workers=1) as pool:
                result = pool.submit(self.run_change, contender, initial)
                self.await_blocked(observer, locker, contender)
                with self.connect('bri_app') as db:
                    db.execute("SET LOCAL statement_timeout='2s'")
                    sid = uuid4()
                    self.assertIsNotNone(self.start(db, sid, structured=True))
                locker.commit()
                self.assertEqual(result.result(timeout=10)[1], 'deactivated')
            contender.commit()
            self.assertEqual(observer.execute('SELECT revoked_at IS NOT NULL FROM bri.auth_sessions WHERE session_id=%s',
                                              (sid,)).fetchone(), (True,))

    def test_concurrent_deactivation_and_fresh_start_serialize(self):
        self.seed_grants()
        initial = self.read()[0]
        with self.connect('bri_app') as writer, self.connect('bri_app') as contender, \
             self.connect('bri_app') as starter, self.connect('postgres', autocommit=True) as observer:
            result = self.run_change(writer, initial)
            self.assertEqual(self.read(), (initial, 'active'))
            # Limit waits even on assertion failures. Each worker owns a distinct DB connection.
            for db in (contender, starter):
                db.execute("SET LOCAL statement_timeout='10s'")

            def try_start():
                result = self.start(starter, uuid4(), structured=True)
                starter.commit()  # Release the target guard acquired even on denial.
                return result

            with ThreadPoolExecutor(max_workers=2) as pool:
                concurrent_change = pool.submit(self.run_change, contender, initial)
                concurrent_start = pool.submit(try_start)
                self.await_blocked(observer, writer, contender)
                self.await_blocked(observer, writer, starter)
                writer.commit()
                with self.assertRaises(psycopg.errors.SerializationFailure):
                    concurrent_change.result(timeout=10)
                self.assertIsNone(concurrent_start.result(timeout=10))
            self.assertEqual(self.read(), result)
            self.assertEqual(observer.execute("SELECT count(*) FROM bri.security_audit_events "
                                              "WHERE subject_principal_id=%s AND event_type='tenant.user.lifecycle.deactivated'",
                                              (self.target,)).fetchone(), (1,))
