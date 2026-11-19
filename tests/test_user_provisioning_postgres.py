"""A11.2 on the private native PG16 fixture (BRI_TEST_PG_BIN, no DSN)."""
import os
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

import psycopg
import test_privileged_approvals_pg as fixtures

ISSUER = fixtures.ISSUER
EMAIL = 'new-user@example.test'
REQUEST = 'SELECT * FROM bri.request_user_provisioning(%s,%s,%s,%s,%s,%s,%s,%s,%s)'
STATUS = 'SELECT * FROM bri.status_user_provisioning(%s,%s,%s,%s,%s)'
WORK = 'SELECT * FROM bri.work_user_provisioning(%s,%s,%s,%s,%s)'
ACTIVATE = 'SELECT * FROM bri.activate_user_provisioning(%s,%s,%s,%s,%s)'


@unittest.skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16')
class UserProvisioningTests(unittest.TestCase):
    connect = classmethod(fixtures.ApprovalDatabase.connect.__func__)

    @classmethod
    def setUpClass(cls):
        with patch.dict(os.environ, BRI_APPROVAL_PG_BIN=os.environ['BRI_TEST_PG_BIN']):
            fixtures.ApprovalDatabase.setUpClass.__func__(cls)
        with cls.connect('bri_migrator') as db:
            db.execute('INSERT INTO bri.provider_event_source (issuer) VALUES (%s)', (ISSUER,))
        with cls.connect('postgres') as db:
            db.execute('CREATE ROLE bri_provision_worker LOGIN NOINHERIT; '
                       'CREATE ROLE bri_provision_activator LOGIN NOINHERIT; '
                       'GRANT USAGE ON SCHEMA bri TO bri_provision_worker,bri_provision_activator')
        with cls.connect('bri_migrator') as db:
            for role, signature in (
                ('bri_provision_worker', 'work_user_provisioning(uuid,text,text,uuid,uuid)'),
                ('bri_provision_activator', 'activate_user_provisioning(text,uuid,timestamptz,timestamptz,uuid)'),
            ):
                if db.execute('SELECT to_regprocedure(%s)', ('bri.' + signature,)).fetchone()[0]:
                    db.execute(f'GRANT EXECUTE ON FUNCTION bri.{signature} TO {role}')

    def setUp(self):
        self.tenant, self.actors = fixtures.seed_approval_tenant(self.connect)
        self.foreign, self.foreign_actors = fixtures.seed_approval_tenant(self.connect)
        self.key = uuid4()
        self.actor = self.grant(self.tenant, self.actors[0])

    def grant(self, tenant, actor, scope='root'):
        principal, user, _ = actor
        sid = uuid4()
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.app_roles VALUES (%s,'provision','Provision') ON CONFLICT DO NOTHING", (tenant,))
            db.execute("INSERT INTO bri.role_permissions VALUES (%s,'provision','user:provision:create') "
                       'ON CONFLICT DO NOTHING', (tenant,))
            db.execute("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) "
                       "VALUES (%s,%s,'provision',%s)", (tenant, principal, scope))
            db.execute('INSERT INTO bri.auth_sessions(auth_user_id,principal_id,session_id) VALUES (%s,%s,%s)',
                       (user, principal, sid))
        return principal, user, sid

    def app(self, db, *, tenant=None, actor=None):
        p, u, sid = actor or self.actor
        tenant = tenant or self.tenant
        db.execute("SELECT set_config('bri.tenant_id',%s,true),set_config('bri.auth_user_id',%s,true)", (tenant, str(u)))
        return tenant, p, sid, ISSUER

    def request(self, *, key=None, email=EMAIL, tenant=None, actor=None, stamp=None):
        with self.connect('bri_app') as db:
            args = self.app(db, tenant=tenant, actor=actor)
            return db.execute(REQUEST, (*args, stamp or datetime.now(UTC), key or self.key,
                                        'New User', email, uuid4())).fetchone()

    def test_authorized_request_durably_creates_only_a_pending_user(self):
        identifier, status = self.request()
        self.assertEqual(status, 'pending_setup')
        self.assertEqual(self.request(email=' NEW-USER@EXAMPLE.TEST '), (identifier, status))
        with self.connect('bri_app') as db:
            db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            self.assertEqual(db.execute(STATUS, (*self.app(db), self.key)).fetchall(), [(identifier, status)])
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT p.status,m.status,m.membership_type,p.display_name '
                                        'FROM bri.auth_principals p JOIN bri.auth_tenant_memberships m USING (principal_id) '
                                        'WHERE p.principal_id=%s', (identifier,)).fetchall(),
                             [('pending', 'pending', 'user', 'New User')])
            for table in ('auth_identity_links', 'auth_role_assignments', 'auth_sessions'):
                self.assertEqual(db.execute(f'SELECT count(*) FROM bri.{table} WHERE principal_id=%s',
                                            (identifier,)).fetchone(), (0,))

    def test_wrong_stale_or_missing_authority_fails_closed(self):
        for actor in (self.actors[1], self.grant(self.tenant, self.actors[2]),
                      self.grant(self.tenant, self.actors[3])):
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self.request(actor=actor)
        for stamp in (datetime.now(UTC) - timedelta(minutes=16), datetime.now(UTC) + timedelta(minutes=1)):
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self.request(stamp=stamp)
        with self.connect('bri_app') as db:
            args = (self.tenant, self.actor[0], self.actor[2], ISSUER)
            with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                db.execute(STATUS, (*args, self.key))
            self.app(db)
            for forged in ((self.foreign, *args[1:]), (args[0], uuid4(), *args[2:]),
                           (*args[:2], uuid4(), args[3]), (*args[:3], ISSUER + '/wrong')):
                with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                    db.execute(STATUS, (*forged, self.key))

    def work(self, identifier, action, attempt, uid=None, issuer=ISSUER):
        with self.connect('bri_provision_worker') as db:
            return db.execute(WORK, (identifier, action, issuer, uid, attempt)).fetchone()

    def activate(self, uid, primary=None, totp=None, issuer=ISSUER):
        with self.connect('bri_provision_activator') as db:
            return db.execute(ACTIVATE, (issuer, uid, primary or datetime.now(UTC),
                                         totp or datetime.now(UTC), uuid4())).fetchone()

    def test_worker_attempts_are_fenced_and_only_a_new_claim_discloses_email(self):
        identifier, _ = self.request()
        first, second, third, uid = uuid4(), uuid4(), uuid4(), uuid4()
        self.assertEqual(self.work(identifier, 'CLAIM', first), (identifier, 'inviting', EMAIL))
        self.assertEqual(self.work(identifier, 'CLAIM', first), (identifier, 'inviting', None))
        self.assertEqual(self.work(identifier, 'CLAIM', second), (identifier, 'inviting', None))
        for attempt in (first, second):
            if attempt == second:
                self.assertEqual(self.work(identifier, 'CLAIM', second), (identifier, 'inviting', EMAIL))
            self.assertEqual(self.work(identifier, 'RETRYABLE', attempt), (identifier, 'invitation_retryable', None))
        self.assertEqual(self.work(identifier, 'CLAIM', first), (identifier, 'invitation_retryable', None))
        self.assertEqual(self.work(identifier, 'CLAIM', third), (identifier, 'inviting', EMAIL))
        for action in ('INVITED', 'RECONCILED_INVITED', 'UNRESOLVED', 'RETRYABLE'):
            with self.subTest(action=action), self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self.work(identifier, action, first, uid if action.endswith('INVITED') else None)
        self.assertEqual(self.work(identifier, 'UNRESOLVED', third), (identifier, 'invitation_unresolved', None))
        self.assertEqual(self.work(identifier, 'CLAIM', uuid4()), (identifier, 'invitation_unresolved', None))
        self.assertEqual(self.work(identifier, 'RECONCILED_INVITED', third, uid), (identifier, 'invitation_sent', None))

    def test_activation_is_exact_and_does_not_start_a_session_or_grant_roles(self):
        identifier, _ = self.request()
        attempt, uid = uuid4(), uuid4()
        before = datetime.now(UTC)
        self.work(identifier, 'CLAIM', attempt)
        self.assertIsNone(self.activate(uid))
        self.assertEqual(self.work(identifier, 'INVITED', attempt, uid), (identifier, 'invitation_sent', None))
        self.assertIsNone(self.activate(uuid4()))
        self.assertIsNone(self.activate(uid, primary=before))
        self.assertIsNone(self.activate(uid, totp=before))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.activate(uid, issuer=ISSUER + '/wrong')
        with self.connect('bri_app') as db:
            db.execute("SELECT set_config('bri.auth_user_id',%s,true)", (str(uid),))
            self.assertEqual(db.execute('SELECT bri.start_security_session(%s,%s,clock_timestamp(),%s)',
                                        (ISSUER, uuid4(), uuid4())).fetchone(), (None,))
        self.assertEqual(self.activate(uid), (identifier, 'active'))
        self.assertEqual(self.activate(uid), (identifier, 'active'))
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT p.status,m.status,m.membership_type,q.email '
                                        'FROM bri.auth_principals p JOIN bri.auth_tenant_memberships m USING (principal_id) '
                                        'JOIN bri.user_provisioning q USING (principal_id) WHERE p.principal_id=%s',
                                        (identifier,)).fetchone(), ('active', 'active', 'user', None))
            for table in ('auth_role_assignments', 'auth_sessions'):
                self.assertEqual(db.execute(f'SELECT count(*) FROM bri.{table} WHERE principal_id=%s',
                                            (identifier,)).fetchone(), (0,))
            rows = db.execute("SELECT event_type,actor_principal_id,to_jsonb(e)::text FROM bri.security_audit_events e "
                              "WHERE subject_principal_id=%s AND event_type LIKE 'tenant.user.provisioning.%%' "
                              'ORDER BY occurred_at', (identifier,)).fetchall()
            self.assertEqual([(kind.split('.')[-1], actor) for kind, actor, _ in rows],
                             [('requested', self.actor[0]), ('claimed', None), ('invitation_sent', None),
                              ('active', identifier)])
            for _, _, event in rows:
                self.assertNotIn(EMAIL, event)
                self.assertNotIn(str(uid), event)

    def test_concurrent_requests_and_claims_have_one_durable_winner(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            requests = [pool.submit(self.request) for _ in range(2)]
            rows = [job.result(timeout=10) for job in requests]
            self.assertEqual(rows[0], rows[1])
            identifier = rows[0][0]
            claims = [pool.submit(self.work, identifier, 'CLAIM', uuid4()) for _ in range(2)]
            self.assertCountEqual([job.result(timeout=10) for job in claims],
                                  [(identifier, 'inviting', EMAIL), (identifier, 'inviting', None)])
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT count(*) FROM bri.user_provisioning WHERE tenant_id=%s',
                                        (self.tenant,)).fetchone(), (1,))

    def test_dispatch_rechecks_live_session_and_an_existing_provider_uid_is_not_linked(self):
        identifier, _ = self.request()
        with self.connect('bri_app') as db:
            self.app(db)
            db.execute('SELECT bri.revoke_security_session(%s,%s)', (self.actor[2], uuid4()))
        attempt = uuid4()
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.work(identifier, 'CLAIM', attempt)
        with self.connect('postgres') as db:
            new_sid = uuid4()
            db.execute('INSERT INTO bri.auth_sessions(auth_user_id,principal_id,session_id) VALUES (%s,%s,%s)',
                       (self.actor[1], self.actor[0], new_sid))
        self.actor = (*self.actor[:2], new_sid)
        self.assertEqual(self.request(), (identifier, 'pending_setup'))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.work(identifier, 'CLAIM', attempt, issuer=ISSUER + '/wrong')
        self.assertEqual(self.work(identifier, 'CLAIM', attempt), (identifier, 'inviting', EMAIL))
        victim = self.foreign_actors[2]
        self.assertEqual(self.work(identifier, 'INVITED', attempt, victim[1]),
                         (identifier, 'invitation_unresolved', None))
        self.assertIsNone(self.activate(victim[1]))
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT principal_id FROM bri.auth_identity_links WHERE auth_user_id=%s',
                                        (victim[1],)).fetchone(), (victim[0],))

    def test_activation_state_and_audit_commit_or_rollback_together(self):
        identifier, _ = self.request()
        attempt, uid = uuid4(), uuid4()
        self.work(identifier, 'CLAIM', attempt)
        self.work(identifier, 'INVITED', attempt, uid)
        with self.connect('postgres') as db:
            # A failure only on the audit append, after activation's state writes.
            db.execute("ALTER TABLE bri.security_audit_events ADD CONSTRAINT fixture_audit_failure "
                       "CHECK (event_type <> 'tenant.user.provisioning.active') NOT VALID")
        try:
            with self.assertRaises(psycopg.errors.CheckViolation):
                self.activate(uid)
            with self.connect('postgres') as db:
                self.assertEqual(db.execute('SELECT p.status,m.status,q.status FROM bri.auth_principals p '
                                            'JOIN bri.auth_tenant_memberships m USING (principal_id) '
                                            'JOIN bri.user_provisioning q USING (principal_id) '
                                            'WHERE p.principal_id=%s', (identifier,)).fetchone(),
                                 ('pending', 'pending', 'invitation_sent'))
        finally:
            with self.connect('postgres') as db:
                db.execute('ALTER TABLE bri.security_audit_events DROP CONSTRAINT fixture_audit_failure')
        self.assertEqual(self.activate(uid), (identifier, 'active'))

    def test_worker_and_activator_have_no_direct_data_or_cross_boundary_access(self):
        self.request()
        with self.connect('postgres') as db:
            self.assertEqual(db.execute("SELECT relrowsecurity,relforcerowsecurity FROM pg_class "
                                        "WHERE oid='bri.user_provisioning'::regclass").fetchone(), (True, True))
        for role in ('bri_app', 'bri_provision_worker', 'bri_provision_activator'):
            with self.connect(role) as db:
                for statement in ('SELECT * FROM bri.user_provisioning',
                                  'UPDATE bri.user_provisioning SET email=NULL',
                                  'SELECT * FROM bri.provider_event_source',
                                  'SELECT bri.lock_user_provisioning_governance()'):
                    with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                        db.execute(statement)
                if role != 'bri_provision_worker':
                    with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                        db.execute(WORK, (uuid4(), 'CLAIM', ISSUER, None, uuid4()))
                if role != 'bri_provision_activator':
                    with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                        db.execute(ACTIVATE, (ISSUER, uuid4(), datetime.now(UTC), datetime.now(UTC), uuid4()))
                if role != 'bri_app':
                    with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                        db.execute(STATUS, (*self.app(db), self.key))

    def test_runtime_cannot_create_or_reparent_a_provisioning_grant(self):
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.org_nodes VALUES (%s,'leaf','department','Leaf','root')", (self.tenant,))
            db.execute("INSERT INTO bri.app_roles VALUES (%s,'catalog','Catalog')", (self.tenant,))
            db.execute("INSERT INTO bri.role_permissions VALUES (%s,'catalog','user:provision:create')", (self.tenant,))
        scoped = self.grant(self.tenant, self.actors[1], scope='leaf')
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.request(actor=scoped)
        with self.connect('bri_app') as db:
            self.app(db, actor=scoped)
            for statement in ("DELETE FROM bri.app_roles WHERE role_id='catalog'",
                              "UPDATE bri.org_nodes SET parent_node_id=NULL,node_type='root' WHERE node_id='leaf'",
                              ("INSERT INTO bri.role_permissions VALUES (current_setting('bri.tenant_id'),'reset',"
                               "'user:provision:create')")):
                with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                    db.execute(statement)

    def test_duplicate_and_status_keys_are_tenant_local(self):
        identifier, _ = self.request()
        with self.assertRaises(psycopg.errors.UniqueViolation):
            self.request(key=uuid4(), email=EMAIL.upper())
        with self.assertRaises(psycopg.errors.UniqueViolation):
            self.request(email='changed@example.test')
        foreign = self.grant(self.foreign, self.foreign_actors[0])
        with self.connect('bri_app') as db:
            self.assertIsNone(db.execute(STATUS, (*self.app(db, tenant=self.foreign, actor=foreign), self.key)).fetchone())
        other, _ = self.request(tenant=self.foreign, actor=foreign)
        self.assertNotEqual(identifier, other)
