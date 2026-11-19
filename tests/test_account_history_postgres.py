"""A11.6 real-role tests; BRI_TEST_PG_BIN opts into a private native PG16 cluster."""
import os
import unittest
from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import UUID, uuid4

import psycopg
import test_privileged_approvals_pg as fixtures

ISSUER = fixtures.ISSUER
READ = 'SELECT * FROM bri.read_account_history(%s,%s,%s,%s,%s,%s,%s)'
EMPTY = [(None,) * 7]
STAMP = datetime(2026, 1, 1, tzinfo=UTC)


@unittest.skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16')
class AccountHistoryTests(unittest.TestCase):
    @classmethod
    def connect(cls, role, **kwargs):
        return fixtures.ApprovalDatabase.connect.__func__(cls, role, options='-c timezone=UTC', **kwargs)

    @classmethod
    def setUpClass(cls):
        with patch.dict(os.environ, BRI_APPROVAL_PG_BIN=os.environ['BRI_TEST_PG_BIN']):
            fixtures.ApprovalDatabase.setUpClass.__func__(cls)
        with cls.connect('postgres') as db:
            assert not db.execute("SELECT FROM bri.role_permissions WHERE permission='account:history:read'").fetchall()

    def setUp(self):
        self.tenant, self.actors = fixtures.seed_approval_tenant(self.connect)
        self.foreign, self.foreign_actors = fixtures.seed_approval_tenant(self.connect)
        self.actor = self.actors[0]
        self.target = self.actors[2][0]
        with self.connect('postgres') as db:
            for tenant, actors in ((self.tenant, self.actors), (self.foreign, self.foreign_actors)):
                for role, permission in (('directory', 'user:directory:read'),
                                         ('history', 'account:history:read'),
                                         ('audit', 'security:audit:read')):
                    db.execute('INSERT INTO bri.app_roles VALUES (%s,%s,%s)', (tenant, role, role))
                    db.execute('INSERT INTO bri.role_permissions VALUES (%s,%s,%s)', (tenant, role, permission))
                    db.execute('INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) '
                               "VALUES (%s,%s,%s,'root')", (tenant, actors[0][0], role))
                # Grant changes retire earlier sessions. Materialize the session after the grants.
                actors[0] = (*actors[0][:2], uuid4())
                db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                           'VALUES (%s,%s,%s,clock_timestamp())', actors[0])
        self.actor = self.actors[0]

    def args(self, db, *, target=True, tenant=None, actor=None, issuer=ISSUER, size=100, before=None):
        tenant = tenant or self.tenant
        principal, uid, sid = actor or self.actor
        db.execute("SELECT set_config('bri.tenant_id',%s,true),set_config('bri.auth_user_id',%s,true)",
                   (tenant, str(uid)))
        return tenant, principal, sid, issuer, self.target if target is True else target, size, before

    def read(self, **kwargs):
        with self.connect('bri_app') as db:
            db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            return db.execute(READ, self.args(db, **kwargs)).fetchall()

    def event(self, db, kind, *, event_id=None, tenant=None, target=None, actor: UUID | bool | None = True,
              reason=None, stamp=STAMP, outcome='success'):
        event_id = event_id or uuid4()
        scope = ('organisation:read', 'private-scope') if kind.startswith('tenant.user.delegation.') else (None, None)
        db.execute('INSERT INTO bri.security_audit_events(event_id,tenant_id,subject_principal_id,actor_principal_id,'
                   'event_type,outcome,lifecycle_reason,occurred_at,request_id,delegation_permission,delegation_scope_node_id) '
                   'VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                   (event_id, tenant or self.tenant, target or self.target, self.actor[0] if actor is True else actor,
                    kind, outcome, reason, stamp, uuid4(), *scope))
        return event_id

    def test_visible_empty_and_indistinguishable_hidden_targets(self):
        self.assertEqual(self.read(), EMPTY)
        for target in (None, uuid4(), self.foreign_actors[2][0], self.actor[0],
                       self.actors[1][0], self.actors[3][0]):
            with self.subTest(target=target):
                self.assertEqual(self.read(target=target, size=0, before=uuid4()), [])
        self.assertEqual(self.read(tenant=self.foreign, actor=self.foreign_actors[0],
                                   target=self.foreign_actors[2][0]), EMPTY)

    def test_raw_audit_unreadable_to_runtime_with_general_audit_permission(self):
        with self.connect('postgres') as db:
            self.event(db, 'tenant.user.provisioning.requested')
            self.assertEqual(db.execute("SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                                        "WHERE oid='bri.security_audit_events'::regclass").fetchone(), (True, True))
        self.assertEqual(len(self.read()), 1)
        with self.connect('bri_app') as db:
            self.args(db)
            self.assertEqual(db.execute("SELECT has_any_column_privilege(current_user,"
                                        "'bri.security_audit_events','SELECT')").fetchone(), (False,))
            self.assertEqual(db.execute("SELECT has_column_privilege(current_user,"
                                        "'bri.security_audit_events','event_type','INSERT')").fetchone(), (True,))
            for statement in ('SELECT * FROM bri.security_audit_events',
                              "UPDATE bri.security_audit_events SET outcome='failure'",
                              'DELETE FROM bri.security_audit_events', 'TRUNCATE bri.security_audit_events'):
                with self.subTest(statement=statement), self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                    db.execute(statement)
            with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                db.execute('INSERT INTO bri.security_audit_events '
                           '(tenant_id,subject_principal_id,actor_principal_id,event_type,outcome) '
                           "VALUES (%s,%s,%s,'tenant.user.provisioning.requested','success')",
                           (self.tenant, self.target, self.actor[0]))
        with self.connect('postgres') as db:
            for statement in ("UPDATE bri.security_audit_events SET outcome='failure'",
                              'DELETE FROM bri.security_audit_events', 'TRUNCATE bri.security_audit_events'):
                with self.subTest(statement=statement), self.assertRaisesRegex(psycopg.errors.RaiseException, 'immutable'), db.transaction():
                    db.execute(statement)

    def test_authorized_legacy_audit_append_still_works_without_raw_read_access(self):
        correlation = uuid4()
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.role_permissions VALUES (%s,'audit','security:audit:write')", (self.tenant,))
        with self.connect('bri_app') as db:
            self.args(db)
            result = db.execute('INSERT INTO bri.security_audit_events '
                                '(tenant_id,subject_principal_id,actor_principal_id,event_type,outcome,request_id) '
                                "VALUES (%s,%s,%s,'tenant.user.created','success',%s)",
                                (self.tenant, self.target, self.actor[0], correlation))
            self.assertEqual(result.rowcount, 1)
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT event_type FROM bri.security_audit_events WHERE request_id=%s',
                                        (correlation,)).fetchall(), [('tenant.user.created',)])

    def test_allowlisted_projection_for_deactivated_account_and_independent_actor_visibility(self):
        ordinary = uuid4()
        peer, platform = self.actors[1][0], self.actors[3][0]
        foreign = self.foreign_actors[2][0]
        cases = (
            ('provisioning.requested', 'provisioned', None, self.actor[0]),
            ('provisioning.active', 'activated', None, peer),
            ('lifecycle.edited', 'display_name_changed', None, None),
            ('lifecycle.suspended', 'suspended', 'temporary_leave', ordinary),
            ('lifecycle.reactivated', 'reactivated', 'access_restored', platform),
            ('delegation.granted', 'permission_granted', None, foreign),
            ('delegation.revoked', 'permission_revoked', None, peer),
            ('lifecycle.deactivated', 'deactivated', 'account_closed', ordinary),
        )
        expected = []
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.auth_principals(principal_id,display_name,status) VALUES (%s,'Old name','active')",
                       (ordinary,))
            db.execute("INSERT INTO bri.auth_tenant_memberships(tenant_id,principal_id,status) VALUES (%s,%s,'active')",
                       (self.tenant, ordinary))
            db.execute("UPDATE bri.auth_principals SET display_name='Masked name' WHERE principal_id=ANY(%s)",
                       ([peer, platform, foreign, self.actor[0]],))
            for i, (kind, action, reason, actor) in enumerate(cases):
                stamp = STAMP + timedelta(seconds=i)
                outcome = 'failure' if action == 'provisioned' else 'success'
                event = self.event(db, 'tenant.user.' + kind, reason=reason, actor=actor, stamp=stamp, outcome=outcome)
                expected.append((event, stamp, action, outcome, reason, ordinary if actor == ordinary else None,
                                 'Current name' if actor == ordinary else None))
            for phase in ('claimed', 'invitation_sent', 'invitation_retryable', 'invitation_unresolved'):
                self.event(db, 'tenant.user.provisioning.' + phase)
            self.event(db, 'auth.session.revoked')
            self.event(db, 'tenant.user.lifecycle.edited', tenant=self.foreign)
            db.execute("UPDATE bri.auth_principals SET display_name='Current name' WHERE principal_id=%s", (ordinary,))
            db.execute("UPDATE bri.auth_tenant_memberships SET status='deactivated' WHERE principal_id=%s", (self.target,))
            db.execute("UPDATE bri.auth_principals SET status='deactivated' WHERE principal_id=%s", (self.target,))
        def persisted_history():
            with self.connect('postgres') as db:
                return db.execute('SELECT * FROM bri.security_audit_events WHERE subject_principal_id=%s '
                                  'ORDER BY event_id', (self.target,)).fetchall()

        before = persisted_history()
        self.assertEqual(self.read(), expected[::-1])
        self.assertEqual(self.read(), expected[::-1])
        self.assertEqual(persisted_history(), before)

    def test_cursor_resolves_only_inside_current_target_tenant_and_allowlist(self):
        tied = [UUID(int=i) for i in (91, 93, 92)]
        with self.connect('postgres') as db:
            for event_id in tied:
                self.event(db, 'tenant.user.lifecycle.edited', event_id=event_id)
            # The timestamp must dominate UUID order.
            newest = self.event(db, 'tenant.user.lifecycle.edited', event_id=UUID(int=90), stamp=STAMP + timedelta(seconds=1))
            wrong_target = self.event(db, 'tenant.user.lifecycle.edited', target=self.actors[1][0])
            wrong_tenant = self.event(db, 'tenant.user.lifecycle.edited', tenant=self.foreign)
            excluded = [self.event(db, kind) for kind in (
                'tenant.user.provisioning.invitation_sent', 'tenant.user.created', 'tenant.user.suspended',
                'tenant.user.role_assigned', 'tenant.user.role_revoked',
            )]
        self.assertEqual([row[0] for row in self.read(size=1)], [newest, tied[1]])
        self.assertEqual([row[0] for row in self.read(size=1, before=newest)], [tied[1], tied[2]])
        self.assertEqual([row[0] for row in self.read(size=1, before=tied[1])], [tied[2], tied[0]])
        self.assertEqual(self.read(before=tied[0]), EMPTY)
        for cursor in (wrong_target, wrong_tenant, *excluded, uuid4()):
            with self.subTest(cursor=cursor), self.assertRaises(psycopg.errors.InvalidParameterValue):
                self.read(before=cursor)
        for size in (None, 0, 101, 2147483647):
            with self.subTest(size=size), self.assertRaises(psycopg.errors.InvalidParameterValue):
                self.read(size=size)

    def test_authority_requires_both_live_grants_and_exact_live_session(self):
        self.assertEqual(self.read(), EMPTY)
        principal, uid, sid = self.actor
        for args in ({'issuer': ISSUER + '/wrong'}, {'actor': (principal, uid, uuid4())},
                     {'actor': (principal, uuid4(), sid)}, {'actor': (self.actors[1][0], uid, sid)},
                     {'tenant': self.foreign}):
            with self.subTest(args=args), self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self.read(**args)

        def set_grant(db, role, status):
            db.execute('UPDATE bri.auth_role_assignments SET status=%s WHERE principal_id=%s AND role_id=%s',
                       (status, principal, role))

        def new_session(db, age='0 seconds'):
            self.actor = (principal, uid, uuid4())
            db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at,expires_at) '
                       "VALUES (%s,%s,%s,clock_timestamp()-%s::interval,clock_timestamp()+interval '1 hour')",
                       (*self.actor, age))

        for role in ('directory', 'history'):
            with self.connect('postgres') as db:
                set_grant(db, role, 'revoked')
                new_session(db)
            with self.subTest(role=role), self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self.read()
            with self.connect('postgres') as db:
                set_grant(db, role, 'active')
                new_session(db)
            self.assertEqual(self.read(), EMPTY)
        with self.connect('postgres') as db:
            db.execute('UPDATE bri.session_guards SET primary_after=clock_timestamp() WHERE principal_id=%s', (principal,))
            self.assertIsNone(db.execute('SELECT revoked_at FROM bri.auth_sessions WHERE session_id=%s',
                                         (self.actor[2],)).fetchone()[0])
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.read()
        with self.connect('postgres') as db:
            # Isolate the eight-hour cap from the invalidation cutoff and stored expiry.
            db.execute("UPDATE bri.session_guards SET primary_after='-infinity' WHERE principal_id=%s", (principal,))
            new_session(db, '9 hours')
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.read()
        with self.connect('postgres') as db:
            new_session(db)
        self.assertEqual(self.read(), EMPTY)
        with self.connect('postgres') as db:
            db.execute('UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() WHERE session_id=%s', (self.actor[2],))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.read()

    def test_active_scoped_grant_cannot_be_translated_into_root_authority(self):
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.org_nodes VALUES (%s,'leaf','team','Leaf','root')", (self.tenant,))
            db.execute("UPDATE bri.auth_role_assignments SET scope_node_id='leaf' WHERE principal_id=%s AND role_id='history'",
                       (self.actor[0],))
            self.actor = (*self.actor[:2], uuid4())
            db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                       'VALUES (%s,%s,%s,clock_timestamp())', self.actor)
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.read()
        promote = "UPDATE bri.org_nodes SET node_type='root',parent_node_id=NULL WHERE tenant_id=%s AND node_id='leaf'"
        with self.connect('bri_app') as db:
            self.args(db)
            with self.assertRaisesRegex(psycopg.errors.InsufficientPrivilege, 'account history root topology'), db.transaction():
                db.execute(promote, (self.tenant,))
            # Neither changing regular metadata nor non-root insertion is blocked.
            self.assertEqual(db.execute("UPDATE bri.org_nodes SET display_name='Renamed' WHERE node_id='root'").rowcount, 1)
            db.execute("INSERT INTO bri.org_nodes VALUES (%s,'another','team','Another','root')", (self.tenant,))
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_role_assignments SET status='revoked' WHERE principal_id=%s AND role_id='history'",
                       (self.actor[0],))
        with self.connect('bri_app') as db:
            self.args(db)
            self.assertEqual(db.execute(promote, (self.tenant,)).rowcount, 1)
