"""A11.7 real-role tests on a private, Unix-socket-only PostgreSQL 16 cluster."""
import os
import unittest
from unittest.mock import patch
from uuid import uuid4

import psycopg
import test_privileged_approvals_pg as fixtures

ISSUER = fixtures.ISSUER
READ = 'SELECT * FROM bri.read_account_current_grants(%s,%s,%s,%s,%s)'
EMPTY = [('user', 'active', None, None, None, None)]
RESERVE = ('INSERT INTO bri.credential_operations(operation_id,principal_id,auth_user_id,auth_issuer,kind) '
           "VALUES (%s,%s,%s,%s,'password_reset')")


@unittest.skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16')
class AccountCurrentGrantsTests(unittest.TestCase):
    @classmethod
    def connect(cls, role, **kwargs):
        return fixtures.ApprovalDatabase.connect.__func__(cls, role, options='-c timezone=UTC', **kwargs)

    @classmethod
    def setUpClass(cls):
        with patch.dict(os.environ, BRI_APPROVAL_PG_BIN=os.environ['BRI_TEST_PG_BIN']):
            fixtures.ApprovalDatabase.setUpClass.__func__(cls)
        with cls.connect('postgres') as db:
            assert not db.execute("SELECT FROM bri.role_permissions WHERE permission='account:grants:read'").fetchall()

    def setUp(self):
        self.tenant, self.actors = fixtures.seed_approval_tenant(self.connect)
        self.foreign, self.foreign_actors = fixtures.seed_approval_tenant(self.connect)
        self.target = self.actors[2][0]
        with self.connect('postgres') as db:
            for tenant, actors in ((self.tenant, self.actors), (self.foreign, self.foreign_actors)):
                for role, permission in (('directory', 'user:directory:read'), ('grants', 'account:grants:read')):
                    self.grant(db, tenant, actors[0][0], role, permission, 'root')
                self.refresh(db, actors)

    def refresh(self, db, actors=None):
        actors = self.actors if actors is None else actors
        actors[0] = (*actors[0][:2], uuid4())
        db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                   'VALUES (%s,%s,%s,clock_timestamp())', actors[0])

    def grant(self, db, tenant, principal, role, permission, scope):
        db.execute('INSERT INTO bri.app_roles VALUES (%s,%s,%s) ON CONFLICT DO NOTHING', (tenant, role, role))
        db.execute('INSERT INTO bri.role_permissions VALUES (%s,%s,%s) ON CONFLICT DO NOTHING',
                   (tenant, role, permission))
        db.execute('INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) '
                   'VALUES (%s,%s,%s,%s)', (tenant, principal, role, scope))

    def args(self, db, *, tenant=None, actor=None, target=True, issuer=ISSUER):
        tenant = tenant or self.tenant
        principal, uid, sid = actor or self.actors[0]
        db.execute("SELECT set_config('bri.tenant_id',%s,true),set_config('bri.auth_user_id',%s,true)",
                   (tenant, str(uid)))
        return tenant, principal, sid, issuer, self.target if target is True else target

    def read(self, **kwargs):
        with self.connect('bri_app') as db:
            db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            return db.execute(READ, self.args(db, **kwargs)).fetchall()

    def test_exact_directory_target_and_visible_empty(self):
        self.assertEqual(self.read(), EMPTY)
        for target in (None, uuid4(), self.foreign_actors[2][0], *[self.actors[i][0] for i in (0, 1, 3)]):
            with self.subTest(target=target):
                self.assertEqual(self.read(target=target), [])
        self.assertEqual(self.read(tenant=self.foreign, actor=self.foreign_actors[0],
                                   target=self.foreign_actors[2][0]), EMPTY)

    def test_projection_deduplicates_and_requires_independent_exact_node_visibility(self):
        with self.connect('postgres') as db:
            for node, label, parent in (('visible', 'Visible team', 'root'),
                                        ('hidden', 'Hidden child', 'visible'),
                                        ('internal', 'Internal only', 'root')):
                db.execute("INSERT INTO bri.org_nodes VALUES (%s,%s,'team',%s,%s)",
                           (self.tenant, node, label, parent))
            for node, permission in (('root', 'organisation:read'), ('visible', 'organisation:read'),
                                     ('hidden', 'knowledge:read'), ('internal', 'organisation:read')):
                self.grant(db, self.tenant, self.actors[0][0], 'view-' + node, permission, node)
            for role, permission, node in (
                ('secret1', 'knowledge:read', 'visible'), ('secret2', 'knowledge:read', 'visible'),
                ('secret3', 'organisation:read', 'visible'), ('secret4', 'knowledge:read', 'hidden'),
                ('secret5', 'organisation:read', 'hidden'), ('secret6', 'security:audit:read', 'internal'),
                ('retired', 'knowledge:read', 'root'),
            ):
                self.grant(db, self.tenant, self.target, role, permission, node)
            db.execute("UPDATE bri.auth_role_assignments SET status='revoked' WHERE principal_id=%s AND role_id='retired'",
                       (self.target,))
            db.execute('DELETE FROM bri.auth_sessions WHERE principal_id=%s', (self.target,))
            self.refresh(db)
        expected = [('user', 'active', 'visible', 'Visible team', permission, True)
                    for permission in ('knowledge:read', 'organisation:read')]
        self.assertCountEqual(self.read(), expected)
        self.assertEqual(self.read(tenant=self.foreign, actor=self.foreign_actors[0],
                                   target=self.foreign_actors[2][0]), EMPTY)
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_role_assignments SET status='revoked' WHERE principal_id=%s AND role_id='view-visible'",
                       (self.actors[0][0],))
            self.refresh(db)
        self.assertEqual(self.read(), EMPTY)

    def test_root_topology_is_protected_only_while_read_authority_is_active(self):
        self.assertEqual(self.read(), EMPTY)
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.org_nodes VALUES (%s,'leaf','team','Leaf','root')", (self.tenant,))
            db.execute("UPDATE bri.auth_role_assignments SET scope_node_id='leaf' WHERE principal_id=%s AND role_id='grants'",
                       (self.actors[0][0],))
            self.refresh(db)
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.read()

        promote = "UPDATE bri.org_nodes SET node_type='root',parent_node_id=NULL WHERE node_id='leaf'"
        with self.connect('bri_app') as db:
            self.args(db)
            with self.assertRaisesRegex(psycopg.errors.InsufficientPrivilege, 'account grants root topology'), db.transaction():
                db.execute(promote)
            self.assertEqual(db.execute("UPDATE bri.org_nodes SET display_name='Renamed' WHERE node_id='root'").rowcount, 1)
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_role_assignments SET status='revoked' WHERE principal_id=%s AND role_id='grants'",
                       (self.actors[0][0],))
        with self.connect('bri_app') as db:
            self.args(db)
            self.assertEqual(db.execute(promote).rowcount, 1)

    def test_grants_and_directory_authorities_are_separate(self):
        self.assertEqual(self.read(), EMPTY)
        for role in ('directory', 'grants'):
            with self.subTest(role=role):
                with self.connect('postgres') as db:
                    db.execute("UPDATE bri.auth_role_assignments SET status='revoked' WHERE principal_id=%s AND role_id=%s",
                               (self.actors[0][0], role))
                    self.refresh(db)
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    self.read()
                with self.connect('postgres') as db:
                    db.execute("UPDATE bri.auth_role_assignments SET status='active' WHERE principal_id=%s AND role_id=%s",
                               (self.actors[0][0], role))
                    self.refresh(db)
                self.assertEqual(self.read(), EMPTY)

    def test_ambiguous_or_untyped_root_denies_authority(self):
        self.assertEqual(self.read(), EMPTY)
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.org_nodes SET node_type='team' WHERE tenant_id=%s AND node_id='root'", (self.tenant,))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.read()
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.org_nodes SET node_type='root' WHERE tenant_id=%s AND node_id='root'", (self.tenant,))
            db.execute("INSERT INTO bri.org_nodes VALUES (%s,'other-root','team','Other parentless node')", (self.tenant,))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.read()

    def test_requires_exact_live_actor_session_without_credential_quarantine(self):
        self.assertEqual(self.read(), EMPTY)
        principal, uid, sid = self.actors[0]
        for args in ({'issuer': ISSUER + '/wrong'}, {'tenant': self.foreign},
                     {'actor': (principal, uid, uuid4())}, {'actor': (principal, uuid4(), sid)},
                     {'actor': self.actors[1]}):
            with self.subTest(args=args), self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self.read(**args)
        with self.connect('postgres') as db:
            db.execute('UPDATE bri.session_guards SET primary_after=clock_timestamp() WHERE principal_id=%s', (principal,))
            self.assertEqual(db.execute('SELECT revoked_at FROM bri.auth_sessions WHERE session_id=%s',
                                        (sid,)).fetchone(), (None,))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.read()
        with self.connect('postgres') as db:
            self.refresh(db)
        self.assertEqual(self.read(), EMPTY)
        with self.connect('postgres') as db:
            live_sid = self.actors[0][2]
            db.execute(RESERVE, (uuid4(), principal, uid, ISSUER))
            self.assertEqual(db.execute('SELECT revoked_at FROM bri.auth_sessions WHERE session_id=%s',
                                        (live_sid,)).fetchone(), (None,))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.read()

    def seed_visible_root_grant(self):
        with self.connect('postgres') as db:
            self.grant(db, self.tenant, self.actors[0][0], 'view-root', 'organisation:read', 'root')
            self.grant(db, self.tenant, self.target, 'target-read', 'knowledge:read', 'root')
            self.refresh(db)

    def test_recorded_grants_survive_suspension_but_not_retirement(self):
        self.seed_visible_root_grant()
        fields = ('root', 'root', 'knowledge:read')
        self.assertEqual(self.read(), [('user', 'active', *fields, True)])
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_tenant_memberships SET membership_type='superuser',status='pending' "
                       'WHERE principal_id=%s', (self.target,))
        self.assertEqual(self.read(), [('superuser', 'pending', *fields, False)])
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_tenant_memberships SET status='active' WHERE principal_id=%s", (self.target,))
            db.execute("UPDATE bri.auth_principals SET status='suspended' WHERE principal_id=%s", (self.target,))
        self.assertEqual(self.read(), [('superuser', 'suspended', *fields, False)])
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_principals SET status='deactivated' WHERE principal_id=%s", (self.target,))
            db.execute("UPDATE bri.auth_tenant_memberships SET status='deactivated' WHERE principal_id=%s", (self.target,))
        # Even an inconsistent terminal fixture cannot imply eligibility.
        self.assertEqual(self.read(), [('superuser', 'deactivated', *fields, False)])
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_role_assignments SET status='revoked' WHERE principal_id=%s", (self.target,))
        self.assertEqual(self.read(), [('superuser', 'deactivated', None, None, None, None)])

    def test_eligibility_is_invariant_to_private_target_admission_state(self):
        self.seed_visible_root_grant()
        before = self.read()
        self.assertEqual(before, [('user', 'active', 'root', 'root', 'knowledge:read', True)])

        with self.subTest(private_change='identity link revoked'):
            with self.connect('postgres') as db:
                self.assertEqual(db.execute("UPDATE bri.auth_identity_links SET status='revoked' WHERE principal_id=%s",
                                            (self.target,)).rowcount, 1)
            self.assertEqual(self.read(), before)

        with self.subTest(private_change='credential operation pending'):
            with self.connect('postgres') as db:
                db.execute("UPDATE bri.auth_identity_links SET status='active' WHERE principal_id=%s", (self.target,))
            self.assertEqual(self.read(), before)
            with self.connect('postgres') as db:
                db.execute(RESERVE, (uuid4(), self.target, self.actors[2][1], ISSUER))
            self.assertEqual(self.read(), before)

    def test_deletion_request_preserves_recorded_grant_but_suspends_eligibility(self):
        self.seed_visible_root_grant()
        fields = ('root', 'root', 'knowledge:read')
        self.assertEqual(self.read(), [('user', 'active', *fields, True)])
        with self.connect('postgres') as db:
            db.execute('UPDATE bri.auth_principals SET deletion_requested_at=clock_timestamp() WHERE principal_id=%s',
                       (self.target,))
        self.assertEqual(self.read(), [('user', 'suspended', *fields, False)])

    def test_runtime_cannot_read_raw_target_bindings_or_private_controls(self):
        self.seed_visible_root_grant()
        with self.connect('bri_app') as db:
            self.args(db)
            self.assertEqual(db.execute('SELECT session_user,current_user').fetchone(), ('bri_app', 'bri_app'))
            for statement in ('SELECT * FROM bri.auth_role_assignments WHERE principal_id=%s',
                              'SELECT * FROM bri.auth_identity_links WHERE principal_id=%s',
                              'SELECT * FROM bri.auth_tenant_memberships WHERE principal_id=%s'):
                with self.subTest(statement=statement):
                    self.assertEqual(db.execute(statement, (self.target,)).fetchall(), [])
            for statement in ('SELECT * FROM bri.security_audit_events', 'SELECT * FROM bri.credential_operations',
                              'SELECT * FROM bri.session_guards'):
                with self.subTest(statement=statement), self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                    db.execute(statement)
            relations = ['auth_role_assignments', 'auth_identity_links', 'auth_tenant_memberships', 'auth_principals',
                         'auth_sessions', 'session_guards', 'credential_operations', 'org_nodes', 'role_permissions']
            self.assertCountEqual(db.execute('SELECT relname,relrowsecurity,relforcerowsecurity FROM pg_class '
                                             "WHERE relnamespace='bri'::regnamespace AND relname=ANY(%s)",
                                             (relations,)).fetchall(), [(r, True, True) for r in relations])
