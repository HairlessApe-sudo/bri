"""A11.3 against a private Unix-socket PostgreSQL 16 cluster; no supplied DSN."""
import os
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from unittest.mock import patch
from uuid import uuid4

import psycopg
import test_privileged_approvals_pg as fixtures

ISSUER = fixtures.ISSUER
READ = 'SELECT * FROM bri.read_user_lifecycle(%s,%s,%s,%s,%s)'
CHANGE = 'SELECT * FROM bri.change_user_lifecycle(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'
PERMISSIONS = ('user:profile:edit', 'user:suspend', 'user:reactivate')


@unittest.skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16')
class UserLifecycleTests(unittest.TestCase):
    connect = classmethod(fixtures.ApprovalDatabase.connect.__func__)

    @classmethod
    def setUpClass(cls):
        with patch.dict(os.environ, BRI_APPROVAL_PG_BIN=os.environ['BRI_TEST_PG_BIN']):
            fixtures.ApprovalDatabase.setUpClass.__func__(cls, staged_account_write=fixtures.LIFECYCLE_WRITE)
        with cls.connect('bri_migrator') as db:
            db.execute('INSERT INTO bri.provider_event_source (issuer) VALUES (%s)', (ISSUER,))

    def setUp(self):
        self.tenant, self.actors = fixtures.seed_approval_tenant(self.connect)
        self.actor = self.actors[0]
        self.target, self.target_uid, self.target_sid = self.actors[2]
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.app_roles VALUES (%s,'life','Lifecycle')", (self.tenant,))
            for permission in PERMISSIONS:
                db.execute("INSERT INTO bri.role_permissions VALUES (%s,'life',%s)", (self.tenant, permission))
            db.execute("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) "
                       "VALUES (%s,%s,'life','root')", (self.tenant, self.actor[0]))
            self.actor = (*self.actor[:2], uuid4())
            db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id) VALUES (%s,%s,%s)', self.actor)

    def args(self, db, target=None, actor=None):
        principal, uid, sid = actor or self.actor
        db.execute("SELECT set_config('bri.tenant_id',%s,true),set_config('bri.auth_user_id',%s,true)",
                   (self.tenant, str(uid)))
        return self.tenant, principal, sid, ISSUER, target or self.target

    def read(self, target=None):
        with self.connect('bri_app') as db:
            db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            return db.execute(READ, self.args(db, target)).fetchone()

    def change(self, action, version, *, target=None, name=None, reason=None,
               stamp: datetime | bool | None = True, correlation=None):
        with self.connect('bri_app') as db:
            return db.execute(CHANGE, (*self.args(db, target), action, version, name, reason,
                                       datetime.now(UTC) if stamp is True else stamp,
                                       correlation or uuid4())).fetchone()

    def test_edit_only_changes_name_and_advances_version(self):
        before = self.read()
        self.assertEqual(before[:4], (self.target, None, 'active', 'user'))
        self.assertEqual(before[5:], (True, True, False))
        after = self.change('edit', before[4], name='  Synthetic Name  ')
        self.assertEqual(after[:4], (self.target, 'Synthetic Name', 'active', 'user'))
        self.assertGreater(after[4], before[4])
        self.assertEqual(after, self.read())
        with self.assertRaises(psycopg.errors.SerializationFailure):
            self.change('edit', before[4], name='Stale edit')
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT revoked_at FROM bri.auth_sessions WHERE session_id=%s',
                                        (self.target_sid,)).fetchone(), (None,))

    def test_reactivated_user_requires_new_primary_and_structured_totp(self):
        stale = datetime.now(UTC)
        suspended = self.change('suspend', self.read()[4], reason='access_review')
        self.assertEqual(suspended[2], 'suspended')
        self.assertEqual(suspended[5:], (False, False, True))
        restored = self.change('reactivate', suspended[4], reason='review_complete')
        self.assertEqual(restored[2], 'active')
        with self.connect('postgres') as db:
            self.assertIsNotNone(db.execute('SELECT revoked_at FROM bri.auth_sessions WHERE session_id=%s',
                                            (self.target_sid,)).fetchone()[0])
        with self.connect('bri_app') as db:
            db.execute("SELECT set_config('bri.auth_user_id',%s,true)", (str(self.target_uid),))
            start = 'SELECT bri.start_security_session(%s,%s,%s,%s)'
            verified = 'SELECT bri.start_security_session(%s,%s,%s,%s,%s)'
            fresh = datetime.now(UTC)
            self.assertEqual(db.execute(start, (ISSUER, uuid4(), fresh, uuid4())).fetchone(), (None,))
            for sid, primary, totp in ((uuid4(), fresh, None), (uuid4(), fresh, stale),
                                       (uuid4(), stale, fresh), (self.target_sid, fresh, fresh)):
                self.assertEqual(db.execute(verified, (ISSUER, sid, primary, totp, uuid4())).fetchone(), (None,))
            self.assertIsNotNone(db.execute(verified, (ISSUER, uuid4(), fresh, fresh, uuid4())).fetchone()[0])

    def test_exact_session_and_individual_root_grants(self):
        with self.connect('postgres') as db:
            db.execute("DELETE FROM bri.role_permissions WHERE tenant_id=%s AND role_id='life' "
                       "AND permission<>'user:suspend'", (self.tenant,))
            # Permission DML revokes the prior admin session; renew it.
            self.actor = (*self.actor[:2], uuid4())
            db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id) VALUES (%s,%s,%s)',
                       self.actor)
            db.execute("UPDATE bri.auth_tenant_memberships SET membership_type='superuser' WHERE principal_id=%s",
                       (self.target,))
        valid = self.read()
        self.assertEqual(valid[3], 'superuser')
        self.assertEqual(valid[5:], (False, True, False))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.change('edit', valid[4], name='Not authorized')
        with self.connect('bri_app') as db:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                db.execute(READ, (self.tenant, self.actor[0], self.actor[2], ISSUER, self.target))
            args = self.args(db)
            for forged in ((str(uuid4()), *args[1:]), (args[0], uuid4(), *args[2:]),
                           (*args[:2], uuid4(), *args[3:]), (*args[:3], ISSUER + '/wrong', args[4])):
                with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                    db.execute(READ, forged)
            with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                db.execute(READ, (args[0], *self.actors[1][::2], ISSUER, self.target))
            db.execute('SELECT bri.revoke_security_session(%s,%s)', (self.actor[2], uuid4()))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.read()

    def test_excluded_and_unknown_targets_do_not_reveal_state_or_version(self):
        _, foreign = fixtures.seed_approval_tenant(self.connect)
        for target in (uuid4(), self.actor[0], self.actors[3][0], foreign[2][0]):
            self.assertIsNone(self.read(target))
            self.assertIsNone(self.change('suspend', -1, target=target, reason='access_review'))
        for status in ('pending', 'suspended', 'deactivated'):
            with self.connect('postgres') as db:
                db.execute('UPDATE bri.auth_principals SET status=%s WHERE principal_id=%s', (status, self.target))
            self.assertIsNone(self.read())
            self.assertIsNone(self.change('reactivate', -1, reason='access_restored'))

    def test_out_of_band_changes_consume_suspension_provenance(self):
        writes = (
            ('UPDATE bri.auth_principals SET status=status WHERE principal_id=%s',),
            ("UPDATE bri.auth_tenant_memberships SET status='suspended' WHERE principal_id=%s",
             "UPDATE bri.auth_tenant_memberships SET status='active' WHERE principal_id=%s"),
            ("UPDATE bri.auth_identity_links SET status='suspended' WHERE principal_id=%s",
             "UPDATE bri.auth_identity_links SET status='active' WHERE principal_id=%s"),
            ('UPDATE bri.auth_principals SET deletion_requested_at=clock_timestamp() WHERE principal_id=%s',
             'UPDATE bri.auth_principals SET deletion_requested_at=NULL WHERE principal_id=%s'),
            (('INSERT INTO bri.credential_operations(operation_id,principal_id,auth_user_id,auth_issuer,kind) '
             "SELECT gen_random_uuid(),principal_id,auth_user_id,auth_issuer,'factor_reenrollment' "
             'FROM bri.auth_identity_links WHERE principal_id=%s'),
             'UPDATE bri.credential_operations SET confirmed_at=clock_timestamp() WHERE principal_id=%s'),
        )
        for statements in writes:
            with self.subTest(statements=statements):
                suspended = self.change('suspend', self.read()[4], reason='policy_violation')
                with self.connect('postgres') as db:
                    for statement in statements:
                        db.execute(statement, (self.target,))
                self.assertIsNone(self.read())
                self.assertIsNone(self.change('reactivate', suspended[4], reason='review_complete'))
                with self.connect('postgres') as db:
                    db.execute("UPDATE bri.auth_principals SET status='active' WHERE principal_id=%s", (self.target,))

    def test_lifecycle_freshness_reason_allowlist_and_state_conflicts(self):
        before = self.read()
        for stamp in (None, datetime.now(UTC) - timedelta(minutes=16), datetime.now(UTC) + timedelta(minutes=1)):
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self.change('suspend', before[4], reason='temporary_leave', stamp=stamp)
        with self.assertRaises(psycopg.errors.InvalidParameterValue):
            self.change('suspend', before[4], reason='not allowlisted')
        with self.assertRaises(psycopg.errors.InvalidParameterValue):
            self.change('edit', before[4], name='Name\nValue')
        with self.assertRaises(psycopg.errors.ObjectNotInPrerequisiteState):
            self.change('reactivate', before[4], reason='access_restored')
        self.assertEqual(before, self.read())

    def test_atomic_attributed_audits_and_no_profile_data(self):
        edit_id, suspend_id, restore_id = uuid4(), uuid4(), uuid4()
        name = 'Synthetic Profile Sentinel'
        edited = self.change('edit', self.read()[4], name=name, correlation=edit_id)
        with self.connect('postgres') as db:
            db.execute("ALTER TABLE bri.security_audit_events ADD CONSTRAINT test_fail_lifecycle_audit "
                       "CHECK (event_type <> 'tenant.user.lifecycle.suspended') NOT VALID")
        try:
            with self.assertRaises(psycopg.errors.CheckViolation):
                self.change('suspend', edited[4], reason='access_review', correlation=suspend_id)
            self.assertEqual(edited, self.read())
            with self.connect('postgres') as db:
                self.assertEqual(db.execute('SELECT revoked_at FROM bri.auth_sessions WHERE session_id=%s',
                                            (self.target_sid,)).fetchone(), (None,))
                self.assertEqual(db.execute('SELECT count(*) FROM bri.security_audit_events WHERE request_id=%s',
                                            (suspend_id,)).fetchone(), (0,))
        finally:
            with self.connect('postgres') as db:
                db.execute('ALTER TABLE bri.security_audit_events DROP CONSTRAINT test_fail_lifecycle_audit')
        suspended = self.change('suspend', edited[4], reason='access_review', correlation=suspend_id)
        self.change('reactivate', suspended[4], reason='access_restored', correlation=restore_id)
        with self.connect('postgres') as db:
            rows = db.execute('SELECT event_type,lifecycle_reason,request_id,to_jsonb(e)::text '
                              'FROM bri.security_audit_events e WHERE request_id=ANY(%s) AND tenant_id=%s '
                              'AND actor_principal_id=%s AND subject_principal_id=%s',
                              ([edit_id, suspend_id, restore_id], self.tenant, self.actor[0], self.target)).fetchall()
            self.assertCountEqual([row[:3] for row in rows], [
                ('tenant.user.lifecycle.edited', None, edit_id),
                ('auth.session.revoked', None, suspend_id),
                ('auth.access.changed', None, suspend_id),
                ('tenant.user.lifecycle.suspended', 'access_review', suspend_id),
                ('auth.access.changed', None, restore_id),
                ('tenant.user.lifecycle.reactivated', 'access_restored', restore_id),
            ])
            for *_, payload in rows:
                self.assertNotIn(name, payload)
                self.assertNotIn(str(self.target_uid), payload)
                self.assertNotIn(str(self.target_sid), payload)
            with self.assertRaisesRegex(psycopg.Error, 'immutable'), db.transaction():
                db.execute("UPDATE bri.security_audit_events SET outcome='denied' WHERE request_id=%s", (edit_id,))

    def test_runtime_cannot_forge_grants_cascade_or_widen_root_scope(self):
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.org_nodes VALUES (%s,'leaf','department','Leaf','root'),"
                       "(%s,'other','root','Other',NULL)", (self.tenant, self.tenant))
            db.execute("INSERT INTO bri.app_roles VALUES (%s,'unused','Unused')", (self.tenant,))
            db.execute("INSERT INTO bri.role_permissions VALUES (%s,'unused','user:suspend')", (self.tenant,))
            db.execute("INSERT INTO bri.role_permissions VALUES (%s,'unused','fixture:unprotected')", (self.tenant,))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.read()
        with self.connect('bri_app') as db:
            self.args(db)
            for statement in (
                "INSERT INTO bri.role_permissions VALUES (current_setting('bri.tenant_id'),'reset','user:suspend')",
                "UPDATE bri.role_permissions SET permission='user:reactivate' WHERE permission='fixture:unprotected'",
                "DELETE FROM bri.app_roles WHERE role_id='unused'",
                "DELETE FROM bri.org_nodes WHERE node_id='other'",
                "UPDATE bri.org_nodes SET parent_node_id=NULL,node_type='root' WHERE node_id='leaf'",
                'UPDATE bri.auth_principals SET display_name=NULL',
                'SELECT * FROM bri.user_lifecycle_state',
                'SELECT bri.start_security_session_core(NULL,NULL,NULL,NULL)',
            ):
                with self.subTest(statement=statement), self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                    db.execute(statement)
            with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                db.execute("DELETE FROM bri.role_permissions WHERE role_id='life'")

    def test_concurrent_edits_with_equal_version_have_one_winner(self):
        version = self.read()[4]

        def edit(name):
            try:
                return self.change('edit', version, name=name)[1]
            except psycopg.errors.SerializationFailure:
                return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            result = list(pool.map(edit, ('Name A', 'Name B')))
        self.assertCountEqual(result, (self.read()[1], None))

    def wait_for_blocker(self, observer, writer, app_name):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if observer.execute('SELECT EXISTS (SELECT FROM pg_stat_activity WHERE application_name=%s '
                                'AND %s=ANY(pg_blocking_pids(pid)))',
                                (app_name, writer.info.backend_pid)).fetchone()[0]:
                return
            time.sleep(0.02)
        writer.rollback()
        self.fail(f'{app_name} did not wait for the competing transaction')

    def test_waiting_mutation_rechecks_authority_after_role_change(self):
        version = self.read()[4]
        with self.connect('postgres') as writer, self.connect('postgres', autocommit=True) as observer:
            writer.execute("DELETE FROM bri.role_permissions WHERE tenant_id=%s AND role_id='life' "
                           "AND permission='user:suspend'", (self.tenant,))

            def attempt():
                with self.connect('bri_app') as db:
                    db.execute("SET application_name='a113_waiter'; SET statement_timeout='10s'")
                    db.execute(CHANGE, (*self.args(db), 'suspend', version, None, 'temporary_leave',
                                        datetime.now(UTC), uuid4()))

            with ThreadPoolExecutor(max_workers=1) as pool:
                waiter = pool.submit(attempt)
                self.wait_for_blocker(observer, writer, 'a113_waiter')
                writer.commit()
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    waiter.result(timeout=5)

    def test_start_waiting_on_reactivation_observes_the_committed_totp_cutoff(self):
        stale = datetime.now(UTC)
        version = self.change('suspend', self.read()[4], reason='access_review')[4]
        with self.connect('bri_app') as writer, self.connect('postgres', autocommit=True) as observer:
            writer.execute(CHANGE, (*self.args(writer), 'reactivate', version, None, 'review_complete',
                                    datetime.now(UTC), uuid4()))

            def attempt():
                with self.connect('bri_app') as db:
                    db.execute("SET application_name='a113_session'; SET statement_timeout='10s'")
                    db.execute("SELECT set_config('bri.auth_user_id',%s,true)", (str(self.target_uid),))
                    return db.execute('SELECT bri.start_security_session(%s,%s,%s,%s,%s)',
                                      (ISSUER, uuid4(), stale, stale, uuid4())).fetchone()

            with ThreadPoolExecutor(max_workers=1) as pool:
                waiter = pool.submit(attempt)
                self.wait_for_blocker(observer, writer, 'a113_session')
                writer.commit()
                self.assertEqual(waiter.result(timeout=5), (None,))
