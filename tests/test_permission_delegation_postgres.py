"""A11.4 in a private PostgreSQL 16 Unix-socket cluster; no external DSN."""
import os
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import psycopg
from fastapi.testclient import TestClient
import test_knowledge_authorization_postgres as p1
import test_privileged_approvals_pg as fixtures
from bri.access.roles import role_allows_permission
from bri.api.app import ApiSettings, create_app
from bri.api.authentication import AuthenticatedIdentity

ISSUER = fixtures.ISSUER
READ = 'SELECT * FROM bri.read_user_delegation(%s,%s,%s,%s,%s,%s,%s)'
CHANGE = 'SELECT * FROM bri.change_user_delegation(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'
ORG = 'organisation:read'
KNOWLEDGE = 'knowledge:read'
BUNDLES = {ORG: 'delegation-org', KNOWLEDGE: 'delegation-knowledge'}
ROUTINES = (
    'bri.read_user_delegation(text,uuid,uuid,text,uuid,text,text)',
    'bri.change_user_delegation(text,uuid,uuid,text,uuid,text,text,text,bigint,timestamptz,uuid)',
)


def seed_delegation_catalog(db, tenant, actor, node='leaf'):
    """Platform-only synthetic registration; role permissions precede the registry."""
    for permission, role in BUNDLES.items():
        db.execute('INSERT INTO bri.app_roles VALUES (%s,%s,%s)', (tenant, role, role))
        db.execute('INSERT INTO bri.role_permissions VALUES (%s,%s,%s)', (tenant, role, permission))
        db.execute('INSERT INTO bri.user_delegation_bundles VALUES (%s,%s,%s)', (tenant, permission, role))
        db.execute('INSERT INTO bri.user_delegation_authority VALUES (%s,%s,%s,%s)',
                   (tenant, actor, node, permission))


@unittest.skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16')
class PermissionDelegationTests(unittest.TestCase):
    connect = classmethod(fixtures.ApprovalDatabase.connect.__func__)

    @classmethod
    def setUpClass(cls):
        with patch.dict(os.environ, BRI_APPROVAL_PG_BIN=os.environ['BRI_TEST_PG_BIN']):
            fixtures.ApprovalDatabase.setUpClass.__func__(cls)
        with cls.connect('bri_app') as db:
            for routine in ROUTINES:
                assert db.execute("SELECT has_function_privilege(current_user,%s,'EXECUTE')", (routine,)).fetchone() == (False,), routine
        with cls.connect('bri_migrator') as db:
            db.execute('INSERT INTO bri.provider_event_source (issuer) VALUES (%s)', (ISSUER,))
            for table in ('user_delegation_bundles', 'user_delegation_authority', 'user_delegation_state'):
                assert db.execute('SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid=%s::regclass',
                                  (f'bri.{table}',)).fetchone() == (True, True)
                assert db.execute(f'SELECT count(*) FROM bri.{table}').fetchone() == (0,)
            # This cluster is created by the fixture in an owner-only socket
            # directory with TCP disabled. The release migration never grants this.
            for routine in ROUTINES:
                db.execute(f'GRANT EXECUTE ON FUNCTION {routine} TO bri_app')

    def setUp(self):
        self.tenant, self.actors = fixtures.seed_approval_tenant(self.connect)
        self.foreign_tenant, self.foreign_actors = fixtures.seed_approval_tenant(self.connect)
        with self.connect('postgres') as db:
            for tenant, actors in ((self.tenant, self.actors), (self.foreign_tenant, self.foreign_actors)):
                db.execute("INSERT INTO bri.org_nodes VALUES (%s,'leaf','team','Leaf','root'),"
                           "(%s,'child','team','Child','leaf'),(%s,'sibling','team','Sibling','root')", (tenant,)*3)
                seed_delegation_catalog(db, tenant, actors[0][0])
                for index, (principal, uid, prior_sid) in enumerate(actors):
                    # The shared fixture's transaction-start default predates
                    # its own A10 identity and membership cutoff writes.
                    actors[index] = (principal, uid, uuid4())
                    db.execute('UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() WHERE session_id=%s',
                               (prior_sid,))
                    db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                               'VALUES (%s,%s,%s,clock_timestamp())', actors[index])
        self.actor = self.actors[0]
        self.target, self.target_uid, self.target_sid = self.actors[2]

    def args(self, db, *, tenant=None, actor=None, target=None, node='leaf', permission=ORG):
        tenant = tenant or self.tenant
        principal, uid, sid = actor or self.actor
        db.execute("SELECT set_config('bri.tenant_id',%s,true),set_config('bri.auth_user_id',%s,true)",
                   (tenant, str(uid)))
        return tenant, principal, sid, ISSUER, target or self.target, node, permission

    def read(self, **kwargs):
        with self.connect('bri_app') as db:
            db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            return db.execute(READ, self.args(db, **kwargs)).fetchone()

    def run_change(self, db, action, version, *, stamp: datetime | bool | str | None = True,
                   correlation=None, **kwargs):
        args = self.args(db, **kwargs)
        return db.execute(CHANGE, (*args, action, version, datetime.now(UTC) if stamp is True else stamp,
                                   correlation or uuid4())).fetchone()

    def change(self, action, version, **kwargs):
        with self.connect('bri_app') as db:
            return self.run_change(db, action, version, **kwargs)

    def test_grant_and_revoke_use_native_exact_scope(self):
        for role in ('user', 'superuser'):
            for permission in BUNDLES:
                self.assertTrue(role_allows_permission(role, permission))
        for permission in BUNDLES:
            with self.subTest(permission=permission):
                initial = self.read(permission=permission)
                self.assertEqual(initial, (0, False))
                grant = self.change('grant', initial[0], permission=permission)
                self.assertTrue(grant[1])
                self.assertGreater(grant[0], initial[0])
                self.assertEqual(self.read(permission=permission), grant)
                with self.connect('bri_app') as db:
                    self.args(db, actor=self.actors[2])
                    rows = db.execute('SELECT a.scope_node_id,r.permission FROM bri.auth_role_assignments a '
                                      'JOIN bri.role_permissions r USING (tenant_id,role_id) '
                                      "WHERE a.status='active'").fetchall()
                    self.assertEqual(rows, [('leaf', permission)])
                revoke = self.change('revoke', grant[0], permission=permission)
                self.assertFalse(revoke[1])
                self.assertGreater(revoke[0], grant[0])
                self.assertEqual(self.read(permission=permission), revoke)

    def test_exact_authority_is_separate_from_possession_and_tenant(self):
        self.assertEqual(self.read(tenant=self.foreign_tenant, actor=self.foreign_actors[0],
                                   target=self.foreign_actors[2][0]), (0, False))
        for kwargs in ({'node': 'root'}, {'node': 'child'}, {'node': 'sibling'},
                       {'permission': 'document:read'}, {'tenant': self.foreign_tenant},
                       {'actor': self.actors[1]}, {'actor': self.actors[3]}):
            with self.subTest(kwargs=kwargs), self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self.change('grant', 0, **kwargs)
        peer, peer_uid, _ = self.actors[1]
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.role_permissions VALUES (%s,'reset',%s)", (self.tenant, ORG))
            sid = uuid4()
            db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                       'VALUES (%s,%s,%s,clock_timestamp())', (peer, peer_uid, sid))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.read(actor=(peer, peer_uid, sid), node='root')

    def test_exact_session_provider_cutoff_and_totp(self):
        with self.connect('bri_app') as db:
            args = self.args(db)
            for forged in ((args[0], self.actors[1][0], *args[2:]), (*args[:2], uuid4(), *args[3:]),
                           (*args[:3], ISSUER+'/wrong', *args[4:])):
                with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                    db.execute(READ, forged)
        now = datetime.now(UTC)
        for stamp in (None, 'infinity', now-timedelta(minutes=15), now+timedelta(minutes=1)):
            with self.subTest(stamp=stamp), self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self.change('grant', 0, stamp=stamp)
        with self.connect('postgres') as db:
            db.execute('UPDATE bri.session_guards SET latest_provider_change=clock_timestamp() WHERE principal_id=%s',
                       (self.actor[0],))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.change('grant', 0, stamp=now)
        self.assertEqual(self.read(), (0, False))
        with self.connect('postgres') as db:
            db.execute('UPDATE bri.session_guards SET primary_after=clock_timestamp() WHERE principal_id=%s',
                       (self.actor[0],))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.read()

    def test_excluded_targets_and_superuser_positive(self):
        for target in (uuid4(), self.actor[0], self.actors[1][0], self.actors[3][0], self.foreign_actors[2][0]):
            with self.subTest(target=target):
                self.assertIsNone(self.read(target=target))
                self.assertIsNone(self.change('grant', -1, target=target))
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_principals SET status='suspended' WHERE principal_id=%s", (self.target,))
        self.assertIsNone(self.read())
        self.assertIsNone(self.change('grant', -1))
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_principals SET status='active' WHERE principal_id=%s", (self.target,))
            db.execute("UPDATE bri.auth_tenant_memberships SET membership_type='superuser' WHERE principal_id=%s",
                       (self.target,))
            db.execute('INSERT INTO bri.user_delegation_authority VALUES (%s,%s,%s,%s)',
                       (self.tenant, self.target, 'leaf', ORG))
            fresh_actor = (self.target, self.target_uid, uuid4())
            db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                       'VALUES (%s,%s,%s,clock_timestamp())', fresh_actor)
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.read(actor=fresh_actor)
        self.assertTrue(self.change('grant', 0)[1])

    def test_state_conflict_never_adopts_or_revokes_legacy_assignment(self):
        legacy = (self.tenant, self.target)
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.app_roles VALUES (%s,'legacy','Legacy')", (self.tenant,))
            db.execute("INSERT INTO bri.role_permissions VALUES (%s,'legacy',%s)", (self.tenant, ORG))
            db.execute("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) "
                       "VALUES (%s,%s,'legacy','leaf')", legacy)
        self.assertEqual(self.read(), (0, False))
        for action in ('grant', 'revoke'):
            with self.assertRaises(psycopg.errors.ObjectNotInPrerequisiteState):
                self.change(action, 0)
        with self.connect('postgres') as db:
            assignment = db.execute('SELECT role_id,scope_node_id,status FROM bri.auth_role_assignments '
                                    'WHERE (tenant_id,principal_id)=(%s,%s)', legacy).fetchall()
        self.assertEqual(assignment, [('legacy', 'leaf', 'active')])

    def wait_for_blocker(self, observer, writer, name):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if observer.execute('SELECT EXISTS (SELECT FROM pg_stat_activity WHERE application_name=%s '
                                'AND %s=ANY(pg_blocking_pids(pid)))',
                                (name, writer.info.backend_pid)).fetchone()[0]:
                return
            time.sleep(0.02)
        writer.rollback()
        self.fail(f'{name} did not wait for the competing transaction')

    def test_concurrent_writes_have_one_winner_and_stale_replay_fails(self):
        def attempt():
            with self.connect('bri_app') as db:
                db.execute("SET application_name='a114_cas'; SET statement_timeout='10s'")
                return self.run_change(db, 'grant', 0)

        with self.connect('bri_app') as writer, self.connect('postgres', autocommit=True) as observer:
            winner = self.run_change(writer, 'grant', 0)
            with ThreadPoolExecutor(max_workers=1) as pool:
                waiter = pool.submit(attempt)
                self.wait_for_blocker(observer, writer, 'a114_cas')
                writer.commit()
                with self.assertRaises(psycopg.errors.SerializationFailure):
                    waiter.result(timeout=5)
        self.assertEqual(self.read(), winner)
        with self.assertRaises(psycopg.errors.ObjectNotInPrerequisiteState):
            self.change('grant', winner[0])
        with self.assertRaises(psycopg.errors.SerializationFailure):
            self.change('revoke', 0)

    def test_waits_recheck_authority_and_wall_clock_freshness(self):
        # Near-expiry TOTP must still follow the actor's (independent) cutoff.
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.session_guards SET primary_after=clock_timestamp()-interval '20 minutes' "
                       "WHERE principal_id=%s", (self.actor[0],))
        for reason in ('authority', 'totp', 'audit', 'session'):
            with self.subTest(reason=reason), self.connect('postgres') as writer, \
                    self.connect('postgres', autocommit=True) as observer:
                stamp = True
                if reason == 'authority':
                    writer.execute('DELETE FROM bri.user_delegation_authority WHERE tenant_id=%s AND permission=%s',
                                   (self.tenant, ORG))
                elif reason in ('totp', 'audit'):
                    if reason == 'totp':
                        writer.execute('UPDATE bri.client_governance_fence SET id=true')
                    else:
                        # Wait after the initial authorization recheck, in the
                        # A10 trigger's audit append, not at the governance fence.
                        writer.execute('LOCK TABLE bri.security_audit_events IN SHARE MODE')
                    stamp = datetime.now(UTC) - timedelta(minutes=15) + timedelta(seconds=1)
                else:
                    writer.execute('UPDATE bri.auth_sessions SET expires_at=clock_timestamp() WHERE session_id=%s',
                                   (self.actor[2],))
                    # Logout uses the same guard as the delegation boundary.
                    writer.execute('SELECT bri.lock_session_guard(%s)', (self.actor[0],))

                def attempt():
                    with self.connect('bri_app') as db:
                        db.execute("SET application_name='a114_recheck'; SET statement_timeout='10s'")
                        return self.run_change(db, 'grant', 0, stamp=stamp)

                with ThreadPoolExecutor(max_workers=1) as pool:
                    waiter = pool.submit(attempt)
                    self.wait_for_blocker(observer, writer, 'a114_recheck')
                    if reason in ('totp', 'audit'):
                        time.sleep(1.1)
                    writer.commit()
                    with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                        waiter.result(timeout=5)
                if reason == 'authority':
                    writer.execute('INSERT INTO bri.user_delegation_authority VALUES (%s,%s,%s,%s)',
                                   (self.tenant, self.actor[0], 'leaf', ORG))
                elif reason != 'session':
                    self.assertEqual(self.read(), (0, False))

    def test_audit_failure_rolls_back_grant_revoke_and_session_cutoff(self):
        old_primary = datetime.now(UTC)
        for action, past_version in (('grant', 0), ('revoke', 1)):
            with self.subTest(action=action):
                correlation = uuid4()
                before = self.read()
                with self.connect('postgres') as db:
                    prior_cutoff = db.execute('SELECT primary_after FROM bri.session_guards WHERE principal_id=%s',
                                              (self.target,)).fetchone()
                    db.execute("ALTER TABLE bri.security_audit_events ADD CONSTRAINT test_delegation_audit_failure "
                               "CHECK (event_type NOT LIKE 'tenant.user.delegation.%') NOT VALID")
                try:
                    with self.assertRaises(psycopg.errors.CheckViolation):
                        self.change(action, past_version, correlation=correlation)
                    self.assertEqual(self.read(), before)
                    with self.connect('postgres') as db:
                        self.assertEqual(db.execute('SELECT primary_after FROM bri.session_guards WHERE principal_id=%s',
                                                    (self.target,)).fetchone(), prior_cutoff)
                        self.assertEqual(db.execute('SELECT revoked_at FROM bri.auth_sessions WHERE session_id=%s',
                                                    (self.target_sid,)).fetchone(), (None,))
                        self.assertFalse(db.execute('SELECT EXISTS (SELECT FROM bri.security_audit_events '
                                                    'WHERE request_id=%s)', (correlation,)).fetchone()[0])
                finally:
                    with self.connect('postgres') as db:
                        db.execute('ALTER TABLE bri.security_audit_events DROP CONSTRAINT test_delegation_audit_failure')
                self.assertEqual(self.change(action, past_version, correlation=correlation),
                                 (past_version+1, action == 'grant'))
                with self.connect('postgres') as db:
                    self.assertIsNotNone(db.execute('SELECT revoked_at FROM bri.auth_sessions WHERE session_id=%s',
                                                    (self.target_sid,)).fetchone()[0])
                    rows = db.execute('SELECT event_type,delegation_permission,delegation_scope_node_id '
                                      'FROM bri.security_audit_events WHERE request_id=%s AND tenant_id=%s '
                                      'AND actor_principal_id=%s AND subject_principal_id=%s',
                                      (correlation, self.tenant, self.actor[0], self.target)).fetchall()
                    event = 'tenant.user.delegation.granted' if action == 'grant' else 'tenant.user.delegation.revoked'
                    self.assertCountEqual(rows, [('auth.session.revoked', None, None), ('auth.access.changed', None, None),
                                                 (event, ORG, 'leaf')])
                    with self.assertRaisesRegex(psycopg.Error, 'immutable'), db.transaction():
                        db.execute("UPDATE bri.security_audit_events SET outcome='denied' WHERE request_id=%s",
                                   (correlation,))
                with self.connect('bri_app') as db:
                    self.args(db, actor=self.actors[2])
                    start = 'SELECT bri.start_security_session(%s,%s,%s,%s)'
                    for sid, primary in ((self.target_sid, datetime.now(UTC)), (uuid4(), old_primary)):
                        self.assertEqual(db.execute(start, (ISSUER, sid, primary, uuid4())).fetchone(), (None,))
                    self.target_sid = uuid4()
                    self.assertIsNotNone(db.execute(start, (ISSUER, self.target_sid, datetime.now(UTC),
                                                            uuid4())).fetchone()[0])

    def test_runtime_catalog_acl_and_indirect_parent_paths(self):
        with self.connect('bri_app') as db:
            self.args(db)
            for stmt in ("INSERT INTO bri.app_roles VALUES (current_setting('bri.tenant_id'),'extra','Extra')",
                         "UPDATE bri.app_roles SET display_name='Changed' WHERE role_id='reset'",
                         "DELETE FROM bri.app_roles WHERE role_id='delegation-org'",  # permission FK cascade
                         "INSERT INTO bri.role_permissions VALUES (current_setting('bri.tenant_id'),'reset','extra')",
                         "UPDATE bri.role_permissions SET permission='extra' WHERE role_id='reset'",
                         "DELETE FROM bri.role_permissions WHERE role_id='reset'",
                         "UPDATE bri.tenants SET tenant_id='changed' WHERE tenant_id=current_setting('bri.tenant_id')",
                         'TRUNCATE bri.app_roles CASCADE', 'DELETE FROM bri.auth_role_assignments',
                         'SELECT * FROM bri.user_delegation_authority', 'SELECT * FROM bri.user_delegation_bundles',
                         'SELECT * FROM bri.user_delegation_state',
                         'SELECT bri.user_delegation_delta_allowed(NULL,NULL,NULL,NULL)',
                         "INSERT INTO bri.security_audit_events (event_type,outcome) "
                         "VALUES ('tenant.user.delegation.granted','success')"):
                with self.subTest(stmt=stmt), self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                    db.execute(stmt)
            for stmt in ("DELETE FROM bri.tenants WHERE tenant_id=current_setting('bri.tenant_id')",
                         "UPDATE bri.org_nodes SET node_id='changed' WHERE node_id='leaf'",
                         "DELETE FROM bri.org_nodes WHERE node_id='leaf'"):
                with self.subTest(stmt=stmt), self.assertRaises(psycopg.errors.ForeignKeyViolation), db.transaction():
                    db.execute(stmt)
            db.execute("INSERT INTO bri.synthetic_principals VALUES (current_setting('bri.tenant_id'),'fixture','Test')")
            db.execute("INSERT INTO bri.role_assignments VALUES (current_setting('bri.tenant_id'),'fixture','reset','leaf')")
            with self.assertRaises(psycopg.errors.ObjectNotInPrerequisiteState), db.transaction():
                db.execute("UPDATE bri.role_assignments SET role_id='delegation-org' WHERE principal_id='fixture'")
        self.assertEqual(self.read(), (0, False))

    def test_platform_cannot_register_non_singleton_or_repurpose_live_bundle(self):
        self.change('grant', 0)
        with self.connect('postgres') as db:
            for stmt, args in (
                ("INSERT INTO bri.role_permissions VALUES (%s,'delegation-org','document:create')", (self.tenant,)),
                ("DELETE FROM bri.role_permissions WHERE tenant_id=%s AND role_id='delegation-org'", (self.tenant,)),
                ("DELETE FROM bri.app_roles WHERE tenant_id=%s AND role_id='delegation-org'", (self.tenant,)),
                ("DELETE FROM bri.user_delegation_bundles WHERE tenant_id=%s", (self.tenant,)),
                ("UPDATE bri.user_delegation_bundles SET role_id='reset' WHERE tenant_id=%s", (self.tenant,)),
                ("UPDATE bri.auth_role_assignments SET scope_node_id='root' WHERE tenant_id=%s AND principal_id=%s",
                 (self.tenant,self.target)),
                ("DELETE FROM bri.auth_role_assignments WHERE tenant_id=%s AND principal_id=%s", (self.tenant,self.target)),
                ("INSERT INTO bri.user_delegation_bundles VALUES (%s,'organisation:read','reset')", (self.tenant,)),
            ):
                with self.subTest(stmt=stmt), self.assertRaises(psycopg.errors.ObjectNotInPrerequisiteState), db.transaction():
                    db.execute(stmt, args)
            db.execute('INSERT INTO bri.app_roles VALUES (%s,%s,%s)', (self.tenant, 'unlisted', 'Unlisted'))
            db.execute('INSERT INTO bri.role_permissions VALUES (%s,%s,%s)', (self.tenant, 'unlisted', 'document:read'))
            with self.assertRaises(psycopg.errors.CheckViolation), db.transaction():
                db.execute('INSERT INTO bri.user_delegation_bundles VALUES (%s,%s,%s)',
                           (self.tenant, 'document:read', 'unlisted'))
            db.execute('DELETE FROM bri.user_delegation_authority WHERE tenant_id=%s AND permission=%s', (self.tenant, ORG))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.read()

    def test_operational_two_admin_minimum_remains_in_force(self):
        with self.connect('postgres') as db:
            with self.assertRaises(psycopg.errors.CheckViolation), db.transaction():
                db.execute("UPDATE bri.auth_tenant_memberships SET membership_type='user' WHERE principal_id=%s",
                           (self.actors[1][0],))
        self.assertTrue(self.change('grant', 0)[1])
        with self.connect('postgres') as db:
            db.execute('SELECT bri.record_client_totp_observation(%s,%s,%s,%s,clock_timestamp(),NULL)',
                       (self.tenant, self.actors[1][0], self.actors[1][1], ISSUER))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.change('revoke', 1)

    def test_real_knowledge_routes_require_p1_record_and_version_access(self):
        cases = ((True, True), (False, True), (True, False), (p1.ABSENT, True), (True, p1.ABSENT))
        items = [p1.Evidence(f'delegatedartifact{i}', tenant=self.tenant, scope='leaf') for i in range(len(cases))]
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.synthetic_principals VALUES (%s,'author','Author'),(%s,'reviewer','Reviewer')",
                       (self.tenant,self.tenant))
            for item in items:
                p1.seed_evidence(db, item)
        with self.connect('bri_migrator') as db:
            p1.set_tenant(db, self.tenant)
            for item, (record, version) in zip(items, cases, strict=True):
                p1.insert_policy(db, p1.RECORD_ACCESS, item, record)
                p1.insert_policy(db, p1.VERSION_ACCESS, item, version)
        verifier = AsyncMock()
        database = p1.PrivateAppDatabase(self.connect)
        database.supabase_url = ISSUER.removesuffix('/auth/v1')  # issuer comparison only; sockets stay private
        app = create_app(settings=ApiSettings(environment='hosted-development', auth_mode='supabase'),
                         database=database, token_verifier=verifier)
        client = self.enterContext(TestClient(app))
        headers = {'Authorization': 'Bearer synthetic'}
        verifier.verify.return_value = AuthenticatedIdentity(str(self.target_uid), str(self.target_sid), ISSUER, 'aal2', ('totp',))
        self.assertEqual(client.get(p1.BASE, headers=headers).status_code, 403)
        self.change('grant', 0, permission=KNOWLEDGE)
        self.assertEqual(client.get(p1.BASE, headers=headers).status_code, 401)
        sid = uuid4()
        with self.connect('bri_app') as db:
            self.args(db, actor=self.actors[2])
            started = db.execute('SELECT bri.start_security_session(%s,%s,%s,%s)',
                                 (ISSUER, sid, datetime.now(UTC), uuid4())).fetchone()[0]
            self.assertIsNotNone(started)
        verifier.verify.return_value = AuthenticatedIdentity(str(self.target_uid), str(sid), ISSUER, 'aal2', ('totp',))
        listing = client.get(p1.BASE, headers=headers)
        self.assertEqual(listing.status_code, 200, listing.text)
        self.assertEqual([row['record_id'] for row in listing.json()], [items[0].record_id])
        for index, item in enumerate(items):
            for base in (p1.BASE, '/v1/sources'):
                self.assertEqual(client.get(f'{base}/{item.record_id}', headers=headers).status_code, 404 if index else 200)
            search = client.get(f'{p1.BASE}/search', headers=headers, params={'q': item.token})
            self.assertEqual(search.status_code, 200, search.text)
            if index:
                self.assertEqual(search.json(), p1.INSUFFICIENT)
            else:
                self.assertEqual(search.json()['citations'][0]['record_id'], item.record_id)
