"""Opt-in private PG16+ cluster. Set BRI_TEST_PG_BIN to a local bin directory.

Never reads a DSN, .env or provider configuration. No TCP listener. Temporary
owner-only socket directory and fresh database are removed on completion.
"""
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path
from threading import Barrier
from typing import cast
from unittest.mock import patch
from uuid import uuid4

import psycopg

from bri.api.database import Database, ProtectedAccessDenied
from scripts.db import migrate

ROOT = Path(__file__).resolve().parents[1]
BIN = os.environ.get('BRI_TEST_PG_BIN')
ISSUER = 'https://synthetic.invalid/auth/v1'


@unittest.skipUnless(BIN, 'requires local PostgreSQL binaries for a new private cluster')
class LifecyclePostgres(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # libpq PGHOSTADDR/PGSERVICE etc can override even an explicit host.
        if any(name.startswith('PG') for name in os.environ):
            raise RuntimeError('unset inherited PostgreSQL settings before running private tests')
        tmp = tempfile.TemporaryDirectory(prefix='a10-')
        cls.addClassCleanup(tmp.cleanup)
        root = Path(tmp.name)
        data = root / 'pg'
        env = {'PATH': os.defpath, 'LC_ALL': 'C'}

        assert BIN is not None

        def ctl(program, *args):
            subprocess.run([str(Path(BIN) / program), *args], env=env, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        ctl('initdb', '-D', str(data), '-U', 'test_owner', '-A', 'trust', '--no-locale', '-E', 'UTF8')
        ctl('pg_ctl', '-D', str(data), '-l', str(root/'pg.log'), '-o',
            f"-c listen_addresses='' -c unix_socket_directories='{root}' -c unix_socket_permissions=0700", '-w', 'start')
        cls.addClassCleanup(ctl, 'pg_ctl', '-D', str(data), '-m', 'immediate', '-w', 'stop')
        connect = psycopg.connect

        def local(role, **kwargs):
            return connect(host=str(root), port=5432, user=role, dbname='postgres', passfile=str(root/'nonexistent-passfile'), **kwargs)
        cls.local = staticmethod(local)
        with local('test_owner') as conn:
            conn.execute('CREATE ROLE bri_app LOGIN NOINHERIT; CREATE ROLE bri_migrator LOGIN NOINHERIT CONNECTION LIMIT 2; CREATE SCHEMA bri AUTHORIZATION bri_migrator;')
        target = root/'db'/'migrations'
        target.mkdir(parents=True)
        for migration in (ROOT/'db'/'migrations').glob('*.sql'):
            # These tests call the current Database adapter, including the
            # structured-TOTP session-start overload added in 0019.
            shutil.copy(migration, target)
        supplied = 'postgresql://bri_migrator@db.' + migrate.EXPECTED_REF + '.supabase.co:5432/postgres'

        def restricted(dsn, **kwargs):
            assert dsn == supplied
            return local('bri_migrator', **kwargs)
        with patch.object(migrate, 'ROOT', root), patch.object(migrate, 'env_values', return_value={
            'BRI_ENVIRONMENT': 'local', 'SUPABASE_URL': f'https://{migrate.EXPECTED_REF}.supabase.co',
            'BRI_MIGRATION_ROLE_DATABASE_URL': supplied,
        }), patch.object(migrate.psycopg, 'connect', restricted), redirect_stdout(StringIO()) as log:
            if migrate.main() or migrate.main():
                raise AssertionError(log.getvalue())
            assert 'applied_count=0' in log.getvalue()
        with local('bri_migrator') as conn:
            migrate.verify_ledger(conn, sorted(target.glob('*.sql')))
            assert conn.execute('select version from bri.schema_migrations order by version').fetchall() == [
                (path.stem,) for path in sorted(target.glob('*.sql'))
            ]

    def setUp(self):
        self.subject, self.user, self.sid = (str(uuid4()) for _ in range(3))
        self.tenant = 'synthetic-' + self.subject
        with self.local('test_owner') as c:
            c.execute("INSERT INTO bri.tenants VALUES (%s,'Test','synthetic')", (self.tenant,))
            c.execute("INSERT INTO bri.auth_principals(principal_id,status) VALUES (%s,'active')", (self.subject,))
            c.execute("INSERT INTO bri.auth_identity_links(auth_user_id,principal_id,auth_issuer,auth_subject,provider_type,provider_issuer,provider_subject) VALUES (%s,%s,%s,%s,'native',%s,%s)", (self.user,self.subject,ISSUER,self.user,ISSUER,self.user))
            c.execute("INSERT INTO bri.auth_tenant_memberships(tenant_id,principal_id,status) VALUES (%s,%s,'active')", (self.tenant,self.subject))
        self.db = Database(ISSUER.removesuffix('/auth/v1'), '')
        self.enterContext(patch.object(Database, '_connect', lambda _: self.local('bri_app')))

    def start(self, sid=None, primary=None, correlation=None):
        return self.db.start_auth_session(self.user,ISSUER,self.user,sid or self.sid,
                                          primary_authenticated_at=primary,correlation_id=correlation)

    def activate_client(self):
        # Platform provisioning + two distinct, currently attested client admins.
        with self.local('test_owner') as c:
            c.execute('INSERT INTO bri.tenant_admin_policies(tenant_id) VALUES (%s)', (self.tenant,))
            c.execute("INSERT INTO bri.org_nodes VALUES(%s,'root','test','Root')", (self.tenant,))
            c.execute("INSERT INTO bri.app_roles VALUES(%s,'setup','Setup')", (self.tenant,))
            c.execute("INSERT INTO bri.role_permissions VALUES(%s,'setup','platform:client_admin:manage')", (self.tenant,))
            for membership in ('platform_superadmin','admin','admin'):
                principal, uid = str(uuid4()), str(uuid4())
                c.execute("INSERT INTO bri.auth_principals(principal_id,status) VALUES (%s,'active')", (principal,))
                c.execute("INSERT INTO bri.auth_identity_links(auth_user_id,principal_id,auth_issuer,auth_subject,provider_type,provider_issuer,provider_subject) VALUES(%s,%s,%s,%s,'native',%s,%s)",
                          (uid,principal,ISSUER,uid,ISSUER,uid))
                if membership == 'platform_superadmin':
                    c.execute('INSERT INTO bri.platform_superadmins(principal_id) VALUES (%s)', (principal,))
                    c.execute("SELECT set_config('bri.auth_user_id',%s,true),set_config('bri.tenant_id',%s,true)", (uid,self.tenant))
                c.execute("INSERT INTO bri.auth_tenant_memberships(tenant_id,principal_id,membership_type,status) VALUES(%s,%s,%s,'active')",
                          (self.tenant,principal,membership))
                if membership == 'platform_superadmin':
                    c.execute("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) VALUES(%s,%s,'setup','root')", (self.tenant,principal))
                else:
                    c.execute("SELECT bri.record_client_totp_observation(%s,%s,%s,%s,now(),now()+interval '10 minutes')", (self.tenant,principal,uid,ISSUER))
            c.execute('SELECT bri.activate_client(%s)', (self.tenant,))

    def protected(self, **changes):
        params = {'tenant_id': self.tenant, 'auth_user_id': self.user, 'session_id': self.sid,
                      'principal_id': self.subject, 'issuer': ISSUER}
        params.update(changes)
        return self.db.protected_tenant_context(**params)

    def test_protected_read_uses_the_authorized_snapshot_not_later_data(self):
        self.assertTrue(self.start(primary=datetime.now(UTC)))
        with self.assertRaises(ProtectedAccessDenied), self.protected():
            self.fail('provisioning tenant admitted')
        self.activate_client()
        self.assertTrue(self.db.client_is_operational(self.tenant,self.user))
        for binding in ({'principal_id': str(uuid4())}, {'session_id': str(uuid4())},
                        {'auth_user_id': str(uuid4())}, {'tenant_id':'other'}, {'issuer':'other'}):
            with self.subTest(binding=binding), self.assertRaises(ProtectedAccessDenied), self.protected(**binding):
                self.fail('wrong identity/tenant/session admitted')
        with self.protected() as session:
            reader = cast(psycopg.Connection, session.connection)
            self.assertEqual(reader.execute('SHOW transaction_read_only').fetchone(), ('on',))
            self.assertEqual(reader.execute('SHOW transaction_isolation').fetchone(), ('repeatable read',))
            # Quorum loss and new client data commit on another connection AFTER
            # the check, BEFORE the business read. The checked reader cannot see
            # the new data. The next protected transaction cannot enter at all.
            with self.local('test_owner') as writer:
                writer.execute("UPDATE bri.client_totp_observations SET verified_until=NULL WHERE tenant_id=%s", (self.tenant,))
                writer.execute("UPDATE bri.tenants SET display_name='Changed' WHERE tenant_id=%s", (self.tenant,))
            self.assertEqual(reader.execute('SELECT display_name FROM bri.tenants').fetchall(), [('Test',)])
        with self.assertRaises(ProtectedAccessDenied), self.protected():
            self.fail('lost quorum admitted')

    def test_hosted_tenant_and_configuration_requests_share_the_guarded_db_boundary(self):
        from fastapi.testclient import TestClient

        from bri.api.app import ApiSettings, create_app
        from bri.api.authentication import AuthenticatedIdentity

        self.activate_client()
        with self.local('test_owner') as c:
            c.execute("UPDATE bri.auth_tenant_memberships SET membership_type='admin' WHERE principal_id=%s", (self.subject,))
            c.execute("INSERT INTO bri.app_roles VALUES (%s,'reader','Reader')", (self.tenant,))
            for permission in ('prompt:client:read','organisation:read'):
                c.execute("INSERT INTO bri.role_permissions VALUES (%s,'reader',%s)", (self.tenant,permission))
            c.execute("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) VALUES(%s,%s,'reader','root')", (self.tenant,self.subject))
        self.assertTrue(self.start(primary=datetime.now(UTC)))
        identity = AuthenticatedIdentity(self.user,self.sid,ISSUER,'aal2',('totp',))
        class LocalVerifier:
            async def verify(self, token):
                return identity
        settings = ApiSettings(environment='hosted-development', auth_mode='supabase', supabase_url=self.db.supabase_url)
        client = TestClient(create_app(settings=settings,database=self.db,token_verifier=LocalVerifier()))
        headers = {'Authorization':'Bearer synthetic-only'}
        paths = ('/v1/configuration/prompts/versions','/v1/organizations/structure')
        for path in paths:
            response = client.get(path,headers=headers)
            self.assertEqual(response.status_code,200,response.text)
        with self.local('test_owner') as c:
            c.execute('UPDATE bri.client_totp_observations SET verified_until=NULL WHERE tenant_id=%s', (self.tenant,))
        self.assertTrue(self.db.auth_session_is_active(self.user,self.sid))
        for path in paths:
            self.assertEqual(client.get(path,headers=headers).status_code,403)

    def test_protected_read_rechecks_session_and_membership_after_preflight(self):
        self.activate_client()
        self.assertTrue(self.start(primary=datetime.now(UTC)))
        self.assertTrue(self.db.auth_session_is_active(self.user,self.sid))
        self.assertTrue(self.db.revoke_auth_session(self.user,self.sid))
        with self.assertRaises(ProtectedAccessDenied), self.protected():
            self.fail('logged-out session admitted')
        self.sid = str(uuid4())
        self.assertTrue(self.start(primary=datetime.now(UTC)))
        with self.local('test_owner') as c:
            c.execute("UPDATE bri.auth_tenant_memberships SET status='suspended' WHERE principal_id=%s", (self.subject,))
        with self.assertRaises(ProtectedAccessDenied), self.protected():
            self.fail('suspended membership admitted')

    def test_eight_hour_expiry_cannot_be_restarted(self):
        with self.local('test_owner') as c:
            c.execute("INSERT INTO bri.auth_sessions(auth_user_id,principal_id,session_id,started_at,expires_at) "
                      "VALUES(%s,%s,%s,now()-interval '9 hours',now()-interval '1 hour')",
                      (self.user,self.subject,self.sid))
        self.assertFalse(self.db.auth_session_is_active(self.user,self.sid))
        self.assertIsNone(self.start(primary=datetime.now(UTC)))

    def seed_session_window(self, start_offset, expiry_offset):
        with self.local('test_owner') as c:
            return c.execute(
                "INSERT INTO bri.auth_sessions(auth_user_id,principal_id,session_id,started_at,expires_at) "
                "VALUES(%s,%s,%s,now()+%s,now()+%s) RETURNING started_at,expires_at",
                (self.user, self.subject, self.sid, start_offset, expiry_offset),
            ).fetchone()

    def test_persisted_session_window_at_each_access_boundary(self):
        self.activate_client()
        for start_hours, expiry_hours, live in (
            (-9, 12, False), (-8, 1, False), (1, 9, False),
            (-1, -0.5, False), (-7, 12, True), (-1, 2, True),
        ):
            self.sid = str(uuid4())
            started, expires = self.seed_session_window(
                timedelta(hours=start_hours), timedelta(hours=expiry_hours)
            )
            with self.subTest(start=start_hours, path='ordinary'):
                self.assertIs(self.db.auth_session_is_active(self.user, self.sid), live)
            with self.subTest(start=start_hours, path='resource'):
                if live:
                    with self.protected() as session:
                        reader = cast(psycopg.Connection, session.connection)
                        self.assertEqual(reader.execute('SELECT tenant_id FROM bri.tenants').fetchall(), [(self.tenant,)])
                else:
                    with self.assertRaises(ProtectedAccessDenied), self.protected():
                        self.fail('invalid session admitted to protected resource')
            deadline = min(started + timedelta(hours=8), expires) if live else None
            with self.subTest(start=start_hours, path='start/replay'):
                for _ in range(2):
                    self.assertEqual(self.start(primary=datetime.now(UTC)), deadline)

    def test_over_age_persisted_session_cannot_reserve_recovery(self):
        self.seed_session_window(timedelta(hours=-9), timedelta(hours=2))
        self.assertFalse(self.db.invalidate_for_password_recovery(
            self.user, self.sid, correlation_id=uuid4(), recovery_authenticated_at=datetime.now(UTC),
        ))
        with self.local('test_owner') as c:
            self.assertEqual(c.execute('SELECT count(*) FROM bri.credential_operations WHERE principal_id=%s',
                                       (self.subject,)).fetchone(), (0,))

    def test_logout_of_unseen_session_is_a_durable_idempotent_denial(self):
        request_id = uuid4()
        self.assertTrue(self.db.revoke_auth_session(self.user,self.sid,correlation_id=request_id))
        self.assertIsNone(self.start(primary=datetime.now(UTC)))
        self.assertTrue(self.db.revoke_auth_session(self.user,self.sid))
        self.assertFalse(self.db.invalidate_for_password_recovery(self.user,self.sid,correlation_id=uuid4(),
                                                                  recovery_authenticated_at=datetime.now(UTC)))
        with self.local('test_owner') as c:
            self.assertEqual(c.execute('SELECT logout_tombstone,revoked_at IS NOT NULL FROM bri.auth_sessions WHERE auth_user_id=%s AND session_id=%s',
                                       (self.user,self.sid)).fetchone(), (True,True))
            self.assertEqual(c.execute("SELECT event_type,request_id FROM bri.security_audit_events WHERE subject_principal_id=%s AND event_type LIKE 'auth.session.%%'", (self.subject,)).fetchall(),
                             [('auth.session.revoked',request_id)])

    def test_logout_audit_failure_rolls_back_tombstone_and_existing_revocation(self):
        from bri.api.database import DatabaseUnavailable
        self.assertTrue(self.start(primary=datetime.now(UTC)))
        unseen = str(uuid4())
        with self.local('bri_migrator') as c:
            c.execute("ALTER TABLE bri.security_audit_events ADD CONSTRAINT reject_logout_audit CHECK(event_type<>'auth.session.revoked') NOT VALID")
        try:
            for sid in (self.sid,unseen):
                with self.assertRaises(DatabaseUnavailable):
                    self.db.revoke_auth_session(self.user,sid)
            self.assertTrue(self.db.auth_session_is_active(self.user,self.sid))
            with self.local('test_owner') as c:
                self.assertEqual(c.execute('SELECT count(*) FROM bri.auth_sessions WHERE auth_user_id=%s AND session_id=%s',
                                           (self.user,unseen)).fetchone(), (0,))
        finally:
            with self.local('bri_migrator') as c:
                c.execute('ALTER TABLE bri.security_audit_events DROP CONSTRAINT reject_logout_audit')

    def test_start_and_logout_serialize_in_both_orders(self):
        for logout_first in (False, True):
            sid = str(uuid4())
            start = ('SELECT bri.start_security_session(%s,%s,%s,%s)', (ISSUER,sid,datetime.now(UTC),uuid4()))
            end = ('SELECT bri.revoke_security_session(%s,%s)', (sid,uuid4()))
            with self.subTest(logout_first=logout_first), self.local('bri_app') as first, self.local('bri_app') as second:
                for c in (first,second):
                    c.execute("SELECT set_config('bri.auth_user_id',%s,true)", (self.user,))
                    c.execute("SET LOCAL statement_timeout='6s'")
                self.assertTrue(first.execute(*(end if logout_first else start)).fetchone()[0])
                with ThreadPoolExecutor(1) as pool:
                    waiter = pool.submit(second.execute, *(start if logout_first else end))
                    try:
                        with self.local('test_owner',autocommit=True) as monitor:
                            deadline = time.monotonic()+4
                            while time.monotonic()<deadline:
                                blockers = monitor.execute('SELECT pg_blocking_pids(%s)', (second.info.backend_pid,)).fetchone()[0]
                                if first.info.backend_pid in blockers:
                                    break
                                time.sleep(.01)
                            else:
                                self.fail('start/logout did not serialize on the pending transaction')
                        first.commit()
                        self.assertIs(waiter.result(timeout=4).fetchone()[0], None if logout_first else True)
                    finally:
                        first.rollback()
            self.assertFalse(self.db.auth_session_is_active(self.user,sid))
            self.assertIsNone(self.start(sid,datetime.now(UTC)))

    def test_atomic_immutable_session_and_logout(self):
        now = datetime.now(UTC)
        start, end = uuid4(), uuid4()
        expiry = self.start(primary=now, correlation=start)
        self.assertIsNotNone(expiry)
        self.assertEqual(expiry,self.start(primary=now))
        with self.local('test_owner') as c:
            self.assertEqual(c.execute('SELECT expires_at-started_at FROM bri.auth_sessions WHERE auth_user_id=%s', (self.user,)).fetchone()[0], timedelta(hours=8))
        self.assertTrue(self.db.revoke_auth_session(self.user,self.sid,correlation_id=end))
        self.assertTrue(self.db.revoke_auth_session(self.user,self.sid))
        self.assertIsNone(self.start(primary=now))
        with self.local('test_owner') as c:
            rows = c.execute("SELECT event_type, request_id FROM bri.security_audit_events WHERE subject_principal_id=%s AND event_type LIKE 'auth.session.%%' ORDER BY occurred_at", (self.subject,)).fetchall()
        self.assertEqual(rows,[('auth.session.started',start),('auth.session.revoked',end)])

    def confirm(self, kind='password_reset', op=None, eid=None, issuer=ISSUER, role='bri_migrator'):
        with self.local(role) as c:
            return c.execute('SELECT bri.confirm_credential_change(%s,%s,%s,%s,%s,%s)',
                             (self.user,issuer,kind,eid or uuid4(),op,uuid4())).fetchone()[0]

    def test_recovery_replay_and_trusted_correlated_confirmation(self):
        old = datetime.now(UTC)
        self.assertTrue(self.start(primary=old))
        op, sid, eid = uuid4(), str(uuid4()), uuid4()
        self.assertTrue(self.db.invalidate_for_password_recovery(self.user,sid,correlation_id=op,recovery_authenticated_at=old))
        self.assertFalse(self.db.auth_session_is_active(self.user,self.sid))
        self.assertFalse(self.db.invalidate_for_password_recovery(self.user,sid,correlation_id=uuid4()))
        self.assertFalse(self.confirm(op=uuid4()))
        self.assertFalse(self.confirm(op=op,issuer='https://wrong.invalid'))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.confirm(op=op,role='bri_app')
        # A real uncorrelated change cannot release someone else's pending op.
        self.assertTrue(self.confirm())
        self.assertIsNone(self.start(str(uuid4()),datetime.now(UTC)))
        self.assertTrue(self.confirm(op=op,eid=eid))
        fresh = datetime.now(UTC)
        self.assertIsNone(self.start(primary=fresh))  # revoked provider session
        self.assertIsNone(self.start(sid,fresh))  # consumed recovery session, never registered in BRI
        self.assertFalse(self.db.invalidate_for_password_recovery(self.user,sid,correlation_id=uuid4()))
        self.assertIsNone(self.start(str(uuid4()),old))  # old unseen provider session
        self.assertIsNone(self.start(str(uuid4())))      # no primary evidence
        new = str(uuid4())
        self.assertTrue(self.start(new,fresh))
        self.assertTrue(self.confirm(op=op,eid=eid))
        self.assertFalse(self.confirm(eid=eid))  # event ID cannot be rebound
        self.assertTrue(self.db.auth_session_is_active(self.user,new))
        self.assertTrue(self.confirm())           # external reset without any browser callback
        unseen = str(uuid4())
        self.assertFalse(self.db.invalidate_for_password_recovery(self.user,unseen,correlation_id=uuid4()))
        self.assertFalse(self.db.invalidate_for_password_recovery(self.user,unseen,correlation_id=uuid4(),
                                                                  recovery_authenticated_at=old))
        self.assertFalse(self.db.auth_session_is_active(self.user,new))
        self.assertIsNone(self.start(str(uuid4()),fresh))

    def test_concurrent_recovery_has_one_permit_and_start_cannot_escape(self):
        primary = datetime.now(UTC)
        recovery, op1, op2 = str(uuid4()), uuid4(), uuid4()
        ready = Barrier(3)

        def reserve(op):
            ready.wait(timeout=10)
            return self.db.invalidate_for_password_recovery(self.user,recovery,correlation_id=op,recovery_authenticated_at=primary)

        def sign_in():
            ready.wait(timeout=10)
            return self.start(primary=primary)

        with ThreadPoolExecutor(max_workers=3) as pool:
            attempts = [pool.submit(reserve,op) for op in (op1,op2)]
            pool.submit(sign_in).result(timeout=15)
            self.assertCountEqual([a.result(timeout=15) for a in attempts],[True,False])
        self.assertFalse(self.db.auth_session_is_active(self.user,self.sid))
        self.assertIsNone(self.start(str(uuid4()),datetime.now(UTC)))

    def test_suspended_membership_denies_recovery_and_start_after_reactivation_needs_fresh_auth(self):
        old = datetime.now(UTC)
        self.assertIsNotNone(self.start(primary=old))
        with self.local('test_owner') as c:
            c.execute("UPDATE bri.auth_tenant_memberships SET status='suspended' WHERE principal_id=%s", (self.subject,))
        self.assertFalse(self.db.auth_session_is_active(self.user,self.sid))
        self.assertFalse(self.db.invalidate_for_password_recovery(self.user,str(uuid4()),correlation_id=uuid4()))
        self.assertIsNone(self.start(str(uuid4()),datetime.now(UTC)))
        with self.local('test_owner') as c:
            c.execute("UPDATE bri.auth_tenant_memberships SET status='active' WHERE principal_id=%s", (self.subject,))
        self.assertIsNone(self.start(str(uuid4()),old))
        self.assertIsNone(self.start(primary=datetime.now(UTC)))
        self.assertIsNone(self.start(str(uuid4()),datetime.now(UTC)+timedelta(seconds=60)))
        self.assertTrue(self.start(str(uuid4()),datetime.now(UTC)))

    def test_reenrollment_requires_a_matching_trusted_completion(self):
        op = uuid4()
        with self.local('bri_migrator') as c:
            self.assertTrue(c.execute('SELECT bri.reserve_factor_reenrollment(%s,%s,%s,%s)',
                                      (self.user,self.subject,op,uuid4())).fetchone()[0])
        self.assertFalse(self.confirm(op=op))
        self.assertFalse(self.confirm(kind='factor_reenrollment'))
        self.assertIsNone(self.start(primary=datetime.now(UTC)))
        # 0012 additionally requires the separately verified re-enrollment proof.
        # An operator calling the generic 0008 helper alone cannot release it.
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.confirm(kind='factor_reenrollment',op=op)
        self.assertIsNone(self.start(primary=datetime.now(UTC)))

    def test_grant_changes_cover_other_links_and_shared_role_definitions(self):
        other = str(uuid4())
        with self.local('test_owner') as c:
            c.execute("INSERT INTO bri.auth_identity_links(auth_user_id,principal_id,auth_issuer,auth_subject,provider_type,provider_issuer,provider_subject) VALUES (%s,%s,%s,%s,'native',%s,%s)",
                      (other,self.subject,ISSUER,other,ISSUER,other))
            c.execute("INSERT INTO bri.org_nodes(tenant_id,node_id,node_type,display_name) VALUES(%s,'scope','test','Test')", (self.tenant,))
            c.execute("INSERT INTO bri.app_roles VALUES(%s,'role','Test')", (self.tenant,))
        stmts = [
            ("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) VALUES(%s,%s,'role','scope')", (self.tenant,self.subject)),
            ("INSERT INTO bri.role_permissions VALUES(%s,'role','document:read')", (self.tenant,)),
            ("UPDATE bri.role_permissions SET permission='document:create' WHERE tenant_id=%s", (self.tenant,)),
            ("DELETE FROM bri.role_permissions WHERE tenant_id=%s", (self.tenant,)),
            ("DELETE FROM bri.auth_role_assignments WHERE principal_id=%s", (self.subject,)),
            ("UPDATE bri.auth_tenant_memberships SET membership_type='superuser' WHERE principal_id=%s", (self.subject,)),
            ("INSERT INTO bri.platform_superadmins(principal_id) VALUES(%s)", (self.subject,)),
            ("DELETE FROM bri.platform_superadmins WHERE principal_id=%s", (self.subject,)),
            ("UPDATE bri.auth_identity_links SET status='suspended' WHERE auth_user_id=%s", (other,)),
            ("UPDATE bri.auth_principals SET status='suspended' WHERE principal_id=%s", (self.subject,)),
        ]
        old = datetime.now(UTC)
        for stmt,args in stmts:
            with self.subTest(stmt=stmt):
                old = datetime.now(UTC)
                sid = str(uuid4())
                self.assertTrue(self.start(sid,old))
                if stmt.startswith('INSERT INTO bri.role_permissions'):
                    self.assertTrue(self.db.start_auth_session(other,ISSUER,other,sid,primary_authenticated_at=old))
                with self.local('test_owner') as c:
                    c.execute(stmt,args)
                self.assertFalse(self.db.auth_session_is_active(self.user,sid))
                self.assertFalse(self.db.auth_session_is_active(other,sid))
                self.assertIsNone(self.start(str(uuid4()),old))
        with self.local('test_owner') as c:
            c.execute("UPDATE bri.auth_principals SET status='active' WHERE principal_id=%s", (self.subject,))
        self.assertIsNone(self.start(str(uuid4()),old))
        self.assertTrue(self.start(str(uuid4()),datetime.now(UTC)))

    def test_forced_rls_grants_immutability_and_atomic_rollback(self):
        with self.local('bri_app') as c:
            for tbl in ('session_guards','credential_operations','credential_event_receipts','security_retention_policy'):
                self.assertEqual(c.execute("SELECT relrowsecurity,relforcerowsecurity,has_table_privilege(current_user,oid,'UPDATE') FROM pg_class WHERE oid=%s::regclass", ('bri.'+tbl,)).fetchone(), (True,True,False))
            self.assertFalse(c.execute("SELECT has_column_privilege(current_user,'bri.auth_sessions','session_id','INSERT')").fetchone()[0])
            self.assertFalse(c.execute("SELECT has_column_privilege(current_user,'bri.auth_sessions','revoked_at','UPDATE')").fetchone()[0])
            self.assertEqual(c.execute("SELECT relrowsecurity,relforcerowsecurity,has_function_privilege(current_user,'bri.revoke_security_session(uuid,uuid)','EXECUTE'),has_column_privilege(current_user,oid,'logout_tombstone','UPDATE'),has_column_privilege(current_user,oid,'logout_tombstone','INSERT') FROM pg_class WHERE oid='bri.auth_sessions'::regclass").fetchone(), (True,True,True,False,False))
        with self.local('bri_migrator') as c:
            self.assertEqual(c.execute('SELECT retention_days FROM bri.security_retention_policy').fetchone(), (365,))
            with self.assertRaises(psycopg.Error), c.transaction():
                c.execute('DELETE FROM bri.security_audit_events')
            with self.assertRaises(psycopg.Error), c.transaction():
                c.execute('TRUNCATE bri.security_audit_events')
        # Inject a transaction-local failure at audit insertion. No start or
        # change in expiry can persist without its paired immutable event.
        with self.local('bri_migrator') as c:
            c.execute("ALTER TABLE bri.security_audit_events ADD CONSTRAINT test_failure CHECK(event_type <> 'auth.session.started') NOT VALID")
        try:
            from bri.api.database import DatabaseUnavailable
            with self.assertRaises(DatabaseUnavailable):
                self.start(primary=datetime.now(UTC))
            self.assertFalse(self.db.auth_session_is_active(self.user,self.sid))
        finally:
            with self.local('bri_migrator') as c:
                c.execute('ALTER TABLE bri.security_audit_events DROP CONSTRAINT test_failure')
