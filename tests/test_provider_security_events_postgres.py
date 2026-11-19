"""PG16+ opt-in: create a new private Unix-socket cluster; never accept a DSN."""
import hashlib
import hmac
import io
import json
import os
import secrets
import subprocess
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import psycopg

from bri.api.provider_events import IngestionUnavailable, ProviderEventConsumer
from scripts.db import migrate

BIN = os.environ.get('BRI_TEST_PG_BIN')
ISSUER = 'https://synthetic.invalid/auth/v1'
ROLE = 'bri_provider_ingest'
ROUTINE = 'bri.ingest_provider_security_event(text,uuid,uuid,text,text,timestamptz,uuid)'


def now():
    return datetime.now(UTC)


@unittest.skipUnless(BIN, 'requires PG16+ binaries for a new private cluster')
class ProviderPostgres(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if any(k.startswith('PG') for k in os.environ):
            raise RuntimeError('unset inherited PostgreSQL settings for this private test')
        assert BIN is not None
        tmp = tempfile.TemporaryDirectory(prefix='events-')
        cls.addClassCleanup(tmp.cleanup)
        root = Path(tmp.name)
        data = root / 'pg'

        def ctl(cmd, *args):
            subprocess.run([str(Path(BIN) / cmd), *args], check=True, capture_output=True,
                           env={'LC_ALL': 'C', 'PATH': os.defpath})
        ctl('initdb', '-D', str(data), '-U', 'fixture', '-A', 'trust', '--no-locale', '-E', 'UTF8')
        ctl('pg_ctl', '-D', str(data), '-l', str(root/'pg.log'), '-o',
            f"-c timezone=UTC -c listen_addresses='' -c unix_socket_directories='{root}' -c unix_socket_permissions=0700", '-w', 'start')
        cls.addClassCleanup(ctl, 'pg_ctl', '-D', str(data), '-m', 'immediate', '-w', 'stop')
        connect = psycopg.connect

        def local(role, **kw):
            return connect(host=str(root), port=5432, dbname='postgres', user=role,
                           passfile=str(root/'unused'), **kw)
        cls.local = staticmethod(local)
        with local('fixture') as c:
            c.execute('CREATE ROLE bri_app LOGIN NOINHERIT; CREATE ROLE bri_migrator LOGIN NOINHERIT CONNECTION LIMIT 2; '
                      'CREATE SCHEMA bri AUTHORIZATION bri_migrator')
        # Supply only synthetic configuration; replace the connector before running the ledger runner.
        expected = f'postgresql://bri_migrator@db.{migrate.EXPECTED_REF}.supabase.co:5432/postgres'

        def guarded(dsn, **kw):
            if dsn != expected:
                raise AssertionError('unexpected runner target')
            return local('bri_migrator', **kw)
        with (
            patch.object(migrate, 'env_values', return_value={'BRI_ENVIRONMENT':'local',
                'SUPABASE_URL':f'https://{migrate.EXPECTED_REF}.supabase.co',
                'BRI_MIGRATION_ROLE_DATABASE_URL':expected}),
            patch.object(migrate.psycopg, 'connect', guarded),
            redirect_stdout(io.StringIO()) as log,
        ):
            if migrate.main() or migrate.main() or 'applied_count=0' not in log.getvalue():
                raise AssertionError(log.getvalue())
        with local('bri_migrator') as c:
            versions = sorted((migrate.ROOT/'db/migrations').glob('[0-9]*_*.sql'))
            migrate.verify_ledger(c, versions)
            assert c.execute('SELECT version FROM bri.schema_migrations ORDER BY version').fetchall() == [(x.stem,) for x in versions]
            c.execute('INSERT INTO bri.provider_event_source(issuer) VALUES (%s)', (ISSUER,))
        with local('fixture') as c:
            c.execute('CREATE ROLE bri_provider_ingest LOGIN NOINHERIT')
        with local('bri_migrator') as c:
            c.execute('GRANT USAGE ON SCHEMA bri TO bri_provider_ingest')
            c.execute(f'GRANT EXECUTE ON FUNCTION {ROUTINE} TO bri_provider_ingest')

    def fixture(self):
        p, u = uuid4(), uuid4()
        t = 'synthetic-' + str(p)
        with self.local('fixture') as c:
            c.execute("INSERT INTO bri.tenants VALUES(%s,'test','synthetic')", (t,))
            c.execute("INSERT INTO bri.auth_principals(principal_id,status) VALUES(%s,'active')", (p,))
            c.execute("INSERT INTO bri.auth_identity_links(auth_user_id,principal_id,auth_issuer,auth_subject,provider_type,provider_issuer,provider_subject) VALUES(%s,%s,%s,%s,'native',%s,%s)", (u,p,ISSUER,str(u),ISSUER,str(u)))
            c.execute("INSERT INTO bri.auth_tenant_memberships(tenant_id,principal_id,membership_type,status) VALUES(%s,%s,'admin','active')", (t,p))
        return p,u,t

    def setUp(self):
        self.p,self.uid,self.tenant = self.fixture()
        self.key = secrets.token_bytes(32)
        self.consumer = ProviderEventConsumer(ISSUER,self.key,lambda: self.local(ROLE))

    def event(self, action='user_updated_password', when=None, **changes):
        return dict({'issuer':ISSUER,'event_id':str(uuid4()),'subject':str(self.uid),'action':action,
                     'outcome':'success','occurred_at':(when or now()).isoformat().replace('+00:00','Z'),
                     'operation_id':None}, **changes)

    def send(self, event):
        body = json.dumps(event).encode()
        return self.consumer.consume(body, hmac.new(self.key,b'BRI.provider-security.v1\0'+body,hashlib.sha256).hexdigest())

    def start(self, when, sid=None, uid=None):
        with self.local('bri_app') as c:
            c.execute("SELECT set_config('bri.auth_user_id',%s,true)", (str(uid or self.uid),))
            return c.execute('SELECT bri.start_security_session(%s,%s,%s,%s)', (ISSUER,sid or uuid4(),when,uuid4())).fetchone()[0]

    def test_concurrent_replay_and_session_restart_with_late_event(self):
        _,other,_ = self.fixture()
        old, sid, other_sid = now(),uuid4(),uuid4()
        self.assertTrue(self.start(old,sid)); self.assertTrue(self.start(old,other_sid,other))
        event = self.event()
        with ThreadPoolExecutor(2) as pool:
            self.assertCountEqual(pool.map(self.send,[event,event]), ['applied','duplicate'])
        self.assertIsNone(self.start(now(),sid))  # materialized and revoked
        self.assertIsNone(self.start(old)); self.assertIsNone(self.start(None))  # previously unseen IDs
        self.assertTrue(self.start(old,other_sid,other))
        fresh, new_sid = now(),uuid4()
        self.assertTrue(self.start(fresh,new_sid))
        self.assertEqual(self.send(self.event('factor_deleted',when=old)), 'applied')
        self.assertTrue(self.start(fresh,new_sid))
        with self.local('fixture') as c:
            rows = c.execute("SELECT event_type,actor_principal_id,tenant_id FROM bri.security_audit_events WHERE request_id=(SELECT correlation FROM bri.provider_event_receipts WHERE event_id=%s) ORDER BY event_type",(event['event_id'],)).fetchall()
        self.assertEqual(rows,[('auth.provider.user_updated_password',None,self.tenant),('auth.session.revoked',None,self.tenant)])
        with self.assertRaises(IngestionUnavailable):
            self.send(dict(event,action='factor_deleted'))

    def test_factor_loss_is_negative_only_and_attempts_do_not_invalidate(self):
        t = now()
        with self.local('fixture') as c:
            c.execute('SELECT bri.record_client_totp_observation(%s,%s,%s,%s,%s,%s)',
                      (self.tenant,self.p,self.uid,ISSUER,t,t+timedelta(minutes=10)))
        self.assertTrue(self.start(t))
        self.assertEqual(self.send(self.event('verification_attempted',outcome='failure')), 'applied')
        self.assertEqual(self.send(self.event('user_recovery_requested',outcome='observed')), 'applied')
        self.assertTrue(self.start(t))
        self.assertEqual(self.send(self.event('factor_deleted')), 'applied'); self.assertIsNone(self.start(t))
        self.assertEqual(self.send(self.event('mfa_code_login')), 'applied')
        with self.local('fixture') as c:
            self.assertEqual(c.execute('SELECT verified_until FROM bri.client_totp_observations WHERE principal_id=%s',(self.p,)).fetchone(),(None,))
            self.assertEqual(c.execute('SELECT status,membership_type FROM bri.auth_tenant_memberships WHERE principal_id=%s',(self.p,)).fetchone(),('active','admin'))

    def test_session_start_racing_change_cannot_leave_old_session_active(self):
        from threading import Barrier
        primary, sid = now(),uuid4()
        change = self.event('factor_unenrolled')
        barrier = Barrier(2)
        def start():
            barrier.wait(timeout=5)
            return self.start(primary,sid)
        with ThreadPoolExecutor(1) as pool:
            attempt = pool.submit(start)
            barrier.wait(timeout=5)
            self.assertEqual(self.send(change),'applied')
            attempt.result(timeout=5)  # Either serialized order is valid.
        self.assertIsNone(self.start(primary,sid)); self.assertIsNone(self.start(primary))
        with self.local('fixture') as c:
            self.assertEqual(c.execute('SELECT count(*) FROM bri.auth_sessions WHERE principal_id=%s AND revoked_at IS NULL',(self.p,)).fetchone(),(0,))

    def test_suspended_membership_cannot_be_restored_by_an_event(self):
        with self.local('fixture') as c:
            c.execute("UPDATE bri.auth_tenant_memberships SET status='suspended' WHERE principal_id=%s",(self.p,))
        for action in ('login','user_updated_password','factor_updated'):
            self.assertEqual(self.send(self.event(action)), 'applied')
            self.assertIsNone(self.start(now()))

    def test_app_cannot_manufacture_provider_audit(self):
        with self.local('bri_app') as c:
            c.execute("SELECT set_config('bri.auth_user_id',%s,true)",(str(self.uid),))
            with self.assertRaises(psycopg.errors.InsufficientPrivilege), c.transaction():
                c.execute("INSERT INTO bri.security_audit_events(actor_principal_id,subject_principal_id,event_type,outcome) VALUES(%s,%s,'auth.provider.login','success')",(self.p,self.p))
        for role in ('bri_app','fixture'):
            self.consumer = ProviderEventConsumer(ISSUER,self.key,lambda role=role: self.local(role))
            with self.assertRaises(IngestionUnavailable): self.send(self.event())

    def test_only_causally_bound_subsequent_password_change_can_confirm(self):
        op = uuid4(); stale = now()
        with self.local('bri_app') as c:
            c.execute("SELECT set_config('bri.auth_user_id',%s,true)",(str(self.uid),))
            self.assertTrue(c.execute('SELECT bri.reserve_password_recovery(%s,%s,%s)',(uuid4(),op,now())).fetchone()[0])
        for event in (self.event(operation_id=str(uuid4())), self.event('factor_deleted'),
                      self.event(operation_id=str(op),when=stale),self.event()):
            self.assertEqual(self.send(event),'applied'); self.assertIsNone(self.start(now()))
        self.assertEqual(self.send(self.event(operation_id=str(op))), 'applied'); self.assertTrue(self.start(now()))

    def test_bad_source_subject_and_role_have_no_db_effects(self):
        event=self.event(subject=str(uuid4()))
        with self.assertRaises(IngestionUnavailable): self.send(event)
        with self.local('fixture') as c:
            self.assertIsNone(c.execute('SELECT 1 FROM bri.provider_event_receipts WHERE event_id=%s',(event['event_id'],)).fetchone())
            for role in (ROLE,'bri_app'):
                self.assertFalse(c.execute("SELECT has_table_privilege(%s,'bri.provider_event_receipts','INSERT')",(role,)).fetchone()[0])
            self.assertFalse(c.execute("SELECT has_function_privilege('bri_app',%s,'EXECUTE')",(ROUTINE,)).fetchone()[0])
        with self.local(ROLE) as c, self.assertRaises(psycopg.errors.InsufficientPrivilege):
            c.execute('SELECT bri.ingest_provider_security_event(%s,%s,%s,%s,%s,%s,NULL)',('https://wrong.invalid/auth/v1',uuid4(),self.uid,'login','observed',now()))

    def test_audit_failure_rolls_back_receipt_and_invalidation_then_retry(self):
        t,sid = now(),uuid4(); self.assertTrue(self.start(t,sid)); event=self.event()
        # Synthetic downstream audit outage only on this private cluster.
        with self.local('fixture') as c:
            c.execute("ALTER TABLE bri.security_audit_events ADD CONSTRAINT synthetic_outage CHECK(event_type <> 'auth.provider.factor_updated') NOT VALID")
        event['action']='factor_updated'
        try:
            with self.assertRaises(IngestionUnavailable): self.send(event)
            self.assertTrue(self.start(t,sid))
        finally:
            with self.local('fixture') as c: c.execute('ALTER TABLE bri.security_audit_events DROP CONSTRAINT synthetic_outage')
        self.assertEqual(self.send(event),'applied'); self.assertIsNone(self.start(t,sid))
