"""Opt-in: use the checked-in private-socket fixture and checksummed migration runner."""
import os
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from secrets import token_bytes
from time import monotonic, sleep
from unittest.mock import patch
from uuid import UUID, uuid4

import psycopg
import test_privileged_approvals_pg as fixtures
from test_reenrollment import signed

from bri.access.reenrollment import ProofReceiver


@unittest.skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16')
class Reenrollment(unittest.TestCase):
    # Reuse the approval setup, not its test cases or its separate opt-in.
    t: str
    key: UUID
    actors: list
    connect = classmethod(fixtures.ApprovalDatabase.connect.__func__)
    setUp = fixtures.ApprovalDatabase.setUp
    ctx = fixtures.ApprovalDatabase.ctx
    request = fixtures.ApprovalDatabase.request
    decide = fixtures.ApprovalDatabase.decide

    @classmethod
    def setUpClass(cls):
        with patch.dict(os.environ, {'BRI_APPROVAL_PG_BIN': os.environ['BRI_TEST_PG_BIN']}):
            fixtures.ApprovalDatabase.setUpClass.__func__(cls)
        with cls.connect('postgres') as db:
            db.execute("CREATE ROLE bri_reenrollment_platform LOGIN NOINHERIT; "
                       "CREATE ROLE bri_reenrollment_provider LOGIN NOINHERIT; "
                       "CREATE ROLE bri_provider_ingest LOGIN NOINHERIT; GRANT USAGE ON SCHEMA bri TO bri_provider_ingest; "
                       "GRANT EXECUTE ON FUNCTION bri.ingest_provider_security_event(text,uuid,uuid,text,text,timestamptz,uuid) TO bri_provider_ingest; "
                       "GRANT USAGE ON SCHEMA bri TO bri_reenrollment_platform,bri_reenrollment_provider; "
                       "GRANT EXECUTE ON FUNCTION bri.record_reenrollment_proof(text,uuid,text,uuid,uuid,uuid,uuid,timestamptz,timestamptz) "
                       "TO bri_reenrollment_platform,bri_reenrollment_provider")
        with cls.connect('bri_migrator') as db:
            db.execute('insert into bri.provider_event_source(issuer) values(%s)', (fixtures.ISSUER,))

    def work(self, op, ids=None):
        with self.connect('bri_approval_worker') as db:
            self.ctx(1).bind(db)
            return db.execute('select stage from bri.approval_work(%s,%s,%s,%s,%s::uuid[])',
                              (self.t, fixtures.ACTION, self.key, op, ids)).fetchone()[0]

    def test_begin_quarantines_without_admin_suspension(self):
        self.request(); self.decide(); self.work('BEGIN')
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('select status from bri.auth_principals where principal_id=%s',
                                        (self.actors[2][0],)).fetchone(), ('active',))
            self.assertEqual(db.execute('select confirmed_at from bri.credential_operations where operation_id=%s',
                                        (self.key,)).fetchone(), (None,))

    def completed(self):
        self.request(); self.decide(); self.work('BEGIN')
        old = uuid4()
        self.work('PIN', [old]); self.work('DISPATCH', [old]); self.work('ABSENT', [old])
        self.assertEqual(self.work('VERIFIED', []), 'COMPLETED')
        return old

    def test_generic_confirmation_cannot_release_quarantine(self):
        self.completed()
        with self.connect('bri_migrator') as db, self.assertRaises(psycopg.errors.InsufficientPrivilege):
            db.execute("select bri.confirm_credential_change(%s,%s,'factor_reenrollment',%s,%s,%s)",
                       (self.actors[2][1], fixtures.ISSUER, uuid4(), self.key, uuid4()))

    def setup_proofs(self):
        self.old = self.completed()
        self.case, factor = uuid4(), uuid4()
        self.keys = {side: token_bytes(32) for side in ('platform','provider')}
        self.receivers = {side: ProofReceiver(side, fixtures.ISSUER, secret,
                             lambda side=side: self.connect('bri_reenrollment_' + side))
                          for side, secret in self.keys.items()}
        self.human = {'kind': 'identity.bound_to_factor.v1', 'tenant': self.t, 'issuer': fixtures.ISSUER,
                          'subject': str(self.actors[2][1]), 'factor': str(factor), 'case': str(self.case),
                          'operation': str(self.key), 'event': str(self.case), 'created': None,
                          'happened': datetime.now(UTC).isoformat()}
        self.provider = dict(self.human, kind='totp.created_and_challenge_verified.v1', event=str(uuid4()),
                             created=datetime.now(UTC).isoformat(), happened=datetime.now(UTC).isoformat())

    def deliver(self, side, **changes):
        fields = dict(self.human if side=='platform' else self.provider, **changes)
        return self.receivers[side].consume(*signed(self.keys[side], fields))

    def session(self, sid=None, primary=None):
        with self.connect('bri_app') as db:
            db.execute("select set_config('bri.auth_user_id',%s,true)", (str(self.actors[2][1]),))
            return db.execute('select bri.start_security_session(%s,%s,coalesce(%s,clock_timestamp()),%s)',
                              (fixtures.ISSUER, sid or uuid4(), primary, uuid4())).fetchone()[0]

    def test_two_sources_once_only_and_fresh_reentry(self):
        self.setup_proofs()
        self.assertIsNone(self.session())
        with self.assertRaises(psycopg.Error):
            self.deliver('provider')
        self.assertEqual(self.deliver('platform'), 'awaiting_provider')
        self.assertIsNone(self.session())
        with ThreadPoolExecutor(2) as pool:
            self.assertCountEqual(pool.map(lambda _: self.deliver('provider'), range(2)), ['confirmed','duplicate'])
        self.assertIsNone(self.session(self.actors[2][2]))  # revoked session, even with fresh primary
        self.assertIsNone(self.session(primary=datetime.fromisoformat(self.provider['happened'])))
        self.assertIsNotNone(self.session())
        with self.connect('postgres') as db:
            self.assertEqual(db.execute("select count(*) from bri.security_audit_events where event_type="
                                        "'auth.mfa.factor_enrolled' and subject_principal_id=%s", (self.actors[2][0],)).fetchone(), (1,))
        with self.assertRaises(psycopg.Error):
            self.deliver('provider', factor=str(uuid4()))  # same event ID, different contents

    def test_mismatches_cannot_confirm(self):
        self.setup_proofs()
        self.deliver('platform')
        for changes in [{'tenant': 'another'}, {'operation': str(uuid4())}, {'subject': str(uuid4())},
                        {'case': str(uuid4())}, {'factor': str(self.old)}, {'factor': str(uuid4())},
                        {'created': (datetime.now(UTC)-timedelta(hours=1)).isoformat()},
                        {'happened': (datetime.now(UTC)+timedelta(hours=1)).isoformat()}]:
            with self.subTest(changes=list(changes)), self.assertRaises(psycopg.Error):
                self.deliver('provider', **changes)
        self.assertIsNone(self.session())

    def deny_on_pending_change(self, set_clause):
        self.setup_proofs(); self.deliver('platform')
        # Hold the governance write uncommitted while completion is submitted.
        with ThreadPoolExecutor(1) as pool:
            with self.connect('postgres') as db:
                db.execute('update bri.auth_principals set '+set_clause+' where principal_id=%s',(self.actors[2][0],))
                completion = pool.submit(self.deliver,'provider')
                limit = monotonic()+5
                while not db.execute("select exists(select from pg_stat_activity where usename="
                                     "'bri_reenrollment_provider' and pg_backend_pid()=any(pg_blocking_pids(pid)))").fetchone()[0]:
                    self.assertLess(monotonic(), limit, 'completion did not reach the held governance lock')
                    sleep(.01)
                    db.execute('select pg_stat_clear_snapshot()')
            with self.assertRaises(psycopg.Error):
                completion.result(timeout=10)
        self.assertIsNone(self.session())
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('select confirmed_at from bri.credential_operations where operation_id=%s',
                                        (self.key,)).fetchone(), (None,))

    def test_concurrent_suspension(self):
        self.deny_on_pending_change("status='suspended'")

    def test_concurrent_deletion(self):
        self.deny_on_pending_change('deletion_requested_at=clock_timestamp()')

    def test_retry_after_deletion_never_reopens(self):
        self.setup_proofs(); self.deliver('platform'); self.deliver('provider')
        sid = uuid4(); self.assertIsNotNone(self.session(sid))
        with self.connect('postgres') as db:
            db.execute('update bri.auth_principals set deletion_requested_at=clock_timestamp() where principal_id=%s',
                       (self.actors[2][0],))
        self.assertEqual(self.deliver('provider'), 'duplicate')
        self.assertIsNone(self.session(sid)); self.assertIsNone(self.session())

    def test_sources_have_no_direct_authority(self):
        with self.connect('postgres') as db:
            for role in ('bri_app','bri_approval_worker','bri_reenrollment_provider','bri_reenrollment_platform'):
                self.assertEqual(db.execute("select has_table_privilege(%s,'bri.auth_principals','UPDATE'), "
                    "has_table_privilege(%s,'bri.credential_operations','UPDATE'), "
                    "has_table_privilege(%s,'bri.reenrollment_proofs','INSERT'), "
                    "has_function_privilege(%s,'bri.confirm_credential_change(uuid,text,text,uuid,uuid,uuid)','EXECUTE'), "
                    "has_function_privilege(%s,'bri.record_reenrollment_proof(text,uuid,text,uuid,uuid,uuid,uuid,timestamptz,timestamptz)','EXECUTE')",
                    (role,)*5).fetchone(), (False,False,False,False,role.startswith('bri_reenrollment_')))

    def test_provider_event_supersedes_case(self):
        self.setup_proofs(); self.deliver('platform')
        with self.connect('bri_provider_ingest') as db:
            db.execute("select bri.ingest_provider_security_event(%s,%s,%s,'factor_deleted','success',clock_timestamp(),NULL)",
                       (fixtures.ISSUER,uuid4(),self.actors[2][1]))
        with self.assertRaises(psycopg.Error):
            self.deliver('provider', happened=datetime.now(UTC).isoformat())
        self.assertIsNone(self.session())

    def test_independent_suspension_precedes_execution(self):
        self.request(); self.decide()
        with self.connect('postgres') as db:
            db.execute("update bri.auth_principals set status='suspended' where principal_id=%s", (self.actors[2][0],))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.work('BEGIN')
        self.assertIsNone(self.session())
