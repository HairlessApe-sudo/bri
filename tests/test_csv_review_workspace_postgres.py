"""A14 acceptance on a disposable TCP-disabled PostgreSQL 16 cluster."""
import os
import unittest
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path
from time import monotonic, sleep
from unittest.mock import patch
from uuid import UUID, uuid4

import psycopg
import test_csv_intake_postgres as csv

QUEUE = 'bri.csv_review_queue(text,uuid,uuid,uuid,text,text,uuid,integer)'
DETAIL = 'bri.csv_review_detail(text,uuid,uuid,uuid,text,uuid,integer)'
DECIDE = 'bri.csv_review_decide(text,uuid,uuid,text,uuid,text,uuid)'
A12_REVIEW = 'bri.csv_review(text,uuid,uuid,text,text,text,uuid)'
ROLES = ('bri_app', 'bri_csv_intake', 'bri_csv_worker', 'bri_csv_reader')
EMPTY = {'items': [], 'next_cursor': None}


@unittest.skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16')
class CsvReviewWorkspacePostgresTests(unittest.TestCase):
    # Borrow fixture methods, not test methods; discovery runs each suite once.
    connect = csv.CsvIntakePostgresTests.__dict__['connect']
    setUp = csv.CsvIntakePostgresTests.setUp
    intake = csv.CsvIntakePostgresTests.intake
    submit = csv.CsvIntakePostgresTests.submit
    worker = csv.CsvIntakePostgresTests.worker
    ready = csv.CsvIntakePostgresTests.ready
    complete = csv.CsvIntakePostgresTests.complete
    sock: Path
    tenant: str
    foreign: str
    actors: list[tuple[UUID, UUID, UUID]]
    foreign_actors: list[tuple[UUID, UUID, UUID]]

    @classmethod
    def setUpClass(cls):
        with patch.dict(os.environ, BRI_APPROVAL_PG_BIN=os.environ['BRI_TEST_PG_BIN']):
            csv.fixtures.ApprovalDatabase.setUpClass.__func__(cls)
        with cls.connect('bri_migrator') as db:
            db.execute('INSERT INTO bri.provider_event_source (issuer) VALUES (%s)', (csv.ISSUER,))
        with cls.connect('postgres') as db:
            assert db.execute("SELECT inet_server_addr(), current_setting('listen_addresses')").fetchone() == (None, '')
            for role, routines in (('bri_csv_intake', csv.INTAKE), ('bri_csv_worker', csv.WORKER),
                                   ('bri_csv_reader', csv.READER)):
                db.execute(f'CREATE ROLE {role} LOGIN NOINHERIT; GRANT USAGE ON SCHEMA bri TO {role}')
                db.execute(f'GRANT EXECUTE ON FUNCTION {", ".join(r for r in routines if r != A12_REVIEW)} TO {role}')
        checks = unittest.TestCase()
        for role in ROLES:
            with cls.connect(role) as db:
                for routine, volatility in ((QUEUE, 's'), (DETAIL, 's'), (DECIDE, 'v'), (A12_REVIEW, 'v')):
                    checks.assertEqual(db.execute(
                        "SELECT p.provolatile, p.prosecdef, has_function_privilege(p.oid,'EXECUTE'), EXISTS ("
                        "SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a "
                        "WHERE a.grantee=0 AND a.privilege_type='EXECUTE') FROM pg_proc p "
                        "WHERE p.oid=to_regprocedure(%s)", (routine,),
                    ).fetchone(), (volatility, True, False, False), (role, routine))
                    name, types = routine[:-1].split('(')
                    args = ','.join(f'NULL::{kind}' for kind in types.split(','))
                    with checks.assertRaises(psycopg.errors.InsufficientPrivilege) as denied, db.transaction():
                        db.execute(f'SELECT {name}({args})')
                    checks.assertEqual(denied.exception.diag.message_primary,
                                       f'permission denied for function {name.split(".")[1]}')
        with cls.connect('bri_migrator') as db:
            db.execute(f'GRANT EXECUTE ON FUNCTION {QUEUE}, {DETAIL}, {DECIDE} TO bri_csv_intake')

    def read(self, name, *args, identity=None, tenant=None, issuer=csv.ISSUER):
        params = (tenant or self.tenant, *(identity or self.actors[0]), issuer, *args)
        with self.connect('bri_csv_intake') as db:
            db.execute('SET TRANSACTION READ ONLY')
            return db.execute(f'SELECT bri.{name}({", ".join(["%s"] * len(params))})', params).fetchone()[0]

    def queue(self, status: str | None = 'proposed', after=None, size: int | None = 50, **kwargs):
        return self.read('csv_review_queue', status, after, size, **kwargs)

    def detail(self, job, offset: int | None = 0, **kwargs):
        return self.read('csv_review_detail', job, offset, **kwargs)

    def propose(self):
        job = self.ready()
        self.assertEqual(self.complete(job), ('proposed',))
        return job

    def finish_submission(self, job, *, identity=None, tenant=None):
        self.assertEqual(self.intake('csv_mark_ready', job, identity=identity, tenant=tenant), ('ready',))
        claim = self.worker('csv_claim', job)
        self.assertIsNotNone(claim)
        self.assertEqual(self.complete(job), ('proposed',))

    def decide(self, job, decision, *, identity=None, **kwargs):
        return self.intake('csv_review_decide', job, decision, identity=identity or self.actors[0], **kwargs)

    def test_queue_in_read_only_transaction(self):
        job = self.propose()
        page = self.queue()
        self.assertEqual(set(page), {'items', 'next_cursor'})
        item, = page['items']
        self.assertEqual(set(item), {'id', 'state', 'node_id', 'created_at'})
        self.assertEqual((item['id'], item['state'], item['node_id']), (f'csv:{job}', 'proposed', 'team'))
        self.assertIsNone(page['next_cursor'])

    def test_node_labels_are_bounded_by_code_points_without_changing_scope(self):
        prefix = '🐈' * 254 + '\n'
        exact = prefix + 'x'
        long_node = prefix + '<literal>'
        other_node = prefix + '<hidden>'
        nodes = ('', exact, long_node, other_node)
        with self.connect('postgres') as db:
            for i, node in enumerate(nodes):
                db.execute("INSERT INTO bri.org_nodes VALUES (%s,%s,'team','Fixture','root')", (self.tenant, node))
                for index in ((0, 2) if i < 3 else (2,)):
                    db.execute("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) "
                               "VALUES (%s,%s,'csv',%s)", (self.tenant, self.actors[index][0], node))
            for index in (0, 2):
                self.actors[index] = (*self.actors[index][:2], uuid4())
                db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                           'VALUES (%s,%s,%s,clock_timestamp())', self.actors[index])
        jobs = [self.submit(node=node)[0] for node in nodes]
        for job in jobs:
            self.finish_submission(job)
        visible = dict(zip(jobs[:3], ('', exact, prefix + '…'), strict=True))
        self.assertEqual({item['id']: item['node_id'] for item in self.queue()['items']},
                         {f'csv:{job}': label for job, label in visible.items()})
        for job, label in visible.items():
            self.assertEqual(self.detail(job)['node_id'], label)
        self.assertIsNone(self.detail(jobs[-1]))
        self.assertEqual(self.decide(jobs[-1], 'approved'), (None,))
        self.assertEqual(self.decide(jobs[2], 'approved'), ('approved',))

    def test_provenance_and_character_pages_are_exact(self):
        job = self.ready()
        content = 'é' * 4095 + '🐈' + '\nend'
        digest = sha256(content.encode()).hexdigest()
        self.assertEqual(self.worker('csv_complete', job, 1, content, digest, 2, 4), ('proposed',))
        detail = self.detail(job)
        ref = f'csv:{job}'
        item, = self.queue()['items']
        self.assertEqual(detail, {
            **item,
            'provenance': {'source_id': ref, 'source_version_id': ref, 'source_version': '1',
                           'extraction_id': ref, 'original_sha256': csv.ORIGINAL,
                           'content_sha256': digest, 'csv_first_line': 2, 'csv_last_line': 4},
            'evidence': content[:4096], 'next_evidence_offset': 4096,
            'history': detail['history'],
        })
        events = detail['history']
        self.assertEqual([v['event'] for v in events], ['submitted', 'ready', 'claimed', 'proposed'])
        self.assertEqual([v['occurred_at'] for v in events], sorted(v['occurred_at'] for v in events))
        for event in events:
            self.assertEqual(set(event), {'event', 'occurred_at', 'reason'})
            self.assertIsNone(event['reason'])
        self.assertEqual(self.detail(job, 4096), {**detail, 'evidence': '\nend', 'next_evidence_offset': None})
        self.assertEqual(self.detail(job, 20_000_000), {**detail, 'evidence': '', 'next_evidence_offset': None})

    def test_failed_intake_is_not_a_proposal_and_has_no_evidence(self):
        job = self.ready()
        self.assertEqual(self.worker('csv_fail', job, 1, 'invalid_headers', False), ('failed',))
        self.assertEqual(self.queue(), EMPTY)
        item, = self.queue('failed')['items']
        detail = self.detail(job)
        self.assertEqual(item['state'], 'failed')
        self.assertEqual(detail, {**item, 'provenance': None, 'evidence': None,
                                  'next_evidence_offset': None, 'history': detail['history']})
        self.assertEqual([(row['event'], row['reason']) for row in detail['history']],
                         [('submitted', None), ('ready', None), ('claimed', None), ('failed', 'invalid_csv')])
        with self.assertRaises(psycopg.errors.UniqueViolation) as not_pending:
            self.decide(job, 'approved')
        self.assertEqual(not_pending.exception.diag.message_primary, 'CSV proposal is not pending')
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT count(*) FROM bri.knowledge_proposals WHERE proposal_id=%s',
                                        (item['id'],)).fetchone(), (0,))

    def test_queue_and_detail_validate_bounds(self):
        for invalid in ('ready', 'all', '', None):
            with self.subTest(status=invalid), self.assertRaises(psycopg.errors.InvalidParameterValue):
                self.queue(invalid)
        for invalid in (0, 51, None):
            with self.subTest(size=invalid), self.assertRaises(psycopg.errors.InvalidParameterValue):
                self.queue(size=invalid)
        for invalid in (-1, 20_000_001, None):
            with self.subTest(offset=invalid), self.assertRaises(psycopg.errors.InvalidParameterValue):
                self.detail(uuid4(), invalid)

    def test_keyset_breaks_timestamp_ties_and_rechecks_status(self):
        tied = sorted(uuid4() for _ in range(3))
        actor, uid, sid = self.actors[2]
        # Force a tie without changing the immutable metadata of existing jobs.
        with self.connect('bri_migrator') as db:
            for job in reversed(tied):
                db.execute('INSERT INTO bri.csv_jobs (job_id,tenant_id,scope_node_id,actor_id,creator_id,'
                           'auth_user_id,session_id,issuer,request_key,original_sha256,byte_count,created_at) '
                           "VALUES (%s,%s,'team',%s,%s,%s,%s,%s,%s,%s,12,transaction_timestamp())",
                           (job, self.tenant, actor, self.actors[1][0], uid, sid, csv.ISSUER, uuid4(), csv.ORIGINAL))
        for job in reversed(tied):
            self.finish_submission(job)
        cursor = None
        for index, job in enumerate(tied):
            page = self.queue(after=cursor, size=1)
            item, = page['items']
            self.assertEqual(item['id'], f'csv:{job}')
            self.assertEqual(page['next_cursor'], str(job) if index < 2 else None)
            cursor = UUID(page['next_cursor']) if page['next_cursor'] else None
        self.assertEqual(self.queue(after=tied[-1]), EMPTY)
        self.assertEqual(self.decide(tied[0], 'rejected'), ('rejected',))
        self.assertEqual(self.queue('rejected')['items'][0]['id'], f'csv:{tied[0]}')
        self.assertEqual(self.detail(tied[0])['state'], 'rejected')
        self.assertEqual(self.queue(after=tied[0]), self.queue(after=uuid4()))
        self.assertEqual(self.queue(after=tied[0]), EMPTY)

    def test_hidden_details_and_anchors_match_missing(self):
        visible = self.propose()
        foreign_job, _, _ = self.submit(identity=self.foreign_actors[2], tenant=self.foreign)
        self.finish_submission(foreign_job, identity=self.foreign_actors[2], tenant=self.foreign)
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.org_nodes VALUES (%s,'child','team','Child','team')", (self.tenant,))
            actor, uid, _ = self.actors[2]
            db.execute("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) "
                       "VALUES (%s,%s,'csv','child')", (self.tenant, actor))
            self.actors[2] = actor, uid, uuid4()
            db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                       'VALUES (%s,%s,%s,clock_timestamp())', self.actors[2])
        child_job, _, _ = self.submit(node='child')
        self.finish_submission(child_job)
        creating, _, _ = self.submit()
        missing = uuid4()
        self.assertEqual(self.queue(after=missing), EMPTY)
        self.assertIsNone(self.detail(missing))
        self.assertEqual(self.decide(missing, 'rejected'), (None,))
        self.assertEqual([item['id'] for item in self.queue()['items']], [f'csv:{visible}'])
        self.assertEqual(self.detail(foreign_job, identity=self.foreign_actors[0], tenant=self.foreign)['state'],
                         'proposed')
        for job in (child_job, foreign_job, creating):
            with self.subTest(job=job):
                self.assertEqual(self.queue(after=job), EMPTY)
                self.assertIsNone(self.detail(job))
                self.assertEqual(self.decide(job, 'rejected'), (None,))
        for member in self.actors[1:]:
            with self.subTest(identity=member[0]):
                self.assertEqual(self.queue(identity=member), EMPTY)
                self.assertEqual(self.queue(after=visible, identity=member), EMPTY)
                self.assertIsNone(self.detail(visible, identity=member))
                self.assertEqual(self.decide(visible, 'rejected', identity=member), (None,))
        actor, uid, sid = self.actors[0]
        for tenant, issuer, identity in ((self.foreign, csv.ISSUER, self.actors[0]),
                                         (self.tenant, 'https://other.invalid', self.actors[0]),
                                         (self.tenant, csv.ISSUER, (actor, uuid4(), sid)),
                                         (self.tenant, csv.ISSUER, (actor, uid, uuid4()))):
            with self.subTest(tenant=tenant, issuer=issuer, identity=identity):
                self.assertEqual(self.queue(tenant=tenant, issuer=issuer, identity=identity), EMPTY)
                self.assertIsNone(self.detail(visible, tenant=tenant, issuer=issuer, identity=identity))
        self.assertEqual(self.decide(visible, 'rejected', uid=uuid4()), (None,))
        self.assertEqual(self.decide(visible, 'rejected', identity=(actor, uid, uuid4())), (None,))

    def test_review_checks_committed_session_and_assignment_revocations(self):
        job = self.propose()
        with self.connect('bri_csv_intake') as reader, self.connect('postgres') as maintenance:
            reader.execute('SET TRANSACTION READ ONLY ISOLATION LEVEL READ COMMITTED')
            actor, uid, sid = self.actors[0]

            def read_pair(session):
                args = self.tenant, actor, uid, session, csv.ISSUER
                return reader.execute("SELECT bri.csv_review_queue(%s,%s,%s,%s,%s,'proposed',NULL,50),"
                                      'bri.csv_review_detail(%s,%s,%s,%s,%s,%s,0)',
                                      (*args, *args, job)).fetchone()

            self.assertEqual(read_pair(sid)[1]['state'], 'proposed')
            maintenance.execute('UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() WHERE session_id=%s', (sid,))
            maintenance.commit()
            self.assertEqual(read_pair(sid), (EMPTY, None))
            replacement = uuid4()
            maintenance.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                                'VALUES (%s,%s,%s,clock_timestamp())', (actor, uid, replacement))
            maintenance.commit()
            self.assertEqual(read_pair(replacement)[1]['state'], 'proposed')
            maintenance.execute("UPDATE bri.auth_role_assignments SET status='revoked' WHERE tenant_id=%s "
                                "AND principal_id=%s AND role_id='csv'", (self.tenant, actor))
            # A new session after the grant change isolates the permission gate.
            fresh = uuid4()
            maintenance.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                                'VALUES (%s,%s,%s,clock_timestamp())', (actor, uid, fresh))
            maintenance.commit()
            self.assertEqual(read_pair(fresh), (EMPTY, None))

    def audit_rows(self, db, job):
        return db.execute('SELECT to_jsonb(a) FROM bri.csv_audit_events a '
                          'WHERE (a.tenant_id,a.job_id)=(%s,%s) ORDER BY a.event_id',
                          (self.tenant, job)).fetchall()

    def test_review_history_is_read_only_private_and_immutable(self):
        job = self.propose()
        other = self.ready()
        self.assertEqual(self.worker('csv_fail', other, 1, 'invalid_csv', False), ('failed',))
        with self.connect('bri_migrator') as maintenance:
            maintenance.execute("SELECT set_config('bri.tenant_id',%s,true)", (self.tenant,))
            self.assertEqual(maintenance.execute("SELECT relrowsecurity,relforcerowsecurity FROM pg_class "
                                                 "WHERE oid='bri.csv_audit_events'::regclass").fetchone(),
                             (True, True))
            before = self.audit_rows(maintenance, job)
            self.assertEqual(len(before), 4)
            with self.connect('bri_csv_intake') as intake:
                intake.execute('SET TRANSACTION READ ONLY')
                intake.execute("SELECT set_config('bri.csv_review_tenant',%s,true),"
                               "set_config('bri.csv_review_job',%s,true)", (self.tenant, str(other)))
                detail = intake.execute('SELECT bri.csv_review_detail(%s,%s,%s,%s,%s,%s,0)',
                                        (self.tenant, *self.actors[0], csv.ISSUER, job)).fetchone()[0]
                self.assertEqual([row['event'] for row in detail['history']],
                                 ['submitted', 'ready', 'claimed', 'proposed'])
                self.assertEqual(intake.execute("SELECT current_setting('bri.csv_review_tenant'),"
                                                "current_setting('bri.csv_review_job')").fetchone(),
                                 (self.tenant, str(other)))
                with self.assertRaises(psycopg.errors.InsufficientPrivilege) as denied, intake.transaction():
                    intake.execute('SELECT event FROM bri.csv_audit_events')
                self.assertEqual(denied.exception.diag.message_primary, 'permission denied for table csv_audit_events')
            for statement in ("UPDATE bri.csv_audit_events SET reason=NULL WHERE job_id=%s",
                              'DELETE FROM bri.csv_audit_events WHERE job_id=%s',
                              'TRUNCATE bri.csv_audit_events'):
                with self.assertRaises(psycopg.errors.InsufficientPrivilege) as denied, maintenance.transaction():
                    maintenance.execute(statement, (job,) if '%s' in statement else ())
                self.assertEqual(denied.exception.diag.message_primary, 'immutable CSV evidence')
            self.assertEqual(self.audit_rows(maintenance, job), before)

    def test_review_and_published_read_authority_are_independent(self):
        job = self.propose()
        ref = f'csv:{job}'
        self.assertEqual(self.decide(job, 'approved'), ('approved',))

        def published(identity):
            with self.connect('bri_csv_reader') as db:
                db.execute('SET TRANSACTION READ ONLY')
                return db.execute('SELECT proposal_id FROM bri.csv_read_published(%s,%s,%s,%s,%s)',
                                  (self.tenant, *identity, csv.ISSUER)).fetchall()

        self.assertEqual(self.detail(job)['state'], 'approved')
        self.assertEqual(published(self.actors[0]), [])
        with self.connect('bri_migrator') as db:
            db.execute("SELECT set_config('bri.tenant_id',%s,true)", (self.tenant,))
            db.execute('INSERT INTO bri.knowledge_record_access VALUES (%s,%s,true)', (self.tenant, ref))
            db.execute('INSERT INTO bri.knowledge_version_access VALUES (%s,%s,%s,true)', (self.tenant, ref, ref))
        self.assertEqual(published(self.actors[0]), [])
        detail = self.detail(job)
        self.assertEqual([row['event'] for row in detail['history']],
                         ['submitted', 'ready', 'claimed', 'proposed', 'approved'])
        actor, uid, _ = self.actors[0]
        read_identity = actor, uid, uuid4()
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.app_roles VALUES (%s,'publish','Published reader')", (self.tenant,))
            db.execute("INSERT INTO bri.role_permissions VALUES (%s,'publish','knowledge:read')", (self.tenant,))
            db.execute("UPDATE bri.auth_role_assignments SET status='revoked' WHERE "
                       "(tenant_id,principal_id,role_id)=(%s,%s,'csv')", (self.tenant, actor))
            db.execute("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) "
                       "VALUES (%s,%s,'publish','team')", (self.tenant, actor))
            db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                       'VALUES (%s,%s,%s,clock_timestamp())', read_identity)
        self.assertEqual(published(read_identity), [(ref,)])
        self.assertIsNone(self.detail(job, identity=read_identity))
        self.assertEqual(self.queue('approved', identity=read_identity), EMPTY)

    def test_conflicting_decisions_and_stale_replay_commit_only_once(self):
        job = self.propose()
        ref = f'csv:{job}'
        actor, uid, sid = self.actors[0]
        correlations = {'approved': uuid4(), 'rejected': uuid4()}

        def decision(db, value):
            db.execute("SET LOCAL statement_timeout='8s'")
            db.execute("SELECT set_config('bri.auth_user_id',%s,true)", (str(uid),))
            return db.execute('SELECT bri.csv_review_decide(%s,%s,%s,%s,%s,%s,%s)',
                              (self.tenant, actor, sid, csv.ISSUER, job, value, correlations[value])).fetchone()

        with ThreadPoolExecutor(max_workers=1) as pool, self.connect('bri_csv_intake') as winner:
            self.assertEqual(decision(winner, 'approved'), ('approved',))
            with self.connect('bri_csv_intake') as contender:
                pending = pool.submit(decision, contender, 'rejected')
                try:
                    self.assert_decision_waits(winner, contender, pending)
                    self.assertEqual(self.detail(job)['state'], 'proposed')
                    self.assertEqual(self.queue('approved'), EMPTY)
                finally:
                    winner.commit()
                with self.assertRaises(psycopg.errors.UniqueViolation) as stale:
                    pending.result(timeout=5)
                self.assertEqual(stale.exception.diag.message_primary, 'CSV proposal is not pending')
                contender.rollback()

        for value in ('approved', 'rejected'):
            with (self.subTest(decision=value), self.assertRaises(psycopg.errors.UniqueViolation),
                  self.connect('bri_csv_intake') as replay):
                decision(replay, value)
        item, = self.queue('approved')['items']
        self.assertEqual(item['id'], ref)
        self.assertEqual(self.queue(), EMPTY)
        self.assertEqual(self.queue('rejected'), EMPTY)
        self.assertEqual([row['event'] for row in self.detail(job)['history']].count('approved'), 1)
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT decision,csv_governed FROM bri.validation_decisions '
                                        'WHERE (tenant_id,proposal_id)=(%s,%s)', (self.tenant, ref)).fetchall(),
                             [('approved', True)])
            self.assertEqual(db.execute('SELECT count(*) FROM bri.validated_knowledge '
                                        'WHERE (tenant_id,proposal_id)=(%s,%s)', (self.tenant, ref)).fetchone(), (1,))
            self.assertEqual(db.execute("SELECT event,correlation FROM bri.csv_audit_events "
                                        "WHERE (tenant_id,job_id)=(%s,%s) "
                                        "AND event IN ('approved','rejected')", (self.tenant, job)).fetchall(),
                             [('approved', correlations['approved'])])
            for table in ('knowledge_record_access', 'knowledge_version_access'):
                self.assertEqual(db.execute(f'SELECT count(*) FROM bri.{table} '
                                            'WHERE (tenant_id,source_id)=(%s,%s)', (self.tenant, ref)).fetchone(), (0,))

    def assert_decision_waits(self, blocker, contender, pending):
        with self.connect('postgres', autocommit=True) as observer:
            deadline = monotonic() + 5
            while monotonic() < deadline and not pending.done():
                blockers, = observer.execute('SELECT pg_blocking_pids(%s)', (contender.info.backend_pid,)).fetchone()
                if blocker.info.backend_pid in blockers:
                    return
                sleep(0.01)
        self.fail('decision did not wait on the expected transaction')

    def decision_during(self, blocker, job):
        actor, uid, sid = self.actors[0]

        def decide(db):
            db.execute("SET LOCAL statement_timeout='8s'")
            db.execute("SELECT set_config('bri.auth_user_id',%s,true)", (str(uid),))
            return db.execute('SELECT bri.csv_review_decide(%s,%s,%s,%s,%s,%s,%s)',
                              (self.tenant, actor, sid, csv.ISSUER, job, 'approved', uuid4())).fetchone()

        with ThreadPoolExecutor(max_workers=1) as pool, self.connect('bri_csv_intake') as contender:
            pending = pool.submit(decide, contender)
            try:
                self.assert_decision_waits(blocker, contender, pending)
            finally:
                blocker.commit()
            return pending.result(timeout=5)

    def test_decision_waits_for_a_visible_job_row(self):
        job = self.propose()
        with self.connect('bri_migrator') as maintenance:
            self.assertEqual(maintenance.execute('SELECT state FROM bri.csv_jobs '
                                                 'WHERE (tenant_id,job_id)=(%s,%s) FOR UPDATE',
                                                 (self.tenant, job)).fetchone(), ('proposed',))
            self.assertEqual(self.decision_during(maintenance, job), ('approved',))
        self.assertEqual([event['event'] for event in self.detail(job)['history']],
                         ['submitted', 'ready', 'claimed', 'proposed', 'approved'])

    def test_decision_uses_current_authority_after_waiting_for_governance(self):
        job = self.propose()
        self.assertEqual(self.detail(job)['state'], 'proposed')
        with self.connect('postgres') as governance:
            before = self.audit_rows(governance, job)
            governance.execute('SELECT bri.lock_user_provisioning_governance()')
            governance.execute('UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() WHERE session_id=%s',
                               (self.actors[0][2],))
            self.assertEqual(self.decision_during(governance, job), (None,))
            self.assertEqual(governance.execute('SELECT state FROM bri.csv_jobs WHERE job_id=%s',
                                               (job,)).fetchone(), ('proposed',))
            self.assertEqual(self.audit_rows(governance, job), before)
