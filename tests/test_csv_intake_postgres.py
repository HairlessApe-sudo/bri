"""A12 SQL coverage on a new TCP-disabled PostgreSQL 16 cluster (BRI_TEST_PG_BIN)."""
import os
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from uuid import UUID, uuid4

import psycopg
import test_privileged_approvals_pg as fixtures

ISSUER = fixtures.ISSUER
INTAKE = (
    'bri.csv_submit(text,uuid,uuid,text,text,uuid,text,integer,uuid)',
    'bri.csv_mark_ready(text,uuid,uuid,text,uuid,uuid)',
    'bri.csv_status(text,uuid,uuid,text,uuid,uuid)',
    'bri.csv_pending_review(text,uuid,uuid,text,uuid)',
    'bri.csv_review(text,uuid,uuid,text,text,text,uuid)',
)
WORKER = (
    'bri.csv_claim(uuid,uuid)',
    'bri.csv_complete(uuid,integer,text,text,integer,integer,uuid)',
    'bri.csv_fail(uuid,integer,text,boolean,uuid)',
)
READER = ('bri.csv_read_published(text,uuid,uuid,uuid,text)',)
CLAIM_HELPERS = ('bri.csv_is_generated_ref(text)', 'bri.csv_claim_lineage_id()')
ORIGINAL = sha256(b'field\nvalue\n').hexdigest()
LEGACY_TEXT = 'legacy derived fixture text'
LEGACY_DIGEST = sha256(LEGACY_TEXT.encode()).hexdigest()


def write_legacy_source(db, tenant, source):
    db.execute("SELECT set_config('bri.tenant_id',%s,true)", (tenant,))
    db.execute("INSERT INTO bri.synthetic_principals(tenant_id,principal_id,display_name) "
               "VALUES (%s,'legacy','Legacy fixture') ON CONFLICT DO NOTHING", (tenant,))
    db.execute("INSERT INTO bri.source_records(tenant_id,source_id,scope_node_id,title,source_kind,created_by) "
               "VALUES (%s,%s,'team','Legacy fixture','synthetic_text','legacy')", (tenant, source))


def write_approved_legacy_lineage(db, tenant, source, extraction, proposal, decision):
    write_legacy_source(db, tenant, source)
    db.execute("INSERT INTO bri.source_versions(tenant_id,source_id,source_version_id,version_label,content_sha256,"
               "source_location,created_by) VALUES (%s,%s,%s,'1',%s,'legacy:fixture','legacy')",
               (tenant, source, source, LEGACY_DIGEST))
    db.execute("INSERT INTO bri.source_extractions(tenant_id,extraction_id,source_id,source_version_id,"
               "scope_node_id,content,content_sha256,source_location,extractor_name,extractor_version,created_by) "
               "VALUES (%s,%s,%s,%s,'team',%s,%s,'legacy:fixture','synthetic','1','legacy')",
               (tenant, extraction, source, source, LEGACY_TEXT, LEGACY_DIGEST))
    db.execute("INSERT INTO bri.knowledge_proposals(tenant_id,proposal_id,extraction_id,scope_node_id,proposed_by) "
               "VALUES (%s,%s,%s,'team','legacy')", (tenant, proposal, extraction))
    db.execute("INSERT INTO bri.validation_decisions(tenant_id,decision_id,proposal_id,reviewer_id,decision) "
               "VALUES (%s,%s,%s,'legacy','approved')", (tenant, decision, proposal))
    db.execute('INSERT INTO bri.validated_knowledge(tenant_id,proposal_id,decision_id) VALUES (%s,%s,%s)',
               (tenant, proposal, decision))


@unittest.skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16')
class CsvIntakePostgresTests(unittest.TestCase):
    connect = classmethod(fixtures.ApprovalDatabase.connect.__func__)
    sock: Path

    @classmethod
    def setUpClass(cls):
        cls.legacy_tenant = f'a12-legacy-{uuid4()}'
        cls.legacy_refs = tuple(f'csv:{uuid4()}' for _ in range(4))

        def seed_legacy():
            with cls.connect('postgres') as db:
                db.execute("INSERT INTO bri.tenants(tenant_id,display_name,sector) VALUES (%s,'Legacy','test')",
                           (cls.legacy_tenant,))
                db.execute("INSERT INTO bri.org_nodes VALUES (%s,'team','team','Team',NULL)", (cls.legacy_tenant,))
            with cls.connect('bri_app') as db:
                write_approved_legacy_lineage(db, cls.legacy_tenant, *cls.legacy_refs)

        with patch.dict(os.environ, BRI_APPROVAL_PG_BIN=os.environ['BRI_TEST_PG_BIN']):
            fixtures.ApprovalDatabase.setUpClass.__func__(cls, before_csv_migration=seed_legacy)
        with cls.connect('bri_app') as db:
            for routine in INTAKE + WORKER + READER + CLAIM_HELPERS:
                acl = db.execute(
                    "SELECT has_function_privilege(current_user,p.oid,'EXECUTE'), EXISTS ("
                    "SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a "
                    "WHERE a.grantee=0 AND a.privilege_type='EXECUTE') FROM pg_proc p "
                    "WHERE p.oid=to_regprocedure(%s)", (routine,),
                ).fetchone()
                assert acl == (False, False), (routine, acl)
        with cls.connect('bri_migrator') as db:
            db.execute('INSERT INTO bri.provider_event_source (issuer) VALUES (%s)', (ISSUER,))
        with cls.connect('postgres') as db:
            assert db.execute("SELECT inet_server_addr(), current_setting('listen_addresses')").fetchone() == (None, '')
            for role, routines in (('bri_csv_intake', INTAKE), ('bri_csv_worker', WORKER), ('bri_csv_reader', READER)):
                db.execute(f'CREATE ROLE {role} LOGIN NOINHERIT; GRANT USAGE ON SCHEMA bri TO {role}')
                db.execute(f'GRANT EXECUTE ON FUNCTION {", ".join(routines)} TO {role}')

    def setUp(self):
        self.tenant, self.actors = fixtures.seed_approval_tenant(self.connect)
        self.foreign, self.foreign_actors = fixtures.seed_approval_tenant(self.connect)
        with self.connect('postgres') as db:
            for t, actors in ((self.tenant, self.actors), (self.foreign, self.foreign_actors)):
                db.execute("INSERT INTO bri.org_nodes VALUES (%s,'team','team','Team','root')", (t,))
                db.execute("INSERT INTO bri.app_roles VALUES (%s,'csv','CSV fixture')", (t,))
                db.execute("INSERT INTO bri.role_permissions VALUES (%s,'csv','source:submit'),"
                           "(%s,'csv','knowledge:review')", (t, t))
                db.execute("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) "
                           "VALUES (%s,%s,'csv','team'),(%s,%s,'csv','team'),(%s,%s,'csv','team')",
                           (t, actors[2][0], t, actors[0][0], t, actors[1][0]))
                db.execute('INSERT INTO bri.csv_worker_creators VALUES (%s,%s)', (t, actors[1][0]))
                for index in (0, 1, 2):
                    actors[index] = (*actors[index][:2], uuid4())
                    db.execute("INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) "
                               "VALUES (%s,%s,%s,clock_timestamp())", actors[index])

    def intake(self, name, *args, identity=None, tenant=None, uid=None):
        actor, auth_user, sid = identity or self.actors[2]
        with self.connect('bri_csv_intake') as db:
            db.execute("SELECT set_config('bri.auth_user_id',%s,true)", (str(uid or auth_user),))
            params = (tenant or self.tenant, actor, sid, ISSUER, *args, uuid4())
            return db.execute(f'SELECT * FROM bri.{name}({", ".join(["%s"] * len(params))})', params).fetchone()

    def submit(self, key=None, *, size=12, node='team', **kwargs):
        return self.intake('csv_submit', node, key or uuid4(), ORIGINAL, size, **kwargs)

    def worker(self, name, *params):
        with self.connect('bri_csv_worker') as db:
            return db.execute(f'SELECT * FROM bri.{name}({", ".join(["%s"] * (len(params)+1))})',
                              (*params, uuid4())).fetchone()

    def test_submit_is_exact_and_idempotent(self):
        key = uuid4()
        first = self.submit(key, size=5_000_000)
        self.assertEqual(first[1], 'creating')
        self.assertEqual(len({first[0], first[2], key}), 3)
        self.assertEqual(self.submit(key, size=5_000_000), first)
        with self.assertRaises(psycopg.errors.UniqueViolation):
            self.submit(key)
        with self.assertRaises(psycopg.errors.InvalidParameterValue):
            self.submit(size=5_000_001)
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.submit(node='root')
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.submit(tenant=self.foreign)
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.submit(uid=self.actors[0][1])
        with self.connect('postgres') as db:
            db.execute('UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() WHERE session_id=%s',
                       (self.actors[2][2],))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.submit(key, size=5_000_000)

    def ready(self):
        job, _, key = self.submit()
        self.assertIsNone(self.worker('csv_claim', job))
        self.assertEqual(self.intake('csv_mark_ready', job), ('ready',))
        self.assertEqual(self.intake('csv_mark_ready', job), ('ready',))
        self.assertEqual(self.intake('csv_status', job), ('ready',))
        self.assertEqual(self.worker('csv_claim', job), (job, key, ORIGINAL, 12, 1, self.tenant))
        return job

    def complete(self, job, attempt=1, digest=None):
        text = 'safe derived fixture text'
        return self.worker('csv_complete', job, attempt, text, digest or sha256(text.encode()).hexdigest(), 2, 4)

    def test_legacy_csv_identifier_is_not_governed_lineage(self):
        from bri.access.policy import AccessGrant, Principal
        from bri.api.app import read_authorized_knowledge
        from bri.api.database import TenantSession

        source = f'csv:{uuid4()}'
        with self.connect('bri_app') as db:
            write_approved_legacy_lineage(db, self.tenant, source, source, source, source)
        with self.connect('bri_migrator') as db:
            db.execute("SELECT set_config('bri.tenant_id',%s,true)", (self.tenant,))
            db.execute('INSERT INTO bri.knowledge_record_access VALUES (%s,%s,true)', (self.tenant, source))
            db.execute('INSERT INTO bri.knowledge_version_access VALUES (%s,%s,%s,true)', (self.tenant, source, source))
        with self.connect('bri_app') as db:
            db.execute("SELECT set_config('bri.tenant_id',%s,true)", (self.tenant,))
            reader = Principal('legacy', frozenset({self.tenant}), (AccessGrant(self.tenant, 'knowledge:read', 'team'),))
            item, = read_authorized_knowledge(TenantSession(tenant_id=self.tenant, connection=db), reader)
            self.assertEqual((item.record_id, item.content, item.original_sha256), (source, LEGACY_TEXT, None))

    def test_migration_preserves_preexisting_legacy_lineage_ids(self):
        with self.connect('bri_migrator') as db:
            claims = db.execute('SELECT lineage_id,job_ref FROM bri.csv_lineage_claims WHERE tenant_id=%s',
                                (self.legacy_tenant,)).fetchall()
            self.assertCountEqual(claims, [(ref, None) for ref in self.legacy_refs])
            self.assertFalse(db.execute("SELECT EXISTS (SELECT FROM pg_policies WHERE schemaname='bri' "
                                        "AND policyname='csv_claim_backfill')").fetchone()[0])
        with self.connect('bri_app') as db:
            db.execute("SELECT set_config('bri.tenant_id',%s,true)", (self.legacy_tenant,))
            self.assertEqual(db.execute(
                'SELECT x.source_id,x.extraction_id,p.proposal_id,d.decision_id,x.csv_governed '
                'FROM bri.validated_knowledge k JOIN bri.validation_decisions d USING (tenant_id,decision_id) '
                'JOIN bri.knowledge_proposals p ON (p.tenant_id,p.proposal_id)=(k.tenant_id,k.proposal_id) '
                'JOIN bri.source_extractions x ON (x.tenant_id,x.extraction_id)=(p.tenant_id,p.extraction_id) '
                'WHERE k.tenant_id=%s',
                (self.legacy_tenant,),
            ).fetchall(), [(*self.legacy_refs, False)])

    def test_no_creator_binding_means_no_new_job(self):
        with self.connect('bri_migrator') as db:
            db.execute('DELETE FROM bri.csv_worker_creators WHERE tenant_id=%s', (self.tenant,))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.submit()
        with self.connect('postgres') as db:
            self.assertIsNone(db.execute('SELECT job_id FROM bri.csv_jobs WHERE tenant_id=%s', (self.tenant,)).fetchone())

    def test_worker_creator_must_differ_from_uploader(self):
        actor, uid, sid = self.actors[2]
        with self.connect('bri_migrator') as db:
            db.execute('UPDATE bri.csv_worker_creators SET creator_id=%s WHERE tenant_id=%s',
                       (actor, self.tenant))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege) as denied:
            self.submit()
        self.assertEqual(denied.exception.diag.message_primary, 'CSV creator binding unavailable')
        with self.connect('bri_migrator') as db:
            with self.assertRaises(psycopg.errors.CheckViolation) as invalid, db.transaction():
                db.execute('INSERT INTO bri.csv_jobs (tenant_id,scope_node_id,actor_id,creator_id,auth_user_id,'
                           'session_id,issuer,request_key,original_sha256,byte_count) '
                           "VALUES (%s,'team',%s,%s,%s,%s,%s,%s,%s,12)",
                           (self.tenant, actor, actor, uid, sid, ISSUER, uuid4(), ORIGINAL))
            self.assertEqual(invalid.exception.diag.constraint_name, 'csv_jobs_distinct_creator')
            self.assertEqual(db.execute('SELECT count(*) FROM bri.csv_jobs WHERE tenant_id=%s',
                                        (self.tenant,)).fetchone(), (0,))

    def test_submission_reserves_private_lineage_before_processing(self):
        job, state, _ = self.submit()
        self.assertEqual(state, 'creating')
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT job_ref FROM bri.csv_lineage_claims WHERE tenant_id=%s AND lineage_id=%s',
                                        (self.tenant, f'csv:{job}')).fetchone(), (f'csv:{job}',))
            self.assertIsNone(db.execute('SELECT 1 FROM bri.source_records WHERE tenant_id=%s AND source_id=%s',
                                         (self.tenant, f'csv:{job}')).fetchone())
        with self.connect('bri_app') as db:
            self.assertEqual(db.execute("SELECT has_table_privilege(current_user,'bri.csv_lineage_claims',"
                                        "'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')").fetchone(), (False,))
            self.assertEqual(db.execute(
                "SELECT relname FROM pg_class WHERE relnamespace='bri'::regnamespace "
                "AND relname IN ('source_records','source_versions','source_extractions','knowledge_proposals',"
                "'validation_decisions','validated_knowledge') "
                "AND (has_table_privilege(current_user,oid,'DELETE,TRUNCATE,TRIGGER') "
                "OR has_any_column_privilege(current_user,oid,'UPDATE'))"
            ).fetchall(), [])

    def test_reservation_serializes_behind_an_uncommitted_legacy_claim(self):
        candidate = uuid4()
        actor, uid, sid = self.actors[2]

        def reserve_candidate():
            # Supply a deterministic candidate via the private table boundary,
            # using the same reservation trigger as the submission RPC.
            with self.connect('bri_migrator') as db:
                db.execute("SET LOCAL statement_timeout='8s'")
                db.execute('INSERT INTO bri.csv_jobs (job_id,tenant_id,scope_node_id,actor_id,creator_id,auth_user_id,'
                           'session_id,issuer,request_key,original_sha256,byte_count) '
                           "VALUES (%s,%s,'team',%s,%s,%s,%s,%s,%s,%s,12)",
                           (candidate, self.tenant, actor, self.actors[1][0], uid, sid, ISSUER, uuid4(), ORIGINAL))

        blockers = []
        with ThreadPoolExecutor(max_workers=1) as pool, self.connect('bri_app') as legacy:
            write_legacy_source(legacy, self.tenant, f'csv:{candidate}')
            pending = pool.submit(reserve_candidate)
            try:
                with self.connect('postgres', autocommit=True) as observer:
                    end = time.monotonic() + 5
                    while time.monotonic() < end and not pending.done():
                        blockers = observer.execute("SELECT unnest(pg_blocking_pids(pid)) FROM pg_stat_activity "
                                                    "WHERE usename='bri_migrator'").fetchall()
                        if (legacy.info.backend_pid,) in blockers:
                            break
                        time.sleep(0.01)
            finally:
                legacy.commit()
            self.assertIn((legacy.info.backend_pid,), blockers)
            with self.assertRaises(psycopg.errors.UniqueViolation) as denied:
                pending.result(timeout=5)
            self.assertEqual(denied.exception.diag.constraint_name, 'csv_lineage_claims_pkey')
        with self.connect('postgres') as db:
            self.assertIsNone(db.execute('SELECT 1 FROM bri.csv_jobs WHERE job_id=%s', (candidate,)).fetchone())

    def test_reservation_rejects_a_maintenance_key_change(self):
        job, _, _ = self.submit()
        old_ref = 'maintenance-fixture'
        with self.connect('bri_app') as db:
            write_legacy_source(db, self.tenant, old_ref)
        # Exercise the constraint even for a fixture role with UPDATE access.
        with self.connect('postgres') as db:
            with self.assertRaises(psycopg.errors.UniqueViolation) as denied, db.transaction():
                db.execute('UPDATE bri.source_records SET source_id=%s WHERE (tenant_id,source_id)=(%s,%s)',
                           (f'csv:{job}', self.tenant, old_ref))
            self.assertEqual(denied.exception.diag.message_primary, 'lineage identity is reserved')
            self.assertEqual(db.execute('SELECT source_id FROM bri.source_records WHERE tenant_id=%s',
                                        (self.tenant,)).fetchall(), [(old_ref,)])

    def test_complete_review_and_publish_require_distinct_authorities(self):
        job = self.ready()
        proposal = f'csv:{job}'
        # Rotating the trusted config cannot redefine the creator of an already reserved job.
        with self.connect('bri_migrator') as db:
            db.execute('UPDATE bri.csv_worker_creators SET creator_id=%s WHERE tenant_id=%s',
                       (self.actors[0][0], self.tenant))
        with self.assertRaises(psycopg.errors.InvalidParameterValue):
            self.complete(job, digest=ORIGINAL)
        self.assertEqual(self.complete(job), ('proposed',))
        self.assertEqual(self.intake('csv_pending_review', identity=self.actors[0]),
                         (proposal, 'team', 'safe derived fixture text'))
        self.assertIsNone(self.intake('csv_pending_review'))
        self.assertIsNone(self.intake('csv_pending_review', identity=self.actors[1]))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.intake('csv_review', proposal, 'approved', identity=self.actors[1])
        with self.connect('bri_app') as db:
            db.execute("SELECT set_config('bri.tenant_id',%s,true)", (self.tenant,))
            self.assertEqual(db.execute('SELECT content FROM bri.source_extractions WHERE extraction_id=%s',
                                        (proposal,)).fetchall(), [])
            for query, params in (
                ('INSERT INTO bri.source_records (tenant_id,source_id,scope_node_id,title,source_kind,created_by,csv_governed) '
                 "VALUES (%s,'fake','team','fake','governed_csv','fake',true)", (self.tenant,)),
                ('INSERT INTO bri.knowledge_proposals (tenant_id,proposal_id,extraction_id,scope_node_id,proposed_by) '
                 "VALUES (%s,'fake',%s,'team','fake')", (self.tenant, proposal)),
                ('INSERT INTO bri.validation_decisions (tenant_id,decision_id,proposal_id,reviewer_id,decision) '
                 "VALUES (%s,'fake',%s,'fake','approved')", (self.tenant, proposal)),
                ('INSERT INTO bri.validated_knowledge (tenant_id,proposal_id,decision_id) VALUES (%s,%s,%s)',
                 (self.tenant, proposal, proposal)),
            ):
                with self.assertRaises((psycopg.errors.InsufficientPrivilege, psycopg.errors.ForeignKeyViolation)), db.transaction():
                    db.execute(query, params)
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.intake('csv_review', proposal, 'approved')
        self.assertEqual(self.intake('csv_review', proposal, 'approved', identity=self.actors[0]), ('approved',))
        with self.connect('postgres') as db:
            self.assertEqual(db.execute(
                'SELECT p.csv_creator_id,d.reviewer_id,v.content_sha256,x.content_sha256 '
                'FROM bri.knowledge_proposals p JOIN bri.validation_decisions d USING (tenant_id,proposal_id) '
                'JOIN bri.source_extractions x USING (tenant_id,extraction_id) '
                'JOIN bri.source_versions v USING (tenant_id,source_id,source_version_id) '
                'WHERE p.tenant_id=%s AND p.proposal_id=%s', (self.tenant, proposal),
            ).fetchone(), (self.actors[1][0], '__bri_governed_csv__',
                           sha256(b'safe derived fixture text').hexdigest(), sha256(b'safe derived fixture text').hexdigest()))
        with self.connect('bri_migrator') as db:
            db.execute("SELECT set_config('bri.tenant_id',%s,true)", (self.tenant,))
            db.execute('INSERT INTO bri.knowledge_record_access VALUES (%s,%s,true)', (self.tenant, proposal))
            db.execute("INSERT INTO bri.knowledge_version_access VALUES (%s,%s,%s,true)",
                       (self.tenant, proposal, proposal))
        with self.connect('bri_app') as db:
            db.execute("SELECT set_config('bri.tenant_id',%s,true)", (self.tenant,))
            for table, key in (('source_records', 'source_id'), ('source_versions', 'source_id'),
                               ('source_extractions', 'source_id'), ('knowledge_proposals', 'proposal_id'),
                               ('validated_knowledge', 'proposal_id'), ('validation_decisions', 'proposal_id'),
                               ('knowledge_record_access', 'source_id'), ('knowledge_version_access', 'source_id')):
                self.assertEqual(db.execute(f'SELECT 1 FROM bri.{table} WHERE tenant_id=%s AND {key}=%s',
                                            (self.tenant, proposal)).fetchall(), [])
            for query in ('SELECT * FROM bri.csv_source_evidence',
                          'SELECT * FROM bri.csv_read_published(NULL::text,NULL::uuid,NULL::uuid,NULL::uuid,NULL::text)'):
                with self.assertRaises(psycopg.errors.InsufficientPrivilege) as denied, db.transaction():
                    db.execute(query)
                self.assertIn('permission denied for', denied.exception.diag.message_primary)
        # This real reviewer has review authority but no knowledge:read grant, even on the trusted transport.
        actor, uid, sid = self.actors[0]
        with self.connect('bri_csv_reader') as db:
            self.assertEqual(db.execute('SELECT * FROM bri.csv_read_published(%s,%s,%s,%s,%s)',
                                        (self.tenant, actor, uid, sid, ISSUER)).fetchall(), [])
        # Revoke just the read permission and start a fresh valid session, so
        # neither a session cutoff nor either publication gate explains denial.
        for grant in (True, False):
            with self.connect('postgres') as db:
                db.execute("INSERT INTO bri.role_permissions VALUES (%s,'csv','knowledge:read')" if grant else
                           "DELETE FROM bri.role_permissions WHERE (tenant_id,role_id,permission)="
                           "(%s,'csv','knowledge:read')", (self.tenant,))
                sid = uuid4()
                db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                           'VALUES (%s,%s,%s,clock_timestamp())', (actor, uid, sid))
            with self.connect('bri_csv_reader') as db:
                self.assertEqual(db.execute('SELECT proposal_id FROM bri.csv_read_published(%s,%s,%s,%s,%s)',
                                            (self.tenant, actor, uid, sid, ISSUER)).fetchall(),
                                 [(proposal,)] if grant else [])
        with self.connect('bri_migrator') as db:
            db.execute("SELECT set_config('bri.tenant_id',%s,true)", (self.tenant,))
            db.execute('UPDATE bri.knowledge_version_access SET readable=false WHERE source_version_id=%s', (proposal,))
            self.assertEqual(db.execute(
                "SELECT event,actor_id,readable FROM bri.csv_audit_events WHERE job_id=%s AND event IN "
                "('submitted','approved','record_access','version_access') ORDER BY occurred_at", (job,),
            ).fetchall(), [('submitted', self.actors[2][0], None), ('approved', self.actors[0][0], None),
                           ('record_access', None, True), ('version_access', None, True), ('version_access', None, False)])
        with self.connect('bri_app') as db:
            db.execute("SELECT set_config('bri.tenant_id',%s,true)", (self.tenant,))
            with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                db.execute('SELECT * FROM bri.csv_audit_events')

    def test_attempt_fencing_reclaims_stale_and_stops_at_three(self):
        job = self.ready()
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.csv_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE job_id=%s", (job,))
        self.assertEqual(self.worker('csv_claim', job)[4], 2)
        self.assertEqual(self.complete(job), ('stale',))
        self.assertEqual(self.worker('csv_fail', job, 2, 'storage_error', True), ('ready',))
        self.assertEqual(self.worker('csv_claim', job)[4], 3)
        self.assertEqual(self.worker('csv_fail', job, 3, 'private parser message', True), ('failed',))
        self.assertIsNone(self.worker('csv_claim', job))
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT event,reason FROM bri.csv_audit_events WHERE job_id=%s ORDER BY occurred_at',
                                        (job,)).fetchall(), [('submitted', None), ('ready', None), ('claimed', None),
                                                            ('lease_expired', 'lease_expired'), ('claimed', None),
                                                            ('retry', 'storage_error'), ('claimed', None),
                                                            ('failed', 'processing_error')])

    def test_worker_completion_waits_for_uncommitted_revocation(self):
        job = self.ready()
        blockers = []
        with ThreadPoolExecutor(max_workers=1) as pool, self.connect('postgres') as revoker:
            revoker.execute("UPDATE bri.auth_role_assignments SET status='revoked' WHERE tenant_id=%s "
                            "AND principal_id=%s AND role_id='csv'", (self.tenant, self.actors[2][0]))
            pending = pool.submit(self.complete, job)
            try:
                with self.connect('postgres', autocommit=True) as observer:
                    end = time.monotonic() + 5
                    while time.monotonic() < end and not pending.done():
                        blockers = observer.execute("SELECT unnest(pg_blocking_pids(pid)) FROM pg_stat_activity "
                                                    "WHERE usename='bri_csv_worker'").fetchall()
                        if (revoker.info.backend_pid,) in blockers:
                            break
                        time.sleep(0.01)
            finally:
                revoker.commit()
            self.assertIn((revoker.info.backend_pid,), blockers)
            self.assertEqual(pending.result(timeout=5), ('failed',))
        with self.connect('postgres') as db:
            self.assertFalse(db.execute('SELECT EXISTS (SELECT FROM bri.knowledge_proposals WHERE proposal_id=%s)',
                                        (f'csv:{job}',)).fetchone()[0])
            self.assertEqual(db.execute("SELECT event,reason FROM bri.csv_audit_events WHERE job_id=%s AND event='failed'",
                                        (job,)).fetchone(), ('failed', 'authority_lost'))

    def test_revoked_submitter_cannot_release_object_key_to_worker(self):
        job, _, _ = self.submit()
        self.assertEqual(self.intake('csv_mark_ready', job), ('ready',))
        with self.connect('postgres') as db:
            db.execute('UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() WHERE session_id=%s',
                       (self.actors[2][2],))
        self.assertIsNone(self.worker('csv_claim', job))
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT state,attempt FROM bri.csv_jobs WHERE job_id=%s', (job,)).fetchone(),
                             ('failed', 0))

    def test_http_verified_native_sessions_and_private_store(self):
        import httpx
        from fastapi.testclient import TestClient
        from test_authentication import auth_server_response, make_token

        from bri.api.csv_intake import PREFIX, REVIEW_PREFIX, create_staged_csv_intake_app
        from bri.ingestion.csv_intake import LocalCsvQuarantine

        submitter, reviewer, outsider = self.actors[2], self.actors[0], self.foreign_actors[2]
        tokens = {make_token(sub=str(user), session_id=str(sid)): str(user)
                  for _, user, sid in (submitter, reviewer, outsider)}
        submit_token, review_token, outside_token = tokens
        with TemporaryDirectory(prefix='csv-private-') as root:
            app = create_staged_csv_intake_app(
                identity_scope=lambda: self.connect('bri_app'), intake_scope=lambda: self.connect('bri_csv_intake'),
                worker_scope=lambda: self.connect('bri_csv_worker'), private_socket=self.sock,
                auth_transport=httpx.MockTransport(lambda req: auth_server_response(
                    req, user_id=tokens.get(req.headers['authorization'].removeprefix('Bearer '), ''))),
                store=LocalCsvQuarantine(Path(root)),
            )
            with TestClient(app, base_url='http://127.0.0.1', client=('127.0.0.1', 50400)) as client:
                response = client.post(PREFIX, content=b'field\nsynthetic\n', headers={
                    'authorization': f'Bearer {submit_token}', 'content-type': 'text/csv',
                    'x-node-id': 'team', 'idempotency-key': str(uuid4()),
                })
                self.assertEqual(response.status_code, 202, response.text)
                job = response.json()['id']
                self.assertEqual(app.state.csv_worker.dispatch(UUID(job)).value, 'completed')
                response = client.get(f'{PREFIX}/{job}', headers={'authorization': f'Bearer {outside_token}'})
                self.assertIn(response.status_code, (403, 404))
                reviewer_headers = {'authorization': f'Bearer {review_token}'}
                pending = client.get(REVIEW_PREFIX, headers=reviewer_headers)
                self.assertEqual(pending.status_code, 200, pending.text)
                self.assertEqual(pending.json()[0]['id'], f'csv:{job}')
                approved = client.post(f'{REVIEW_PREFIX}/csv:{job}/decision', json={'decision': 'approved'},
                                       headers=reviewer_headers)
                self.assertEqual(approved.status_code, 200, approved.text)
                with self.connect('postgres') as db:
                    db.execute('UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() WHERE session_id=%s',
                               (submitter[2],))
                denied = client.get(f'{PREFIX}/{job}', headers={'authorization': f'Bearer {submit_token}'})
                self.assertEqual(denied.status_code, 403, denied.text)
