"""A19.1 protected SQL on a fresh socket-only PostgreSQL 16.2 cluster."""
import os
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from queue import Queue
from unittest.mock import patch
from uuid import UUID, uuid4

import psycopg
from psycopg.types.json import Jsonb

import test_privileged_approvals_pg as fixtures

ISSUER = fixtures.ISSUER
DIGEST = sha256(b'a\nb\n').hexdigest()
META = dict(version=1, primary_classification_id='policy', title='Validated title',
            additional_classification_ids=[], description=None, effective_date=None, review_date=None, expiry_date=None)
IDENTITY = 'text,uuid,uuid,uuid,text'
CSV_IDENTITY = 'text,uuid,uuid,text'
ROUTINES = {
    'bri_csv_intake': {
        'csv_submit': CSV_IDENTITY + ',text,uuid,text,integer,uuid',
        'csv_submit_metadata_v1': CSV_IDENTITY + ',text,uuid,text,integer,uuid,jsonb',
        'csv_mark_ready': CSV_IDENTITY + ',uuid,uuid',
        'csv_review': CSV_IDENTITY + ',text,text,uuid',
        'csv_review_decide': CSV_IDENTITY + ',uuid,text,uuid',
        'csv_review_metadata_v1': CSV_IDENTITY + ',uuid,text,uuid,uuid,jsonb',
    },
    'bri_csv_worker': {
        'csv_claim': 'uuid,uuid',
        'csv_complete': 'uuid,integer,text,text,integer,integer,uuid',
    },
    'bri_xlsx_submitter': {
        'xlsx_submit': IDENTITY + ',text,uuid,integer,text,uuid',
        'xlsx_submit_metadata_v1': IDENTITY + ',text,uuid,integer,text,uuid,jsonb',
    },
    'bri_csv_reader': {
        'csv_read_metadata_v1': IDENTITY + ',uuid,uuid',
        'csv_propose_metadata_correction_v1': IDENTITY + ',uuid,uuid,bigint,uuid,uuid,jsonb',
        'csv_review_metadata_correction_v1': IDENTITY + ',uuid,uuid,uuid,text,uuid,uuid',
    },
    'bri_xlsx_reader': {
        'xlsx_read_metadata_v1': IDENTITY + ',uuid,uuid',
        'xlsx_propose_metadata_correction_v1': IDENTITY + ',uuid,uuid,bigint,uuid,uuid,jsonb',
        'xlsx_review_metadata_correction_v1': IDENTITY + ',uuid,uuid,uuid,text,uuid,uuid',
    },
    'bri_xlsx_reviewer': {
        'xlsx_review_decide': IDENTITY + ',uuid,text,uuid,uuid',
        'xlsx_review_metadata_v1': IDENTITY + ',uuid,text,uuid,uuid,jsonb',
    },
}


@unittest.skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16.2')
class MetadataPostgresTests(unittest.TestCase):
    connect = classmethod(fixtures.ApprovalDatabase.connect.__func__)

    @classmethod
    def setUpClass(cls):
        with patch.dict(os.environ, BRI_APPROVAL_PG_BIN=os.environ['BRI_TEST_PG_BIN']):
            fixtures.ApprovalDatabase.setUpClass.__func__(cls)
        with cls.connect('postgres') as db:
            assert db.execute("SELECT current_setting('server_version_num'),inet_server_addr(),"
                              " current_setting('listen_addresses')").fetchone() == ('160002', None, '')
            db.execute('INSERT INTO bri.provider_event_source(issuer) VALUES (%s)', (ISSUER,))
            for role in ROUTINES:
                db.execute(f'CREATE ROLE {role} LOGIN NOINHERIT NOBYPASSRLS; GRANT USAGE ON SCHEMA bri TO {role}')

    def install(self, role, name):
        signature = f'bri.{name}({ROUTINES[role][name]})'
        with self.connect('bri_app') as db:
            self.assertEqual(db.execute("SELECT has_function_privilege(to_regprocedure(%s),'EXECUTE')", (signature,)).fetchone(),
                             (False,), signature)
        with self.connect('postgres') as db:
            db.execute(f'GRANT EXECUTE ON FUNCTION {signature} TO {role}')

    def setUp(self):
        self.tenant, self.actors = fixtures.seed_approval_tenant(self.connect)
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.org_nodes VALUES (%s,'team','team','Team','root')", (self.tenant,))
            db.execute("INSERT INTO bri.app_roles VALUES (%s,'intake','Intake')", (self.tenant,))
            db.execute("INSERT INTO bri.role_permissions VALUES (%s,'intake','source:submit'),"
                       "(%s,'intake','knowledge:review')", (self.tenant, self.tenant))
            for index in range(3):
                actor, sub, _ = self.actors[index]
                sid = uuid4()
                self.actors[index] = actor, sub, sid
                db.execute("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id)"
                           " VALUES (%s,%s,'intake','team')", (self.tenant, actor))
                db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at)'
                           ' VALUES (%s,%s,%s,clock_timestamp())', (actor, sub, sid))
            for prefix in ('csv', 'xlsx'):
                db.execute(f'INSERT INTO bri.{prefix}_worker_creators VALUES (%s,%s)', (self.tenant, self.actors[1][0]))

    def seed_catalogue(self):
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.knowledge_classification_categories(tenant_id,category_id,label) VALUES (%s,'general','General')", (self.tenant,))
            db.execute("INSERT INTO bri.knowledge_classifications(tenant_id,classification_id,category_id,label) VALUES "
                       "(%s,'policy','general','Policy'),(%s,'manual','general','Manual')", (self.tenant, self.tenant))

    def call(self, role, name, *args, who=0, db=None):
        if db is None:
            with self.connect(role) as conn:
                return self.call(role, name, *args, who=who, db=conn)
        actor, sub, sid = self.actors[who]
        if ROUTINES[role][name].startswith(CSV_IDENTITY + ','):
            db.execute("SELECT set_config('bri.auth_user_id',%s,true)", (str(sub),))
            identity = (self.tenant, actor, sid, ISSUER)
        elif name in ('csv_claim', 'csv_complete'):
            identity = ()
        else:
            identity = (self.tenant, actor, sub, sid, ISSUER)
        params = (*identity, *args)
        return db.execute(f"SELECT * FROM bri.{name}({','.join(['%s'] * len(params))})", params).fetchone()

    def csv_submit(self, key, metadata=META):
        return self.call('bri_csv_intake', 'csv_submit_metadata_v1', 'team', key, DIGEST, 4, uuid4(), Jsonb(metadata), who=2)[0]

    def test_reservation_binds_metadata_without_retrofit(self):
        for name in ('csv_submit_metadata_v1', 'csv_submit'):
            self.install('bri_csv_intake', name)
        self.seed_catalogue()
        key = uuid4()
        first = self.csv_submit(key)
        self.assertEqual(first, self.csv_submit(key))
        with self.assertRaises(psycopg.errors.UniqueViolation):
            self.csv_submit(key, {**META, 'title': 'retrofitted'})
        old = uuid4()
        self.call('bri_csv_intake', 'csv_submit', 'team', old, DIGEST, 4, uuid4(), who=2)
        with self.assertRaises(psycopg.errors.UniqueViolation):
            self.csv_submit(old)
        for invalid in (
            {**META, 'title': 'é' * 81},
            {**META, 'primary_classification_id': 'foreign-or-missing'},
            {**META, 'additional_classification_ids': ['policy']},
            {**META, 'additional_classification_ids': ['manual', 'manual']},
            {**META, 'additional_classification_ids': [f'c-{i}' for i in range(9)]},
            {**META, 'review_date': '2026-02-29'},
            {**META, 'responsible_node_id': 'root'},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(psycopg.errors.InvalidParameterValue):
                self.csv_submit(uuid4(), invalid)
        self.csv_submit(uuid4(), {**META, 'title': 'é' * 80, 'expiry_date': '2025-01-01', 'review_date': '2026-01-01'})
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT count(*) FROM bri.csv_jobs WHERE tenant_id=%s',(self.tenant,)).fetchone(),(3,))

    def assert_waiter(self, writer, waiter):
        with self.connect('postgres', autocommit=True) as observer:
            until = time.monotonic() + 3
            while time.monotonic() < until:
                blockers, = observer.execute('SELECT pg_blocking_pids(%s)', (waiter,)).fetchone()
                if writer in blockers:
                    return
                time.sleep(0.02)
        self.fail('contender never blocked behind the expected writer')

    def csv_pending(self, metadata=META):
        for role in ('bri_csv_intake', 'bri_csv_worker'):
            for name in ROUTINES[role]:
                self.install(role, name)
        if metadata is None:
            job, _, _ = self.call('bri_csv_intake','csv_submit','team',uuid4(),DIGEST,4,uuid4(),who=2)
        else:
            receipt = self.csv_submit(uuid4(),metadata)
            job = UUID(receipt['job_id'])
        self.call('bri_csv_intake', 'csv_mark_ready', job, uuid4(), who=2)
        self.call('bri_csv_worker', 'csv_claim', job, uuid4())
        text = 'safe text'
        self.call('bri_csv_worker', 'csv_complete', job, 1, text, sha256(text.encode()).hexdigest(), 2, 2, uuid4())
        return job

    def test_metadata_tables_and_all_entry_points_are_private(self):
        with self.connect('bri_app') as db:
            tables = db.execute("""SELECT relname,relrowsecurity,relforcerowsecurity,
                has_table_privilege(oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                FROM pg_class WHERE relnamespace='bri'::regnamespace AND relkind='r'
                AND relname LIKE 'knowledge_metadata_%'""").fetchall()
        self.assertEqual(set(tables), {(f'knowledge_metadata_{suffix}',True,True,False) for suffix in (
            'payloads','additional','initial','revisions','initial_decisions','correction_proposals','correction_decisions')})
        for role in ('bri_app','bri_csv_reader','bri_xlsx_reader'):
            with self.connect(role) as db:
                self.assertFalse(db.execute("""SELECT EXISTS (SELECT FROM pg_proc p
                    WHERE p.pronamespace='bri'::regnamespace
                    AND p.proname LIKE 'km\\_%' AND has_function_privilege(p.oid,'EXECUTE'))""").fetchone()[0])
        # Even an erroneously granted EXECUTE cannot enter from the wrong login.
        with self.connect('postgres') as db:
            db.execute('GRANT EXECUTE ON FUNCTION bri.csv_read_metadata_v1(text,uuid,uuid,uuid,text,uuid,uuid) TO bri_xlsx_reader')
        try:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege) as denied, self.connect('bri_xlsx_reader') as db:
                actor, sub, sid = self.actors[0]
                db.execute('SELECT bri.csv_read_metadata_v1(%s,%s,%s,%s,%s,%s,%s)',
                           (self.tenant,actor,sub,sid,ISSUER,uuid4(),uuid4()))
            self.assertEqual(denied.exception.diag.message_primary,'XLSX role denied')
        finally:
            with self.connect('postgres') as db:
                db.execute('REVOKE EXECUTE ON FUNCTION bri.csv_read_metadata_v1(text,uuid,uuid,uuid,text,uuid,uuid) FROM bri_xlsx_reader')

    def test_csv_read_policy_revocation_beats_waiting_correction(self):
        self.seed_catalogue()
        job = self.csv_pending()
        self.call('bri_csv_intake','csv_review_metadata_v1',job,'approved',uuid4(),uuid4())
        reader = 'bri_csv_reader'
        for name in ROUTINES[reader]:
            self.install(reader,name)
        role_read, propose = 'csv_read_metadata_v1', 'csv_propose_metadata_correction_v1'
        self.grant(0,'knowledge:read')
        self.grant(0,'knowledge:metadata:propose')
        ref = f'csv:{job}'
        def csv_access(db):
            db.execute("SELECT set_config('bri.tenant_id',%s,true)",(self.tenant,))
        with self.connect('bri_migrator') as db:
            csv_access(db)
            db.execute('INSERT INTO bri.knowledge_record_access VALUES (%s,%s,true)',(self.tenant,ref))
        key = uuid4()
        self.assertEqual(self.call(reader,role_read,job,job),(None,))
        with self.connect('bri_migrator') as db:
            csv_access(db)
            db.execute('INSERT INTO bri.knowledge_version_access VALUES (%s,%s,%s,true)',(self.tenant,ref,ref))
        current, = self.call(reader,role_read,job,job)
        self.assertEqual(current['metadata']['responsible_node_id'],'team')
        self.assertEqual(self.call(reader,role_read,job,uuid4()),(None,))
        ready = Queue()
        def contend():
            with self.connect(reader) as db:
                db.execute("SET LOCAL statement_timeout='5s'")
                ready.put(db.info.backend_pid)
                return self.call(reader,propose,job,job,1,key,uuid4(),Jsonb(META),db=db)
        with ThreadPoolExecutor(max_workers=1) as workers:
            with self.connect('bri_migrator') as writer:
                csv_access(writer)
                writer.execute('UPDATE bri.knowledge_version_access SET readable=false WHERE (tenant_id,source_id,source_version_id)=(%s,%s,%s)',
                               (self.tenant,ref,ref))
                fut = workers.submit(contend)
                self.assert_waiter(writer.info.backend_pid,ready.get(timeout=2))
            self.assertEqual(fut.result(timeout=5),(None,))
        self.assertEqual(self.call(reader,role_read,job,job),(None,))
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT count(*) FROM bri.knowledge_metadata_correction_proposals WHERE tenant_id=%s',(self.tenant,)).fetchone(),(0,))
            self.assertEqual(db.execute('SELECT revision FROM bri.knowledge_metadata_revisions WHERE tenant_id=%s',(self.tenant,)).fetchall(),[(1,)])

    def test_retirement_preserves_history_and_blocks_pending_validation(self):
        self.seed_catalogue()
        published = self.csv_pending()
        pending = self.csv_pending()
        self.call('bri_csv_intake','csv_review_metadata_v1',published,'approved',uuid4(),uuid4())
        self.install('bri_csv_reader','csv_read_metadata_v1')
        self.grant(0,'knowledge:read')
        ref = f'csv:{published}'
        with self.connect('bri_migrator') as db:
            db.execute("SELECT set_config('bri.tenant_id',%s,true)",(self.tenant,))
            db.execute('INSERT INTO bri.knowledge_record_access VALUES (%s,%s,true)',(self.tenant,ref))
            db.execute('INSERT INTO bri.knowledge_version_access VALUES (%s,%s,%s,true)',(self.tenant,ref,ref))
        self.grant(0,'classification:catalogue:manage','root')
        with self.connect('postgres') as db:
            db.execute('CREATE ROLE bri_classification_catalogue LOGIN NOINHERIT NOBYPASSRLS; GRANT USAGE ON SCHEMA bri TO bri_classification_catalogue')
            db.execute('GRANT EXECUTE ON FUNCTION bri.classification_catalogue_rename(text,uuid,uuid,uuid,text,text,text),'
                       'bri.classification_catalogue_retire(text,uuid,uuid,uuid,text,text) TO bri_classification_catalogue')
        with self.connect('bri_classification_catalogue') as db:
            identity = self.tenant,*self.actors[0],ISSUER,'policy'
            db.execute('SELECT bri.classification_catalogue_rename(%s,%s,%s,%s,%s,%s,%s)',(*identity,'Renamed'))
            db.execute('SELECT bri.classification_catalogue_retire(%s,%s,%s,%s,%s,%s)',identity)
        row, = self.call('bri_csv_reader','csv_read_metadata_v1',published,published)
        self.assertEqual(row['metadata']['primary_classification'],
                         {'classification_id':'policy','label':'Renamed','retired':True})
        with self.assertRaises(psycopg.errors.InvalidParameterValue):
            self.call('bri_csv_intake','csv_review_metadata_v1',pending,'approved',uuid4(),uuid4())
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT primary_label FROM bri.knowledge_metadata_revisions WHERE tenant_id=%s',(self.tenant,)).fetchall(),[('Policy',)])
            self.assertEqual(db.execute('SELECT state FROM bri.csv_jobs WHERE job_id=%s',(pending,)).fetchone(),('proposed',))
            self.assertEqual(db.execute("SELECT count(*) FROM bri.csv_audit_events WHERE job_id=%s AND event='approved'",(pending,)).fetchone(),(0,))
            for table in ('knowledge_metadata_payloads','knowledge_metadata_revisions'):
                with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                    db.execute(f'DELETE FROM bri.{table} WHERE tenant_id=%s',(self.tenant,))
        self.assertEqual(self.call('bri_csv_intake','csv_review',str(pending),'rejected',uuid4()),('rejected',))

    def test_csv_initial_guards_both_legacy_paths_and_replays(self):
        self.seed_catalogue()
        job = self.csv_pending()
        for name, ref in [('csv_review', str(job)), ('csv_review_decide', job)]:
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self.call('bri_csv_intake', name, ref, 'approved', uuid4())
        key = uuid4()
        def decide(action='approved', who=0):
            return self.call('bri_csv_intake', 'csv_review_metadata_v1', job, action, key, uuid4(), who=who)[0]
        self.assertIsNone(decide(who=1))
        self.assertIsNone(decide(who=2))
        with self.connect('postgres') as db:
            db.execute("ALTER TABLE bri.csv_audit_events ADD CONSTRAINT a19_fixture_fail CHECK (event <> 'approved') NOT VALID")
        try:
            with self.assertRaises(psycopg.errors.CheckViolation):
                decide()
        finally:
            with self.connect('postgres') as db:
                db.execute('ALTER TABLE bri.csv_audit_events DROP CONSTRAINT a19_fixture_fail')
        receipt = dict(job_id=str(job), decision='approved', metadata_revision='1')
        self.assertEqual(decide(), receipt)
        self.assertEqual(decide(), receipt)
        with self.assertRaises(psycopg.errors.UniqueViolation):
            decide('rejected')
        with self.connect('postgres') as db:
            self.assertEqual(db.execute("SELECT count(*) FROM bri.csv_audit_events WHERE tenant_id=%s AND event='approved'", (self.tenant,)).fetchone(), (1,))

    def xlsx_pending(self, metadata=META):
        submitter = 'bri_xlsx_submitter'
        for role in (submitter, 'bri_xlsx_reviewer'):
            for name in ROUTINES[role]:
                self.install(role, name)
        base = ('team', uuid4(), 4, DIGEST, uuid4())
        if metadata is None:
            receipt, = self.call(submitter, 'xlsx_submit', *base, who=2)
            with self.assertRaises(psycopg.errors.UniqueViolation):
                self.call(submitter, 'xlsx_submit_metadata_v1', *base, Jsonb(META), who=2)
        else:
            receipt, = self.call(submitter, 'xlsx_submit_metadata_v1', *base, Jsonb(metadata), who=2)
            self.assertEqual(self.call(submitter, 'xlsx_submit_metadata_v1', *base, Jsonb(metadata), who=2), (receipt,))
            with self.assertRaises(psycopg.errors.UniqueViolation):
                self.call(submitter, 'xlsx_submit_metadata_v1', *base, Jsonb({**metadata, 'title': 'Changed'}), who=2)
        job = UUID(receipt['job_id'])
        # Complete the pre-existing XLSX pipeline fixture without recoding its worker here.
        canonical = '{"rows":[[["text","Header"]]],"version":1,"worksheet":{"identity":"1","range":"A1","title":"Sample"}}'
        canonical_digest = sha256(canonical.encode()).hexdigest()
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.xlsx_jobs SET state='proposed',attempt=1 WHERE job_id=%s", (job,))
            db.execute("INSERT INTO bri.xlsx_sources VALUES (%s,%s,'team',%s)", (self.tenant,job,self.actors[1][0]))
            db.execute("INSERT INTO bri.xlsx_source_versions VALUES (%s,%s,%s,%s,'1','Sample','A1')", (self.tenant,job,DIGEST,canonical_digest))
            db.execute('INSERT INTO bri.xlsx_extractions VALUES (%s,%s,%s,%s,1,1)', (self.tenant,job,canonical,canonical_digest))
            db.execute('INSERT INTO bri.xlsx_pending_proposals(tenant_id,job_id) VALUES (%s,%s)', (self.tenant,job))
        return job

    def grant(self, who, permission, node='team'):
        actor, sub, _ = self.actors[who]
        sid = uuid4()
        with self.connect('postgres') as db:
            db.execute('INSERT INTO bri.app_roles VALUES (%s,%s,%s) ON CONFLICT DO NOTHING', (self.tenant,permission,permission))
            db.execute('INSERT INTO bri.role_permissions VALUES (%s,%s,%s) ON CONFLICT DO NOTHING', (self.tenant,permission,permission))
            db.execute('INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) VALUES (%s,%s,%s,%s)',
                       (self.tenant,actor,permission,node))
            db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) VALUES (%s,%s,%s,clock_timestamp())',
                       (actor,sub,sid))
        self.actors[who] = (actor,sub,sid)

    def extra_actor(self):
        actor, sub, sid = uuid4(), uuid4(), uuid4()
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.auth_principals(principal_id,status) VALUES (%s,'active')", (actor,))
            db.execute("INSERT INTO bri.auth_identity_links(auth_user_id,principal_id,auth_issuer,auth_subject,provider_type,provider_issuer,provider_subject) VALUES (%s,%s,%s,%s,'native',%s,%s)", (sub,actor,ISSUER,str(sub),ISSUER,str(sub)))
            db.execute("INSERT INTO bri.auth_tenant_memberships(tenant_id,principal_id,membership_type,status) VALUES (%s,%s,'user','active')", (self.tenant,actor))
        self.actors.append((actor,sub,sid))
        return len(self.actors)-1

    def test_xlsx_initial_legacy_rejection_and_unclassified_approval(self):
        self.seed_catalogue()
        job = self.xlsx_pending()
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.call('bri_xlsx_reviewer', 'xlsx_review_decide', job, 'approve', uuid4(), uuid4())
        self.assertEqual(self.call('bri_xlsx_reviewer', 'xlsx_review_decide', job, 'reject', uuid4(), uuid4()), ('reject',))
        old = self.xlsx_pending(None)
        self.assertEqual(self.call('bri_xlsx_reviewer', 'xlsx_review_decide', old, 'approve', uuid4(), uuid4()), ('approve',))
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT count(*) FROM bri.knowledge_metadata_revisions WHERE tenant_id=%s', (self.tenant,)).fetchone(), (0,))

    def test_corrected_initial_approval_is_atomic_and_replays_canonical_input(self):
        self.seed_catalogue()
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.knowledge_classifications(tenant_id,classification_id,category_id,label) "
                       "VALUES (%s,'reference','general','Reference')",(self.tenant,))
        for fmt, role, pending, approval, rejection, audit in (
                ('csv','bri_csv_intake',self.csv_pending,'approved','rejected','csv_audit_events'),
                ('xlsx','bri_xlsx_reviewer',self.xlsx_pending,'approve','reject','xlsx_governance_audit_events')):
            with self.subTest(fmt=fmt):
                job = pending()
                request = uuid4()
                replacement = {**META,'title':'Validated correction','primary_classification_id':'manual',
                               'additional_classification_ids':['reference','policy']}
                def decide(action=approval, metadata=replacement, who=0, target=job, key=request):
                    payload = None if metadata is None else Jsonb(metadata)
                    return self.call(role,f'{fmt}_review_metadata_v1',target,action,key,uuid4(),payload,who=who)[0]
                self.assertIsNone(decide(who=1))
                self.assertIsNone(decide(who=2))
                with self.assertRaises(psycopg.errors.InvalidParameterValue):
                    decide(rejection)
                with self.assertRaises(psycopg.errors.InvalidParameterValue):
                    decide(metadata={**replacement,'primary_classification_id':'missing'})
                with self.connect('postgres') as db:
                    db.execute(f"ALTER TABLE bri.{audit} ADD CONSTRAINT a19_override_fail "
                               f"CHECK (event <> '{approval}') NOT VALID")
                try:
                    with self.assertRaises(psycopg.errors.CheckViolation):
                        decide()
                    with self.connect('postgres') as db:
                        self.assertEqual(db.execute('''SELECT count(*) FROM bri.knowledge_metadata_payloads
                            WHERE tenant_id=%s AND title=%s AND payload_id NOT IN (
                                SELECT r.payload_id FROM bri.knowledge_metadata_revisions r WHERE r.tenant_id=%s)''',
                            (self.tenant,replacement['title'],self.tenant)).fetchone(),(0,))
                        for table in ('initial_decisions','revisions'):
                            self.assertEqual(db.execute(f'SELECT count(*) FROM bri.knowledge_metadata_{table} WHERE job_id=%s',
                                                        (job,)).fetchone(),(0,))
                        self.assertEqual(db.execute(f'SELECT count(*) FROM bri.{audit} WHERE job_id=%s AND event=%s',
                                                    (job,approval)).fetchone(),(0,))
                        if fmt=='csv':
                            self.assertEqual(db.execute('SELECT state FROM bri.csv_jobs WHERE job_id=%s',(job,)).fetchone(),('proposed',))
                            self.assertEqual(db.execute('SELECT count(*) FROM bri.validated_knowledge WHERE tenant_id=%s AND proposal_id=%s',
                                                        (self.tenant,f'csv:{job}')).fetchone(),(0,))
                        else:
                            for table in ('xlsx_review_decisions','xlsx_validated_knowledge'):
                                self.assertEqual(db.execute(f'SELECT count(*) FROM bri.{table} WHERE job_id=%s',(job,)).fetchone(),(0,))
                finally:
                    with self.connect('postgres') as db:
                        db.execute(f'ALTER TABLE bri.{audit} DROP CONSTRAINT a19_override_fail')
                receipt = {'job_id':str(job),'decision':approval,'metadata_revision':'1'}
                self.assertEqual(decide(),receipt)
                self.assertEqual(decide(metadata={**replacement,'additional_classification_ids':['policy','reference']}),receipt)
                for different in (None,{}, {**replacement,'title':'Another correction'}):
                    with self.assertRaises(psycopg.errors.UniqueViolation):
                        decide(metadata=different)
                with self.connect('postgres') as db:
                    self.assertEqual(db.execute('''SELECT p.title,v.title,p.payload_id<>v.payload_id
                        FROM bri.knowledge_metadata_initial i
                        JOIN bri.knowledge_metadata_payloads p USING (tenant_id,payload_id)
                        JOIN bri.knowledge_metadata_revisions r USING (tenant_id,format,job_id)
                        JOIN bri.knowledge_metadata_payloads v ON (v.tenant_id,v.payload_id)=(r.tenant_id,r.payload_id)
                        WHERE (i.tenant_id,i.format,i.job_id)=(%s,%s,%s)''',(self.tenant,fmt,job)).fetchone(),
                        (META['title'],replacement['title'],True))
                    self.assertEqual(db.execute(f'SELECT count(*) FROM bri.{audit} WHERE job_id=%s AND event=%s',
                                                (job,approval)).fetchone(),(1,))
                old = pending(None)
                with self.assertRaises(psycopg.errors.InvalidParameterValue):
                    decide(target=old,key=uuid4())
                self.assertEqual(decide(metadata=None,target=old,key=uuid4())['metadata_revision'],None)
                if fmt=='csv':
                    native_job = pending(None)
                    self.assertEqual(self.call(role,'csv_review_decide',native_job,approval,uuid4()),(approval,))
                    with self.connect('postgres') as db:
                        self.assertEqual(db.execute('SELECT count(*) FROM bri.knowledge_metadata_revisions WHERE job_id=%s',
                                                    (native_job,)).fetchone(),(0,))

    def test_corrected_initial_review_rechecks_governance_after_fence_wait(self):
        self.seed_catalogue()
        for fmt, role, pending, action in (
                ('csv','bri_csv_intake',self.csv_pending,'approved'),
                ('xlsx','bri_xlsx_reviewer',self.xlsx_pending,'approve')):
            with self.subTest(fmt=fmt):
                job = pending()
                key = uuid4()
                args = (job,action,key,uuid4(),Jsonb({**META,'title':'Denied replacement'}))
                ready = Queue()
                def contender():
                    with self.connect(role) as db:
                        db.execute("SET LOCAL statement_timeout='5s'")
                        ready.put(db.info.backend_pid)
                        return self.call(role,f'{fmt}_review_metadata_v1',*args,db=db)
                with ThreadPoolExecutor(max_workers=1) as workers:
                    with self.connect('postgres') as blocker:
                        blocker.execute('UPDATE bri.client_totp_observations SET verified_until=NULL '
                                        'WHERE (tenant_id,principal_id)=(%s,%s)',(self.tenant,self.actors[1][0]))
                        result = workers.submit(contender)
                        self.assert_waiter(blocker.info.backend_pid,ready.get(timeout=2))
                    self.assertEqual(result.result(timeout=5),(None,))
                with self.connect('postgres') as db:
                    self.assertEqual(db.execute('SELECT revoked_at IS NULL FROM bri.auth_sessions WHERE session_id=%s',
                                                (self.actors[0][2],)).fetchone(),(True,))
                    for suffix in ('initial_decisions','revisions'):
                        self.assertEqual(db.execute(f'SELECT count(*) FROM bri.knowledge_metadata_{suffix} WHERE job_id=%s',
                                                    (job,)).fetchone(),(0,))
                    db.execute("UPDATE bri.client_totp_observations SET verified_until=observed_at+interval '15 minutes' "
                               'WHERE (tenant_id,principal_id)=(%s,%s)',(self.tenant,self.actors[1][0]))
                self.assertEqual(self.call(role,f'{fmt}_review_metadata_v1',*args)[0]['metadata_revision'],'1')

    def test_concurrent_initial_review_conflicts_after_canonical_binding_commits(self):
        self.seed_catalogue()
        for fmt,role,pending,action,audit in (
                ('csv','bri_csv_intake',self.csv_pending,'approved','csv_audit_events'),
                ('xlsx','bri_xlsx_reviewer',self.xlsx_pending,'approve','xlsx_governance_audit_events')):
            with self.subTest(fmt=fmt):
                job = pending()
                name = f'{fmt}_review_metadata_v1'
                key = uuid4()
                original = {**META,'title':'Winning validation'}
                args = (job,action,key)
                ready = Queue()
                def contender():
                    with self.connect(role) as db:
                        db.execute("SET LOCAL statement_timeout='5s'")
                        ready.put(db.info.backend_pid)
                        return self.call(role,name,*args,uuid4(),Jsonb({**original,'title':'Conflicting retry'}),db=db)
                with ThreadPoolExecutor(max_workers=1) as workers:
                    with self.connect(role) as first:
                        result = self.call(role,name,*args,uuid4(),Jsonb(original),db=first)
                        future = workers.submit(contender)
                        self.assert_waiter(first.info.backend_pid,ready.get(timeout=2))
                    with self.assertRaises(psycopg.errors.UniqueViolation):
                        future.result(timeout=5)
                self.assertEqual(self.call(role,name,*args,uuid4(),Jsonb(original)),result)
                with self.connect('postgres') as db:
                    self.assertEqual(db.execute(f'SELECT count(*) FROM bri.{audit} WHERE job_id=%s AND event=%s',
                                                (job,action)).fetchone(),(1,))
                    self.assertEqual(db.execute('SELECT count(*) FROM bri.knowledge_metadata_payloads WHERE tenant_id=%s AND title=%s',
                                                (self.tenant,'Conflicting retry')).fetchone(),(0,))

    def test_initial_proposal_detail_reuses_native_pending_evidence_and_live_authority(self):
        self.seed_catalogue()
        for fmt, role, pending, approval, trailing in (
                ('csv','bri_csv_intake',self.csv_pending,'approved',(0,)),
                ('xlsx','bri_xlsx_reviewer',self.xlsx_pending,'approve',())):
            with self.subTest(fmt=fmt):
                if fmt == 'xlsx':
                    # Replace the revoked CSV reviewer session and grant with another independent reviewer.
                    who = self.extra_actor()
                    self.grant(who,'knowledge:review')
                else:
                    who = 0
                original = {**META,'effective_date':'2026-11-28'}
                job = pending(original)
                legacy = pending(None)
                detail_name = f'{fmt}_review_metadata_detail_v1'
                native_name = f'{fmt}_review_detail'
                signature = IDENTITY + ',uuid' + (',integer' if trailing else '')
                with self.connect('postgres') as db:
                    for name in (detail_name,native_name):
                        db.execute(f'GRANT EXECUTE ON FUNCTION bri.{name}({signature}) TO {role}')
                def detail(target=job, as_who=who, name=detail_name):
                    with self.connect(role) as db:
                        db.execute('SET TRANSACTION READ ONLY')
                        inputs = (self.tenant,*self.actors[as_who],ISSUER,target,*trailing)
                        return db.execute(f"SELECT bri.{name}({','.join(['%s']*len(inputs))})", inputs).fetchone()[0]
                evidence = detail(name=native_name)
                self.assertTrue(evidence)
                self.assertEqual(detail(),{'detail':evidence,'proposed_metadata':original})
                self.assertEqual(detail(legacy),{'detail':detail(legacy,name=native_name),'proposed_metadata':None})
                self.assertIsNone(detail(as_who=1))
                self.assertIsNone(detail(as_who=2))
                self.assertIsNone(detail(uuid4()))
                self.call(role,f'{fmt}_review_metadata_v1',legacy,approval,uuid4(),uuid4(),who=who)
                self.assertIsNone(detail(legacy))
                with self.connect('postgres') as db:
                    db.execute("UPDATE bri.auth_role_assignments SET status='revoked' WHERE "
                               "(tenant_id,principal_id,role_id)=(%s,%s,%s)",
                               (self.tenant,self.actors[who][0],'intake' if fmt=='csv' else 'knowledge:review'))
                    actor,sub,_ = self.actors[who]
                    sid=uuid4()
                    db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                               'VALUES (%s,%s,%s,clock_timestamp())',(actor,sub,sid))
                    self.actors[who]=(actor,sub,sid)
                self.assertIsNone(detail())
                self.assertEqual(self.call(role,f'{fmt}_review_metadata_v1',job,approval,uuid4(),uuid4(),Jsonb(original),who=who),
                                 (None,))

    def test_correction_inspection_is_bounded_by_live_access_and_review_eligibility(self):
        self.seed_catalogue()
        reviewer = self.extra_actor()
        for who in (0,1,reviewer):
            self.grant(who,'knowledge:read')
            self.grant(who,'knowledge:metadata:review')
        self.grant(0,'knowledge:metadata:propose')
        self.grant(reviewer,'knowledge:metadata:propose')
        for fmt, pending, approval in (('csv',self.csv_pending,'approved'),('xlsx',self.xlsx_pending,'approve')):
            with self.subTest(fmt=fmt):
                job = pending()
                self.call('bri_csv_intake' if fmt=='csv' else 'bri_xlsx_reviewer',f'{fmt}_review_metadata_v1',
                          job,approval,uuid4(),uuid4())
                role = f'bri_{fmt}_reader'
                list_name = f'{fmt}_list_metadata_corrections_v1'
                for name in ROUTINES[role]:
                    self.install(role,name)
                with self.connect('postgres') as db:
                    db.execute(f'GRANT EXECUTE ON FUNCTION bri.{list_name}({IDENTITY},uuid,uuid,uuid,integer) TO {role}')
                    if fmt=='xlsx':
                        record, = db.execute('SELECT record_id FROM bri.xlsx_validated_knowledge WHERE job_id=%s',(job,)).fetchone()
                        db.execute("INSERT INTO bri.xlsx_publication_events (tenant_id,record_id,job_id,revision,action,actor_id) "
                                   "VALUES (%s,%s,%s,1,'publish',%s)",(self.tenant,record,job,self.actors[0][0]))
                        for who in (0,1,reviewer):
                            db.execute('INSERT INTO bri.xlsx_record_access VALUES (%s,%s,%s)',(self.tenant,record,self.actors[who][0]))
                            db.execute('INSERT INTO bri.xlsx_version_access VALUES (%s,%s,%s,%s)',
                                       (self.tenant,record,job,self.actors[who][0]))
                    else:
                        record=job
                ref = f'csv:{job}'
                if fmt=='csv':
                    with self.connect('bri_migrator') as db:
                        db.execute("SELECT set_config('bri.tenant_id',%s,true)",(self.tenant,))
                        db.execute('INSERT INTO bri.knowledge_record_access VALUES (%s,%s,true)',(self.tenant,ref))
                        db.execute('INSERT INTO bri.knowledge_version_access VALUES (%s,%s,%s,true)',(self.tenant,ref,ref))
                def overview(after=None,size=20,as_who=reviewer,version=job):
                    with self.connect(role) as db:
                        db.execute('SET TRANSACTION READ ONLY')
                        return db.execute(f'SELECT bri.{list_name}(%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                                          (self.tenant,*self.actors[as_who],ISSUER,record,version,after,size)).fetchone()[0]
                self.assertEqual(overview(),{'items':[],'next_after':None})
                self.assertIsNone(overview(version=uuid4()))
                self.assertIsNone(overview(as_who=1))  # Original creator, despite correction grant and exact read access.
                self.assertIsNone(overview(as_who=2))  # No separate correction grant.
                for size in (0,21):
                    with self.assertRaises(psycopg.errors.InvalidParameterValue):
                        overview(size=size)
                def propose(title, who=0):
                    payload = {**META,'title':title}
                    result, = self.call(role,f'{fmt}_propose_metadata_correction_v1',record,job,1,uuid4(),uuid4(),Jsonb(payload),who=who)
                    return dict(proposal_id=result['proposal_id'],expected_revision='1',proposed_metadata=payload)
                own = propose('Own proposal',reviewer)
                ordered = sorted((propose('First'),propose('Second')),key=lambda p:str(p['proposal_id']))
                first = UUID(str(ordered[0]['proposal_id']))
                self.assertEqual(overview(size=1),{'items':[ordered[0]],'next_after':ordered[0]['proposal_id']})
                self.assertEqual(overview(first,1),{'items':[ordered[1]],'next_after':None})
                self.assertIsNone(overview(UUID(str(own['proposal_id']))))
                self.assertIsNone(overview(uuid4()))
                self.call(role,f'{fmt}_review_metadata_correction_v1',record,job,first,
                          'approve',uuid4(),uuid4(),who=reviewer)
                self.assertEqual(overview(),{'items':[],'next_after':None})  # decided and stale
                self.assertIsNone(overview(first))
                if fmt=='csv':
                    with self.connect('bri_migrator') as db:
                        db.execute("SELECT set_config('bri.tenant_id',%s,true)",(self.tenant,))
                        db.execute('UPDATE bri.knowledge_version_access SET readable=false WHERE (tenant_id,source_id,source_version_id)=(%s,%s,%s)',
                                   (self.tenant,ref,ref))
                else:
                    with self.connect('postgres') as db:
                        db.execute('DELETE FROM bri.xlsx_version_access WHERE (tenant_id,record_id,job_id,principal_id)=(%s,%s,%s,%s)',
                                   (self.tenant,record,job,self.actors[reviewer][0]))
                self.assertIsNone(overview())

    def test_pending_correction_decisions_require_current_revision_after_fence(self):
        self.seed_catalogue()
        reviewer = self.extra_actor()
        contender = self.extra_actor()
        for who in (0, reviewer, contender):
            self.grant(who, 'knowledge:read')
        self.grant(0, 'knowledge:metadata:propose')
        for who in (reviewer, contender):
            self.grant(who, 'knowledge:metadata:review')

        for fmt, pending, initial_role, initial_action, native_tables in (
            ('csv', self.csv_pending, 'bri_csv_intake', 'approved', (
                'csv_jobs', 'source_records', 'source_versions', 'source_extractions', 'knowledge_proposals',
                'validation_decisions', 'validated_knowledge', 'knowledge_record_access',
                'knowledge_version_access', 'csv_audit_events')),
            ('xlsx', self.xlsx_pending, 'bri_xlsx_reviewer', 'approve', (
                'xlsx_jobs', 'xlsx_sources', 'xlsx_source_versions', 'xlsx_extractions',
                'xlsx_pending_proposals', 'xlsx_review_decisions', 'xlsx_validated_knowledge',
                'xlsx_publication_events', 'xlsx_record_access', 'xlsx_version_access', 'xlsx_governance_audit_events')),
        ):
            with self.subTest(format=fmt):
                job = pending()
                initial, = self.call(initial_role, f'{fmt}_review_metadata_v1', job, initial_action, uuid4(), uuid4())
                self.assertEqual(initial['metadata_revision'], '1')
                role = f'bri_{fmt}_reader'
                for name in ROUTINES[role]:
                    self.install(role, name)
                list_name = f'{fmt}_list_metadata_corrections_v1'
                with self.connect('postgres') as db:
                    db.execute(f'GRANT EXECUTE ON FUNCTION bri.{list_name}({IDENTITY},uuid,uuid,uuid,integer) TO {role}')
                    if fmt == 'xlsx':
                        record, = db.execute('SELECT record_id FROM bri.xlsx_validated_knowledge WHERE job_id=%s', (job,)).fetchone()
                        db.execute("INSERT INTO bri.xlsx_publication_events (tenant_id,record_id,job_id,revision,action,actor_id) "
                                   "VALUES (%s,%s,%s,1,'publish',%s)", (self.tenant, record, job, self.actors[0][0]))
                        for who in (0, reviewer, contender):
                            db.execute('INSERT INTO bri.xlsx_record_access VALUES (%s,%s,%s)', (self.tenant, record, self.actors[who][0]))
                            db.execute('INSERT INTO bri.xlsx_version_access VALUES (%s,%s,%s,%s)',
                                       (self.tenant, record, job, self.actors[who][0]))
                    else:
                        record = job
                if fmt == 'csv':
                    ref = f'csv:{job}'
                    with self.connect('bri_migrator') as db:
                        db.execute("SELECT set_config('bri.tenant_id',%s,true)", (self.tenant,))
                        db.execute('INSERT INTO bri.knowledge_record_access VALUES (%s,%s,true)', (self.tenant, ref))
                        db.execute('INSERT INTO bri.knowledge_version_access VALUES (%s,%s,%s,true)', (self.tenant, ref, ref))

                def propose(revision, title):
                    proposal, = self.call(role, f'{fmt}_propose_metadata_correction_v1', record, job, revision,
                                          uuid4(), uuid4(), Jsonb({**META, 'title': title}))
                    self.assertEqual(proposal['expected_revision'], str(revision))
                    return UUID(proposal['proposal_id'])

                def decide(proposal, action, key, *, who=reviewer, db=None, correlation=None):
                    return self.call(role, f'{fmt}_review_metadata_correction_v1', record, job, proposal,
                                     action, key, correlation or uuid4(), who=who, db=db)[0]

                def receipt(proposal, action, revision):
                    return dict(record_id=str(record), source_version_id=str(job), proposal_id=str(proposal),
                                decision=action, metadata_revision=revision)

                def snapshot(*tables):
                    with self.connect('postgres') as db:
                        return {table: db.execute(f'SELECT to_jsonb(t) FROM bri.{table} t WHERE tenant_id=%s '
                                                  'ORDER BY to_jsonb(t)', (self.tenant,)).fetchall() for table in tables}

                def assert_conflict(attempt, proposal):
                    try:
                        output = attempt()
                    except psycopg.errors.UniqueViolation as error:
                        self.assertEqual((error.sqlstate, error.diag.message_primary), ('23505', 'Metadata revision conflict'))
                    else:
                        with self.connect('postgres') as db:
                            persisted = db.execute('SELECT decision,metadata_revision '
                                                   'FROM bri.knowledge_metadata_correction_decisions '
                                                   'WHERE (tenant_id,format,job_id,proposal_id)=(%s,%s,%s,%s)',
                                                   (self.tenant, fmt, job, proposal)).fetchone()
                        self.fail(f'{fmt} stale decision returned {output!r}; persisted decision={persisted!r}')

                candidates = 'knowledge_metadata_correction_proposals'
                terminals = 'knowledge_metadata_correction_decisions'
                revisions = 'knowledge_metadata_revisions'
                unchanged = (*native_tables, candidates, 'knowledge_metadata_payloads', 'knowledge_metadata_additional',
                             'knowledge_metadata_initial', 'knowledge_metadata_initial_decisions')
                rejected = propose(1, 'Current rejection')
                rejected_key, rejected_correlation = uuid4(), uuid4()
                before = snapshot(*unchanged, revisions)
                self.assertEqual(decide(rejected, 'reject', rejected_key, correlation=rejected_correlation),
                                 receipt(rejected, 'reject', None))
                self.assertEqual(snapshot(*unchanged, revisions), before)

                stale = {action: propose(1, f'Stale {action}') for action in ('approve', 'reject')}
                replays = [(rejected, rejected_key, rejected_correlation, receipt(rejected, 'reject', None))]
                for base, waiting_action in ((1, 'reject'), (2, 'approve')):
                    with self.subTest(waiting_action=waiting_action):
                        winner = propose(base, f'Approved at {base}')
                        waiting = propose(base, f'Waiting {waiting_action}')
                        winner_key, winner_correlation = uuid4(), uuid4()
                        winner_receipt = receipt(winner, 'approve', str(base + 1))
                        if base == 1:
                            replays.append((winner, winner_key, winner_correlation, winner_receipt))
                        before = snapshot(*unchanged, terminals, revisions)
                        ready = Queue()

                        def contend():
                            with self.connect(role) as db:
                                db.execute("SET LOCAL statement_timeout='5s'")
                                ready.put(db.info.backend_pid)
                                # An independent reviewer cannot be waiting on the winner's actor/session guards.
                                return decide(waiting, waiting_action, uuid4(), who=contender, db=db)

                        with ThreadPoolExecutor(max_workers=1) as workers:
                            with self.connect(role) as writer:
                                self.assertEqual(decide(winner, 'approve', winner_key, db=writer,
                                                        correlation=winner_correlation), winner_receipt)
                                future = workers.submit(contend)
                                self.assert_waiter(writer.info.backend_pid, ready.get(timeout=2))
                            assert_conflict(lambda: future.result(timeout=5), waiting)
                        after = snapshot(*unchanged, terminals, revisions)
                        winner_decision, = [d for d, in after[terminals] if d['proposal_id'] == str(winner)]
                        self.assertEqual((winner_decision['decision'], winner_decision['metadata_revision']), ('approve', base + 1))
                        after[terminals].remove((winner_decision,))
                        new_revision, = [r for r, in after[revisions] if r['format'] == fmt and r['revision'] == base + 1]
                        after[revisions].remove((new_revision,))
                        self.assertEqual(after, before)
                current, = self.call(role, f'{fmt}_read_metadata_v1', record, job, who=reviewer)
                self.assertEqual((current['metadata']['revision'], current['metadata']['title']), ('3', 'Approved at 2'))
                with self.connect(role) as db:
                    db.execute('SET TRANSACTION READ ONLY')
                    listed, = db.execute(f'SELECT bri.{list_name}(%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                                         (self.tenant, *self.actors[reviewer], ISSUER, record, job, None, 20)).fetchone()
                self.assertEqual(listed, {'items': [], 'next_after': None})
                for action, proposal in stale.items():
                    with self.subTest(stale_action=action):
                        before = snapshot(*unchanged, terminals, revisions)
                        assert_conflict(lambda: decide(proposal, action, uuid4()), proposal)
                        self.assertEqual(snapshot(*unchanged, terminals, revisions), before)
                before = snapshot(*unchanged, terminals, revisions)
                for proposal, key, correlation, original in replays:
                    action = original['decision']
                    self.assertEqual(decide(proposal, action, key, correlation=correlation), original)
                    for bad_action, bad_key in ((action, uuid4()), ('reject' if action == 'approve' else 'approve', key)):
                        with self.assertRaises(psycopg.errors.UniqueViolation) as mismatch:
                            decide(proposal, bad_action, bad_key)
                        self.assertEqual(mismatch.exception.diag.message_primary, 'Metadata correction decision conflict')
                self.assertEqual(snapshot(*unchanged, terminals, revisions), before)

    def test_xlsx_correction_uses_live_gates_and_cas(self):
        reader = 'bri_xlsx_reader'
        for name in ROUTINES[reader]:
            self.install(reader, name)
        self.seed_catalogue()
        job = self.xlsx_pending({**META, 'additional_classification_ids':['manual'], 'effective_date':'2026-11-28'})
        request = uuid4()
        for excluded in (1,2):
            self.assertEqual(self.call('bri_xlsx_reviewer', 'xlsx_review_metadata_v1', job, 'approve', request, uuid4(), who=excluded), (None,))
        receipt = {'job_id':str(job), 'decision':'approve', 'metadata_revision':'1'}
        self.assertEqual(self.call('bri_xlsx_reviewer', 'xlsx_review_metadata_v1', job, 'approve', request, uuid4()), (receipt,))
        self.assertEqual(self.call('bri_xlsx_reviewer', 'xlsx_review_metadata_v1', job, 'approve', request, uuid4()), (receipt,))
        with self.connect('postgres') as db:
            record, = db.execute('SELECT record_id FROM bri.xlsx_validated_knowledge WHERE job_id=%s', (job,)).fetchone()
        reviewer = self.extra_actor()
        propose, review, read = ('xlsx_propose_metadata_correction_v1','xlsx_review_metadata_correction_v1','xlsx_read_metadata_v1')
        for who in (0,reviewer,1):
            self.grant(who,'knowledge:read')
        self.grant(0,'knowledge:metadata:propose','root')
        self.grant(0,'knowledge:metadata:review')
        self.grant(reviewer,'knowledge:metadata:review')
        self.grant(1,'knowledge:metadata:propose')
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.xlsx_publication_events (tenant_id,record_id,job_id,revision,action,actor_id) VALUES (%s,%s,%s,1,'publish',%s)", (self.tenant,record,job,self.actors[0][0]))
            for who in (0,reviewer,1):
                db.execute('INSERT INTO bri.xlsx_record_access VALUES (%s,%s,%s)', (self.tenant,record,self.actors[who][0]))
        updated = Jsonb({**META, 'title':'Corrected'})
        key = uuid4()
        self.assertEqual(self.call(reader,propose,record,job,1,key,uuid4(),updated), (None,))
        with self.connect('postgres') as db:
            for who in (0,reviewer,1):
                db.execute('INSERT INTO bri.xlsx_version_access VALUES (%s,%s,%s,%s)', (self.tenant,record,job,self.actors[who][0]))
        self.assertEqual(self.call(reader,propose,record,job,1,key,uuid4(),updated), (None,))  # ancestor-only
        self.assertEqual(self.call(reader,propose,record,job,1,key,uuid4(),updated,who=1), (None,))  # actual creator
        self.grant(0,'knowledge:metadata:propose')
        before, = self.call(reader,read,record,job)
        self.assertEqual(before['metadata']['revision'], '1')
        self.assertEqual(before['metadata']['effective_date'], '2026-11-28')
        self.assertEqual(before['metadata']['additional_classifications'][0]['classification_id'], 'manual')
        self.assertEqual(self.call(reader,read,record,uuid4()), (None,))
        proposals = [self.call(reader,propose,record,job,1,k,uuid4(),updated)[0] for k in (key,uuid4())]
        self.assertEqual(self.call(reader,propose,record,job,1,key,uuid4(),updated), (proposals[0],))
        self.assertEqual(self.call(reader,read,record,job), (before,))
        first, competing = (UUID(p['proposal_id']) for p in proposals)
        decision_key = uuid4()
        self.assertEqual(self.call(reader,review,record,job,first,'approve',decision_key,uuid4()), (None,))  # same proposer
        def decide(proposal, request_id):
            return self.call(reader,review,record,job,proposal,'approve',request_id,uuid4(),who=reviewer)[0]
        with self.connect('postgres') as db:
            db.execute('ALTER TABLE bri.knowledge_metadata_correction_decisions ADD CONSTRAINT a19_test_rollback CHECK (false) NOT VALID')
        try:
            with self.assertRaises(psycopg.errors.CheckViolation):
                decide(first,decision_key)
            self.assertEqual(self.call(reader,read,record,job), (before,))
        finally:
            with self.connect('postgres') as db:
                db.execute('ALTER TABLE bri.knowledge_metadata_correction_decisions DROP CONSTRAINT a19_test_rollback')
        ready = Queue()
        def contend():
            with self.connect(reader) as db:
                db.execute("SET LOCAL statement_timeout='5s'")
                ready.put(db.info.backend_pid)
                return self.call(reader,review,record,job,competing,'approve',uuid4(),uuid4(),who=reviewer,db=db)
        with ThreadPoolExecutor(max_workers=1) as workers:
            with self.connect(reader) as writer:
                result, = self.call(reader,review,record,job,first,'approve',decision_key,uuid4(),who=reviewer,db=writer)
                fut = workers.submit(contend)
                self.assert_waiter(writer.info.backend_pid,ready.get(timeout=2))
            with self.assertRaises(psycopg.errors.UniqueViolation):
                fut.result(timeout=5)
        self.assertEqual(result['metadata_revision'],'2')
        self.assertEqual(decide(first,decision_key), result)
        after, = self.call(reader,read,record,job)
        self.assertEqual(after['metadata']['title'],'Corrected')
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT revision FROM bri.knowledge_metadata_revisions WHERE tenant_id=%s ORDER BY revision',(self.tenant,)).fetchall(),[(1,),(2,)])
            self.assertEqual(db.execute('SELECT count(*) FROM bri.knowledge_metadata_correction_decisions WHERE tenant_id=%s',(self.tenant,)).fetchone(),(1,))
            self.assertEqual(db.execute('SELECT count(*) FROM bri.xlsx_record_access WHERE tenant_id=%s',(self.tenant,)).fetchone(),(3,))
            self.assertEqual(db.execute('SELECT count(*) FROM bri.xlsx_version_access WHERE tenant_id=%s',(self.tenant,)).fetchone(),(3,))
            self.assertEqual(db.execute('SELECT revision, action FROM bri.xlsx_publication_events WHERE tenant_id=%s',(self.tenant,)).fetchall(),[(1,'publish')])
            db.execute("INSERT INTO bri.xlsx_publication_events (tenant_id,record_id,job_id,revision,action,actor_id) VALUES (%s,%s,%s,2,'withdraw',%s)", (self.tenant,record,job,self.actors[0][0]))
        self.assertIsNone(decide(first,decision_key))
        self.assertEqual(self.call(reader,read,record,job), (None,))
