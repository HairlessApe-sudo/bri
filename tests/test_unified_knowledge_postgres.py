"""A18 protected SQL checks on a private socket, never using a DSN."""
import os
import time
import unittest
from hashlib import sha256
from uuid import UUID, uuid4

import psycopg
import test_csv_intake_postgres as csv
import test_csv_reporting_postgres as reporting
import test_privileged_approvals_pg as fixtures
from bri.ingestion.csv_intake import extract_bounded_csv

ROLE = 'bri_unified_knowledge_reader'
SEARCH = 'bri.unified_knowledge_search(text,uuid,uuid,uuid,text,text,text)'
EVIDENCE = 'bri.unified_csv_evidence(text,uuid,uuid,uuid,text,uuid,uuid)'


@unittest.skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16')
class UnifiedKnowledgePostgresTests(unittest.TestCase):
    tenant: str
    foreign: str
    actors: list[tuple[UUID, UUID, UUID]]
    connect = classmethod(fixtures.ApprovalDatabase.connect.__func__)
    setUp = reporting.CsvReportingPostgresTests.setUp
    setUp_intake = csv.CsvIntakePostgresTests.setUp
    intake = csv.CsvIntakePostgresTests.intake
    submit = csv.CsvIntakePostgresTests.submit
    worker = csv.CsvIntakePostgresTests.worker

    @classmethod
    def setUpClass(cls):
        reporting.CsvReportingPostgresTests.setUpClass.__func__(cls)
        with cls.connect('postgres') as db:
            assert db.execute("SELECT inet_server_addr(),current_setting('listen_addresses')").fetchone() == (None, '')
            db.execute(f'CREATE ROLE {ROLE} LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS '
                       'NOCREATEROLE NOCREATEDB NOREPLICATION')
            db.execute(f'GRANT USAGE ON SCHEMA bri TO {ROLE}; GRANT EXECUTE ON FUNCTION {SEARCH}, {EVIDENCE} TO {ROLE}')

    def test_protected_entry_points_exist_without_app_or_public_acl(self):
        with self.connect('bri_app') as db:
            for signature in (SEARCH, EVIDENCE):
                row = db.execute('''SELECT p.prosecdef, p.provolatile,
                    has_function_privilege(p.oid,'EXECUTE'), EXISTS (
                        SELECT FROM aclexplode(p.proacl) a WHERE a.grantee=0)
                    FROM pg_proc p WHERE p.oid=to_regprocedure(%s)''', (signature,)).fetchone()
                self.assertEqual(row, (True, 's', False, False), signature)

    def read(self, name, *args, tenant=None, identity=None, issuer=csv.ISSUER):
        with self.connect(ROLE) as db:
            db.execute('SET TRANSACTION READ ONLY')
            db.execute("SET LOCAL statement_timeout = '5s'")
            return db.execute(f'SELECT bri.{name}({",".join(["%s"] * (5+len(args)))})',
                              (tenant or self.tenant, *(identity or self.actors[0]), issuer, *args)).fetchone()[0]

    def search(self, query, node='team', **kwargs):
        return self.read('unified_knowledge_search', node, query, **kwargs)['results']

    def evidence(self, record, version, **kwargs):
        return self.read('unified_csv_evidence', record, version, **kwargs)

    def publish_csv(self, raw=b'"heAd\r\ner",Label\r\n"foo\r\nbar\nbaz",Tail\rLast,Value', allow=True):
        extraction = extract_bounded_csv(raw)
        job, _, _ = self.submit(size=len(raw))
        self.assertEqual(self.intake('csv_mark_ready', job), ('ready',))
        self.assertIsNotNone(self.worker('csv_claim', job))
        self.assertEqual(self.worker('csv_complete', job, 1, extraction.text, extraction.extracted_sha256,
                                     extraction.first_line, extraction.last_line), ('proposed',))
        ref = f'csv:{job}'
        self.assertEqual(self.intake('csv_review', ref, 'approved', identity=self.actors[0]), ('approved',))
        if allow:
            with self.connect('bri_migrator') as db:
                db.execute("SELECT set_config('bri.tenant_id',%s,true)", (self.tenant,))
                db.execute('INSERT INTO bri.knowledge_record_access VALUES (%s,%s,true)', (self.tenant, ref))
                db.execute('INSERT INTO bri.knowledge_version_access VALUES (%s,%s,%s,true)', (self.tenant, ref, ref))
        return job, extraction

    def test_csv_header_and_multiline_row_evidence(self):
        job, extraction = self.publish_csv()
        self.assertEqual(self.search('  HEAD   ER  '), [{'format': 'csv', 'record_id': str(job),
                         'source_id': f'csv:{job}', 'source_version_id': str(job),
                         'original_sha256': csv.ORIGINAL, 'content_sha256': extraction.extracted_sha256,
                         'match': 'exact', 'excerpt': 'head er', 'excerpt_truncated': False,
                         'evidence': {'first_line': 1, 'last_line': 2},
                         'evidence_url': f'/v1/knowledge/csv/{job}/versions/{job}/evidence'}])
        self.assertEqual(self.search('BAR')[0]['evidence'], {'first_line': 3, 'last_line': 5})
        self.assertEqual(self.search('Tail')[0]['evidence'], {'first_line': 3, 'last_line': 5})
        self.assertEqual(self.search('Last')[0]['evidence'], {'first_line': 6, 'last_line': 6})
        self.assertEqual(self.search('%'), [])
        self.assertEqual(self.evidence(job, job), {'record_id': str(job), 'source_version_id': str(job),
                         'first_line': 1, 'last_line': 6, 'original_sha256': csv.ORIGINAL,
                         'content_sha256': extraction.extracted_sha256})
        self.assertIsNone(self.evidence(job, uuid4()))
        self.assertIsNone(self.evidence(job, job, tenant=self.foreign))

    def test_embedded_nul_does_not_break_provenance_or_join_search_terms(self):
        job, _ = self.publish_csv(b'header\npre\x00post\n\\u0000')
        self.assertEqual(self.evidence(job, job)['last_line'], 3)
        self.assertEqual(self.search('prepost'), [])
        self.assertEqual(self.search('POST')[0]['evidence'], {'first_line': 2, 'last_line': 2})
        self.assertEqual(self.search('u0000')[0]['evidence'], {'first_line': 3, 'last_line': 3})

    def test_query_and_match_excerpt_bounds_are_utf8_and_ascii_folded(self):
        self.publish_csv(('label\n'+('é'*1400)+'É%Tail').encode())
        [match] = self.search('É%TAIL')
        self.assertIn('É%tail', match['excerpt'])
        self.assertTrue(match['excerpt'].startswith('…'))
        self.assertEqual(self.search('label')[0]['excerpt'], 'label')
        self.assertLessEqual(len(match['excerpt'].encode()), 2048)
        self.assertEqual(self.search('é%TAIL'), [])
        self.assertEqual(len(self.search('é'*128)), 1)
        with self.assertRaises(psycopg.errors.InvalidParameterValue):
            self.search('é'*129)
        with self.assertRaises(psycopg.errors.InvalidParameterValue):
            self.search(' '*4096+'a')
        job, _ = self.publish_csv(('header\nstart'+('é'*1500)).encode())
        [right] = self.search('start')
        self.assertEqual(right['record_id'], str(job))
        self.assertTrue(right['excerpt'].startswith('start'))
        self.assertTrue(right['excerpt'].endswith('…'))
        self.assertLessEqual(len(right['excerpt'].encode()), 2048)

    def test_csv_both_independent_allows_and_integrity_fail_closed(self):
        job, _ = self.publish_csv()
        for table in ('knowledge_record_access', 'knowledge_version_access'):
            with self.subTest(table=table):
                with self.connect('bri_migrator') as db:
                    db.execute("SELECT set_config('bri.tenant_id',%s,true)", (self.tenant,))
                    db.execute(f'UPDATE bri.{table} SET readable=false WHERE tenant_id=%s AND source_id=%s',
                               (self.tenant, f'csv:{job}'))
                self.assertIsNone(self.evidence(job, job))
                self.assertEqual(self.search('head'), [])
                with self.connect('bri_migrator') as db:
                    db.execute("SELECT set_config('bri.tenant_id',%s,true)", (self.tenant,))
                    db.execute(f'UPDATE bri.{table} SET readable=true WHERE tenant_id=%s AND source_id=%s',
                               (self.tenant, f'csv:{job}'))
        with self.connect('postgres') as db:
            db.execute("SET LOCAL session_replication_role='replica'")
            db.execute('UPDATE bri.csv_source_evidence SET last_line=last_line+1 WHERE (tenant_id,source_id)=(%s,%s)',
                       (self.tenant, f'csv:{job}'))
        with self.assertRaises(psycopg.errors.DataException):
            self.search('never matches')
        with self.assertRaises(psycopg.errors.DataException):
            self.evidence(job, job)

    def test_scope_and_session_rechecked(self):
        self.publish_csv()
        self.assertTrue(self.search('head'))
        for kwargs in ({'node': 'root'}, {'node': 'missing'}, {'tenant': self.foreign}, {'issuer': 'unbound'},
                       {'identity': (*self.actors[0][:2], uuid4())}):
            with self.subTest(**kwargs), self.assertRaises(psycopg.errors.InsufficientPrivilege) as denied:
                self.search('head', **kwargs)
            self.assertEqual(denied.exception.diag.message_primary, 'Knowledge scope denied')
        with self.connect('postgres') as db:
            db.execute('UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() WHERE session_id=%s', (self.actors[0][2],))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.search('head')

    def test_live_identity_eligibility_at_protected_operation(self):
        job, _ = self.publish_csv()
        actor, sub, sid = self.actors[2]  # ordinary reader, not a required emergency admin
        self.assertTrue(self.search('head', identity=(actor,sub,sid)))
        self.assertIsNotNone(self.evidence(job,job,identity=(actor,sub,sid)))
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_identity_links SET status='suspended' WHERE auth_user_id=%s", (sub,))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.search('head', identity=(actor,sub,sid))
        self.assertIsNone(self.evidence(job,job,identity=(actor,sub,sid)))
        # An active linked subject with a session but a pending (not eligible)
        # principal must not become verified merely by possessing the session ID.
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_identity_links SET status='active' WHERE auth_user_id=%s", (sub,))
            db.execute("UPDATE bri.auth_principals SET status='pending' WHERE principal_id=%s", (actor,))
            sid = uuid4()
            db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                       'VALUES (%s,%s,%s,clock_timestamp())', (actor,sub,sid))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.search('head', identity=(actor,sub,sid))
        self.assertIsNone(self.evidence(job,job,identity=(actor,sub,sid)))

    def seed_xlsx(self, count=1, allowed=True, dense=False):
        canonical = ('{"rows":[[["text","Not exact"],["text","Label"]],'
                     '[["text","head"],["text","%"]],[["number","7e0"],["boolean",true]],'
                     '[["date","2026-11-27"],["time","17:22:33"]],'
                     '[["datetime","2026-12-01T10:41:02"],null],[null,["boolean",false]]],"version":1,'
                     '"worksheet":{"identity":"1","range":"A1:B6","title":"Synthetic"}}')
        cell_range = 'A1:B6'
        if dense:
            canonical = ('{"rows":[' + ','.join(['[' + ','.join(['["text","not the search term"]']*50) + ']']*1000)
                         + '],"version":1,"worksheet":{"identity":"1","range":"A1:AX1000","title":"Synthetic"}}')
            cell_range = 'A1:AX1000'
        digest = sha256(canonical.encode()).hexdigest()
        self.xlsx_fixture_digest = digest
        self.xlsx_original_digest = sha256(b'synthetic original workbook bytes').hexdigest()
        actor, sub, sid = self.actors[2]
        creator = self.actors[1][0]
        reader = self.actors[0][0]
        t = self.tenant
        with self.connect('postgres') as db:
            db.execute('CREATE TEMP TABLE ids AS SELECT gen_random_uuid() job,gen_random_uuid() record '
                       'FROM generate_series(1,%s)', (count,))
            db.execute('''INSERT INTO bri.xlsx_jobs(tenant_id,job_id,scope_node_id,actor_id,creator_id,auth_user_id,
                           session_id,issuer,request_key,original_sha256,byte_count,state,attempt)
                           SELECT %s,job,'team',%s,%s,%s,%s,%s,gen_random_uuid(),%s,100,'proposed',1 FROM ids''',
                       (t, actor, creator, sub, sid, csv.ISSUER, self.xlsx_original_digest))
            db.execute("INSERT INTO bri.xlsx_sources SELECT %s,job,'team',%s FROM ids", (t,creator))
            db.execute("INSERT INTO bri.xlsx_source_versions SELECT %s,job,%s,%s,'1','Synthetic',%s FROM ids", (t,self.xlsx_original_digest,digest,cell_range))
            db.execute('INSERT INTO bri.xlsx_extractions SELECT %s,job,%s,%s,1,1 FROM ids', (t,canonical,digest))
            db.execute('INSERT INTO bri.xlsx_pending_proposals(tenant_id,job_id) SELECT %s,job FROM ids', (t,))
            db.execute("INSERT INTO bri.xlsx_review_decisions(tenant_id,job_id,actor_id,request_id,decision) "
                       "SELECT %s,job,%s,gen_random_uuid(),'approve' FROM ids", (t,reader))
            db.execute('INSERT INTO bri.xlsx_validated_knowledge(tenant_id,record_id,job_id) SELECT %s,record,job FROM ids', (t,))
            db.execute("INSERT INTO bri.xlsx_publication_events(tenant_id,record_id,job_id,revision,action,actor_id) "
                       "SELECT %s,record,job,1,'publish',%s FROM ids", (t,reader))
            if allowed:
                db.execute('INSERT INTO bri.xlsx_record_access SELECT %s,record,%s FROM ids', (t,reader))
                db.execute('INSERT INTO bri.xlsx_version_access SELECT %s,record,job,%s FROM ids', (t,reader))
            return db.execute('SELECT record,job FROM ids ORDER BY record').fetchall()

    def test_xlsx_exact_canonical_value_representations_and_provenance(self):
        (record, version), = self.seed_xlsx()
        for exact, partial, cell in (
            ('7e0','7e','A3'), ('true','tru','B3'), ('2026-11-27','11-27','A4'),
            ('17:22:33','22:33','B4'), ('2026-12-01T10:41:02','12-01t10','A5'),
            ('Label','abe','B1'), ('false','als','B6'),
        ):
            for query, match in ((exact,'exact'), (partial,'substring')):
                with self.subTest(query=query):
                    [hit] = self.search(query)
                    self.assertEqual((hit['record_id'],hit['source_id'],hit['source_version_id'],hit['match']),
                                     (str(record),str(version),str(version),match))
                    self.assertEqual(hit['evidence'], {'sheet_id':'1','sheet_title':'Synthetic','cell':cell})
                    self.assertEqual((hit['extractor_version'],hit['canonicalization_version']), (1,1))
                    self.assertFalse(hit['excerpt_truncated'])
                    self.assertEqual(hit['evidence_url'], f'/v2/knowledge/xlsx/{record}/evidence/{version}')
                    self.assertEqual(hit['original_sha256'],self.xlsx_original_digest)
                    self.assertEqual(hit['canonical_sha256'],self.xlsx_fixture_digest)
        for query in ('7.0','number','boolean','datetime','null','head %'):
            self.assertEqual(self.search(query), [])

    def test_xlsx_ranking_coordinates_and_independent_allows(self):
        csv_id, _ = self.publish_csv()
        (record, version), = self.seed_xlsx()
        self.assertEqual([r['record_id'] for r in self.search('HEAD')], [str(record), str(csv_id)])
        self.assertEqual(self.search('%'), [{'format': 'xlsx', 'record_id': str(record),
                         'source_id': str(version), 'source_version_id': str(version),
                         'original_sha256': self.xlsx_original_digest, 'canonical_sha256': self.xlsx_fixture_digest,
                         'extractor_version': 1, 'canonicalization_version': 1, 'match': 'exact',
                         'excerpt': '%', 'excerpt_truncated': False,
                         'evidence': {'sheet_id': '1', 'sheet_title': 'Synthetic', 'cell': 'B2'},
                         'evidence_url': f'/v2/knowledge/xlsx/{record}/evidence/{version}'}])
        self.assertEqual(self.search('7')[0]['match'], 'substring')
        for gate in ('record', 'version'):
            with self.connect('postgres') as db:
                db.execute(f'DELETE FROM bri.xlsx_{gate}_access WHERE tenant_id=%s', (self.tenant,))
            self.assertEqual([r['record_id'] for r in self.search('HEAD')], [str(csv_id)])
            with self.connect('postgres') as db:
                fields = (self.tenant,record,self.actors[0][0]) if gate == 'record' else (self.tenant,record,version,self.actors[0][0])
                db.execute(f'INSERT INTO bri.xlsx_{gate}_access VALUES ({",".join(["%s"]*len(fields))})', fields)
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.xlsx_publication_events(tenant_id,record_id,job_id,revision,action,actor_id) "
                       "VALUES (%s,%s,%s,2,'withdraw',%s)", (self.tenant,record,version,self.actors[0][0]))
        self.assertEqual([r['record_id'] for r in self.search('HEAD')], [str(csv_id)])

    def test_global_limit_ignores_hidden_and_returns_only_top_twenty(self):
        self.publish_csv()
        visible = self.seed_xlsx(999)
        self.seed_xlsx(1001, allowed=False)
        self.assertEqual([r['record_id'] for r in self.search('head')], [str(v[0]) for v in visible[:20]])
        self.seed_xlsx()
        with self.assertRaises(psycopg.errors.ProgramLimitExceeded):
            self.search('does not match')

    def test_resource_guard_and_reader_acl(self):
        args = (self.tenant,*self.actors[0],csv.ISSUER,'team','head')
        with self.connect(ROLE) as db:
            rows = db.execute('''SELECT p.proname FROM pg_proc p WHERE p.pronamespace='bri'::regnamespace
                                 AND has_function_privilege(p.oid,'EXECUTE') ORDER BY 1''').fetchall()
            self.assertEqual(rows, [('unified_csv_evidence',), ('unified_knowledge_search',)])
            self.assertEqual(db.execute('''SELECT count(*) FROM pg_class c WHERE c.relnamespace='bri'::regnamespace
                AND c.relkind IN ('r','v','p','m','f')
                AND has_table_privilege(c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')''').fetchone(), (0,))
            self.assertEqual(db.execute('''SELECT count(*) FROM pg_auth_members
                                           WHERE roleid=current_user::regrole OR member=current_user::regrole''').fetchone(), (0,))
            for sql, error in [('SET LOCAL temp_file_limit=-1', psycopg.errors.InsufficientPrivilege),
                               ('SELECT bri.unified_knowledge_search(%s,%s,%s,%s,%s,%s,%s)',
                                psycopg.errors.ObjectNotInPrerequisiteState)]:
                with self.assertRaises(error), db.transaction():
                    db.execute(sql, args if 'SELECT' in sql else ())
        self.assertEqual(self.search('head'), [])

    def test_forced_rls_policies_are_select_only_for_the_existing_owner(self):
        with self.connect(ROLE) as db:
            rows = db.execute('''SELECT p.tablename,p.roles,p.cmd,p.qual,c.relrowsecurity,c.relforcerowsecurity
                FROM pg_policies p JOIN pg_class c ON c.relnamespace=p.schemaname::regnamespace
                    AND c.relname=p.tablename
                WHERE p.schemaname='bri' AND p.policyname LIKE 'unified_%' ORDER BY p.tablename''').fetchall()
            self.assertEqual([r[0] for r in rows], ['knowledge_record_access', 'knowledge_version_access', 'provider_event_source'])
            for _, roles, action, predicate, enabled, forced in rows:
                self.assertEqual((roles,action,enabled,forced), (['bri_migrator'],'SELECT',True,True))
                self.assertIn('SESSION_USER',predicate)
                self.assertIn(ROLE,predicate)
                self.assertIn('inet_server_addr() IS NULL',predicate)
                self.assertIn('listen_addresses',predicate)

    def test_prearmed_timeout_cancels_instead_of_returning_partial_results(self):
        self.publish_csv()
        self.seed_xlsx()
        with self.connect('postgres') as blocker, self.connect(ROLE) as db:
            blocker.execute('LOCK TABLE bri.xlsx_jobs IN ACCESS EXCLUSIVE MODE')
            db.execute("SET LOCAL statement_timeout='100ms'")
            with self.assertRaises(psycopg.errors.QueryCanceled), db.transaction():
                db.execute('SELECT bri.unified_knowledge_search(%s,%s,%s,%s,%s,%s,%s)',
                           (self.tenant,*self.actors[0],csv.ISSUER,'team','head'))
        self.assertEqual(len(self.search('head')), 2)

    def test_statement_snapshot_across_atomic_visibility_swap(self):
        from concurrent.futures import ThreadPoolExecutor

        self.publish_csv()
        (record, version), = self.seed_xlsx(allowed=False)
        signature = 'bri.fixture_wait_search(text,uuid,uuid,uuid,text,text,text)'
        with self.connect('postgres') as db:
            db.execute(f'''CREATE FUNCTION bri.fixture_wait_search(t text, actor uuid, sub uuid, sid uuid, issuer text,
                        node text, query text) RETURNS jsonb LANGUAGE plpgsql STABLE AS $$ BEGIN
                          PERFORM pg_advisory_xact_lock(180035);
                          RETURN bri.unified_knowledge_search(t,actor,sub,sid,issuer,node,query);
                        END $$;
                        REVOKE ALL ON FUNCTION {signature} FROM PUBLIC;
                        GRANT EXECUTE ON FUNCTION {signature} TO {ROLE}''')
        try:
            with ThreadPoolExecutor() as pool, self.connect('postgres') as writer, self.connect(ROLE) as reader:
                writer.execute("SET LOCAL session_replication_role='replica'")
                writer.execute('SELECT pg_advisory_xact_lock(180035)')
                reader.execute("SET LOCAL statement_timeout='5s'")
                params = (self.tenant,*self.actors[0],csv.ISSUER,'team','head')
                read = pool.submit(reader.execute, 'SELECT bri.fixture_wait_search(%s,%s,%s,%s,%s,%s,%s)', params)
                deadline = time.monotonic()+2
                while time.monotonic() < deadline:
                    if writer.execute('SELECT pg_blocking_pids(%s)', (reader.info.backend_pid,)).fetchone()[0]:
                        break
                    time.sleep(0.01)
                else:
                    self.fail('read never blocked after establishing its statement snapshot')
                writer.execute('DELETE FROM bri.knowledge_record_access WHERE tenant_id=%s', (self.tenant,))
                writer.execute('INSERT INTO bri.xlsx_record_access VALUES (%s,%s,%s)', (self.tenant,record,self.actors[0][0]))
                writer.execute('INSERT INTO bri.xlsx_version_access VALUES (%s,%s,%s,%s)',
                               (self.tenant,record,version,self.actors[0][0]))
                writer.commit()
                self.assertEqual([item['format'] for item in read.result().fetchone()[0]['results']], ['csv'])
                self.assertEqual([item['format'] for item in self.search('head')], ['xlsx'])
        finally:
            with self.connect('postgres') as db:
                db.execute(f'DROP FUNCTION {signature}')
