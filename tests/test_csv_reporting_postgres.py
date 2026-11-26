"""Protected reporting SQL, using only a disposable PostgreSQL 16 Unix socket."""
import os
import unittest
from contextlib import ExitStack, contextmanager
from hashlib import sha256
from unittest.mock import patch
from uuid import UUID, uuid4

import psycopg
import test_csv_intake_postgres as csv

ROUTINE = 'bri.csv_read_reporting(text,uuid,uuid,uuid,text,text)'


@unittest.skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16')
class CsvReportingPostgresTests(unittest.TestCase):
    tenant: str
    foreign: str
    actors: list[tuple[UUID, UUID, UUID]]
    setUp_intake = csv.CsvIntakePostgresTests.setUp
    connect = csv.CsvIntakePostgresTests.__dict__['connect']
    intake = csv.CsvIntakePostgresTests.intake
    submit = csv.CsvIntakePostgresTests.submit
    worker = csv.CsvIntakePostgresTests.worker
    complete = csv.CsvIntakePostgresTests.complete

    @classmethod
    def setUpClass(cls):
        with patch.dict(os.environ, BRI_APPROVAL_PG_BIN=os.environ['BRI_TEST_PG_BIN']):
            csv.fixtures.ApprovalDatabase.setUpClass.__func__(cls, temp_file_limit_kb=16384)
        with cls.connect('bri_migrator') as db:
            db.execute('INSERT INTO bri.provider_event_source (issuer) VALUES (%s)', (csv.ISSUER,))
        with cls.connect('postgres') as db:
            for role, routines in (('bri_csv_intake', csv.INTAKE), ('bri_csv_worker', csv.WORKER),
                                   ('bri_csv_reader', ())):
                db.execute(f'CREATE ROLE {role} LOGIN NOINHERIT; GRANT USAGE ON SCHEMA bri TO {role}')
                if routines:
                    db.execute(f'GRANT EXECUTE ON FUNCTION {", ".join(routines)} TO {role}')
        with cls.connect('bri_migrator') as db:
            db.execute(f'GRANT EXECUTE ON FUNCTION {ROUTINE} TO bri_csv_reader')

    def setUp(self):
        self.setUp_intake()
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.role_permissions VALUES (%s,'csv','knowledge:read')", (self.tenant,))
            for i, actor in enumerate(self.actors):
                self.actors[i] = (*actor[:2], uuid4())
                db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                           'VALUES (%s,%s,%s,clock_timestamp())', self.actors[i])

    def call(self, db, *, node='team', identity=None, tenant=None, issuer=csv.ISSUER):
        return db.execute('SELECT * FROM bri.csv_read_reporting(%s,%s,%s,%s,%s,%s)',
                          (tenant or self.tenant, *(identity or self.actors[0]), issuer, node))

    def read(self, **kwargs):
        with self.connect('bri_csv_reader') as db:
            db.execute('SET TRANSACTION READ ONLY')
            db.execute("SET LOCAL statement_timeout = '5s'")
            result = self.call(db, **kwargs)
            self.assertEqual(tuple(col.name for col in result.description),
                             ('proposal_id', 'source_version_id', 'original_sha256', 'content_sha256',
                              'first_line', 'last_line'))
            return result.fetchall()

    def publish(self, *, node='team'):
        job, _, _ = self.submit(node=node)
        self.assertEqual(self.intake('csv_mark_ready', job), ('ready',))
        self.assertIsNotNone(self.worker('csv_claim', job))
        self.assertEqual(self.complete(job), ('proposed',))
        ref = f'csv:{job}'
        self.assertEqual(self.intake('csv_review', ref, 'approved', identity=self.actors[0]), ('approved',))
        with self.connect('bri_migrator') as db:
            db.execute("SELECT set_config('bri.tenant_id',%s,true)", (self.tenant,))
            db.execute('INSERT INTO bri.knowledge_record_access VALUES (%s,%s,true)', (self.tenant, ref))
            db.execute('INSERT INTO bri.knowledge_version_access VALUES (%s,%s,%s,true)', (self.tenant, ref, ref))
        return ref

    def test_authorized_empty_and_compact_provenance(self):
        self.assertEqual(self.read(), [])
        ref = self.publish()
        self.assertEqual(self.read(), [(ref, ref, csv.ORIGINAL,
                                        sha256(b'safe derived fixture text').hexdigest(), 2, 4)])

    def test_parent_and_child_publications_are_exact_node_only(self):
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.org_nodes VALUES (%s,'child','team','Child','team')", (self.tenant,))
            for i in (0, 2):
                db.execute("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) "
                           "VALUES (%s,%s,'csv','child')", (self.tenant, self.actors[i][0]))
                self.actors[i] = (*self.actors[i][:2], uuid4())
                db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                           'VALUES (%s,%s,%s,clock_timestamp())', self.actors[i])
        parent = self.publish()
        self.assertEqual(self.read(node='child'), [])
        child = self.publish(node='child')
        self.assertEqual([row[0] for row in self.read()], [parent])
        self.assertEqual([row[0] for row in self.read(node='child')], [child])

    def test_deny_exact_scope_tenant_identity_issuer_and_revoked_session(self):
        self.publish()
        self.assertEqual(len(self.read()), 1)
        for kwargs in ({'node': 'root'}, {'node': None}, {'tenant': self.foreign},
                       {'identity': (*self.actors[0][:2], uuid4())}, {'issuer': 'unknown'}):
            with self.subTest(**kwargs), self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self.read(**kwargs)
        with self.connect('postgres') as db:
            db.execute('UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() WHERE session_id=%s',
                       (self.actors[0][2],))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.read()

    def test_both_gates_and_missing_evidence(self):
        ref = self.publish()
        for table in ('knowledge_record_access', 'knowledge_version_access'):
            with self.connect('bri_migrator') as db:
                db.execute("SELECT set_config('bri.tenant_id',%s,true)", (self.tenant,))
                db.execute(f'UPDATE bri.{table} SET readable=false WHERE tenant_id=%s AND source_id=%s',
                           (self.tenant, ref))
            self.assertEqual(self.read(), [])
            with self.connect('bri_migrator') as db:
                db.execute("SELECT set_config('bri.tenant_id',%s,true)", (self.tenant,))
                db.execute(f'UPDATE bri.{table} SET readable=true WHERE tenant_id=%s AND source_id=%s',
                           (self.tenant, ref))
        with self.connect('postgres') as db:
            # Corrupt only the disposable fixture to test the missing LEFT JOIN row.
            db.execute("SET LOCAL session_replication_role='replica'")
            db.execute('DELETE FROM bri.csv_source_evidence WHERE tenant_id=%s AND source_id=%s', (self.tenant, ref))
        with self.assertRaises(psycopg.errors.DataException):
            self.read()

    def test_acl_and_resource_settings(self):
        for role in ('bri_app', 'bri_csv_intake', 'bri_csv_worker', 'bri_approval_worker'):
            with self.subTest(role=role), self.connect(role) as db:
                self.assertEqual(db.execute("SELECT has_function_privilege(%s,'EXECUTE')", (ROUTINE,)).fetchone(), (False,))
                with self.assertRaises(psycopg.errors.InsufficientPrivilege) as denied, db.transaction():
                    self.call(db)
                self.assertEqual(denied.exception.diag.message_primary, 'permission denied for function csv_read_reporting')
        with self.connect('bri_csv_reader') as db:
            self.assertEqual(db.execute(
                "SELECT p.provolatile,p.prosecdef,EXISTS (SELECT FROM aclexplode(p.proacl) a "
                "WHERE a.grantee=0 AND a.privilege_type='EXECUTE') FROM pg_proc p WHERE p.oid=%s::regprocedure",
                (ROUTINE,),
            ).fetchone(), ('s', True, False))
            with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                db.execute('SET LOCAL temp_file_limit = -1')
            with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                db.execute('SELECT * FROM bri.source_extractions')
            with self.assertRaises(psycopg.errors.ObjectNotInPrerequisiteState), db.transaction():
                self.call(db)
            db.execute("SET LOCAL statement_timeout = '5s'")
            db.execute("SET LOCAL work_mem = '64MB'")
            self.assertEqual(self.call(db).fetchall(), [])
            self.assertEqual(db.execute('SHOW work_mem').fetchone(), ('64MB',))
        with self.connect('postgres') as db:
            db.execute('SET LOCAL ROLE bri_csv_reader')
            with self.assertRaises(psycopg.errors.InsufficientPrivilege) as denied:
                self.call(db)
            self.assertEqual(denied.exception.diag.message_primary, 'CSV reporting read denied')

    def test_caller_statement_timeout_bounds_wait(self):
        self.assertEqual(self.read(), [])
        with self.connect('postgres') as blocker, self.connect('bri_csv_reader') as db:
            blocker.execute('LOCK bri.csv_jobs IN ACCESS EXCLUSIVE MODE')
            db.execute("SET LOCAL statement_timeout='100ms'")
            with self.assertRaises(psycopg.errors.QueryCanceled) as canceled:
                self.call(db)
            self.assertEqual(canceled.exception.diag.message_primary, 'canceling statement due to statement timeout')

    def test_visibility_tracks_the_transaction_snapshot(self):
        ref = self.publish()
        with self.connect('bri_csv_reader') as reader:
            reader.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
            reader.execute("SET LOCAL statement_timeout='5s'")
            before = self.call(reader).fetchall()
            self.assertEqual([row[0] for row in before], [ref])
            with self.connect('bri_migrator') as writer:
                writer.execute("SELECT set_config('bri.tenant_id',%s,true)", (self.tenant,))
                writer.execute('DELETE FROM bri.knowledge_version_access WHERE tenant_id=%s AND source_id=%s',
                               (self.tenant, ref))
            self.assertEqual(self.call(reader).fetchall(), before)
        self.assertEqual(self.read(), [])

    def test_gates_apply_before_the_distinct_id_limit(self):
        with ExitStack() as stack:
            connections = {role: stack.enter_context(self.connect(role, autocommit=True))
                           for role in ('bri_csv_intake', 'bri_csv_worker', 'bri_migrator')}

            @contextmanager
            def reuse(role):
                db = connections[role]
                with db.transaction():
                    yield db

            with patch.object(self, 'connect', reuse):
                refs = sorted(self.publish() for _ in range(1002))
        with self.connect('bri_migrator') as db:
            db.execute("SELECT set_config('bri.tenant_id',%s,true)", (self.tenant,))
            db.execute('UPDATE bri.knowledge_record_access SET readable=false WHERE tenant_id=%s AND source_id=%s',
                       (self.tenant, refs[0]))
            db.execute('UPDATE bri.knowledge_version_access SET readable=false WHERE tenant_id=%s AND source_id=%s',
                       (self.tenant, refs[1]))
        self.assertEqual([row[0] for row in self.read()], refs[2:])
        with self.connect('bri_migrator') as db:
            db.execute("SELECT set_config('bri.tenant_id',%s,true)", (self.tenant,))
            db.execute('UPDATE bri.knowledge_record_access SET readable=true WHERE tenant_id=%s AND source_id=%s',
                       (self.tenant, refs[0]))
        with self.assertRaises(psycopg.errors.ProgramLimitExceeded) as overflow:
            self.read()
        self.assertEqual(overflow.exception.diag.message_primary, 'CSV reporting scope exceeds the row limit')


@unittest.skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16')
class CsvReportingExistingReaderTests(unittest.TestCase):
    connect = csv.CsvIntakePostgresTests.__dict__['connect']

    @classmethod
    def setUpClass(cls):
        def provision_reader():
            with cls.connect('postgres') as db:
                db.execute('CREATE ROLE bri_csv_reader LOGIN NOINHERIT; GRANT USAGE ON SCHEMA bri TO bri_csv_reader')

        with patch.dict(os.environ, BRI_APPROVAL_PG_BIN=os.environ['BRI_TEST_PG_BIN']):
            csv.fixtures.ApprovalDatabase.setUpClass.__func__(cls, before_csv_migration=provision_reader)

    def test_existing_reader_receives_only_protected_execute_and_refuses_unlimited_spill(self):
        with self.connect('bri_csv_reader') as db:
            self.assertEqual(db.execute('SELECT has_function_privilege(%s,\'EXECUTE\'), '
                                        'has_function_privilege(%s,\'EXECUTE\')',
                                        (ROUTINE, csv.READER[0])).fetchone(), (True, False))
            self.assertEqual(db.execute('SHOW temp_file_limit').fetchone(), ('-1',))
            db.execute("SET LOCAL statement_timeout='5s'")
            with self.assertRaises(psycopg.errors.ObjectNotInPrerequisiteState):
                db.execute('SELECT * FROM bri.csv_read_reporting(NULL,NULL,NULL,NULL,NULL,NULL)')
