"""Staged XLSX HTTP and SQL contract checks with synthetic identity and bytes.

Run the signed client against the real loopback listener from the repo root:

    BRI_TEST_PG_BIN=/absolute/path/to/postgresql-16/bin PYTHONPATH=src:tests \
      .venv/bin/python -B -m unittest -v test_xlsx_intake_api.StagedXlsxLoopbackTests

The client signs a short-lived fixture JWT via ``make_token`` using the seeded
native user's subject and active session UUID. It sends the token as a Bearer
credential and POSTs raw XLSX bytes to /v1/intake/xlsx with XLSX Content-Type,
X-Node-ID and a UUID Idempotency-Key. Authenticated GET on the returned job
shows ready, then proposed after explicit worker dispatch. Only the upstream
provider transport is mocked; it checks the fixture signature. No hosted
endpoint or real provider credential is used.
"""
import os
from contextlib import contextmanager
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase, skipUnless
from unittest.mock import patch
from uuid import UUID, uuid4

import httpx
import psycopg
from openpyxl import Workbook
from fastapi.testclient import TestClient
from test_authentication import ISSUER, SESSION_ID, USER_ID, auth_server_response, make_token

from bri.access.policy import AccessGrant, Principal
from bri.api.database import Database


class StagedXlsxTests(TestCase):
    path = '/v1/intake/xlsx'

    def setUp(self):
        self.socket = Path(self.enterContext(TemporaryDirectory()))
        self.actor, self.job, self.key, self.artifact = (uuid4() for _ in range(4))
        self.events = []
        self.state = 'creating'
        self.token = make_token()
        self.headers = {'Authorization': f'Bearer {self.token}', 'X-Node-ID': 'fixture-node',
                        'Idempotency-Key': str(self.key), 'Content-Type':
                        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'}
        self.person = Principal(str(self.actor), frozenset({'fixture-tenant'}), (
            AccessGrant('fixture-tenant', 'source:submit', 'fixture-node'),
        ), (('fixture-tenant', 'user'),))
        self.fail_commit = self.fail_install = False
        self.status_row = self.claim_row = None
        self.completion = 'proposed'
        self.failure = 'ready'
        self.role_valid = True
        self.provider_calls = []
        self.resolve = self.enterContext(patch.object(Database, 'resolve_authenticated_principal',
                                                      side_effect=lambda *_: self.person))
        self.active = self.enterContext(patch.object(Database, 'auth_session_is_active', return_value=True))

    def provider(self, req):
        self.provider_calls.append(req.url.path)
        return auth_server_response(req, user_id=USER_ID)

    def start(self):
        from bri.api.xlsx_intake import create_staged_xlsx_intake_app

        self.app = create_staged_xlsx_intake_app(
            identity_scope=lambda: self.scope('bri_app'), submitter_scope=lambda: self.scope('bri_xlsx_submitter'),
            worker_scope=lambda: self.scope('bri_xlsx_worker'), private_socket=self.socket,
            auth_transport=httpx.MockTransport(self.provider),
            store=self,
        )
        return self.enterContext(TestClient(self.app, base_url='http://127.0.0.1', client=('127.0.0.1', 50000)))

    @contextmanager
    def scope(self, role):
        yield SimpleNamespace(info=SimpleNamespace(host=str(self.socket), port=5432, dbname='postgres', user=role,
                                                   transaction_status=psycopg.pq.TransactionStatus.IDLE),
                              transaction=lambda: self.transaction(role),
                              execute=lambda query, args=(): self.execute(role, query, args))

    @contextmanager
    def transaction(self, role):
        yield
        if self.fail_commit:
            raise psycopg.OperationalError('private-marker')
        self.events.append(('commit', role))

    def execute(self, role, sql, args):
        self.events.append((role, sql, args))
        row = (self.role_valid,)
        if 'bri.xlsx_submit(' in sql:
            row = (dict(job_id=str(self.job), state=self.state, artifact_key=str(self.artifact), reason='private-marker'),)
        if 'bri.xlsx_mark_ready(' in sql:
            self.state = 'ready'
            row = (dict(job_id=str(self.job), state='ready'),)
        if 'bri.xlsx_status(' in sql:
            if isinstance(self.status_row, Exception):
                raise self.status_row
            row = (self.status_row,)
        if 'bri.xlsx_claim(' in sql:
            row = (self.claim_row,)
        if 'bri.xlsx_complete(' in sql:
            row = (self.completion,)
        if 'bri.xlsx_fail(' in sql:
            row = (self.failure,)
        return SimpleNamespace(fetchone=lambda: row)

    def install(self, tenant, job, key, body):
        self.assertEqual(self.events[-1], ('commit', 'bri_xlsx_submitter'))
        if self.fail_install:
            raise OSError('private-marker')
        self.events.append(('install', tenant, job, key, body))

    def read_verified(self, tenant, job, key, digest, count):
        self.fail('HTTP handlers must not read artifacts')

    def test_reservation_commits_before_install_and_ready(self):
        client = self.start()
        response = client.post(self.path, headers=self.headers, content=b'fixture-workbook')
        self.assertEqual(response.status_code, 202, response.text)
        self.assertEqual(response.json(), {'id': str(self.job), 'state': 'ready'})
        self.assertEqual(response.headers['Cache-Control'], 'private, no-store')
        self.assertEqual(self.resolve.call_args.args, (USER_ID, ISSUER, USER_ID))
        submit = next(e for e in self.events if e[0] == 'bri_xlsx_submitter' and 'bri.xlsx_submit(' in e[1])
        auth = ('fixture-tenant', self.actor, UUID(USER_ID), UUID(SESSION_ID), ISSUER)
        cid = UUID(response.headers['X-Request-ID'])
        i = self.events.index(submit)
        self.assertEqual(self.events[i - 3][1], 'SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ WRITE')
        self.assertEqual(self.events[i - 1][2], ('fixture-tenant', USER_ID))
        self.assertEqual(submit[2], (*auth, 'fixture-node', self.key, len(b'fixture-workbook'),
                                    sha256(b'fixture-workbook').hexdigest(), cid))
        install = ('install', 'fixture-tenant', self.job, str(self.artifact), b'fixture-workbook')
        ready = next(e for e in self.events if e[0] == 'bri_xlsx_submitter' and 'bri.xlsx_mark_ready(' in e[1])
        self.assertEqual(ready[2], (*auth, self.job, cid))
        self.assertLess(self.events.index(install), self.events.index(ready))
        self.assertEqual(client.post(self.path, headers=self.headers, content=b'fixture-workbook').json(), response.json())
        self.assertEqual(self.events.count(install), 1)

    def test_status_hides_denial_and_private_metadata(self):
        client = self.start()
        url = f'{self.path}/{self.job}'
        auth = {'Authorization': self.headers['Authorization']}
        for receipt in (None, {'job_id': None, 'reason': 'private-marker'},
                        psycopg.errors.InsufficientPrivilege('private-marker')):
            self.status_row = receipt
            response = client.get(url, headers=auth)
            self.assertEqual((response.status_code, response.json()), (404, {'detail': 'XLSX job not found'}))
        self.status_row = {'job_id': str(self.job), 'state': 'failed', 'artifact_key': 'private-marker'}
        found = client.get(url, headers=auth)
        self.assertEqual(found.json(), {'id': str(self.job), 'state': 'failed'})
        self.assertEqual(found.headers['Cache-Control'], 'private, no-store')
        self.assertIn(('bri_xlsx_submitter', 'SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY', ()),
                      self.events)

    def test_commit_and_install_failures_do_not_mark_ready(self):
        client = self.start()
        for self.fail_commit, self.fail_install in ((True, False), (False, True)):
            response = client.post(self.path, headers=self.headers, content=b'workbook')
            self.assertEqual(response.status_code, 503)
            self.assertNotIn('private-marker', response.text)
            self.assertFalse(any(e[0] == 'install' or 'bri.xlsx_mark_ready(' in e[1] for e in self.events))
        self.fail_install = False
        self.assertEqual(client.post(self.path, headers=self.headers, content=b'workbook').status_code, 202)

    def test_body_limit_with_chunked_upload(self):
        client = self.start()
        for overflow in (True, False):
            response = client.post(self.path, headers=self.headers,
                                   content=iter([b'a' * 2_500_000, b'b' * 2_500_000, b'c' if overflow else b'']))
            self.assertEqual(response.status_code, 413 if overflow else 202, response.text)
            if overflow:
                self.assertEqual(self.events, [])

    def test_rejects_ambiguous_headers_and_aliases_before_auth(self):
        client = self.start()
        for path, extra, expected in (
            (self.path + '?tenant=private-marker', [], 400),
            ('/v1/intake/%78lsx', [], 404),
            (self.path, [('X-Tenant-ID', 'private-marker')], 400),
            (self.path, [('Forwarded', 'for=127.0.0.1')], 403),
            (self.path, [('Content-Disposition', 'attachment; filename="private-marker"')], 400),
            (self.path, [('Content-Encoding', 'gzip')], 415),
            (self.path, [('Idempotency-Key', str(uuid4()))], 422),
            (self.path, [('Content-Type', self.headers['Content-Type'])], 415),
        ):
            response = client.post(path, headers=[*self.headers.items(), *extra], content=b'workbook')
            self.assertEqual(response.status_code, expected, response.text)
            self.assertEqual(response.headers['Cache-Control'], 'private, no-store')
        self.assertEqual(self.provider_calls, [])
        self.assertEqual(self.events, [])

    def test_lost_private_socket_permissions_prevent_submit_before_sql(self):
        client = self.start()
        self.socket.chmod(0o755)
        self.assertEqual(client.post(self.path, headers=self.headers, content=b'workbook').status_code, 503)
        self.assertEqual(self.events, [])

    def test_requires_current_node_grant_and_native_session(self):
        client = self.start()
        denied = client.post(self.path, headers={**self.headers, 'X-Node-ID': 'other'}, content=b'workbook')
        self.assertEqual(denied.status_code, 403)
        self.active.return_value = False
        self.assertEqual(client.post(self.path, headers=self.headers, content=b'workbook').status_code, 403)
        self.assertEqual(self.events, [])
        self.active.return_value = True
        self.role_valid = False
        self.assertEqual(client.post(self.path, headers=self.headers, content=b'workbook').status_code, 503)
        self.assertFalse(any('bri.xlsx_submit(' in e[1] for e in self.events))

    def test_worker_sql_adapter_is_fenced_and_not_http(self):
        client = self.start()
        self.assertEqual(client.post(f'{self.path}/{self.job}/process', headers=self.headers).status_code, 404)
        self.assertEqual(self.provider_calls, [])
        repo = self.app.state.xlsx_worker_repository
        cid = uuid4()
        self.assertIsNone(repo.claim(self.job, cid))
        self.claim_row = {'job_id': str(self.job), 'tenant_id': 'fixture-tenant', 'artifact_key': str(self.artifact),
                          'original_sha256': 'a' * 64, 'byte_count': 12, 'attempt': 2}
        claim = repo.claim(self.job, cid)
        self.assertEqual((claim.job_id, claim.tenant_id, claim.artifact_key, claim.byte_count,
                          claim.original_sha256, claim.attempt),
                         (self.job, 'fixture-tenant', str(self.artifact), 12, 'a' * 64, 2))
        args = (self.job, 2, 'fixture-text', 'b' * 64, 1, 1, '1', 'Sheet', 'A1:A2', cid)
        self.assertIsNone(repo.complete(*args))
        self.assertIsNone(repo.fail(self.job, 2, 'infrastructure_unavailable', cid))
        from bri.api.database import DatabaseUnavailable

        self.completion = self.failure = 'stale'
        with self.assertRaises(DatabaseUnavailable):
            repo.complete(*args)
        with self.assertRaises(DatabaseUnavailable):
            repo.fail(self.job, 2, 'infrastructure_unavailable', cid)
        self.claim_row['job_id'] = str(uuid4())
        with self.assertRaises(DatabaseUnavailable):
            repo.claim(self.job, cid)
        self.assertTrue(any(e[0] == 'bri_xlsx_worker' and len(e) == 3 and e[2] == args for e in self.events))

    def test_hosted_release_mounts_neither_xlsx_route(self):
        from bri.api.app import ApiSettings, create_app

        with TestClient(create_app(settings=ApiSettings(environment='hosted-development', auth_mode='supabase'),
                                  token_verifier=object())) as client:
            self.assertEqual(client.post(self.path, headers=self.headers, content=b'private-marker').status_code, 404)
            self.assertEqual(client.get(f'{self.path}/{self.job}').status_code, 404)


@skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16')
class StagedXlsxLoopbackTests(TestCase):
    tenant: str
    creator: UUID
    identity: tuple[UUID, UUID, UUID]
    sock: Path

    @classmethod
    def setUpClass(cls):
        import test_xlsx_intake_postgres as pg

        cls.fixture = pg.XlsxIntakePostgresTests
        cls.connect = classmethod(pg.XlsxIntakePostgresTests.connect.__func__)
        cls.fixture.setUpClass.__func__(cls)

    def _loopback(self, app):
        # Reuse the ephemeral-port Uvicorn harness from the signed A13 tests.
        from test_csv_intake_api import StagedCsvPostgres

        return self.enterContext(StagedCsvPostgres().loopback_reader(app))

    def test_signed_xlsx_proposal_does_not_change_a13_a15_or_publication_tables(self):
        from bri.api import csv_intake as csv
        from bri.ingestion.csv_intake import LocalCsvQuarantine, ProcessOutcome
        from scripts.a15_consumer import PATH as REPORT
        from test_csv_intake_postgres import INTAKE, READER, WORKER
        from test_csv_reporting_postgres import ROUTINE

        def bearer(identity):
            _, user, sid = identity
            token = f'Bearer {make_token(sub=str(user), session_id=str(sid))}'
            users[token] = str(user)
            return {'Authorization': token}

        def provider(req):
            user = users.get(req.headers.get('Authorization'))
            return auth_server_response(req, user_id=user or '', status=200 if user else 401)

        def protected_rows():
            with self.connect('postgres') as db:
                return {table: db.execute(
                    f'SELECT to_jsonb(t) FROM bri.{table} t WHERE tenant_id=%s ORDER BY to_jsonb(t)',
                    (self.tenant,),
                ).fetchall() for table in (
                    'source_records', 'source_versions', 'source_extractions', 'knowledge_proposals',
                    'validation_decisions', 'validated_knowledge', 'knowledge_record_access',
                    'knowledge_version_access', 'auth_role_assignments', 'role_permissions',
                )}

        users = {}
        transport = httpx.MockTransport(provider)
        self.fixture.setUp(self)
        with self.connect('postgres') as db:
            reviewer = db.execute(
                "SELECT m.principal_id,l.auth_user_id FROM bri.auth_tenant_memberships m "
                "JOIN bri.auth_identity_links l USING (principal_id) "
                "WHERE m.tenant_id=%s AND m.membership_type='admin' AND m.principal_id<>%s",
                (self.tenant, self.creator),
            ).fetchone()
            self.assertIsNotNone(reviewer)
            reader = (*reviewer, uuid4())
            for role, routines in (('bri_csv_intake', INTAKE), ('bri_csv_worker', WORKER),
                                   ('bri_csv_reader', (*READER, ROUTINE))):
                db.execute(f'CREATE ROLE {role} LOGIN NOINHERIT; GRANT USAGE ON SCHEMA bri TO {role}')
                db.execute(f'GRANT EXECUTE ON FUNCTION {", ".join(routines)} TO {role}')
            db.execute('ALTER ROLE bri_csv_reader SET temp_file_limit = 16384')
            db.execute("INSERT INTO bri.app_roles VALUES (%s,'parity-reader','Parity reader')", (self.tenant,))
            db.execute("INSERT INTO bri.role_permissions VALUES (%s,'parity-reader','knowledge:read'),"
                       "(%s,'parity-reader','knowledge:review')", (self.tenant, self.tenant))
            db.execute("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) "
                       "VALUES (%s,%s,'parity-reader','team')", (self.tenant, reader[0]))
            db.execute('INSERT INTO bri.csv_worker_creators VALUES (%s,%s)', (self.tenant, self.creator))
            db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                       'VALUES (%s,%s,%s,clock_timestamp())', reader)

        def scope(role):
            return lambda: self.connect(role)

        identity_scope = scope('bri_app')
        submitter_auth, reader_auth = bearer(self.identity), bearer(reader)
        intake = csv.create_staged_csv_intake_app(
            identity_scope=identity_scope, private_socket=self.sock, auth_transport=transport,
            intake_scope=scope('bri_csv_intake'), worker_scope=scope('bri_csv_worker'),
            store=LocalCsvQuarantine(Path(self.enterContext(TemporaryDirectory()))),
        )
        csv_http = self._loopback(intake)
        answer = 'Employee files must be retained for seven years.'
        other_answer = 'Employee files must be retained for ten years.'
        original = f'Policy,Evidence\r\nRecords,"Administrative note.\r\n{answer}"\r\n'.encode()
        upload_headers = {'X-Node-ID': 'team', 'Idempotency-Key': str(uuid4())}
        reply = csv_http.post(csv.PREFIX, headers={**submitter_auth, **upload_headers,
                                                  'Content-Type': 'text/csv'}, content=original)
        self.assertEqual(reply.status_code, 202, reply.text)
        csv_job = UUID(reply.json()['id'])
        self.assertIs(intake.state.csv_worker.dispatch(csv_job), ProcessOutcome.COMPLETED)
        ref = f'csv:{csv_job}'
        reply = csv_http.post(f'{csv.REVIEW_PREFIX}/{ref}/decision', headers=reader_auth,
                              json={'decision': 'approved'})
        self.assertEqual(reply.status_code, 200, reply.text)
        with self.connect('bri_migrator') as db:
            db.execute("SELECT set_config('bri.tenant_id',%s,true)", (self.tenant,))
            db.execute('INSERT INTO bri.knowledge_record_access VALUES (%s,%s,true)', (self.tenant, ref))
            db.execute('INSERT INTO bri.knowledge_version_access VALUES (%s,%s,%s,true)', (self.tenant, ref, ref))

        read_http = self._loopback(csv.create_staged_csv_reader_app(
            identity_scope=identity_scope, private_socket=self.sock, auth_transport=transport,
            reader_scope=scope('bri_csv_reader'),
        ))
        paths = {
            'list': ('/v1/knowledge', {}),
            'search': ('/v1/knowledge/search', {'q': 'How many years must employee files be retained?'}),
            'record': (f'/v1/knowledge/{ref}', {}),
            'source': (f'/v1/sources/{ref}', {}),
            'report': (REPORT, {'scope_node_id': 'team'}),
        }

        def read_results():
            results = {}
            for key, (path, params) in paths.items():
                reply = read_http.get(path, params=params, headers=reader_auth)
                self.assertEqual(reply.status_code, 200, (key, reply.text))
                results[key] = reply.json()
            for key in ('list', 'report'):
                path, params = paths[key]
                self.assertEqual(read_http.get(path, params=params, headers=submitter_auth).status_code, 403)
            return results

        before = read_results()
        self.assertEqual([row['record_id'] for row in before['list']], [ref])
        self.assertEqual(before['search']['status'], 'supported')
        self.assertEqual(before['search']['answer'], answer)
        self.assertEqual([citation['record_id'] for citation in before['search']['citations']], [ref])
        report = before['report']['result']
        self.assertEqual(report['metric_id'], 'published_knowledge_inventory')
        self.assertEqual((report['metric_version'], report['status'], report['count']), (1, 'complete', 1))
        self.assertEqual([row['record_id'] for row in report['evidence']], [ref])
        tables_before = protected_rows()
        for table in ('validation_decisions', 'validated_knowledge', 'knowledge_record_access',
                      'knowledge_version_access'):
            self.assertEqual(len(tables_before[table]), 1)

        self._complete_workbook(transport, submitter_auth, ['Records', other_answer])
        self.assertEqual(read_results(), before)
        self.assertEqual(protected_rows(), tables_before)

    def _complete_workbook(self, transport, auth, row):
        from bri.api.xlsx_intake import PREFIX, create_staged_xlsx_intake_app
        from bri.ingestion.xlsx_intake import LocalXlsxQuarantine

        workbook = Workbook()
        workbook.worksheets[0].append(['Policy', 'Evidence'])
        workbook.worksheets[0].append(row)
        raw = BytesIO()
        workbook.save(raw)
        workbook.close()
        payload = raw.getvalue()
        store = LocalXlsxQuarantine(self.enterContext(TemporaryDirectory()))
        app = create_staged_xlsx_intake_app(
            identity_scope=lambda: self.connect('bri_app'), private_socket=self.sock, auth_transport=transport,
            submitter_scope=lambda: self.connect('bri_xlsx_submitter'),
            worker_scope=lambda: self.connect('bri_xlsx_worker'),
            store=store,
        )
        client = self._loopback(app)
        media = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        headers = {**auth, 'Content-Type': media, 'X-Node-ID': 'team', 'Idempotency-Key': str(uuid4())}
        submitted = client.post(PREFIX, headers=headers, content=iter((payload[:20], payload[20:])))
        self.assertEqual(submitted.status_code, 202, submitted.text)
        job = UUID(submitted.json()['id'])
        url = f'{PREFIX}/{job}'
        self.assertEqual(client.get(url, headers=auth).json(), {'id': str(job), 'state': 'ready'})
        self.assertEqual(client.post('/v1/intake/%78lsx', headers=headers, content=payload).status_code, 404)
        self.assertEqual(app.state.xlsx_worker.dispatch(job, uuid4()), 'completed')
        self.assertEqual(client.get(url, headers=auth).json(), {'id': str(job), 'state': 'proposed'})
        with self.connect('postgres') as db:
            for suffix in ('sources', 'source_versions', 'extractions', 'pending_proposals'):
                lineage = db.execute(f'SELECT job_id FROM bri.xlsx_{suffix} WHERE tenant_id=%s',
                                     (self.tenant,)).fetchall()
                self.assertEqual(lineage, [(job,)], suffix)
            self.assertEqual(db.execute('SELECT original_sha256 FROM bri.xlsx_source_versions WHERE tenant_id=%s',
                                        (self.tenant,)).fetchone(), (sha256(payload).hexdigest(),))
