"""Local XLSX governance API boundaries with signed fixture identities."""
import os
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase, skipUnless
from unittest.mock import patch
from uuid import UUID, uuid4

import httpx
import psycopg
import test_xlsx_governance_postgres as pg
from fastapi.testclient import TestClient
from test_authentication import ISSUER, SESSION_ID, USER_ID, auth_server_response, make_token

from bri.access.policy import AccessGrant, Principal
from bri.api.database import Database


class GovernanceTests(TestCase):
    prefix = '/v1/knowledge/proposals/xlsx'

    def start(self, *, reader=False):
        from bri.api.xlsx_governance import create_staged_xlsx_governance_app

        self.socket = Path(self.enterContext(TemporaryDirectory()))
        self.app = create_staged_xlsx_governance_app(
            identity_scope=lambda: self.scope('bri_app'), review_scope=lambda: self.scope('bri_xlsx_reviewer'),
            private_socket=self.socket, auth_transport=httpx.MockTransport(self.provider),
            **({"reader_scope": lambda: self.scope("bri_xlsx_reader")} if reader else {}),
        )
        return self.enterContext(TestClient(self.app, base_url='http://127.0.0.1', client=('127.0.0.1', 50000)))

    def setUp(self):
        self.actor, self.job = uuid4(), uuid4()
        self.headers = {'Authorization': f'Bearer {make_token()}'}
        self.events = []
        self.provider_calls = []
        self.queue_rows = []
        self.detail_row = None
        self.published_row = self.evidence_row = None
        self.decision_row = 'approve'
        self.commit_error = False
        self.tenant = 'fixture-tenant'
        self.grant = 'knowledge:review'
        self.active = self.enterContext(patch.object(Database, 'auth_session_is_active', return_value=True))
        self.resolve = self.enterContext(patch.object(Database, 'resolve_authenticated_principal',
                                                      side_effect=lambda *_: self.person()))

    def person(self):
        return Principal(str(self.actor), frozenset({self.tenant}), (
            AccessGrant(self.tenant, self.grant, 'fixture-node'),
        ), ((self.tenant, 'user'),))

    @contextmanager
    def scope(self, role):
        yield SimpleNamespace(info=SimpleNamespace(host=str(self.socket), port=5432, dbname='postgres', user=role,
                                                   transaction_status=psycopg.pq.TransactionStatus.IDLE),
                              transaction=lambda: self.transaction(role),
                              execute=lambda query, args=(): self.execute(role, query, args))

    @contextmanager
    def transaction(self, role):
        yield
        if self.commit_error:
            raise psycopg.OperationalError('private-marker')
        self.events.append(('commit', role))

    def execute(self, role, sql, args):
        self.events.append((role, sql, args))
        row = (True,)
        if 'bri.xlsx_review_queue(' in sql:
            _, _, _, _, _, after, limit = args
            row = ([item for item in self.queue_rows if after is None or UUID(item['job_id']) > after][:limit],)
        if 'bri.xlsx_review_detail(' in sql:
            if isinstance(self.detail_row, Exception):
                raise self.detail_row
            self.assertEqual(args[:6], (self.tenant, self.actor, UUID(USER_ID), UUID(SESSION_ID), ISSUER, self.job))
            self.assertEqual(len(args), 6)
            row = (self.detail_row,)
        if 'bri.xlsx_review_decide(' in sql:
            row = (self.decision_row,)
        if 'bri.xlsx_published_detail(' in sql:
            row = (self.published_row,)
        if 'bri.xlsx_published_evidence(' in sql:
            row = (self.evidence_row,)
        return SimpleNamespace(fetchone=lambda: row)

    def provider(self, request):
        self.provider_calls.append(request.url.path)
        return auth_server_response(request, user_id=USER_ID)

    def test_queue_uses_scoped_read_and_exposes_only_allowed_fields(self):
        self.queue_rows = [{'job_id': str(self.job), 'node_id': 'fixture-node', 'state': 'proposed',
                            'artifact_key': 'private-marker'}]
        client = self.start()
        result = client.get(self.prefix, headers=self.headers)
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(result.json(), {'items': [{'id': f'xlsx:{self.job}', 'node_id': 'fixture-node',
                                                    'state': 'proposed'}], 'next_cursor': None})
        self.assertEqual(self.resolve.call_args.args, (USER_ID, ISSUER, USER_ID))
        self.assertEqual(self.active.call_args.args, (USER_ID, SESSION_ID))
        scope, transaction, params = self.events[0]
        self.assertEqual((scope, transaction, params), ('bri_xlsx_reviewer',
                         'SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY', ()))
        self.assertEqual(self.events[2][2], (self.tenant, USER_ID))
        self.assertEqual(self.events[3][2], (self.tenant, self.actor, UUID(USER_ID), UUID(SESSION_ID), ISSUER, None, 21))
        self.assertEqual(self.events[-1], ('commit', 'bri_xlsx_reviewer'))
        self.events.clear()
        self.active.return_value = False
        self.assertEqual(client.get(self.prefix, headers=self.headers).status_code, 403)
        self.assertEqual(self.events, [])
        self.active.return_value = True
        self.grant = 'source:submit'
        self.assertEqual(client.get(self.prefix, headers=self.headers).status_code, 403)
        self.assertEqual(self.events, [])

    def test_queue_cursor_caps_items_and_is_bound_to_reviewer_and_page_size(self):
        jobs = sorted(uuid4() for _ in range(21))
        self.queue_rows = [dict(job_id=str(job), node_id='fixture-node', state='proposed') for job in jobs]
        client = self.start()
        data = client.get(self.prefix, headers=self.headers).json()
        self.assertEqual(len(data['items']), 20)
        cursor = data['next_cursor']
        url = f'{self.prefix}?cursor={cursor}'
        self.assertNotIn(str(jobs[19]), cursor)
        self.assertEqual(client.get(url, headers=self.headers).json()['items'][0]['id'], f'xlsx:{jobs[-1]}')
        self.events.clear()
        self.assertEqual(client.get(url + '&limit=1', headers=self.headers).status_code, 400)
        self.actor = uuid4()
        self.assertEqual(client.get(url, headers=self.headers).status_code, 400)
        self.assertEqual(self.events, [])

    def test_detail_traverses_dense_rows_without_exceeding_entire_response_budget(self):
        rows: list[list[list[str] | None]] = [[['text', f'header-{col}'] for col in range(64)]] + [[None] * 64 for _ in range(51)]
        rows[1] = [['text', '\t' * 4096] for _ in range(64)]
        rows[-1][-1] = ['text', 'last']
        self.detail_row = dict(job_id=str(self.job), node_id='fixture-node', state='proposed',
                               sheet_id='1', sheet_title='Synthetic sheet', cell_range='A1:BL52',
                               rows=rows, artifact_key='private-marker')
        client = self.start()
        url = f'{self.prefix}/xlsx:{self.job}'
        visited = {}
        path = url
        for _ in range(10):
            response = client.get(path, headers=self.headers)
            self.assertEqual(response.status_code, 200, response.text[:200])
            self.assertLessEqual(len(response.content), 524288)
            self.assertNotIn('private-marker', response.text)
            data = response.json()
            self.assertLessEqual(len({cell['row'] for cell in data['cells']}), 50)
            for cell in data['cells']:
                coord = (cell['row'], cell['column'])
                self.assertNotIn(coord, visited)
                visited[coord] = cell['value']
            if not data['next_cursor']:
                break
            cursor = data['next_cursor']
            self.assertEqual(client.get(f'{self.prefix}?cursor={cursor}', headers=self.headers).status_code, 400)
            self.assertEqual(client.get(f'{self.prefix}/xlsx:{uuid4()}?cursor={cursor}',
                                        headers=self.headers).status_code, 400)
            path = f'{url}?cursor={cursor}'
        self.assertEqual(visited, {(r, c): val for r, row in enumerate(rows, 1) for c, val in enumerate(row, 1)})

    def test_missing_and_hidden_proposals_are_indistinguishable(self):
        client = self.start()
        url = f'{self.prefix}/xlsx:{self.job}'
        for self.detail_row in (None, psycopg.errors.InsufficientPrivilege('private-marker')):
            response = client.get(url, headers=self.headers)
            self.assertEqual((response.status_code, response.json()), (404, {'detail': 'XLSX proposal not found'}))
            self.assertEqual(response.headers['cache-control'], 'private, no-store')

    def test_decision_only_acknowledges_committed_protected_sql_command(self):
        client = self.start()
        url = f'{self.prefix}/xlsx:{self.job}/decision'
        key = uuid4()
        headers = {**self.headers, 'Content-Type': 'application/json', 'Idempotency-Key': str(key)}
        for content in (b'{"decision":"approve","node_id":"forged"}',
                        b'{"decision":"approve","decision":"reject"}', b'{"decision":"publish"}'):
            self.assertEqual(client.post(url, headers=headers, content=content).status_code, 422)
        self.assertEqual(self.events, [])
        reply = client.post(url, headers=headers, json={'decision': 'approve'})
        self.assertEqual(reply.status_code, 200, reply.text)
        self.assertEqual(reply.json(), {'id': f'xlsx:{self.job}', 'decision': 'approve'})
        self.assertEqual(self.events[0][1], 'SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ WRITE')
        self.assertEqual(self.events[2][2], (self.tenant, USER_ID))
        self.assertEqual(self.events[3][2], (self.tenant, self.actor, UUID(USER_ID), UUID(SESSION_ID), ISSUER,
                                             self.job, 'approve', key, UUID(reply.headers['x-request-id'])))
        self.assertEqual(self.events[4], ('commit', 'bri_xlsx_reviewer'))
        self.commit_error = True
        reply = client.post(url, headers=headers, json={'decision': 'approve'})
        self.assertEqual(reply.status_code, 503)
        self.assertNotIn('private-marker', reply.text)

    def test_published_reads_use_reader_role_exact_versions_and_cannot_borrow_review_grant(self):
        record = uuid4()
        url = f'/v1/knowledge/xlsx/{record}'
        evidence = f'{url}/evidence/{self.job}'
        base = {'record_id': str(record), 'source_version_id': str(self.job), 'node_id': 'fixture-node'}
        self.published_row = dict(base, tenant_id='private-marker', rows=['private-marker'])
        self.evidence_row = dict(base, sheet_id='1', sheet_title='Sample', cell_range='A1',
                                 rows=[[['text', 'Header']]], artifact_key='private-marker')
        client = self.start(reader=True)
        self.assertEqual(client.get(url, headers=self.headers).status_code, 403)
        self.assertEqual(self.events, [])
        self.grant = 'knowledge:read'
        self.assertEqual(client.get(self.prefix, headers=self.headers).status_code, 403)
        self.assertEqual(self.events, [])
        for path, extra in ((url, (record,)), (evidence, (record, self.job))):
            result = client.get(path, headers=self.headers)
            self.assertEqual(result.status_code, 200, result.text)
            self.assertEqual(result.headers['cache-control'], 'private, no-store')
            self.assertNotIn('private-marker', result.text)
            self.assertEqual(self.events[0], ('bri_xlsx_reader',
                                             'SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY', ()))
            self.assertEqual(self.events[3][2], (self.tenant, self.actor, UUID(USER_ID), UUID(SESSION_ID), ISSUER, *extra))
            self.assertEqual(self.events[-1], ('commit', 'bri_xlsx_reader'))
            data = result.json()
            self.assertEqual({key: data[key] for key in base}, base)
            if path == evidence:
                self.assertEqual(data['cells'], [{'row': 1, 'column': 1, 'value': ['text', 'Header']}])
            else:
                self.assertEqual(data, base)
            self.events.clear()
        self.published_row = self.evidence_row = None
        for path in (url, evidence):
            response = client.get(path, headers=self.headers)
            self.assertEqual((response.status_code, response.json()), (404, {'detail': 'XLSX record not found'}))

    def test_published_evidence_v2_reuses_v1_rpc_without_changing_v1_body(self):
        record = uuid4()
        base = {'record_id': str(record), 'source_version_id': str(self.job), 'node_id': 'fixture-node'}
        meta = {'original_sha256': 'a' * 64, 'canonical_sha256': 'b' * 64,
                'extractor_version': 1, 'canonicalization_version': 1}
        self.evidence_row = dict(base, **meta, sheet_id='1', sheet_title='Sample', cell_range='A1',
                                 rows=[[['text', 'Header']]], artifact_key='private-marker')
        self.grant = 'knowledge:read'
        client = self.start(reader=True)
        path = f'/knowledge/xlsx/{record}/evidence/{self.job}'
        v1 = client.get('/v1' + path, headers=self.headers)
        commands = self.events.copy()
        self.events.clear()
        v2 = client.get('/v2' + path, headers=self.headers)
        self.assertEqual((v1.status_code, v2.status_code), (200, 200), v2.text)
        self.assertEqual(self.events, commands)
        self.assertEqual(v1.json(), dict(base, sheet_id='1', sheet_title='Sample', cell_range='A1',
                                         cells=[{'row': 1, 'column': 1, 'value': ['text', 'Header']}], next_cursor=None))
        self.assertEqual(v2.json(), v1.json() | meta | {'version': 2, 'source_id': str(self.job)})
        self.assertEqual(v2.headers['cache-control'], 'private, no-store')
        self.evidence_row = None
        denied = client.get('/v2' + path, headers=self.headers)
        self.assertEqual((denied.status_code, denied.json()), (404, {'detail': 'XLSX record not found'}))

    def test_unapproved_routes_and_inputs_fail_before_authentication(self):
        client = self.start()
        for method, path, headers, status in (
            ('GET', '/openapi.json', {}, 404),
            ('POST', self.prefix + '/publish', {}, 404),
            ('POST', self.prefix + '/revoke', {}, 404),
            ('GET', self.prefix + '/', {}, 404),
            ('GET', self.prefix.replace('xlsx', '%78lsx'), {}, 404),
            ('HEAD', self.prefix, {}, 404),
            ('GET', self.prefix + '?limit=21', {}, 400),
            ('GET', self.prefix + '?limit=1&limit=1', {}, 400),
            ('GET', self.prefix + '?tenant=forged', {}, 400),
            ('GET', self.prefix, {'X-Tenant-ID': 'forged'}, 400),
            ('GET', self.prefix, {'Forwarded': 'for=127.0.0.1'}, 403),
            ('GET', self.prefix, {'Expect': '100-continue'}, 400),
            ('GET', self.prefix, {'Content-Length': '1'}, 413),
            ('GET', self.prefix, {}, 401),
        ):
            with self.subTest(method=method, path=path, headers=headers):
                result = client.request(method, path, headers=headers, follow_redirects=False)
                self.assertEqual(result.status_code, status, result.text)
                self.assertEqual(result.headers['cache-control'], 'private, no-store')
        self.assertEqual(self.provider_calls, [])
        self.assertEqual(self.events, [])

    def test_release_has_no_xlsx_governance_route(self):
        from bri.api.app import ApiSettings, create_app

        app = create_app(settings=ApiSettings(environment='hosted-development', auth_mode='supabase'),
                         token_verifier=object())
        with TestClient(app) as client:
            item = uuid4()
            self.assertEqual(client.get('/v1/knowledge/proposals/xlsx').status_code, 404)
            self.assertEqual(client.post(f'/v1/knowledge/proposals/xlsx/xlsx:{item}/decision').status_code, 404)
            # The existing generic release knowledge ID route must not be used for XLSX.
            self.assertEqual(client.get(f'/v1/knowledge/xlsx/{item}').status_code, 404)
            self.assertEqual(client.get(f'/v2/knowledge/xlsx/{item}/evidence/{item}').status_code, 404)


@skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16')
class GovernanceLoopbackTests(TestCase):
    setUpClass = classmethod(pg.XlsxGovernancePostgresTests.setUpClass.__func__)
    connect = pg.XlsxGovernancePostgresTests.__dict__['connect']
    prepare = pg.XlsxGovernancePostgresTests.prepare
    provision = pg.XlsxGovernancePostgresTests.provision
    grant_authority = pg.XlsxGovernancePostgresTests.grant_authority
    call = pg.XlsxGovernancePostgresTests.call

    def test_signed_review_and_published_reads_on_real_private_listener(self):
        from bri.api.xlsx_governance import PUBLISHED_PREFIX, REVIEW_PREFIX, create_staged_xlsx_governance_app
        from test_csv_intake_api import StagedCsvPostgres

        self.prepare()
        self.grant_authority('reviewer', 'knowledge:publish')
        self.grant_authority('creator', 'knowledge:access_manage')
        self.grant_authority('uploader', 'knowledge:read')
        publisher, access, reader = 'bri_xlsx_publication_maintainer', 'bri_xlsx_access_maintainer', 'bri_xlsx_reader'
        self.provision(publisher, {'xlsx_publication_change': 'uuid,uuid,text,uuid'})
        self.provision(access, {'xlsx_record_access_change': 'uuid,uuid,boolean,uuid',
                                'xlsx_version_access_change': 'uuid,uuid,uuid,boolean,uuid'})
        self.provision(reader, {'xlsx_published_detail': 'uuid', 'xlsx_published_evidence': 'uuid,uuid'})
        tokens = {}

        def headers(name):
            _, sub, sid = self.identities[name]
            bearer = f'Bearer {make_token(sub=str(sub), session_id=str(sid))}'
            tokens[bearer] = str(sub)
            return {'Authorization': bearer}

        def provider(request):
            uid = tokens.get(request.headers.get('Authorization'))
            return auth_server_response(request, user_id=uid or '', status=200 if uid else 401)

        app = create_staged_xlsx_governance_app(
            identity_scope=lambda: self.connect('bri_app'), review_scope=lambda: self.connect(pg.REVIEWER),
            reader_scope=lambda: self.connect(reader), private_socket=self.sock,
            auth_transport=httpx.MockTransport(provider),
        )
        client = self.enterContext(StagedCsvPostgres().loopback_reader(app))
        review_headers, reader_headers = headers('reviewer'), headers('uploader')
        item_id = f'xlsx:{self.job}'
        url = f'{REVIEW_PREFIX}/{item_id}'
        queue = client.get(REVIEW_PREFIX, headers=review_headers)
        self.assertEqual(queue.status_code, 200, queue.text)
        self.assertEqual(queue.json()['items'], [{'id': item_id, 'node_id': 'team', 'state': 'proposed'}])
        detail = client.get(url, headers=review_headers)
        self.assertEqual(detail.status_code, 200, detail.text)
        self.assertEqual(detail.json()['cells'], [{'row': 1, 'column': 1, 'value': ['text', 'Header']}])
        hidden = client.get(url, headers=reader_headers)
        missing = client.get(f'{REVIEW_PREFIX}/xlsx:{uuid4()}', headers=reader_headers)
        self.assertEqual((hidden.status_code, hidden.json()), (missing.status_code, missing.json()))
        self.assertEqual(hidden.status_code, 404)
        decision_headers = {**review_headers, 'Idempotency-Key': str(uuid4())}
        for _ in range(2):
            receipt = client.post(url + '/decision', json={'decision': 'approve'}, headers=decision_headers)
            self.assertEqual(receipt.status_code, 200, receipt.text)
            self.assertEqual(receipt.json(), {'id': item_id, 'decision': 'approve'})
        with self.connect('postgres') as db:
            record = db.execute('SELECT record_id FROM bri.xlsx_validated_knowledge WHERE tenant_id=%s',
                                (self.tenant,)).fetchone()[0]
            self.assertEqual(db.execute('SELECT count(*) FROM bri.xlsx_governance_audit_events WHERE tenant_id=%s',
                                        (self.tenant,)).fetchone(), (1,))
        published = f'{PUBLISHED_PREFIX}/{record}'
        evidence = f'{published}/evidence/{self.job}'
        self.assertEqual(client.get(published, headers=reader_headers).status_code, 404)
        self.assertEqual(client.post(published, headers=review_headers).status_code, 404)
        self.call(publisher, 'xlsx_publication_change', record, self.job, 'publish', uuid4())
        target = self.identities['uploader'][0]
        self.call(access, 'xlsx_record_access_change', record, target, True, uuid4(), identity='creator')
        self.assertEqual(client.get(published, headers=reader_headers).status_code, 404)
        self.call(access, 'xlsx_version_access_change', record, self.job, target, True, uuid4(), identity='creator')
        record_reply = client.get(published, headers=reader_headers)
        self.assertEqual(record_reply.status_code, 200, record_reply.text)
        self.assertEqual(record_reply.json()['source_version_id'], str(self.job))
        evidence_reply = client.get(evidence, headers=reader_headers)
        self.assertEqual(evidence_reply.status_code, 200, evidence_reply.text)
        self.assertEqual(evidence_reply.json()['cells'], detail.json()['cells'])
        self.assertEqual(evidence_reply.headers['cache-control'], 'private, no-store')
        self.call(access, 'xlsx_version_access_change', record, self.job, target, False, uuid4(), identity='creator')
        for path in (published, evidence):
            self.assertEqual(client.get(path, headers=reader_headers).status_code, 404)
