"""HTTP contract for the isolated CSV review workspace (synthetic fixtures)."""
import os
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier
from types import SimpleNamespace
from unittest.mock import patch
from uuid import UUID, uuid4

import httpx
import psycopg
import test_csv_intake_api as intake_http
import test_csv_review_workspace_postgres as pg
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from test_authentication import ISSUER, SESSION_ID, USER_ID, auth_server_response, make_token

from bri.access.policy import AccessGrant, Principal
from bri.api.database import Database


BASE = '/v1/knowledge/proposals/csv'
ITEM = UUID('5607a17a-61be-4c19-a912-bbfe61d070e3')
ACTOR = UUID('13e3b7f7-3ddc-4f53-a7da-928b3ec700bd')
DETAIL = f'{BASE}/csv:{ITEM}'
DECISION = f'{DETAIL}/decision'
TENANT = 'fixture-tenant'


class ReviewWorkspaceTests(unittest.TestCase):
    def setUp(self):
        from bri.api.csv_review_workspace import create_staged_csv_review_app

        self.socket = Path(self.enterContext(TemporaryDirectory()))
        self.person = Principal(str(ACTOR), frozenset({TENANT}), (
            AccessGrant(TENANT, 'knowledge:review', 'team'),
        ), ((TENANT, 'admin'),))
        self.resolve = self.enterContext(patch.object(Database, 'resolve_authenticated_principal',
                                                      side_effect=lambda *_: self.person))
        self.session = self.enterContext(patch.object(Database, 'auth_session_is_active', return_value=True))
        self.sql, self.verifications = [], []
        self.results = {}
        self.commit_error = None
        self.headers = {'Authorization': f'Bearer {make_token()}'}
        self.app = create_staged_csv_review_app(
            identity_scope=lambda: self.scope('bri_app'), review_scope=lambda: self.scope('bri_csv_intake'),
            private_socket=self.socket, auth_transport=httpx.MockTransport(self.verify),
        )
        self.client = self.enterContext(TestClient(self.app, base_url='http://127.0.0.1:8114',
                                                   client=('127.0.0.1', 50400), follow_redirects=False))

    def verify(self, req):
        self.verifications.append(req.url.path)
        return auth_server_response(req, status=200 if req.headers['Authorization'] == self.headers['Authorization']
                                    else 401)

    @contextmanager
    def transaction(self):
        yield
        if self.commit_error:
            raise self.commit_error

    @contextmanager
    def scope(self, role):
        yield SimpleNamespace(
            info=SimpleNamespace(host=str(self.socket), port=5432, dbname='postgres', user=role,
                                 transaction_status=psycopg.pq.TransactionStatus.IDLE),
            transaction=self.transaction,
            execute=lambda query, args=(): self.execute(role, query, args),
        )

    def execute(self, role, query, args):
        self.sql.append((role, query, args))
        if query.startswith('SELECT bri.csv_review'):
            name = query.split('(', 1)[0].split('.')[-1]
            result = self.results[name]
            if isinstance(result, Exception):
                raise result
        else:
            result = True
        return SimpleNamespace(fetchone=lambda: (result,))

    def test_queue_uses_verified_identity_and_read_only_transaction(self):
        queue = {'items': [{'id': f'csv:{ITEM}', 'state': 'rejected', 'node_id': 'team',
                            'created_at': '2026-11-01T00:00:00+00:00'}], 'next_cursor': str(ITEM)}
        self.results['csv_review_queue'] = queue
        response = self.client.get(f'{BASE}?status=rejected&after={ITEM}&limit=1', headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), queue)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(self.resolve.call_args.args, (USER_ID, ISSUER, USER_ID))
        self.assertEqual(self.session.call_args.args, (USER_ID, SESSION_ID))
        self.assertEqual(self.sql[0][1], 'SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY')
        self.assertEqual(self.sql[-1], ('bri_csv_intake', 'SELECT bri.csv_review_queue(%s,%s,%s,%s,%s,%s,%s,%s)',
                                       (TENANT, ACTOR, UUID(USER_ID), UUID(SESSION_ID), ISSUER, 'rejected', ITEM, 1)))

    def test_failed_detail_preserves_existing_processing_reason(self):
        result = {'id': f'csv:{ITEM}', 'state': 'failed', 'node_id': 'team',
                  'created_at': '2026-11-01T00:00:00+00:00', 'provenance': None, 'evidence': None,
                  'next_evidence_offset': None, 'history': [
                      {'event': 'failed', 'occurred_at': '2026-11-01T00:01:00+00:00', 'reason': 'invalid_csv'},
                  ]}
        self.results['csv_review_detail'] = result
        response = self.client.get(f'{DETAIL}?offset=4096', headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), result)
        self.assertEqual(self.sql[0][1], 'SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY')
        self.assertEqual(self.sql[-1], ('bri_csv_intake', 'SELECT bri.csv_review_detail(%s,%s,%s,%s,%s,%s,%s)',
                                       (TENANT, ACTOR, UUID(USER_ID), UUID(SESSION_ID), ISSUER, ITEM, 4096)))

    def test_exactly_three_routes_and_no_worker(self):
        self.assertFalse(hasattr(self.app.state, 'csv_worker'))
        self.assertEqual({(route.path, frozenset(route.methods)) for route in self.app.routes
                          if isinstance(route, APIRoute)}, {
            (BASE, frozenset({'GET'})), (BASE + '/{item_id}', frozenset({'GET'})),
            (BASE + '/{item_id}/decision', frozenset({'POST'})),
        })

    def test_decision_uses_locked_workspace_command_and_returns_only_committed_success(self):
        self.results['csv_review_decide'] = 'approved'
        reply = self.client.post(DECISION, headers=self.headers, json={'decision': 'approved'})
        self.assertEqual(reply.status_code, 200, reply.text)
        self.assertEqual(reply.json(), {'id': f'csv:{ITEM}', 'decision': 'approved'})
        self.assertEqual(reply.headers['Cache-Control'], 'no-store')
        self.assertEqual(self.sql[0][1], 'SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ WRITE')
        self.assertEqual(self.sql[-2][2], (TENANT, USER_ID))
        self.assertEqual(self.sql[-1], ('bri_csv_intake', 'SELECT bri.csv_review_decide(%s,%s,%s,%s,%s,%s,%s)',
                                       (TENANT, ACTOR, UUID(SESSION_ID), ISSUER, ITEM, 'approved',
                                        UUID(reply.headers['X-Request-ID']))))
        self.results['csv_review_decide'] = psycopg.errors.UniqueViolation('private marker')
        replay = self.client.post(DECISION, headers=self.headers, json={'decision': 'approved'})
        self.assertEqual(replay.status_code, 409)
        self.assertNotIn('private marker', replay.text)
        self.results['csv_review_decide'] = 'rejected'
        self.commit_error = psycopg.OperationalError('private marker')
        failed = self.client.post(DECISION, headers=self.headers, json={'decision': 'rejected'})
        self.assertEqual(failed.status_code, 503)
        self.assertNotIn('private marker', failed.text)
        self.assertEqual(len(self.verifications), 3)

    def test_missing_and_resource_denial_are_indistinguishable(self):
        class DecisionDenied(psycopg.errors.InsufficientPrivilege):
            @property
            def diag(self):
                return SimpleNamespace(message_primary='CSV review denied')

        self.results['csv_review_detail'] = None
        missing = self.client.get(DETAIL, headers=self.headers)
        self.assertEqual(missing.status_code, 404)
        for result in (None, DecisionDenied()):
            self.results['csv_review_decide'] = result
            denied = self.client.post(DECISION, headers=self.headers, json={'decision': 'rejected'})
            self.assertEqual((denied.status_code, denied.json()), (404, missing.json()))
            self.assertEqual(denied.headers['Cache-Control'], 'no-store')
        self.results['csv_review_decide'] = psycopg.errors.InsufficientPrivilege('private marker')
        unavailable = self.client.post(DECISION, headers=self.headers, json={'decision': 'rejected'})
        self.assertEqual(unavailable.status_code, 503)
        self.assertNotIn('private marker', unavailable.text)

    def test_decision_auth_is_fresh_and_no_command_runs_on_denial(self):
        self.results['csv_review_decide'] = 'approved'
        body = {'decision': 'approved'}
        self.assertEqual(self.client.post(DECISION, headers=self.headers, json=body).status_code, 200)
        self.sql.clear()
        self.session.return_value = False
        self.assertEqual(self.client.post(DECISION, headers=self.headers, json=body).status_code, 403)
        self.session.return_value = True
        self.person = replace(self.person, grants=())
        self.assertEqual(self.client.post(DECISION, headers=self.headers, json=body).status_code, 403)
        self.assertEqual(self.client.post(DECISION, json=body).status_code, 401)
        self.assertEqual(self.sql, [])
        self.assertEqual(len(self.verifications), 3)

    def test_strict_request_guards_run_before_provider_or_database(self):
        for method, url, extras, code in (
            ('GET', '/docs', {}, 404),
            ('GET', '/v1/knowledge', {}, 404),
            ('POST', '/v1/sources/csv', {}, 404),
            ('HEAD', BASE, {}, 404),
            ('POST', BASE, {}, 404),
            ('GET', DECISION, {}, 404),
            ('POST', DETAIL, {}, 404),
            ('POST', DECISION + '?status=proposed', {}, 400),
            ('GET', BASE + '/', {}, 404),
            ('GET', BASE.replace('/csv', '/%63sv'), {}, 404),
            ('GET', DETAIL.replace('csv:', 'csv%3A'), {}, 404),
            ('GET', DETAIL.replace(str(ITEM), str(ITEM).upper()), {}, 404),
            ('GET', f'{BASE}/csv:{UUID(int=0)}', {}, 404),
            ('GET', BASE + '?status=processing', {}, 400),
            ('GET', BASE + '?status=%66ailed', {}, 400),
            ('GET', BASE + '?status=', {}, 400),
            ('GET', BASE + '?%6cimit=1', {}, 400),
            ('GET', BASE + '?limit=1&limit=2', {}, 400),
            ('GET', BASE + '?limit=51', {}, 400),
            ('GET', BASE + '?limit=1&', {}, 400),
            ('GET', f'{BASE}?after=csv:{ITEM}', {}, 400),
            ('GET', f'{BASE}?after={UUID(int=0)}', {}, 400),
            ('GET', BASE + '?tenant=private-marker', {}, 400),
            ('GET', DETAIL + '?limit=1', {}, 400),
            ('GET', DETAIL + '?offset=01', {}, 400),
            ('GET', DETAIL + '?offset=-1', {}, 400),
            ('GET', DETAIL + '?offset=20000001', {}, 400),
            ('GET', BASE, {'Host': '192.0.2.1:8114'}, 403),
            ('GET', BASE, {'Origin': 'http://127.0.0.1:8115'}, 403),
            ('GET', BASE, {'Origin': 'null'}, 403),
            ('GET', BASE, {'Forwarded': 'for=127.0.0.1'}, 403),
            ('GET', BASE, {'X-Forwarded-For': '127.0.0.1'}, 403),
            ('GET', BASE, {'X-Node-ID': 'private-marker'}, 400),
            ('GET', BASE, {'Cookie': 'fixture=private-marker'}, 400),
            ('GET', BASE, {'Sub': 'private-marker'}, 400),
        ):
            with self.subTest(method=method, url=url, extras=extras):
                reply = self.client.request(method, url, headers={**self.headers, **extras})
                self.assertEqual(reply.status_code, code, reply.text)
                self.assertEqual(reply.headers['Cache-Control'], 'no-store')
                self.assertNotIn('private-marker', reply.text)
        with TestClient(self.app, base_url='http://127.0.0.1:8114', client=('192.0.2.1', 50400)) as remote:
            self.assertEqual(remote.get(BASE, headers=self.headers).status_code, 403)
        self.assertEqual(self.verifications, [])
        self.assertEqual(self.sql, [])

    def test_only_a12_payload_is_accepted(self):
        for content in (b'{"decision":"approved","reason":"private-marker"}',
                        b'{"decision":"approved","decision":"rejected"}',
                        b'{"decision":"pending"}', b'null'):
            with self.subTest(content=content):
                response = self.client.post(DECISION, content=content, headers={
                    **self.headers, 'Content-Type': 'application/json',
                })
                self.assertEqual(response.status_code, 422, response.text)
                self.assertNotIn('private-marker', response.text)
        self.assertEqual(self.client.request('GET', DETAIL, headers=self.headers, content=b'body').status_code, 400)
        self.assertEqual(self.verifications, [])
        self.assertEqual(self.sql, [])


    def test_queue_defaults_and_accepts_same_origin(self):
        self.results['csv_review_queue'] = {'items': [], 'next_cursor': None}
        response = self.client.get(BASE, headers={**self.headers, 'Origin': 'http://127.0.0.1:8114'})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(self.sql[-1][2][-3:], ('proposed', None, 50))


@unittest.skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16')
class ReviewWorkspacePostgresTests(unittest.TestCase):
    # Reuse the socket-only migrated fixture without inheriting its SQL test methods.
    connect = classmethod(pg.csv.fixtures.ApprovalDatabase.connect.__func__)
    sock: Path
    actors: list[tuple[UUID, UUID, UUID]]
    foreign_actors: list[tuple[UUID, UUID, UUID]]
    foreign: str

    @classmethod
    def setUpClass(cls):
        pg.CsvReviewWorkspacePostgresTests.setUpClass.__func__(cls)

    setUp = pg.CsvReviewWorkspacePostgresTests.setUp
    intake = pg.CsvReviewWorkspacePostgresTests.intake
    submit = pg.CsvReviewWorkspacePostgresTests.submit
    worker = pg.CsvReviewWorkspacePostgresTests.worker
    ready = pg.CsvReviewWorkspacePostgresTests.ready
    complete = pg.CsvReviewWorkspacePostgresTests.complete
    propose = pg.CsvReviewWorkspacePostgresTests.propose

    def test_real_review_queue_detail_and_competing_decisions(self):
        from bri.api.csv_review_workspace import create_staged_csv_review_app

        users = {}

        def bearer(identity):
            _, uid, sid = identity
            header = f'Bearer {make_token(sub=str(uid), session_id=str(sid))}'
            users[header] = str(uid)
            return {'Authorization': header}

        def verify(request):
            uid = users.get(request.headers['Authorization'])
            return auth_server_response(request, user_id=uid or '', status=200 if uid else 401)

        reviewer, creator, uploader, other = map(bearer, (*self.actors[:3], self.foreign_actors[0]))
        app = create_staged_csv_review_app(
            identity_scope=lambda: self.connect('bri_app'), review_scope=lambda: self.connect('bri_csv_intake'),
            private_socket=self.sock, auth_transport=httpx.MockTransport(verify),
        )
        pending = self.propose()
        reject = self.propose()
        failed = self.ready()
        self.assertEqual(self.worker('csv_fail', failed, 1, 'invalid_csv', False), ('failed',))
        creating, _, _ = self.submit()
        ready, _, _ = self.submit()
        self.assertEqual(self.intake('csv_mark_ready', ready), ('ready',))
        processing = self.ready()

        def audit_events(job):
            with self.connect('postgres') as db:
                return db.execute('SELECT event FROM bri.csv_audit_events WHERE job_id=%s '
                                  'ORDER BY occurred_at,event_id', (job,)).fetchall()

        initial_events = audit_events(pending)
        with intake_http.StagedCsvPostgres.loopback_reader(self, app) as client:  # type: ignore[arg-type]
            def get(path, auth=reviewer, code=200):
                response = client.get(path, headers=auth)
                self.assertEqual(response.status_code, code, response.text)
                self.assertEqual(response.headers['Cache-Control'], 'no-store')
                return response.json()

            def decide(job, decision, auth=reviewer):
                return client.post(f'{BASE}/csv:{job}/decision', headers=auth, json={'decision': decision})

            first = get(BASE + '?limit=1')
            self.assertEqual([item['id'] for item in first['items']], [f'csv:{pending}'])
            rest = get(f'{BASE}?after={first["next_cursor"]}')
            self.assertEqual([item['id'] for item in rest['items']], [f'csv:{reject}'])
            self.assertIsNone(rest['next_cursor'])
            detail = get(f'{BASE}/csv:{pending}?offset=5')
            self.assertEqual(detail['evidence'], 'derived fixture text')
            self.assertEqual(detail['provenance']['csv_last_line'], 4)
            self.assertEqual(get(f'{BASE}/csv%3A{pending}', code=404), {'detail': 'Not Found'})
            self.assertEqual(audit_events(pending), initial_events)
            self.assertEqual(get(BASE + '?status=failed')['items'][0]['id'], f'csv:{failed}')
            failed_detail = get(f'{BASE}/csv:{failed}')
            self.assertIsNone(failed_detail['provenance'])
            self.assertIsNone(failed_detail['evidence'])
            self.assertEqual(failed_detail['history'][-1]['reason'], 'invalid_csv')
            initial_failed = audit_events(failed)
            conflict = decide(failed, 'approved')
            self.assertEqual((conflict.status_code, conflict.json()), (409, {'detail': 'CSV review conflict'}))
            self.assertEqual(audit_events(failed), initial_failed)

            missing = uuid4()
            absent = get(f'{BASE}/csv:{missing}', code=404)
            foreign = self.submit(identity=self.foreign_actors[2], tenant=self.foreign)[0]
            for job in (missing, creating, ready, processing, foreign):
                with self.subTest(job=job):
                    before = audit_events(job)
                    self.assertEqual(get(f'{BASE}/csv:{job}', code=404), absent)
                    for decision in ('approved', 'rejected'):
                        reply = decide(job, decision)
                        self.assertEqual((reply.status_code, reply.json()), (404, absent))
                        self.assertEqual(reply.headers['Cache-Control'], 'no-store')
                    self.assertEqual(audit_events(job), before)
            for auth in (creator, uploader, other):
                self.assertEqual(get(f'{BASE}/csv:{pending}', auth=auth, code=404), absent)
                denied = decide(pending, 'approved', auth)
                self.assertEqual((denied.status_code, denied.json()), (404, absent))

            # Both requests traverse their own verified preflight and database transaction.
            start = Barrier(2)

            def competing_approval():
                start.wait(timeout=5)
                return decide(pending, 'approved')

            with ThreadPoolExecutor(max_workers=2) as pool:
                replies = [future.result() for future in (pool.submit(competing_approval),
                                                          pool.submit(competing_approval))]
            self.assertCountEqual([response.status_code for response in replies], [200, 409])
            self.assertEqual(audit_events(pending), initial_events + [('approved',)])
            self.assertEqual(decide(reject, 'rejected').status_code, 200)
            for job, state in ((pending, 'approved'), (reject, 'rejected')):
                self.assertEqual([item['id'] for item in get(BASE + f'?status={state}')['items']], [f'csv:{job}'])
                self.assertEqual(get(f'{BASE}/csv:{job}')['history'][-1]['event'], state)
                stale = decide(job, state)
                self.assertEqual((stale.status_code, stale.json()), (409, conflict.json()))
            self.assertEqual(get(BASE), {'items': [], 'next_cursor': None})
