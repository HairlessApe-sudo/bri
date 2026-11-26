"""HTTP boundary for the isolated published-knowledge inventory."""
import socket
import threading
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
from uuid import UUID

import httpx
import psycopg
import uvicorn
from fastapi.testclient import TestClient
from test_authentication import ISSUER, SESSION_ID, USER_ID, auth_server_response, make_token

from bri.access.policy import AccessGrant, Principal
from bri.api.csv_intake import create_staged_csv_reader_app
from bri.api.database import Database

PATH = '/v1/reports/published-knowledge-inventory'
NODE = 'fixture-node'
URL = f'{PATH}?scope_node_id={NODE}'
ACTOR = UUID('2b986c7e-9ff7-46c4-8b7c-ec5a8deb01ee')
RECORD = f'csv:{ACTOR}'
ROW = (RECORD, RECORD, 'a' * 64, 'b' * 64, 1, 5)
BASE = dict(metric_id='published_knowledge_inventory', metric_version=1, scope_node_id=NODE)


class CsvReportingApiTests(unittest.TestCase):
    def setUp(self):
        self.socket = Path(self.enterContext(TemporaryDirectory()))
        self.commands, self.auth_calls = [], []
        self.rows = [ROW]
        self.failure = self.commit_failure = None
        self.principal = Principal(str(ACTOR), frozenset({'tenant'}), (
            AccessGrant('tenant', 'knowledge:read', NODE),
        ), (('tenant', 'user'),))
        self.resolve = self.enterContext(patch.object(Database, 'resolve_authenticated_principal',
                                                      side_effect=lambda *_: self.principal))
        self.active = self.enterContext(patch.object(Database, 'auth_session_is_active', return_value=True))
        self.client = self.enterContext(TestClient(create_staged_csv_reader_app(
            identity_scope=lambda: self.db('bri_app'), reader_scope=lambda: self.db('bri_csv_reader'),
            private_socket=self.socket, auth_transport=httpx.MockTransport(self.provider),
        ), base_url='http://127.0.0.1', client=('127.0.0.1', 51000)))
        self.headers = {'Authorization': f'Bearer {make_token()}'}

    def provider(self, request):
        self.auth_calls.append(request.url.path)
        return auth_server_response(request)

    @contextmanager
    def db(self, role):
        yield SimpleNamespace(
            info=SimpleNamespace(host=str(self.socket), port=5432, dbname='postgres', user=role,
                                 transaction_status=psycopg.pq.TransactionStatus.IDLE),
            transaction=self.transaction,
            execute=self.execute,
        )

    @contextmanager
    def transaction(self):
        yield
        if self.commit_failure:
            raise self.commit_failure

    def execute(self, sql, args=()):
        self.commands.append((sql, args))
        if 'bri.csv_read_reporting(' in sql:
            if self.failure:
                raise self.failure
            return SimpleNamespace(fetchmany=lambda size: self.rows[:size])
        return SimpleNamespace(fetchone=lambda: (True,))

    def assert_private(self, reply):
        self.assertEqual(reply.headers.get('Cache-Control'), 'private, no-store')

    def test_exact_verified_identity_reads_bounded_provenance(self):
        reply = self.client.get(URL, headers=self.headers)
        self.assertEqual(reply.status_code, 200, reply.text)
        self.assert_private(reply)
        self.assertEqual(reply.json(), {'result': {**BASE, 'status': 'complete', 'count': 1, 'evidence': [{
            'record_id': RECORD, 'source_version_id': RECORD, 'original_sha256': 'a' * 64,
            'content_sha256': 'b' * 64, 'first_line': 1, 'last_line': 5,
        }]}})
        self.resolve.assert_called_once_with(USER_ID, ISSUER, USER_ID)
        self.active.assert_called_once_with(USER_ID, SESSION_ID)
        self.assertEqual(len(self.commands), 4)
        self.assertIn('READ ONLY', self.commands[0][0])
        self.assertEqual(self.commands[1][1], ('bri_csv_reader',))
        self.assertRegex(self.commands[2][0], r"^SET LOCAL statement_timeout = '(?:[1-9][0-9]{0,2}|[1-4][0-9]{3}|5000)ms'$")
        self.assertIn('bri.csv_read_reporting(', self.commands[3][0])
        self.assertEqual(self.commands[3][1], ('tenant', ACTOR, UUID(USER_ID), UUID(SESSION_ID), ISSUER, NODE, 1001))

    def test_authorized_empty_is_complete(self):
        self.rows = []
        reply = self.client.get(URL, headers=self.headers)
        self.assertEqual(reply.status_code, 200)
        self.assertEqual(reply.json(), {'result': {**BASE, 'status': 'complete', 'count': 0, 'evidence': []}})

    def test_unknown_inaccessible_inactive_and_sql_denial_have_the_same_shape(self):
        replies = [self.client.get(f'{PATH}?scope_node_id={node}', headers=self.headers)
                   for node in ('unknown', 'other-existing-node')]
        self.active.return_value = False
        replies.append(self.client.get(URL, headers=self.headers))
        self.assertEqual(self.commands, [])
        self.active.return_value = True
        self.failure = psycopg.errors.InsufficientPrivilege('private sql detail')
        replies.append(self.client.get(URL, headers=self.headers))
        for reply in replies:
            self.assertEqual(reply.status_code, 403, reply.text)
            self.assertEqual(reply.json(), replies[0].json())
            self.assertNotIn('private sql detail', reply.text)
            self.assert_private(reply)

    def test_malformed_spoofed_or_aliased_requests_never_reach_auth(self):
        for method, url, extra, status in (
            ('GET', PATH, {}, 400),
            ('GET', URL + '&scope_node_id=other', {}, 400),
            ('GET', URL + '&tenant_id=other', {}, 400),
            ('GET', PATH + '?scope_node_id=%FF', {}, 400),
            ('GET', URL, {'x-tenant-id': 'other'}, 400),
            ('GET', URL, {'scope-node-id': 'other'}, 400),
            ('GET', URL, {'x-forwarded-for': '127.0.0.1'}, 403),
            ('GET', URL.replace('/reports/', '/%72eports/'), {}, 404),
            ('GET', URL.replace('?', '/?'), {}, 404),
            ('POST', URL, {}, 404),
        ):
            with self.subTest(url=url, method=method, extra=extra):
                reply = self.client.request(method, url, headers={**self.headers, **extra}, follow_redirects=False)
                self.assertEqual(reply.status_code, status, reply.text)
                self.assert_private(reply)
        self.assertEqual(self.commands, [])
        self.assertEqual(self.auth_calls, [])

    def test_unsigned_or_unverified_identity_never_reaches_registry(self):
        header, payload, signature = make_token().split('.')
        tampered = ('A' if signature[0] != 'A' else 'B') + signature[1:]
        for headers in ({}, {'Authorization': f'Bearer {header}.{payload}.{tampered}'}):
            reply = self.client.get(URL, headers=headers)
            self.assertEqual(reply.status_code, 401, reply.text)
            self.assert_private(reply)
        self.resolve.assert_not_called()
        self.assertEqual(self.commands, [])

    def test_unavailable_never_returns_a_partial_result(self):
        for failure, commit_failure, rows in (
            (psycopg.errors.QueryCanceled('private sql detail'), None, [ROW]),
            (psycopg.errors.ObjectNotInPrerequisiteState('private sql detail'), None, [ROW]),
            (None, psycopg.OperationalError('private commit detail'), [ROW]),
            (None, None, [ROW] * 1001),
            (None, None, [ROW, (*ROW[:4], 6, 5)]),
        ):
            self.failure, self.commit_failure, self.rows = failure, commit_failure, rows
            reply = self.client.get(URL, headers=self.headers)
            self.assertEqual(reply.status_code, 503, reply.text)
            self.assertEqual(reply.json(), {'result': {**BASE, 'status': 'unavailable'}})
            self.assert_private(reply)

    def test_encoded_response_budget_is_all_or_nothing(self):
        expected_size = len(self.client.get(URL, headers=self.headers).content)
        with patch('bri.api.csv_intake._REPORT_MAX_BYTES', expected_size):
            self.assertEqual(self.client.get(URL, headers=self.headers).status_code, 200)
        with patch('bri.api.csv_intake._REPORT_MAX_BYTES', expected_size - 1):
            reply = self.client.get(URL, headers=self.headers)
        self.assertEqual(reply.status_code, 503)
        self.assertEqual(reply.json(), {'result': {**BASE, 'status': 'unavailable'}})

    def test_complete_result_has_stable_evidence_order(self):
        other = f'csv:{UUID(int=1)}'
        self.rows = [ROW, (other, other, *ROW[2:])]
        first = self.client.get(URL, headers=self.headers)
        self.rows.reverse()
        second = self.client.get(URL, headers=self.headers)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.content, second.content)

    def test_report_is_not_mounted_on_hosted_app(self):
        from bri.api.app import ApiSettings, create_app

        app = create_app(settings=ApiSettings(environment='hosted-development', auth_mode='supabase',
                                              supabase_url=ISSUER.removesuffix('/auth/v1')),
                         token_verifier=object())
        with TestClient(app) as client:
            reply = client.get(URL, headers=self.headers)
        self.assertEqual(reply.status_code, 404, reply.text)
        self.assertNotIn(PATH, app.openapi()['paths'])

    def test_report_keeps_success_and_denial_private_on_loopback_http(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            port = listener.getsockname()[1]
            server = uvicorn.Server(uvicorn.Config(self.client.app, proxy_headers=False, access_log=False,
                                                   log_level='error', ws='none'))
            thread = threading.Thread(target=server.run, kwargs={'sockets': [listener]}, daemon=True)
            thread.start()
            try:
                deadline = time.monotonic() + 5
                while not server.started and thread.is_alive() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(server.started)
                with httpx.Client(base_url=f'http://127.0.0.1:{port}', trust_env=False) as client:
                    success = client.get(URL, headers=self.headers)
                    denial = client.get(URL.replace(NODE, 'unknown'), headers=self.headers)
                    self.assertEqual(client.get('/openapi.json').status_code, 404)
                self.assertEqual(success.status_code, 200)
                self.assertEqual(denial.status_code, 403)
                self.assert_private(success)
                self.assert_private(denial)
            finally:
                server.should_exit = True
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())
