"""HTTP boundary checks for the isolated A11.4 delegation API."""
import unittest
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from time import time
from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import UUID, uuid4

import httpx
import psycopg
from fastapi.testclient import TestClient
from test_authentication import ISSUER, SESSION_ID, USER_ID, auth_server_response, make_token

from bri.access.policy import Principal
from bri.api.app import ApiSettings, create_app
from bri.api.database import Database

PATH = '/v1/users/{id}/delegation'
MAX_VERSION = (1 << 63) - 1


class DisabledRoutes(unittest.TestCase):
    def test_normal_app_denies_without_parsing_authenticating_or_contacting_db(self):
        db, verifier = Mock(), Mock()
        app = create_app(settings=ApiSettings(environment='hosted-development', auth_mode='supabase',
                                             supabase_url=ISSUER.removesuffix('/auth/v1')),
                         database=db, token_verifier=verifier)
        with patch.dict('os.environ', BRI_USER_DELEGATION_ENABLED='1'), TestClient(app) as client:
            schema = client.get('/openapi.json').json()
            operations = schema['paths'][PATH]
            self.assertEqual({p['name'] for p in operations['get']['parameters']}, {'id', 'node', 'permission'})
            self.assertEqual(schema['components']['schemas']['_Change']['properties']['expected_version']['type'],
                             'string')
            for method in ('GET', 'PATCH'):
                with self.subTest(method=method):
                    response = client.request(method, PATH.format(id='private-marker') + '?tenant=other',
                                              content=b'{', headers={'Content-Type': 'application/json'})
                    self.assertEqual(response.status_code, 403)
                    self.assertEqual(response.headers['Cache-Control'], 'no-store')
                    self.assertNotIn('private-marker', response.text)
        self.assertEqual(db.mock_calls, [])
        self.assertEqual(verifier.mock_calls, [])


class StagedRoutes(unittest.TestCase):
    def setUp(self):
        from bri.api.user_delegation import create_staged_user_delegation_app

        self.socket = Path(self.enterContext(TemporaryDirectory()))
        self.actor, self.target = uuid4(), uuid4()
        self.path = PATH.format(id=self.target)
        self.scope_input = {'node': 'Region/Case + space', 'permission': 'organisation:read'}
        self.body = {**self.scope_input, 'action': 'grant', 'expected_version': str(MAX_VERSION)}
        self.authority = ('tenant-a', self.actor, UUID(SESSION_ID), ISSUER, self.target)
        self.admin = Principal(str(self.actor), frozenset({'tenant-a'}), (), (('tenant-a', 'admin'),))
        self.resolve = self.enterContext(patch.object(Database, 'resolve_authenticated_principal',
                                                       return_value=self.admin))
        self.active = self.enterContext(patch.object(Database, 'auth_session_is_active', return_value=True))
        self.info = {'host': str(self.socket), 'hostaddr': '', 'port': 5432, 'dbname': 'postgres',
                     'user': 'bri_app', 'transaction_status': psycopg.pq.TransactionStatus.IDLE}
        self.autocommit, self.role_ok = False, True
        self.row, self.error, self.commit_error = (MAX_VERSION, False), None, None
        self.events, self.commands, self.auth_calls = [], [], []
        self.stage = create_staged_user_delegation_app(
            app_scope=self.scope, private_socket=self.socket, auth_transport=httpx.MockTransport(self.auth),
        )
        self.client = self.enterContext(TestClient(self.stage, base_url='http://127.0.0.1',
                                                   client=('127.0.0.1', 50200)))

    def auth(self, request):
        self.assertEqual((request.method, str(request.url)), ('GET', f'{ISSUER}/user'))
        self.auth_calls.append(request)
        return auth_server_response(request)

    @contextmanager
    def scope(self):
        @contextmanager
        def transaction():
            self.events.append('begin')
            try:
                yield
            except Exception:
                self.events.append('rollback')
                raise
            else:
                if self.commit_error:
                    self.events.append('commit_failed')
                    raise self.commit_error('private-marker')
                self.events.append('commit')

        def execute(query, params=()):
            self.events.append((query, params))
            row = (self.role_ok,)
            if 'user_delegation(' in query:
                self.commands.append((query, params))
                if self.error:
                    raise self.error('private-marker')
                row = self.row
            return SimpleNamespace(fetchone=lambda: row)

        yield SimpleNamespace(info=SimpleNamespace(**self.info), autocommit=self.autocommit,
                              execute=execute, transaction=transaction)

    @staticmethod
    def headers(**claims):
        return {'Authorization': f'Bearer {make_token(**claims)}'}

    def read(self, headers=None):
        return self.client.get(self.path, params=self.scope_input, headers=headers or self.headers())

    def change(self, headers=None, body=None):
        return self.client.patch(self.path, json=self.body if body is None else body,
                                 headers=headers or self.headers(amr=[{'method': 'totp', 'timestamp': int(time())}]))

    def test_read_projects_contract_and_preserves_exact_node(self):
        reply = self.read()
        self.assertEqual(reply.status_code, 200, reply.text)
        self.assertEqual(reply.json(), {'version': str(MAX_VERSION), 'granted': False})
        self.assertEqual(reply.headers['Cache-Control'], 'no-store')
        self.resolve.assert_called_once_with(USER_ID, ISSUER, USER_ID)
        self.active.assert_called_once_with(USER_ID, SESSION_ID)
        [(query, params)] = self.commands
        self.assertIn('FROM bri.read_user_delegation(', query)
        self.assertEqual(params, (*self.authority, *self.scope_input.values()))
        self.assertEqual(self.events[0], 'begin')
        self.assertIn('READ ONLY', self.events[1][0])
        self.assertIn(("SELECT set_config('bri.tenant_id',%s,true),set_config('bri.auth_user_id',%s,true)",
                       ('tenant-a', USER_ID)), self.events)
        self.assertEqual(self.events[-2:], [(query, params), 'commit'])

    def test_both_writes_use_verified_totp_and_server_correlation(self):
        stamp = int(time()) - 3
        for action, version, granted in (('grant', MAX_VERSION, True), ('revoke', 0, False)):
            with self.subTest(action=action):
                self.events.clear()
                self.row = (MAX_VERSION, granted)
                headers = {**self.headers(amr=[{'method': 'totp', 'timestamp': stamp}]),
                           'X-Request-ID': str(self.target)}
                reply = self.change(headers, {**self.body, 'action': action, 'expected_version': str(version),
                                              'permission': 'knowledge:read'})
                self.assertEqual(reply.status_code, 200, reply.text)
                self.assertEqual(reply.json(), {'version': str(MAX_VERSION), 'granted': granted})
                self.assertEqual(reply.headers['Cache-Control'], 'no-store')
                cid = UUID(reply.headers['X-Request-ID'])
                self.assertNotEqual(cid, self.target)
                query, params = self.commands[-1]
                self.assertIn('FROM bri.change_user_delegation(', query)
                self.assertEqual(params, (*self.authority, self.body['node'], 'knowledge:read', action, version,
                                          datetime.fromtimestamp(stamp, UTC), cid))
                self.assertEqual(self.events[:2],
                                 ['begin', ('SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ WRITE', ())])
                self.assertEqual(self.events[-2:], [(query, params), 'commit'])

    def test_no_success_if_commit_fails(self):
        self.commit_error = psycopg.OperationalError
        reply = self.change()
        self.assertEqual(reply.status_code, 503)
        self.assertNotIn('private-marker', reply.text)
        self.assertEqual(reply.headers['Cache-Control'], 'no-store')
        self.assertEqual(len(self.commands), 1)
        self.assertEqual(self.events[-1], 'commit_failed')

    def test_write_requires_recent_verified_totp(self):
        now = int(time())
        for amr, code in (
            ([], 401), ([{'method': 'password', 'timestamp': now}], 401),
            *(([{'method': 'totp', 'timestamp': stamp}], 403) for stamp in (now - 901, now + 60, str(now), None)),
        ):
            for action in ('grant', 'revoke'):
                with self.subTest(amr=amr, action=action):
                    headers = {**self.headers(iat=now, amr=amr, totp_authenticated_at=now), 'X-TOTP-At': str(now)}
                    self.assertEqual(self.change(headers, {**self.body, 'action': action}).status_code, code)
        self.assertEqual(self.commands, [])
        stale = self.headers(iat=now, amr=[{'method': 'totp', 'timestamp': now - 901}])
        self.assertEqual(self.read(stale).status_code, 200)

    def test_invalid_input_never_reaches_auth_or_db(self):
        for field, values in {
            'expected_version': [1, True, 1.0, None, '-1', '+1', '1.0', '1e1', '1\n', ' 1', '١', '',
                                 str(MAX_VERSION + 1), '1' * 20],
            'node': ['', ' ', 'region\x00east', 42], 'permission': ['user:suspend', 'Knowledge:read'],
            'action': ['add', 'Grant'],
            'tenant': ['other'], 'actor': [str(self.target)], 'sid': [SESSION_ID], 'issuer': [ISSUER],
            'target': [str(self.actor)], 'totp_at': [1], 'correlation': [str(self.target)],
        }.items():
            for value in values:
                with self.subTest(field=field, value=value):
                    reply = self.change(body={**self.body, field: value})
                    self.assertEqual(reply.status_code, 422, reply.text)
                    self.assertEqual(reply.headers['Cache-Control'], 'no-store')
        for query in ('', '?node=x', '?node=x&permission=knowledge:read&node=y',
                      '?node=x&permission=knowledge:read&tenant=other', '?node=x&permission=user:suspend',
                      '?node=%FF&permission=knowledge:read'):
            self.assertEqual(self.client.get(self.path + query, headers=self.headers()).status_code, 422)
        self.assertEqual(self.client.patch(self.path + '?tenant=other', json=self.body).status_code, 400)
        for content in (b'{', b'{"action":"grant","action":"revoke"}'):
            self.assertEqual(self.client.patch(self.path, content=content,
                                               headers={'Content-Type': 'application/json'}).status_code, 422)
        self.assertEqual(self.client.request('GET', self.path, params=self.scope_input, content=b'{}').status_code, 400)
        self.assertEqual((self.auth_calls, self.events), ([], []))

    def test_only_live_single_tenant_admin_reaches_sql(self):
        self.assertEqual(self.read({'Authorization': 'Bearer invalid'}).status_code, 401)
        self.resolve.assert_not_called()
        for principal, active in (
            (None, True), (self.admin, False),
            (Principal(str(self.actor), frozenset({'tenant-a'}), (), (('tenant-a', 'user'),)), True),
            (Principal(str(self.actor), frozenset({'tenant-a'}), (), (('tenant-a', 'admin'),), True), True),
            (Principal(str(self.actor), frozenset({'tenant-a', 'b'}), (), (('tenant-a', 'admin'),)), True),
        ):
            self.resolve.return_value, self.active.return_value = principal, active
            self.assertEqual(self.read().status_code, 403)
            self.assertEqual(self.change().status_code, 403)
        self.assertEqual(self.events, [])

    def test_private_and_restricted_stage(self):
        from bri.api.user_delegation import create_staged_user_delegation_app

        with httpx.HTTPTransport() as live, self.assertRaises(ValueError):
            create_staged_user_delegation_app(app_scope=self.scope, private_socket=self.socket,
                                              auth_transport=live)  # type: ignore[arg-type] -- runtime rejection
        self.socket.chmod(0o755)
        with self.assertRaises(ValueError):
            create_staged_user_delegation_app(app_scope=self.scope, private_socket=self.socket,
                                              auth_transport=httpx.MockTransport(self.auth))
        self.socket.chmod(0o700)
        with TestClient(self.stage, base_url='http://127.0.0.1', client=('192.0.2.10', 50200)) as remote:
            self.assertEqual(remote.get(self.path, params=self.scope_input).status_code, 403)
        for name, code in (('X-Forwarded-For', 403), ('X-Dev-Identity', 400), ('X-BRI-Tenant-Context', 400)):
            self.assertEqual(self.read({**self.headers(), name: '127.0.0.1'}).status_code, code)
        self.assertEqual((self.events, self.auth_calls), ([], []))
        for field, value in (('user', 'postgres'), ('host', '127.0.0.1'), ('hostaddr', '127.0.0.1'),
                             ('dbname', 'other'), ('port', 5555),
                             ('transaction_status', psycopg.pq.TransactionStatus.INTRANS)):
            with patch.dict(self.info, {field: value}):
                self.assertEqual(self.read().status_code, 503)
        self.autocommit = True
        self.assertEqual(self.read().status_code, 503)
        self.assertEqual(self.events, [])
        self.autocommit, self.role_ok = False, False
        self.assertEqual(self.read().status_code, 503)
        self.assertEqual(self.commands, [])

    def test_database_outcomes_are_generic_and_rolled_back(self):
        for error, code in ((psycopg.errors.InsufficientPrivilege, 403), (psycopg.errors.SerializationFailure, 409),
                            (psycopg.errors.ObjectNotInPrerequisiteState, 409), (psycopg.OperationalError, 503)):
            self.error = error
            reply = self.change()
            self.assertEqual(reply.status_code, code)
            self.assertNotIn('private-marker', reply.text)
            self.assertEqual(reply.headers['Cache-Control'], 'no-store')
            self.assertEqual(self.events[-1], 'rollback')
        self.error, self.row = None, None
        for send in (self.read, self.change):
            reply = send()
            self.assertEqual((reply.status_code, reply.json()), (404, {'detail': 'User not found'}))
            self.assertEqual(self.events[-1], 'rollback')
