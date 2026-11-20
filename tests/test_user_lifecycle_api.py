"""HTTP boundary checks for the isolated A11.3 lifecycle stage."""
import os
import unittest
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from time import sleep, time
from types import SimpleNamespace
from unittest.mock import patch
from uuid import UUID, uuid4

import httpx
import psycopg
import test_privileged_approvals_pg as pg
from fastapi import FastAPI
from fastapi.testclient import TestClient
from test_authentication import (
    ISSUER,
    SESSION_ID,
    USER_ID,
    auth_server_response,
    make_token,
)

from bri.access.policy import Principal
from bri.api.database import Database

PATH = '/v1/users/{id}/lifecycle'


class DisabledRoutes(unittest.TestCase):
    def test_normal_mount_denies_before_reading_body_or_parsing_id(self):
        from bri.api.user_lifecycle import create_user_lifecycle_router

        app = FastAPI()
        app.include_router(create_user_lifecycle_router())
        with patch.dict('os.environ', BRI_USER_LIFECYCLE_ENABLED='1'), TestClient(app) as client:
            operations = client.get('/openapi.json').json()['paths'][PATH]
            schema = operations['patch']['requestBody']['content']['application/json']['schema']
            self.assertEqual(set(schema['discriminator']['mapping']), {'edit', 'suspend', 'reactivate'})
            for method in ('GET', 'PATCH'):
                with self.subTest(method=method):
                    reply = client.request(method, PATH.format(id='private-marker'), content=b'{',
                                           headers={'Content-Type': 'application/json'})
                    self.assertEqual(reply.status_code, 403)
                    self.assertEqual(reply.headers['Cache-Control'], 'no-store')
                    self.assertNotIn('private-marker', reply.text)


class StagedRoutes(unittest.TestCase):
    def setUp(self):
        from bri.api.user_lifecycle import create_staged_user_lifecycle_app

        self.socket = Path(self.enterContext(TemporaryDirectory()))
        self.actor, self.target = uuid4(), uuid4()
        self.path = PATH.format(id=self.target)
        self.authority = ('tenant-a', self.actor, UUID(SESSION_ID), ISSUER, self.target)
        self.sql, self.auth_calls = [], []
        self.row = (self.target, 'Fixture User', 'active', 'user', 1, True, True, False)
        self.reply = dict(zip(('id', 'display_name', 'status', 'role', 'version',
                               'can_edit', 'can_suspend', 'can_reactivate'),
                              (str(self.target), *self.row[1:]), strict=True))
        self.role_ok, self.error = True, None
        self.connection_info = {'host': str(self.socket), 'hostaddr': '', 'port': 5432, 'dbname': 'postgres',
                                    'user': 'bri_app', 'transaction_status': psycopg.pq.TransactionStatus.IDLE}
        self.autocommit = False
        self.stage = create_staged_user_lifecycle_app(
            app_scope=self.scope, private_socket=self.socket, auth_transport=httpx.MockTransport(self.auth),
        )
        self.client = self.enterContext(TestClient(self.stage, base_url='http://127.0.0.1',
                                                   client=('127.0.0.1', 50200)))
        self.admin = Principal(str(self.actor), frozenset({'tenant-a'}), (), (('tenant-a', 'admin'),))
        self.resolve = self.enterContext(patch.object(Database, 'resolve_authenticated_principal',
                                                       return_value=self.admin))
        self.active = self.enterContext(patch.object(Database, 'auth_session_is_active', return_value=True))

    def auth(self, request):
        self.assertEqual((request.method, str(request.url)), ('GET', f'{ISSUER}/user'))
        self.auth_calls.append(request)
        return auth_server_response(request)

    @contextmanager
    def scope(self):
        @contextmanager
        def transaction():
            yield

        def execute(query, params=()):
            self.sql.append((query, params))
            row = (self.role_ok,)
            if 'user_lifecycle(' in query:
                if self.error:
                    raise self.error('private-marker')
                row = self.row
            return SimpleNamespace(fetchone=lambda: row)

        yield SimpleNamespace(info=SimpleNamespace(**self.connection_info), autocommit=self.autocommit,
                              execute=execute, transaction=transaction)

    @staticmethod
    def headers(**claims):
        return {'Authorization': f'Bearer {make_token(**claims)}'}

    def commands(self):
        return [(query, params) for query, params in self.sql if 'user_lifecycle(' in query]

    def test_read_uses_verified_live_admin_and_projects_only_contract_fields(self):
        assert self.row is not None
        self.row += ('private-marker',)
        reply = self.client.get(self.path, headers=self.headers())
        self.assertEqual(reply.status_code, 200, reply.text)
        self.assertEqual(reply.json(), self.reply)
        self.assertEqual(reply.headers['Cache-Control'], 'no-store')
        self.resolve.assert_called_once_with(USER_ID, ISSUER, USER_ID)
        self.active.assert_called_once_with(USER_ID, SESSION_ID)
        [(query, params)] = self.commands()
        self.assertIn('bri.read_user_lifecycle(', query)
        self.assertEqual(params, self.authority)
        self.assertTrue(any('bri.auth_user_id' in q and p == ('tenant-a', USER_ID) for q, p in self.sql))

    def test_all_actions_bind_only_defined_fields_and_server_correlation(self):
        now = int(time()) - 3
        stamp = datetime.fromtimestamp(now, UTC)
        for action, fields, tail in (
            ('edit', {'display_name': 'Fixture User'}, ('Fixture User', None, stamp)),
            ('suspend', {'reason': 'temporary_leave'}, (None, 'temporary_leave', stamp)),
            ('reactivate', {'reason': 'access_restored'}, (None, 'access_restored', stamp)),
        ):
            with self.subTest(action=action):
                reply = self.client.patch(self.path, json={'action': action, 'expected_version': 1, **fields},
                    headers={**self.headers(amr=[{'method': 'totp', 'timestamp': now}]),
                             'X-Request-ID': str(self.target)})
                self.assertEqual(reply.status_code, 200, reply.text)
                self.assertEqual(reply.json(), self.reply)
                query, params = self.commands()[-1]
                self.assertIn('bri.change_user_lifecycle(', query)
                correlation = UUID(reply.headers['X-Request-ID'])
                self.assertNotEqual(correlation, self.target)
                self.assertEqual(params, (*self.authority, action, 1, *tail, correlation))

    def test_rejects_malformed_or_out_of_action_fields_without_auth_or_sql(self):
        edit = {'action': 'edit', 'expected_version': 1, 'display_name': 'Fixture'}
        headers = self.headers()
        for body in (
            {**edit, 'reason': None}, {**edit, 'totp_at': 'private-marker'}, {**edit, 'expected_version': True},
            {**edit, 'expected_version': '1'}, {**edit, 'expected_version': 1.0},
            {**edit, 'expected_version': 2**63}, {**edit, 'expected_version': -1},
            {**edit, 'display_name': ' '}, {**edit, 'display_name': 'private-marker\x00'},
            {**edit, 'display_name': 'x' * 129}, {'action': 'edit', 'expected_version': 1},
            {'action': 'suspend', 'expected_version': 1},
            {'action': 'suspend', 'expected_version': 1, 'reason': 'review_complete'},
            {'action': 'reactivate', 'expected_version': 1, 'reason': 'temporary_leave'},
            {'action': 'reactivate', 'expected_version': 1, 'reason': 'review_complete', 'display_name': None},
            {'action': 'private-marker', 'expected_version': 1},
        ):
            with self.subTest(body=body):
                reply = self.client.patch(self.path, json=body, headers=headers)
                self.assertEqual((reply.status_code, reply.json()), (422, {'detail': 'Invalid user lifecycle request'}))
        json_headers = {**headers, 'Content-Type': 'application/json'}
        for raw in (b'{private-marker', b'\xff',
                    b'{"action":"edit","expected_version":1,"display_name":"x","action":"suspend"}'):
            self.assertEqual(self.client.patch(self.path, content=raw, headers=json_headers).status_code, 422)
        self.assertEqual(self.client.patch(self.path, content=iter([b' ' * 3000] * 2),
                                           headers=json_headers).status_code, 413)
        self.assertEqual(self.client.patch(self.path, content=b'{}', headers=headers).status_code, 415)
        self.assertEqual(self.client.request('GET', self.path, content=b'{}', headers=headers).status_code, 400)
        bad_path = self.client.get(PATH.format(id='private-marker'), headers=headers)
        self.assertEqual((bad_path.status_code, bad_path.json()), (422, {'detail': 'Invalid user lifecycle request'}))
        self.assertEqual((self.auth_calls, self.sql), ([], []))

    def test_lifecycle_step_up_uses_verified_amr_event_not_token_issue_or_header(self):
        now = int(time())
        for amr in ([{'method': 'totp', 'timestamp': stamp}] for stamp in (now - 901, now + 60, None, str(now))):
            headers = {**self.headers(iat=now, amr=amr, totp_authenticated_at=now), 'X-TOTP-At': str(now)}
            for action, reason in (('suspend', 'policy_violation'), ('reactivate', 'review_complete')):
                reply = self.client.patch(self.path, headers=headers,
                                          json={'action': action, 'expected_version': 1, 'reason': reason})
                self.assertEqual(reply.status_code, 403)
        self.assertEqual(self.commands(), [])
        # Step-up is not required for a read or a display-name-only edit.
        stale = now - 901
        headers = self.headers(amr=[{'method': 'totp', 'timestamp': stale}])
        self.assertEqual(self.client.get(self.path, headers=headers).status_code, 200)
        self.assertEqual(self.client.patch(self.path, headers=headers,
            json={'action': 'edit', 'expected_version': 1, 'display_name': 'Renamed'}).status_code, 200)
        self.assertEqual(self.commands()[-1][1][-2], datetime.fromtimestamp(stale, UTC))

    def test_unverified_or_ineligible_admin_cannot_reach_either_command(self):
        body = {'action': 'edit', 'expected_version': 1, 'display_name': 'Fixture'}
        def requests(headers):
            yield self.client.get(self.path, headers=headers)
            yield self.client.patch(self.path, headers=headers, json=body)

        for reply in requests({'Authorization': 'Bearer private-marker'}):
            self.assertEqual(reply.status_code, 401)
            self.assertNotIn('private-marker', reply.text)
        self.resolve.assert_not_called()

        for principal, active in (
            (None, True), (self.admin, False),
            (Principal(str(self.actor), frozenset({'tenant-a'}), (), (('tenant-a', 'user'),)), True),
            (Principal(str(self.actor), frozenset({'tenant-a'}), (), (('tenant-a', 'admin'),), True), True),
            (Principal(str(self.actor), frozenset({'tenant-a', 'b'}), (), (('tenant-a', 'admin'),)), True),
        ):
            self.resolve.return_value, self.active.return_value = principal, active
            for reply in requests(self.headers()):
                self.assertEqual(reply.status_code, 403)
        self.assertEqual(self.sql, [])

    def test_guard_rejects_network_proxy_and_browser_selected_authority(self):
        with (TestClient(self.stage, base_url='http://127.0.0.1', client=('192.0.2.10', 50200)) as remote,
              TestClient(self.stage, base_url='http://192.0.2.10', client=('127.0.0.1', 50200)) as remote_server):
            for client, extra, suffix, code in (
                (remote, {}, '', 403), (remote_server, {'Host': '127.0.0.1'}, '', 403),
                (self.client, {'Host': 'localhost'}, '', 403),
                (self.client, {'X-Forwarded-For': '127.0.0.1'}, '', 403),
                (self.client, {'X-Dev-Identity': 'admin'}, '', 400),
                (self.client, {'X-BRI-Tenant-Context': 'other'}, '', 400),
                (self.client, {}, '?tenant=other', 400),
            ):
                self.assertEqual(client.get(self.path + suffix, headers={**self.headers(), **extra}).status_code, code)
        self.assertEqual((self.auth_calls, self.sql), ([], []))

    def test_stage_rejects_non_mock_auth_and_non_private_socket(self):
        from bri.api.user_lifecycle import create_staged_user_lifecycle_app

        with httpx.HTTPTransport() as live, self.assertRaises(ValueError):
            create_staged_user_lifecycle_app(app_scope=self.scope, private_socket=self.socket,
                                             auth_transport=live)  # type: ignore[arg-type] -- exercise runtime rejection
        self.socket.chmod(0o755)
        with self.assertRaises(ValueError):
            create_staged_user_lifecycle_app(app_scope=self.scope, private_socket=self.socket,
                                             auth_transport=httpx.MockTransport(self.auth))

    def test_commands_reject_wrong_connection_or_privileged_role(self):
        for key, value in (('user', 'postgres'), ('host', '127.0.0.1'), ('hostaddr', '127.0.0.1'),
                           ('dbname', 'other'), ('port', 5555),
                           ('transaction_status', psycopg.pq.TransactionStatus.INTRANS)):
            with patch.dict(self.connection_info, {key: value}):
                self.assertEqual(self.client.get(self.path, headers=self.headers()).status_code, 503)
        self.autocommit = True
        self.assertEqual(self.client.get(self.path, headers=self.headers()).status_code, 503)
        self.assertEqual(self.sql, [])
        self.autocommit, self.role_ok = False, False
        self.assertEqual(self.client.get(self.path, headers=self.headers()).status_code, 503)
        self.assertEqual(self.commands(), [])

    def test_database_states_map_to_generic_http_errors(self):
        body = {'action': 'edit', 'expected_version': 1, 'display_name': 'Fixture'}
        for error, code in ((psycopg.errors.InsufficientPrivilege, 403), (psycopg.errors.SerializationFailure, 409),
                            (psycopg.errors.ObjectNotInPrerequisiteState, 409),
                            (psycopg.errors.InvalidParameterValue, 422), (psycopg.OperationalError, 503)):
            with self.subTest(error=error):
                self.error = error
                reply = self.client.patch(self.path, headers=self.headers(), json=body)
                self.assertEqual(reply.status_code, code)
                self.assertNotIn('private-marker', reply.text)
                self.assertEqual(reply.headers['Cache-Control'], 'no-store')
        self.error, self.row = None, None
        for reply in (self.client.get(self.path, headers=self.headers()),
                      self.client.patch(self.path, headers=self.headers(), json=body)):
            self.assertEqual((reply.status_code, reply.json()), (404, {'detail': 'User not found'}))


@unittest.skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16')
class StagedPostgres(unittest.TestCase):
    sock: Path
    connect = classmethod(pg.ApprovalDatabase.connect.__func__)

    @classmethod
    def setUpClass(cls):
        with patch.dict(os.environ, BRI_APPROVAL_PG_BIN=os.environ['BRI_TEST_PG_BIN']):
            pg.ApprovalDatabase.setUpClass.__func__(cls, staged_account_write=pg.LIFECYCLE_WRITE)
        with cls.connect('bri_migrator') as db:
            db.execute('INSERT INTO bri.provider_event_source(issuer) VALUES (%s)', (ISSUER,))

    def test_restricted_stage_edits_suspends_and_reactivates_with_live_authority(self):
        from bri.api.user_lifecycle import create_staged_user_lifecycle_app

        tenant, actors = pg.seed_approval_tenant(self.connect)
        _, foreign = pg.seed_approval_tenant(self.connect)
        admin, uid, _ = actors[0]
        target, target_uid, target_session = actors[2]
        sid = uuid4()
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.app_roles VALUES (%s,'life','Lifecycle')", (tenant,))
            for permission in ('user:profile:edit', 'user:suspend', 'user:reactivate'):
                db.execute("INSERT INTO bri.role_permissions VALUES (%s,'life',%s)", (tenant, permission))
            db.execute("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) "
                       "VALUES (%s,%s,'life','root')", (tenant, admin))
            db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id) VALUES (%s,%s,%s)',
                       (admin, uid, sid))
        stage = create_staged_user_lifecycle_app(
            app_scope=lambda: self.connect('bri_app'), private_socket=self.sock,
            auth_transport=httpx.MockTransport(lambda req: auth_server_response(req, user_id=str(uid))),
        )
        # Whole-second AMR evidence must follow the role change's subsecond cutoff.
        sleep(1.05)
        headers = StagedRoutes.headers(sub=str(uid), session_id=str(sid))
        client = self.enterContext(TestClient(stage, base_url='http://127.0.0.1', client=('127.0.0.1', 50200)))
        path = PATH.format(id=target)
        initial = client.get(path, headers=headers)
        self.assertEqual(initial.status_code, 200, initial.text)
        self.assertEqual(initial.json(), {'id': str(target), 'display_name': None, 'status': 'active', 'role': 'user',
            'version': initial.json()['version'], 'can_edit': True, 'can_suspend': True, 'can_reactivate': False})
        for absent in (foreign[2][0], actors[1][0], uuid4()):
            reply = client.get(PATH.format(id=absent), headers=headers)
            self.assertEqual((reply.status_code, reply.json()), (404, {'detail': 'User not found'}))

        def change(action, reply, **fields):
            payload = {'action': action, 'expected_version': reply.json()['version'], **fields}
            return client.patch(path, json=payload, headers=headers)

        edited = change('edit', initial, display_name='Updated Fixture')
        self.assertEqual(edited.status_code, 200, edited.text)
        self.assertEqual(edited.json()['display_name'], 'Updated Fixture')
        self.assertEqual(change('edit', initial, display_name='Stale').status_code, 409)
        suspended = change('suspend', edited, reason='access_review')
        self.assertEqual(suspended.status_code, 200, suspended.text)
        self.assertEqual(suspended.json()['status'], 'suspended')
        with self.connect('postgres') as db:
            self.assertIsNotNone(db.execute('SELECT revoked_at FROM bri.auth_sessions WHERE session_id=%s',
                                            (target_session,)).fetchone()[0])
        restored = change('reactivate', suspended, reason='review_complete')
        self.assertEqual(restored.status_code, 200, restored.text)
        self.assertEqual(restored.json()['status'], 'active')
        self.assertEqual(client.get(path, headers=headers).json(), restored.json())

        from bri.api.app import ApiSettings, create_app
        from bri.api.authentication import SupabaseTokenVerifier

        connect = self.connect

        class LocalDatabase(Database):
            def _connect(self):
                return connect('bri_app')

        origin = ISSUER.removesuffix('/auth/v1')
        auth = httpx.AsyncClient(transport=httpx.MockTransport(
            lambda req: auth_server_response(req, user_id=str(target_uid)),
        ))
        from asyncio import run

        self.addCleanup(lambda: run(auth.aclose()))
        normal = create_app(
            settings=ApiSettings(environment='hosted-development', auth_mode='supabase', supabase_url=origin),
            database=LocalDatabase(origin, ''), token_verifier=SupabaseTokenVerifier(origin, 'test-only', client=auth),
        )
        normal_client = self.enterContext(TestClient(normal))
        sleep(1.05)
        now, fresh_id = int(time()), str(uuid4())

        def start_session(session_id, totp_at):
            proof = StagedRoutes.headers(sub=str(target_uid), session_id=str(session_id), amr=[
                {'method': 'password', 'timestamp': now}, {'method': 'totp', 'timestamp': totp_at},
            ])
            return normal_client.post('/v1/auth/session', headers=proof)

        self.assertEqual(start_session(fresh_id, now - 60).status_code, 403)
        self.assertEqual(start_session(target_session, now).status_code, 403)
        fresh = start_session(fresh_id, now)
        self.assertEqual(fresh.status_code, 201, fresh.text)
        with self.connect('postgres') as db:
            for action, reply, reason in (('edited', edited, None), ('suspended', suspended, 'access_review'),
                                          ('reactivated', restored, 'review_complete')):
                self.assertEqual(db.execute(
                    'SELECT tenant_id,actor_principal_id,subject_principal_id,event_type,lifecycle_reason '
                    'FROM bri.security_audit_events WHERE request_id=%s AND event_type LIKE %s',
                    (reply.headers['X-Request-ID'], 'tenant.user.lifecycle.%'),
                ).fetchall(), [(tenant, admin, target, f'tenant.user.lifecycle.{action}', reason)])
            db.execute('UPDATE bri.auth_sessions SET revoked_at=now() WHERE session_id=%s', (sid,))
        self.assertEqual(client.get(path, headers=headers).status_code, 403)
