"""A11.2 fixture-only HTTP/worker checks, optionally on disposable PostgreSQL."""
import json
import os
import time
import unittest
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
from uuid import UUID, uuid4

import httpx
import psycopg
import test_user_provisioning_postgres as pg
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


class DisabledRoutes(unittest.TestCase):
    def test_normal_mount_disables_every_route_before_parsing(self):
        from bri.api.user_provisioning import PREFIX, create_user_provisioning_router

        app = FastAPI()
        app.include_router(create_user_provisioning_router())
        with TestClient(app) as client:
            for method, path in [('POST', PREFIX), ('GET', f'{PREFIX}/{uuid4()}'),
                                 ('POST', f'{PREFIX}/activate')]:
                response = client.request(method, path, content=b'{', headers={
                    'Content-Type': 'application/json',
                })
                self.assertEqual(response.status_code, 403)
                self.assertEqual(response.headers['Cache-Control'], 'no-store')


class WorkerTests(unittest.TestCase):
    def test_ambiguous_invitation_is_quarantined_and_only_read_only_proof_reconciles(self):
        from test_authentication import ISSUER

        from bri.api.provider_provisioning import (
            FixtureInvitationProvider,
            ProvisioningWorker,
        )

        key, assigned = uuid4(), uuid4()
        calls, operations = [], []
        state, in_transaction = 'pending_setup', False

        def command(request_key, action, issuer, provider_user, correlation):
            nonlocal state, in_transaction
            self.assertEqual((request_key, issuer), (key, ISSUER))
            self.assertFalse(in_transaction)
            in_transaction = True
            try:
                calls.append((action, provider_user, correlation))
                if action == 'CLAIM':
                    if state != 'pending_setup':
                        return None
                    state = 'inviting'
                    return (key, state, 'person@example.test')
                state = {'UNRESOLVED': 'invitation_unresolved',
                         'RECONCILED_INVITED': 'invitation_sent'}[action]
                return (key, state, None)
            finally:
                in_transaction = False

        def transport(request):
            self.assertFalse(in_transaction)
            operations.append((request.method, request.url.path))
            if request.method == 'POST':
                self.assertEqual(state, 'inviting')
                self.assertEqual(json.loads(request.content)['email'], 'person@example.test')
                raise httpx.ReadTimeout('opaque provider error')
            self.assertEqual(state, 'invitation_unresolved')
            return httpx.Response(200, json={
                'issuer': ISSUER, 'operation': str(key), 'attempt': str(calls[0][2]),
                'outcome': 'invited', 'provider_user': str(assigned),
            })

        worker = ProvisioningWorker(command, FixtureInvitationProvider(httpx.MockTransport(transport)))
        first = worker.dispatch(key)
        assert first is not None
        self.assertEqual(first.status, 'invitation_unresolved')
        self.assertEqual(calls[1], ('UNRESOLVED', None, calls[0][2]))
        self.assertIsNone(worker.dispatch(key))
        reconciled = worker.reconcile(key, first.attempt_id)
        assert reconciled is not None
        self.assertEqual(reconciled.status, 'invitation_sent')
        self.assertEqual(calls[-1], ('RECONCILED_INVITED', assigned, first.attempt_id))
        self.assertEqual([method for method, _ in operations], ['POST', 'GET'])

    def test_retry_requires_exact_no_effect_proof_and_uses_new_fence(self):
        from bri.api.provider_provisioning import (
            FixtureInvitationProvider,
            ProvisioningWorker,
        )

        operation, provider_uid = uuid4(), uuid4()
        calls = []

        def command(key, action, issuer, uid, attempt):
            self.assertEqual((key, issuer), (operation, ISSUER))
            calls.append((action, uid, attempt))
            if action == 'CLAIM':
                return (operation, 'inviting', 'fixture@example.test')
            return (operation, {'RETRYABLE': 'invitation_retryable', 'INVITED': 'invitation_sent',
                                'UNRESOLVED': 'invitation_unresolved'}[action], None)

        def fixture(request):
            return httpx.Response(200, json={
                'issuer': ISSUER, 'operation': str(operation), 'attempt': request.url.path.split('/')[-1],
                **outcome,
            })

        outcome = {'outcome': 'confirmed_no_effect'}
        worker = ProvisioningWorker(command, FixtureInvitationProvider(httpx.MockTransport(fixture)))
        retryable = worker.dispatch(operation)
        assert retryable is not None
        self.assertEqual(retryable.status, 'invitation_retryable')
        self.assertEqual(calls[-1], ('RETRYABLE', None, retryable.attempt_id))
        outcome = {'outcome': 'invited', 'provider_user': str(provider_uid)}
        sent = worker.dispatch(operation)
        assert sent is not None
        self.assertNotEqual(sent.attempt_id, retryable.attempt_id)
        self.assertEqual(calls[-2:], [('CLAIM', None, sent.attempt_id), ('INVITED', provider_uid, sent.attempt_id)])

        for change in ({'issuer': ISSUER + '/wrong'}, {'operation': str(uuid4())}, {'attempt': str(uuid4())},
                       {'provider_user': None}, {'provider_user': str(UUID(int=0))}, {'email': 'fixture@example.test'}):
            with self.subTest(change=change):
                outcome = {'outcome': 'invited', 'provider_user': str(provider_uid), **change}
                result = worker.dispatch(operation)
                assert result is not None
                self.assertEqual(result.status, 'invitation_unresolved')
                self.assertEqual(calls[-1], ('UNRESOLVED', None, result.attempt_id))
                self.assertIsNone(worker.reconcile(operation, result.attempt_id))

    def test_duplicate_provider_proof_field_cannot_authorize_safe_retry(self):
        from bri.api.provider_provisioning import FixtureInvitationProvider

        key, attempt = uuid4(), uuid4()
        evidence = json.dumps({'issuer': ISSUER, 'operation': str(key), 'attempt': str(attempt),
                               'outcome': 'confirmed_no_effect'})
        conflicting = '{"outcome":"invited",' + evidence[1:]
        transport = httpx.MockTransport(lambda _: httpx.Response(200, content=conflicting))
        self.assertEqual(FixtureInvitationProvider(transport).invite(key, attempt, 'fixture@example.test').outcome,
                         'unresolved')


class StagedRoutes(unittest.TestCase):
    def setUp(self):
        from bri.api.user_provisioning import (
            PREFIX,
            create_staged_user_provisioning_app,
        )

        self.prefix = PREFIX
        self.key, self.actor, self.invitee = uuid4(), uuid4(), uuid4()
        self.body = {'request_id': str(self.key), 'display_name': 'Fixture User',
                     'email': 'fixture@example.test'}
        self.sql, self.auth_calls = [], []
        self.principal = Principal(str(self.actor), frozenset({'tenant-a'}), (),
                                   (('tenant-a', 'admin'),))
        self.session = True
        self.activate_match = True
        self.socket = Path(self.enterContext(TemporaryDirectory()))

        def verified_user(request):
            self.assertEqual(request.url.path, '/auth/v1/user')
            token = request.headers['authorization'][7:]
            self.auth_calls.append(token)
            return auth_server_response(request, user_id=self.tokens.get(token, ''))

        def no_provider(_):
            self.fail('HTTP routes must never send or reconcile an invitation')

        self.tokens = {}
        self.app = create_staged_user_provisioning_app(
            app_scope=lambda: self.scope('bri_app'),
            worker_scope=lambda: self.scope('bri_provision_worker'),
            activator_scope=lambda: self.scope('bri_provision_activator'),
            private_socket=self.socket, auth_transport=httpx.MockTransport(verified_user),
            invite_transport=httpx.MockTransport(no_provider),
        )
        self.client = self.enterContext(TestClient(
            self.app, base_url='http://127.0.0.1', client=('127.0.0.1', 50400),
        ))
        self.resolve = self.enterContext(patch.object(Database, 'resolve_authenticated_principal',
            side_effect=lambda uid, *_: self.principal if uid == USER_ID else None))
        self.is_active = self.enterContext(patch.object(Database, 'auth_session_is_active',
            side_effect=lambda *_: self.session))

    @contextmanager
    def scope(self, role):
        def execute(query, params=()):
            self.sql.append((role, query, params))
            row = (True,)
            if 'request_user_provisioning' in query or 'status_user_provisioning' in query:
                row = (self.key, 'pending_setup', 'unprojected fixture data')
            if 'activate_user_provisioning' in query:
                if not self.activate_match:
                    raise psycopg.errors.InsufficientPrivilege('private provider info')
                row = (self.key, 'active')
            return SimpleNamespace(fetchone=lambda: row)

        yield SimpleNamespace(
            info=SimpleNamespace(user=role, host=str(self.socket), port=5432, dbname='postgres',
                                 transaction_status=psycopg.pq.TransactionStatus.IDLE),
            execute=execute, transaction=self.transaction,
        )

    @staticmethod
    @contextmanager
    def transaction():
        yield

    def headers(self, uid=USER_ID, **claims):
        token = make_token(sub=uid, **claims)
        self.tokens[token] = uid
        return {'Authorization': f'Bearer {token}'}

    def test_request_and_status_bind_server_authority_and_slim_response(self):
        headers = self.headers()
        reply = self.client.post(self.prefix, json=self.body, headers=headers)
        self.assertEqual(reply.status_code, 200, reply.text)
        self.assertEqual(reply.json(), {'id': str(self.key), 'status': 'pending_setup'})
        self.assertEqual(reply.headers['Cache-Control'], 'no-store')
        self.assertEqual(self.is_active.call_args.args, (USER_ID, SESSION_ID))
        self.assertEqual(self.resolve.call_args.args, (USER_ID, ISSUER, USER_ID))
        request = next(command for command in self.sql if 'request_user_provisioning' in command[1])
        self.assertTrue(any('bri.auth_user_id' in query and params == ('tenant-a', USER_ID)
                            for _, query, params in self.sql))
        self.assertEqual(request[0], 'bri_app')
        self.assertEqual(request[2][:4], ('tenant-a', self.actor, UUID(SESSION_ID), ISSUER))
        self.assertEqual(request[2][5:], (self.key, 'Fixture User', 'fixture@example.test',
                                          UUID(reply.headers['X-Request-ID'])))
        now = int(time.time())
        stale = self.headers(amr=[{'method': 'totp', 'timestamp': now - 901},
                                  {'method': 'password', 'timestamp': now - 902}])
        denied = self.client.post(self.prefix, json=self.body, headers=stale)
        self.assertEqual(denied.status_code, 403)
        self.assertEqual(sum('request_user_provisioning' in query for _, query, _ in self.sql), 1)
        status = self.client.get(f'{self.prefix}/{self.key}', headers=stale)
        self.assertEqual(status.json(), reply.json())
        self.session = False
        self.assertEqual(self.client.get(f'{self.prefix}/{self.key}', headers=headers).status_code, 403)
        self.assertEqual(sum('status_user_provisioning' in query for _, query, _ in self.sql), 1)

    def test_activation_uses_verified_subject_not_email_and_no_bri_session(self):
        self.session = False
        path = f'{self.prefix}/activate'
        self.assertEqual(self.client.post(path, headers=self.headers()).status_code, 403)
        self.assertFalse(any('activate_user_provisioning' in query for _, query, _ in self.sql))
        headers = self.headers(str(self.invitee), email=self.body['email'])
        self.activate_match = False
        denied = self.client.post(path, headers=headers)
        self.assertEqual(denied.status_code, 403)
        self.assertNotIn('private provider info', denied.text)
        self.activate_match = True
        reply = self.client.post(path, headers=headers)
        self.assertEqual(reply.status_code, 200, reply.text)
        self.assertEqual(reply.json(), {'id': str(self.key), 'status': 'active'})
        self.is_active.assert_not_called()
        role, _, params = self.sql[-1]
        self.assertEqual(role, 'bri_provision_activator')
        self.assertEqual(params[:2], (ISSUER, self.invitee))
        self.assertEqual(params[4], UUID(reply.headers['X-Request-ID']))

    def test_rejects_remote_peer_proxy_and_browser_selected_authority(self):
        headers = self.headers()
        for client, extra, suffix, code in (
            (self.client, {'Forwarded': 'for=127.0.0.1'}, '', 403),
            (self.client, {'Host': 'other.invalid'}, '', 403),
            (self.client, {'X-Tenant-ID': 'tenant-b'}, '', 400),
            (self.client, {}, '?tenant=tenant-b', 400),
            (self.enterContext(TestClient(self.app, base_url='http://127.0.0.1',
                                          client=('192.0.2.2', 50123))), {}, '', 403),
            (self.enterContext(TestClient(self.app, base_url='http://192.0.2.2',
                                          client=('127.0.0.1', 50123))), {'Host': '127.0.0.1'}, '', 403),
        ):
            with self.subTest(extra=extra, suffix=suffix, code=code):
                response = client.post(self.prefix + suffix, json=self.body, headers={**headers, **extra})
                self.assertEqual(response.status_code, code)
        self.assertEqual(self.auth_calls, [])
        self.assertEqual(self.sql, [])

    def test_bounded_strict_input_and_sanitized_errors(self):
        headers = {**self.headers(), 'Content-Type': 'application/json'}
        payload = json.dumps(self.body).encode()
        for path, body, code in (
            (self.prefix, b'{"email":"private-marker",' + payload[1:], 422),
            (self.prefix, json.dumps({**self.body, 'role': 'private-marker'}).encode(), 422),
            (self.prefix, json.dumps({**self.body, 'tenant_id': 'private-marker'}).encode(), 422),
            (self.prefix, b'private-marker' * 500, 413),
            (f'{self.prefix}/activate', b'{}', 400),
        ):
            response = self.client.post(path, content=body, headers=headers)
            self.assertEqual(response.status_code, code)
            self.assertNotIn('private-marker', response.text)
        streamed = self.client.post(self.prefix, content=iter([b' ' * 3000, b' ' * 3000]), headers=headers)
        self.assertEqual(streamed.status_code, 413)
        self.assertEqual(self.client.get(f'{self.prefix}/private-marker', headers=headers).json(),
                         {'detail': 'Invalid provisioning request'})
        self.assertEqual(self.auth_calls, [])
        self.assertEqual(self.sql, [])

    def test_verified_invitee_needs_password_evidence_not_recovery_claim(self):
        now = int(time.time())
        headers = self.headers(str(self.invitee), amr=[{'method': 'totp', 'timestamp': now},
                                                       {'method': 'recovery', 'timestamp': now}])
        response = self.client.post(f'{self.prefix}/activate', headers=headers)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(len(self.auth_calls), 1)
        self.assertEqual(self.sql, [])


@unittest.skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16')
class StagedPostgres(unittest.TestCase):
    connect = classmethod(pg.UserProvisioningTests.connect.__func__)
    setUpClass = classmethod(pg.UserProvisioningTests.setUpClass.__func__)
    setUp = pg.UserProvisioningTests.setUp
    grant = pg.UserProvisioningTests.grant

    def test_mock_invitation_and_bodyless_activation_with_real_restricted_roles(self):
        from bri.api.user_provisioning import (
            PREFIX,
            create_staged_user_provisioning_app,
        )

        _, admin_uid, session_id = self.actor
        assigned = uuid4()
        tokens, calls = {}, []

        def auth(request):
            return auth_server_response(request, user_id=tokens[request.headers['authorization'][7:]])

        def token(uid, **claims):
            bearer = make_token(sub=str(uid), **claims)
            tokens[bearer] = str(uid)
            return {'Authorization': f'Bearer {bearer}'}

        def invitation(request):
            parts = request.url.path.split('/')
            operation, attempt = parts[-3], parts[-1]
            self.assertEqual((request.method, json.loads(request.content)), ('POST', {'email': pg.EMAIL}))
            # An independent connection sees the committed CLAIM before fixture I/O.
            with self.connect('postgres') as db:
                self.assertEqual(db.execute(
                    'SELECT status,attempt_id FROM bri.user_provisioning WHERE principal_id=%s',
                    (operation,),
                ).fetchone(), ('inviting', UUID(attempt)))
            calls.append(attempt)
            return httpx.Response(200, json={'issuer': ISSUER, 'operation': operation,
                                  'attempt': attempt, 'outcome': 'invited', 'provider_user': str(assigned)})

        stage = create_staged_user_provisioning_app(
            app_scope=lambda: self.connect('bri_app'),
            worker_scope=lambda: self.connect('bri_provision_worker'),
            activator_scope=lambda: self.connect('bri_provision_activator'),
            private_socket=self.sock, auth_transport=httpx.MockTransport(auth),
            invite_transport=httpx.MockTransport(invitation),
        )
        client = self.enterContext(TestClient(stage, base_url='http://127.0.0.1',
                                             client=('127.0.0.1', 50400)))
        # Seeded permission changes cut off prior authentication evidence.
        # Advance past their subsecond timestamps before issuing a fixture AMR.
        time.sleep(1.05)
        admin = token(admin_uid, session_id=str(session_id))
        payload = {'request_id': str(self.key), 'display_name': 'Fixture User', 'email': pg.EMAIL}
        request = client.post(PREFIX, json=payload, headers=admin)
        self.assertEqual(request.status_code, 200, request.text)
        operation = UUID(request.json()['id'])
        self.assertNotEqual(operation, self.key)
        self.assertEqual(calls, [])
        self.assertEqual(request.json()['status'], 'pending_setup')
        self.assertEqual(client.get(f'{PREFIX}/{self.key}', headers=admin).json(), request.json())
        self.assertIsNone(stage.state.provisioning_worker.dispatch(self.key))
        self.assertEqual(stage.state.provisioning_worker.dispatch(operation).status, 'invitation_sent')
        self.assertIsNone(stage.state.provisioning_worker.dispatch(operation))
        self.assertEqual(len(calls), 1)

        # Whole-second AMR events must be strictly later than the subsecond CLAIM.
        time.sleep(1.05)
        self.assertEqual(client.post(f'{PREFIX}/activate', headers=token(uuid4(), email=pg.EMAIL)).status_code, 404)
        reply = client.post(f'{PREFIX}/activate', headers=token(assigned, session_id=str(uuid4())))
        self.assertEqual(reply.status_code, 200, reply.text)
        self.assertEqual(reply.json(), {'id': str(operation), 'status': 'active'})
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT count(*) FROM bri.auth_sessions WHERE principal_id=%s',
                                        (operation,)).fetchone(), (0,))
