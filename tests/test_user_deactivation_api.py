"""HTTP boundary checks for the isolated A11.5 deactivation stage."""
import os
import unittest
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from time import sleep, time
from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import UUID, uuid4

import httpx
import psycopg
import test_privileged_approvals_pg as pg
from fastapi.testclient import TestClient
from test_authentication import ISSUER, SESSION_ID, USER_ID, auth_server_response, make_token

from bri.access.policy import Principal
from bri.api.app import ApiSettings, create_app
from bri.api.database import Database

PATH = '/v1/users/{id}/deactivation'


class DisabledRoutes(unittest.TestCase):
    def test_hosted_app_denies_before_parsing_authentication_or_database_access(self):
        db, verifier = Mock(), Mock()
        app = create_app(settings=ApiSettings(environment='hosted-development', auth_mode='supabase',
                                             supabase_url=ISSUER.removesuffix('/auth/v1')),
                         database=db, token_verifier=verifier)
        with patch.dict('os.environ', BRI_USER_DEACTIVATION_ENABLED='1'), TestClient(app) as client:
            for method in ('GET', 'PATCH'):
                with self.subTest(method=method):
                    reply = client.request(method, PATH.format(id='private-marker') + '?tenant=other',
                                           content=b'{', headers={'Content-Type': 'application/json',
                                                                   'Authorization': 'Bearer private-marker'})
                    self.assertEqual(reply.status_code, 403)
                    self.assertEqual(reply.headers['Cache-Control'], 'no-store')
                    self.assertNotIn('private-marker', reply.text)
            schema = client.get('/openapi.json').json()
            operations = schema['paths'][PATH]
            body_ref = operations['patch']['requestBody']['content']['application/json']['schema']['$ref']
            body = schema['components']['schemas'][body_ref.rsplit('/', 1)[-1]]
            self.assertEqual(body['properties']['expected_version']['type'], 'string')
            self.assertEqual(set(body['required']), {'expected_version', 'reason'})
            self.assertFalse(body['additionalProperties'])
        self.assertEqual(db.mock_calls, [])
        self.assertEqual(verifier.mock_calls, [])


class StagedRoutes(unittest.TestCase):
    def setUp(self):
        from bri.api.user_deactivation import create_staged_user_deactivation_app

        self.socket = Path(self.enterContext(TemporaryDirectory()))
        self.actor, self.target = uuid4(), uuid4()
        self.path = PATH.format(id=self.target)
        self.authority = ('tenant-a', self.actor, UUID(SESSION_ID), ISSUER, self.target)
        self.body = {'expected_version': '9007199254740993', 'reason': 'account_closed'}
        self.admin = Principal(str(self.actor), frozenset({'tenant-a'}), (), (('tenant-a', 'admin'),))
        self.resolve = self.enterContext(patch.object(Database, 'resolve_authenticated_principal',
                                                       return_value=self.admin))
        self.active = self.enterContext(patch.object(Database, 'auth_session_is_active', return_value=True))
        self.info = {'host': str(self.socket), 'hostaddr': '', 'port': 5432, 'dbname': 'postgres',
                     'user': 'bri_app', 'transaction_status': psycopg.pq.TransactionStatus.IDLE}
        self.autocommit, self.role_ok = False, True
        self.row, self.error, self.commit_error = (9007199254740994, 'deactivated'), None, None
        self.events, self.commands, self.auth_calls = [], [], []
        self.factors = None
        self.stage = create_staged_user_deactivation_app(
            app_scope=self.scope, private_socket=self.socket, auth_transport=httpx.MockTransport(self.auth),
        )
        self.client = self.enterContext(TestClient(self.stage, base_url='http://127.0.0.1',
                                                   client=('127.0.0.1', 50200)))

    def auth(self, request):
        self.auth_calls.append((request.method, str(request.url)))
        return auth_server_response(request, factors=self.factors)

    @contextmanager
    def scope(self):
        @contextmanager
        def transaction():
            self.events.append('begin')
            try:
                yield
                if self.commit_error:
                    self.events.append('commit_failed')
                    raise self.commit_error('private-marker')
            except Exception:
                self.events.append('rollback')
                raise
            else:
                self.events.append('commit')

        def execute(query, params=()):
            self.events.append((query, params))
            row = (self.role_ok,)
            if 'bri.read_user_deactivation(' in query or 'bri.deactivate_user_account(' in query:
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

    def change(self, headers=None, body=None):
        return self.client.patch(self.path, json=self.body if body is None else body,
                                 headers=self.headers() if headers is None else headers)

    def test_write_binds_exact_authority_and_responds_after_commit(self):
        stamp = int(time()) - 10
        headers = {**self.headers(amr=[{'method': 'totp', 'timestamp': stamp}]),
                   'X-Request-ID': str(self.target)}
        reply = self.change(headers)
        self.assertEqual(reply.status_code, 200, reply.text)
        self.assertEqual(reply.json(), {'version': '9007199254740994', 'status': 'deactivated'})
        self.assertEqual(reply.headers['Cache-Control'], 'no-store')
        self.assertEqual(self.auth_calls, [('GET', f'{ISSUER}/user')])
        self.resolve.assert_called_once_with(USER_ID, ISSUER, USER_ID)
        self.active.assert_called_once_with(USER_ID, SESSION_ID)
        [(query, params)] = self.commands
        self.assertIn('bri.deactivate_user_account(', query)
        cid = UUID(reply.headers['X-Request-ID'])
        self.assertNotEqual(cid, self.target)
        self.assertEqual(params, (*self.authority, 9007199254740993, 'account_closed',
                                  datetime.fromtimestamp(stamp, UTC), cid))
        self.assertEqual(self.events[0:2], ['begin', ('SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ WRITE', ())])
        self.assertIn('current_user', self.events[2][0])
        self.assertEqual(self.events[3], ("SELECT set_config('bri.tenant_id',%s,true),"
                                          "set_config('bri.auth_user_id',%s,true)", ('tenant-a', USER_ID)))
        self.assertEqual(self.events[4:], [(query, params), 'commit'])

    def test_read_needs_no_step_up_and_uses_a_read_only_transaction(self):
        self.row = (9223372036854775807, 'suspended')
        stale = [{'method': 'totp', 'timestamp': int(time()) - 901}]
        reply = self.client.get(self.path, headers=self.headers(amr=stale))
        self.assertEqual((reply.status_code, reply.json()),
                         (200, {'version': '9223372036854775807', 'status': 'suspended'}))
        self.assertEqual(reply.headers['Cache-Control'], 'no-store')
        [(query, args)] = self.commands
        self.assertIn('bri.read_user_deactivation(', query)
        self.assertEqual(args, self.authority)
        self.assertEqual(self.events[1], ('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY', ()))

    def test_invalid_input_never_reaches_verifier_or_database(self):
        for value in (True, None, 1, 1.0, '', '-1', '+1', '00', '01', '1\n', ' 1', '1.0', '1e2', '１',
                      '9223372036854775808', '9' * 25):
            with self.subTest(value=value):
                reply = self.change(body={**self.body, 'expected_version': value})
                self.assertEqual(reply.status_code, 422)
        for fields in ({'totp_at': 'private-marker'}, {'reason': 'private-marker'}, {'actor': str(self.actor)},
                       {'session_id': SESSION_ID}, {'tenant_id': 'tenant-a'}, {'status': 'deactivated'}):
            reply = self.change(body={**self.body, **fields})
            self.assertEqual(reply.status_code, 422)
            self.assertNotIn('private-marker', reply.text)
        for raw in (b'{', b'\xff', b'null', b'[]', b'{"reason":"account_closed"}',
                    b'{"expected_version":"1","reason":"access_review","expected_version":"2"}'):
            self.assertEqual(self.client.patch(self.path, content=raw,
                                               headers={'Content-Type': 'application/json'}).status_code, 422)
        self.assertEqual(self.client.patch(self.path, content=b'{}').status_code, 415)
        self.assertEqual(self.client.patch(self.path, content=iter([b' ' * 3000] * 2),
                                           headers={'Content-Type': 'application/json'}).status_code, 413)
        self.assertEqual(self.client.request('GET', self.path, content=b'{}').status_code, 400)
        self.assertEqual(self.client.get(PATH.format(id='private-marker')).status_code, 422)
        self.assertEqual((self.auth_calls, self.events), ([], []))

    def test_write_requires_provider_verified_recent_totp_not_client_claims(self):
        now = int(time())
        for stamp in (now - 901, now + 60, str(now), None):
            amr = [{'method': 'totp', 'timestamp': stamp}]
            headers = {**self.headers(iat=now, amr=amr, totp_authenticated_at=now), 'X-TOTP-At': str(now)}
            self.assertEqual(self.change(headers).status_code, 403)
        # The shared verifier rejects a bearer without verified TOTP enrollment/assurance.
        self.assertEqual(self.change(self.headers(aal='aal1', amr=[])).status_code, 401)
        self.factors = [{'factor_type': 'totp', 'status': 'unverified'}]
        self.assertEqual(self.change().status_code, 401)
        self.assertEqual(self.commands, [])

    def test_both_methods_fail_closed_without_verified_current_single_tenant_admin(self):
        def assert_requests(code, headers):
            self.assertEqual(self.client.get(self.path, headers=headers).status_code, code)
            self.assertEqual(self.change(headers).status_code, code)

        for auth in ({}, {'Authorization': 'Bearer private-marker'}, self.headers(iss='https://invalid.example')):
            assert_requests(401, auth)
        self.resolve.assert_not_called()
        for actor, active in (
            (None, True), (self.admin, False),
            (Principal(str(self.actor), frozenset({'tenant-a'}), (), (('tenant-a', 'superuser'),)), True),
            (Principal(str(self.actor), frozenset({'tenant-a'}), (), (('tenant-a', 'admin'),), True), True),
            (Principal(str(self.actor), frozenset({'tenant-a', 'tenant-b'}), (), (('tenant-a', 'admin'),)), True),
        ):
            self.resolve.return_value, self.active.return_value = actor, active
            assert_requests(403, self.headers())
        self.assertEqual(self.events, [])

    def test_private_stage_rejects_proxy_and_browser_authority_before_auth(self):
        for headers, code in (({'Forwarded': 'for=127.0.0.1'}, 403), ({'Host': 'localhost'}, 403),
                              ({'X-Dev-Identity': 'admin'}, 400), ({'X-BRI-Tenant-Context': 'tenant-a'}, 400)):
            reply = self.change({**self.headers(), **headers})
            self.assertEqual(reply.status_code, code)
        self.assertEqual(self.client.get(self.path + '?tenant=tenant-a', headers=self.headers()).status_code, 400)
        with TestClient(self.stage, base_url='http://127.0.0.1', client=('192.0.2.1', 50200)) as remote:
            self.assertEqual(remote.get(self.path, headers=self.headers()).status_code, 403)
        self.assertEqual((self.auth_calls, self.events), ([], []))

    def test_stage_requires_private_socket_mock_auth_and_restricted_database(self):
        from bri.api.user_deactivation import create_staged_user_deactivation_app

        for fields in ({'user': 'postgres'}, {'host': '127.0.0.1'}, {'hostaddr': '127.0.0.1'}, {'port': 5433},
                       {'dbname': 'other'}, {'transaction_status': psycopg.pq.TransactionStatus.INTRANS}):
            with patch.dict(self.info, fields):
                self.assertEqual(self.change().status_code, 503)
        self.autocommit = True
        self.assertEqual(self.change().status_code, 503)
        self.assertEqual(self.events, [])
        self.autocommit, self.role_ok = False, False
        self.assertEqual(self.change().status_code, 503)
        self.assertEqual(self.commands, [])

        with httpx.HTTPTransport() as transport, self.assertRaises(ValueError):
            create_staged_user_deactivation_app(app_scope=self.scope, private_socket=self.socket,
                                                auth_transport=transport)  # type: ignore[arg-type] -- rejected at runtime
        self.socket.chmod(0o755)
        with self.assertRaises(ValueError):
            create_staged_user_deactivation_app(app_scope=self.scope, private_socket=self.socket,
                                                auth_transport=httpx.MockTransport(self.auth))

    def test_database_failures_roll_back_and_map_without_diagnostics(self):
        for error, code, detail in (
            (psycopg.errors.InsufficientPrivilege, 403, 'User deactivation denied'),
            (psycopg.errors.SerializationFailure, 409, 'User deactivation version is stale'),
            (psycopg.errors.ObjectNotInPrerequisiteState, 409, 'User deactivation state conflict'),
            (psycopg.errors.InvalidParameterValue, 422, 'Invalid user deactivation request'),
            (psycopg.OperationalError, 503, 'User deactivation service unavailable'),
        ):
            self.error = error
            reply = self.change()
            self.assertEqual((reply.status_code, reply.json()), (code, {'detail': detail}))
            self.assertEqual(reply.headers['Cache-Control'], 'no-store')
            self.assertEqual(self.events[-1], 'rollback')
        self.assertNotIn('commit', self.events)
        self.error, self.row = None, None
        for reply in (self.client.get(self.path, headers=self.headers()), self.change()):
            self.assertEqual((reply.status_code, reply.json()), (404, {'detail': 'User not found'}))
            self.assertEqual(reply.headers['Cache-Control'], 'no-store')

    def test_commit_failure_cannot_return_projected_success(self):
        self.commit_error = psycopg.OperationalError
        reply = self.change()
        self.assertEqual((reply.status_code, reply.json()), (503, {'detail': 'User deactivation service unavailable'}))
        self.assertEqual(len(self.commands), 1)
        self.assertEqual(self.events[-2:], ['commit_failed', 'rollback'])


@unittest.skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16')
class StagedPostgres(unittest.TestCase):
    sock: Path
    connect = classmethod(pg.ApprovalDatabase.connect.__func__)

    @classmethod
    def setUpClass(cls):
        with patch.dict(os.environ, BRI_APPROVAL_PG_BIN=os.environ['BRI_TEST_PG_BIN']):
            pg.ApprovalDatabase.setUpClass.__func__(cls)
        routines = ('bri.read_user_deactivation(text,uuid,uuid,text,uuid)',
                    'bri.deactivate_user_account(text,uuid,uuid,text,uuid,bigint,text,timestamptz,uuid)')
        with cls.connect('bri_app') as db:
            for routine in routines:
                assert db.execute("SELECT has_function_privilege(current_user,%s,'EXECUTE')",
                                  (routine,)).fetchone() == (False,), routine
        with cls.connect('postgres') as db:
            db.execute('INSERT INTO bri.provider_event_source(issuer) VALUES (%s)', (ISSUER,))
            for routine in routines:
                db.execute(f'GRANT EXECUTE ON FUNCTION {routine} TO bri_app')

    def test_stage_conflict_rollback_and_committed_deactivation(self):
        from bri.api.user_deactivation import create_staged_user_deactivation_app

        tenant, actors = pg.seed_approval_tenant(self.connect)
        _, foreign = pg.seed_approval_tenant(self.connect)
        admin, uid, _ = actors[0]
        target, _, target_session = actors[2]
        sid = uuid4()
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.role_permissions VALUES (%s,'reset','user:deactivate')", (tenant,))
            db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                       'VALUES (%s,%s,%s,clock_timestamp())', (admin, uid, sid))
            db.execute('''
                CREATE FUNCTION bri.fixture_reject_deactivation_commit() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN RAISE EXCEPTION 'private-marker'; END; $$;
                CREATE CONSTRAINT TRIGGER fixture_reject_deactivation_commit AFTER UPDATE ON bri.auth_principals
                    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
                    WHEN (NEW.status = 'deactivated') EXECUTE FUNCTION bri.fixture_reject_deactivation_commit();
            ''')
        # Provider AMR uses whole seconds; the preceding role change may advance
        # the cutoff with subsecond precision.
        sleep(1.05)
        stage = create_staged_user_deactivation_app(
            app_scope=lambda: self.connect('bri_app'), private_socket=self.sock,
            auth_transport=httpx.MockTransport(lambda req: auth_server_response(req, user_id=str(uid))),
        )
        client = self.enterContext(TestClient(stage, base_url='http://127.0.0.1', client=('127.0.0.1', 50200)))
        headers = StagedRoutes.headers(sub=str(uid), session_id=str(sid))
        path = PATH.format(id=target)
        before = client.get(path, headers=headers)
        self.assertEqual(before.status_code, 200, before.text)
        initial = before.json()
        self.assertEqual(initial['status'], 'active')
        for absent in (admin, actors[1][0], actors[3][0], foreign[2][0], uuid4()):
            reply = client.get(PATH.format(id=absent), headers=headers)
            self.assertEqual((reply.status_code, reply.json()), (404, {'detail': 'User not found'}))

        body = {'expected_version': initial['version'], 'reason': 'policy_violation'}
        self.assertEqual(client.patch(path, headers=headers, json={**body, 'reason': 'private-marker'}).status_code, 422)
        stale = client.patch(path, headers=headers, json={**body, 'expected_version': str(int(initial['version']) + 1)})
        self.assertEqual((stale.status_code, stale.json()), (409, {'detail': 'User deactivation version is stale'}))
        failure = client.patch(path, headers=headers, json=body)
        self.assertEqual((failure.status_code, failure.json()), (503, {'detail': 'User deactivation service unavailable'}))
        self.assertEqual(client.get(path, headers=headers).json(), initial)

        def observe(correlation):
            with self.connect('postgres') as db:
                revoked = db.execute('SELECT revoked_at IS NOT NULL FROM bri.auth_sessions WHERE session_id=%s',
                                     (target_session,)).fetchone()
                audit = db.execute('SELECT tenant_id,actor_principal_id,subject_principal_id,lifecycle_reason '
                                   'FROM bri.security_audit_events WHERE request_id=%s '
                                   "AND event_type='tenant.user.lifecycle.deactivated'", (correlation,)).fetchall()
                return revoked, audit

        self.assertEqual(observe(failure.headers['X-Request-ID']), ((False,), []))
        with self.connect('postgres') as db:
            db.execute('DROP TRIGGER fixture_reject_deactivation_commit ON bri.auth_principals')
        success = client.patch(path, headers=headers, json=body)
        self.assertEqual(success.status_code, 200, success.text)
        updated = success.json()
        # The lifecycle revision is a CAS token, not a promised +1 increment.
        self.assertEqual(updated, {'version': str(int(updated['version'])), 'status': 'deactivated'})
        self.assertGreater(int(updated['version']), int(initial['version']))
        self.assertEqual(observe(success.headers['X-Request-ID']),
                         ((True,), [(tenant, admin, target, body['reason'])]))
        self.assertEqual(client.get(path, headers=headers).json(), updated)
        conflict = client.patch(path, headers=headers, json={**body, 'expected_version': updated['version']})
        self.assertEqual((conflict.status_code, conflict.json()), (409, {'detail': 'User deactivation state conflict'}))
