"""A12 private intake and published-read acceptance with synthetic CSV and mocked provider."""
import os
import unittest
from contextlib import contextmanager
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch
from uuid import UUID, uuid4

import httpx
import psycopg
import test_csv_intake_postgres as pg
from fastapi.testclient import TestClient
from test_authentication import ISSUER, SESSION_ID, USER_ID, auth_server_response, make_token

from bri.access.policy import AccessGrant, Principal
from bri.api.database import Database


class StagedCsvTests(unittest.TestCase):
    def setUp(self):
        from bri.api.csv_intake import PREFIX, create_staged_csv_intake_app

        self.prefix = PREFIX
        self.socket = Path(self.enterContext(TemporaryDirectory()))
        self.actor, self.job, self.key = uuid4(), uuid4(), uuid4()
        self.proposal = f'csv:{self.job}'
        self.state = 'creating'
        self.objects, self.sql, self.auth = [], [], []
        self.token = make_token()
        self.headers = {'Authorization': f'Bearer {self.token}', 'Content-Type': 'text/csv',
                        'X-Node-ID': 'fixture-node', 'Idempotency-Key': str(self.key)}
        self.person = Principal(str(self.actor), frozenset({'fixture-tenant'}), (
            AccessGrant('fixture-tenant', 'source:submit', 'fixture-node'),
        ), (('fixture-tenant', 'user'),))
        self.active = True
        self.commit_failure = False
        self.fail_install = False
        self.claim = None
        self.completion = 'proposed'
        self.role_valid = True
        self.resolve = self.enterContext(patch.object(Database, 'resolve_authenticated_principal',
                                                      side_effect=lambda *_: self.person))
        self.enterContext(patch.object(Database, 'auth_session_is_active', side_effect=lambda *_: self.active))
        self.app = create_staged_csv_intake_app(
            identity_scope=lambda: self.scope('bri_app'), intake_scope=lambda: self.scope('bri_csv_intake'),
            worker_scope=lambda: self.scope('bri_csv_worker'), private_socket=self.socket,
            auth_transport=httpx.MockTransport(self.provider),
            store=SimpleNamespace(install=self.put, read_verified=self.read_object),
        )
        self.client = self.enterContext(TestClient(self.app, base_url='http://127.0.0.1',
                                                   client=('127.0.0.1', 50400)))

    def provider(self, req):
        self.auth.append(req.url.path)
        return auth_server_response(req, user_id=USER_ID if req.headers['authorization'] == self.headers['Authorization'] else '')

    def put(self, tenant, key, content):
        self.assertEqual(tenant, 'fixture-tenant')
        self.assertEqual(self.sql[-1], ('committed', 'bri_csv_intake'))
        if self.fail_install:
            raise OSError('private-marker')
        self.objects.append((key, content))

    def read_object(self, tenant, key, digest, count):
        from bri.ingestion.csv_intake import CsvIntakeError, IntakeReason

        self.assertEqual(self.sql[-1], ('committed', 'bri_csv_worker'))
        self.assertEqual((tenant, key), ('fixture-tenant', 'private-object-key'))
        if not self.objects:
            raise CsvIntakeError(IntakeReason.STORAGE_MISSING)
        payload = self.objects[-1][1]
        self.assertEqual((digest, count), (sha256(payload).hexdigest(), len(payload)))
        return payload

    @contextmanager
    def scope(self, role):
        yield SimpleNamespace(
            info=SimpleNamespace(host=str(self.socket), port=5432, dbname='postgres', user=role,
                                 transaction_status=psycopg.pq.TransactionStatus.IDLE),
            transaction=lambda: self.transaction(role),
            execute=lambda query, args=(): self.execute(role, query, args),
        )

    @contextmanager
    def transaction(self, role):
        yield
        if self.commit_failure:
            raise psycopg.OperationalError('private-marker')
        self.sql.append(('committed', role))

    def execute(self, role, query, args):
        self.sql.append((role, query, args))
        row = (self.role_valid,)
        if 'bri.csv_submit(' in query:
            row = self.job, self.state, 'private-object-key'
        if 'bri.csv_mark_ready(' in query:
            self.state = 'ready'
        if 'bri.csv_mark_ready(' in query or 'bri.csv_status(' in query:
            row = (self.state,)
        if 'bri.csv_pending_review(' in query:
            return SimpleNamespace(fetchall=lambda: [(self.proposal, 'fixture-node', 'synthetic reviewed text')])
        if 'bri.csv_review(' in query:
            row = (args[-2],)
        if 'bri.csv_claim(' in query:
            row = self.claim
        if 'bri.csv_fail(' in query:
            row = ('ready',)
        if 'bri.csv_complete(' in query:
            row = (self.completion,)
        return SimpleNamespace(fetchone=lambda: row)

    def test_review_queue_and_decision_are_separate_from_submit(self):
        from bri.api.csv_intake import REVIEW_PREFIX

        auth = {'Authorization': self.headers['Authorization']}
        decision = f'{REVIEW_PREFIX}/{self.proposal}/decision'
        self.assertEqual(self.client.get(REVIEW_PREFIX, headers=auth).status_code, 403)
        self.assertEqual(self.client.post(decision, headers=auth, json={'decision': 'approved'}).status_code, 403)
        self.assertEqual(self.sql, [])
        self.person = Principal(str(self.actor), frozenset({'fixture-tenant'}), (
            AccessGrant('fixture-tenant', 'knowledge:review', 'fixture-node'),
        ), (('fixture-tenant', 'admin'),))
        listing = self.client.get(REVIEW_PREFIX, headers=auth)
        self.assertEqual(listing.status_code, 200, listing.text)
        self.assertEqual(listing.json(), [{'id': self.proposal, 'node_id': 'fixture-node',
                                           'text': 'synthetic reviewed text'}])
        self.assertEqual(listing.headers['Cache-Control'], 'no-store')
        self.assertEqual(self.client.post(
            decision, headers={**auth, 'Content-Type': 'application/json'},
            content=b'{"decision":"approved","decision":"rejected"}',
        ).status_code, 422)
        denied = self.client.post(decision, headers=auth, json={'decision': 'approved', 'tenant': 'private-marker'})
        self.assertEqual(denied.status_code, 422)
        self.assertNotIn('private-marker', denied.text)
        accepted = self.client.post(decision, headers=auth, json={'decision': 'approved'})
        self.assertEqual(accepted.status_code, 200, accepted.text)
        self.assertEqual(accepted.json(), {'id': self.proposal, 'decision': 'approved'})
        self.assertEqual(self.client.post(self.prefix, headers=self.headers, content=b'h\nv\n').status_code, 403)
        self.assertFalse(any('bri.csv_submit(' in entry[1] for entry in self.sql))

    def test_reserve_commit_store_mark_ready_and_exact_replay(self):
        csv = b'fixture_name,value\nsynthetic,1\n'
        first = self.client.post(self.prefix, headers=self.headers, content=csv)
        self.assertEqual(first.status_code, 202, first.text)
        self.assertEqual(first.json(), {'id': str(self.job), 'state': 'ready'})
        self.assertEqual(first.headers['Cache-Control'], 'no-store')
        self.assertEqual(self.resolve.call_args.args, (USER_ID, ISSUER, USER_ID))
        submit_at = next(i for i, entry in enumerate(self.sql) if 'bri.csv_submit(' in entry[1])
        role, _, submit = self.sql[submit_at]
        self.assertEqual(role, 'bri_csv_intake')
        self.assertEqual(self.sql[submit_at - 3][1], 'SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ WRITE')
        _, binding, bound = self.sql[submit_at - 1]
        self.assertIn("set_config('bri.auth_user_id',%s,true)", binding)
        self.assertIn("set_config('bri.tenant_id',%s,true)", binding)
        self.assertEqual(bound, ('fixture-tenant', USER_ID))
        self.assertEqual(submit, ('fixture-tenant', self.actor, UUID(SESSION_ID), ISSUER,
                                  'fixture-node', self.key, sha256(csv).hexdigest(), len(csv),
                                  UUID(first.headers['X-Request-ID'])))
        self.assertEqual(self.objects, [('private-object-key', csv)])
        replay = self.client.post(self.prefix, headers=self.headers, content=csv)
        self.assertEqual(replay.json(), first.json())
        self.assertEqual(len(self.objects), 1)
        status = self.client.get(f'{self.prefix}/{self.job}', headers={'Authorization': self.headers['Authorization']})
        self.assertEqual(status.json(), first.json())
        self.assertTrue(all(entry[0] != 'bri_csv_worker' for entry in self.sql))

    def test_worker_is_server_only_and_claim_commit_precedes_verified_read(self):
        payload = b'field\n"quoted\nfixture"\n'
        self.claim = (self.job, 'fixture-tenant', 'private-object-key', sha256(payload).hexdigest(), len(payload), 3)
        dispatch = self.app.state.csv_worker.dispatch
        self.assertEqual(self.client.post(f'{self.prefix}/{self.job}/process', headers=self.headers).status_code, 404)
        self.assertEqual(self.auth, [])
        dispatch(self.job)
        fail = next(q for q in self.sql if 'bri.csv_fail(' in q[1])
        self.assertEqual(fail[2][:4], (self.job, 3, 'object_missing', True))
        self.objects.append(('private-object-key', payload))
        dispatch(self.job)
        complete = next(q for q in self.sql if 'bri.csv_complete(' in q[1])
        self.assertEqual(complete[0], 'bri_csv_worker')
        expected = '{"headers":["field"],"rows":[["quoted\\nfixture"]]}'
        self.assertEqual(complete[2][:6], (self.job, 3, expected, sha256(expected.encode()).hexdigest(), 1, 3))
        claims = [q for q in self.sql if 'bri.csv_claim(' in q[1]]
        self.assertEqual(complete[2][-1], claims[-1][2][-1])
        self.assertNotEqual(claims[0][2][-1], claims[-1][2][-1])

    def test_worker_stale_completion_is_not_success_or_rewritten_as_failure(self):
        from bri.api.database import DatabaseUnavailable

        payload = b'field\nfixture\n'
        self.claim = (self.job, 'fixture-tenant', 'private-object-key', sha256(payload).hexdigest(), len(payload), 1)
        self.objects.append(('private-object-key', payload))
        self.completion = 'stale'
        with self.assertRaisesRegex(DatabaseUnavailable, '^CSV worker unavailable$'):
            self.app.state.csv_worker.dispatch(self.job)
        self.assertFalse(any('bri.csv_fail(' in entry[1] for entry in self.sql))

    def test_unsafe_database_role_fails_before_any_command_or_file_install(self):
        self.role_valid = False
        result = self.client.post(self.prefix, headers=self.headers, content=b'field\nfixture\n')
        self.assertEqual(result.status_code, 503)
        self.assertFalse(any('bri.csv_submit(' in entry[1] for entry in self.sql))
        self.assertEqual(self.objects, [])

    def test_assembly_rejects_non_mock_auth_and_shared_socket_directory(self):
        from bri.api.csv_intake import create_staged_csv_intake_app

        options = {
            'identity_scope': lambda: self.scope('bri_app'),
            'intake_scope': lambda: self.scope('bri_csv_intake'),
            'worker_scope': lambda: self.scope('bri_csv_worker'),
            'private_socket': self.socket,
            'store': SimpleNamespace(install=self.put, read_verified=self.read_object),
        }
        with httpx.HTTPTransport() as transport:
            with self.assertRaises(ValueError):
                create_staged_csv_intake_app(**options, auth_transport=transport)
        self.socket.chmod(0o755)
        with self.assertRaises(ValueError):
            create_staged_csv_intake_app(**options, auth_transport=httpx.MockTransport(self.provider))
        result = self.client.post(self.prefix, headers=self.headers, content=b'field\nfixture\n')
        self.assertEqual(result.status_code, 503)
        self.assertEqual(self.sql, [])
        self.assertEqual(self.objects, [])

    def test_no_object_install_on_failed_reservation_commit_and_exact_retry_repairs(self):
        csv = b'fixture\nentry\n'
        self.commit_failure = True
        response = self.client.post(self.prefix, headers=self.headers, content=csv)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(self.objects, [])
        self.commit_failure = False
        self.fail_install = True
        response = self.client.post(self.prefix, headers=self.headers, content=csv)
        self.assertEqual(response.status_code, 503)
        self.assertNotIn('private-marker', response.text)
        self.assertEqual(self.state, 'creating')
        self.fail_install = False
        self.assertEqual(self.client.post(self.prefix, headers=self.headers, content=csv).json(),
                         {'id': str(self.job), 'state': 'ready'})

    def test_authority_spoofing_and_nonlocal_requests_denied_before_sql(self):
        payload = b'fixture\nentry\n'
        for headers, suffix, status in (
            ({'Host': '192.0.2.8'}, '', 403),
            ({'Host': '127.0.0.1:12345'}, '', 403),
            ({'Forwarded': 'for=127.0.0.1'}, '', 403),
            ({'X-Actor-ID': str(self.actor)}, '', 400),
            ({'X-Creator-ID': str(self.actor)}, '', 400),
            ({'X-Dev-Identity': 'private-marker'}, '', 400),
            ({'X-Tenant-ID': 'private-marker'}, '', 400),
            ({}, '?tenant=private-marker', 400),
        ):
            with self.subTest(headers=headers, suffix=suffix):
                reply = self.client.post(self.prefix + suffix, headers={**self.headers, **headers}, content=payload)
                self.assertEqual(reply.status_code, status)
                self.assertEqual(reply.headers['Cache-Control'], 'no-store')
                self.assertNotIn('private-marker', reply.text)
        for origin, peer, host in (('http://192.0.2.4', '127.0.0.1', '192.0.2.4'),
                                   ('http://127.0.0.1', '192.0.2.4', '127.0.0.1')):
            with TestClient(self.app, base_url=origin, client=(peer, 5000)) as client:
                self.assertEqual(client.post(self.prefix, headers={**self.headers, 'Host': host},
                                             content=payload).status_code, 403)
        self.assertEqual(self.auth, [])
        self.assertEqual(self.sql, [])

    def test_submission_checks_verified_role_session_exact_scope_and_input(self):
        from bri.ingestion.csv_intake import MAX_CSV_BYTES

        payload = b'fixture\nentry\n'
        user = self.person
        for principal, active, extra, code in (
            (user, False, {}, 403),
            (replace(user, platform_superadmin=True), True, {}, 403),
            (replace(user, role_bindings=(('fixture-tenant', 'admin'),)), True, {}, 403),
            (replace(user, grants=()), True, {}, 403),
            (user, True, {'X-Node-ID': 'different-node'}, 403),
            (user, True, {'X-Node-ID': '../invalid'}, 422),
            (user, True, {'Idempotency-Key': str(UUID(int=0))}, 422),
            (user, True, {'Content-Type': 'multipart/form-data'}, 415),
            (user, True, {'Content-Encoding': 'gzip'}, 415),
            (user, True, {'Authorization': self.headers['Authorization'] + 'x'}, 401),
        ):
            self.person, self.active = principal, active
            with self.subTest(extra=extra, code=code):
                reply = self.client.post(self.prefix, headers={**self.headers, **extra}, content=payload)
                self.assertEqual(reply.status_code, code, reply.text)
        self.person, self.active = user, True
        reply = self.client.post(self.prefix, headers=self.headers, content=iter((b'a' * MAX_CSV_BYTES, b'x')))
        self.assertEqual(reply.status_code, 413)
        self.assertEqual(self.sql, [])
        self.assertEqual(self.objects, [])


@unittest.skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16')
class StagedCsvPostgres(unittest.TestCase):
    connect = classmethod(pg.CsvIntakePostgresTests.connect.__func__)
    setUpClass = classmethod(pg.CsvIntakePostgresTests.setUpClass.__func__)
    sock: Path
    tenant: str
    foreign: str
    actors: list[tuple[UUID, UUID, UUID]]
    foreign_actors: list[tuple[UUID, UUID, UUID]]

    def setUp(self):
        pg.CsvIntakePostgresTests.setUp(self)

    @staticmethod
    def stage_client(app):
        return TestClient(app, base_url='http://127.0.0.1', client=('127.0.0.1', 50400))

    def seed_readers(self):
        # Give the release readers independent sessions started after the grant writes.
        result = []
        with self.connect('postgres') as db:
            for tenant, actor, node in ((self.tenant, self.actors[1], 'team'),
                                        (self.tenant, self.actors[0], 'root'),
                                        (self.foreign, self.foreign_actors[1], 'team')):
                db.execute("INSERT INTO bri.app_roles VALUES (%s,'csv-reader','CSV reader') "
                           'ON CONFLICT DO NOTHING', (tenant,))
                db.execute("INSERT INTO bri.role_permissions VALUES (%s,'csv-reader','knowledge:read') "
                           'ON CONFLICT DO NOTHING', (tenant,))
                db.execute("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) "
                           "VALUES (%s,%s,'csv-reader',%s)", (tenant, actor[0], node))
                session = (*actor[:2], uuid4())
                db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                           'VALUES (%s,%s,%s,clock_timestamp())', session)
                result.append(session)
        return result

    def assert_published_reads(self, release, auth, proposal, expected=None, *, needle='a12syntheticartifact'):
        base = '/v1/knowledge'
        record = None if expected is None else {
            **expected, 'scope_id': 'team', 'validation_state': 'approved',
        }
        response = release.get(base, headers=auth)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), [] if record is None else [record])
        source = None if expected is None else {k: v for k, v in expected.items() if k != 'content'}
        for route, body, not_found in (
            (base, record, 'Knowledge record not found'),
            ('/v1/sources', source, 'Source reference not found'),
        ):
            response = release.get(f'{route}/{proposal}', headers=auth)
            self.assertEqual(response.status_code, 404 if body is None else 200, response.text)
            self.assertEqual(response.json(), {'detail': not_found} if body is None else body)
        response = release.get(f'{base}/search', headers=auth, params={'q': needle})
        self.assertEqual(response.status_code, 200, response.text)
        if expected is None or source is None:
            self.assertEqual(response.json(), {'status': 'insufficient', 'answer': None, 'citations': []})
        else:
            content = expected['content']
            self.assertEqual(response.json(), {'status': 'supported', 'answer': content,
                                               'citations': [{**source, 'excerpt': content}]})

    def test_private_intake_through_restart_review_and_published_reads(self):
        from bri.api.app import ApiSettings, create_app
        from bri.api.authentication import SupabaseTokenVerifier
        from bri.api.csv_intake import PREFIX, REVIEW_PREFIX, create_staged_csv_intake_app
        from bri.api.database import DatabaseUnavailable
        from bri.ingestion.csv_intake import LocalCsvQuarantine, ProcessOutcome

        users = {}

        def bearer(identity):
            _, uid, sid = identity
            token = make_token(sub=str(uid), session_id=str(sid))
            users[token] = str(uid)
            return {'Authorization': f'Bearer {token}'}

        def verify(request):
            self.assertEqual(request.url.path, '/auth/v1/user')
            uid = users.get(request.headers['Authorization'].removeprefix('Bearer '))
            return auth_server_response(request, user_id=uid or '', status=200 if uid else 401)

        user, reviewer, creator = map(bearer, (self.actors[2], self.actors[0], self.actors[1]))
        other_user, other_reviewer = bearer(self.foreign_actors[2]), bearer(self.foreign_actors[0])
        request_key = uuid4()
        headers = {**user, 'Content-Type': 'text/csv; charset=utf-8',
                   'X-Node-ID': 'team', 'Idempotency-Key': str(request_key)}
        csv = b'field,value\r\na12syntheticartifact,"quoted\r\ntext"\r\n'
        root = Path(self.enterContext(TemporaryDirectory(prefix='a12-http-')))

        def stage(store):
            return create_staged_csv_intake_app(
                identity_scope=lambda: self.connect('bri_app'),
                intake_scope=lambda: self.connect('bri_csv_intake'),
                worker_scope=lambda: self.connect('bri_csv_worker'),
                reader_scope=lambda: self.connect('bri_csv_reader'),
                private_socket=self.sock, auth_transport=httpx.MockTransport(verify), store=store,
            )

        class InterruptedQuarantine(LocalCsvQuarantine):
            def read_verified(self, verified_tenant_id: str, key: str, sha256: str, byte_count: int) -> bytes:
                # Let the real worker commit its claim, then stop before completion.
                raise RuntimeError('synthetic dispatch interruption')

        first_stage = stage(InterruptedQuarantine(root))
        with self.stage_client(first_stage) as client:
            self.assertEqual(client.post(PREFIX, headers={**headers, 'X-Node-ID': 'root'}, content=csv).status_code,
                             403)
            response = client.post(PREFIX, headers=headers, content=csv)
            self.assertEqual(response.status_code, 202, response.text)
            job = UUID(response.json()['id'])
            self.assertNotEqual(job, request_key)
            self.assertEqual(response.json(), {'id': str(job), 'state': 'ready'})
            self.assertEqual(client.post(PREFIX, headers=headers, content=csv + b'\n').status_code, 409)
            self.assertEqual(client.get(f'{PREFIX}/{job}', headers=other_user).status_code, 403)
            self.assertEqual(client.get(f'{PREFIX}/{request_key}', headers=user).status_code, 403)
            with self.assertRaisesRegex(DatabaseUnavailable, '^CSV worker unavailable$'):
                first_stage.state.csv_worker.dispatch(job)
        del first_stage

        staged = stage(LocalCsvQuarantine(root))
        client = self.enterContext(self.stage_client(staged))
        self.assertEqual(client.get(f'{PREFIX}/{job}', headers=user).json(), {'id': str(job), 'state': 'processing'})
        self.assertEqual(staged.state.csv_worker.dispatch(job), ProcessOutcome.NOT_CLAIMED)
        with self.connect('postgres') as db:
            expired = db.execute("UPDATE bri.csv_jobs SET lease_until=clock_timestamp()-interval '1 second' "
                                 "WHERE tenant_id=%s AND job_id=%s AND state='processing' AND attempt=1 "
                                 'AND lease_until>clock_timestamp()', (self.tenant, job))
            self.assertEqual(expired.rowcount, 1)
        self.assertEqual(staged.state.csv_worker.dispatch(job), ProcessOutcome.COMPLETED)
        self.assertEqual(staged.state.csv_worker.dispatch(job), ProcessOutcome.NOT_CLAIMED)
        self.assertEqual(client.post(PREFIX, headers=headers, content=csv).json(),
                         {'id': str(job), 'state': 'proposed'})
        expected_text = '{"headers":["field","value"],"rows":[["a12syntheticartifact","quoted\\r\\ntext"]]}'
        proposal = f'csv:{job}'
        decision_path = f'{REVIEW_PREFIX}/{proposal}/decision'
        self.assertEqual(client.get(REVIEW_PREFIX, headers=other_reviewer).json(), [])
        self.assertEqual(client.post(decision_path, headers=other_reviewer, json={'decision': 'approved'}).status_code,
                         403)
        self.assertEqual(client.post(decision_path, headers=user, json={'decision': 'approved'}).status_code, 403)
        creator_queue = client.get(REVIEW_PREFIX, headers=creator)
        self.assertEqual(creator_queue.status_code, 200, creator_queue.text)
        self.assertEqual(creator_queue.json(), [])
        self.assertEqual(client.post(decision_path, headers=creator, json={'decision': 'approved'}).status_code, 403)
        listing = client.get(REVIEW_PREFIX, headers=reviewer)
        self.assertEqual(listing.status_code, 200, listing.text)
        self.assertEqual(listing.json(), [{'id': proposal, 'node_id': 'team', 'text': expected_text}])
        decision = client.post(decision_path, headers=reviewer, json={'decision': 'approved'})
        self.assertEqual(decision.status_code, 200, decision.text)
        self.assertEqual(decision.json(), {'id': proposal, 'decision': 'approved'})
        self.assertEqual(client.post(decision_path, headers=reviewer, json={'decision': 'rejected'}).status_code, 409)
        self.assertEqual(client.get(REVIEW_PREFIX, headers=reviewer).json(), [])
        self.assertEqual(client.get(f'{PREFIX}/{job}', headers=user).json(), {'id': str(job), 'state': 'approved'})

        def submit_terminal_fixture(content):
            reply = client.post(PREFIX, headers={**headers, 'Idempotency-Key': str(uuid4())}, content=content)
            self.assertEqual(reply.status_code, 202, reply.text)
            return UUID(reply.json()['id'])

        rejected = submit_terminal_fixture(b'field\na12rejectedfixture\n')
        self.assertEqual(staged.state.csv_worker.dispatch(rejected), ProcessOutcome.COMPLETED)
        rejected_reply = client.post(f'{REVIEW_PREFIX}/csv:{rejected}/decision', headers=reviewer,
                                     json={'decision': 'rejected'})
        self.assertEqual(rejected_reply.status_code, 200, rejected_reply.text)
        self.assertEqual(client.get(f'{PREFIX}/{rejected}', headers=user).json()['state'], 'rejected')
        failed = submit_terminal_fixture(b'field\na12failedfixture,wrong-width\n')
        self.assertEqual(staged.state.csv_worker.dispatch(failed), ProcessOutcome.FAILED)
        self.assertEqual(client.get(f'{PREFIX}/{failed}', headers=user).json()['state'], 'failed')
        self.assertEqual(client.get(REVIEW_PREFIX, headers=reviewer).json(), [])

        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT event,attempt FROM bri.csv_audit_events '
                                        'WHERE tenant_id=%s AND job_id=%s ORDER BY occurred_at',
                                        (self.tenant, job)).fetchall(), [
                ('submitted', 0), ('ready', 0), ('claimed', 1), ('lease_expired', 1),
                ('claimed', 2), ('proposed', 2), ('approved', 2),
            ])
            self.assertEqual(db.execute('SELECT decision FROM bri.validation_decisions WHERE tenant_id=%s AND proposal_id=%s',
                                        (self.tenant, f'csv:{rejected}')).fetchone(), ('rejected',))
            self.assertEqual(db.execute("SELECT reason FROM bri.csv_audit_events WHERE job_id=%s AND event='failed'",
                                        (failed,)).fetchone(), ('invalid_csv',))
            self.assertEqual(db.execute('SELECT proposal_id FROM bri.validated_knowledge WHERE tenant_id=%s',
                                        (self.tenant,)).fetchall(), [(proposal,)])
            db.execute('UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() WHERE session_id=%s',
                       (self.actors[2][2],))
        self.assertEqual(client.get(f'{PREFIX}/{job}', headers=user).status_code, 403)
        self.assertEqual(client.post(PREFIX, headers=headers, content=csv).status_code, 403)

        reader_sessions = self.seed_readers()
        reader, parent_node, foreign_reader = map(bearer, reader_sessions)
        self.assertEqual(client.get('/v1/knowledge', headers=reviewer).status_code, 403)
        connect = self.connect

        class PrivateReleaseDatabase(Database):
            def _connect(self):
                return connect('bri_app')

        origin = ISSUER.removesuffix('/auth/v1')
        provider = httpx.AsyncClient(transport=httpx.MockTransport(verify), trust_env=False)
        verifier = SupabaseTokenVerifier(origin, 'csv-test-only', client=provider)
        release = self.enterContext(TestClient(create_app(
            settings=ApiSettings(environment='hosted-development', auth_mode='supabase', supabase_url=origin),
            database=PrivateReleaseDatabase(origin, ''), token_verifier=verifier,
        )))
        assert release.portal is not None
        self.addCleanup(release.portal.call, provider.aclose)

        original_digest = sha256(csv).hexdigest()
        extracted_digest = sha256(expected_text.encode()).hexdigest()
        self.assertNotEqual(original_digest, extracted_digest)
        expected = {
            'record_id': proposal, 'title': 'Governed CSV', 'source_id': proposal,
            'source_version_id': proposal, 'source_version': '1', 'extraction_id': proposal,
            'content_sha256': extracted_digest, 'extractor_name': 'governed-csv', 'extractor_version': '1',
            'source_location': 'csv:lines=1-3', 'content': expected_text,
            'original_sha256': original_digest, 'csv_first_line': 1, 'csv_last_line': 3,
        }

        @contextmanager
        def maintain_policy():
            with self.connect('bri_migrator') as db:
                db.execute("SELECT set_config('bri.tenant_id',%s,true)", (self.tenant,))
                yield db

        record_key = (self.tenant, proposal)
        version_key = (*record_key, proposal)
        for terminal, needle, denied in (
            (rejected, 'a12rejectedfixture', psycopg.errors.InsufficientPrivilege),
            (failed, 'a12failedfixture', psycopg.errors.ForeignKeyViolation),
        ):
            ref = f'csv:{terminal}'
            with maintain_policy() as db:
                for query, args in (
                    ('INSERT INTO bri.knowledge_record_access VALUES (%s,%s,true)', (self.tenant, ref)),
                    ('INSERT INTO bri.knowledge_version_access VALUES (%s,%s,%s,true)', (self.tenant, ref, ref)),
                ):
                    with self.assertRaises(denied), db.transaction():
                        db.execute(query, args)
            self.assert_published_reads(client, reader, ref, needle=needle)
            self.assert_published_reads(release, reader, ref, needle=needle)
        rejected_ref = f'csv:{rejected}'
        with maintain_policy() as db:
            db.execute('INSERT INTO bri.knowledge_record_access VALUES (%s,%s,false)', (self.tenant, rejected_ref))
            db.execute('INSERT INTO bri.knowledge_version_access VALUES (%s,%s,%s,false)',
                       (self.tenant, rejected_ref, rejected_ref))
            for table in ('knowledge_record_access', 'knowledge_version_access'):
                with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                    db.execute(f'UPDATE bri.{table} SET readable=true WHERE tenant_id=%s AND source_id=%s',
                               (self.tenant, rejected_ref))
        self.assert_published_reads(client, reader, rejected_ref, needle='a12rejectedfixture')
        with self.subTest(gates='approved, neither gate'):
            self.assert_published_reads(client, reader, proposal)
        with maintain_policy() as db:
            db.execute('INSERT INTO bri.knowledge_version_access VALUES (%s,%s,%s,true)', version_key)
        with self.subTest(gates='missing record gate'):
            self.assert_published_reads(client, reader, proposal)
        with maintain_policy() as db:
            db.execute('DELETE FROM bri.knowledge_version_access '
                       'WHERE tenant_id=%s AND source_id=%s AND source_version_id=%s', version_key)
            db.execute('INSERT INTO bri.knowledge_record_access VALUES (%s,%s,true)', record_key)
        with self.subTest(gates='missing exact version gate'):
            self.assert_published_reads(client, reader, proposal)
        with maintain_policy() as db:
            db.execute('INSERT INTO bri.knowledge_version_access VALUES (%s,%s,%s,true)', version_key)
        with self.subTest(gates='both gates allow'):
            self.assert_published_reads(client, reader, proposal, expected)
            self.assert_published_reads(release, reader, proposal)
        with self.subTest(reader='same tenant, parent node only'):
            self.assert_published_reads(client, parent_node, proposal)
        with self.subTest(reader='other tenant, matching node ID'):
            self.assert_published_reads(client, foreign_reader, proposal)

        # Exercise the transport's own exact-scope check, independently of API preflight.
        with self.connect('bri_csv_reader') as db:
            db.execute('SET TRANSACTION READ ONLY')
            query = 'SELECT proposal_id FROM bri.csv_read_published(%s,%s,%s,%s,%s)'
            exact, parent, foreign = reader_sessions
            self.assertEqual(db.execute(query, (self.tenant, *exact, ISSUER)).fetchall(), [(proposal,)])
            for identity in (parent, foreign):
                self.assertEqual(db.execute(query, (self.tenant, *identity, ISSUER)).fetchall(), [])

        for gate, query, key in (
            ('record', 'UPDATE bri.knowledge_record_access SET readable=%s '
                       'WHERE tenant_id=%s AND source_id=%s', record_key),
            ('exact version', 'UPDATE bri.knowledge_version_access SET readable=%s '
                              'WHERE tenant_id=%s AND source_id=%s AND source_version_id=%s', version_key),
        ):
            with maintain_policy() as db:
                self.assertEqual(db.execute(query, (False, *key)).rowcount, 1)
            with self.subTest(revoked=gate):
                self.assert_published_reads(client, reader, proposal)
            with maintain_policy() as db:
                self.assertEqual(db.execute(query, (True, *key)).rowcount, 1)
            with self.subTest(restored=gate):
                self.assert_published_reads(client, reader, proposal, expected)
