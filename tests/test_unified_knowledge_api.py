"""Signed fixture requests through the isolated knowledge reader."""
import os
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from typing import Any
from unittest import TestCase, skipUnless
from unittest.mock import patch
from uuid import UUID, uuid4

import httpx
import psycopg
from fastapi.testclient import TestClient
from test_authentication import ISSUER, SESSION_ID, USER_ID, auth_server_response, make_token

from bri.access.policy import AccessGrant, Principal
from bri.api.database import Database


class UnifiedKnowledgeTests(TestCase):
    def setUp(self):
        self.socket = Path(self.enterContext(TemporaryDirectory()))
        self.actor, self.record = uuid4(), uuid4()
        self.version = self.record
        self.node = 'fixture-node'
        self.headers = {'Authorization': f'Bearer {make_token()}'}
        self.calls = []
        self.auth_calls = []
        self.temp_configured = True
        self.commit_failure = False
        self.receipt = {'version': 1, 'status': 'complete', 'results': []}
        self.scope_identity = ('fixture-tenant', self.actor)
        self.active = self.enterContext(patch.object(Database, 'auth_session_is_active', return_value=True))
        self.resolve = self.enterContext(patch.object(Database, 'resolve_authenticated_principal', return_value=Principal(
            str(self.actor), frozenset({'fixture-tenant'}), (AccessGrant('fixture-tenant', 'knowledge:read', self.node),),
            (('fixture-tenant', 'user'),),
        )))

    def provider(self, request):
        self.auth_calls.append(request.url.path)
        return auth_server_response(request, user_id=USER_ID)

    @contextmanager
    def scope(self, role):
        yield SimpleNamespace(info=SimpleNamespace(host=str(self.socket), port=5432, dbname='postgres', user=role,
                                                   transaction_status=psycopg.pq.TransactionStatus.IDLE),
                              transaction=self.transaction, execute=self.execute)

    @contextmanager
    def transaction(self):
        yield
        if self.commit_failure:
            raise psycopg.OperationalError('private commit detail')
        self.calls.append(('commit', ()))

    def execute(self, sql, args=()):
        self.calls.append((sql, args))
        if 'current_setting(\'bri.auth_user_id\'' in sql:
            return SimpleNamespace(fetchone=lambda: (USER_ID,))
        if 'auth_sessions' in sql and 'auth_tenant_memberships' in sql:
            return SimpleNamespace(fetchall=lambda: [self.scope_identity] if self.scope_identity else [])
        if 'temp_file_limit' in sql:
            return SimpleNamespace(fetchone=lambda: (self.temp_configured,))
        if 'bri.unified_' in sql:
            if isinstance(self.receipt, Exception):
                raise self.receipt
            return SimpleNamespace(fetchone=lambda: (self.receipt,))
        return SimpleNamespace(fetchone=lambda: (True,))

    def start(self):
        from bri.api.unified_knowledge import create_staged_unified_knowledge_app

        app = create_staged_unified_knowledge_app(
            identity_scope=lambda: self.scope('bri_app'),
            reader_scope=lambda: self.scope('bri_unified_knowledge_reader'),
            private_socket=self.socket, auth_transport=httpx.MockTransport(self.provider),
        )
        return self.enterContext(TestClient(app, base_url='http://127.0.0.1', client=('127.0.0.1', 50000)))

    def test_scope_identity_resolution_does_not_load_shared_permission_inventory(self):
        self.resolve.side_effect = AssertionError('unbounded permission inventory invoked')
        self.receipt = {'version': 1, 'status': 'complete', 'scopes': []}
        reply = self.start().get('/v1/knowledge/search/scopes', headers=self.headers)
        self.assertEqual((reply.status_code, reply.json()), (200, self.receipt))
        self.resolve.assert_not_called()
        self.active.assert_not_called()
        query = next(sql for sql, _ in self.calls if 'auth_sessions' in sql)
        settings = [sql for sql, _ in self.calls]
        self.assertLess(settings.index("SET LOCAL statement_timeout = '1000ms'"), settings.index(query))
        self.assertNotRegex(query, r'auth_role_assignments|role_permissions|ORDER BY')

    def test_scope_discovery_accepts_eligible_session_with_no_search_grants(self):
        self.resolve.return_value = Principal(str(self.actor), frozenset({'fixture-tenant'}), (),
                                              (('fixture-tenant', 'admin'),))
        self.receipt = {'version': 1, 'status': 'complete', 'scopes': []}
        client = self.start()
        reply = client.get('/v1/knowledge/search/scopes', headers=self.headers)
        self.assertEqual((reply.status_code, reply.json()), (200, self.receipt))
        self.assertEqual(reply.headers['Cache-Control'], 'private, no-store')
        args = next(a for sql, a in self.calls if 'bri.unified_knowledge_search_scopes' in sql)
        self.assertEqual(args, ('fixture-tenant', self.actor, UUID(USER_ID), UUID(SESSION_ID), ISSUER))
        self.assertEqual(client.post('/v1/knowledge/search', headers=self.headers,
                                     json={'scope_node_id': self.node, 'query': 'x'}).status_code, 403)

    def test_scope_discovery_wire_cap_and_fail_closed_receipts(self):
        from fastapi.responses import JSONResponse

        client = self.start()
        path = '/v1/knowledge/search/scopes'
        receipt = {'version': 1, 'status': 'complete', 'scopes': [
            {'scope_node_id': self.node, 'display_label': ''}]}
        padding = 131072 - len(JSONResponse(receipt).body)
        receipt['scopes'][0]['display_label'] = 'é' * (padding // 2) + 'x' * (padding % 2)
        self.receipt = receipt
        reply = client.get(path, headers=self.headers)
        self.assertEqual((reply.status_code, len(reply.content)), (200, 131072))
        receipt['scopes'][0]['display_label'] += 'x'
        for invalid in (receipt, {'version': 2, 'status': 'complete', 'scopes': []},
                        {'version': 1, 'status': 'complete', 'scopes': [{'scope_node_id': 'team'}]},
                        psycopg.errors.QueryCanceled('private deadline'),
                        psycopg.errors.InsufficientPrivilege('private dependency privilege')):
            self.receipt = invalid
            reply = client.get(path, headers=self.headers)
            self.assertEqual((reply.status_code, reply.json()), (503, {'version': 1, 'status': 'unavailable'}))
            self.assertEqual(reply.headers['Cache-Control'], 'private, no-store')

    def test_scope_discovery_is_not_registered_in_ordinary_profiles(self):
        from bri.api.app import ApiSettings, create_app

        path = '/v1/knowledge/search/scopes'
        for env, auth in (('', 'disabled'), ('development', 'disabled'), ('production', 'disabled'),
                          ('hosted-development', 'supabase')):
            with self.subTest(env=env):
                app = create_app(settings=ApiSettings(environment=env, auth_mode=auth), token_verifier=object())
                self.assertFalse(any(getattr(route, 'path', None) == path for route in app.routes))
                with TestClient(app) as client:
                    self.assertIn(client.get(path).status_code, (404, 405))

    def test_scope_discovery_rejects_browser_authority_before_authentication(self):
        client = self.start()
        path = '/v1/knowledge/search/scopes'
        for method, target, extra, body in (
            ('POST', path, {}, b''), ('GET', path + '/', {}, b''),
            ('GET', path.replace('scopes', '%73copes'), {}, b''), ('GET', path + '?tenant=x', {}, b''),
            ('GET', path, {'X-Tenant-Id': 'foreign'}, b''), ('GET', path, {'permission': 'knowledge:read'}, b''),
            ('GET', path, {}, b'x'),
        ):
            reply = client.request(method, target, headers=self.headers | extra, content=body)
            self.assertIn(reply.status_code, (400, 404, 413))
        self.assertFalse(self.auth_calls)
        self.assertFalse(self.calls)

    def test_signed_search_passes_server_authority_and_normalized_query_under_limits(self):
        result = self.start().post('/v1/knowledge/search', headers=self.headers,
                                   json={'scope_node_id': self.node, 'query': '  FiXtUrE  '})
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(result.json(), self.receipt)
        self.assertEqual(result.headers['Cache-Control'], 'private, no-store')
        self.resolve.assert_called_once_with(USER_ID, ISSUER, USER_ID)
        self.active.assert_called_once_with(USER_ID, SESSION_ID)
        sql, args = next((sql, args) for sql, args in self.calls if 'bri.unified_knowledge_search' in sql)
        self.assertEqual(args, ('fixture-tenant', self.actor, UUID(USER_ID), UUID(SESSION_ID), ISSUER,
                                self.node, 'fixture'))
        commands = [command for command, _ in self.calls]
        for setting in ('statement_timeout', 'temp_file_limit'):
            self.assertLess(next(i for i, command in enumerate(commands) if setting in command), commands.index(sql))
        self.assertEqual(self.calls[-1], ('commit', ()))

    def test_evidence_rechecks_exact_ids_and_has_single_generic_denial(self):
        self.receipt = {'record_id': str(self.record), 'source_version_id': str(self.version),
                        'first_line': 2, 'last_line': 4, 'original_sha256': 'a' * 64, 'content_sha256': 'b' * 64}
        client = self.start()
        url = f'/v1/knowledge/csv/{self.record}/versions/{self.version}/evidence'
        response = client.get(url, headers=self.headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers['Cache-Control'], 'private, no-store')
        self.assertEqual(response.json(), self.receipt)
        self.assertEqual(next(args for sql, args in self.calls if 'bri.unified_csv_evidence' in sql),
                         ('fixture-tenant', self.actor, UUID(USER_ID), UUID(SESSION_ID), ISSUER,
                          self.record, self.version))
        self.receipt = None
        absent = client.get(url, headers=self.headers)
        self.receipt = psycopg.errors.InsufficientPrivilege('private detail')
        denied = client.get(url, headers=self.headers)
        self.calls.clear()
        self.active.return_value = False
        revoked = client.get(url, headers=self.headers)
        self.assertEqual([response.status_code for response in (absent, denied, revoked)], [404, 404, 404])
        self.assertEqual(absent.content, denied.content)
        self.assertEqual(absent.content, revoked.content)
        self.assertFalse(self.calls)

    def test_evidence_rejects_unbound_or_expanded_receipts_without_projection(self):
        receipt = {'record_id': str(self.record), 'source_version_id': str(self.version),
                   'first_line': 1, 'last_line': 4, 'original_sha256': 'a' * 64, 'content_sha256': 'b' * 64}
        client = self.start()
        url = f'/v1/knowledge/csv/{self.record}/versions/{self.version}/evidence'
        for change in ({'source_version_id': str(uuid4())}, {'record_id': str(uuid4())},
                       {'last_line': False}, {'storage_key': 'private-sentinel'}, {'content_sha256': 'g' * 64}):
            self.receipt = receipt | change
            response = client.get(url, headers=self.headers)
            self.assertEqual((response.status_code, response.json()), (503, {'detail': 'Knowledge evidence unavailable'}))
            self.assertEqual(response.headers['Cache-Control'], 'private, no-store')

    def test_search_validates_each_format_and_never_returns_partial_receipts(self):
        r, v = str(uuid4()), str(uuid4())
        rid = str(self.record)
        common = {'match': 'exact', 'excerpt_truncated': False, 'original_sha256': 'a' * 64}
        csv = common | {'format': 'csv', 'record_id': rid, 'source_id': 'csv:' + rid, 'source_version_id': rid,
                        'content_sha256': 'b'*64, 'excerpt': 'évidence', 'evidence': {'first_line': 3, 'last_line': 4},
                        'evidence_url': f'/v1/knowledge/csv/{rid}/versions/{rid}/evidence'}
        xlsx = common | {'format': 'xlsx', 'record_id': r, 'source_id': v, 'source_version_id': v,
                         'canonical_sha256': 'c'*64, 'extractor_version': 1, 'canonicalization_version': 1,
                         'excerpt': 'evidence', 'evidence': {'sheet_id': '1', 'sheet_title': 'Synthetic', 'cell': 'BL10000'},
                         'evidence_url': f'/v2/knowledge/xlsx/{r}/evidence/{v}'}
        client = self.start()
        def call():
            return client.post('/v1/knowledge/search', headers=self.headers,
                               json={'scope_node_id': self.node, 'query': 'ÉviDence'})
        self.receipt = {'version': 1, 'status': 'complete', 'results': [csv, xlsx]}
        response = call()
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), {'version': 1, 'status': 'complete', 'results': [csv, xlsx]})
        self.assertEqual(next(args[-1] for sql, args in self.calls if 'bri.unified_knowledge_search' in sql),
                         'Évidence')
        for results in ([csv, csv], [csv, xlsx | {'artifact_key': 'secret'}],
                        [csv, xlsx | {'evidence': {'sheet_id': '1', 'sheet_title': 'Synthetic', 'cell': 'XFE1048576'}}],
                        [csv, xlsx | {'evidence_url': '/v1/knowledge/xlsx/wrong'}],
                        [csv, xlsx | {'extractor_version': True}],
                        [csv, xlsx | {'canonical_sha256': 'invalid'}],
                        [csv, xlsx | {'excerpt': 'é' * 1025}],
                        [csv, csv | {'evidence': {'first_line': True, 'last_line': 1}}]):
            self.receipt = {'version': 1, 'status': 'complete', 'results': results}
            response = call()
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.json(), {'version': 1, 'status': 'unavailable'})

    def test_exact_serialized_cap_with_full_versioned_hits(self):
        from fastapi.responses import JSONResponse
        results = []
        for _ in range(20):
            identifier = str(uuid4())
            results.append({'format':'csv', 'record_id':identifier, 'source_id':'csv:'+identifier,
                            'source_version_id':identifier, 'original_sha256':'a'*64, 'content_sha256':'b'*64,
                            'match':'substring', 'excerpt':'é', 'excerpt_truncated':True,
                            'evidence':{'first_line':1,'last_line':1},
                            'evidence_url':f'/v1/knowledge/csv/{identifier}/versions/{identifier}/evidence'})
        self.receipt = {'version':1, 'status':'complete', 'results':results}
        deficit = 131072 - len(JSONResponse(self.receipt).body)
        for hit in results:
            count = min(1900, deficit // 6)
            hit['excerpt'] += '\x02' * count
            deficit -= 6 * count
        results[-1]['excerpt'] += 'a' * deficit
        self.assertEqual(len(JSONResponse(self.receipt).body), 131072)
        client = self.start()
        def call():
            return client.post('/v1/knowledge/search', headers=self.headers,
                               json={'scope_node_id':self.node,'query':'é'})
        exact = call()
        self.assertEqual(exact.status_code, 200)
        self.assertEqual(len(exact.content), 131072)
        self.assertEqual(exact.json(), self.receipt)
        results[-1]['excerpt'] += 'a'
        self.assertEqual(len(JSONResponse(self.receipt).body), 131073)
        over = call()
        self.assertEqual((over.status_code, over.json()), (503, {'version':1,'status':'unavailable'}))

    def test_untrusted_temp_configuration_prevents_protected_sql(self):
        client = self.start()
        self.temp_configured = False
        response = client.post('/v1/knowledge/search', headers=self.headers,
                               json={'scope_node_id': self.node, 'query': 'fixture'})
        self.assertEqual(response.status_code, 503)
        self.assertFalse(any('bri.unified_' in sql for sql, _ in self.calls))

    def test_commit_failure_does_not_expose_success_receipt(self):
        self.commit_failure = True
        response = self.start().post('/v1/knowledge/search', headers=self.headers,
                                     json={'scope_node_id': self.node, 'query': 'fixture'})
        self.assertTrue(any('bri.unified_' in sql for sql, _ in self.calls))
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {'version': 1, 'status': 'unavailable'})

    def test_sql_timeout_has_unavailable_shape_and_no_private_error(self):
        self.receipt = psycopg.errors.QueryCanceled('private timeout detail')
        response = self.start().post('/v1/knowledge/search', headers=self.headers,
                                     json={'scope_node_id': self.node, 'query': 'fixture'})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {'version': 1, 'status': 'unavailable'})
        self.assertEqual(response.headers['Cache-Control'], 'private, no-store')

    def test_byte_limits_apply_to_body_query_and_escaped_receipt(self):
        client = self.start()
        def call(query):
            return client.post('/v1/knowledge/search', headers=self.headers,
                               json={'scope_node_id': self.node, 'query': query})
        self.assertEqual(call('é' * 128).status_code, 200)
        self.auth_calls.clear()
        self.assertEqual(call('é' * 129).status_code, 422)
        self.assertEqual(call(' ' * 4096).status_code, 413)
        self.assertFalse(self.auth_calls)
        self.receipt = {'version': 1, 'status': 'complete', 'results': [
            {'format': 'csv', 'record_id': identifier, 'source_version_id': identifier,
             'source_id': 'csv:' + identifier, 'original_sha256': 'a'*64, 'content_sha256': 'b'*64,
             'match': 'substring', 'excerpt_truncated': True, 'excerpt': 'a' + '\x02' * 2047,
             'evidence': {'first_line': 1, 'last_line': 1},
             'evidence_url': f'/v1/knowledge/csv/{identifier}/versions/{identifier}/evidence'}
            for identifier in (str(uuid4()) for _ in range(20))
        ]}
        response = call('a')
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json(), {'version': 1, 'status': 'unavailable'})

    def test_search_requires_revalidated_native_session_and_exact_node_before_reader(self):
        client = self.start()
        payload = {'scope_node_id': self.node, 'query': 'fixture'}
        self.assertEqual(client.post('/v1/knowledge/search', json=payload).status_code, 401)
        self.assertEqual(client.post('/v1/knowledge/search', headers={'Authorization': 'Bearer tampered'},
                                     json=payload).status_code, 401)
        self.assertEqual(client.post('/v1/knowledge/search', headers=self.headers,
                                     json=payload | {'scope_node_id': 'sibling-node'}).status_code, 403)
        self.active.return_value = False
        self.assertEqual(client.post('/v1/knowledge/search', headers=self.headers, json=payload).status_code, 403)
        self.assertFalse(self.calls)

    def test_invalid_search_and_evidence_selectors_never_reach_identity(self):
        client = self.start()
        url = '/v1/knowledge/search'
        evidence = f'/v1/knowledge/csv/{self.record}/versions/{self.version}/evidence'
        cases: tuple[tuple[str, str, dict[str, Any]], ...] = (
            ('POST', url, {'json': {'scope_node_id': self.node, 'query': 'foo', 'tenant': 'spoof'}}),
            ('POST', url, {'content': b'{"scope_node_id":"fixture-node","query":"a","query":"b"}',
                           'headers': {'Content-Type': 'application/json'}}),
            ('POST', url + '?q=foo', {'json': {'scope_node_id': self.node, 'query': 'foo'}}),
            ('GET', evidence + '?first_line=2', {}),
            ('GET', evidence.replace('/csv/', '/%63sv/'), {}),
            ('GET', url, {}),
        )
        for method, path, args in cases:
            with self.subTest(method=method, path=path):
                headers = self.headers | args.pop('headers', {})
                response = client.request(method, path, headers=headers, **args)
                self.assertIn(response.status_code, (400, 404, 422))
                self.assertEqual(response.headers['Cache-Control'], 'private, no-store')
        self.assertFalse(self.auth_calls)
        self.assertFalse(self.calls)


@skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16')
class UnifiedKnowledgeLoopbackTests(TestCase):
    from test_unified_knowledge_postgres import UnifiedKnowledgePostgresTests as _pg

    sock: Path
    tenant: str
    foreign: str
    actors: list[tuple[UUID, UUID, UUID]]

    @classmethod
    def setUpClass(cls):
        cls._pg.setUpClass.__func__(cls)
        with cls.connect('postgres') as db:
            db.execute('CREATE ROLE bri_xlsx_reader LOGIN NOINHERIT; CREATE ROLE bri_xlsx_reviewer LOGIN NOINHERIT')
            db.execute('GRANT USAGE ON SCHEMA bri TO bri_xlsx_reader,bri_xlsx_reviewer')
            db.execute('GRANT EXECUTE ON FUNCTION bri.xlsx_published_evidence(text,uuid,uuid,uuid,text,uuid,uuid) TO bri_xlsx_reader')

    connect = _pg.__dict__['connect']
    setUp = _pg.setUp
    setUp_intake = _pg.setUp_intake
    publish_csv = _pg.publish_csv
    seed_xlsx = _pg.seed_xlsx
    intake = _pg.intake
    submit = _pg.submit
    worker = _pg.worker

    def test_scope_discovery_signed_loopback_authority_and_wire_limit(self):
        from fastapi.responses import JSONResponse
        from bri.api.unified_knowledge import create_staged_unified_knowledge_app
        from test_csv_intake_api import StagedCsvPostgres
        from test_unified_knowledge_postgres import ROLE

        _, sub, sid = self.actors[2]
        verified = True

        def provider(request):
            return auth_server_response(request, user_id=str(sub), factors=[{
                'factor_type': 'totp', 'status': 'verified' if verified else 'unverified'}])

        with self.connect('postgres') as db:
            db.execute("UPDATE bri.org_nodes SET display_name='' WHERE (tenant_id,node_id)=(%s,'team')", (self.tenant,))
        app = create_staged_unified_knowledge_app(identity_scope=lambda: self.connect('bri_app'),
            reader_scope=lambda: self.connect(ROLE), private_socket=self.sock, auth_transport=httpx.MockTransport(provider))
        client = self.enterContext(StagedCsvPostgres().loopback_reader(app))

        def discover():
            return client.get('/v1/knowledge/search/scopes', headers={'Authorization':
                f'Bearer {make_token(sub=str(sub), session_id=str(sid))}'})

        initial = discover()
        self.assertEqual(initial.json(), {'version': 1, 'status': 'complete', 'scopes': [
            {'scope_node_id': 'team', 'display_label': ''}]})
        padding = 131072 - len(JSONResponse(initial.json()).body)
        exact_label = 'é' * (padding // 2) + 'x' * (padding % 2)
        for label, status in ((exact_label, 200), (exact_label + 'x', 503)):
            with self.connect('postgres') as db:
                db.execute("UPDATE bri.org_nodes SET display_name=%s WHERE (tenant_id,node_id)=(%s,'team')",
                           (label, self.tenant))
            reply = discover()
            self.assertEqual(reply.status_code, status)
            if status == 200:
                self.assertEqual(len(reply.content), 131072)
            else:
                self.assertEqual(reply.json(), {'version': 1, 'status': 'unavailable'})
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.org_nodes SET display_name='Team' WHERE (tenant_id,node_id)=(%s,'team')", (self.tenant,))
        self.assertEqual(discover().status_code, 200)
        verified = False
        self.assertEqual(discover().status_code, 401)
        verified = True
        self.assertEqual(discover().status_code, 200)
        with self.connect('postgres') as db:
            db.execute('UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() WHERE session_id=%s', (sid,))
        self.assertEqual(discover().status_code, 403)
        with self.connect('postgres') as db:
            sid = uuid4()
            db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                       'VALUES (%s,%s,%s,clock_timestamp())', (*self.actors[2][:2], sid))
        self.assertEqual(discover().status_code, 200)
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_identity_links SET status='suspended' WHERE auth_user_id=%s", (sub,))
        self.assertEqual(discover().status_code, 403)

    def test_bounded_discovery_eligibility_and_no_transfer_of_authority(self):
        from bri.api.unified_knowledge import create_staged_unified_knowledge_app
        from test_csv_intake_api import StagedCsvPostgres
        from test_unified_knowledge_postgres import ROLE, SCOPES

        record, _ = self.publish_csv()
        actor, sub, sid = self.actors[2]
        _, platform_sub, platform_sid = self.actors[3]
        transport = httpx.MockTransport(lambda request: auth_server_response(request, user_id=str(
            platform_sub if request.headers.get('authorization') == platform_auth['Authorization'] else sub)))

        def auth(user=sub, session=sid, **claims):
            return {'Authorization': 'Bearer ' + make_token(sub=str(user), session_id=str(session), **claims)}

        platform_auth = auth(platform_sub, platform_sid)
        app = create_staged_unified_knowledge_app(identity_scope=lambda: self.connect('bri_app'),
            reader_scope=lambda: self.connect(ROLE), private_socket=self.sock, auth_transport=transport)
        client = self.enterContext(StagedCsvPostgres().loopback_reader(app))
        path = '/v1/knowledge/search/scopes'
        original = auth()
        discovery = client.get(path, headers=original)
        self.assertEqual(discovery.json(), {'version': 1, 'status': 'complete', 'scopes': [
            {'scope_node_id': 'team', 'display_label': 'Team'}]})
        for headers, expected in (({}, 401), ({'Authorization': 'Bearer malformed.token.signature'}, 401),
                (auth(exp=1), 401), (auth(iss='https://invalid.example/auth/v1'), 401),
                (auth(session=uuid4()), 403), (platform_auth, 403), (original | {'Tenant-Id': self.foreign}, 400)):
            reply = client.get(path, headers=headers)
            self.assertEqual(reply.status_code, expected)
            self.assertEqual(set(reply.json()), {'detail'})
            self.assertEqual(reply.headers['Cache-Control'], 'private, no-store')
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_identity_links SET auth_issuer='https://invalid.example/auth/v1',"
                       "provider_issuer='https://invalid.example/auth/v1' WHERE auth_user_id=%s", (sub,))
        self.assertEqual(client.get(path, headers=original).status_code, 403)
        with self.connect('postgres') as db:
            db.execute('UPDATE bri.auth_identity_links SET auth_issuer=%s,provider_issuer=%s WHERE auth_user_id=%s',
                       (ISSUER, ISSUER, sub))
            db.execute("UPDATE bri.auth_tenant_memberships SET status='suspended' WHERE (tenant_id,principal_id)=(%s,%s)",
                       (self.tenant, actor))
        self.assertEqual(client.get(path, headers=original).status_code, 403)
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_tenant_memberships SET status='active' WHERE (tenant_id,principal_id)=(%s,%s)",
                       (self.tenant, actor))
            expired = uuid4()
            db.execute("INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at,expires_at) "
                       "VALUES (%s,%s,%s,clock_timestamp()-interval '9 hours',clock_timestamp()+interval '1 hour')",
                       (actor, sub, expired))
            sid = uuid4()
            db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                       'VALUES (%s,%s,%s,clock_timestamp())', (actor, sub, sid))
        self.assertEqual(client.get(path, headers=auth(session=expired)).status_code, 403)
        current = auth(session=sid)
        self.assertEqual(client.get(path, headers=current).json(), discovery.json())
        evidence = f'/v1/knowledge/csv/{record}/versions/{record}/evidence'
        self.assertEqual(client.get(evidence, headers=current).status_code, 200)
        with self.connect('postgres') as db:
            db.execute(f'REVOKE EXECUTE ON FUNCTION {SCOPES} FROM {ROLE}')
        try:
            unavailable = client.get(path, headers=current)
            self.assertEqual((unavailable.status_code, unavailable.json()),
                             (503, {'version': 1, 'status': 'unavailable'}))
        finally:
            with self.connect('postgres') as db:
                db.execute(f'GRANT EXECUTE ON FUNCTION {SCOPES} TO {ROLE}')
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_role_assignments SET status='revoked' WHERE "
                       "(tenant_id,principal_id,role_id,scope_node_id)=(%s,%s,'csv','team')", (self.tenant, actor))
            next_sid = uuid4()
            db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                       'VALUES (%s,%s,%s,clock_timestamp())', (actor, sub, next_sid))
        fresh = auth(session=next_sid)
        self.assertEqual(client.get(path, headers=fresh).json(), {'version': 1, 'status': 'complete', 'scopes': []})
        self.assertEqual(client.post('/v1/knowledge/search', headers=fresh,
                                    json={'scope_node_id': 'team', 'query': 'head'}).status_code, 403)
        self.assertEqual(client.get(evidence, headers=fresh).status_code, 404)

    def test_actual_sql_to_http_wire_cap_and_overflow(self):
        from fastapi.responses import JSONResponse
        from bri.api.unified_knowledge import create_staged_unified_knowledge_app
        from test_csv_intake_api import StagedCsvPostgres
        from test_unified_knowledge_postgres import ROLE

        _, sub, sid = self.actors[0]
        headers = {'Authorization': f'Bearer {make_token(sub=str(sub), session_id=str(sid))}'}
        def provider(request):
            return auth_server_response(request, user_id=str(sub))
        app = create_staged_unified_knowledge_app(identity_scope=lambda: self.connect('bri_app'),
            reader_scope=lambda: self.connect(ROLE), private_socket=self.sock, auth_transport=httpx.MockTransport(provider))
        client = self.enterContext(StagedCsvPostgres().loopback_reader(app))
        def search(q):
            return client.post('/v1/knowledge/search', headers=headers, json={'scope_node_id':'team','query':q})
        self.publish_csv('label\ncapxé'.encode())
        reply = search('capx')
        self.assertEqual(reply.status_code,200,reply.text)
        hit, = reply.json()['results']
        # Fixed-width UUIDs/digests make the reference skeleton independent of the generated IDs.
        blank = JSONResponse({'version':1,'status':'complete','results':[hit]*20}).body
        remaining = 131072 - len(blank)
        suffixes = []
        for _ in range(19):
            count = min(1700, remaining // 6)
            suffixes.append('\x02'*count)
            remaining -= 6*count
        self.assertIn(remaining,range(6))
        suffixes[-1] += 'z'*remaining
        for suffix in suffixes:
            self.publish_csv(('label\ncapxé'+suffix).encode())
        exact = search('capx')
        self.assertEqual(exact.status_code,200,exact.text)
        self.assertEqual(len(exact.content),131072)
        self.assertEqual(len(exact.json()['results']),20)
        self.assertTrue(all(not h['excerpt_truncated'] and 'é' in h['excerpt'] for h in exact.json()['results']))
        self.publish_csv('label\ncapyéa'.encode())
        for suffix in suffixes:
            self.publish_csv(('label\ncapyé'+suffix).encode())
        over = search('capy')
        self.assertEqual((over.status_code,over.json()), (503,{'version':1,'status':'unavailable'}))

    def test_signed_versions_revalidate_every_evidence_gate(self):
        from bri.api.unified_knowledge import create_staged_unified_knowledge_app
        from bri.api.xlsx_governance import create_staged_xlsx_governance_app
        from test_csv_intake_api import StagedCsvPostgres
        from test_unified_knowledge_postgres import ROLE

        csv_id, extracted = self.publish_csv()
        (record, version), = self.seed_xlsx()
        actor, sub, sid = self.actors[0]
        auth = {}
        verified = True
        def authenticate(session):
            auth['Authorization'] = f'Bearer {make_token(sub=str(sub), session_id=str(session))}'
        authenticate(sid)
        def provider(request):
            valid = request.headers.get('authorization') == auth['Authorization']
            factors = [{'factor_type':'totp','status':'verified' if verified else 'unverified'}]
            return auth_server_response(request, user_id=str(sub) if valid else '', status=200 if valid else 401,
                                        factors=factors)
        transport = httpx.MockTransport(provider)
        loopback = StagedCsvPostgres().loopback_reader
        search = self.enterContext(loopback(create_staged_unified_knowledge_app(
            identity_scope=lambda: self.connect('bri_app'), private_socket=self.sock, auth_transport=transport,
            reader_scope=lambda: self.connect(ROLE))))
        xlsx = self.enterContext(loopback(create_staged_xlsx_governance_app(
            identity_scope=lambda: self.connect('bri_app'), private_socket=self.sock, auth_transport=transport,
            reader_scope=lambda: self.connect('bri_xlsx_reader'), review_scope=lambda: self.connect('bri_xlsx_reviewer'))))
        csv_path = f'/v1/knowledge/csv/{csv_id}/versions/{csv_id}/evidence'
        x1 = f'/v1/knowledge/xlsx/{record}/evidence/{version}'
        x2 = '/v2' + x1[3:]
        guarded = ((search,csv_path),(xlsx,x1),(xlsx,x2))
        def initial():
            reply = search.post('/v1/knowledge/search', headers=auth, json={'scope_node_id':'team','query':'head'})
            self.assertEqual(reply.status_code,200,reply.text)
            self.assertEqual(reply.json()['version'],1)
            self.assertEqual([h['evidence_url'] for h in reply.json()['results']], [x2,csv_path])
            return reply.json()['results']
        def get(client, path, status=200):
            reply = client.get(path, headers=auth)
            self.assertEqual(reply.status_code,status,reply.text)
            self.assertEqual(reply.headers['cache-control'],'private, no-store')
            if status != 200:
                self.assertEqual(set(reply.json()), {'detail'})
            return reply.json()
        def ok():
            for client,path in guarded:
                get(client,path)
        def exec_fixture(sql, args):
            with self.connect('postgres') as db:
                db.execute(sql,args)
        def csv_gate(table, readable):
            with self.connect('bri_migrator') as db:
                db.execute("SELECT set_config('bri.tenant_id',%s,true)",(self.tenant,))
                db.execute(f'UPDATE bri.knowledge_{table}_access SET readable=%s WHERE tenant_id=%s AND source_id=%s',
                           (readable,self.tenant,f'csv:{csv_id}'))
        def new_session():
            current = uuid4()
            exec_fixture('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                         'VALUES (%s,%s,%s,clock_timestamp())',(actor,sub,current))
            authenticate(current)
            return current
        xhit, chit = initial()
        self.assertEqual(chit['content_sha256'], extracted.extracted_sha256)
        self.assertEqual(chit['source_id'],f'csv:{csv_id}')
        csv_page, page1, page2 = (get(*pair) for pair in guarded)
        self.assertEqual(csv_page['content_sha256'], chit['content_sha256'])
        self.assertEqual(page2, page1 | {'version':2, **{key:xhit[key] for key in
                        ('source_id','original_sha256','canonical_sha256','extractor_version','canonicalization_version')}})
        self.assertEqual(page1['sheet_title'],xhit['evidence']['sheet_title'])
        verified = False
        for pair in guarded:
            get(*pair,401)
        denied = search.post('/v1/knowledge/search', headers=auth, json={'scope_node_id':'team','query':'head'})
        self.assertEqual(denied.status_code,401)
        self.assertEqual(set(denied.json()), {'detail'})
        verified = True
        ok()
        wrong = tuple(get(client,path.replace(str(vid),str(uuid4()),1) if client is xlsx else
                          path.replace(f'/versions/{vid}/',f'/versions/{uuid4()}/'),404)
                      for (client,path),vid in zip(guarded,(csv_id,version,version),strict=True))
        for gate in ('record','version'):
            csv_gate(gate,False)
            self.assertEqual(get(search,csv_path,404),wrong[0])
            csv_gate(gate,True)
            keys = (self.tenant,record,actor) if gate == 'record' else (self.tenant,record,version,actor)
            exec_fixture(f'DELETE FROM bri.xlsx_{gate}_access WHERE tenant_id=%s AND record_id=%s AND principal_id=%s',
                         (self.tenant,record,actor))
            self.assertEqual(get(xlsx,x1,404),wrong[1]); self.assertEqual(get(xlsx,x2,404),wrong[2])
            markers = ','.join(['%s']*len(keys))
            exec_fixture(f'INSERT INTO bri.xlsx_{gate}_access VALUES ({markers})',keys)
            ok()
        for revision, action in ((2,'withdraw'),(3,'publish')):
            exec_fixture('INSERT INTO bri.xlsx_publication_events (tenant_id,record_id,job_id,revision,action,actor_id) '
                         'VALUES (%s,%s,%s,%s,%s,%s)',(self.tenant,record,version,revision,action,actor))
            if action == 'withdraw':
                self.assertEqual(get(xlsx,x1,404),wrong[1]); self.assertEqual(get(xlsx,x2,404),wrong[2])
        ok()
        exec_fixture('UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() WHERE session_id=%s',(sid,))
        self.assertEqual(get(search,csv_path,404),wrong[0]); get(xlsx,x1,403)
        self.assertEqual(get(xlsx,x2,404),wrong[2])
        exec_fixture("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) VALUES (%s,%s,'csv','root')",
                     (self.tenant,actor))
        new_session()
        ok()
        exec_fixture("UPDATE bri.auth_role_assignments SET status='revoked' WHERE tenant_id=%s AND principal_id=%s AND scope_node_id='team'",
                     (self.tenant,actor))
        new_session()  # Keep a valid session and root grant; neither grants the exact team node.
        for pair, denial in zip(guarded,wrong,strict=True):
            self.assertEqual(get(*pair,404),denial)
        self.assertEqual(search.post('/v1/knowledge/search',headers=auth,
                                    json={'scope_node_id':'team','query':'head'}).status_code,403)

    def test_signed_search_then_exact_evidence_after_revocation_on_real_listener(self):
        from test_csv_intake_api import StagedCsvPostgres
        from test_unified_knowledge_postgres import ROLE

        from bri.api.unified_knowledge import create_staged_unified_knowledge_app

        record, extraction = self.publish_csv()
        (xlsx_record, xlsx_version), = self.seed_xlsx()
        _, uid, sid = self.actors[0]
        headers = {'Authorization': f'Bearer {make_token(sub=str(uid), session_id=str(sid))}'}

        def provider(request):
            valid = request.headers.get('authorization') == headers['Authorization']
            return auth_server_response(request, user_id=str(uid) if valid else '', status=200 if valid else 401)

        app = create_staged_unified_knowledge_app(
            identity_scope=lambda: self.connect('bri_app'), reader_scope=lambda: self.connect(ROLE),
            private_socket=self.sock, auth_transport=httpx.MockTransport(provider),
        )
        client = self.enterContext(StagedCsvPostgres().loopback_reader(app))
        request = {'scope_node_id': 'team', 'query': '  HEAd   ER  '}
        search = client.post('/v1/knowledge/search', headers=headers, json=request)
        self.assertEqual(search.status_code, 200, search.text)
        self.assertEqual(search.headers['cache-control'], 'private, no-store')
        hit, = search.json()['results']
        self.assertEqual(hit['record_id'], str(record))
        self.assertEqual(hit['evidence'], {'first_line': 1, 'last_line': 2})
        combined = client.post('/v1/knowledge/search', headers=headers, json=request | {'query': 'head'})
        self.assertEqual(combined.status_code, 200, combined.text)
        self.assertEqual([(entry['format'], entry['record_id']) for entry in combined.json()['results']],
                         [('xlsx', str(xlsx_record)), ('csv', str(record))])
        xlsx_hit = combined.json()['results'][0]
        self.assertEqual(xlsx_hit['source_version_id'], str(xlsx_version))
        self.assertEqual(xlsx_hit['evidence'], {'sheet_id': '1', 'sheet_title': 'Synthetic', 'cell': 'A2'})
        url = f"/v1/knowledge/csv/{hit['record_id']}/versions/{hit['source_version_id']}/evidence"
        evidence = client.get(url, headers=headers)
        self.assertEqual(evidence.status_code, 200, evidence.text)
        self.assertEqual(evidence.json()['content_sha256'], extraction.extracted_sha256)
        self.assertEqual(evidence.headers['cache-control'], 'private, no-store')
        wrong = client.get(url.replace(f'/versions/{record}/', f'/versions/{uuid4()}/'), headers=headers)
        self.assertEqual(wrong.status_code, 404, wrong.text)
        self.assertEqual(client.get(url.replace('/csv/', '/%63sv/'), headers=headers).status_code, 404)
        with self.connect('bri_migrator') as db:
            db.execute("SELECT set_config('bri.tenant_id', %s, true)", (self.tenant,))
            db.execute('UPDATE bri.knowledge_version_access SET readable=false WHERE tenant_id=%s AND source_id=%s',
                       (self.tenant, f'csv:{record}'))
        revoked = client.get(url, headers=headers)
        self.assertEqual((revoked.status_code, revoked.content), (404, wrong.content))
        empty = client.post('/v1/knowledge/search', headers=headers, json=request)
        self.assertEqual((empty.status_code, empty.json()), (200, {'version': 1, 'status': 'complete', 'results': []}))
