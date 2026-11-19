"""HTTP contract for the verified, read-only ordinary account history."""
import os
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from typing import cast
from unittest import TestCase, skipUnless
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
from psycopg.errors import InsufficientPrivilege, InvalidParameterValue, UndefinedFunction

from bri.access.policy import AccessGrant, Principal
from bri.api.app import ApiSettings, DatabaseProtocol, create_app
from bri.api.authentication import AuthenticatedIdentity
from bri.api.catalog import SyntheticCatalog
from bri.api.database import Database, TenantSession
import test_account_history_postgres as postgres
from test_remote_auth_api import AUTH_USER_ID, ISSUER, SESSION_ID, FakeRemoteDatabase, FakeVerifier

TENANT = 'history-tenant'
ACTOR = str(uuid4())
TARGET = uuid4()
EVENT = UUID('e7862349-a9ea-4915-9c89-6e68ce3bb778')
TIMESTAMP = datetime(2026, 11, 19, 9, tzinfo=timezone.utc)
PATH = f'/v1/users/{TARGET}/history'
HEADERS = {'Authorization': 'Bearer valid-supabase-token'}
DIRECTORY = 'user:directory:read'
HISTORY = 'account:history:read'


def principal(*permissions):
    return Principal(ACTOR, frozenset({TENANT}), tuple(AccessGrant(TENANT, p, 'root') for p in permissions),
                     ((TENANT, 'admin'),))


class HistoryDatabase(FakeRemoteDatabase):
    def __init__(self, *permissions):
        super().__init__(principal(*permissions))
        self.calls = []
        self.rows = []
        self.error = None

    @contextmanager
    def protected_tenant_context(self, tenant_id, *, auth_user_id, session_id, principal_id, issuer):
        with super().protected_tenant_context(tenant_id, auth_user_id=auth_user_id, session_id=session_id,
                                              principal_id=principal_id, issuer=issuer):
            yield TenantSession(tenant_id, self)

    def execute(self, sql, args):
        assert sql.startswith('SELECT ')
        assert 'FROM bri.read_account_history(' in sql
        self.calls.append(args)
        if self.error is not None:
            raise self.error
        return self

    def fetchall(self):
        return self.rows


def hosted_client(db: HistoryDatabase):
    return TestClient(create_app(
        settings=ApiSettings(environment='hosted-development', auth_mode='supabase'),
        database=cast(DatabaseProtocol, db), token_verifier=FakeVerifier(),
    ))


class AccountHistoryApiTests(TestCase):
    def assert_reply(self, response, status, body):
        self.assertEqual(response.status_code, status, response.text)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(response.json(), body)

    def test_history_projects_only_defined_fields_and_restricts_unavailable_actor(self):
        db = HistoryDatabase(DIRECTORY, HISTORY)
        db.rows = [(EVENT, TIMESTAMP, 'deactivated', 'success', 'account_closed', None, 'Do not disclose'),
                   (uuid4(), TIMESTAMP, 'activated', 'success', None, UUID(ACTOR), 'Visible actor')]
        with hosted_client(db) as client:
            response = client.get(PATH, headers=HEADERS)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(response.json(), {'items': [
            {'id': str(EVENT), 'occurred_at': '2026-11-19T09:00:00Z', 'action': 'deactivated', 'outcome': 'success',
             'reason_code': 'account_closed', 'actor': {'id': None, 'display_name': 'Restricted actor'}},
            {'id': str(db.rows[1][0]), 'occurred_at': '2026-11-19T09:00:00Z', 'action': 'activated', 'outcome': 'success',
             'reason_code': None, 'actor': {'id': ACTOR, 'display_name': 'Visible actor'}},
        ], 'next_cursor': None})
        self.assertEqual(db.protected_scopes, [(TENANT, AUTH_USER_ID, SESSION_ID, ACTOR, ISSUER)])
        self.assertEqual(db.calls, [(TENANT, ACTOR, SESSION_ID, ISSUER, TARGET, 25, None)])

    def test_next_cursor_identifies_last_disclosed_event_not_lookahead(self):
        db = HistoryDatabase(DIRECTORY, HISTORY)
        older = uuid4()
        first = (EVENT, TIMESTAMP, 'activated', 'success', None, None, None)
        second = (older, TIMESTAMP, 'provisioned', 'success', None, None, None)
        db.rows = [first, second]
        with hosted_client(db) as client:
            page = client.get(PATH, params={'limit': 1}, headers=HEADERS)
            self.assertEqual(page.status_code, 200, page.text)
            self.assertEqual([item['id'] for item in page.json()['items']], [str(EVENT)])
            self.assertEqual(page.json()['next_cursor'], str(EVENT))
            db.rows = [second]
            page = client.get(PATH, params={'limit': 1, 'cursor': page.json()['next_cursor']}, headers=HEADERS)
            self.assertEqual(page.status_code, 200, page.text)
            self.assertEqual([item['id'] for item in page.json()['items']], [str(older)])
            self.assertIsNone(page.json()['next_cursor'])
        self.assertEqual([args[-2:] for args in db.calls], [(1, None), (1, EVENT)])

    def test_invalid_or_duplicate_query_parameters_never_reach_database_read(self):
        db = HistoryDatabase(DIRECTORY, HISTORY)
        with hosted_client(db) as client:
            for query in ('limit=0', 'limit=101', 'limit=%2B1', 'limit=1.0', 'limit=', 'limit=١', 'limit=1&limit=1',
                          'cursor=', f'cursor={EVENT.hex}', f'cursor={str(EVENT).upper()}',
                          f'cursor={EVENT}&cursor={EVENT}', 'principal_id=other', 'issuer=other', 'session_id=other'):
                with self.subTest(query=query):
                    self.assert_reply(client.get(f'{PATH}?{query}', headers=HEADERS), 400,
                                      {'detail': 'Invalid history query'})
            detail = {'detail': 'Tenant selection is server-controlled'}
            self.assert_reply(client.get(f'{PATH}?tenant_id=other', headers=HEADERS), 400, detail)
            self.assert_reply(client.get(PATH, headers=HEADERS | {'X-Tenant-ID': 'other'}), 400, detail)
        self.assertEqual(db.protected_scopes, [])
        self.assertEqual(db.calls, [])

    def test_missing_account_and_malformed_path_match_but_visible_empty_is_success(self):
        db = HistoryDatabase(DIRECTORY, HISTORY)
        with hosted_client(db) as client:
            self.assert_reply(client.get(PATH, headers=HEADERS), 404, {'detail': 'Not Found'})
            self.assert_reply(client.get('/v1/users/invalid/history', headers=HEADERS), 404, {'detail': 'Not Found'})
            db.rows = [(None,) * 7]
            self.assert_reply(client.get(PATH, headers=HEADERS), 200, {'items': [], 'next_cursor': None})

    def test_admin_and_both_explicit_same_tenant_permissions_are_required_before_query(self):
        db = HistoryDatabase(DIRECTORY, HISTORY)
        db.rows = [(None,) * 7]
        both = principal(DIRECTORY, HISTORY)
        with hosted_client(db) as client:
            self.assert_reply(client.get(PATH, headers=HEADERS), 200, {'items': [], 'next_cursor': None})
            db.protected_scopes.clear()
            db.calls.clear()
            for denied in (principal(), principal(DIRECTORY), principal(HISTORY),
                           replace(both, platform_superadmin=True), replace(both, role_bindings=((TENANT, 'user'),)),
                           replace(both, tenant_ids=frozenset({TENANT, 'other'})),
                           replace(both, grants=(*principal(DIRECTORY).grants, AccessGrant('other', HISTORY, 'root')))):
                with self.subTest(principal=denied):
                    db.principal = denied
                    self.assert_reply(client.get(PATH, headers=HEADERS), 403,
                                      {'detail': 'Client access is not authorized'})
        self.assertEqual(db.protected_scopes, [])
        self.assertEqual(db.calls, [])

    def test_default_auth_failure_and_hosted_session_failure_are_not_cacheable(self):
        db = HistoryDatabase(DIRECTORY, HISTORY)
        with TestClient(create_app(settings=ApiSettings(), database=cast(DatabaseProtocol, db))) as disabled:
            self.assert_reply(disabled.get(PATH), 503, {'detail': 'Authentication is not configured'})
        with hosted_client(db) as hosted:
            self.assert_reply(hosted.get(PATH), 401, {'detail': 'A valid Supabase access token is required'})
            db.active_session = False
            self.assert_reply(hosted.get(PATH, headers=HEADERS), 401, {'detail': 'BRI session is inactive or expired'})
        self.assertEqual(db.protected_scopes, [])

    def test_synthetic_principal_with_both_permissions_is_rejected(self):
        db = HistoryDatabase(DIRECTORY, HISTORY)
        app = create_app(settings=ApiSettings(environment='development', dev_auth_enabled=True),
                         database=cast(DatabaseProtocol, db),
                         catalog=SyntheticCatalog({}, {'fake-admin': principal(DIRECTORY, HISTORY)}))
        with TestClient(app, client=('127.0.0.1', 1234)) as client:
            self.assert_reply(client.get(PATH, headers={'X-Dev-Identity': 'fake-admin'}), 403,
                              {'detail': 'Client access is not authorized'})
        self.assertEqual(db.protected_scopes, [])

    def test_database_errors_are_generic(self):
        db = HistoryDatabase(DIRECTORY, HISTORY)
        with hosted_client(db) as client:
            for exception, status, body in (
                (InsufficientPrivilege, 403, {'detail': 'Client access is not authorized'}),
                (InvalidParameterValue, 400, {'detail': 'Invalid history query'}),
                (UndefinedFunction, 503, {'status': 'unavailable', 'database': 'unavailable'}),
            ):
                with self.subTest(sqlstate=exception.sqlstate):
                    db.error = exception('private database diagnostic')
                    self.assert_reply(client.get(PATH, params={'cursor': str(EVENT)}, headers=HEADERS), status, body)

    def test_unsafe_rows_including_lookahead_fail_closed(self):
        db = HistoryDatabase(DIRECTORY, HISTORY)
        good = (EVENT, TIMESTAMP, 'activated', 'success', None, None, None)
        with hosted_client(db) as client:
            for tail in ([(None,) * 7], [good], [(uuid4(), *good[1:])] * 2,
                         [(uuid4(), TIMESTAMP, 'raw.audit.event', *good[3:])],
                         [(uuid4(), TIMESTAMP, 'activated', 'success', 'private free-text note', None, None)],
                         [(uuid4(), TIMESTAMP.replace(tzinfo=None), *good[2:])]):
                with self.subTest(tail=tail):
                    db.rows = [good, *tail]
                    self.assert_reply(client.get(PATH, params={'limit': 1}, headers=HEADERS), 503,
                                      {'status': 'unavailable', 'database': 'unavailable'})

    def test_post_is_not_mounted_or_cacheable(self):
        db = HistoryDatabase(DIRECTORY, HISTORY)
        with hosted_client(db) as client:
            self.assert_reply(client.post(PATH, headers=HEADERS), 405, {'detail': 'Method Not Allowed'})
            operation = client.get('/openapi.json').json()['paths']['/v1/users/{id}/history']
            self.assertEqual(set(operation), {'get'})
            self.assertEqual({p['name'] for p in operation['get']['parameters'] if p['in'] == 'query'},
                             {'limit', 'cursor'})
        self.assertEqual(db.protected_scopes, [])


@skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16')
class AccountHistoryDisposableApiTests(TestCase):
    actor: tuple[UUID, UUID, UUID]
    target: UUID
    tenant: str
    foreign_actors: list[tuple[UUID, UUID, UUID]]

    @classmethod
    def connect(cls, role, **kwargs):
        return postgres.AccountHistoryTests.connect.__func__(cls, role, **kwargs)

    @classmethod
    def setUpClass(cls):
        postgres.AccountHistoryTests.setUpClass.__func__(cls)

    def setUp(self):
        # Both suites exercise the same synthetic actors and database grants.
        postgres.AccountHistoryTests.setUp(cast(postgres.AccountHistoryTests, self))

    def test_real_app_role_projects_and_paginates_existing_events(self):
        admin, user, session = self.actor
        older, newer = sorted((uuid4(), uuid4()))
        row_count = 'SELECT count(*) FROM bri.security_audit_events WHERE tenant_id=%s'
        with self.connect('postgres') as db:
            for event, actor, action in ((older, admin, 'requested'), (newer, self.target, 'active')):
                db.execute('INSERT INTO bri.security_audit_events(event_id,tenant_id,actor_principal_id,'
                           'subject_principal_id,event_type,outcome,occurred_at) '
                           "VALUES (%s,%s,%s,%s,%s,'success',%s)",
                           (event, self.tenant, actor, self.target, f'tenant.user.provisioning.{action}', TIMESTAMP))
            before = db.execute(row_count, (self.tenant,)).fetchone()

        connect = self.connect

        class LocalDatabase(Database):
            def _connect(self):
                return connect('bri_app')

        verifier = FakeVerifier()
        issuer = postgres.ISSUER
        url = issuer.removesuffix('/auth/v1')
        verifier.identity = AuthenticatedIdentity(str(user), str(session), issuer, 'aal2', ('totp',))
        app = create_app(settings=ApiSettings(environment='hosted-development', auth_mode='supabase', supabase_url=url),
                         database=LocalDatabase(url, ''), token_verifier=verifier)
        with TestClient(app) as client:
            path = f'/v1/users/{self.target}/history'
            first = client.get(path, params={'limit': 1}, headers=HEADERS)
            self.assertEqual(first.status_code, 200, first.text)
            self.assertEqual(first.headers['Cache-Control'], 'no-store')
            self.assertEqual(first.json(), {'items': [
                {'id': str(newer), 'occurred_at': '2026-11-19T09:00:00Z', 'action': 'activated', 'outcome': 'success',
                 'reason_code': None, 'actor': {'id': str(self.target), 'display_name': None}},
            ], 'next_cursor': str(newer)})
            second = client.get(path, params={'cursor': first.json()['next_cursor']}, headers=HEADERS)
            self.assertEqual(second.status_code, 200, second.text)
            self.assertEqual(second.json(), {'items': [
                {'id': str(older), 'occurred_at': '2026-11-19T09:00:00Z', 'action': 'provisioned', 'outcome': 'success',
                 'reason_code': None, 'actor': {'id': None, 'display_name': 'Restricted actor'}},
            ], 'next_cursor': None})
            invalid = client.get(path, params={'cursor': str(uuid4())}, headers=HEADERS)
            self.assertEqual((invalid.status_code, invalid.json()), (400, {'detail': 'Invalid history query'}))
            for hidden in (self.foreign_actors[2][0], admin, uuid4()):
                response = client.get(f'/v1/users/{hidden}/history', headers=HEADERS)
                self.assertEqual((response.status_code, response.json()), (404, {'detail': 'Not Found'}))
                self.assertEqual(response.headers['Cache-Control'], 'no-store')

        with self.connect('postgres') as db:
            self.assertEqual(db.execute(row_count, (self.tenant,)).fetchone(), before)
