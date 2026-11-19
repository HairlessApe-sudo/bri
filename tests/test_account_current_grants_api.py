"""HTTP contract for the verified current account grants projection."""
import os
from contextlib import contextmanager
from dataclasses import replace
from typing import cast
from unittest import TestCase, skipUnless
from unittest.mock import patch
from uuid import UUID, uuid4

from fastapi.testclient import TestClient
from psycopg.errors import InsufficientPrivilege, UndefinedFunction

from bri.access.policy import AccessGrant, Principal
from bri.api.app import ApiSettings, DatabaseProtocol, create_app
from bri.api.authentication import AuthenticatedIdentity
from bri.api.catalog import SyntheticCatalog
from bri.api.database import Database, TenantSession
import test_account_current_grants_postgres as postgres
from test_remote_auth_api import AUTH_USER_ID, ISSUER, SESSION_ID, FakeRemoteDatabase, FakeVerifier

TENANT = 'grants-tenant'
ACTOR = str(uuid4())
TARGET = uuid4()
PATH = f'/v1/users/{TARGET}/grants'
HEADERS = {'Authorization': 'Bearer valid-supabase-token'}
DIRECTORY = 'user:directory:read'
GRANTS = 'account:grants:read'
ORGANISATION = 'organisation:read'
KNOWLEDGE = 'knowledge:read'
DENIED = {'detail': 'Client access is not authorized'}
NOT_FOUND = {'detail': 'Not Found'}
UNAVAILABLE = {'status': 'unavailable', 'database': 'unavailable'}


def principal(*permissions):
    return Principal(ACTOR, frozenset({TENANT}), tuple(AccessGrant(TENANT, p, 'root') for p in permissions),
                     ((TENANT, 'admin'),))


class GrantsDatabase(FakeRemoteDatabase):
    def __init__(self):
        super().__init__(principal(DIRECTORY, GRANTS, ORGANISATION))
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
        assert 'FROM bri.read_account_current_grants(%s,%s,%s,%s,%s)' in sql
        self.calls.append(args)
        if self.error:
            raise self.error
        return self

    def fetchall(self):
        return self.rows


def hosted_client(db):
    return TestClient(create_app(
        settings=ApiSettings(environment='hosted-development', auth_mode='supabase'),
        database=cast(DatabaseProtocol, db), token_verifier=FakeVerifier(),
    ))


def item(permission, scope_id='root', scope_name='Client root'):
    return {'scope_id': scope_id, 'scope_name': scope_name, 'permission': permission}


class AccountCurrentGrantsApiTests(TestCase):
    def assert_reply(self, response, status, body):
        self.assertEqual(response.status_code, status, response.text)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertEqual(response.json(), body)

    def test_projects_assigned_and_effective_from_verified_actor_context(self):
        db = GrantsDatabase()
        db.rows = [('superuser', 'active', 'root', 'Client root', KNOWLEDGE, True),
                   ('superuser', 'active', 'root', 'Client root', ORGANISATION, False)]
        with hosted_client(db) as client:
            self.assert_reply(client.get(PATH, headers=HEADERS), 200, {
                'account_class': 'superuser', 'account_status': 'active',
                'assigned': [item(KNOWLEDGE), item(ORGANISATION)], 'effective': [item(KNOWLEDGE)],
            })
        self.assertEqual(db.protected_scopes, [(TENANT, AUTH_USER_ID, SESSION_ID, ACTOR, ISSUER)])
        self.assertEqual(db.calls, [(TENANT, UUID(ACTOR), SESSION_ID, ISSUER, TARGET)])

    def test_visible_empty_is_distinct_from_generic_unavailable_target(self):
        db = GrantsDatabase()
        with hosted_client(db) as client:
            for invalid in ('not-a-uuid', TARGET.hex, '{' + str(TARGET) + '}'):
                self.assert_reply(client.get(f'/v1/users/{invalid}/grants', headers=HEADERS), 404, NOT_FOUND)
            self.assertEqual(db.protected_scopes, [])
            self.assert_reply(client.get(PATH, headers=HEADERS), 404, NOT_FOUND)
            db.rows = [('user', 'pending', None, None, None, None)]
            self.assert_reply(client.get(PATH, headers=HEADERS), 200, {
                'account_class': 'user', 'account_status': 'pending', 'assigned': [], 'effective': [],
            })

    def test_nonactive_accounts_have_no_effective_grants_even_if_sql_marks_eligible(self):
        db = GrantsDatabase()
        with hosted_client(db) as client:
            for status in ('suspended', 'deactivated', 'pending'):
                with self.subTest(status=status):
                    db.rows = [('user', status, 'root', 'Client root', KNOWLEDGE, True)]
                    self.assert_reply(client.get(PATH, headers=HEADERS), 200, {
                        'account_class': 'user', 'account_status': status,
                        'assigned': [item(KNOWLEDGE)], 'effective': [],
                    })

    def test_effective_grants_also_obey_the_shared_role_ceiling(self):
        db = GrantsDatabase()
        db.rows = [('user', 'active', 'root', 'Client root', KNOWLEDGE, True)]
        # These permissions currently pass the shared ceiling; simulate its narrowing.
        with hosted_client(db) as client, patch('bri.api.account_current_grants.role_allows_permission',
                                                return_value=False) as ceiling:
            self.assert_reply(client.get(PATH, headers=HEADERS), 200, {
                'account_class': 'user', 'account_status': 'active',
                'assigned': [item(KNOWLEDGE)], 'effective': [],
            })
        ceiling.assert_called_once_with('user', KNOWLEDGE)

    def test_invalid_projection_fails_closed_without_partial_disclosure(self):
        db = GrantsDatabase()
        good = ('user', 'active', 'root', 'Client root', KNOWLEDGE, True)
        with hosted_client(db) as client:
            for bad in (
                ('admin', *good[1:]), ('user', 'disabled', *good[2:]),
                (*good[:4], 'Knowledge:read', True), (*good[:4], 'account:grants:read', True),
                (*good[:5], 1), (*good[:5], None),
                (*good[:2], None, *good[3:]), (*good[:2], '', *good[3:]),
                (*good[:3], 42, *good[4:]), (*good[:3], 'Label\x00', *good[4:]),
                ('user', 'active', None, None, None, None),
                ('superuser', *good[1:]), ('user', 'suspended', *good[2:]),
                (*good, uuid4()), good, (*good[:3], 'Conflicting name', ORGANISATION, False),
            ):
                with self.subTest(bad=bad):
                    self.assert_reply_for_rows(client, db, [good, bad])
            self.assert_reply_for_rows(client, db, [('admin', 'active', None, None, None, None)])

    def assert_reply_for_rows(self, client, db, rows):
        db.rows = rows
        self.assert_reply(client.get(PATH, headers=HEADERS), 503, UNAVAILABLE)

    def test_queries_and_browser_tenant_headers_are_rejected_before_protected_read(self):
        db = GrantsDatabase()
        with hosted_client(db) as client:
            for query in ('scope_id=root', 'limit=1&limit=1', 'session_id=other', 'account_status', '&'):
                self.assert_reply(client.get(f'{PATH}?{query}', headers=HEADERS), 400,
                                  {'detail': 'Invalid grants query'})
            detail = {'detail': 'Tenant selection is server-controlled'}
            self.assert_reply(client.get(f'{PATH}?tenant_id=other', headers=HEADERS), 400, detail)
            for header in ('X-Tenant-ID', 'X-BRI-Tenant-Context'):
                self.assert_reply(client.get(PATH, headers=HEADERS | {header: 'other'}), 400, detail)
        self.assertEqual(db.protected_scopes, [])
        self.assertEqual(db.calls, [])

    def test_only_single_tenant_client_admin_with_both_explicit_grants_can_read(self):
        db = GrantsDatabase()
        both = principal(DIRECTORY, GRANTS)
        db.principal = both
        with hosted_client(db) as client:
            db.rows = [('user', 'active', None, None, None, None)]
            self.assert_reply(client.get(PATH, headers=HEADERS), 200, {
                'account_class': 'user', 'account_status': 'active', 'assigned': [], 'effective': [],
            })
            db.protected_scopes.clear()
            db.calls.clear()
            for denied in (
                principal(), principal(DIRECTORY), principal(GRANTS),
                replace(both, platform_superadmin=True), replace(both, role_bindings=((TENANT, 'superuser'),)),
                replace(both, tenant_ids=frozenset({TENANT, 'other'})),
                replace(both, grants=(*principal(DIRECTORY).grants, AccessGrant('other', GRANTS, 'root'))),
            ):
                with self.subTest(principal=denied):
                    db.principal = denied
                    self.assert_reply(client.get(PATH, headers=HEADERS), 403, DENIED)
        self.assertEqual(db.protected_scopes, [])
        self.assertEqual(db.calls, [])

    def test_synthetic_principal_with_both_permissions_is_rejected(self):
        db = GrantsDatabase()
        app = create_app(settings=ApiSettings(environment='development', dev_auth_enabled=True),
                         database=cast(DatabaseProtocol, db),
                         catalog=SyntheticCatalog({}, {'fake-admin': principal(DIRECTORY, GRANTS)}))
        with TestClient(app, client=('127.0.0.1', 1234)) as client:
            self.assert_reply(client.get(PATH, headers={'X-Dev-Identity': 'fake-admin'}), 403, DENIED)
        self.assertEqual(db.protected_scopes, [])

    def test_authentication_errors_are_not_cacheable(self):
        db = GrantsDatabase()
        with TestClient(create_app(settings=ApiSettings(), database=cast(DatabaseProtocol, db))) as disabled:
            self.assert_reply(disabled.get(PATH), 503, {'detail': 'Authentication is not configured'})
        with hosted_client(db) as client:
            self.assert_reply(client.get(PATH), 401, {'detail': 'A valid Supabase access token is required'})
            db.active_session = False
            self.assert_reply(client.get(PATH, headers=HEADERS), 401, {'detail': 'BRI session is inactive or expired'})
        self.assertEqual(db.protected_scopes, [])

    def test_sql_denial_and_outage_are_generic(self):
        db = GrantsDatabase()
        with hosted_client(db) as client:
            db.error = InsufficientPrivilege('private diagnostic')
            self.assert_reply(client.get(PATH, headers=HEADERS), 403, DENIED)
            db.error = UndefinedFunction('private diagnostic')
            self.assert_reply(client.get(PATH, headers=HEADERS), 503, UNAVAILABLE)

    def test_only_get_is_mounted_with_no_query_parameters(self):
        db = GrantsDatabase()
        with hosted_client(db) as client:
            self.assert_reply(client.post(PATH, headers=HEADERS), 405, {'detail': 'Method Not Allowed'})
            operation = client.get('/openapi.json').json()['paths']['/v1/users/{id}/grants']
            self.assertEqual(set(operation), {'get'})
            self.assertFalse(any(p['in'] == 'query' for p in operation['get']['parameters']))
        self.assertEqual(db.protected_scopes, [])


@skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16')
class AccountCurrentGrantsDisposableApiTests(TestCase):
    target: UUID
    actors: list[tuple[UUID, UUID, UUID]]
    foreign_actors: list[tuple[UUID, UUID, UUID]]

    @classmethod
    def connect(cls, role, **kwargs):
        return postgres.AccountCurrentGrantsTests.connect.__func__(cls, role, **kwargs)

    @classmethod
    def setUpClass(cls):
        postgres.AccountCurrentGrantsTests.setUpClass.__func__(cls)

    def setUp(self):
        postgres.AccountCurrentGrantsTests.setUp(cast(postgres.AccountCurrentGrantsTests, self))

    # The SQL fixture defines its setup helpers as instance methods.
    grant = postgres.AccountCurrentGrantsTests.grant
    refresh = postgres.AccountCurrentGrantsTests.refresh

    def test_real_app_role_distinguishes_visible_empty_from_unavailable(self):
        actor, user, session = self.actors[0]
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
            response = client.get(f'/v1/users/{self.target}/grants', headers=HEADERS)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.headers['Cache-Control'], 'no-store')
            self.assertEqual(response.json(), {
                'account_class': 'user', 'account_status': 'active', 'assigned': [], 'effective': [],
            })
            for unavailable in (self.foreign_actors[2][0], actor, uuid4()):
                response = client.get(f'/v1/users/{unavailable}/grants', headers=HEADERS)
                self.assertEqual((response.status_code, response.json()), (404, NOT_FOUND))
                self.assertEqual(response.headers['Cache-Control'], 'no-store')
