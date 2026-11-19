"""A11.1 through actual verified HTTP and bri_app in a private PG16 cluster."""
from __future__ import annotations

import asyncio
import os
import unittest
from contextlib import contextmanager
from unittest.mock import patch
from uuid import uuid4

import httpx
import psycopg
import test_privileged_approvals_pg as fixtures
from fastapi.testclient import TestClient
from test_authentication import PUBLISHABLE_KEY, auth_server_response, make_token

from bri.api.app import ApiSettings, create_app
from bri.api.authentication import SupabaseTokenVerifier
from bri.api.database import Database

ISSUER = fixtures.ISSUER
PERMISSION = 'user:directory:read'
PATH = '/v1/users'


@unittest.skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16')
class UserDirectoryTests(unittest.TestCase):
    connect = classmethod(fixtures.ApprovalDatabase.connect.__func__)

    @classmethod
    def setUpClass(cls):
        with patch.dict(os.environ, {'BRI_APPROVAL_PG_BIN': os.environ['BRI_TEST_PG_BIN']}):
            fixtures.ApprovalDatabase.setUpClass.__func__(cls)

    def setUp(self):
        self.tenant, self.actors = fixtures.seed_approval_tenant(self.connect)
        self.foreign, self.foreign_actors = fixtures.seed_approval_tenant(self.connect)
        self.tokens = {}
        connect = self.connect

        class LocalDatabase(Database):
            def _connect(self):
                return connect('bri_app')

        def auth(request):
            self.assertEqual((request.method, str(request.url)), ('GET', ISSUER + '/user'))
            token = request.headers['authorization'].removeprefix('Bearer ')
            return auth_server_response(request, user_id=self.tokens.get(token, ''))

        url = ISSUER.removesuffix('/auth/v1')
        transport = httpx.AsyncClient(transport=httpx.MockTransport(auth))
        self.addCleanup(lambda: asyncio.run(transport.aclose()))
        self.database = LocalDatabase(url, '')
        self.app = create_app(
            settings=ApiSettings(environment='hosted-development', auth_mode='supabase', supabase_url=url),
            database=self.database,
            token_verifier=SupabaseTokenVerifier(url, PUBLISHABLE_KEY, client=transport),
        )
        self.client = self.enterContext(TestClient(self.app))
        self.admin, self.peer, self.ordinary, self.platform = self.actors
        self.superuser = self.seed_account('superuser')

    def seed_account(self, role='user', status='active', membership_status=None):
        principal, user, sid = uuid4(), uuid4(), uuid4()
        with self.connect('postgres') as db:
            db.execute('INSERT INTO bri.auth_principals(principal_id,status) VALUES (%s,%s)', (principal, status))
            db.execute(
                'INSERT INTO bri.auth_tenant_memberships(tenant_id,principal_id,membership_type,status) '
                'VALUES (%s,%s,%s,%s)', (self.tenant, principal, role, membership_status or status),
            )
            if status == 'active' and membership_status in (None, 'active'):
                self.add_link(db, principal, user)
                db.execute('INSERT INTO bri.auth_sessions(auth_user_id,principal_id,session_id) VALUES (%s,%s,%s)',
                           (user, principal, sid))
        return principal, user, sid

    def add_link(self, db, principal, user, issuer=ISSUER, status='active'):
        db.execute(
            'INSERT INTO bri.auth_identity_links '
            '(auth_user_id,principal_id,auth_issuer,auth_subject,provider_type,provider_issuer,provider_subject,status) '
            "VALUES (%s,%s,%s,%s,'native',%s,%s,%s)", (user, principal, issuer, str(user), issuer, str(user), status),
        )

    def grant_directory(self, actor=None, scope='root', tenant=None):
        principal, user, _ = actor or self.admin
        tenant = tenant or self.tenant
        sid = uuid4()  # A10 invalidates sessions when a relevant grant changes.
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.app_roles VALUES (%s,'directory','Directory') ON CONFLICT DO NOTHING", (tenant,))
            db.execute("INSERT INTO bri.role_permissions VALUES (%s,'directory',%s) ON CONFLICT DO NOTHING",
                       (tenant, PERMISSION))
            db.execute(
                "INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) "
                "VALUES (%s,%s,'directory',%s)", (tenant, principal, scope),
            )
            db.execute('INSERT INTO bri.auth_sessions(auth_user_id,principal_id,session_id) VALUES (%s,%s,%s)',
                       (user, principal, sid))
        return principal, user, sid

    def headers(self, actor):
        _, user, sid = actor
        token = make_token(sub=str(user), session_id=str(sid))
        self.tokens[token] = str(user)
        return {'Authorization': 'Bearer ' + token}

    def get(self, path=PATH, actor=None, **kwargs):
        return self.client.get(path, headers=self.headers(actor or self.admin), **kwargs)

    def test_granted_admin_lists_only_ordinary_accounts_with_exact_safe_fields(self):
        self.admin = self.grant_directory()
        response = self.get()
        self.assertEqual(response.status_code, 200, response.text)
        expected = [
            {'id': str(actor[0]), 'display_name': None, 'status': 'active', 'role': role, 'mfa_status': 'unknown'}
            for actor, role in ((self.ordinary, 'user'), (self.superuser, 'superuser'))
        ]
        self.assertEqual(response.json(), {'items': sorted(expected, key=lambda item: item['id']), 'has_more': False})

    def test_scoped_grant_cannot_be_promoted_by_runtime_topology_edits(self):
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.org_nodes VALUES (%s,'leaf','department','Leaf','root')", (self.tenant,))
        self.admin = self.grant_directory(scope='leaf')
        self.assertEqual(self.get().status_code, 403)
        with self.connect('bri_app') as db:
            db.execute("SELECT set_config('bri.tenant_id',%s,true)", (self.tenant,))
            with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                db.execute("UPDATE bri.org_nodes SET parent_node_id=NULL WHERE node_id='leaf'")
        self.assertEqual(self.get().status_code, 403)

    def test_directory_requires_verified_client_admin_with_an_explicit_grant(self):
        self.assertEqual(self.client.get(PATH).status_code, 401)
        self.assertEqual(self.get().status_code, 403)  # Admin alone is insufficient.
        self.assertEqual(self.get(actor=self.grant_directory(self.ordinary)).status_code, 403)
        self.assertEqual(self.get(actor=self.grant_directory(self.superuser)).status_code, 403)
        self.assertEqual(self.get(actor=self.grant_directory(self.platform)).status_code, 403)
        self.assertEqual(self.get(actor=self.grant_directory(self.peer)).status_code, 200)

    def test_foreign_and_excluded_detail_ids_have_the_same_404(self):
        self.admin = self.grant_directory()
        detail = self.get(f'{PATH}/{self.ordinary[0]}')
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(detail.json(), {
            'id': str(self.ordinary[0]), 'display_name': None, 'status': 'active',
            'role': 'user', 'mfa_status': 'unknown',
        })
        self.assertEqual(detail.headers['Cache-Control'], 'no-store')
        foreign_admin = self.grant_directory(self.foreign_actors[0], tenant=self.foreign)
        self.assertEqual(self.get(f'{PATH}/{self.foreign_actors[2][0]}', actor=foreign_admin).status_code, 200)
        hybrid = self.seed_account()
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.platform_superadmins(principal_id,status) VALUES (%s,'revoked')", (hybrid[0],))
        denied = [self.admin[0], self.peer[0], self.platform[0], self.foreign_actors[2][0], hybrid[0], uuid4(), 'not-a-uuid']
        for target in denied:
            with self.subTest(target=target):
                response = self.get(f'{PATH}/{target}')
                self.assertEqual((response.status_code, response.json()), (404, {'detail': 'Not Found'}))
                self.assertEqual(response.headers['Cache-Control'], 'no-store')

    def test_literal_search_exact_id_and_bounded_pagination(self):
        self.admin = self.grant_directory()
        with self.connect('postgres') as db:
            for actor, name in ((self.ordinary, 'A %_ Label'), (self.superuser, 'Ordinary'),
                                (self.foreign_actors[2], 'A %_ Label')):
                db.execute('UPDATE bri.auth_principals SET display_name=%s WHERE principal_id=%s', (name, actor[0]))
        for query in ('%_', 'lAbEl', str(self.ordinary[0]).upper()):
            with self.subTest(query=query):
                page = self.get(params={'q': query}).json()
                self.assertEqual([row['id'] for row in page['items']], [str(self.ordinary[0])])
        for query in (str(self.ordinary[1]), str(self.ordinary[0])[:20], "%' OR 'x'='x"):
            self.assertEqual(self.get(params={'q': query}).json(), {'items': [], 'has_more': False})
        all_items = self.get().json()['items']
        self.assertEqual(self.get(params={'limit': 1}).json(), {'items': all_items[:1], 'has_more': True})
        self.assertEqual(self.get(params={'limit': 1, 'offset': 1}).json(),
                         {'items': all_items[1:], 'has_more': False})
        self.assertEqual(self.get(params={'limit': 100, 'offset': 10000}).json(), {'items': [], 'has_more': False})
        for _ in range(24):
            self.seed_account(status='pending')
        default = self.get().json()
        self.assertEqual((len(default['items']), default['has_more']), (25, True))

    def test_query_is_allowlisted_and_does_not_accept_authority(self):
        self.admin = self.grant_directory()
        for query in ('q=a&q=b', 'limit=1&limit=1', 'offset=0&offset=0', 'tenant_id=elsewhere', 'role=admin',
                      'principal_id=other', 'limit=0', 'limit=101', 'offset=-1', 'offset=10001', 'q=%00',
                      'q=' + 'x' * 129):
            with self.subTest(query=query):
                self.assertEqual(self.get(f'{PATH}?{query}').status_code, 400)
        self.assertEqual(self.get(f'{PATH}/{self.ordinary[0]}?q=a').status_code, 400)
        headers = self.headers(self.admin) | {'X-Tenant-Id': self.foreign}
        self.assertEqual(self.client.get(PATH, headers=headers).status_code, 400)
        operations = self.client.get('/openapi.json').json()['paths']
        parameters = operations[PATH]['get']['parameters']
        self.assertEqual({item['name'] for item in parameters if item['in'] == 'query'}, {'q', 'limit', 'offset'})

    def test_mfa_evidence_must_be_unexpired_and_match_the_active_link(self):
        self.admin = self.grant_directory()
        self.observe(self.ordinary, valid=True)
        self.observe(self.superuser, valid=False)

        def detail(actor):
            return self.get(f'{PATH}/{actor[0]}').json()['mfa_status']

        self.assertEqual(detail(self.ordinary), 'verified')
        self.assertEqual(detail(self.superuser), 'unknown')
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_identity_links SET status='revoked' WHERE auth_user_id=%s", (self.ordinary[1],))
            self.add_link(db, self.ordinary[0], uuid4())
        self.assertEqual(detail(self.ordinary), 'unknown')

    def test_pending_credential_change_and_deletion_do_not_report_verified_mfa(self):
        self.admin = self.grant_directory()
        self.observe(self.ordinary, valid=True)
        self.observe(self.superuser, valid=True)
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.credential_operations(operation_id,principal_id,auth_user_id,auth_issuer,kind) "
                       "VALUES (%s,%s,%s,%s,'factor_reenrollment')", (uuid4(), *self.ordinary[:2], ISSUER))
            db.execute('UPDATE bri.auth_principals SET deletion_requested_at=now() WHERE principal_id=%s',
                       (self.superuser[0],))
        pending = self.get(f'{PATH}/{self.ordinary[0]}').json()
        deleting = self.get(f'{PATH}/{self.superuser[0]}').json()
        self.assertEqual((pending['status'], pending['mfa_status']), ('active', 'unknown'))
        self.assertEqual((deleting['status'], deleting['mfa_status']), ('suspended', 'unknown'))

    def test_retired_session_is_denied_in_database_even_if_stored_expiry_is_future(self):
        self.admin = self.grant_directory()
        principal, user, sid = self.admin
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_sessions SET started_at=now()-interval '9 hours' WHERE session_id=%s", (sid,))
        self.assertEqual(self.get().status_code, 401)
        with self.connect('bri_app') as db:
            db.execute('SET TRANSACTION READ ONLY')
            db.execute("SELECT set_config('bri.tenant_id',%s,true),set_config('bri.auth_user_id',%s,true)",
                       (self.tenant, str(user)))
            with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                db.execute('SELECT id FROM bri.read_user_directory(%s,%s,%s,%s,NULL,NULL,NULL,25,0)',
                           (self.tenant, principal, sid, ISSUER))

    def observe(self, actor, *, valid):
        with self.connect('postgres') as db:
            if valid:
                observed, valid_until = 'now()', "now()+interval '14 minutes'"
            else:
                observed, valid_until = "now()-interval '20 minutes'", "now()-interval '10 minutes'"
            db.execute(f'SELECT bri.record_client_totp_observation(%s,%s,%s,%s,{observed},{valid_until})',
                       (self.tenant, actor[0], actor[1], ISSUER))

    def test_directory_reports_lifecycle_without_exposing_lifecycle_metadata(self):
        self.admin = self.grant_directory()
        accounts = {
            'pending': self.seed_account(status='pending'),
            'suspended': self.seed_account(status='active', membership_status='suspended'),
            'deactivated': self.seed_account(status='deactivated'),
        }
        for status, actor in accounts.items():
            self.assertEqual(self.get(f'{PATH}/{actor[0]}').json(), {
                'id': str(actor[0]), 'display_name': None, 'status': status,
                'role': 'user', 'mfa_status': 'unknown',
            })

    def test_no_runtime_role_catalog_escalation_or_profile_write(self):
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.app_roles VALUES (%s,'unassigned','Unassigned')", (self.tenant,))
            db.execute("INSERT INTO bri.role_permissions VALUES (%s,'unassigned',%s)", (self.tenant, PERMISSION))
        with self.connect('bri_app') as db:
            db.execute("SELECT set_config('bri.tenant_id',%s,true), set_config('bri.auth_user_id',%s,true)",
                       (self.tenant, str(self.admin[1])))
            attempts = [
                ("INSERT INTO bri.role_permissions VALUES (%s,'reset',%s)", (self.tenant, PERMISSION)),
                (("UPDATE bri.role_permissions SET permission=%s WHERE permission='platform:client_admin:manage' "
                  "OR permission='document:read'"), (PERMISSION,)),
                ("DELETE FROM bri.app_roles WHERE role_id='unassigned'", ()),
                ('UPDATE bri.auth_principals SET display_name=%s WHERE principal_id=%s', ('New', self.admin[0])),
                (("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) "
                  "VALUES (%s,%s,'unassigned','root')"), (self.tenant, self.admin[0])),
            ]
            db.execute("INSERT INTO bri.role_permissions VALUES (%s,'reset','document:read')", (self.tenant,))
            for query, args in attempts:
                with self.subTest(query=query), self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                    db.execute(query, args)
            self.assertEqual(db.execute('DELETE FROM bri.role_permissions WHERE permission=%s', (PERMISSION,)).rowcount, 0)
        with self.connect('postgres') as db, self.assertRaises(psycopg.errors.CheckViolation), db.transaction():
            db.execute('UPDATE bri.auth_principals SET display_name=%s WHERE principal_id=%s',
                       ('x' * 129, self.ordinary[0]))

    def test_direct_sql_rechecks_context_session_principal_and_scope(self):
        self.admin = self.grant_directory()
        principal, user, sid = self.admin
        sql = 'SELECT id FROM bri.read_user_directory(%s,%s,%s,%s,NULL,NULL,NULL,25,0)'
        with self.connect('bri_app') as db:
            db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                db.execute(sql, (self.tenant, principal, sid, ISSUER))
            db.execute("SELECT set_config('bri.tenant_id',%s,true),set_config('bri.auth_user_id',%s,true)",
                       (self.tenant, str(user)))
            self.assertEqual({row[0] for row in db.execute(sql, (self.tenant, principal, sid, ISSUER))},
                             {self.ordinary[0], self.superuser[0]})
            for args in ((self.foreign, principal, sid, ISSUER), (self.tenant, self.peer[0], sid, ISSUER),
                         (self.tenant, principal, uuid4(), ISSUER), (self.tenant, principal, sid, ISSUER + '/wrong')):
                with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                    db.execute(sql, args)
            self.assertEqual(db.execute('SELECT principal_id FROM bri.auth_principals').fetchall(), [(principal,)])
            self.assertEqual(db.execute('SELECT principal_id FROM bri.auth_tenant_memberships').fetchall(), [(principal,)])
            with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                db.execute('SELECT * FROM bri.client_totp_observations')

    def test_grant_removal_after_preflight_denies_even_with_live_session(self):
        self.admin = self.grant_directory()
        self.assertEqual(self.get().status_code, 200)
        principal, user, _ = self.admin
        stale_principal = self.database.resolve_authenticated_principal(str(user), ISSUER, str(user))
        sid = uuid4()
        with self.connect('postgres') as db:
            db.execute('DELETE FROM bri.role_permissions WHERE tenant_id=%s AND permission=%s', (self.tenant, PERMISSION))
            # A10 revokes old sessions on grant removal. A valid new session
            # isolates this test to the stale principal's grant decision.
            db.execute('INSERT INTO bri.auth_sessions(auth_user_id,principal_id,session_id) VALUES (%s,%s,%s)',
                       (user, principal, sid))
        real_scope = self.database.protected_tenant_context

        @contextmanager
        def scope(*args, **kwargs):
            with real_scope(*args, **kwargs) as session:
                db = session.connection
                assert isinstance(db, psycopg.Connection)
                self.assertEqual(db.execute('SHOW transaction_read_only').fetchone(), ('on',))
                self.assertEqual(db.execute('SHOW transaction_isolation').fetchone(), ('repeatable read',))
                yield session

        with (
            patch.object(type(self.database), 'resolve_authenticated_principal', return_value=stale_principal),
            patch.object(type(self.database), 'protected_tenant_context', side_effect=scope) as guarded,
        ):
            self.assertEqual(self.get(actor=(principal, user, sid)).status_code, 403)
            guarded.assert_called_once_with(self.tenant, auth_user_id=str(user), session_id=str(sid),
                                            principal_id=str(principal), issuer=ISSUER)
