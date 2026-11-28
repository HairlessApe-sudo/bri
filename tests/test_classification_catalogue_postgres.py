"""A19.1 catalogue authorization on the private PostgreSQL 16 fixture, never a DSN."""
import os
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from unittest.mock import patch
from uuid import uuid4

import psycopg
import test_privileged_approvals_pg as fixtures

ROLE = 'bri_classification_catalogue'
PERMISSION = 'classification:catalogue:manage'
PREFIX = 'text,uuid,uuid,uuid,text'
SUFFIXES = {'list': ',text,text', 'seed': '', 'create': ',text,text,text,text',
            'rename': ',text,text', 'describe': ',text,text', 'retire': ',text'}
ROUTINES = {name: f'bri.classification_catalogue_{name}({PREFIX}{suffix})'
            for name, suffix in SUFFIXES.items()}
STARTER = {
    'Governance': {'Policy', 'Regulation', 'Standard', 'Decision record'},
    'Operations': {'Process description', 'Procedure', 'Working instruction'},
    'Technology': {'Application', 'Infrastructure', 'Integration', 'Technical architecture'},
    'Strategy': {'Objective', 'Roadmap', 'Strategic plan'},
    'Finance': {'Budget', 'Contract', 'Expenditure'},
    'Risk': {'Risk', 'Control', 'Assessment', 'Incident'},
    'Experience': {'Historical case', 'Lesson learned', 'Evaluation'},
    'Organisation': {'Responsibility', 'Capability', 'Service'},
    'General': {'Reference material', 'Unclassified knowledge'},
}


@unittest.skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16.2')
class ClassificationCataloguePostgresTests(unittest.TestCase):
    connect = classmethod(fixtures.ApprovalDatabase.connect.__func__)

    @classmethod
    def setUpClass(cls):
        with patch.dict(os.environ, BRI_APPROVAL_PG_BIN=os.environ['BRI_TEST_PG_BIN']):
            fixtures.ApprovalDatabase.setUpClass.__func__(cls)
        with cls.connect('postgres') as db:
            assert db.execute("SELECT inet_server_addr(),current_setting('listen_addresses'),"
                              "current_setting('server_version_num')").fetchone() == (None, '', '160002')
            db.execute('INSERT INTO bri.provider_event_source(issuer) VALUES (%s)', (fixtures.ISSUER,))
            db.execute(f'CREATE ROLE {ROLE} LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS '
                       f'NOCREATEROLE NOCREATEDB NOREPLICATION; GRANT USAGE ON SCHEMA bri TO {ROLE}')
            cls.release_implicit_acl = {}
            for name, signature in ROUTINES.items():
                cls.release_implicit_acl[name] = db.execute(
                    "SELECT has_function_privilege(%s,p.oid,'EXECUTE'),"
                    "has_function_privilege('bri_app',p.oid,'EXECUTE'), EXISTS ("
                    "SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a "
                    "WHERE a.grantee=0 AND a.privilege_type='EXECUTE') "
                    "FROM pg_proc p WHERE p.oid=to_regprocedure(%s)", (ROLE, signature)).fetchone()
                if cls.release_implicit_acl[name] is not None:
                    db.execute(f'GRANT EXECUTE ON FUNCTION {signature} TO {ROLE}')

    def setUp(self):
        self.tenant, self.actors = fixtures.seed_approval_tenant(self.connect)
        self.foreign, self.foreign_actors = fixtures.seed_approval_tenant(self.connect)
        with self.connect('postgres') as db:
            for t, actors in ((self.tenant, self.actors), (self.foreign, self.foreign_actors)):
                db.execute("INSERT INTO bri.org_nodes(tenant_id,node_id,node_type,display_name,parent_node_id) "
                           "VALUES (%s,'team','team','Private name for team','root'),"
                           "(%s,'child','team','Private name for child','team')", (t, t))
                db.execute("INSERT INTO bri.app_roles VALUES (%s,'catalogue','Catalogue'),(%s,'submit','Submit')", (t, t))
                db.execute("INSERT INTO bri.role_permissions VALUES (%s,'catalogue',%s),(%s,'submit','source:submit')",
                           (t, PERMISSION, t))
                db.execute("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) "
                           "VALUES (%s,%s,'catalogue','root'),(%s,%s,'submit','team')", (t, actors[0][0], t, actors[2][0]))
                for i in range(4):
                    actors[i] = self.fresh(db, actors[i])

    @staticmethod
    def fresh(db, identity):
        refreshed = (*identity[:2], uuid4())
        db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                   'VALUES (%s,%s,%s,clock_timestamp())', refreshed)
        return refreshed

    def call(self, name, *args, tenant=None, actor=None, issuer=fixtures.ISSUER, login=ROLE):
        with self.connect(login) as db:
            db.execute("SET LOCAL statement_timeout='5s'")
            if name == 'list':
                db.execute('SET TRANSACTION READ ONLY')
            inputs = (tenant or self.tenant, *(actor or self.actors[0]), issuer, *args)
            return db.execute(f'SELECT bri.classification_catalogue_{name}({",".join(["%s"]*len(inputs))})', inputs).fetchone()[0]

    def selection(self, node: str | None = 'team', operation: str | None = 'csv_submit', **kwargs):
        kwargs.setdefault('actor', self.actors[2])
        return self.call('list', node, operation, **kwargs)

    def test_explicit_seed_is_complete_idempotent_and_does_not_overwrite(self):
        self.assertEqual(self.selection(), [])
        self.call('seed')
        seeded = self.selection()
        expected = {(cat, label) for cat, labels in STARTER.items() for label in labels}
        self.assertEqual(len(seeded), len(expected))
        self.assertEqual({(r['category_label'], r['label']) for r in seeded}, expected)
        self.assertEqual(len({r['classification_id'] for r in seeded}), len(expected))
        for item in seeded:
            self.assertEqual(set(item), {'category_id', 'category_label', 'classification_id', 'label', 'description', 'retired'})
        self.assertEqual(self.selection(operation='xlsx_submit'), seeded)
        self.call('rename', 'policy', 'Tenant policy')
        self.call('describe', 'policy', 'Customer text')
        self.call('retire', 'regulation')
        self.call('seed')
        actual = {r['classification_id']: r for r in self.selection()}
        self.assertEqual(len(actual), len(seeded) - 1)
        self.assertEqual((actual['policy']['label'], actual['policy']['description']), ('Tenant policy', 'Customer text'))
        self.assertNotIn('regulation', actual)
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT retired_at IS NOT NULL FROM bri.knowledge_classifications '
                                        "WHERE tenant_id=%s AND classification_id='regulation'", (self.tenant,)).fetchone(), (True,))

    def test_stable_ids_and_customer_lifecycle_are_tenant_qualified(self):
        for t, actors in ((self.tenant, self.actors), (self.foreign, self.foreign_actors)):
            self.call('seed', tenant=t, actor=actors[0])
            self.call('create', 'general', 'customer-type', 'Customer label', 'Some text', tenant=t, actor=actors[0])
        self.call('describe', 'customer-type', None)
        customer = next(r for r in self.selection() if r['classification_id'] == 'customer-type')
        self.assertIsNone(customer['description'])
        self.call('retire', 'customer-type')
        with self.assertRaises(psycopg.errors.UniqueViolation):
            self.call('create', 'general', 'customer-type', 'Another', None)
        self.assertNotIn('customer-type', {r['classification_id'] for r in self.selection()})
        foreign = next(r for r in self.selection(tenant=self.foreign, actor=self.foreign_actors[2])
                       if r['classification_id'] == 'customer-type')
        self.assertEqual(foreign['description'], 'Some text')
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.call('retire', 'customer-type', tenant=self.foreign)

    def test_list_requires_exact_live_submit_permission_not_root_maintenance(self):
        self.call('seed')
        self.assertTrue(self.selection())
        denials: tuple[dict[str, Any], ...] = (
            {'node': 'root'}, {'node': 'child'}, {'operation': 'knowledge:read'},
            {'operation': None}, {'actor': self.actors[0]}, {'actor': self.actors[1]},
            {'issuer': 'unbound'}, {'tenant': self.foreign},
            {'actor': (*self.actors[2][:2], uuid4())},
        )
        for args in denials:
            with self.subTest(args=args), self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self.selection(**args)
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_role_assignments SET status='revoked' "
                       "WHERE (tenant_id,principal_id,role_id)=(%s,%s,'submit')", (self.tenant, self.actors[2][0]))
            refreshed = self.fresh(db, self.actors[2])
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.selection(actor=refreshed)

    def test_admin_can_manage_retired_entries_without_gaining_selection(self):
        self.call('seed')
        self.call('retire', 'policy')
        admin = self.call('list', None, 'admin')
        self.assertTrue(next(r for r in admin if r['classification_id'] == 'policy')['retired'])
        self.assertTrue(all(not r['retired'] for r in self.selection()))
        for node, operation, actor in (('team', 'admin', self.actors[0]),
                                       (None, 'admin', self.actors[2]),
                                       ('team', 'csv_review', self.actors[0]),
                                       ('team', 'xlsx_review', self.actors[2]),
                                       ('team', 'csv_review', self.actors[2])):
            with self.subTest(operation=operation), self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self.call('list', node, operation, actor=actor)
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.app_roles VALUES (%s,'review-only','Review only')", (self.tenant,))
            db.execute("INSERT INTO bri.role_permissions VALUES (%s,'review-only','knowledge:review')", (self.tenant,))
            db.execute("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) "
                       "VALUES (%s,%s,'review-only','team')", (self.tenant,self.actors[1][0]))
            reviewer = self.fresh(db,self.actors[1])
        for operation in ('csv_review','xlsx_review'):
            self.assertEqual(self.selection(operation=operation,actor=reviewer),self.selection())
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self.selection('child',operation,actor=reviewer)
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.selection(actor=reviewer)
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_role_assignments SET status='revoked' "
                       "WHERE (tenant_id,principal_id,role_id)=(%s,%s,'review-only')",(self.tenant,reviewer[0]))
            reviewer = self.fresh(db,reviewer)
        for operation in ('csv_review','xlsx_review'):
            with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self.selection(operation=operation,actor=reviewer)

    def test_private_catalogue_list_rejects_retained_transaction_snapshots(self):
        self.call('seed')
        self.assertTrue(self.call('list',None,'admin'))
        with self.assertRaises(psycopg.errors.ActiveSqlTransaction), self.connect(ROLE) as db:
            db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
            db.execute('SELECT bri.classification_catalogue_list(%s,%s,%s,%s,%s,NULL,\'admin\')',
                       (self.tenant,*self.actors[0],fixtures.ISSUER))

    def test_maintenance_requires_explicit_authority_not_role_or_submit(self):
        self.call('seed')
        denials: tuple[dict[str, Any], ...] = (
            {'actor': self.actors[1]}, {'actor': self.actors[2]}, {'actor': self.actors[3]},
            {'tenant': self.foreign}, {'issuer': 'unbound'},
            {'actor': (self.actors[0][0], self.actors[1][1], self.actors[0][2])},
        )
        for opts in denials:
            with self.subTest(opts=opts), self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self.call('rename', 'policy', 'Should not write', **opts)
        with self.connect('postgres') as db:
            db.execute('UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() WHERE session_id=%s',
                       (self.actors[0][2],))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.call('rename', 'policy', 'Should not write')
        self.assertEqual(next(r['label'] for r in self.selection() if r['classification_id'] == 'policy'), 'Policy')

    def test_mutation_rechecks_governance_after_fence_wait(self):
        self.call('seed')
        with (self.connect('postgres') as blocker, self.connect('postgres', autocommit=True) as observer,
              self.connect(ROLE) as contender, ThreadPoolExecutor(max_workers=1) as worker):
            blocked_by = blocker.info.backend_pid
            pid = contender.info.backend_pid
            # Truthful provider evidence loss closes the quorum without changing
            # the actor's grant, session, or identity cutoff.
            blocker.execute('UPDATE bri.client_totp_observations SET verified_until=NULL '
                            'WHERE (tenant_id,principal_id)=(%s,%s)', (self.tenant, self.actors[1][0]))
            contender.execute("SET LOCAL statement_timeout='5s'")
            future = worker.submit(contender.execute, 'SELECT bri.classification_catalogue_rename(%s,%s,%s,%s,%s,%s,%s)',
                                   (self.tenant, *self.actors[0], fixtures.ISSUER, 'policy', 'Should not write'))
            try:
                deadline = time.monotonic() + 4
                while time.monotonic() < deadline:
                    if observer.execute('SELECT %s=ANY(pg_blocking_pids(%s))', (blocked_by, pid)).fetchone() == (True,):
                        break
                    time.sleep(.01)
                else:
                    self.fail('the catalogue mutation did not wait on the governance writer')
                blocker.commit()
                with self.assertRaises(psycopg.errors.InsufficientPrivilege):
                    future.result(timeout=5)
                contender.rollback()
            finally:
                blocker.rollback()
            self.assertEqual(observer.execute('SELECT revoked_at IS NULL FROM bri.auth_sessions WHERE session_id=%s',
                                              (self.actors[0][2],)).fetchone(), (True,))
            observer.execute("UPDATE bri.client_totp_observations SET verified_until=observed_at+interval '15 minutes' "
                             'WHERE (tenant_id,principal_id)=(%s,%s)', (self.tenant, self.actors[1][0]))
        self.assertEqual(next(r['label'] for r in self.selection() if r['classification_id'] == 'policy'), 'Policy')
        # Restoring quorum is sufficient without replacing the session: a
        # cutoff did not mask the required post-wait governance check.
        self.call('rename', 'policy', 'Quorum restored')

    def test_protected_catalogue_root_topology_and_scope_promotion(self):
        self.call('seed')
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_role_assignments SET scope_node_id='team' "
                       "WHERE (tenant_id,principal_id,role_id)=(%s,%s,'catalogue')", (self.tenant, self.actors[0][0]))
            self.actors[0] = self.fresh(db, self.actors[0])
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.call('seed')
        with self.connect('bri_app') as db:
            db.execute("SELECT set_config('bri.tenant_id',%s,true)", (self.tenant,))
            for sql in ("UPDATE bri.org_nodes SET node_type='team' WHERE tenant_id=%s AND node_id='root'",
                        "UPDATE bri.org_nodes SET node_type='root',parent_node_id=NULL WHERE tenant_id=%s AND node_id='team'",
                        "INSERT INTO bri.org_nodes(tenant_id,node_id,node_type,display_name) VALUES (%s,'second','team','Second')"):
                with self.assertRaises(psycopg.errors.InsufficientPrivilege) as denied, db.transaction():
                    db.execute(sql, (self.tenant,))
                self.assertEqual(denied.exception.diag.message_primary, 'classification catalogue root topology is protected')
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_role_assignments SET status='revoked' "
                       "WHERE (tenant_id,principal_id,role_id)=(%s,%s,'catalogue')", (self.tenant, self.actors[0][0]))
        with self.connect('bri_app') as db:
            db.execute("SELECT set_config('bri.tenant_id',%s,true)", (self.tenant,))
            self.assertEqual(db.execute("INSERT INTO bri.org_nodes(tenant_id,node_id,node_type,display_name) "
                                        "VALUES (%s,'second','team','Second')", (self.tenant,)).rowcount, 1)
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) "
                       "VALUES (%s,%s,'catalogue','root')", (self.tenant, self.actors[0][0]))
            self.actors[0] = self.fresh(db, self.actors[0])
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.call('seed')  # even an untyped second parentless row makes the root ambiguous

    def test_release_acls_and_forced_rls_deny_raw_catalogue_access(self):
        for name in ROUTINES:
            self.assertEqual(self.release_implicit_acl[name], (False, False, False), name)
        self.call('seed')
        for login in ('bri_app', ROLE, 'bri_migrator'):
            with self.subTest(login=login), self.connect(login) as db:
                for rel in ('knowledge_classification_categories', 'knowledge_classifications'):
                    self.assertEqual(db.execute("SELECT relrowsecurity,relforcerowsecurity FROM pg_class "
                                                "WHERE oid=%s::regclass", (f'bri.{rel}',)).fetchone(), (True, True))
                    if login == 'bri_migrator':
                        self.assertEqual(db.execute(f'SELECT count(*) FROM bri.{rel}').fetchone(), (0,))
                    else:
                        with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                            db.execute(f'SELECT * FROM bri.{rel}')
        with self.assertRaises(psycopg.errors.InsufficientPrivilege) as denied:
            self.selection(login='bri_app')
        self.assertEqual(denied.exception.diag.message_primary, 'permission denied for function classification_catalogue_list')
        with self.assertRaises(psycopg.errors.InsufficientPrivilege) as denied:
            self.call('seed', login='bri_migrator')
        self.assertEqual(denied.exception.diag.message_primary, 'Classification catalogue denied')
