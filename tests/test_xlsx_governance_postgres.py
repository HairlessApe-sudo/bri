"""Protected XLSX governance exercised on the socket-only disposable fixture."""
import os
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from queue import Queue
from unittest.mock import patch
from uuid import uuid4

import psycopg
import test_privileged_approvals_pg as fixtures
from scripts.db.disposable.catalog import XLSX_GOVERNANCE_ROUTINES, XLSX_TABLES, verify_xlsx_catalog

IDENTITY = 'text,uuid,uuid,uuid,text,'
REVIEWER = 'bri_xlsx_reviewer'
REVIEW = {
    'xlsx_review_queue': 'uuid,integer',
    'xlsx_review_detail': 'uuid',
    'xlsx_review_decide': 'uuid,text,uuid,uuid',
}
CANONICAL = '{"rows":[[["text","Header"]]],"version":1,"worksheet":{"identity":"1","range":"A1","title":"Sample"}}'
DIGEST = sha256(CANONICAL.encode()).hexdigest()


@unittest.skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16')
class XlsxGovernancePostgresTests(unittest.TestCase):
    connect = classmethod(fixtures.ApprovalDatabase.connect.__func__)

    @classmethod
    def setUpClass(cls):
        with patch.dict(os.environ, BRI_APPROVAL_PG_BIN=os.environ['BRI_TEST_PG_BIN']):
            fixtures.ApprovalDatabase.setUpClass.__func__(cls)
        with cls.connect('bri_app') as db:
            verify_xlsx_catalog(db)
        with cls.connect('postgres') as db:
            assert not db.execute("SELECT permission FROM bri.role_permissions WHERE permission IN "
                                  "('knowledge:publish','knowledge:access_manage')").fetchall(), 'unexpected default XLSX authority'

    def test_governance_tables_are_private_and_force_rls(self):
        expected = {
            'xlsx_review_decisions', 'xlsx_validated_knowledge', 'xlsx_publication_events',
            'xlsx_record_access', 'xlsx_version_access', 'xlsx_governance_audit_events',
        }
        with self.connect('bri_app') as db:
            rows = db.execute('''SELECT relname, relrowsecurity, relforcerowsecurity,
                                has_table_privilege(oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
                                FROM pg_class WHERE relnamespace='bri'::regnamespace AND relname=ANY(%s)''',
                              (sorted(expected),)).fetchall()
        self.assertEqual(set(rows), {(name, True, True, False) for name in expected})

    def provision(self, role, routines):
        with self.connect('postgres') as db:
            self.assertEqual(db.execute("SELECT inet_server_addr(),current_setting('listen_addresses')").fetchone(), (None, ''))
            if db.execute('SELECT 1 FROM pg_roles WHERE rolname=%s', (role,)).fetchone():
                return
            signatures = [f'bri.{name}({IDENTITY}{types})' for name, types in routines.items()]
            for signature in signatures:
                self.assertEqual(db.execute('SELECT to_regprocedure(%s) IS NOT NULL', (signature,)).fetchone(), (True,), signature)
            db.execute(f'CREATE ROLE {role} LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION')
            db.execute(f"GRANT USAGE ON SCHEMA bri TO {role}; GRANT EXECUTE ON FUNCTION {', '.join(signatures)} TO {role}")

    def prepare(self):
        self.provision(REVIEWER, REVIEW)
        self.tenant, (reviewer, creator, uploader, _) = fixtures.seed_approval_tenant(self.connect)
        self.job = uuid4()
        self.identities = {}
        with self.connect('postgres') as db:
            db.execute('INSERT INTO bri.provider_event_source(issuer) VALUES (%s) ON CONFLICT DO NOTHING', (fixtures.ISSUER,))
            db.execute("INSERT INTO bri.org_nodes VALUES (%s,'team','team','Team','root')", (self.tenant,))
            db.execute("INSERT INTO bri.app_roles VALUES (%s,'review','Review')", (self.tenant,))
            db.execute("INSERT INTO bri.role_permissions VALUES (%s,'review','knowledge:review')", (self.tenant,))
            for name, (principal, sub, _) in (('reviewer',reviewer),('creator',creator),('uploader',uploader)):
                sid = uuid4()
                self.identities[name] = principal,sub,sid
                db.execute("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) VALUES (%s,%s,'review','team')", (self.tenant,principal))
                db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) VALUES (%s,%s,%s,clock_timestamp())', (principal,sub,sid))
            db.execute("""INSERT INTO bri.xlsx_jobs(tenant_id,job_id,scope_node_id,actor_id,creator_id,auth_user_id,
                         session_id,issuer,request_key,original_sha256,byte_count,state,attempt)
                         VALUES (%s,%s,'team',%s,%s,%s,%s,%s,%s,%s,100,'proposed',1)""",
                       (self.tenant,self.job,uploader[0],creator[0],uploader[1],self.identities['uploader'][2],fixtures.ISSUER,uuid4(),DIGEST))
            db.execute("INSERT INTO bri.xlsx_sources VALUES (%s,%s,'team',%s)", (self.tenant,self.job,creator[0]))
            db.execute("INSERT INTO bri.xlsx_source_versions VALUES (%s,%s,%s,%s,'1','Sample','A1')", (self.tenant,self.job,DIGEST,DIGEST))
            db.execute('INSERT INTO bri.xlsx_extractions VALUES (%s,%s,%s,%s,1,1)', (self.tenant,self.job,CANONICAL,DIGEST))
            db.execute('INSERT INTO bri.xlsx_pending_proposals(tenant_id,job_id) VALUES (%s,%s)', (self.tenant,self.job))

    def call(self, role, name, *args, identity='reviewer'):
        with self.connect(role) as db:
            params = (self.tenant,*self.identities[identity],fixtures.ISSUER,*args)
            return db.execute(f"SELECT bri.{name}({','.join(['%s'] * len(params))})", params).fetchone()[0]

    def test_review_visibility_and_atomic_idempotent_approval(self):
        self.prepare()
        request_id = uuid4()
        self.assertEqual(self.call(REVIEWER,'xlsx_review_queue',None,20)[0]['job_id'],str(self.job))
        self.assertIsNotNone(self.call(REVIEWER,'xlsx_review_detail',self.job))
        for identity in ('creator','uploader'):
            self.assertEqual(self.call(REVIEWER,'xlsx_review_queue',None,20,identity=identity),[])
            self.assertIsNone(self.call(REVIEWER,'xlsx_review_detail',self.job,identity=identity))
            self.assertIsNone(self.call(REVIEWER,'xlsx_review_decide',self.job,'approve',request_id,uuid4(),identity=identity))
        with self.connect('postgres') as db:
            db.execute("ALTER TABLE bri.xlsx_governance_audit_events ADD CONSTRAINT fixture_fail CHECK (event <> 'approve') NOT VALID")
        try:
            with self.assertRaises(psycopg.errors.CheckViolation):
                self.call(REVIEWER,'xlsx_review_decide',self.job,'approve',request_id,uuid4())
        finally:
            with self.connect('postgres') as db:
                db.execute('ALTER TABLE bri.xlsx_governance_audit_events DROP CONSTRAINT fixture_fail')
        original = self.call(REVIEWER,'xlsx_review_decide',self.job,'approve',request_id,uuid4())
        self.assertEqual(original,'approve')
        self.assertEqual(self.call(REVIEWER,'xlsx_review_decide',self.job,'approve',request_id,uuid4()),original)
        with self.assertRaises(psycopg.errors.UniqueViolation):
            self.call(REVIEWER,'xlsx_review_decide',self.job,'reject',request_id,uuid4())
        with self.connect('postgres') as db:
            for table in ('xlsx_review_decisions','xlsx_validated_knowledge','xlsx_governance_audit_events'):
                self.assertEqual(db.execute(f'SELECT count(*) FROM bri.{table} WHERE tenant_id=%s', (self.tenant,)).fetchone(), (1,))
            self.assertEqual(db.execute('SELECT count(*) FROM bri.xlsx_publication_events WHERE tenant_id=%s', (self.tenant,)).fetchone(), (0,))

    def approve(self):
        self.call(REVIEWER,'xlsx_review_decide',self.job,'approve',uuid4(),uuid4())
        with self.connect('postgres') as db:
            return db.execute('SELECT record_id FROM bri.xlsx_validated_knowledge WHERE (tenant_id,job_id)=(%s,%s)',
                              (self.tenant,self.job)).fetchone()[0]

    def grant_authority(self, identity, permission, node='team'):
        principal, sub, _ = self.identities[identity]
        sid = uuid4()
        with self.connect('postgres') as db:
            db.execute('INSERT INTO bri.app_roles VALUES (%s,%s,%s) ON CONFLICT DO NOTHING', (self.tenant,permission,permission))
            db.execute('INSERT INTO bri.role_permissions VALUES (%s,%s,%s) ON CONFLICT DO NOTHING', (self.tenant,permission,permission))
            db.execute('INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) VALUES (%s,%s,%s,%s)',
                       (self.tenant,principal,permission,node))
            db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) VALUES (%s,%s,%s,clock_timestamp())',
                       (principal,sub,sid))
        self.identities[identity] = (principal,sub,sid)

    def test_publication_appends_only_on_exact_live_authority(self):
        self.prepare()
        role, command = 'bri_xlsx_publication_maintainer','xlsx_publication_change'
        self.provision(role,{command:'uuid,uuid,text,uuid'})
        record = self.approve()
        self.assertIsNone(self.call(role,command,record,self.job,'publish',uuid4()))
        self.grant_authority('reviewer','knowledge:publish','root')
        self.assertIsNone(self.call(role,command,record,self.job,'publish',uuid4()))
        self.grant_authority('reviewer','knowledge:publish')
        self.assertIsNone(self.call(role,command,record,uuid4(),'publish',uuid4()))
        published = self.call(role,command,record,self.job,'publish',uuid4())
        self.assertEqual((published['state'],published['revision']),('published',1))
        self.assertEqual(self.call(role,command,record,self.job,'publish',uuid4()),published)
        self.assertEqual(self.call(role,command,record,self.job,'withdraw',uuid4())['revision'],2)
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT action FROM bri.xlsx_publication_events WHERE tenant_id=%s ORDER BY revision',
                                        (self.tenant,)).fetchall(), [('publish',),('withdraw',)])
            with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                db.execute('DELETE FROM bri.xlsx_publication_events WHERE tenant_id=%s', (self.tenant,))

    def test_publication_replay_preserves_later_state_and_original_receipts(self):
        self.prepare()
        role, command = 'bri_xlsx_publication_maintainer', 'xlsx_publication_change'
        self.provision(role, XLSX_GOVERNANCE_ROUTINES[role])
        record = self.approve()
        self.grant_authority('reviewer', 'knowledge:publish')

        def change(action, key):
            return self.call(role, command, record, self.job, action, key)

        initial_key, publish_key, noop_key, withdraw_key = (uuid4() for _ in range(4))
        initial = change('withdraw', initial_key)
        published = change('publish', publish_key)
        self.assertEqual(change('publish', noop_key), published)
        withdrawn = change('withdraw', withdraw_key)
        self.assertEqual(change('publish', publish_key), published)
        self.assertEqual(change('publish', noop_key), published)
        self.assertEqual(change('publish', uuid4())['revision'], 3)
        self.assertEqual(change('withdraw', withdraw_key), withdrawn)
        self.assertEqual(change('withdraw', initial_key), initial)
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT action FROM bri.xlsx_publication_events WHERE tenant_id=%s ORDER BY revision',
                                        (self.tenant,)).fetchall(), [('publish',), ('withdraw',), ('publish',)])
            results = db.execute("""SELECT correlation,event,state_changed,publication_revision
                FROM bri.xlsx_governance_audit_events WHERE tenant_id=%s AND event IN ('publish','withdraw')
                ORDER BY publication_revision,state_changed DESC""", (self.tenant,)).fetchall()
            self.assertEqual([row[1:] for row in results], [
                ('withdraw', False, 0), ('publish', True, 1), ('publish', False, 1),
                ('withdraw', True, 2), ('publish', True, 3),
            ])
            self.assertEqual([row[0] for row in results[:4]], [initial_key, publish_key, noop_key, withdraw_key])

    def test_access_replay_preserves_later_record_and_version_decisions(self):
        self.prepare()
        role = 'bri_xlsx_access_maintainer'
        self.provision(role, XLSX_GOVERNANCE_ROUTINES[role])
        record = self.approve()
        target = self.identities['uploader'][0]
        self.grant_authority('creator', 'knowledge:access_manage')
        for gate, version in (('record', ()), ('version', (self.job,))):
            with self.subTest(gate=gate):
                def change(allow, key):
                    return self.call(role, f'xlsx_{gate}_access_change', record, *version, target,
                                     allow, key, identity='creator')

                def present():
                    with self.connect('postgres') as db:
                        return db.execute(f'SELECT count(*) FROM bri.xlsx_{gate}_access WHERE tenant_id=%s',
                                          (self.tenant,)).fetchone()[0]

                initial_key, grant_key, noop_key, revoke_key = (uuid4() for _ in range(4))
                self.assertIs(change(False, initial_key), False)
                self.assertIs(change(True, grant_key), True)
                self.assertIs(change(True, noop_key), True)
                self.assertIs(change(False, revoke_key), False)
                self.assertIs(change(True, grant_key), True)
                self.assertEqual(present(), 0, 'an old grant restored revoked access')
                self.assertIs(change(True, noop_key), True)
                self.assertEqual(present(), 0)
                self.assertIs(change(True, uuid4()), True)
                self.assertIs(change(False, revoke_key), False)
                self.assertIs(change(False, initial_key), False)
                self.assertEqual(present(), 1, 'an old revoke removed restored access')
                with self.connect('postgres') as db:
                    self.assertEqual(db.execute('''SELECT event,state_changed,count(*) FROM bri.xlsx_governance_audit_events
                        WHERE tenant_id=%s AND event IN (%s,%s) GROUP BY event,state_changed ORDER BY event,state_changed''',
                        (self.tenant, f'{gate}_grant', f'{gate}_revoke')).fetchall(), [
                            (f'{gate}_grant', False, 1), (f'{gate}_grant', True, 2),
                            (f'{gate}_revoke', False, 1), (f'{gate}_revoke', True, 1),
                        ])

    def test_binding_conflicts_only_after_live_authority_and_target_checks(self):
        self.prepare()
        publisher, maintainer = 'bri_xlsx_publication_maintainer', 'bri_xlsx_access_maintainer'
        for role in (publisher, maintainer):
            self.provision(role, XLSX_GOVERNANCE_ROUTINES[role])
        record = self.approve()
        target = self.identities['uploader'][0]
        publish_key, access_key = uuid4(), uuid4()
        self.grant_authority('reviewer', 'knowledge:publish')
        self.grant_authority('creator', 'knowledge:access_manage')

        def publish(action, key, version=None, identity='reviewer'):
            return self.call(publisher, 'xlsx_publication_change', record, version or self.job, action, key,
                             identity=identity)

        def record_gate(principal, allow, key, identity='creator'):
            return self.call(maintainer, 'xlsx_record_access_change', record, principal, allow, key,
                             identity=identity)

        self.assertEqual(publish('publish', publish_key)['revision'], 1)
        self.assertTrue(record_gate(target, True, access_key))
        self.assertIsNone(publish('withdraw', publish_key, version=uuid4()))
        self.assertIsNone(publish('withdraw', publish_key, identity='creator'))
        self.assertIsNone(record_gate(uuid4(), True, access_key))
        self.assertIsNone(record_gate(uuid4(), False, access_key))
        self.assertIsNone(record_gate(target, False, access_key, identity='reviewer'))
        self.grant_authority('creator', 'knowledge:publish')
        for conflict in (
            lambda: publish('withdraw', publish_key),
            lambda: publish('publish', publish_key, identity='creator'),
            lambda: record_gate(target, False, access_key),
            lambda: record_gate(self.identities['reviewer'][0], True, access_key),
            lambda: record_gate(target, True, publish_key),
            lambda: self.call(maintainer, 'xlsx_version_access_change', record, self.job, target, True, access_key,
                              identity='creator'),
        ):
            with self.assertRaisesRegex(psycopg.errors.UniqueViolation, 'XLSX governance request conflict'):
                conflict()
        with self.connect('postgres') as db:
            db.execute('UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() WHERE session_id=ANY(%s)',
                       ([self.identities[name][2] for name in ('reviewer', 'creator')],))
        self.assertIsNone(publish('publish', publish_key))
        self.assertIsNone(record_gate(target, True, access_key))

    def test_published_reader_requires_both_independent_live_gates(self):
        self.prepare()
        publisher, publish = 'bri_xlsx_publication_maintainer','xlsx_publication_change'
        maintainer, reader = 'bri_xlsx_access_maintainer','bri_xlsx_reader'
        record_gate, version_gate = 'xlsx_record_access_change','xlsx_version_access_change'
        detail, evidence = 'xlsx_published_detail','xlsx_published_evidence'
        self.provision(publisher,{publish:'uuid,uuid,text,uuid'})
        self.provision(maintainer,{record_gate:'uuid,uuid,boolean,uuid',version_gate:'uuid,uuid,uuid,boolean,uuid'})
        self.provision(reader,{detail:'uuid',evidence:'uuid,uuid'})
        record = self.approve()
        target = self.identities['uploader'][0]
        self.grant_authority('reviewer','knowledge:publish')
        self.grant_authority('creator','knowledge:access_manage')
        self.grant_authority('uploader','knowledge:read')
        self.assertIsNone(self.call(maintainer,record_gate,record,target,True,uuid4()))
        self.assertIsNone(self.call(maintainer,record_gate,record,self.identities['creator'][0],True,uuid4(),identity='creator'))
        self.assertIsNone(self.call(maintainer,version_gate,record,uuid4(),target,True,uuid4(),identity='creator'))
        self.assertIsNone(self.call(maintainer,record_gate,record,uuid4(),True,uuid4(),identity='creator'))
        self.assertTrue(self.call(maintainer,record_gate,record,target,True,uuid4(),identity='creator'))
        self.assertIsNone(self.call(reader,detail,record,identity='uploader'))
        self.call(publisher,publish,record,self.job,'publish',uuid4())
        self.assertIsNone(self.call(reader,detail,record,identity='uploader'))
        self.assertTrue(self.call(maintainer,version_gate,record,self.job,target,True,uuid4(),identity='creator'))
        self.assertFalse(self.call(maintainer,record_gate,record,target,False,uuid4(),identity='creator'))
        self.assertIsNone(self.call(reader,evidence,record,self.job,identity='uploader'))
        self.assertTrue(self.call(maintainer,record_gate,record,target,True,uuid4(),identity='creator'))
        self.assertNotIn('rows',self.call(reader,detail,record,identity='uploader'))
        self.assertEqual(self.call(reader,evidence,record,self.job,identity='uploader')['rows'],[[['text','Header']]])
        self.assertIsNone(self.call(reader,evidence,record,uuid4(),identity='uploader'))
        self.assertIsNone(self.call(reader,detail,record,identity='reviewer'))
        self.assertFalse(self.call(maintainer,version_gate,record,self.job,target,False,uuid4(),identity='creator'))
        self.assertIsNone(self.call(reader,detail,record,identity='uploader'))
        self.assertTrue(self.call(maintainer,version_gate,record,self.job,target,True,uuid4(),identity='creator'))
        self.call(publisher,publish,record,self.job,'withdraw',uuid4())
        self.assertIsNone(self.call(reader,evidence,record,self.job,identity='uploader'))
        self.call(publisher,publish,record,self.job,'publish',uuid4())
        self.assertIsNotNone(self.call(reader,detail,record,identity='uploader'))
        with self.connect('postgres') as db:
            db.execute("UPDATE bri.auth_role_assignments SET status='revoked' WHERE tenant_id=%s AND role_id='knowledge:read'", (self.tenant,))
        self.assertIsNone(self.call(reader,detail,record,identity='uploader'))

    def test_hidden_review_does_not_wait_for_governance_or_proposal_lock(self):
        self.prepare()
        with self.connect('postgres') as writer, self.connect(REVIEWER) as rejected:
            writer.execute('SELECT 1 FROM bri.client_governance_fence FOR UPDATE')
            writer.execute('SELECT 1 FROM bri.xlsx_jobs WHERE job_id=%s FOR UPDATE', (self.job,))
            rejected.execute("SET LOCAL lock_timeout='200ms'")
            args = (self.tenant,*self.identities['creator'],fixtures.ISSUER,self.job,'approve',uuid4(),uuid4())
            self.assertEqual(rejected.execute('SELECT bri.xlsx_review_decide(%s,%s,%s,%s,%s,%s,%s,%s,%s)', args).fetchone(), (None,))

    def test_in_flight_review_rechecks_authority_after_session_lock(self):
        self.prepare()
        pid = Queue()
        sql = 'SELECT bri.xlsx_review_decide(%s,%s,%s,%s,%s,%s,%s,%s,%s)'
        args = (self.tenant,*self.identities['reviewer'],fixtures.ISSUER,self.job,'approve',uuid4(),uuid4())

        def decide():
            with self.connect(REVIEWER) as db:
                db.execute("SET LOCAL statement_timeout='8s'")
                pid.put(db.info.backend_pid)
                return db.execute(sql,args).fetchone()[0]

        with ThreadPoolExecutor(max_workers=1) as pool, self.connect('postgres') as writer:
            writer.execute('UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() WHERE session_id=%s',
                           (self.identities['reviewer'][2],))
            waiting = pool.submit(decide)
            worker_pid = pid.get(timeout=5)
            with self.connect('postgres',autocommit=True) as monitor:
                cutoff = time.monotonic()+5
                while time.monotonic()<cutoff:
                    if writer.info.backend_pid in monitor.execute('SELECT pg_blocking_pids(%s)', (worker_pid,)).fetchone()[0]:
                        break
                    time.sleep(.01)
                else:
                    self.fail('Reviewer did not block on the actual revocation writer')
            writer.commit()
            self.assertIsNone(waiting.result(timeout=5))
            self.assertEqual(writer.execute('SELECT count(*) FROM bri.xlsx_review_decisions WHERE tenant_id=%s',
                                            (self.tenant,)).fetchone(),(0,))

    def test_fixture_stage_roles_have_only_their_named_entry_points(self):
        for role, routines in XLSX_GOVERNANCE_ROUTINES.items():
            self.provision(role,routines)
        for role, expected in XLSX_GOVERNANCE_ROUTINES.items():
            with self.connect(role) as db:
                table_grants = db.execute("""SELECT c.relname FROM pg_class c WHERE c.relnamespace='bri'::regnamespace
                    AND c.relname=ANY(%s) AND has_table_privilege(c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')""",
                                          (sorted(XLSX_TABLES),)).fetchall()
                execution_grants = db.execute("""SELECT p.proname FROM pg_proc p WHERE p.pronamespace='bri'::regnamespace
                    AND left(p.proname,5)='xlsx_' AND has_function_privilege(p.oid,'EXECUTE')""").fetchall()
                self.assertEqual(table_grants,[])
                self.assertEqual(sorted(execution_grants),[(name,) for name in sorted(expected)])
                self.assertEqual(db.execute("""SELECT count(*) FROM pg_auth_members m JOIN pg_roles r
                    ON r.oid IN (m.member,m.roleid) WHERE r.rolname=session_user""").fetchone(),(0,))

    def test_mirrored_review_read_authority_matches_csv_predicates(self):
        self.prepare()
        self.grant_authority('reviewer','knowledge:read')
        actor,sub,sid = self.identities['reviewer']
        with self.connect('postgres') as db:
            def match(t,a,u,s,issuer,node,permission,expected):
                args = (t,a,u,s,issuer,node,permission)
                self.assertEqual(db.execute('SELECT bri.xlsx_governance_authorized(%s,%s,%s,%s,%s,%s,%s), '
                                            'bri.csv_has_authority(%s,%s,%s,%s,%s,%s,%s)',args+args).fetchone(),
                                 (expected,expected))

            for permission in ('knowledge:review','knowledge:read'):
                for case in (
                    (self.tenant,actor,sub,sid,fixtures.ISSUER,'team',True),
                    (self.tenant,actor,sub,sid,fixtures.ISSUER,'root',False),
                    (self.tenant,actor,sub,uuid4(),fixtures.ISSUER,'team',False),
                    (self.tenant,actor,uuid4(),sid,fixtures.ISSUER,'team',False),
                    (self.tenant,actor,sub,sid,'https://other.invalid','team',False),
                    ('other-tenant',actor,sub,sid,fixtures.ISSUER,'team',False),
                ):
                    match(*case[:-1],permission,case[-1])
            db.execute('UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() WHERE session_id=%s', (sid,))
            for permission in ('knowledge:review','knowledge:read'):
                match(self.tenant,actor,sub,sid,fixtures.ISSUER,'team',permission,False)

    def test_protected_read_rejects_stale_transaction_isolation(self):
        self.prepare()
        with self.connect(REVIEWER) as db:
            db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            with self.assertRaises(psycopg.errors.ActiveSqlTransaction):
                db.execute('SELECT bri.xlsx_review_detail(%s,%s,%s,%s,%s,%s)',
                           (self.tenant,*self.identities['reviewer'],fixtures.ISSUER,self.job))
            db.rollback()

    def test_concurrent_withdrawal_observes_preceding_publication(self):
        self.concurrent_publication_withdrawal(conflict=False)

    def test_concurrent_binding_conflict_observes_committed_request(self):
        self.concurrent_publication_withdrawal(conflict=True)

    def concurrent_publication_withdrawal(self, *, conflict):
        self.prepare()
        role = 'bri_xlsx_publication_maintainer'
        self.provision(role,XLSX_GOVERNANCE_ROUTINES[role])
        record = self.approve()
        self.grant_authority('reviewer','knowledge:publish')
        args = (self.tenant,*self.identities['reviewer'],fixtures.ISSUER,record,self.job)
        query = 'SELECT bri.xlsx_publication_change(%s,%s,%s,%s,%s,%s,%s,%s,%s)'
        pid = Queue()
        publish_key = uuid4()

        def withdraw():
            with self.connect(role) as db:
                db.execute("SET LOCAL statement_timeout='8s'")
                pid.put(db.info.backend_pid)
                return db.execute(query,(*args,'withdraw',publish_key if conflict else uuid4())).fetchone()[0]

        with ThreadPoolExecutor(max_workers=1) as pool, self.connect(role) as writer:
            self.assertEqual(writer.execute(query,(*args,'publish',publish_key)).fetchone()[0]['revision'],1)
            waiting = pool.submit(withdraw)
            worker_pid = pid.get(timeout=5)
            with self.connect('postgres',autocommit=True) as monitor:
                cutoff = time.monotonic()+5
                while time.monotonic()<cutoff:
                    if writer.info.backend_pid in monitor.execute('SELECT pg_blocking_pids(%s)', (worker_pid,)).fetchone()[0]:
                        break
                    time.sleep(.01)
                else:
                    self.fail('Withdrawal did not wait for the publication writer')
            writer.commit()
            if conflict:
                with self.assertRaisesRegex(psycopg.errors.UniqueViolation, 'XLSX governance request conflict'):
                    waiting.result(timeout=5)
                with self.connect('postgres') as db:
                    self.assertEqual(db.execute('SELECT action FROM bri.xlsx_publication_events WHERE tenant_id=%s',
                                                (self.tenant,)).fetchall(), [('publish',)])
            else:
                result = waiting.result(timeout=5)
                self.assertEqual((result['state'],result['revision']),('withdrawn',2))
