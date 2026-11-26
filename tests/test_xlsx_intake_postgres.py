"""Exercise staged XLSX SQL only on a fresh socket-only PG16 cluster."""
import os
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from hashlib import sha256
from unittest.mock import patch
from uuid import UUID, uuid4

import psycopg
import test_privileged_approvals_pg as fixtures
from scripts.db.disposable.catalog import verify_xlsx_catalog

ISSUER = fixtures.ISSUER
ORIGINAL = sha256(b"synthetic fixture").hexdigest()
CANONICAL = '{"rows":[[["text","Header"]]],"version":1,"worksheet":{"identity":"1","range":"A1","title":"Sample"}}'
DIGEST = sha256(CANONICAL.encode()).hexdigest()
SUBMITTER = (
    "bri.xlsx_submit(text,uuid,uuid,uuid,text,text,uuid,integer,text,uuid)",
    "bri.xlsx_mark_ready(text,uuid,uuid,uuid,text,uuid,uuid)",
    "bri.xlsx_status(text,uuid,uuid,uuid,text,uuid)",
)
WORKER = (
    "bri.xlsx_claim(uuid,uuid)",
    "bri.xlsx_complete(uuid,integer,text,text,integer,integer,text,text,text,uuid)",
    "bri.xlsx_fail(uuid,integer,text,uuid)",
)


@unittest.skipUnless(os.getenv("BRI_TEST_PG_BIN"), "requires private PostgreSQL 16")
class XlsxIntakePostgresTests(unittest.TestCase):
    connect = classmethod(fixtures.ApprovalDatabase.connect.__func__)

    @classmethod
    def setUpClass(cls):
        with patch.dict(os.environ, BRI_APPROVAL_PG_BIN=os.environ["BRI_TEST_PG_BIN"]):
            fixtures.ApprovalDatabase.setUpClass.__func__(cls)
        with cls.connect("bri_app") as db:
            verify_xlsx_catalog(db)
        with cls.connect("postgres") as db:
            assert db.execute("SELECT inet_server_addr(), current_setting('listen_addresses')").fetchone() == (None, "")
            for role, routines in (("bri_xlsx_submitter", SUBMITTER), ("bri_xlsx_worker", WORKER)):
                for routine in routines:
                    assert db.execute("SELECT to_regprocedure(%s) IS NOT NULL", (routine,)).fetchone() == (True,), routine
                db.execute(f"CREATE ROLE {role} LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION")
                db.execute(f"GRANT USAGE ON SCHEMA bri TO {role}; GRANT EXECUTE ON FUNCTION {', '.join(routines)} TO {role}")
        with cls.connect("bri_migrator") as db:
            db.execute("INSERT INTO bri.provider_event_source(issuer) VALUES (%s)", (ISSUER,))

    def setUp(self):
        self.tenant, actors = fixtures.seed_approval_tenant(self.connect)
        self.creator = actors[1][0]
        self.identity = (*actors[2][:2], uuid4())
        with self.connect("postgres") as db:
            db.execute("INSERT INTO bri.org_nodes VALUES (%s,'team','team','Team','root')", (self.tenant,))
            db.execute("INSERT INTO bri.app_roles VALUES (%s,'xlsx','XLSX fixture')", (self.tenant,))
            db.execute("INSERT INTO bri.role_permissions VALUES (%s,'xlsx','source:submit')", (self.tenant,))
            db.execute("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) "
                       "VALUES (%s,%s,'xlsx','team')", (self.tenant, self.identity[0]))
            db.execute("INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) VALUES (%s,%s,%s,clock_timestamp())", self.identity)
            db.execute("INSERT INTO bri.xlsx_worker_creators VALUES (%s,%s)", (self.tenant, self.creator))

    def call(self, role, name, *params):
        with self.connect(role) as db:
            return db.execute(f"SELECT bri.xlsx_{name}({','.join(['%s'] * len(params))})", params).fetchone()[0]

    def submitter(self, name, *args, tenant=None, identity=None, issuer=ISSUER):
        return self.call("bri_xlsx_submitter", name, tenant or self.tenant, *(identity or self.identity), issuer, *args)

    def submit(self, key=None, size=17, node="team", **identity):
        return self.submitter("submit", node, key or uuid4(), size, ORIGINAL, uuid4(), **identity)

    def worker(self, name, *args):
        return self.call("bri_xlsx_worker", name, *args, uuid4())

    def start(self):
        submitted = self.submit()
        job = UUID(submitted["job_id"])
        self.assertIsNone(self.worker("claim", job))
        self.assertEqual(self.submitter("mark_ready", job, uuid4())["state"], "ready")
        return job, submitted

    def complete(self, job, attempt=1, digest=DIGEST):
        return self.worker("complete", job, attempt, CANONICAL, digest, 1, 1, "1", "Sample", "A1")

    def test_completion_has_one_immutable_xlsx_lineage(self):
        job, submitted = self.start()
        self.assertEqual(self.worker("claim", job), {
            "job_id": str(job), "tenant_id": self.tenant, "artifact_key": submitted["artifact_key"],
            "byte_count": 17, "original_sha256": ORIGINAL, "attempt": 1,
        })
        self.assertIsNone(self.worker("claim", job))
        with self.assertRaises(psycopg.errors.InvalidParameterValue):
            self.complete(job, digest=ORIGINAL)
        self.assertEqual(self.complete(job), "proposed")
        self.assertEqual(self.complete(job), "stale")
        self.assertEqual(self.submitter("status", job)["state"], "proposed")
        with self.connect("postgres") as db:
            for table in ("sources", "source_versions", "extractions", "pending_proposals"):
                self.assertEqual(db.execute(f"SELECT count(*) FROM bri.xlsx_{table} WHERE tenant_id=%s", (self.tenant,)).fetchone(), (1,))
                with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                    db.execute(f"DELETE FROM bri.xlsx_{table} WHERE tenant_id=%s", (self.tenant,))
            self.assertEqual(db.execute("SELECT original_sha256,canonical_sha256 FROM bri.xlsx_source_versions WHERE tenant_id=%s", (self.tenant,)).fetchone(), (ORIGINAL, DIGEST))
            self.assertEqual(db.execute("SELECT count(*) FROM bri.knowledge_proposals WHERE tenant_id=%s", (self.tenant,)).fetchone(), (0,))

    def test_exact_authority_and_idempotency(self):
        key = uuid4()
        original = self.submit(key)
        self.assertEqual(self.submit(key), original)
        job = UUID(original['job_id'])
        ready = self.submitter('mark_ready', job, uuid4())
        self.assertNotIn('artifact_key', ready)
        self.assertNotIn('artifact_key', self.submitter('status', job))
        self.assertEqual(self.submit(key), {**original, 'state': 'ready'})
        with self.assertRaises(psycopg.errors.UniqueViolation):
            self.submit(key, size=18)
        actor, sub, sid = self.identity
        for kwargs in ({"node": "root"}, {"issuer": "https://other.invalid"},
                       {"identity": (actor, uuid4(), sid)}, {"identity": (actor, sub, uuid4())},
                       {"tenant": "unrelated"}):
            with self.subTest(kwargs=kwargs), self.assertRaises(psycopg.errors.InsufficientPrivilege):
                self.submit(**kwargs)
        with self.connect("postgres") as db:
            db.execute("UPDATE bri.auth_role_assignments SET status='revoked' WHERE tenant_id=%s AND role_id='xlsx'", (self.tenant,))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.submit(key)

    def test_durable_delays_lease_and_attempt_fencing(self):
        job, _ = self.start()
        self.assertEqual(self.worker("claim", job)["attempt"], 1)
        with self.connect("postgres") as db:
            self.assertTrue(db.execute("SELECT lease_until-clock_timestamp() BETWEEN interval '55 seconds' AND interval '60 seconds' FROM bri.xlsx_jobs WHERE job_id=%s", (job,)).fetchone()[0])
        for attempt, delay in ((1, 5), (2, 15)):
            self.assertEqual(self.worker("fail", job, attempt, "infrastructure_unavailable"), "ready")
            self.assertIsNone(self.worker("claim", job))
            with self.connect("postgres") as db:
                self.assertTrue(db.execute("SELECT available_at-clock_timestamp() BETWEEN make_interval(secs=>%s) AND make_interval(secs=>%s) FROM bri.xlsx_jobs WHERE job_id=%s", (delay-2, delay, job)).fetchone()[0])
                db.execute("UPDATE bri.xlsx_jobs SET available_at=clock_timestamp()-interval '1 second' WHERE job_id=%s", (job,))
            self.assertEqual(self.worker("claim", job)["attempt"], attempt+1)
            self.assertEqual(self.complete(job, attempt), "stale")
        self.assertEqual(self.worker("fail", job, 3, "infrastructure_unavailable"), "failed")
        self.assertIsNone(self.worker("claim", job))

    def test_worker_rechecks_original_authority_and_sanitizes_failures(self):
        job, _ = self.start()
        self.worker("claim", job)
        self.assertEqual(self.worker("fail", job, 1, "private parser details"), "failed")
        self.assertNotEqual(self.submitter("status", job)["reason"], "private parser details")
        other, _ = self.start()
        self.worker("claim", other)
        with self.connect("postgres") as db:
            db.execute("UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() WHERE session_id=%s", (self.identity[2],))
        self.assertEqual(self.complete(other), "failed")
        with self.connect("postgres") as db:
            self.assertEqual(db.execute("SELECT state,reason FROM bri.xlsx_jobs WHERE job_id=%s", (other,)).fetchone(), ("failed", "authority_lost"))

    def test_stage_role_has_only_its_own_rpc_grants(self):
        for role, allowed in (("bri_xlsx_submitter", SUBMITTER), ("bri_xlsx_worker", WORKER)):
            with self.connect(role) as db:
                self.assertEqual(db.execute("SELECT session_user,current_user,inet_server_addr()").fetchone(), (role, role, None))
                self.assertEqual(db.execute(
                    "SELECT rolinherit,rolsuper,rolbypassrls,rolcreaterole,rolcreatedb,rolreplication, "
                    "EXISTS (SELECT FROM pg_auth_members WHERE current_user::regrole::oid IN (roleid,member)) "
                    "FROM pg_roles WHERE rolname=current_user").fetchone(), (False,)*7)
                self.assertEqual(db.execute("SELECT relname FROM pg_class WHERE relnamespace='bri'::regnamespace "
                                            "AND relkind IN ('r','v','m','p') AND has_table_privilege(current_user,oid,"
                                            "'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')").fetchall(), [])
                grants = db.execute("SELECT p.oid::regprocedure::text FROM pg_proc p "
                                    "WHERE p.pronamespace='bri'::regnamespace "
                                    "AND has_function_privilege(current_user,p.oid,'EXECUTE')").fetchall()
                self.assertEqual({r[0] for r in grants}, set(allowed))

    def test_elapsed_lease_retries_but_never_reuses_an_attempt(self):
        job, _ = self.start()
        self.assertEqual(self.worker("claim", job)["attempt"], 1)
        with self.connect("postgres") as db:
            db.execute("UPDATE bri.xlsx_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE job_id=%s", (job,))
        self.assertEqual(self.complete(job), "stale")
        self.assertIsNone(self.worker("claim", job))
        self.assertEqual(self.submitter("status", job)["state"], "ready")
        with self.connect("postgres") as db:
            db.execute("UPDATE bri.xlsx_jobs SET available_at=clock_timestamp()-interval '1 second' WHERE job_id=%s", (job,))
        self.assertEqual(self.worker("claim", job)["attempt"], 2)
        self.assertEqual(self.complete(job), "stale")
        self.assertEqual(self.complete(job, 2), "proposed")

    def test_cutoff_pending_credential_and_deadline_each_deny(self):
        actor, sub, sid = self.identity
        checks = (
            ("UPDATE bri.session_guards SET primary_after=clock_timestamp() WHERE principal_id=%s", (actor,)),
            ("INSERT INTO bri.credential_operations(operation_id,principal_id,auth_user_id,auth_issuer,kind,recovery_session_id) "
             "VALUES (%s,%s,%s,%s,'password_reset',%s)", (uuid4(),actor,sub,ISSUER,uuid4())),
            ("UPDATE bri.auth_sessions SET started_at=clock_timestamp()-interval '9 hours', "
             "expires_at=clock_timestamp()+interval '1 hour' WHERE session_id=%s", (sid,)),
        )
        for sql, params in checks:
            # Each mutation is isolated and reversed after observing SQL denial.
            with self.subTest(sql=sql), self.connect("postgres") as control:
                control.execute(sql, params)
                control.execute("SET SESSION AUTHORIZATION bri_xlsx_submitter")
                with self.assertRaises(psycopg.errors.InsufficientPrivilege), control.transaction():
                    control.execute("SELECT bri.xlsx_submit(%s,%s,%s,%s,%s,'team',%s,17,%s,%s)",
                                    (self.tenant,actor,sub,sid,ISSUER,uuid4(),ORIGINAL,uuid4()))
                control.rollback()

    def test_concurrent_revocation_wins_when_it_holds_the_session_row(self):
        job, _ = self.start()
        self.worker('claim', job)
        pid = Queue()

        def complete():
            with self.connect('bri_xlsx_worker') as db:
                pid.put(db.info.backend_pid)
                return db.execute('SELECT bri.xlsx_complete(%s,1,%s,%s,1,1,%s,%s,%s,%s)',
                                  (job,CANONICAL,DIGEST,'1','Sample','A1',uuid4())).fetchone()[0]

        with ThreadPoolExecutor(max_workers=1) as pool, self.connect('postgres') as writer:
            writer.execute('UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() WHERE session_id=%s', (self.identity[2],))
            future = pool.submit(complete)
            worker_pid = pid.get(timeout=5)
            with self.connect('postgres', autocommit=True) as monitor:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    blockers = monitor.execute('SELECT pg_blocking_pids(%s)', (worker_pid,)).fetchone()[0]
                    if writer.info.backend_pid in blockers:
                        break
                    time.sleep(.01)
                else:
                    self.fail('Completion did not wait behind the session revocation')
            writer.commit()
            self.assertEqual(future.result(timeout=5), 'failed')
            self.assertEqual(writer.execute('SELECT state,reason FROM bri.xlsx_jobs WHERE job_id=%s', (job,)).fetchone(), ('failed','authority_lost'))
            self.assertEqual(writer.execute('SELECT count(*) FROM bri.xlsx_pending_proposals WHERE job_id=%s', (job,)).fetchone(), (0,))

    def test_audit_is_content_free_immutable_and_not_duplicated_on_replay(self):
        key = uuid4()
        job = UUID(self.submit(key)['job_id'])
        self.submit(key)
        self.submitter('mark_ready', job, uuid4())
        self.submitter('mark_ready', job, uuid4())
        self.worker('claim',job)
        self.complete(job)
        self.complete(job)
        with self.connect('postgres') as db:
            rows = db.execute('SELECT event,attempt,actor_id,reason FROM bri.xlsx_audit_events WHERE job_id=%s ORDER BY occurred_at', (job,)).fetchall()
            self.assertEqual(rows, [('submitted',0,self.identity[0],None),('ready',0,self.identity[0],None),
                                    ('claimed',1,None,None),('proposed',1,self.creator,None)])
            for statement in ('UPDATE bri.xlsx_audit_events SET reason=NULL', 'DELETE FROM bri.xlsx_audit_events',
                              'TRUNCATE bri.xlsx_audit_events'):
                with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                    db.execute(statement)

    def test_tenant_is_part_of_every_proposal_lineage_binding(self):
        job, _ = self.start()
        self.worker('claim', job)
        self.complete(job)
        other, _ = fixtures.seed_approval_tenant(self.connect, tenant=str(uuid4()))
        with self.connect('postgres') as db:
            with self.assertRaises(psycopg.errors.ForeignKeyViolation), db.transaction():
                db.execute('INSERT INTO bri.xlsx_pending_proposals(tenant_id,job_id) VALUES (%s,%s)', (other,job))

    def test_lifecycle_locks_but_does_not_write_legacy_fences(self):
        def legacy_versions():
            with self.connect('postgres') as db:
                return db.execute('SELECT f.xmin::text, g.xmin::text, s.xmin::text '
                                  'FROM bri.client_governance_fence f, bri.session_guards g, bri.auth_sessions s '
                                  'WHERE g.principal_id=s.principal_id AND s.session_id=%s',
                                  (self.identity[2],)).fetchone()

        initial = legacy_versions()
        self.assertIsNotNone(initial)
        job, _ = self.start()
        self.worker('claim', job)
        self.complete(job)
        self.assertEqual(legacy_versions(), initial)
