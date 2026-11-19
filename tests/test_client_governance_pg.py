"""Opt in with BRI_RUN_GOVERNANCE_PG=1. Never accepts a supplied DSN.

Starts and removes its OWN loopback-only PostgreSQL 16 container. Requires a
local Docker engine and an already-present postgres:16 image; no pulls, env
files, shared credentials, persistent data mounts or hosted connections.
"""
import importlib.util
import io
import os
import secrets
import shutil
import subprocess
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import psycopg
from psycopg import sql

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.getenv("BRI_RUN_GOVERNANCE_PG") == "1", "requires private disposable PostgreSQL")
class GovernancePG(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if any(name.startswith("PG") for name in os.environ):
            raise RuntimeError("run the disposable suite without inherited libpq settings")
        win = shutil.which("docker.exe")
        docker = ([win, "--host", "npipe:////./pipe/dockerDesktopLinuxEngine"] if win else
                  ["docker", "--host", "unix:///var/run/docker.sock"])
        name = "bri-governance-" + uuid4().hex
        password = secrets.token_hex(32)
        cls.password = password
        def cli(*args, **kwargs):
            return subprocess.check_output([*docker, *args], text=True, timeout=45, **kwargs).strip()
        cid = cli("run", "--detach", "--rm", "--pull=never", "--name", name,
                  "--tmpfs", "/var/lib/postgresql/data", "--publish", "127.0.0.1::5432",
                  "--env", "POSTGRES_PASSWORD", "postgres:16", env={**os.environ, "POSTGRES_PASSWORD": password,
                      "WSLENV": "POSTGRES_PASSWORD"})
        cls.addClassCleanup(cli, "rm", "--force", cid)
        host, port = cli("port", cid, "5432/tcp").split(":")
        if host != "127.0.0.1" or not port.isdigit():
            raise RuntimeError("container did not publish exclusively on loopback")
        cls.port = int(port)
        for _ in range(100):
            if cli("exec", cid, "sh", "-c", "pg_isready -h 127.0.0.1 >/dev/null; printf '%s' $?") == "0":
                break
            time.sleep(.1)
        with cls.connect("postgres") as db:
            for role, limit in [("bri_app", 8), ("bri_migrator", 2)]:
                db.execute(sql.SQL("CREATE ROLE {} LOGIN NOINHERIT CONNECTION LIMIT {} PASSWORD {}").format(
                    sql.Identifier(role), sql.Literal(limit), sql.Literal(password)))
            db.execute("CREATE SCHEMA bri AUTHORIZATION bri_migrator")
            db.execute("GRANT USAGE ON SCHEMA bri TO bri_app")
        spec = importlib.util.spec_from_file_location("governance_runner", ROOT / "scripts/db/migrate.py")
        if spec is None or spec.loader is None:
            raise RuntimeError("migration runner not found")
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / "db/migrations"
            folder.mkdir(parents=True)
            for f in sorted((ROOT / "db/migrations").glob("*.sql")):
                if f.name[:4] <= "0009":
                    shutil.copyfile(f, folder / f.name)
            expected = "postgresql://bri_migrator@db." + runner.EXPECTED_REF + ".supabase.co:5432/postgres"
            env = {"SUPABASE_URL": "https://" + runner.EXPECTED_REF + ".supabase.co",
                   "BRI_MIGRATION_ROLE_DATABASE_URL": expected, "BRI_ENVIRONMENT": "local"}
            connect = psycopg.connect
            def guarded(dsn, **kwargs):
                if dsn != expected:
                    raise ValueError("unexpected migration target")
                return cls.connect("bri_migrator", factory=connect, **kwargs)
            with patch.object(runner, "ROOT", Path(tmp)), patch.object(runner, "env_values", return_value=env), \
                    patch.object(runner.psycopg, "connect", guarded):
                for rerun in [False, True]:
                    log = io.StringIO()
                    with redirect_stdout(log):
                        rc = runner.main()
                    assert rc == 0, log.getvalue()
                    if rerun:
                        assert "applied_count=0" in log.getvalue()
            files = sorted(folder.glob("*.sql"))
            with cls.connect("bri_migrator") as db:
                runner.verify_ledger(db, files)
                assert db.execute("SELECT version FROM bri.schema_migrations ORDER BY version").fetchall() == [
                    (f.stem,) for f in files]

    @classmethod
    def connect(cls, user, *, factory=None, **kwargs):
        return (factory or psycopg.connect)(host="127.0.0.1", hostaddr="127.0.0.1", port=cls.port,
                user=user, password=cls.password, dbname="postgres", sslmode="disable", passfile=os.devnull, gssencmode="disable",
                **{"connect_timeout": 3, **kwargs})

    @staticmethod
    def context(db, t, uid):
        db.execute("SELECT set_config('bri.tenant_id',%s,true),set_config('bri.auth_user_id',%s,true)",
                   (t,str(uid)))

    @staticmethod
    def observe(db,t,p,u,valid=True):
        db.execute("SELECT bri.record_client_totp_observation(%s,%s,%s,'synthetic:issuer',statement_timestamp(),"
                   "CASE WHEN %s THEN statement_timestamp()+interval '14 minutes' END)", (t,p,u,valid))

    def fixture(self, n=2, activate=True):
        t = 'synthetic-' + uuid4().hex
        pairs = [(uuid4(),uuid4()) for _ in range(n+1)]
        with self.connect('postgres') as db:
            db.execute("INSERT INTO bri.tenants VALUES (%s,'Synthetic','test')", (t,))
            db.execute("INSERT INTO bri.tenant_admin_policies (tenant_id) VALUES (%s)", (t,))
            db.execute("INSERT INTO bri.org_nodes VALUES (%s,'root','test','Root')", (t,))
            db.execute("INSERT INTO bri.app_roles VALUES (%s,'setup','Setup')", (t,))
            db.execute("INSERT INTO bri.role_permissions VALUES (%s,'setup','platform:client_admin:manage')", (t,))
            for i,(p,u) in enumerate(pairs):
                db.execute("INSERT INTO bri.auth_principals(principal_id,status) VALUES (%s,'active')", (p,))
                db.execute("INSERT INTO bri.auth_identity_links(auth_user_id,principal_id,auth_issuer,auth_subject,"
                           "provider_type,provider_issuer,provider_subject) VALUES "
                           "(%s,%s,'synthetic:issuer',%s,'native','synthetic:issuer',%s)", (u,p,str(u),str(u)))
                if not i:
                    db.execute("INSERT INTO bri.platform_superadmins(principal_id) VALUES (%s)", (p,))
                db.execute("INSERT INTO bri.auth_tenant_memberships(tenant_id,principal_id,membership_type,status) "
                           "VALUES (%s,%s,%s,'active')", (t,p,'admin' if i else 'platform_superadmin'))
                if not i:
                    db.execute("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) "
                               "VALUES (%s,%s,'setup','root')", (t,p))
                self.observe(db,t,p,u)
            self.context(db,t,pairs[0][1])
            if activate:
                db.execute("SELECT bri.activate_client(%s)",(t,))
        return t,pairs

    def test_provisioning_needs_two_and_platform_release(self):
        t, pairs = self.fixture(1, False)
        with self.connect('bri_migrator') as db:
            self.context(db,t,pairs[0][1])
            self.assertFalse(db.execute("SELECT bri.client_is_operational(%s)",(t,)).fetchone()[0])
            with self.assertRaises(psycopg.errors.CheckViolation), db.transaction():
                db.execute("SELECT bri.activate_client(%s)",(t,))
        t,pairs = self.fixture(2, False)
        with self.connect('bri_migrator') as db:
            self.context(db,t,pairs[1][1])
            with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                db.execute("SELECT bri.activate_client(%s)",(t,))
            self.context(db,t,pairs[0][1])
            self.assertFalse(db.execute("SELECT bri.client_is_operational(%s)",(t,)).fetchone()[0])
            db.execute("SELECT bri.activate_client(%s)",(t,))
        with self.connect('bri_app') as db:
            self.context(db,t,pairs[1][1])
            self.assertTrue(db.execute("SELECT bri.client_is_operational(%s)",(t,)).fetchone()[0])
            for stmt in ["SELECT bri.activate_client(%s)", "SELECT * FROM bri.governance_eligible WHERE tenant_id=%s",
                         "DELETE FROM bri.client_totp_observations WHERE tenant_id=%s"]:
                with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                    db.execute(stmt,(t,))
            with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                self.observe(db,t,*pairs[1])

    def test_role_and_tenant_boundaries(self):
        a,aa = self.fixture()
        b,bb = self.fixture()
        with self.connect('bri_app') as db:
            self.context(db,a,aa[2][1])
            for tenant, subject, expected in [(a,aa[1][0],True),(a,aa[0][0],False),(b,bb[1][0],False)]:
                self.assertIs(db.execute("SELECT bri.eligible_client_admin(%s,%s)",(tenant,subject)).fetchone()[0],expected)
            self.context(db,b,aa[2][1])
            self.assertEqual(db.execute("SELECT bri.client_is_operational(%s),bri.eligible_client_admin(%s,%s)",
                                        (b,b,bb[1][0])).fetchone(), (False,False))

    def test_all_voluntary_loss_paths_rejected_at_floor(self):
        _, pairs = self.fixture()
        p, _ = pairs[1]
        with self.connect('postgres') as db:
            for stmt in ["UPDATE bri.auth_principals SET deletion_requested_at=now() WHERE principal_id=%s",
                         "UPDATE bri.auth_principals SET status='suspended' WHERE principal_id=%s",
                         "UPDATE bri.auth_tenant_memberships SET membership_type='superuser' WHERE principal_id=%s",
                         "UPDATE bri.auth_tenant_memberships SET status='deactivated' WHERE principal_id=%s",
                         "UPDATE bri.auth_identity_links SET status='revoked' WHERE principal_id=%s",
                         "UPDATE bri.auth_identity_links SET auth_issuer='other',provider_issuer='other' WHERE principal_id=%s",
                         "INSERT INTO bri.platform_superadmins(principal_id) VALUES (%s)",
                         *('DELETE FROM bri.'+table+' WHERE principal_id=%s' for table in
                           ['auth_principals','auth_tenant_memberships','auth_identity_links','client_totp_observations'])]:
                with self.subTest(stmt=stmt), self.assertRaises(psycopg.errors.CheckViolation), db.transaction():
                    db.execute(stmt,(p,))

    def test_expiry_and_unknown_provider_close_then_recover(self):
        t,pairs = self.fixture()
        with self.connect('postgres') as db:
            self.context(db,t,pairs[1][1])
            self.observe(db,t,*pairs[1],False)
            self.assertFalse(db.execute("SELECT bri.client_is_operational(%s)",(t,)).fetchone()[0])
            # A delayed positive cannot overwrite the newer negative.
            db.execute("SELECT bri.record_client_totp_observation(%s,%s,%s,'synthetic:issuer',"
                       "now()-interval '1 minute',now()+interval '10 minutes')",(t,*pairs[1]))
            self.assertFalse(db.execute("SELECT bri.eligible_client_admin(%s,%s)",(t,pairs[1][0])).fetchone()[0])
            self.observe(db,t,*pairs[1])
            self.assertTrue(db.execute("SELECT bri.client_is_operational(%s)",(t,)).fetchone()[0])
            db.execute("UPDATE bri.client_totp_observations SET observed_at=now()-interval '10 minutes',"
                       "verified_until=now()-interval '1 minute' WHERE principal_id=%s", (pairs[2][0],))
            self.assertFalse(db.execute("SELECT bri.client_is_operational(%s)",(t,)).fetchone()[0])

    def test_simultaneous_different_losses(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        for isolation in ('READ COMMITTED','REPEATABLE READ','SERIALIZABLE'):
            t,pairs = self.fixture(3)
            race = Barrier(2)
            def lose(item, *, isolation=isolation, race=race):
                stmt,p = item
                try:
                    with self.connect('postgres') as db:
                        db.execute('SET TRANSACTION ISOLATION LEVEL '+isolation)
                        db.execute("SET LOCAL statement_timeout='5s'")
                        db.execute('SELECT 1 FROM bri.client_governance_fence').fetchone()
                        race.wait(timeout=5)
                        db.execute(stmt,(p,))
                    return 'committed'
                except (psycopg.errors.CheckViolation,psycopg.errors.SerializationFailure):
                    return 'denied'
            with self.subTest(isolation=isolation), ThreadPoolExecutor(2) as pool:
                self.assertCountEqual(pool.map(lose, [
                    ("UPDATE bri.auth_principals SET deletion_requested_at=now() WHERE principal_id=%s",pairs[1][0]),
                    ("DELETE FROM bri.client_totp_observations WHERE principal_id=%s",pairs[2][0])]),
                    ['committed','denied'])
            with self.connect('bri_app') as db:
                self.context(db,t,pairs[3][1])
                self.assertTrue(db.execute("SELECT bri.client_is_operational(%s)",(t,)).fetchone()[0])

    def test_newly_attested_admin_cannot_be_lost_by_waiting_writer(self):
        from concurrent.futures import ThreadPoolExecutor
        t, pairs = self.fixture(2,False)
        with self.connect('postgres') as first, self.connect('postgres') as second, ThreadPoolExecutor(1) as pool:
            self.context(first,t,pairs[0][1])
            self.observe(first,t,*pairs[1],False)
            pid = second.info.backend_pid
            job = pool.submit(second.execute, "UPDATE bri.auth_principals SET status='suspended' WHERE principal_id=%s",
                              (pairs[1][0],))
            try:
                deadline = time.monotonic() + 3
                with self.connect('postgres',autocommit=True) as watcher:
                    while time.monotonic() < deadline:
                        if watcher.execute("SELECT cardinality(pg_blocking_pids(%s))>0", (pid,)).fetchone()[0]:
                            break
                        time.sleep(.01)
                    else:
                        self.fail('writer did not reach governance fence')
                self.observe(first,t,*pairs[1])
                first.execute("SELECT bri.activate_client(%s)",(t,))
                first.commit()
                with self.assertRaises(psycopg.errors.CheckViolation):
                    job.result(timeout=3)
            finally:
                first.rollback()
                second.rollback()

    def test_runtime_cannot_mint_platform_setup_authority(self):
        t,pairs = self.fixture()
        with self.connect('bri_app') as db:
            self.context(db,t,pairs[1][1])
            db.execute("INSERT INTO bri.app_roles VALUES (%s,'ordinary','ordinary')",(t,))
            with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                db.execute("INSERT INTO bri.role_permissions VALUES (%s,'ordinary','platform:client_admin:manage')",(t,))

    def test_multirow_loss_rolls_back(self):
        t, _ = self.fixture(3)
        with self.connect('postgres') as db:
            with self.assertRaises(psycopg.errors.CheckViolation), db.transaction():
                db.execute("UPDATE bri.auth_tenant_memberships SET status='suspended' "
                           "WHERE tenant_id=%s AND membership_type='admin'",(t,))
            self.assertEqual(db.execute("SELECT count(*) FROM bri.governance_eligible WHERE tenant_id=%s",(t,)).fetchone(), (3,))

    def test_missing_context_is_closed(self):
        with self.connect("bri_app") as db:
            self.assertEqual(db.execute("SELECT bri.client_is_operational('absent'), "
                                        "bri.eligible_client_admin('absent',gen_random_uuid())").fetchone(),
                             (False, False))
