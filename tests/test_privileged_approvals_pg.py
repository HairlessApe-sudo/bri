"""A10 restricted-role tests. Opt in with BRI_APPROVAL_PG_BIN pointing to PG16 binaries.
Creates its OWN cluster (0700 temporary Unix socket, TCP disabled). Never opens a supplied
DSN, runs psql service files, or reads application credentials. No provider network calls.
"""

import asyncio
import importlib.util
import io
import os
import subprocess
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import psycopg

from bri.access.approvals import (
    ACTION,
    ApprovalContext,
    ApprovalRepository,
    ApprovalWorker,
    ProviderMfaError,
)
from bri.api.authentication import AuthenticatedIdentity
from bri.api.database import EXPECTED_PROJECT_REF

ROOT = Path(__file__).resolve().parents[1]
ISSUER = f"https://{EXPECTED_PROJECT_REF}.supabase.co/auth/v1"
APPROVAL_APP_ROUTINES = (
    "bri.approval_request(text,text,uuid,text,uuid)",
    "bri.approval_decide(text,text,uuid,text)",
    "bri.approval_status(text,text,uuid)",
    "bri.read_mfa_reset_queue(text,uuid,uuid,text,integer,uuid,uuid)",
    "bri.can_request_mfa_reset(text,uuid,uuid,text,uuid)",
)
PROVISIONING_WRITE = "bri.request_user_provisioning(text,uuid,uuid,text,timestamptz,uuid,text,text,uuid)"
LIFECYCLE_WRITE = "bri.change_user_lifecycle(text,uuid,uuid,text,uuid,text,bigint,text,text,timestamptz,uuid)"
STAGED_ACCOUNT_WRITES = (PROVISIONING_WRITE, LIFECYCLE_WRITE)
ACCOUNT_READS = (
    "bri.status_user_provisioning(text,uuid,uuid,text,uuid)",
    "bri.read_user_lifecycle(text,uuid,uuid,text,uuid)",
)


def assert_release_account_acls(db):
    checks = unittest.TestCase()
    with db.transaction():
        db.execute("SET TRANSACTION READ ONLY")
        denied = {
            routine: db.execute(
                "SELECT has_function_privilege(current_user,p.oid,'EXECUTE'), EXISTS ("
                "SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) acl "
                "WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE') "
                "FROM pg_proc p WHERE p.oid=%s::regprocedure",
                (routine,),
            ).fetchone()
            for routine in STAGED_ACCOUNT_WRITES
        }
        checks.assertEqual(denied, dict.fromkeys(STAGED_ACCOUNT_WRITES, (False, False)))
        for routine in ACCOUNT_READS:
            checks.assertEqual(db.execute(
                "SELECT has_function_privilege(current_user,%s::regprocedure,'EXECUTE')",
                (routine,),
            ).fetchone(), (True,), routine)
        for routine in STAGED_ACCOUNT_WRITES:
            # No actor, tenant, evidence or valid write input. Require PostgreSQL's
            # function ACL denial, not a matching SQLSTATE from inside the routine.
            name, types = routine[:-1].split("(")
            args = ",".join(f"NULL::{kind}" for kind in types.split(","))
            with checks.assertRaises(psycopg.errors.InsufficientPrivilege) as denied_call, db.transaction():
                db.execute(f"SELECT * FROM {name}({args})")
            checks.assertEqual(denied_call.exception.sqlstate, "42501")
            checks.assertEqual(denied_call.exception.diag.message_primary,
                               f"permission denied for function {name.split('.')[1]}")


def seed_approval_tenant(connect):
    """Create one operational client with independent admins, grants and sessions."""
    tenant = "fixture-" + uuid4().hex
    actors = []
    with connect("postgres") as db:
        db.execute(
            "INSERT INTO bri.tenants VALUES (%s,'Fixture','fixture')", (tenant,)
        )
        db.execute(
            "INSERT INTO bri.tenant_admin_policies(tenant_id) VALUES (%s)",
            (tenant,),
        )
        db.execute(
            "INSERT INTO bri.org_nodes VALUES (%s,'root','root','root')", (tenant,)
        )
        db.execute(
            "INSERT INTO bri.app_roles VALUES (%s,'reset','reset')", (tenant,)
        )
        for permission in (
            "user:mfa_reset:request",
            "user:mfa_reset:decide",
            "platform:client_admin:manage",
        ):
            db.execute(
                "INSERT INTO bri.role_permissions VALUES(%s,'reset',%s)",
                (tenant, permission),
            )
        for membership in ("admin", "admin", "user", "platform_superadmin"):
            p, u, s, person = (uuid4() for _ in range(4))
            actors.append((p, u, s))
            db.execute(
                "INSERT INTO bri.auth_principals(principal_id,status) VALUES(%s,'active')",
                (p,),
            )
            db.execute(
                "INSERT INTO bri.auth_identity_links(auth_user_id,principal_id,auth_issuer,auth_subject,provider_type,provider_issuer,provider_subject) VALUES(%s,%s,%s,%s,'native',%s,%s)",
                (u, p, ISSUER, str(u), ISSUER, str(u)),
            )
            if membership == "platform_superadmin":
                db.execute(
                    "INSERT INTO bri.platform_superadmins(principal_id) VALUES(%s)",
                    (p,),
                )
            db.execute(
                "INSERT INTO bri.auth_tenant_memberships(tenant_id,principal_id,membership_type,status) VALUES(%s,%s,%s,'active')",
                (tenant, p, membership),
            )
            if membership != "user":
                db.execute(
                    "INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) VALUES(%s,%s,'reset','root')",
                    (tenant, p),
                )
            if membership == "admin":
                db.execute(
                    "INSERT INTO bri.approval_admin_people VALUES(%s,%s,%s,'root',false)",
                    (p, person, tenant),
                )
                db.execute(
                    "SELECT bri.record_client_totp_observation(%s,%s,%s,%s,now(),now()+interval '14 minutes')",
                    (tenant, p, u, ISSUER),
                )
        db.execute(
            "SELECT set_config('bri.auth_user_id',%s,true),set_config('bri.tenant_id',%s,true)",
            (str(u), tenant),
        )
        db.execute("SELECT bri.activate_client(%s)", (tenant,))
        for p, u, s in actors:
            db.execute(
                "INSERT INTO bri.auth_sessions(auth_user_id,principal_id,session_id) VALUES(%s,%s,%s)",
                (u, p, s),
            )
    return tenant, actors


@unittest.skipUnless(
    os.getenv("BRI_APPROVAL_PG_BIN"),
    "requires private disposable PostgreSQL 16 binaries",
)
class ApprovalDatabase(unittest.TestCase):
    @classmethod
    def setUpClass(cls, *, staged_account_write=None):
        if any(k.startswith("PG") for k in os.environ):
            raise RuntimeError(
                "run disposable tests without inherited libpq environment"
            )
        binary = Path(os.environ["BRI_APPROVAL_PG_BIN"]).resolve(strict=True)
        tmp = tempfile.TemporaryDirectory(prefix="approval-")
        cls.addClassCleanup(tmp.cleanup)
        cls.sock = Path(tmp.name)
        data = str(cls.sock / "data")
        env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(cls.sock)}

        def cli(cmd, *args):
            return subprocess.run(
                [str(binary / cmd), *args],
                env=env,
                check=True,
                capture_output=True,
                text=True,
                timeout=45,
            )

        if " 16." not in cli("postgres", "--version").stdout:
            raise RuntimeError("requires PostgreSQL 16")
        cli(
            "initdb",
            "-D",
            data,
            "--no-locale",
            "--encoding=UTF8",
            "--username=postgres",
            "--auth=trust",
        )
        cli(
            "pg_ctl",
            "-D",
            data,
            "-l",
            str(cls.sock / "log"),
            "-o",
            f"-k {cls.sock} -c listen_addresses=''",
            "-w",
            "start",
        )
        cls.addClassCleanup(cli, "pg_ctl", "-D", data, "-m", "immediate", "-w", "stop")
        cls.factory = staticmethod(psycopg.connect)
        with cls.connect("postgres") as db:
            db.execute(
                "CREATE ROLE bri_app LOGIN NOINHERIT; CREATE ROLE bri_approval_worker LOGIN NOINHERIT; "
                "CREATE ROLE bri_migrator LOGIN NOINHERIT CONNECTION LIMIT 2; "
                "CREATE SCHEMA bri AUTHORIZATION bri_migrator"
            )
        spec = importlib.util.spec_from_file_location(
            "approval_runner", ROOT / "scripts/db/migrate.py"
        )
        assert spec is not None and spec.loader is not None
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        dsn = (
            "postgresql://bri_migrator@db."
            + runner.EXPECTED_REF
            + ".supabase.co:5432/postgres"
        )

        def guarded(d, **kw):
            if d != dsn:
                raise AssertionError("unexpected migration target")
            return cls.connect("bri_migrator", **kw)

        fake = {
            "SUPABASE_URL": "https://" + runner.EXPECTED_REF + ".supabase.co",
            "BRI_ENVIRONMENT": "local",
            "BRI_MIGRATION_ROLE_DATABASE_URL": dsn,
        }
        with (
            patch.object(runner, "env_values", return_value=fake),
            patch.object(runner.psycopg, "connect", guarded),
        ):
            for replay in (False, True):
                log = io.StringIO()
                with redirect_stdout(log):
                    rc = runner.main()
                if rc or (replay and "applied_count=0" not in log.getvalue()):
                    raise AssertionError(log.getvalue())
        with cls.connect("bri_migrator") as db:
            files = sorted((ROOT / "db/migrations").glob("*.sql"))
            runner.verify_ledger(db, files)
            assert db.execute(
                "SELECT version FROM bri.schema_migrations ORDER BY version"
            ).fetchall() == [(p.stem,) for p in files]

        with cls.connect("bri_app") as db:
            assert_release_account_acls(db)
            for routine in APPROVAL_APP_ROUTINES:
                assert db.execute(
                    "SELECT has_function_privilege(current_user,p.oid,'EXECUTE'), EXISTS ("
                    "SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) acl "
                    "WHERE acl.grantee=0 AND acl.privilege_type='EXECUTE') "
                    "FROM pg_proc p WHERE p.oid=%s::regprocedure",
                    (routine,),
                ).fetchone() == (False, False), routine

        with cls.connect("bri_migrator") as db:
            # Enable only these entry points inside disposable SQL/HTTP fixtures.
            routines = ", ".join(APPROVAL_APP_ROUTINES)
            db.execute(f"GRANT EXECUTE ON FUNCTION {routines} TO bri_app")
            if staged_account_write is not None:
                if staged_account_write not in STAGED_ACCOUNT_WRITES:
                    raise AssertionError("unexpected staged account write")
                db.execute(f"GRANT EXECUTE ON FUNCTION {staged_account_write} TO bri_app")
            db.execute(
                "GRANT USAGE ON SCHEMA bri TO bri_approval_worker; GRANT EXECUTE ON FUNCTION "
                "bri.approval_work(text,text,uuid,text,uuid[]) TO bri_approval_worker"
            )

    @classmethod
    def connect(cls, user, **kwargs):
        return cls.factory(
            host=str(cls.sock),
            port=5432,
            user=user,
            dbname="postgres",
            sslmode="disable",
            passfile=str(cls.sock / "no-credential-file"),
            **kwargs,
        )

    def setUp(self):
        self.t, self.actors = seed_approval_tenant(self.connect)
        self.key = uuid4()
        self.repo = ApprovalRepository(lambda: self.connect("bri_app"))

    def ctx(self, index):
        _, u, s = self.actors[index]
        identity = AuthenticatedIdentity(str(u), str(s), ISSUER, "aal2", ("totp",))
        # Test-only stand-in for the verifier's signed AMR event.
        object.__setattr__(identity, "totp_authenticated_at", int(time.time()))
        return ApprovalContext(self.t, identity, uuid4())

    def request(self):
        return self.repo.request(
            self.ctx(0),
            target=self.actors[2][0],
            reason="LOST_FACTOR",
            request_id=self.key,
        )

    def decide(self, choice="APPROVE"):
        return self.repo.decide(self.ctx(1), self.key, choice)

    def test_unrestricted_scope_rejected(self):
        unsafe = ApprovalRepository(lambda: self.connect("postgres"))
        with self.assertRaises(PermissionError):
            unsafe.request(
                self.ctx(0),
                target=self.actors[2][0],
                reason="LOST_FACTOR",
                request_id=self.key,
            )

    def test_privileges(self):
        with self.connect("bri_app") as db:
            for table in (
                "privileged_approvals",
                "approval_votes",
                "approval_events",
                "approval_dispatches",
                "approval_admin_people",
            ):
                forced, access = db.execute(
                    "SELECT relrowsecurity AND relforcerowsecurity, has_table_privilege(current_user,oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE') FROM pg_class WHERE oid=%s::regclass",
                    ("bri." + table,),
                ).fetchone()
                self.assertTrue(forced)
                self.assertFalse(access)
            self.assertFalse(
                db.execute(
                    "SELECT has_function_privilege(current_user,'bri.approval_work(text,text,uuid,text,uuid[])','EXECUTE')"
                ).fetchone()[0]
            )

    def test_denials_and_separation(self):
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.repo.request(
                self.ctx(0),
                target=self.actors[1][0],
                reason="LOST_FACTOR",
                request_id=self.key,
            )
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.repo.request(
                self.ctx(0),
                target=self.actors[2][0],
                reason="unknown",
                request_id=self.key,
            )
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.repo.request(
                self.ctx(3),
                target=self.actors[2][0],
                reason="LOST_FACTOR",
                request_id=self.key,
            )
        self.assertEqual(self.request(), "PENDING")
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.repo.decide(self.ctx(0), self.key, "APPROVE")
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.repo.decide(self.ctx(2), self.key, "APPROVE")
        ctx = self.ctx(1)
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.repo.decide(
                ApprovalContext("other", ctx.identity, ctx.correlation_id),
                self.key,
                "APPROVE",
            )
        self.assertEqual(self.decide("REJECT"), "REJECTED")
        self.assertEqual(self.decide("REJECT"), "REJECTED")
        with self.assertRaises(psycopg.errors.ObjectNotInPrerequisiteState):
            self.decide()

    def test_principal_proofing_and_scope(self):
        with self.connect("postgres") as db:
            with self.assertRaises(psycopg.errors.UniqueViolation), db.transaction():
                db.execute(
                    "INSERT INTO bri.approval_admin_people SELECT %s,person_id,tenant_id,scope_node_id,false FROM bri.approval_admin_people WHERE principal_id=%s",
                    (self.actors[2][0], self.actors[0][0]),
                )
            db.execute(
                "INSERT INTO bri.org_nodes VALUES (%s,'leaf','leaf','leaf','root')",
                (self.t,),
            )
            db.execute(
                "UPDATE bri.auth_role_assignments SET scope_node_id='leaf' WHERE principal_id=%s",
                (self.actors[0][0],),
            )
            db.execute(
                "INSERT INTO bri.auth_sessions(auth_user_id,principal_id,session_id) VALUES(%s,%s,%s)",
                (self.actors[0][1], self.actors[0][0], sid := uuid4()),
            )
            self.actors[0] = (self.actors[0][0], self.actors[0][1], sid)
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.request()

    def test_sql_step_up_and_exact_action(self):
        with self.connect("bri_app") as db:
            self.ctx(0).bind(db)
            for action, stamp in [
                (ACTION, "clock_timestamp()-interval '16 minutes'"),
                (ACTION, "clock_timestamp()+interval '1 minute'"),
                ("OTHER", "clock_timestamp()"),
            ]:
                with (
                    self.assertRaises(psycopg.errors.InsufficientPrivilege),
                    db.transaction(),
                ):
                    db.execute(
                        "SELECT set_config('bri.totp_at',(" + stamp + ")::text,true)"
                    )
                    db.execute(
                        "SELECT bri.approval_request(%s,%s,%s,%s,%s)",
                        (self.t, action, self.actors[2][0], "LOST_FACTOR", self.key),
                    )

    def test_revoked_requester_session_blocks_second_decision(self):
        self.request()
        with self.connect("postgres") as db:
            db.execute(
                "UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() WHERE session_id=%s",
                (self.actors[0][2],),
            )
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            self.decide()

    def test_reviewer_loses_session_before_execution(self):
        self.request()
        self.decide()
        with self.connect("postgres") as db:
            db.execute(
                "UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() WHERE session_id=%s",
                (self.actors[1][2],),
            )
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            asyncio.run(
                ApprovalWorker(
                    lambda: self.connect("bri_approval_worker"), None
                ).execute(self.ctx(1), self.key)
            )
        self.assertEqual(self.repo.status(self.ctx(0), self.key), "APPROVED")

    def test_no_unverified_completion(self):
        self.request()
        self.decide()
        with self.connect("bri_approval_worker") as db:
            self.ctx(1).bind(db)

            def work(op, ids):
                return db.execute(
                    "SELECT stage FROM bri.approval_work(%s,%s,%s,%s,%s::uuid[])",
                    (self.t, ACTION, self.key, op, ids),
                ).fetchone()[0]

            self.assertEqual(work("BEGIN", None), "EXECUTING")
            with self.assertRaises(psycopg.Error), db.transaction():
                work("VERIFIED", [])
            factor = uuid4()
            work("PIN", [factor])
            work("DISPATCH", [factor])
            with self.assertRaises(psycopg.Error), db.transaction():
                work("VERIFIED", [])
        with self.connect("postgres") as db:
            with (
                self.assertRaises(psycopg.errors.ObjectNotInPrerequisiteState),
                db.transaction(),
            ):
                db.execute(
                    "UPDATE bri.auth_tenant_memberships SET membership_type='admin' WHERE principal_id=%s",
                    (self.actors[2][0],),
                )
            self.assertTrue(
                db.execute(
                    "SELECT confirmed_at IS NULL FROM bri.credential_operations WHERE operation_id=%s",
                    (self.key,),
                ).fetchone()[0]
            )

    def test_expiry_persists(self):
        self.request()
        with self.connect("postgres") as db:
            db.execute(
                "UPDATE bri.privileged_approvals SET created_at=created_at-interval '25 hours',expires_at=expires_at-interval '25 hours' WHERE approval_id=%s",
                (self.key,),
            )
        reviewer = self.ctx(1)
        self.assertEqual(self.repo.decide(reviewer, self.key, "APPROVE"), "EXPIRED")
        self.assertEqual(self.repo.status(self.ctx(0), self.key), "EXPIRED")
        with self.connect("postgres") as db:
            self.assertEqual(db.execute(
                "SELECT actor_principal_id,subject_principal_id,request_id FROM bri.security_audit_events "
                "WHERE event_type='auth.approval.expired' AND tenant_id=%s AND outcome='success'", (self.t,)
            ).fetchall(), [(self.actors[1][0], self.actors[2][0], reviewer.correlation_id)])

    def test_authority_rechecked_after_vote(self):
        self.request()
        self.decide()
        with self.connect("postgres") as db:
            db.execute(
                "UPDATE bri.approval_admin_people SET revoked=true WHERE principal_id=%s",
                (self.actors[0][0],),
            )
        worker = ApprovalWorker(lambda: self.connect("bri_approval_worker"), None)
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            asyncio.run(worker.execute(self.ctx(1), self.key))
        self.assertEqual(self.repo.status(self.ctx(1), self.key), "APPROVED")

    def test_concurrent_replay_provider_loss_and_reconcile(self):
        with ThreadPoolExecutor(2) as pool:
            self.assertEqual(
                list(pool.map(lambda _: self.request(), range(2))), ["PENDING"] * 2
            )
            self.assertEqual(
                list(pool.map(lambda _: self.decide(), range(2))), ["APPROVED"] * 2
            )
        factor = str(uuid4())
        target = self.actors[2][0]
        case = self

        class Provider:
            calls = 0
            present = True

            async def list_totp_factor_ids(self, user):
                with case.connect("postgres") as db:
                    case.assertEqual(
                        db.execute(
                            "SELECT p.status, co.confirmed_at FROM bri.auth_principals p "
                            "JOIN bri.credential_operations co USING(principal_id) WHERE p.principal_id=%s "
                            "AND co.operation_id=%s AND co.kind='factor_reenrollment'",
                            (target, case.key),
                        ).fetchone(),
                        ("active", None),
                    )
                    case.assertFalse(
                        db.execute(
                            "SELECT EXISTS(SELECT FROM bri.auth_sessions WHERE principal_id=%s AND revoked_at IS NULL)",
                            (target,),
                        ).fetchone()[0]
                    )
                return [factor] if self.present else []

            async def remove_totp_factor(self, user, fid):
                case.assertEqual((user, fid), (str(case.actors[2][1]), factor))
                self.calls += 1
                self.present = False
                raise ProviderMfaError("unknown outcome")

            async def factor_absent(self, user, fid):
                return not self.present

        provider = Provider()

        async def execute():
            return await ApprovalWorker(
                lambda: self.connect("bri_approval_worker"), provider
            ).execute(self.ctx(1), self.key)

        self.assertEqual(asyncio.run(execute()), "FAILED")
        self.assertEqual(asyncio.run(execute()), "COMPLETED")
        self.assertEqual(asyncio.run(execute()), "COMPLETED")
        self.assertEqual(provider.calls, 1)
        with self.connect("postgres") as db:
            self.assertEqual(
                db.execute(
                    "SELECT state FROM bri.approval_events WHERE approval_id=%s ORDER BY event_id",
                    (self.key,),
                ).fetchall(),
                [
                    (s,)
                    for s in (
                        "PENDING",
                        "APPROVED",
                        "EXECUTING",
                        "FAILED",
                        "EXECUTING",
                        "COMPLETED",
                    )
                ],
            )
