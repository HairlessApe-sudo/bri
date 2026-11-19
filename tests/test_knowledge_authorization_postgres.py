"""A11.4-P1: real knowledge readers on an opt-in, private PG16 cluster.

Set BRI_TEST_PG_BIN to the PG16 bin directory. No DSNs or provider credentials
are read; all connections use a new owner-only Unix socket with TCP disabled.
"""

from contextlib import redirect_stdout
from dataclasses import dataclass, replace
from enum import Enum, auto
from hashlib import sha256
import importlib.util
import io
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
import psycopg
from psycopg import sql

from bri.access.policy import AccessGrant, Principal
from bri.api.app import ApiSettings, create_app
from bri.api.catalog import SyntheticCatalog
from bri.api.database import Database


ROOT = Path(__file__).resolve().parents[1]
TENANT_A, TENANT_B = "knowledge-fixture-a", "knowledge-fixture-b"
BASE = "/v1/knowledge"
RECORD_ACCESS, VERSION_ACCESS = "knowledge_record_access", "knowledge_version_access"
INSUFFICIENT = {"status": "insufficient", "answer": None, "citations": []}


class PolicyRow(Enum):
    ABSENT = auto()
    DEFAULT = auto()


ABSENT, DEFAULT = PolicyRow.ABSENT, PolicyRow.DEFAULT


@dataclass(frozen=True)
class Evidence:
    token: str
    tenant: str = TENANT_A
    source: str = ""
    version: str = "v1"
    scope: str = "team"

    @property
    def source_id(self):
        return f"source-{self.source or self.token}"

    @property
    def version_id(self):
        return f"version-{self.source or self.token}-{self.version}"

    @property
    def record_id(self):
        return f"publication-{self.token}"

    @property
    def content(self):
        return f"{self.token} describes synthetic evidence."

    @property
    def reference(self):
        return {
            "record_id": self.record_id,
            "title": f"Synthetic {self.tenant} {self.source_id}",
            "source_id": self.source_id,
            "source_version_id": self.version_id,
            "source_version": self.version,
            "extraction_id": f"extraction-{self.token}",
            "content_sha256": sha256(self.content.encode()).hexdigest(),
            "extractor_name": "fixture-extractor",
            "extractor_version": "3",
            "source_location": f"fixture://{self.tenant}/{self.token}#page=2",
        }


LEGACY = Evidence("legacyartifact")


def seed_evidence(db, item, *, decision="approved", published=True):
    ref = item.reference
    key = (item.tenant, item.source_id)
    db.execute(
        "INSERT INTO bri.source_records "
        "(tenant_id,source_id,scope_node_id,title,source_kind,created_by) "
        "VALUES (%s,%s,%s,%s,'synthetic_text','author') "
        "ON CONFLICT (tenant_id,source_id) DO NOTHING",
        (*key, item.scope, ref["title"]),
    )
    db.execute(
        "INSERT INTO bri.source_versions "
        "(tenant_id,source_id,source_version_id,version_label,content_sha256,source_location,created_by) "
        "VALUES (%s,%s,%s,%s,%s,%s,'author')",
        (*key, item.version_id, item.version, ref["content_sha256"], ref["source_location"]),
    )
    db.execute(
        "INSERT INTO bri.source_extractions "
        "(tenant_id,extraction_id,source_id,source_version_id,scope_node_id,content,"
        "content_sha256,source_location,extractor_name,extractor_version,created_by) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'author')",
        (item.tenant, ref["extraction_id"], item.source_id, item.version_id, item.scope,
         item.content, ref["content_sha256"], ref["source_location"],
         ref["extractor_name"], ref["extractor_version"]),
    )
    db.execute(
        "INSERT INTO bri.knowledge_proposals "
        "(tenant_id,proposal_id,extraction_id,scope_node_id,proposed_by) VALUES (%s,%s,%s,%s,'author')",
        (item.tenant, item.record_id, ref["extraction_id"], item.scope),
    )
    decision_id = f"decision-{item.token}"
    if decision is not None:
        db.execute(
            "INSERT INTO bri.validation_decisions "
            "(tenant_id,decision_id,proposal_id,reviewer_id,decision) VALUES (%s,%s,%s,'reviewer',%s)",
            (item.tenant, decision_id, item.record_id, decision),
        )
    if published:
        db.execute(
            "INSERT INTO bri.validated_knowledge (tenant_id,proposal_id,decision_id) VALUES (%s,%s,%s)",
            (item.tenant, item.record_id, decision_id),
        )


def insert_policy(db, table, item, readable: bool | PolicyRow):
    if readable is ABSENT:
        return
    columns = ["tenant_id", "source_id"]
    values = [item.tenant, item.source_id]
    if table == VERSION_ACCESS:
        columns.append("source_version_id")
        values.append(item.version_id)
    if readable is not DEFAULT:
        columns.append("readable")
        values.append(readable)
    db.execute(
        sql.SQL("INSERT INTO bri.{} ({}) VALUES ({})").format(
            sql.Identifier(table), sql.SQL(",").join(map(sql.Identifier, columns)),
            sql.SQL(",").join(sql.Placeholder() for _ in values),
        ),
        values,
    )


def set_tenant(db, tenant):
    db.execute("SELECT set_config('bri.tenant_id', %s, true)", (tenant,))


class PrivateAppDatabase(Database):
    def __init__(self, connect):
        super().__init__(supabase_url="", database_url="")
        self.connect_private = connect

    def _connect(self):
        return self.connect_private("bri_app")


@unittest.skipUnless(os.getenv("BRI_TEST_PG_BIN"), "set BRI_TEST_PG_BIN to local PG16 binaries")
class KnowledgeAuthorizationPostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if any(key.startswith("PG") for key in os.environ):
            raise RuntimeError("run disposable tests without inherited libpq environment")
        binary = Path(os.environ["BRI_TEST_PG_BIN"]).resolve(strict=True)
        tmp = tempfile.TemporaryDirectory(prefix="knowledge-")
        cls.addClassCleanup(tmp.cleanup)
        cls.sock = Path(tmp.name)
        data = str(cls.sock / "data")
        env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(cls.sock)}

        def cli(cmd, *args):
            result = subprocess.run(
                [str(binary / cmd), *args], env=env, capture_output=True, text=True, timeout=45,
            )
            if result.returncode:
                raise RuntimeError(f"{cmd} failed: {result.stdout}\n{result.stderr}")
            return result.stdout

        if " 16." not in cli("postgres", "--version"):
            raise RuntimeError("requires PostgreSQL 16")
        cli("initdb", "-D", data, "--no-locale", "--encoding=UTF8",
            "--username=postgres", "--auth=trust")
        cli("pg_ctl", "-D", data, "-l", str(cls.sock / "log"), "-o",
            f"-k {shlex.quote(str(cls.sock))} -c listen_addresses='' -c timezone=UTC", "-w", "start")
        cls.addClassCleanup(cli, "pg_ctl", "-D", data, "-m", "immediate", "-w", "stop")
        cls.factory = staticmethod(psycopg.connect)
        with cls.connect("postgres") as db:
            assert db.execute("SELECT inet_server_addr(), current_setting('listen_addresses')").fetchone() == (None, "")
            db.execute(
                "CREATE ROLE bri_app LOGIN NOINHERIT; CREATE ROLE bri_approval_worker LOGIN NOINHERIT; "
                "CREATE ROLE bri_migrator LOGIN NOINHERIT CONNECTION LIMIT 2; "
                "CREATE SCHEMA bri AUTHORIZATION bri_migrator"
            )

        spec = importlib.util.spec_from_file_location("knowledge_runner", ROOT / "scripts/db/migrate.py")
        assert spec is not None and spec.loader is not None
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        dsn = f"postgresql://bri_migrator@db.{runner.EXPECTED_REF}.supabase.co:5432/postgres"

        def guarded(target, **kwargs):
            if target != dsn:
                raise AssertionError("unexpected migration target")
            return cls.connect("bri_migrator", **kwargs)

        settings = {
            "BRI_ENVIRONMENT": "local",
            "SUPABASE_URL": f"https://{runner.EXPECTED_REF}.supabase.co",
            "BRI_MIGRATION_ROLE_DATABASE_URL": dsn,
        }

        def migrate(root):
            output = io.StringIO()
            with (
                patch.object(runner, "ROOT", root),
                patch.object(runner, "env_values", return_value=settings),
                patch.object(runner.psycopg, "connect", guarded),
                redirect_stdout(output),
            ):
                status = runner.main()
            if status:
                raise AssertionError(output.getvalue())
            return output.getvalue()

        # Seed a publication before the access migration to detect permissive backfills.
        files = sorted((ROOT / "db/migrations").glob("[0-9]*_*.sql"))
        baseline = cls.sock / "baseline"
        prefix = baseline / "db/migrations"
        prefix.mkdir(parents=True)
        for path in files:
            if path.name[:4] <= "0019":
                (prefix / path.name).symlink_to(path)
        migrate(baseline)
        with cls.connect("postgres") as db:
            for tenant in (TENANT_A, TENANT_B):
                db.execute("INSERT INTO bri.tenants VALUES (%s,%s,'fixture')", (tenant, tenant))
                db.execute(
                    "INSERT INTO bri.org_nodes (tenant_id,node_id,node_type,display_name,parent_node_id) "
                    "VALUES (%s,'parent','department','Parent',NULL), (%s,'team','team','Team','parent')",
                    (tenant, tenant),
                )
                db.execute(
                    "INSERT INTO bri.synthetic_principals (tenant_id,principal_id,display_name) "
                    "VALUES (%s,'author','Author'), (%s,'reviewer','Reviewer')",
                    (tenant, tenant),
                )
            seed_evidence(db, LEGACY)
        migrate(ROOT)
        assert "applied_count=0" in migrate(ROOT)
        with cls.connect("bri_migrator") as db:
            runner.verify_ledger(db, files)
            assert db.execute("SELECT version FROM bri.schema_migrations ORDER BY version").fetchall() == [
                (path.stem,) for path in files
            ]

    @classmethod
    def connect(cls, user, **kwargs):
        return cls.factory(
            host=str(cls.sock), port=5432, user=user, dbname="postgres", sslmode="disable",
            passfile=str(cls.sock / "no-credential-file"), **kwargs,
        )

    def setUp(self):
        def reader(identity, tenant, scope):
            return Principal(identity, frozenset({tenant}), (AccessGrant(tenant, "knowledge:read", scope),))

        catalog = SyntheticCatalog({}, {
            "reader-a": reader("reader-a", TENANT_A, "team"),
            "reader-b": reader("reader-b", TENANT_B, "team"),
            "parent-a": reader("parent-a", TENANT_A, "parent"),
            "no-tenant": Principal("no-tenant", frozenset(), ()),
        })
        app = create_app(
            settings=ApiSettings(environment="development", dev_auth_enabled=True),
            database=PrivateAppDatabase(self.connect), catalog=catalog,
        )
        self.client = self.enterContext(TestClient(app, client=("127.0.0.1", 51000)))

    def add_evidence(self, item, *, record: bool | PolicyRow = True,
                     version: bool | PolicyRow = True, **validation):
        with self.connect("postgres") as db:
            seed_evidence(db, item, **validation)
        with self.connect("bri_migrator") as db:
            set_tenant(db, item.tenant)
            insert_policy(db, RECORD_ACCESS, item, record)
            insert_policy(db, VERSION_ACCESS, item, version)

    def get(self, path, identity: str | None = "reader-a", *, status=200, **params):
        headers = {} if identity is None else {"X-Dev-Identity": identity}
        response = self.client.get(path, headers=headers, params=params)
        self.assertEqual(response.status_code, status, response.text)
        return response.json()

    def assert_readable(self, item, identity="reader-a"):
        ref = item.reference
        record = {**ref, "content": item.content, "scope_id": item.scope, "validation_state": "approved"}
        self.assertEqual(
            [row for row in self.get(BASE, identity) if row["record_id"] == item.record_id],
            [record],
        )
        self.assertEqual(self.get(f"{BASE}/{item.record_id}", identity), record)
        self.assertEqual(self.get(f"/v1/sources/{item.record_id}", identity), ref)
        self.assertEqual(self.get(f"{BASE}/search", identity, q=item.token), {
            "status": "supported", "answer": item.content,
            "citations": [{**ref, "excerpt": item.content}],
        })

    def assert_hidden(self, item, identity="reader-a"):
        self.assertNotIn(item.token, str(self.get(BASE, identity)))
        for path in (BASE, "/v1/sources"):
            with self.subTest(path=path):
                hidden = self.get(f"{path}/{item.record_id}", identity, status=404)
                absent = self.get(f"{path}/absent-publication", identity, status=404)
                self.assertEqual(hidden, absent)
        self.assertEqual(self.get(f"{BASE}/search", identity, q=item.token), INSUFFICIENT)

    def test_legacy_publication_is_not_automatically_readable(self):
        self.assert_hidden(LEGACY)

    def test_both_access_rows_must_explicitly_allow(self):
        allowed = Evidence("allowedartifact")
        self.add_evidence(allowed)
        self.assert_readable(allowed)
        for token, record, version in (
            ("missingrecordartifact", ABSENT, True),
            ("missingversionartifact", True, ABSENT),
            ("falserecordartifact", False, True),
            ("falseversionartifact", True, False),
            ("defaultrecordartifact", DEFAULT, True),
            ("defaultversionartifact", True, DEFAULT),
        ):
            with self.subTest(case=token):
                item = Evidence(token)
                self.add_evidence(item, record=record, version=version)
                self.assert_hidden(item)
        self.assert_readable(allowed)

    def test_both_access_rows_do_not_replace_publication_or_exact_node_grant(self):
        allowed = Evidence("scopeartifact")
        self.add_evidence(allowed)
        self.assert_readable(allowed)
        self.assert_hidden(allowed, "parent-a")
        for token, decision in (("pendingartifact", None), ("rejectedartifact", "rejected"),
                                ("unpublishedartifact", "approved")):
            with self.subTest(decision=decision):
                item = Evidence(token)
                self.add_evidence(item, decision=decision, published=False)
                self.assert_hidden(item)

    def test_current_version_revocation_removes_previously_searchable_evidence(self):
        older = Evidence("previousartifact", source="two-versions", version="v1")
        newer = Evidence("retainedartifact", source="two-versions", version="v2")
        self.add_evidence(older)
        self.add_evidence(newer, record=ABSENT)
        self.assert_readable(older)
        self.assert_readable(newer)

        # Independent committed policy update; keep both publications and the node grant unchanged.
        with self.connect("bri_migrator") as db:
            set_tenant(db, TENANT_A)
            updated = db.execute(
                "UPDATE bri.knowledge_version_access SET readable=false "
                "WHERE tenant_id=%s AND source_id=%s AND source_version_id=%s AND readable IS TRUE",
                (TENANT_A, older.source_id, older.version_id),
            )
            self.assertEqual(updated.rowcount, 1)
        self.assert_hidden(older)
        self.assert_readable(newer)

    def test_current_record_revocation_applies_to_every_version(self):
        first = Evidence("firstrecordartifact", source="revoked-record", version="v1")
        second = Evidence("secondrecordartifact", source="revoked-record", version="v2")
        unaffected = Evidence("unaffectedartifact")
        self.add_evidence(first)
        self.add_evidence(second, record=ABSENT)
        self.add_evidence(unaffected)
        self.assert_readable(first)
        self.assert_readable(second)
        with self.connect("bri_migrator") as db:
            set_tenant(db, TENANT_A)
            updated = db.execute(
                "UPDATE bri.knowledge_record_access SET readable=false "
                "WHERE tenant_id=%s AND source_id=%s AND readable IS TRUE",
                (TENANT_A, first.source_id),
            )
            self.assertEqual(updated.rowcount, 1)
        self.assert_hidden(first)
        self.assert_hidden(second)
        self.assert_readable(unaffected)

    def test_foreign_access_rows_cannot_authorize_identical_local_source_and_version_keys(self):
        for key, local_record, local_version in (("record", ABSENT, True), ("version", True, ABSENT)):
            with self.subTest(key=key):
                foreign = Evidence(f"foreign{key}artifact", tenant=TENANT_B, source=f"shared-{key}")
                local = Evidence(f"local{key}artifact", source=f"shared-{key}")
                self.add_evidence(foreign)
                self.add_evidence(local, record=local_record, version=local_version)
                self.assert_readable(foreign, "reader-b")
                self.assert_hidden(foreign)
                self.assert_hidden(local)

    def test_all_routes_reject_missing_identity_or_tenant_context(self):
        sample = Evidence("contextartifact")
        self.add_evidence(sample)
        self.assert_readable(sample)
        for path, params in ((BASE, {}), (f"{BASE}/{sample.record_id}", {}),
                             ("/v1/sources/" + sample.record_id, {}),
                             (f"{BASE}/search", {"q": sample.token})):
            with self.subTest(path=path):
                self.get(path, None, status=401, **params)
                self.get(path, "no-tenant", status=403, **params)

    def test_policy_tables_force_tenant_rls_and_are_read_only_for_bri_app(self):
        local = Evidence("rlslocalartifact")
        foreign = Evidence("rlsforeignartifact", tenant=TENANT_B)
        self.add_evidence(local)
        self.add_evidence(foreign)
        with self.connect("bri_app") as db:
            self.assertEqual(db.execute(
                "SELECT current_user, rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user"
            ).fetchone(), ("bri_app", False, False))
            for table in (RECORD_ACCESS, VERSION_ACCESS):
                with self.subTest(table=table):
                    relation = sql.Identifier("bri", table)
                    self.assertEqual(db.execute(
                        "SELECT relrowsecurity, relforcerowsecurity, pg_get_userbyid(relowner) "
                        "FROM pg_class WHERE oid=%s::regclass",
                        (f"bri.{table}",),
                    ).fetchone(), (True, True, "bri_migrator"))
                    select = sql.SQL("SELECT tenant_id, source_id, readable FROM {} ").format(relation)
                    matching = select + sql.SQL("WHERE source_id IN (%s,%s)")
                    keys = (local.source_id, foreign.source_id)
                    with db.transaction():
                        self.assertEqual(db.execute(matching, keys).fetchall(), [])
                        set_tenant(db, TENANT_A)
                        self.assertEqual(db.execute(matching, keys).fetchall(), [(TENANT_A, local.source_id, True)])
                        self.assertEqual(db.execute(select + sql.SQL("WHERE tenant_id=%s"), (TENANT_B,)).fetchall(), [])
                        for statement in ("UPDATE {} SET readable=false WHERE source_id=%s",
                                          "DELETE FROM {} WHERE source_id=%s"):
                            with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                                db.execute(sql.SQL(statement).format(relation), (local.source_id,))
                        with self.assertRaises(psycopg.errors.InsufficientPrivilege), db.transaction():
                            insert_policy(db, table, LEGACY, True)
                        self.assertEqual(db.execute(matching, keys).fetchall(), [(TENANT_A, local.source_id, True)])
                        set_tenant(db, "")

    def test_policy_rows_require_matching_tenant_source_and_version(self):
        foreign = Evidence("fkforeignartifact", tenant=TENANT_B)
        local = Evidence("fklocalartifact")
        with self.connect("postgres") as db:
            seed_evidence(db, foreign)
            seed_evidence(db, local)
        with self.connect("bri_migrator") as db:
            set_tenant(db, TENANT_A)
            for table, wrong_key in (
                (RECORD_ACCESS, replace(foreign, tenant=TENANT_A)),
                (VERSION_ACCESS, replace(foreign, tenant=TENANT_A)),
                (VERSION_ACCESS, replace(local, version="v9")),
            ):
                with self.subTest(table=table, wrong_key=wrong_key):
                    with self.assertRaises(psycopg.errors.ForeignKeyViolation), db.transaction():
                        insert_policy(db, table, wrong_key, True)
                        db.execute("SET CONSTRAINTS ALL IMMEDIATE")


if __name__ == "__main__":
    unittest.main()
