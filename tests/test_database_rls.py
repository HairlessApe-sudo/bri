"""Live Supabase PostgreSQL RLS tests; all fixture writes roll back."""
from __future__ import annotations

import json
import os
import re
import unittest
from pathlib import Path
from urllib.parse import unquote, urlparse

import psycopg
from scripts.db.migrate import validate_role_memberships

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = json.loads((ROOT / "tests/fixtures/synthetic_municipalities.json").read_text(encoding="utf-8"))


EXPECTED_PROJECT_REF = "bwqdyibvuecgthtatrtv"
EXPECTED_POOLER_HOST = "aws-1-eu-west-1.pooler.supabase.com"


def _local_env() -> dict[str, str]:
    values: dict[str, str] = {}
    env_file = ROOT / ".env.local"
    if env_file.is_file():
        for raw in env_file.read_text(encoding="utf-8").splitlines():
            line = raw.strip().removeprefix("export ").strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            val = val.strip()
            if len(val) >= 2 and val[0] == val[-1] and val[0] in "\"'":
                val = val[1:-1]
            values[key.strip()] = val
    values.update({key: value for key, value in os.environ.items() if key in {"DATABASE_URL", "SUPABASE_URL", "BRI_ENVIRONMENT"}})
    return values


def _project_ref(value: str) -> str | None:
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower()
    username = unquote(parsed.username or "")
    try:
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme == "https" and port in (None, 443):
        api_match = re.fullmatch(r"([a-z0-9]{20})\.supabase\.co", host)
        if api_match:
            return api_match.group(1)
    match = re.fullmatch(r"db\.([a-z0-9]{20})\.supabase\.co", host) if port == 5432 else None
    if match:
        return match.group(1)
    if host != EXPECTED_POOLER_HOST or port != 5432:
        return None
    match = re.fullmatch(r"[^.]+\.([a-z0-9]{20})", username)
    return match.group(1) if match else None


@unittest.skipUnless(os.environ.get("BRI_RUN_DB_TESTS") == "1", "set BRI_RUN_DB_TESTS=1 to opt in to the verified development database")
class TenantRlsIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        config = _local_env()
        api_ref = _project_ref(config.get("SUPABASE_URL", ""))
        database_url = config.get("DATABASE_URL", "")
        if config.get("BRI_ENVIRONMENT", "").lower() not in {"development", "dev", "local"}:
            self.fail("database integration tests require explicit development environment")
        if api_ref != EXPECTED_PROJECT_REF or _project_ref(database_url) != api_ref:
            self.fail("database integration test target does not match the approved Supabase development project")
        self.conn = psycopg.connect(database_url, connect_timeout=12)
        self.addCleanup(self._rollback_close)
        self.conn.execute("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE")
        who = self.conn.execute("SELECT current_user").fetchone()[0]
        if who != "bri_app":
            self.fail("integration tests must connect as the restricted bri_app role")
        self._seed_synthetic_fixture()

    def _rollback_close(self) -> None:
        if getattr(self, "conn", None) and not self.conn.closed:
            self.conn.rollback()
            self.conn.close()

    def _tenant_context(self, tenant_id: str) -> None:
        self.conn.execute("SELECT set_config('bri.tenant_id', %s, true)", (tenant_id,))

    def _seed_synthetic_fixture(self) -> None:
        from scripts.db.seed_synthetic_data import insert_or_verify

        def ensure(
            table: str,
            columns: tuple[str, ...],
            values: tuple[object, ...],
            keys: tuple[str, ...],
        ) -> None:
            insert_or_verify(
                self.conn,
                table=table,
                columns=columns,
                values=values,
                key_columns=keys,
            )

        for tenant in FIXTURE["tenants"]:
            tenant_id = tenant["tenant_id"]
            self._tenant_context(tenant_id)
            ensure(
                "bri.tenants",
                ("tenant_id", "display_name", "sector"),
                (tenant_id, tenant["display_name"], tenant["sector"]),
                ("tenant_id",),
            )
            for node in tenant["org_nodes"]:
                ensure(
                    "bri.org_nodes",
                    ("tenant_id", "node_id", "node_type", "display_name", "parent_node_id"),
                    (tenant_id, node["node_id"], node["node_type"], node["display_name"], node["parent_id"]),
                    ("tenant_id", "node_id"),
                )
            for role in tenant["roles"]:
                ensure(
                    "bri.app_roles",
                    ("tenant_id", "role_id", "display_name"),
                    (tenant_id, role["role_id"], role["display_name"]),
                    ("tenant_id", "role_id"),
                )
                for permission in role["permissions"]:
                    ensure(
                        "bri.role_permissions",
                        ("tenant_id", "role_id", "permission"),
                        (tenant_id, role["role_id"], permission),
                        ("tenant_id", "role_id", "permission"),
                    )
            for user in tenant["users"]:
                ensure(
                    "bri.synthetic_principals",
                    ("tenant_id", "principal_id", "display_name"),
                    (tenant_id, user["user_id"], user["display_name"]),
                    ("tenant_id", "principal_id"),
                )
                for assignment in user["role_assignments"]:
                    ensure(
                        "bri.role_assignments",
                        ("tenant_id", "principal_id", "role_id", "scope_node_id"),
                        (tenant_id, user["user_id"], assignment["role_id"], assignment["scope_node_id"]),
                        ("tenant_id", "principal_id", "role_id", "scope_node_id"),
                    )
            for relationship in tenant["relationships"]:
                ensure(
                    "bri.org_relationships",
                    (
                        "tenant_id", "relationship_id", "from_node_id", "to_node_id",
                        "relationship_type", "grants_access",
                    ),
                    (
                        tenant_id, relationship["relationship_id"], relationship["from_node_id"],
                        relationship["to_node_id"], relationship["relationship_type"],
                        relationship["grants_access"],
                    ),
                    ("tenant_id", "relationship_id"),
                )
        self.conn.execute("SELECT set_config('bri.tenant_id', '', true)")

    def test_tenant_context_limits_reads_and_writes_to_one_fixture_tenant(self) -> None:
        first, second = FIXTURE["tenants"]
        self._tenant_context(first["tenant_id"])
        visible = self.conn.execute("SELECT tenant_id FROM bri.tenants ORDER BY tenant_id").fetchall()
        self.assertEqual(visible, [(first["tenant_id"],)])
        node_count = self.conn.execute("SELECT count(*) FROM bri.org_nodes").fetchone()[0]
        self.assertEqual(node_count, len(first["org_nodes"]))
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            with self.conn.transaction():
                self.conn.execute(
                    "INSERT INTO bri.tenants (tenant_id, display_name, sector) VALUES (%s, %s, %s)",
                    (f"tenant-synth-denied-write", second["display_name"], second["sector"]),
                )

    def test_missing_tenant_context_denies_reads_and_writes(self) -> None:
        self.assertEqual(self.conn.execute("SELECT count(*) FROM bri.tenants").fetchone()[0], 0)
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            with self.conn.transaction():
                self.conn.execute(
                    "INSERT INTO bri.tenants (tenant_id, display_name, sector) VALUES ('test-no-context', 'synthetic', 'test')"
                )

    def test_composite_foreign_key_rejects_cross_tenant_parent_reference(self) -> None:
        first, second = FIXTURE["tenants"]
        self._tenant_context(first["tenant_id"])
        foreign_parent = second["org_nodes"][0]["node_id"]
        with self.assertRaises(psycopg.errors.ForeignKeyViolation):
            with self.conn.transaction():
                self.conn.execute(
                    "INSERT INTO bri.org_nodes (tenant_id, node_id, node_type, display_name, parent_node_id) VALUES (%s, 'test-cross-parent', 'team', 'Synthetic test', %s)",
                    (first["tenant_id"], foreign_parent),
                )

    def test_application_role_cannot_bypass_rls_or_own_tenant_tables(self) -> None:
        row = self.conn.execute(
            "SELECT r.rolsuper, r.rolbypassrls, r.rolcreatedb, r.rolcreaterole, "
            "r.rolinherit, r.rolcanlogin, r.rolconnlimit, pg_has_role(current_user, c.relowner, 'MEMBER'), "
            "EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid) "
            "FROM pg_roles r CROSS JOIN pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE r.rolname=current_user AND n.nspname='bri' AND c.relname='tenants'"
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row, (False, False, False, False, False, True, 10, False, False))
        member_of_roles = self.conn.execute(
            "SELECT EXISTS (SELECT 1 FROM pg_auth_members m "
            "JOIN pg_roles r ON r.oid=m.member WHERE r.rolname=current_user)"
        ).fetchone()[0]
        grants = self.conn.execute(
            "SELECT member.rolname, grantor.rolname, m.admin_option, m.inherit_option, m.set_option "
            "FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid "
            "JOIN pg_roles member ON member.oid=m.member "
            "JOIN pg_roles grantor ON grantor.oid=m.grantor "
            "WHERE r.rolname=current_user ORDER BY member.rolname"
        ).fetchall()
        validate_role_memberships(member_of_roles=member_of_roles, grants=grants)
        self.assertFalse(self.conn.execute("SELECT has_schema_privilege(current_user, 'bri', 'CREATE')").fetchone()[0])
        self.assertFalse(self.conn.execute("SELECT has_table_privilege(current_user, 'bri.tenants', 'TRUNCATE')").fetchone()[0])

    def test_migration_role_is_login_enabled_without_escalation_attributes(self) -> None:
        row = self.conn.execute(
            "SELECT rolcanlogin, rolsuper, rolbypassrls, rolcreatedb, rolcreaterole, rolinherit, rolconnlimit, "
            "EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member=pg_roles.oid) "
            "FROM pg_roles WHERE rolname='bri_migrator'"
        ).fetchone()
        self.assertEqual(row, (True, False, False, False, False, False, 2, False))
        member_of_roles = self.conn.execute(
            "SELECT EXISTS (SELECT 1 FROM pg_auth_members m "
            "JOIN pg_roles r ON r.oid=m.member WHERE r.rolname='bri_migrator')"
        ).fetchone()[0]
        grants = self.conn.execute(
            "SELECT member.rolname, grantor.rolname, m.admin_option, m.inherit_option, m.set_option "
            "FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid "
            "JOIN pg_roles member ON member.oid=m.member "
            "JOIN pg_roles grantor ON grantor.oid=m.grantor "
            "WHERE r.rolname='bri_migrator' ORDER BY member.rolname"
        ).fetchall()
        validate_role_memberships(member_of_roles=member_of_roles, grants=grants)

    def test_application_role_has_no_access_to_other_application_schemas_or_objects(self) -> None:
        schemas = self.conn.execute(
            "SELECT n.nspname FROM pg_namespace n "
            "WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema' "
            "AND n.nspname NOT IN ('bri', 'public') "
            "AND has_schema_privilege(current_user, n.oid, 'USAGE') ORDER BY n.nspname"
        ).fetchall()
        self.assertEqual(schemas, [])
        relations = self.conn.execute(
            "SELECT n.nspname, c.relname FROM pg_class c "
            "JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema' "
            "AND n.nspname <> 'bri' AND has_schema_privilege(current_user,n.oid,'USAGE') "
            "AND c.relkind IN ('r','v','m','f') "
            "AND (has_table_privilege(current_user,c.oid,'SELECT') "
            "OR has_table_privilege(current_user,c.oid,'INSERT') "
            "OR has_table_privilege(current_user,c.oid,'UPDATE') "
            "OR has_table_privilege(current_user,c.oid,'DELETE') "
            "OR has_table_privilege(current_user,c.oid,'TRUNCATE')) ORDER BY n.nspname,c.relname"
        ).fetchall()
        self.assertEqual(relations, [])
        sequences = self.conn.execute(
            "SELECT n.nspname, c.relname FROM pg_class c "
            "JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema' "
            "AND n.nspname <> 'bri' AND has_schema_privilege(current_user,n.oid,'USAGE') "
            "AND c.relkind='S' AND (has_sequence_privilege(current_user,c.oid,'USAGE') "
            "OR has_sequence_privilege(current_user,c.oid,'SELECT') "
            "OR has_sequence_privilege(current_user,c.oid,'UPDATE')) ORDER BY n.nspname,c.relname"
        ).fetchall()
        self.assertEqual(sequences, [])
        functions = self.conn.execute(
            "SELECT n.nspname, p.proname FROM pg_proc p "
            "JOIN pg_namespace n ON n.oid=p.pronamespace "
            "WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema' "
            "AND n.nspname <> 'bri' AND has_schema_privilege(current_user,n.oid,'USAGE') "
            "AND has_function_privilege(current_user,p.oid,'EXECUTE') "
            "ORDER BY n.nspname,p.proname"
        ).fetchall()
        self.assertEqual(functions, [])

    def test_knowledge_tables_allow_only_select_and_insert_for_bri_app(self) -> None:
        expected = {
            "source_records",
            "source_versions",
            "source_extractions",
            "knowledge_proposals",
            "validation_decisions",
            "validated_knowledge",
        }
        rows = self.conn.execute(
            "SELECT c.relname, has_table_privilege(current_user, c.oid, 'SELECT'), "
            "has_table_privilege(current_user, c.oid, 'INSERT'), "
            "has_table_privilege(current_user, c.oid, 'UPDATE'), "
            "has_table_privilege(current_user, c.oid, 'DELETE') "
            "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname='bri' AND c.relname = ANY(%s) ORDER BY c.relname",
            (list(expected),),
        ).fetchall()
        self.assertEqual({row[0] for row in rows}, expected)
        self.assertTrue(all(row[1:] == (True, True, False, False) for row in rows))

    def test_knowledge_relations_enforce_tenant_scope_and_version_provenance(self) -> None:
        import hashlib

        first, second = FIXTURE["tenants"]
        tenant_id = first["tenant_id"]
        source_id = "test-source-noordlicht"
        version_id = "test-source-version-noordlicht-v1"
        extraction_id = "test-extraction-noordlicht-v1"
        proposal_id = "test-proposal-noordlicht"
        rejected_id = "test-proposal-noordlicht-rejected"
        reviewer_id = "user-noordlicht-reviewer"
        proposer_id = "user-noordlicht-proposer"
        scope_id = "org-noordlicht-policy-team"
        content = "A synthetic test policy requires seven years."
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        self._tenant_context(tenant_id)
        with self.assertRaises(psycopg.errors.ForeignKeyViolation):
            with self.conn.transaction():
                self.conn.execute(
                    "INSERT INTO bri.source_records "
                    "(tenant_id, source_id, scope_node_id, title, source_kind, created_by) "
                    "VALUES (%s, 'test-cross-tenant-source', %s, 'Synthetic cross-tenant attempt', 'synthetic_text', %s)",
                    (tenant_id, "org-zilvermeer-culture-team", proposer_id),
                )
        self.conn.execute(
            "INSERT INTO bri.source_records "
            "(tenant_id, source_id, scope_node_id, title, source_kind, created_by) "
            "VALUES (%s, %s, %s, %s, 'synthetic_text', %s)",
            (tenant_id, source_id, scope_id, "Synthetic test source", proposer_id),
        )
        self.conn.execute(
            "INSERT INTO bri.source_versions "
            "(tenant_id, source_id, source_version_id, version_label, content_sha256, source_location, created_by) "
            "VALUES (%s, %s, %s, 'v1', %s, 'fixture://synthetic/test/v1#page=1', %s)",
            (tenant_id, source_id, version_id, content_hash, proposer_id),
        )
        other_tenant_id = second["tenant_id"]
        other_source_id = "test-source-zilvermeer"
        other_version_id = "test-source-version-zilvermeer-v1"
        other_content = "A synthetic Zilvermeer test source."
        other_hash = hashlib.sha256(other_content.encode("utf-8")).hexdigest()
        other_scope_id = "org-zilvermeer-culture-team"
        self._tenant_context(other_tenant_id)
        self.conn.execute(
            "INSERT INTO bri.source_records "
            "(tenant_id, source_id, scope_node_id, title, source_kind, created_by) "
            "VALUES (%s, %s, %s, 'Synthetic cross-tenant source', 'synthetic_text', %s)",
            (other_tenant_id, other_source_id, other_scope_id, "user-zilvermeer-proposer"),
        )
        self.conn.execute(
            "INSERT INTO bri.source_versions "
            "(tenant_id, source_id, source_version_id, version_label, content_sha256, source_location, created_by) "
            "VALUES (%s, %s, %s, 'v1', %s, 'fixture://synthetic/zilvermeer/test/v1', %s)",
            (other_tenant_id, other_source_id, other_version_id, other_hash, "user-zilvermeer-proposer"),
        )
        self._tenant_context(tenant_id)
        with self.assertRaises(psycopg.errors.ForeignKeyViolation):
            with self.conn.transaction():
                self.conn.execute(
                    "INSERT INTO bri.source_extractions "
                    "(tenant_id, extraction_id, source_id, source_version_id, scope_node_id, content, "
                    "content_sha256, source_location, extractor_name, extractor_version, created_by) "
                    "VALUES (%s, 'test-cross-tenant-extraction', %s, %s, %s, %s, %s, "
                    "'fixture://synthetic/zilvermeer/test/v1', 'test', '1', %s)",
                    (tenant_id, other_source_id, other_version_id, other_scope_id, other_content, other_hash, proposer_id),
                )
        for bad_hash, bad_location in (
            ("0" * 64, "fixture://synthetic/test/v1#page=1"),
            (content_hash, "fixture://synthetic/test/v1#page=2"),
        ):
            with self.assertRaises(psycopg.errors.ForeignKeyViolation):
                with self.conn.transaction():
                    self.conn.execute(
                        "INSERT INTO bri.source_extractions "
                        "(tenant_id, extraction_id, source_id, source_version_id, scope_node_id, content, "
                        "content_sha256, source_location, extractor_name, extractor_version, created_by) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'test', '1', %s)",
                        (
                            tenant_id,
                            "test-extraction-provenance-mismatch",
                            source_id,
                            version_id,
                            scope_id,
                            content,
                            bad_hash,
                            bad_location,
                            proposer_id,
                        ),
                    )
        self.conn.execute(
            "INSERT INTO bri.source_extractions "
            "(tenant_id, extraction_id, source_id, source_version_id, scope_node_id, content, "
            "content_sha256, source_location, extractor_name, extractor_version, created_by) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, 'fixture://synthetic/test/v1#page=1', 'test', '1', %s)",
            (tenant_id, extraction_id, source_id, version_id, scope_id, content, content_hash, proposer_id),
        )
        for current_proposal in (proposal_id, rejected_id):
            self.conn.execute(
                "INSERT INTO bri.knowledge_proposals "
                "(tenant_id, proposal_id, extraction_id, scope_node_id, proposed_by) VALUES (%s, %s, %s, %s, %s)",
                (tenant_id, current_proposal, extraction_id, scope_id, proposer_id),
            )
        approved_decision = "test-decision-approved"
        rejected_decision = "test-decision-rejected"
        self.conn.execute(
            "INSERT INTO bri.validation_decisions "
            "(tenant_id, decision_id, proposal_id, reviewer_id, decision) VALUES (%s, %s, %s, %s, 'approved')",
            (tenant_id, approved_decision, proposal_id, reviewer_id),
        )
        self.conn.execute(
            "INSERT INTO bri.validated_knowledge (tenant_id, proposal_id, decision_id) VALUES (%s, %s, %s)",
            (tenant_id, proposal_id, approved_decision),
        )
        self.conn.execute(
            "INSERT INTO bri.validation_decisions "
            "(tenant_id, decision_id, proposal_id, reviewer_id, decision) VALUES (%s, %s, %s, %s, 'rejected')",
            (tenant_id, rejected_decision, rejected_id, reviewer_id),
        )
        with self.assertRaises(psycopg.errors.ForeignKeyViolation):
            with self.conn.transaction():
                self.conn.execute(
                    "INSERT INTO bri.validated_knowledge (tenant_id, proposal_id, decision_id) VALUES (%s, %s, %s)",
                    (tenant_id, rejected_id, rejected_decision),
                )

        approved = self.conn.execute(
            "SELECT p.proposal_id, x.content, x.source_location, sv.source_version_id "
            "FROM bri.validated_knowledge v "
            "JOIN bri.knowledge_proposals p ON p.tenant_id=v.tenant_id AND p.proposal_id=v.proposal_id "
            "JOIN bri.source_extractions x ON x.tenant_id=p.tenant_id AND x.extraction_id=p.extraction_id "
            "JOIN bri.source_versions sv ON sv.tenant_id=x.tenant_id AND sv.source_id=x.source_id "
            "AND sv.source_version_id=x.source_version_id "
            "WHERE v.tenant_id=%s AND v.proposal_id=%s",
            (tenant_id, proposal_id),
        ).fetchall()
        self.assertEqual(approved, [(proposal_id, content, "fixture://synthetic/test/v1#page=1", version_id)])

        self._tenant_context(second["tenant_id"])
        self.assertEqual(
            self.conn.execute("SELECT count(*) FROM bri.source_records WHERE source_id=%s", (source_id,)).fetchone()[0],
            0,
        )
        self.conn.execute("SELECT set_config('bri.tenant_id', '', true)")
        self.assertEqual(self.conn.execute("SELECT count(*) FROM bri.knowledge_proposals").fetchone()[0], 0)

    def test_every_tenant_table_enables_and_forces_rls(self) -> None:
        rows = self.conn.execute(
            "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity, pg_get_userbyid(c.relowner) "
            "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname='bri' AND c.relkind='r' AND c.relname <> 'schema_migrations' "
            "ORDER BY c.relname"
        ).fetchall()
        expected_tables = {
            "tenants",
            "org_nodes",
            "org_relationships",
            "app_roles",
            "role_permissions",
            "synthetic_principals",
            "role_assignments",
            "source_records",
            "source_versions",
            "source_extractions",
            "knowledge_proposals",
            "validation_decisions",
            "validated_knowledge",
        }
        self.assertEqual({row[0] for row in rows}, expected_tables)
        self.assertEqual(len(rows), len(expected_tables))
        for _, enabled, forced, owner in rows:
            self.assertTrue(enabled)
            self.assertTrue(forced)
            self.assertEqual(owner, "bri_migrator")


if __name__ == "__main__":
    unittest.main()
