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
        for tenant in FIXTURE["tenants"]:
            tenant_id = tenant["tenant_id"]
            self._tenant_context(tenant_id)
            self.conn.execute(
                "INSERT INTO bri.tenants (tenant_id, display_name, sector) VALUES (%s, %s, %s)",
                (tenant_id, tenant["display_name"], tenant["sector"]),
            )
            for node in tenant["org_nodes"]:
                self.conn.execute(
                    "INSERT INTO bri.org_nodes (tenant_id, node_id, node_type, display_name, parent_node_id) VALUES (%s, %s, %s, %s, %s)",
                    (tenant_id, node["node_id"], node["node_type"], node["display_name"], node["parent_id"]),
                )
            for role in tenant["roles"]:
                self.conn.execute(
                    "INSERT INTO bri.app_roles (tenant_id, role_id, display_name) VALUES (%s, %s, %s)",
                    (tenant_id, role["role_id"], role["display_name"]),
                )
                for permission in role["permissions"]:
                    self.conn.execute(
                        "INSERT INTO bri.role_permissions (tenant_id, role_id, permission) VALUES (%s, %s, %s)",
                        (tenant_id, role["role_id"], permission),
                    )
            for user in tenant["users"]:
                self.conn.execute(
                    "INSERT INTO bri.synthetic_principals (tenant_id, principal_id, display_name) VALUES (%s, %s, %s)",
                    (tenant_id, user["user_id"], user["display_name"]),
                )
                for assignment in user["role_assignments"]:
                    self.conn.execute(
                        "INSERT INTO bri.role_assignments (tenant_id, principal_id, role_id, scope_node_id) VALUES (%s, %s, %s, %s)",
                        (tenant_id, user["user_id"], assignment["role_id"], assignment["scope_node_id"]),
                    )
            for relationship in tenant["relationships"]:
                self.conn.execute(
                    "INSERT INTO bri.org_relationships (tenant_id, relationship_id, from_node_id, to_node_id, relationship_type, grants_access) VALUES (%s, %s, %s, %s, %s, %s)",
                    (tenant_id, relationship["relationship_id"], relationship["from_node_id"], relationship["to_node_id"], relationship["relationship_type"], relationship["grants_access"]),
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

    def test_every_tenant_table_enables_and_forces_rls(self) -> None:
        rows = self.conn.execute(
            "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity, pg_get_userbyid(c.relowner) "
            "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
            "WHERE n.nspname='bri' AND c.relkind='r' AND c.relname <> 'schema_migrations' "
            "ORDER BY c.relname"
        ).fetchall()
        self.assertEqual(len(rows), 7)
        for _, enabled, forced, owner in rows:
            self.assertTrue(enabled)
            self.assertTrue(forced)
            self.assertEqual(owner, "bri_migrator")


if __name__ == "__main__":
    unittest.main()
