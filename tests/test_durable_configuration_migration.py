"""Structural safeguards for durable configuration migration."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "db/migrations/0007_durable_configuration.sql"


class DurableConfigurationMigrationTests(unittest.TestCase):
    def test_migration_adds_forced_rls_append_only_configuration_tables(self):
        self.assertTrue(MIGRATION.is_file(), "durable configuration migration must exist")
        sql = MIGRATION.read_text(encoding="utf-8").lower()
        self.assertIn("create table bri.prompt_versions", sql)
        self.assertIn("create table bri.prompt_lifecycle_events", sql)
        self.assertIn("create table bri.signature_package_versions", sql)
        self.assertIn("create table bri.tenant_signature_revisions", sql)
        self.assertIn("create table bri.shield_config_revisions", sql)
        self.assertIn("force row level security", sql)
        self.assertIn("tenant_id = nullif(current_setting('bri.tenant_id'", sql)
        self.assertNotIn("bypassrls", sql)
        self.assertNotIn("grant all", sql)
        self.assertNotIn("insert into bri.schema_migrations", sql)
        self.assertNotIn("begin;", sql)
        self.assertNotIn("commit;", sql)

    def test_migration_keeps_audit_metadata_separate_from_content(self):
        self.assertTrue(MIGRATION.is_file(), "durable configuration migration must exist")
        sql = MIGRATION.read_text(encoding="utf-8").lower()
        audit = sql.split("create table bri.configuration_audit_events", 1)[1].split(";", 1)[0]
        self.assertNotIn("content text", audit)
        self.assertNotIn("pattern text", audit)
        self.assertIn("content_hash", audit)


if __name__ == "__main__":
    unittest.main()
