"""Unit tests for migration checksum enforcement."""
from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from scripts.db.migrate import (
    LEGACY_MIGRATION_CHECKSUMS,
    ROOT,
    file_checksum,
    validate_checksum,
    validate_ledger_checksum_state,
    validate_legacy_migration_files,
)


class MigrationChecksumTests(unittest.TestCase):
    def test_accepts_a_matching_stored_checksum(self) -> None:
        self.assertTrue(validate_checksum("a" * 64, "a" * 64, version="0001_tenant_foundation", allow_baseline=False))

    def test_rejects_a_changed_applied_migration(self) -> None:
        with self.assertRaises(ValueError):
            validate_checksum("a" * 64, "b" * 64, version="0001_tenant_foundation", allow_baseline=False)

    def test_rejects_missing_checksum_after_baseline(self) -> None:
        with self.assertRaises(ValueError):
            validate_checksum(None, "a" * 64, version="0001_tenant_foundation", allow_baseline=False)

    def test_allows_one_time_legacy_baseline(self) -> None:
        expected = {
            "0001_tenant_foundation": "63c6db848986b4dfd1a4c91c6005667b929a9b1d39ad648ea734cb55d3e81a1b",
            "0002_immediate_parent_fk": "f57d9b41a21665394e9c79add79ecbdc32d74d4eb556840cb86a149b33e638ca",
        }
        self.assertEqual(LEGACY_MIGRATION_CHECKSUMS, expected)
        for version, digest in expected.items():
            with self.subTest(version=version):
                self.assertFalse(validate_checksum(None, digest, version=version, allow_baseline=True))

    def test_rejects_modified_legacy_migration_during_checksum_baseline(self) -> None:
        with self.assertRaises(ValueError):
            validate_checksum(
                None,
                "a" * 64,
                version="0001_tenant_foundation",
                allow_baseline=True,
            )

    def test_rejects_unknown_legacy_migration_during_checksum_baseline(self) -> None:
        with self.assertRaises(ValueError):
            validate_checksum(
                None,
                "a" * 64,
                version="0099_untrusted_migration",
                allow_baseline=True,
            )

    def test_rejects_checksum_marker_without_checksum_column(self) -> None:
        with self.assertRaises(ValueError):
            validate_ledger_checksum_state(
                ledger_exists=True, checksums_enabled=False, marker_exists=True
            )

    def test_allows_legacy_ledger_before_checksum_migration(self) -> None:
        validate_ledger_checksum_state(
            ledger_exists=True, checksums_enabled=False, marker_exists=False
        )

    def test_current_legacy_files_match_the_trusted_baseline(self) -> None:
        paths = [ROOT / "db/migrations" / f"{version}.sql" for version in LEGACY_MIGRATION_CHECKSUMS]
        validate_legacy_migration_files(paths)

    def test_rejects_modified_legacy_file_before_migration_execution(self) -> None:
        with TemporaryDirectory() as directory:
            altered = Path(directory) / "0001_tenant_foundation.sql"
            altered.write_text("SELECT 1;", encoding="utf-8")
            unchanged = ROOT / "db/migrations/0002_immediate_parent_fk.sql"
            with self.assertRaises(ValueError):
                validate_legacy_migration_files([altered, unchanged])

    def test_file_checksum_is_stable_across_windows_and_unix_newlines(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "migration.sql"
            path.write_bytes(b"SELECT 1;\r\nSELECT 2;\r\n")
            windows_digest = file_checksum(path)
            path.write_bytes(b"SELECT 1;\nSELECT 2;\n")
            unix_digest = file_checksum(path)
        self.assertEqual(windows_digest, unix_digest)


if __name__ == "__main__":
    unittest.main()
