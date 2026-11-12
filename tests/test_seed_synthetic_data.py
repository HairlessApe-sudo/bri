import unittest

from scripts.db.seed_synthetic_data import SeedConflict, build_parser, insert_or_verify


class FakeResult:
    def __init__(self, row):
        self.row = row

    def fetchone(self):
        return self.row


class FakeConnection:
    def __init__(self, inserted_row=None, existing_row=None):
        self.inserted_row = inserted_row
        self.existing_row = existing_row
        self.statements = []

    def execute(self, statement, parameters=()):
        self.statements.append(statement)
        if statement.startswith("INSERT"):
            return FakeResult(self.inserted_row)
        return FakeResult(self.existing_row)


class SyntheticSeedTests(unittest.TestCase):
    def test_seed_requires_explicit_apply_flag(self):
        parser = build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args([])
        args = parser.parse_args(["--apply"])
        self.assertTrue(args.apply)

    def test_existing_matching_row_is_verified_without_overwrite(self):
        connection = FakeConnection(
            inserted_row=None,
            existing_row=("tenant-synth-noordlicht", "source-synth-noordlicht-retention", "Synthetic title"),
        )
        inserted = insert_or_verify(
            connection,
            table="bri.source_records",
            columns=("tenant_id", "source_id", "title"),
            values=("tenant-synth-noordlicht", "source-synth-noordlicht-retention", "Synthetic title"),
            key_columns=("tenant_id", "source_id"),
        )
        self.assertFalse(inserted)
        self.assertIn("ON CONFLICT DO NOTHING", connection.statements[0])
        self.assertNotIn("UPDATE", " ".join(connection.statements).upper())
        self.assertNotIn("DELETE", " ".join(connection.statements).upper())

    def test_existing_conflicting_row_fails_closed(self):
        connection = FakeConnection(
            inserted_row=None,
            existing_row=("tenant-synth-noordlicht", "source-synth-noordlicht-retention", "Different title"),
        )
        with self.assertRaises(SeedConflict):
            insert_or_verify(
                connection,
                table="bri.source_records",
                columns=("tenant_id", "source_id", "title"),
                values=("tenant-synth-noordlicht", "source-synth-noordlicht-retention", "Synthetic title"),
                key_columns=("tenant_id", "source_id"),
            )


if __name__ == "__main__":
    unittest.main()
