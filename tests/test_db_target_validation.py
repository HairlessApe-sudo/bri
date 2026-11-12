"""Fail-closed Supabase project endpoint parsing tests."""
from __future__ import annotations

import unittest

from scripts.db.bootstrap_roles import project_ref
from scripts.db.migrate import ref_from
from test_database_rls import _project_ref

REF = "bwqdyibvuecgthtatrtv"
VALID_POOLER = f"postgres.{REF}:p%40ss@aws-1-eu-west-1.pooler.supabase.com:5432/postgres"


class SupabaseTargetValidationTests(unittest.TestCase):
    def test_accepts_approved_pooler_host_and_project_username(self) -> None:
        url = "postgresql://" + VALID_POOLER
        self.assertEqual(project_ref(url)[0], REF)
        self.assertEqual(ref_from(url), REF)
        self.assertEqual(_project_ref(url), REF)

    def test_rejects_lookalike_pooler_host_with_matching_username(self) -> None:
        url = f"postgresql://postgres.{REF}:pw@attacker.pooler.supabase.com:5432/postgres"
        self.assertIsNone(project_ref(url)[0])
        self.assertIsNone(ref_from(url))
        self.assertIsNone(_project_ref(url))

    def test_rejects_pooler_host_with_unexpected_region(self) -> None:
        url = f"postgresql://postgres.{REF}:pw@aws-1-us-east-1.pooler.supabase.com:5432/postgres"
        self.assertIsNone(project_ref(url)[0])
        self.assertIsNone(ref_from(url))
        self.assertIsNone(_project_ref(url))

    def test_rejects_valid_pooler_hostname_on_wrong_port(self) -> None:
        url = f"postgresql://postgres.{REF}:pw@aws-1-eu-west-1.pooler.supabase.com:6543/postgres"
        self.assertIsNone(project_ref(url)[0])
        self.assertIsNone(ref_from(url))
        self.assertIsNone(_project_ref(url))

    def test_accepts_supabase_api_url_project_host(self) -> None:
        url = f"https://{REF}.supabase.co"
        self.assertEqual(project_ref(url)[0], REF)
        self.assertEqual(ref_from(url), REF)
        self.assertEqual(_project_ref(url), REF)

    def test_accepts_exact_direct_database_host(self) -> None:
        url = f"postgresql://postgres:pw@db.{REF}.supabase.co:5432/postgres"
        self.assertEqual(project_ref(url)[0], REF)
        self.assertEqual(ref_from(url), REF)
        self.assertEqual(_project_ref(url), REF)

    def test_rejects_direct_host_on_wrong_port(self) -> None:
        url = f"postgresql://postgres:pw@db.{REF}.supabase.co:6543/postgres"
        self.assertIsNone(project_ref(url)[0])
        self.assertIsNone(ref_from(url))
        self.assertIsNone(_project_ref(url))


if __name__ == "__main__":
    unittest.main()
