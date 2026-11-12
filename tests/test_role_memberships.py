"""Fail-closed validation for dedicated-role grants and legacy ledger entries."""
from __future__ import annotations

import unittest

from scripts.db.migrate import validate_legacy_ledger_versions, validate_role_memberships

TRUSTED = {"0001_tenant_foundation", "0002_immediate_parent_fk"}
SUPABASE_POSTGRES_GRANT = ("postgres", "supabase_admin", True, False, False)


class DedicatedRoleMembershipTests(unittest.TestCase):
    def test_allows_no_memberships(self) -> None:
        validate_role_memberships(member_of_roles=False, grants=[])

    def test_allows_only_supabase_managed_noninheriting_postgres_membership(self) -> None:
        validate_role_memberships(member_of_roles=False, grants=[SUPABASE_POSTGRES_GRANT])

    def test_rejects_membership_in_another_role(self) -> None:
        with self.assertRaises(ValueError):
            validate_role_memberships(member_of_roles=True, grants=[])

    def test_rejects_grant_to_any_other_role(self) -> None:
        with self.assertRaises(ValueError):
            validate_role_memberships(
                member_of_roles=False,
                grants=[SUPABASE_POSTGRES_GRANT, ("other_role", "postgres", True, False, True)],
            )

    def test_rejects_settable_or_inheritable_supabase_admin_edge(self) -> None:
        with self.assertRaises(ValueError):
            validate_role_memberships(
                member_of_roles=False,
                grants=[("postgres", "supabase_admin", True, False, True)],
            )


class LegacyLedgerVersionTests(unittest.TestCase):
    def test_allows_partial_known_ledger_before_pending_migrations(self) -> None:
        validate_legacy_ledger_versions({"0001_tenant_foundation"}, require_complete=False)

    def test_rejects_unrecognized_or_future_ledger_version(self) -> None:
        with self.assertRaises(ValueError):
            validate_legacy_ledger_versions(TRUSTED | {"0004_unverified"}, require_complete=False)

    def test_requires_exact_legacy_versions_before_checksum_baseline(self) -> None:
        with self.assertRaises(ValueError):
            validate_legacy_ledger_versions({"0001_tenant_foundation"}, require_complete=True)
        validate_legacy_ledger_versions(TRUSTED, require_complete=True)


if __name__ == "__main__":
    unittest.main()
