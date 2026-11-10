import unittest

from bri.access.policy import AccessGrant, Principal, Resource, is_authorized


class AuthorizationPolicyTests(unittest.TestCase):
    def test_allows_matching_tenant_action_and_exact_scope_grant(self):
        principal = Principal(
            subject_id="user-1",
            tenant_ids=frozenset({"tenant-a"}),
            grants=(AccessGrant("tenant-a", "knowledge:read", "node-team-1"),),
        )
        resource = Resource("tenant-a", "node-team-1")

        self.assertTrue(is_authorized(principal, "knowledge:read", resource))

    def test_denies_cross_tenant_access_even_when_scope_identifier_matches(self):
        principal = Principal(
            subject_id="user-1",
            tenant_ids=frozenset({"tenant-a"}),
            grants=(AccessGrant("tenant-a", "knowledge:read", "node-1"),),
        )
        resource = Resource("tenant-b", "node-1")

        self.assertFalse(is_authorized(principal, "knowledge:read", resource))

    def test_denies_when_action_grant_is_missing(self):
        principal = Principal("user-1", frozenset({"tenant-a"}), ())

        self.assertFalse(
            is_authorized(principal, "knowledge:read", Resource("tenant-a", "node-1"))
        )

    def test_parent_scope_grant_does_not_inherit_to_child(self):
        principal = Principal(
            "user-1",
            frozenset({"tenant-a"}),
            (AccessGrant("tenant-a", "knowledge:read", "department-1"),),
        )

        self.assertFalse(
            is_authorized(principal, "knowledge:read", Resource("tenant-a", "team-1"))
        )

    def test_denies_grant_for_tenant_without_active_membership(self):
        principal = Principal(
            "user-1",
            frozenset(),
            (AccessGrant("tenant-a", "knowledge:read", "node-1"),),
        )

        self.assertFalse(
            is_authorized(principal, "knowledge:read", Resource("tenant-a", "node-1"))
        )

    def test_denies_when_resource_scope_is_missing(self):
        principal = Principal(
            "user-1",
            frozenset({"tenant-a"}),
            (AccessGrant("tenant-a", "knowledge:read", "node-1"),),
        )

        self.assertFalse(
            is_authorized(principal, "knowledge:read", Resource("tenant-a", None))
        )


if __name__ == "__main__":
    unittest.main()
