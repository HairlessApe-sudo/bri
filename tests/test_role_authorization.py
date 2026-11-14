from __future__ import annotations

import unittest

from bri.access.policy import AccessGrant, Principal, Resource, is_authorized


USER_ACTIONS = frozenset({
    "historical_case:read",
    "document:read",
    "ai_question:ask",
})
SUPERUSER_ACTIONS = USER_ACTIONS | frozenset(
    f"{resource}:{verb}"
    for resource in ("historical_case", "document")
    for verb in ("create", "read", "update", "delete")
)
ADMIN_ACTIONS = SUPERUSER_ACTIONS | frozenset(
    f"{resource}:{verb}"
    for resource in ("standard_user", "ai_gateway_config", "approved_website")
    for verb in ("create", "read", "update", "delete")
)


def principal_with(tenant_id: str, scope_id: str, actions: frozenset[str]) -> Principal:
    return Principal(
        subject_id="synthetic-principal",
        tenant_ids=frozenset({tenant_id}),
        grants=tuple(AccessGrant(tenant_id, action, scope_id) for action in sorted(actions)),
    )


class ClientRoleAuthorizationTests(unittest.TestCase):
    def test_user_can_read_historical_content_and_ask_ai_but_cannot_mutate(self) -> None:
        principal = principal_with("tenant-a", "unit-a", USER_ACTIONS)
        for action in USER_ACTIONS:
            with self.subTest(action=action):
                self.assertTrue(is_authorized(principal, action, Resource("tenant-a", "unit-a")))
        for action in ("historical_case:create", "document:update", "standard_user:create"):
            with self.subTest(action=action):
                self.assertFalse(is_authorized(principal, action, Resource("tenant-a", "unit-a")))

    def test_superuser_includes_user_capabilities_and_scoped_case_document_crud(self) -> None:
        principal = principal_with("tenant-a", "unit-a", SUPERUSER_ACTIONS)
        self.assertTrue(USER_ACTIONS <= SUPERUSER_ACTIONS)
        for action in SUPERUSER_ACTIONS:
            with self.subTest(action=action):
                self.assertTrue(is_authorized(principal, action, Resource("tenant-a", "unit-a")))
        self.assertFalse(is_authorized(principal, "document:delete", Resource("tenant-b", "unit-a")))
        self.assertFalse(is_authorized(principal, "document:delete", Resource("tenant-a", "unit-b")))

    def test_admin_includes_superuser_capabilities_without_platform_admin_grants(self) -> None:
        principal = principal_with("tenant-a", "unit-a", ADMIN_ACTIONS)
        self.assertTrue(SUPERUSER_ACTIONS <= ADMIN_ACTIONS)
        for action in ADMIN_ACTIONS:
            with self.subTest(action=action):
                self.assertTrue(is_authorized(principal, action, Resource("tenant-a", "unit-a")))
        for platform_action in (
            "platform:client_admin:create",
            "platform:client_admin:promote",
            "platform:client_admin:manage",
        ):
            with self.subTest(action=platform_action):
                self.assertFalse(is_authorized(principal, platform_action, Resource("tenant-a", "unit-a")))
        self.assertFalse(is_authorized(principal, "document:delete", Resource("tenant-a", "unit-b")))

    def test_superadmin_can_hold_explicit_scoped_grants_for_multiple_organisations(self) -> None:
        actions = ADMIN_ACTIONS | frozenset({
            "platform:tenant:manage",
            "platform:client_admin:create",
            "platform:client_admin:promote",
            "platform:client_admin:manage",
        })
        tenant_scopes = {"tenant-a": "unit-a", "tenant-b": "unit-b"}
        principal = Principal(
            subject_id="employee-superadmin",
            tenant_ids=frozenset(tenant_scopes),
            grants=tuple(
                AccessGrant(tenant_id, action, scope_id)
                for tenant_id, scope_id in tenant_scopes.items()
                for action in sorted(actions)
            ),
        )
        self.assertTrue(is_authorized(principal, "document:delete", Resource("tenant-a", "unit-a")))
        self.assertTrue(is_authorized(principal, "document:delete", Resource("tenant-b", "unit-b")))
        self.assertTrue(is_authorized(principal, "platform:client_admin:manage", Resource("tenant-b", "unit-b")))
        self.assertFalse(is_authorized(principal, "document:delete", Resource("tenant-b", "unit-a")))
        self.assertFalse(is_authorized(principal, "document:delete", Resource("tenant-c", "unit-c")))

    def test_role_labels_do_not_bypass_explicit_action_tenant_and_scope_grants(self) -> None:
        # These capability sets model role_permissions rows; is_authorized remains the enforcement point.
        principal = principal_with("tenant-a", "unit-a", ADMIN_ACTIONS)
        self.assertFalse(is_authorized(principal, "standard_user:delete", Resource("tenant-b", "unit-a")))
        self.assertFalse(is_authorized(principal, "platform:client_admin:manage", Resource("tenant-a", "unit-a")))
        self.assertFalse(is_authorized(principal, "standard_user:delete", Resource("tenant-a", None)))


if __name__ == "__main__":
    unittest.main()
