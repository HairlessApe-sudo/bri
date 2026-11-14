import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from bri.access.policy import AccessGrant, Principal
from bri.prompts.management import (
    InMemoryPromptRepository,
    PromptAuthorizationError,
    PromptLayer,
    PromptManager,
    PromptNotApprovedError,
    PromptNotFoundError,
    PromptValidationError,
    PromptVersionConflict,
)

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)


def grant(tenant: str, action: str, scope: str | None = None) -> AccessGrant:
    return AccessGrant(tenant, action, scope or tenant)


class PromptManagementTests(unittest.TestCase):
    def setUp(self):
        self.repository = InMemoryPromptRepository()
        self.manager = PromptManager(self.repository, clock=lambda: NOW)
        self.platform_admin = Principal(
            "brs-admin", frozenset(),
            (grant("brs-platform", "prompt:platform:manage", "platform-prompt"),),
        )
        self.tenant_admin = Principal(
            "admin-a", frozenset({"client-a"}),
            (grant("client-a", "prompt:client:read"),
             grant("client-a", "prompt:client:manage"),
             grant("client-a", "prompt:platform:read")),
        )
        self.tenant_b_admin = Principal(
            "admin-b", frozenset({"client-b"}),
            (grant("client-b", "prompt:client:read"), grant("client-b", "prompt:client:manage")),
        )
        self.user = Principal("user-a", frozenset({"client-a"}), (grant("client-a", "historical_case:read"),))
        self.superuser = Principal("superuser-a", frozenset({"client-a"}), (grant("client-a", "document:read"),))
        self.superadmin = Principal(
            "platform-superadmin", frozenset({"client-a", "client-b"}),
            (grant("brs-platform", "prompt:platform:manage", "platform-prompt"),
             grant("client-a", "platform:prompt:tenant:manage"),
             grant("client-b", "platform:prompt:tenant:manage")),
        )

    def seed_active_prompts(self):
        platform = self.manager.create_platform_version(
            self.platform_admin, "Platform rules: preserve Privacy Shield boundaries.",
            "Initial platform version", expected_latest_version=0,
        )
        self.manager.approve_platform_version(self.platform_admin, platform.version)
        self.manager.activate_platform_version(self.platform_admin, platform.version, expected_active_version=0)
        client = self.manager.create_client_version(
            self.tenant_admin, "client-a", "Organisation style: concise and formal.",
            "Initial client version", expected_latest_version=0,
        )
        self.manager.approve_client_version(self.tenant_admin, "client-a", client.version)
        self.manager.activate_client_version(self.tenant_admin, "client-a", client.version, expected_active_version=0)
        return platform, client

    def test_superadmin_creates_immutable_platform_prompt_version(self):
        version = self.manager.create_platform_version(
            self.platform_admin, "Use synthetic instructions.", "Initial platform prompt", expected_latest_version=0
        )
        self.assertEqual(version.version, 1)
        self.assertEqual(version.author_id, "brs-admin")
        self.assertEqual(version.created_at, NOW)
        self.assertEqual(version.previous_version_ref, None)
        self.assertEqual(len(version.content_hash), 64)
        self.assertEqual(self.repository.versions(PromptLayer.PLATFORM, None), (version,))
        with self.assertRaises((AttributeError, TypeError)):
            version.version = 9

    def test_client_admin_creates_and_versions_only_their_tenant_prompt(self):
        first = self.manager.create_client_version(self.tenant_admin, "client-a", "First client prompt", "Initial", expected_latest_version=0)
        second = self.manager.create_client_version(self.tenant_admin, "client-a", "Second client prompt", "Update", expected_latest_version=1)
        self.assertEqual([item.version for item in self.manager.client_history(self.tenant_admin, "client-a")], [1, 2])
        self.assertEqual(second.previous_version_ref, first.version_id)
        self.assertEqual(self.repository.versions(PromptLayer.CLIENT, "client-b"), ())

    def test_user_superuser_and_client_admin_cannot_modify_platform_prompt(self):
        for principal in (self.user, self.superuser, self.tenant_admin):
            with self.subTest(subject=principal.subject_id), self.assertRaises(PromptAuthorizationError):
                self.manager.create_platform_version(principal, "forbidden", "No permission", expected_latest_version=0)

    def test_superadmin_needs_explicit_tenant_scope_to_manage_client_prompt(self):
        created = self.manager.create_client_version(self.superadmin, "client-a", "Scoped admin prompt", "Administer tenant", expected_latest_version=0)
        self.assertEqual(created.tenant_id, "client-a")
        with self.assertRaises(PromptAuthorizationError):
            self.manager.create_client_version(self.superadmin, "client-c", "No scope", "Denied", expected_latest_version=0)

    def test_tenant_isolation_blocks_cross_tenant_reads_and_writes(self):
        self.manager.create_client_version(self.tenant_admin, "client-a", "Private tenant A content", "Initial", expected_latest_version=0)
        with self.assertRaises(PromptAuthorizationError):
            self.manager.client_history(self.tenant_admin, "client-b")
        with self.assertRaises(PromptAuthorizationError):
            self.manager.create_client_version(self.tenant_admin, "client-b", "Cross tenant", "Denied", expected_latest_version=0)
        with self.assertRaises(PromptAuthorizationError):
            self.manager.client_history(self.tenant_b_admin, "client-a")

    def test_active_platform_prompt_read_requires_explicit_tenant_policy_grant(self):
        platform, _ = self.seed_active_prompts()
        self.assertEqual(self.manager.current_platform(self.tenant_admin, tenant_id="client-a"), platform)
        with self.assertRaises(PromptAuthorizationError):
            self.manager.platform_history(self.tenant_admin)
        with self.assertRaises(PromptAuthorizationError):
            self.manager.current_platform(self.tenant_b_admin, tenant_id="client-b")

    def test_assembler_keeps_trust_layers_order_and_both_version_provenance(self):
        platform, client = self.seed_active_prompts()
        assembled = self.manager.assemble(self.tenant_admin, "client-a")
        self.assertEqual(tuple(section.layer for section in assembled.sections), (PromptLayer.PLATFORM, PromptLayer.CLIENT))
        self.assertEqual(tuple(section.trust_level for section in assembled.sections), ("trusted_platform", "untrusted_tenant_instruction"))
        self.assertEqual(assembled.sections[0].content, platform.content)
        self.assertEqual(assembled.sections[1].content, client.content)
        self.assertEqual(assembled.provenance.platform_version_id, platform.version_id)
        self.assertEqual(assembled.provenance.client_version_id, client.version_id)
        self.assertEqual(assembled.provenance.platform_content_hash, platform.content_hash)
        self.assertEqual(assembled.provenance.client_content_hash, client.content_hash)
        self.assertEqual(self.manager.assemble(self.tenant_admin, "client-a"), assembled)

    def test_versions_require_approval_before_activation_and_record_status_events(self):
        created = self.manager.create_platform_version(self.platform_admin, "platform prompt", "Initial", expected_latest_version=0)
        with self.assertRaises(PromptNotApprovedError):
            self.manager.activate_platform_version(self.platform_admin, created.version, expected_active_version=0)
        self.manager.approve_platform_version(self.platform_admin, created.version)
        self.manager.activate_platform_version(self.platform_admin, created.version, expected_active_version=0)
        revised = self.manager.create_platform_version(self.platform_admin, "revised platform prompt", "Updated", expected_latest_version=1)
        self.manager.approve_platform_version(self.platform_admin, revised.version)
        self.manager.activate_platform_version(self.platform_admin, revised.version, expected_active_version=1)
        self.assertEqual(self.manager.current_platform(self.platform_admin), revised)
        self.assertEqual(
            [event.status for event in self.manager.audit_events(self.platform_admin, PromptLayer.PLATFORM)],
            ["draft", "approved", "active", "draft", "approved", "inactive", "active"],
        )

    def test_restore_creates_new_version_and_does_not_rewrite_history(self):
        first = self.manager.create_platform_version(self.platform_admin, "first content", "Initial", expected_latest_version=0)
        second = self.manager.create_platform_version(self.platform_admin, "second content", "Changed", expected_latest_version=1)
        restored = self.manager.restore_platform_version(self.platform_admin, first.version, expected_latest_version=2)
        history = self.manager.platform_history(self.platform_admin)
        self.assertEqual([item.version for item in history], [1, 2, 3])
        self.assertEqual(history[0], first)
        self.assertEqual(history[1], second)
        self.assertEqual(restored.content, first.content)
        self.assertEqual(restored.restored_from_version_id, first.version_id)
        self.assertEqual(restored.previous_version_ref, second.version_id)
        self.assertEqual(restored.version, 3)

    def test_compare_returns_requested_immutable_snapshots(self):
        first = self.manager.create_client_version(self.tenant_admin, "client-a", "old synthetic wording", "Initial", expected_latest_version=0)
        second = self.manager.create_client_version(self.tenant_admin, "client-a", "new synthetic wording", "Revision", expected_latest_version=1)
        compared = self.manager.compare_client_versions(self.tenant_admin, "client-a", 1, 2)
        self.assertEqual(compared, (first, second))
        self.assertEqual(compared[0].content, "old synthetic wording")
        with self.assertRaises(PromptAuthorizationError):
            self.manager.compare_client_versions(self.tenant_b_admin, "client-a", 1, 2)

    def test_compare_and_swap_rejects_stale_concurrent_version_writes(self):
        barrier = threading.Barrier(2)
        def create(content):
            barrier.wait()
            try:
                return self.manager.create_client_version(
                    self.tenant_admin, "client-a", content, "Concurrent change", expected_latest_version=0
                )
            except PromptVersionConflict as error:
                return error
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(create, ("synthetic prompt one", "synthetic prompt two")))
        self.assertEqual(sum(not isinstance(item, Exception) for item in outcomes), 1)
        self.assertEqual(sum(isinstance(item, PromptVersionConflict) for item in outcomes), 1)
        self.assertEqual(len(self.repository.versions(PromptLayer.CLIENT, "client-a")), 1)

    def test_activation_compare_and_swap_rejects_stale_state(self):
        version = self.manager.create_client_version(self.tenant_admin, "client-a", "client prompt", "Initial", expected_latest_version=0)
        self.manager.approve_client_version(self.tenant_admin, "client-a", version.version)
        with self.assertRaises(PromptVersionConflict):
            self.manager.activate_client_version(self.tenant_admin, "client-a", version.version, expected_active_version=1)

    def test_invalid_tenant_prompt_and_credential_material_are_rejected(self):
        for tenant_id, content in (("", "valid"), ("client-a", ""), ("client-a", "\x00"), ("client-a", "bad\x0bcontrol"), ("client-a", "api_key=synthetic-secret-value-123"), ("client-a", "Authorization: Bearer synthetic-token-value"), ("client-a", "x" * 32_001)):
            with self.subTest(tenant_id=tenant_id, content_length=len(content)), self.assertRaises(PromptValidationError):
                self.manager.create_client_version(self.tenant_admin, tenant_id, content, "Test", expected_latest_version=0)
        with self.assertRaises(PromptValidationError):
            self.manager.create_client_version(self.tenant_admin, None, "valid", "Test", expected_latest_version=0)  # type: ignore[arg-type]
        with self.assertRaises(PromptValidationError):
            self.manager.create_client_version(self.tenant_admin, "client-a", "valid", "Test", expected_latest_version=True)  # type: ignore[arg-type]
        with self.assertRaises(PromptValidationError):
            self.manager.compare_client_versions(self.tenant_admin, "client-a", True, 1)  # type: ignore[arg-type]

    def test_missing_versions_and_unapproved_assembly_fail_closed(self):
        with self.assertRaises(PromptNotFoundError):
            self.manager.current_platform(self.platform_admin)
        with self.assertRaises(PromptNotFoundError):
            self.manager.compare_platform_versions(self.platform_admin, 1, 2)
        with self.assertRaises(PromptNotFoundError):
            self.manager.assemble(self.tenant_admin, "client-a")

    def test_audit_contains_version_metadata_not_prompt_content(self):
        secret_marker = "synthetic-confidential-instruction-8f2a"
        self.manager.create_client_version(self.tenant_admin, "client-a", secret_marker, "Synthetic test content", expected_latest_version=0)
        events = self.manager.audit_events(self.tenant_admin, PromptLayer.CLIENT, "client-a")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].action, "created")
        self.assertEqual(events[0].status, "draft")
        self.assertEqual(len(events[0].content_hash), 64)
        self.assertNotIn(secret_marker, repr(events))


if __name__ == "__main__":
    unittest.main()
