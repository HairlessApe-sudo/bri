import unittest

from bri.privacy.models import (
    Detection,
    DetectionCategory,
    InputType,
    PolicyAction,
    ProcessingPurpose,
    ProcessingDestination,
)
from bri.privacy.policy import (
    PlatformPolicy,
    PolicyEngine,
    PolicyRule,
    TenantPolicy,
)


class PolicyEngineTests(unittest.TestCase):
    def setUp(self):
        self.platform = PlatformPolicy(
            policy_id="brs-baseline",
            version="1",
            rules=(
                PolicyRule(
                    rule_id="platform-bsn-mask",
                    category=DetectionCategory.BSN,
                    action=PolicyAction.MASK,
                    destinations=(ProcessingDestination.AI_PROVIDER,),
                ),
            ),
        )
        self.engine = PolicyEngine(self.platform)
        self.context = {
            "tenant_id": "tenant-a",
            "input_type": InputType.DOCUMENT,
            "purpose": ProcessingPurpose.DOCUMENT_EXTRACTION,
            "destination": ProcessingDestination.AI_PROVIDER,
        }
        self.finding = Detection(DetectionCategory.BSN, 10, 19)

    def test_platform_mask_restriction_overrides_tenant_allow(self):
        policy = TenantPolicy(
            tenant_id="tenant-a",
            policy_id="tenant-policy",
            version="7",
            rules=(
                PolicyRule(
                    rule_id="tenant-allow-bsn",
                    category=DetectionCategory.BSN,
                    action=PolicyAction.ALLOW,
                ),
            ),
        )

        result = self.engine.evaluate(policy, (self.finding,), **self.context)

        self.assertEqual(result.decision, PolicyAction.MASK)
        self.assertEqual(result.actions[0][1], PolicyAction.MASK)
        self.assertIn("platform-bsn-mask", result.matched_rule_ids)

    def test_tenant_block_restriction_is_applied(self):
        policy = TenantPolicy(
            tenant_id="tenant-a",
            policy_id="tenant-policy",
            version="1",
            rules=(
                PolicyRule("block-email", DetectionCategory.EMAIL, PolicyAction.BLOCK),
            ),
        )
        email = Detection(DetectionCategory.EMAIL, 0, 19)

        result = self.engine.evaluate(policy, (email,), **self.context)

        self.assertEqual(result.decision, PolicyAction.BLOCK)

    def test_clean_content_can_be_allowed(self):
        policy = TenantPolicy("tenant-a", "tenant-policy", "1", ())

        result = self.engine.evaluate(policy, (), **self.context)

        self.assertEqual(result.decision, PolicyAction.ALLOW)

    def test_missing_or_wrong_tenant_policy_fails_closed(self):
        wrong_tenant = TenantPolicy("tenant-b", "other-policy", "1", ())

        result = self.engine.evaluate(None, (), **self.context)
        wrong_result = self.engine.evaluate(wrong_tenant, (), **self.context)

        self.assertEqual(result.decision, PolicyAction.BLOCK)
        self.assertEqual(result.failure_reason, "policy_unavailable")
        self.assertEqual(wrong_result.decision, PolicyAction.BLOCK)
        self.assertEqual(wrong_result.failure_reason, "invalid_policy")

    def test_global_block_applies_even_when_no_signature_was_found(self):
        policy = TenantPolicy(
            "tenant-a",
            "tenant-policy",
            "1",
            (
                PolicyRule(
                    "deny-ai-destination",
                    None,
                    PolicyAction.BLOCK,
                    destinations=(ProcessingDestination.AI_PROVIDER,),
                ),
            ),
        )

        result = self.engine.evaluate(policy, (), **self.context)

        self.assertEqual(result.decision, PolicyAction.BLOCK)

    def test_platform_global_mask_cannot_be_weakened_by_tenant_allow(self):
        platform = PlatformPolicy(
            "platform-global",
            "1",
            (PolicyRule("platform-mask-all", None, PolicyAction.MASK),),
        )
        engine = PolicyEngine(platform)
        policy = TenantPolicy(
            "tenant-a",
            "tenant-policy",
            "1",
            (PolicyRule("tenant-allow-all", None, PolicyAction.ALLOW),),
        )

        result = engine.evaluate(policy, (), **self.context)

        self.assertEqual(result.decision, PolicyAction.MASK)
        self.assertTrue(result.mask_all)

    def test_platform_policy_cannot_declare_allow(self):
        with self.assertRaisesRegex(ValueError, "invalid_platform_policy"):
            PlatformPolicy(
                "unsafe-platform",
                "1",
                (PolicyRule("allow-everything", None, PolicyAction.ALLOW),),
            )

    def test_invalid_policy_rule_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "invalid_policy"):
            TenantPolicy(
                tenant_id="tenant-a",
                policy_id="tenant-policy",
                version="1",
                rules=(PolicyRule("bad id!", DetectionCategory.EMAIL, PolicyAction.ALLOW),),
            )


if __name__ == "__main__":
    unittest.main()
