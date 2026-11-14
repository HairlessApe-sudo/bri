import logging
import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import cast

from bri.privacy.contracts import (
    ShieldAttestor,
    TenantContextAuthority,
    TenantContextVerifier,
    UnverifiedShieldResult,
)
from bri.privacy.models import (
    InputType,
    PolicyAction,
    ProcessingDestination,
    ProcessingPurpose,
    ProcessingRequest,
    ProcessingStatus,
    DetectionCategory,
    Detection,
    TenantContext,
)
from bri.privacy.policy import (
    DEFAULT_PLATFORM_POLICY,
    MappingPolicyProvider,
    PolicyRule,
    TenantPolicy,
)
from bri.privacy.service import InMemoryAuditSink, PrivacyShieldService
from bri.privacy.regional import (
    InMemoryTenantSignatureStore,
    ManagedTenantSignature,
    MappingSignatureConfigurationProvider,
    PrivacyShieldConfig,
    RegionalSignatureRegistry,
)


class PrivacyShieldServiceTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)
        self.authority = TenantContextAuthority(b"c" * 32, clock=lambda: self.now)
        self.attestor = ShieldAttestor(b"a" * 32, clock=lambda: self.now)
        self.policy = TenantPolicy("tenant-a", "tenant-policy", "3", ())
        self.audit = InMemoryAuditSink()
        self.signature_store = InMemoryTenantSignatureStore()
        self.signature_provider = MappingSignatureConfigurationProvider(
            {"tenant-a": PrivacyShieldConfig("tenant-a", "NL")},
            RegionalSignatureRegistry.with_defaults(), self.signature_store,
        )
        self.service = PrivacyShieldService(
            context_authority=self.authority,
            policy_provider=MappingPolicyProvider({"tenant-a": self.policy}),
            audit_sink=self.audit,
            attestor=self.attestor,
            signature_configuration_provider=self.signature_provider,
            clock=lambda: self.now,
            id_factory=lambda: "process-0001",
        )
        self.context = self.authority.issue(
            "tenant-a",
            "principal-1",
            "scope-document-1",
            InputType.DOCUMENT,
            ProcessingPurpose.DOCUMENT_EXTRACTION,
            ProcessingDestination.AI_PROVIDER,
            self.now + timedelta(minutes=10),
        )

    def request(
        self,
        text,
        *,
        input_type=InputType.DOCUMENT,
        purpose=None,
        destination=ProcessingDestination.AI_PROVIDER,
    ):
        if purpose is None:
            purpose = {
                InputType.DOCUMENT: ProcessingPurpose.DOCUMENT_EXTRACTION,
                InputType.HISTORICAL_CASE: ProcessingPurpose.HISTORICAL_CASE_ANALYSIS,
                InputType.RETRIEVED_CONTEXT: ProcessingPurpose.RETRIEVAL,
                InputType.USER_QUESTION: ProcessingPurpose.QUESTION_ANSWERING,
            }.get(input_type, ProcessingPurpose.DOCUMENT_EXTRACTION)
        context = self.authority.issue(
            "tenant-a",
            "principal-1",
            "scope-document-1",
            input_type,
            purpose,
            destination,
            self.now + timedelta(minutes=10),
        )
        return ProcessingRequest(
            tenant_context=context,
            resource_scope_id=context.scope_id,
            input_type=input_type,
            text=text,
            purpose=purpose,
            destination=destination,
        )

    def test_masks_bsn_and_returns_attested_sanitised_payload(self):
        result = self.service.process(self.request("BSN 111222333"))

        self.assertEqual(result.status, ProcessingStatus.APPROVED)
        self.assertEqual(result.decision, PolicyAction.MASK)
        self.assertEqual(result.sanitised_content, "BSN [BSN_REDACTED]")
        self.assertNotIn("111222333", repr(result))
        self.assertIsNotNone(result.gateway_envelope)
        assert result.gateway_envelope is not None
        self.assertEqual(result.gateway_envelope.decision, result.decision)
        verified = self.attestor.verify(
            result.gateway_envelope,
            expected_tenant_id="tenant-a",
            expected_scope_id="scope-document-1",
            expected_input_type=InputType.DOCUMENT,
            expected_destination=ProcessingDestination.AI_PROVIDER,
            expected_purpose=ProcessingPurpose.DOCUMENT_EXTRACTION,
            now=self.now,
        )
        self.assertEqual(verified.sanitised_content, result.sanitised_content)
        self.assertEqual(verified.resource_scope_id, "scope-document-1")
        self.assertEqual(verified.decision, result.decision)

    def test_blocks_when_tenant_policy_blocks_detected_email(self):
        self.service = PrivacyShieldService(
            context_authority=self.authority,
            policy_provider=MappingPolicyProvider(
                {
                    "tenant-a": TenantPolicy(
                        "tenant-a",
                        "tenant-policy",
                        "3",
                        (PolicyRule("block-email", DetectionCategory.EMAIL, PolicyAction.BLOCK),),
                    )
                }
            ),
            audit_sink=self.audit,
            attestor=self.attestor,
            signature_configuration_provider=self.signature_provider,
            clock=lambda: self.now,
            id_factory=lambda: "process-0002",
        )

        result = self.service.process(self.request("Contact m.kuiper@example.invalid"))

        self.assertEqual(result.status, ProcessingStatus.BLOCKED)
        self.assertEqual(result.decision, PolicyAction.BLOCK)
        self.assertIsNone(result.sanitised_content)
        self.assertIsNone(result.gateway_envelope)

    def test_missing_tenant_context_fails_closed_and_audits_only_safe_metadata(self):
        request = replace(self.request("BSN 111222333"), tenant_context=None)

        result = self.service.process(request)

        self.assertEqual(result.status, ProcessingStatus.BLOCKED)
        self.assertEqual(result.failure_reason, "missing_tenant_context")
        self.assertIsNone(result.sanitised_content)
        self.assertEqual(len(self.audit.entries), 1)
        self.assertNotIn("111222333", repr(self.audit.entries[0]))

    def test_wrong_tenant_policy_fails_closed_without_fallback(self):
        self.service = PrivacyShieldService(
            context_authority=self.authority,
            policy_provider=MappingPolicyProvider(
                {"tenant-a": TenantPolicy("tenant-b", "other", "1", ())}
            ),
            audit_sink=self.audit,
            attestor=self.attestor,
            signature_configuration_provider=self.signature_provider,
            clock=lambda: self.now,
            id_factory=lambda: "process-0003",
        )

        result = self.service.process(self.request("ordinary text"))

        self.assertEqual(result.status, ProcessingStatus.BLOCKED)
        self.assertEqual(result.failure_reason, "invalid_policy")
        self.assertIsNone(result.sanitised_content)

    def test_non_ai_destinations_return_no_gateway_attestation(self):
        for destination in (
            ProcessingDestination.BRI_INTERNAL,
            ProcessingDestination.HUMAN_REVIEW,
        ):
            with self.subTest(destination=destination):
                result = self.service.process(
                    self.request("ordinary text", destination=destination)
                )

                self.assertEqual(result.status, ProcessingStatus.APPROVED)
                self.assertIsNone(result.gateway_envelope)
                self.assertEqual(result.sanitised_content, "ordinary text")

    def test_gateway_contract_rejects_a_different_resource_scope(self):
        result = self.service.process(self.request("ordinary text"))
        assert result.gateway_envelope is not None

        with self.assertRaises(UnverifiedShieldResult):
            self.attestor.verify(
                result.gateway_envelope,
                expected_tenant_id="tenant-a",
                expected_scope_id="scope-other",
                expected_input_type=InputType.DOCUMENT,
                expected_destination=ProcessingDestination.AI_PROVIDER,
                expected_purpose=ProcessingPurpose.DOCUMENT_EXTRACTION,
                now=self.now,
            )

    def test_gateway_contract_rejects_a_different_input_type(self):
        result = self.service.process(self.request("ordinary text"))
        assert result.gateway_envelope is not None

        with self.assertRaises(UnverifiedShieldResult):
            self.attestor.verify(
                result.gateway_envelope,
                expected_tenant_id="tenant-a",
                expected_scope_id="scope-document-1",
                expected_input_type=InputType.USER_QUESTION,
                expected_destination=ProcessingDestination.AI_PROVIDER,
                expected_purpose=ProcessingPurpose.DOCUMENT_EXTRACTION,
                now=self.now,
            )

    def test_rejects_tampered_or_unverified_envelope(self):
        result = self.service.process(self.request("ordinary text"))
        forged = replace(result.gateway_envelope, sanitised_content="attacker supplied")

        with self.assertRaises(UnverifiedShieldResult):
            self.attestor.verify(
                forged,
                expected_tenant_id="tenant-a",
                expected_scope_id="scope-document-1",
                expected_input_type=InputType.DOCUMENT,
                expected_destination=ProcessingDestination.AI_PROVIDER,
                expected_purpose=ProcessingPurpose.DOCUMENT_EXTRACTION,
                now=self.now,
            )

    def test_processes_documents_cases_retrieval_and_questions(self):
        inputs = (
            (InputType.DOCUMENT, ProcessingPurpose.DOCUMENT_EXTRACTION),
            (InputType.HISTORICAL_CASE, ProcessingPurpose.HISTORICAL_CASE_ANALYSIS),
            (InputType.RETRIEVED_CONTEXT, ProcessingPurpose.RETRIEVAL),
            (InputType.USER_QUESTION, ProcessingPurpose.QUESTION_ANSWERING),
        )
        for input_type, purpose in inputs:
            with self.subTest(input_type=input_type):
                request = self.request(
                    "Dossier voor de fictieve organisatie.",
                    input_type=input_type,
                    purpose=purpose,
                )
                result = self.service.process(request)
                self.assertEqual(result.status, ProcessingStatus.APPROVED)
                self.assertEqual(result.decision, PolicyAction.ALLOW)
                self.assertEqual(result.sanitised_content, request.text)

    def test_masks_overlapping_identifiers_with_a_nonrevealing_marker(self):
        result = self.service.process(self.request("111222333@example.invalid"))

        self.assertEqual(result.decision, PolicyAction.MASK)
        self.assertEqual(result.sanitised_content, "[SENSITIVE_REDACTED]")
        self.assertEqual({item.category.value for item in result.detection_counts}, {"bsn", "email"})
        self.assertNotIn("111222333", result.sanitised_content)
        self.assertNotIn("example.invalid", result.sanitised_content)

    def test_masks_multiple_values_and_preserves_unicode_surrounding_text(self):
        content = "Café Zoë: mail m.kuiper@example.invalid; telefoon +31 6 00000000."
        result = self.service.process(self.request(content))

        self.assertEqual(result.decision, PolicyAction.MASK)
        self.assertIn("Café Zoë", result.sanitised_content)
        self.assertIn("[EMAIL_REDACTED]", result.sanitised_content)
        self.assertIn("[PHONE_REDACTED]", result.sanitised_content)
        self.assertNotIn("m.kuiper@example.invalid", result.sanitised_content)
        self.assertNotIn("+31 6 00000000", result.sanitised_content)

    def test_platform_floor_prevents_tenant_allow_from_exposing_bsn(self):
        self.service = PrivacyShieldService(
            context_authority=self.authority,
            policy_provider=MappingPolicyProvider(
                {
                    "tenant-a": TenantPolicy(
                        "tenant-a",
                        "tenant-policy",
                        "3",
                        (PolicyRule("allow-bsn", DetectionCategory.BSN, PolicyAction.ALLOW),),
                    )
                }
            ),
            audit_sink=self.audit,
            attestor=self.attestor,
            signature_configuration_provider=self.signature_provider,
            clock=lambda: self.now,
            id_factory=lambda: "process-allow-floor",
        )

        result = self.service.process(self.request("BSN 111222333"))

        self.assertEqual(result.decision, PolicyAction.MASK)
        self.assertEqual(result.sanitised_content, "BSN [BSN_REDACTED]")

    def test_uses_tenant_specific_literal_signature(self):
        self.signature_store.append(
            "tenant-a",
            (
                ManagedTenantSignature("project-tag", "project-omega-42"),
                ManagedTenantSignature("internal-term", "intern gebruik"),
            ),
        )
        policy = TenantPolicy(
            "tenant-a",
            "tenant-policy",
            "4",
            (),
        )
        self.service = PrivacyShieldService(
            context_authority=self.authority,
            policy_provider=MappingPolicyProvider({"tenant-a": policy}),
            audit_sink=self.audit,
            attestor=self.attestor,
            signature_configuration_provider=self.signature_provider,
            clock=lambda: self.now,
            id_factory=lambda: "process-tenant-signature",
        )

        result = self.service.process(
            self.request("Notitie: project-omega-42; INTERN GEBRUIK.")
        )

        self.assertEqual(
            result.sanitised_content,
            "Notitie: [TENANT_SENSITIVE_REDACTED]; [TENANT_SENSITIVE_REDACTED].",
        )
        self.assertNotIn("project-omega-42", repr(policy))
        self.assertNotIn("intern gebruik", repr(policy))

    def test_missing_signature_configuration_fails_closed(self):
        service = PrivacyShieldService(
            context_authority=self.authority,
            policy_provider=MappingPolicyProvider({"tenant-a": self.policy}),
            audit_sink=self.audit,
            attestor=self.attestor,
            clock=lambda: self.now,
        )

        result = service.process(self.request("synthetic text"))

        self.assertEqual(result.status, ProcessingStatus.BLOCKED)
        self.assertEqual(result.failure_reason, "signature_configuration_unavailable")
        self.assertIsNone(result.sanitised_content)
        self.assertIsNone(result.gateway_envelope)

    def test_missing_policy_never_falls_back_to_another_tenant(self):
        self.service = PrivacyShieldService(
            context_authority=self.authority,
            policy_provider=MappingPolicyProvider({}),
            audit_sink=self.audit,
            attestor=self.attestor,
            signature_configuration_provider=self.signature_provider,
            clock=lambda: self.now,
            id_factory=lambda: "process-no-policy",
        )

        result = self.service.process(self.request("ordinary text"))

        self.assertEqual(result.status, ProcessingStatus.BLOCKED)
        self.assertEqual(result.failure_reason, "policy_unavailable")
        self.assertIsNone(result.sanitised_content)
        self.assertIsNone(result.gateway_envelope)

    def test_rejects_resource_scope_not_bound_to_authorized_tenant_context(self):
        request = replace(self.request("ordinary text"), resource_scope_id="scope-other")

        result = self.service.process(request)

        self.assertEqual(result.status, ProcessingStatus.BLOCKED)
        self.assertEqual(result.failure_reason, "invalid_processing_context")
        self.assertIsNone(result.sanitised_content)

    def test_rejects_input_purpose_or_destination_not_bound_to_context(self):
        base = self.request("ordinary text")
        tampered_requests = (
            replace(base, input_type=InputType.HISTORICAL_CASE),
            replace(base, purpose=ProcessingPurpose.INTERNAL_REVIEW),
            replace(base, destination=ProcessingDestination.BRI_INTERNAL),
        )

        for request in tampered_requests:
            with self.subTest(request=request):
                result = self.service.process(request)

                self.assertEqual(result.status, ProcessingStatus.BLOCKED)
                self.assertEqual(result.failure_reason, "invalid_processing_context")
                self.assertIsNone(result.gateway_envelope)

    def test_context_verifier_must_return_literal_true(self):
        class TruthyContextVerifier:
            def verify(self, context: TenantContext, *, now: datetime) -> object:
                return "verified"

        self.service = PrivacyShieldService(
            context_authority=cast(TenantContextVerifier, TruthyContextVerifier()),
            policy_provider=MappingPolicyProvider({"tenant-a": self.policy}),
            audit_sink=self.audit,
            attestor=self.attestor,
            signature_configuration_provider=self.signature_provider,
            clock=lambda: self.now,
        )

        result = self.service.process(self.request("ordinary text"))

        self.assertEqual(result.status, ProcessingStatus.BLOCKED)
        self.assertEqual(result.failure_reason, "invalid_tenant_context")
        self.assertIsNone(result.gateway_envelope)

    def test_rejects_tampering_of_signed_context_fields(self):
        tampered_contexts = (
            replace(self.context, principal_id="principal-other"),
            replace(self.context, action="privacy:admin"),
            replace(self.context, scope_id="scope-other"),
            replace(self.context, input_type=InputType.HISTORICAL_CASE),
            replace(self.context, purpose=ProcessingPurpose.INTERNAL_REVIEW),
            replace(self.context, destination=ProcessingDestination.BRI_INTERNAL),
        )

        for context in tampered_contexts:
            request = replace(
                self.request("ordinary text"),
                tenant_context=context,
                resource_scope_id=context.scope_id,
                input_type=context.input_type,
                purpose=context.purpose,
                destination=context.destination,
            )
            with self.subTest(context=context):
                result = self.service.process(request)

                self.assertEqual(result.status, ProcessingStatus.BLOCKED)
                self.assertEqual(result.failure_reason, "invalid_tenant_context")
                self.assertIsNone(result.sanitised_content)

    def test_invalid_input_type_and_unverified_context_fail_closed(self):
        invalid_input = replace(self.request("BSN 111222333"), input_type="unsupported")
        forged_context = replace(self.context, tenant_id="tenant-other")
        forged_request = replace(self.request("BSN 111222333"), tenant_context=forged_context)

        invalid_result = self.service.process(invalid_input)
        forged_result = self.service.process(forged_request)

        self.assertEqual(invalid_result.failure_reason, "invalid_processing_context")
        self.assertEqual(forged_result.failure_reason, "invalid_tenant_context")
        self.assertIsNone(forged_result.audit_summary.tenant_id)
        self.assertIsNone(invalid_result.gateway_envelope)

    def test_processing_is_deterministic_for_the_same_context_and_policy(self):
        request = self.request("BSN 111222333 and m.kuiper@example.invalid")

        first = self.service.process(request)
        second = self.service.process(request)

        self.assertEqual(first, second)

    def test_audit_sink_failure_blocks_and_does_not_leak_exception_text(self):
        class FailingAuditSink:
            def record(self, summary):
                raise RuntimeError("m.kuiper@example.invalid")

        self.service = PrivacyShieldService(
            context_authority=self.authority,
            policy_provider=MappingPolicyProvider({"tenant-a": self.policy}),
            audit_sink=FailingAuditSink(),
            attestor=self.attestor,
            signature_configuration_provider=self.signature_provider,
            clock=lambda: self.now,
            id_factory=lambda: "process-audit-failure",
        )

        result = self.service.process(self.request("ordinary text"))

        self.assertEqual(result.status, ProcessingStatus.BLOCKED)
        self.assertEqual(result.failure_reason, "audit_unavailable")
        self.assertIsNone(result.sanitised_content)
        self.assertNotIn("m.kuiper@example.invalid", repr(result))

    def test_policy_provider_exception_fails_closed_without_exposing_error(self):
        class FailingPolicyProvider:
            def load(self, tenant_id):
                raise RuntimeError("m.kuiper@example.invalid")

        self.service = PrivacyShieldService(
            context_authority=self.authority,
            policy_provider=FailingPolicyProvider(),
            audit_sink=self.audit,
            attestor=self.attestor,
            signature_configuration_provider=self.signature_provider,
            clock=lambda: self.now,
        )

        result = self.service.process(self.request("ordinary text"))

        self.assertEqual(result.status, ProcessingStatus.BLOCKED)
        self.assertEqual(result.failure_reason, "policy_unavailable")
        self.assertIsNone(result.gateway_envelope)
        self.assertNotIn("m.kuiper@example.invalid", repr(result))

    def test_detector_exception_fails_closed_without_exposing_error(self):
        class FailingDetector:
            def detect(self, text: str) -> tuple[Detection, ...]:
                raise RuntimeError("m.kuiper@example.invalid")

        self.service = PrivacyShieldService(
            context_authority=self.authority,
            policy_provider=MappingPolicyProvider({"tenant-a": self.policy}),
            audit_sink=self.audit,
            attestor=self.attestor,
            signature_configuration_provider=self.signature_provider,
            detector_factory=lambda signatures, terms: FailingDetector(),
            clock=lambda: self.now,
        )

        result = self.service.process(self.request("ordinary text"))

        self.assertEqual(result.status, ProcessingStatus.BLOCKED)
        self.assertEqual(result.failure_reason, "detection_unavailable")
        self.assertIsNone(result.gateway_envelope)
        self.assertNotIn("m.kuiper@example.invalid", repr(result))

    def test_attestor_exception_fails_closed_without_exposing_error(self):
        class FailingAttestor(ShieldAttestor):
            def __init__(self):
                super().__init__(b"f" * 32)

            def issue(self, **kwargs):
                raise RuntimeError("m.kuiper@example.invalid")

        self.service = PrivacyShieldService(
            context_authority=self.authority,
            policy_provider=MappingPolicyProvider({"tenant-a": self.policy}),
            audit_sink=self.audit,
            attestor=FailingAttestor(),
            signature_configuration_provider=self.signature_provider,
            clock=lambda: self.now,
        )

        result = self.service.process(self.request("ordinary text"))

        self.assertEqual(result.status, ProcessingStatus.BLOCKED)
        self.assertEqual(result.failure_reason, "attestation_unavailable")
        self.assertIsNone(result.sanitised_content)
        self.assertNotIn("m.kuiper@example.invalid", repr(result))

    def test_expired_gateway_attestation_is_rejected(self):
        result = self.service.process(self.request("ordinary text"))
        assert result.gateway_envelope is not None

        with self.assertRaises(UnverifiedShieldResult):
            self.attestor.verify(
                result.gateway_envelope,
                expected_tenant_id="tenant-a",
                expected_scope_id="scope-document-1",
                expected_input_type=InputType.DOCUMENT,
                expected_destination=ProcessingDestination.AI_PROVIDER,
                expected_purpose=ProcessingPurpose.DOCUMENT_EXTRACTION,
                now=self.now + timedelta(minutes=3),
            )

    def test_no_raw_content_is_logged_or_retained_in_audit(self):
        secret = "m.kuiper@example.invalid"
        with self.assertNoLogs("bri.privacy", level="DEBUG"):
            result = self.service.process(self.request(f"Contact {secret}"))

        self.assertNotIn(secret, repr(result.audit_summary))
        self.assertNotIn(secret, repr(self.audit.entries))


if __name__ == "__main__":
    unittest.main()
