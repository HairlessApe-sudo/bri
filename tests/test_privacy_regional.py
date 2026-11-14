import unittest

from bri.access.policy import AccessGrant, Principal
from bri.privacy.models import DetectionCategory
from bri.privacy.regional import (
    InMemoryTenantSignatureStore,
    InMemoryShieldConfigurationStore,
    ManagedTenantSignature,
    PrivacyShieldConfig,
    PrivacyShieldConfigurationManager,
    RegionalSignatureDetector,
    RegionalSignatureRegistry,
    SignaturePackage,
    SignatureAuthorizationError,
    SignatureValidationError,
    TenantSignatureManager,
)


class RegionalSignatureTests(unittest.TestCase):
    def test_primary_jurisdiction_activates_only_its_regional_package(self):
        nl = RegionalSignatureDetector(PrivacyShieldConfig("tenant-a", "NL"))
        au = RegionalSignatureDetector(PrivacyShieldConfig("tenant-b", "AU"))

        nl_bsn = nl.detect("Fictieve BSN 111222333")
        au_bsn = au.detect("Fictieve BSN 111222333")
        au_tfn = au.detect("TFN 123 456 782")
        nl_tfn = nl.detect("TFN 123 456 782")

        self.assertEqual([item.category for item in nl_bsn], [DetectionCategory.BSN])
        self.assertNotIn(DetectionCategory.BSN, {item.category for item in au_bsn})
        self.assertEqual([item.category for item in au_tfn], [DetectionCategory.TAX_FILE_NUMBER])
        self.assertNotIn(DetectionCategory.TAX_FILE_NUMBER, {item.category for item in nl_tfn})

    def test_global_detection_remains_active_with_region_and_extra_region_is_explicit(self):
        registry = RegionalSignatureRegistry.with_defaults()
        nl = RegionalSignatureDetector(PrivacyShieldConfig("tenant-a", "NL"), registry)
        nl_au = RegionalSignatureDetector(
            PrivacyShieldConfig("tenant-a", "NL", additional_regions=("AU",)), registry
        )
        text = "mail demo@example.invalid; BSN 111222333; TFN 123 456 782"

        self.assertEqual(len([d for d in nl.detect(text) if d.category is DetectionCategory.EMAIL]), 1)
        self.assertNotIn(DetectionCategory.TAX_FILE_NUMBER, {d.category for d in nl.detect(text)})
        self.assertIn(DetectionCategory.TAX_FILE_NUMBER, {d.category for d in nl_au.detect(text)})

    def test_cross_package_dedup_keeps_distinct_overlapping_identifiers(self):
        detector = RegionalSignatureDetector(PrivacyShieldConfig("tenant-a", "NL"))
        findings = detector.detect("111222333@example.invalid")

        self.assertEqual(len(findings), 2)
        self.assertEqual({item.category for item in findings}, {DetectionCategory.BSN, DetectionCategory.EMAIL})

    def test_invalid_regional_package_fails_closed_and_invalid_tfn_is_not_detected(self):
        registry = RegionalSignatureRegistry((
            SignaturePackage("global", "1", None),
            SignaturePackage("australia", "1", "AU", available=False),
            SignaturePackage("netherlands", "1", "NL"),
        ))
        with self.assertRaisesRegex(RuntimeError, "required_signature_package_unavailable"):
            RegionalSignatureDetector(PrivacyShieldConfig("tenant-a", "AU"), registry)
        au = RegionalSignatureDetector(PrivacyShieldConfig("tenant-b", "AU"))
        self.assertEqual(au.detect("TFN 123 456 781"), ())

    def test_registry_retains_immutable_independent_package_and_engine_history(self):
        registry = RegionalSignatureRegistry(
            (
                SignaturePackage("global", "1", None),
                SignaturePackage("netherlands", "1", "NL"),
                SignaturePackage("australia", "1", "AU"),
                SignaturePackage("global", "2", None),
                SignaturePackage("netherlands", "3", "NL"),
            ),
            engine_version="2",
            engine_history=("1", "2"),
        )
        effective = registry.resolve(PrivacyShieldConfig("tenant-a", "NL"))

        self.assertEqual(effective.package_versions["global"], "2")
        self.assertEqual(effective.package_versions["netherlands"], "3")
        self.assertEqual(tuple(item.version for item in registry.package_history("global")), ("1", "2"))
        self.assertEqual(registry.engine_history, ("1", "2"))
        with self.assertRaises(AttributeError):
            getattr(effective.package_versions, "__setitem__")("global", "3")

    def test_registry_accepts_a_new_region_with_an_explicit_detector(self):
        from bri.privacy.models import Detection

        registry = RegionalSignatureRegistry(
            (
                SignaturePackage("global", "1", None),
                SignaturePackage("new-zealand", "1", "NZ"),
            ),
            jurisdiction_packages={"NZ": "new-zealand"},
            regional_detectors={
                "NZ": lambda text: (Detection(DetectionCategory.TENANT_SENSITIVE, 0, 3),)
                if text.startswith("NZ:") else ()
            },
        )
        detector = RegionalSignatureDetector(PrivacyShieldConfig("tenant-nz", "NZ"), registry)

        self.assertEqual(
            detector.detect("NZ: synthetic"),
            (Detection(DetectionCategory.TENANT_SENSITIVE, 0, 3),),
        )
        self.assertEqual(
            detector.effective_config.package_ids,
            ("global", "new-zealand"),
        )

    def test_effective_configuration_records_independent_package_versions(self):
        effective = RegionalSignatureRegistry.with_defaults().resolve(
            PrivacyShieldConfig("tenant-a", "AU")
        )

        self.assertEqual(effective.package_versions["global"], "1")
        self.assertEqual(effective.package_versions["australia"], "1")
        self.assertNotIn("netherlands", effective.package_versions)
        self.assertTrue(effective.configuration_version)


class TenantSignatureManagementTests(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryTenantSignatureStore()
        self.manager = TenantSignatureManager(self.store)
        self.admin = Principal(
            "admin-a", frozenset({"tenant-a"}),
            (AccessGrant("tenant-a", "privacy:signature:manage", "tenant-a"),
             AccessGrant("tenant-a", "privacy:configuration:manage", "tenant-a")),
        )

    def test_admin_crud_history_and_restore_append_new_immutable_revision(self):
        original = ManagedTenantSignature("case-tag", r"CASE-[0-9]{4}", is_regex=True)
        revision1 = self.manager.create(self.admin, "tenant-a", original)
        updated = ManagedTenantSignature("case-tag", r"CASE-[0-9]{5}", is_regex=True)
        revision2 = self.manager.update(self.admin, "tenant-a", "case-tag", updated)
        self.manager.deactivate(self.admin, "tenant-a", "case-tag")
        history_before_restore = self.manager.history(self.admin, "tenant-a")
        restored = self.manager.restore(self.admin, "tenant-a", revision1.version)

        self.assertEqual(revision1.version, 1)
        self.assertEqual(revision2.version, 2)
        self.assertEqual(history_before_restore[1].signatures[0].pattern, r"CASE-[0-9]{5}")
        test_hits = self.manager.test(self.admin, "tenant-a", updated, "synthetic CASE-12345")
        self.assertEqual(len(test_hits), 1)
        self.assertEqual([revision.version for revision in history_before_restore], [1, 2, 3])
        self.assertEqual(restored.version, 4)
        self.assertEqual(restored.signatures[0].pattern, r"CASE-[0-9]{4}")
        self.assertEqual([revision.version for revision in self.manager.history(self.admin, "tenant-a")], [1, 2, 3, 4])

    def test_user_superuser_and_wrong_tenant_cannot_change_signatures(self):
        for role, principal in (
            ("user", Principal("user-a", frozenset({"tenant-a"}), ())),
            ("superuser", Principal("superuser-a", frozenset({"tenant-a"}), ())),
            ("superadmin", Principal("brs-admin", frozenset({"tenant-a"}), (AccessGrant("tenant-a", "platform:admin", "tenant-a"),))),
            ("other-tenant-admin", Principal(
                "admin-b", frozenset({"tenant-b"}),
                (AccessGrant("tenant-b", "privacy:signature:manage", "tenant-b"),),
            )),
        ):
            with self.subTest(role=role), self.assertRaises(SignatureAuthorizationError):
                self.manager.create(principal, "tenant-a", ManagedTenantSignature("x", "alpha"))

    def test_rejects_invalid_and_unsafe_regex_but_accepts_bounded_pattern(self):
        for unsafe in (r"(a+)+$", r"a{1,}", r"a{1,2}b{1,2}"):
            with self.subTest(unsafe=unsafe), self.assertRaises(SignatureValidationError):
                ManagedTenantSignature("bad", unsafe, is_regex=True)
        with self.assertRaises(SignatureValidationError):
            ManagedTenantSignature("bad", r"[", is_regex=True)
        safe = ManagedTenantSignature("safe", r"CASE-[0-9]{4}", is_regex=True)

        self.assertTrue(safe.is_regex)
        with self.assertRaises(SignatureValidationError):
            ManagedTenantSignature("code", "CASE-[0-9]{4}", category=DetectionCategory.EMAIL)


    def test_authorized_region_configuration_is_versioned_and_restore_appends(self):
        store = InMemoryShieldConfigurationStore()
        manager = PrivacyShieldConfigurationManager(store)
        first = manager.configure(self.admin, "tenant-a", "NL")
        second = manager.configure(self.admin, "tenant-a", "NL", ("AU",))
        restored = manager.restore(self.admin, "tenant-a", first.version)
        inspection = manager.inspect(self.admin, "tenant-a", RegionalSignatureRegistry.with_defaults())

        self.assertIsNotNone(inspection)
        assert inspection is not None
        self.assertEqual(first.version, 1)
        self.assertEqual(second.config.additional_regions, ("AU",))
        self.assertEqual(restored.version, 3)
        self.assertEqual(restored.config.additional_regions, ())
        self.assertEqual(inspection.effective.package_ids, ("global", "netherlands"))
        self.assertIn(("netherlands", ("bsn", "phone", "postal_address", "date_of_birth")), inspection.capabilities)
        self.assertEqual([revision.version for revision in manager.history(self.admin, "tenant-a")], [1, 2, 3])

    def test_processing_attestation_binds_independent_signature_versions(self):
        from datetime import datetime, timedelta, timezone
        from bri.privacy.contracts import ShieldAttestor, TenantContextAuthority
        from bri.privacy.models import (
            InputType, ProcessingDestination, ProcessingPurpose, ProcessingRequest,
        )
        from bri.privacy.policy import MappingPolicyProvider, TenantPolicy
        from bri.privacy.regional import MappingSignatureConfigurationProvider
        from bri.privacy.service import InMemoryAuditSink, PrivacyShieldService

        now = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)
        authority = TenantContextAuthority(b"c" * 32, clock=lambda: now)
        attestor = ShieldAttestor(b"a" * 32, clock=lambda: now)
        context = authority.issue(
            "tenant-a", "principal-a", "scope-a", InputType.DOCUMENT,
            ProcessingPurpose.DOCUMENT_EXTRACTION, ProcessingDestination.AI_PROVIDER,
            now + timedelta(minutes=5),
        )
        request = ProcessingRequest(
            context, "scope-a", InputType.DOCUMENT, "synthetic TFN 123 456 782",
            ProcessingPurpose.DOCUMENT_EXTRACTION, ProcessingDestination.AI_PROVIDER,
        )
        versions = MappingSignatureConfigurationProvider(
            {"tenant-a": PrivacyShieldConfig("tenant-a", "AU")},
            RegionalSignatureRegistry.with_defaults(),
        )
        service = PrivacyShieldService(
            context_authority=authority,
            policy_provider=MappingPolicyProvider({"tenant-a": TenantPolicy("tenant-a", "policy", "1", ())}),
            audit_sink=InMemoryAuditSink(), attestor=attestor, clock=lambda: now,
            signature_configuration_provider=versions,
        )

        result = service.process(request)

        self.assertEqual(result.status.value, "approved")
        self.assertIsNotNone(result.signature_versions)
        self.assertIsNotNone(result.gateway_envelope)
        assert result.signature_versions is not None
        assert result.gateway_envelope is not None
        self.assertEqual(result.signature_versions.engine_version, "1")
        self.assertEqual(result.signature_versions.regional_package_versions, (("australia", "1"),))
        self.assertEqual(result.signature_versions.tenant_signature_version, "0")
        self.assertEqual(result.gateway_envelope.signature_versions, result.signature_versions)
        verified = attestor.verify(
            result.gateway_envelope, expected_tenant_id="tenant-a", expected_scope_id="scope-a",
            expected_input_type=InputType.DOCUMENT, expected_destination=ProcessingDestination.AI_PROVIDER,
            expected_purpose=ProcessingPurpose.DOCUMENT_EXTRACTION, now=now,
        )
        self.assertEqual(verified.signature_versions, result.signature_versions)

    def test_missing_regional_configuration_fails_closed_in_processing(self):
        from datetime import datetime, timedelta, timezone
        from bri.privacy.contracts import ShieldAttestor, TenantContextAuthority
        from bri.privacy.models import InputType, ProcessingDestination, ProcessingPurpose, ProcessingRequest
        from bri.privacy.policy import MappingPolicyProvider, TenantPolicy
        from bri.privacy.regional import MappingSignatureConfigurationProvider
        from bri.privacy.service import InMemoryAuditSink, PrivacyShieldService

        now = datetime(2026, 11, 14, 12, 0, tzinfo=timezone.utc)
        authority = TenantContextAuthority(b"c" * 32, clock=lambda: now)
        attestor = ShieldAttestor(b"a" * 32, clock=lambda: now)
        context = authority.issue("tenant-a", "principal-a", "scope-a", InputType.DOCUMENT,
            ProcessingPurpose.DOCUMENT_EXTRACTION, ProcessingDestination.BRI_INTERNAL,
            now + timedelta(minutes=5))
        request = ProcessingRequest(context, "scope-a", InputType.DOCUMENT, "synthetic",
            ProcessingPurpose.DOCUMENT_EXTRACTION, ProcessingDestination.BRI_INTERNAL)
        provider = MappingSignatureConfigurationProvider({}, RegionalSignatureRegistry.with_defaults())
        service = PrivacyShieldService(context_authority=authority,
            policy_provider=MappingPolicyProvider({"tenant-a": TenantPolicy("tenant-a", "policy", "1", ())}),
            audit_sink=InMemoryAuditSink(), attestor=attestor, clock=lambda: now,
            signature_configuration_provider=provider)

        result = service.process(request)

        self.assertEqual(result.status.value, "blocked")
        self.assertEqual(result.failure_reason, "detection_unavailable")
        self.assertIsNone(result.sanitised_content)


if __name__ == "__main__":
    unittest.main()
