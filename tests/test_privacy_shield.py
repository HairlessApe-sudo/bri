import unittest

from bri.privacy.detection import SignatureDetector
from bri.privacy.models import DetectionCategory


class SignatureDetectionTests(unittest.TestCase):
    def setUp(self):
        self.detector = SignatureDetector()

    def test_detects_only_bsns_that_pass_the_elfproef(self):
        valid = self.detector.detect("Referentie 111222333.")
        invalid = self.detector.detect("Referentie 111222334.")

        self.assertEqual([item.category for item in valid], [DetectionCategory.BSN])
        self.assertEqual(invalid, ())

    def test_accepts_eight_digit_bsn_and_separator_format(self):
        compact = self.detector.detect("BSN 10000021")
        separated = self.detector.detect("BSN 111-222-333")

        self.assertEqual([item.category for item in compact], [DetectionCategory.BSN])
        self.assertEqual([item.category for item in separated], [DetectionCategory.BSN])

    def test_detects_email_and_dutch_phone_without_storing_values(self):
        findings = self.detector.detect("Mail m.kuiper@example.invalid or call +31 6 00000000.")

        self.assertEqual(
            {item.category for item in findings},
            {DetectionCategory.EMAIL, DetectionCategory.PHONE},
        )
        self.assertTrue(all(not hasattr(item, "value") for item in findings))

    def test_detects_explicit_international_phone_numbers(self):
        findings = self.detector.detect("Bel testlijn +1 202-555-0100.")

        self.assertEqual([item.category for item in findings], [DetectionCategory.PHONE])

    def test_validates_dutch_iban_checksum_and_format(self):
        valid = self.detector.detect("IBAN NL69 TEST 0000 0000 01")
        invalid = self.detector.detect("IBAN NL69 TEST 0000 0000 02")

        self.assertEqual([item.category for item in valid], [DetectionCategory.IBAN])
        self.assertEqual(invalid, ())

    def test_validates_non_dutch_iban_using_registered_length_and_checksum(self):
        finding = self.detector.detect("SEPA test DE36 0000 0000 0000 0000 00")

        self.assertEqual([item.category for item in finding], [DetectionCategory.IBAN])

    def test_rejects_checksum_valid_iban_for_unsupported_country(self):
        unsupported = self.detector.detect("IBAN ZZ59 1234 5678 9012 3456")

        self.assertEqual(unsupported, ())

    def test_detects_bank_account_only_with_account_context(self):
        contextual = self.detector.detect("Rekeningnummer: 1234567890")
        ordinary = self.detector.detect("In het rapport staat 1234567890 als meetwaarde.")

        self.assertIn(DetectionCategory.BANK_ACCOUNT, {item.category for item in contextual})
        self.assertNotIn(DetectionCategory.BANK_ACCOUNT, {item.category for item in ordinary})

    def test_detects_postal_address_and_contextual_valid_date_of_birth(self):
        address = self.detector.detect("Stuur het naar Fictiefstraat 42, 9999 ZZ.")
        birth_date = self.detector.detect("geboortedatum: 29-02-2000")
        invalid_birth_date = self.detector.detect("geboortedatum: 29-02-2001")

        self.assertIn(DetectionCategory.POSTAL_ADDRESS, {item.category for item in address})
        self.assertIn(DetectionCategory.DATE_OF_BIRTH, {item.category for item in birth_date})
        self.assertNotIn(DetectionCategory.DATE_OF_BIRTH, {item.category for item in invalid_birth_date})

    def test_representative_false_positive_and_false_negative_cases_are_documented(self):
        incidental_number = self.detector.detect("Meetwaarde 1234567890 in kwartaal 2026.")
        unstructured_name = self.detector.detect("De fictieve inwoner Zoë woont in Utrecht.")

        self.assertEqual(incidental_number, ())
        self.assertEqual(unstructured_name, ())

    def test_supports_tenant_sensitive_terms_separately_from_signatures(self):
        detector = SignatureDetector(tenant_terms=("intern gebruik",))
        findings = detector.detect("Label: INTERN GEBRUIK.")

        self.assertEqual([item.category for item in findings], [DetectionCategory.TENANT_SENSITIVE])

    def test_supports_unicode_context_and_tenant_literal_signatures(self):
        from bri.privacy.models import TenantSignature

        detector = SignatureDetector(
            tenant_signatures=(TenantSignature("contract-tag", "zaakcode QX-123"),)
        )
        findings = detector.detect("Zoë noemt zaakcode QX-123 in Café Ångström.")

        self.assertIn(DetectionCategory.TENANT_SENSITIVE, {item.category for item in findings})
        self.assertTrue(all(0 <= item.start < item.end <= len("Zoë noemt zaakcode QX-123 in Café Ångström.") for item in findings))


if __name__ == "__main__":
    unittest.main()
