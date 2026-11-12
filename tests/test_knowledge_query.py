from dataclasses import replace
import unittest

from bri.knowledge.query import KnowledgeItem, answer_question
from bri.access.policy import AccessGrant, Principal


class KnowledgeAnswerTests(unittest.TestCase):
    def setUp(self):
        self.principal = Principal(
            "employee-1",
            frozenset({"tenant-city"}),
            (AccessGrant("tenant-city", "knowledge:read", "node-policy-team"),),
        )
        self.approved = KnowledgeItem(
            record_id="knowledge-1",
            tenant_id="tenant-city",
            scope_id="node-policy-team",
            validation_state="approved",
            title="Records Retention Policy",
            source_version="v1",
            source_location="page 2, section 4",
            content="Employee files must be retained for seven years.",
        )

    def test_returns_supported_text_with_source_version_and_location(self):
        result = answer_question(
            self.principal,
            "How many years must employee files be retained?",
            [self.approved],
        )

        self.assertEqual(result.status, "supported")
        self.assertEqual(result.answer, "Employee files must be retained for seven years.")
        self.assertEqual(len(result.citations), 1)
        self.assertEqual(result.citations[0].source_version, "v1")
        self.assertEqual(result.citations[0].source_location, "page 2, section 4")

    def test_citations_preserve_source_version_and_extraction_provenance(self):
        item = replace(
            self.approved,
            source_id="source-1",
            source_version_id="source-version-1-v1",
            extraction_id="extract-1-v1",
            content_sha256="a" * 64,
            extractor_name="synthetic-fixture",
            extractor_version="1",
        )
        result = answer_question(
            self.principal,
            "How many years must employee files be retained?",
            [item],
        )
        citation = result.citations[0]
        self.assertEqual(citation.source_id, "source-1")
        self.assertEqual(citation.source_version_id, "source-version-1-v1")
        self.assertEqual(citation.extraction_id, "extract-1-v1")
        self.assertEqual(citation.content_sha256, "a" * 64)
        self.assertEqual(citation.extractor_name, "synthetic-fixture")
        self.assertEqual(citation.extractor_version, "1")

    def test_excludes_unapproved_knowledge_before_matching(self):
        proposed = replace(self.approved, validation_state="proposed")

        result = answer_question(
            self.principal,
            "How many years must employee files be retained?",
            [proposed],
        )

        self.assertEqual(result.status, "insufficient")
        self.assertIsNone(result.answer)
        self.assertEqual(result.citations, ())

    def test_excludes_other_tenants_before_matching(self):
        other_tenant = KnowledgeItem(
            record_id="secret-1",
            tenant_id="tenant-other",
            scope_id="node-policy-team",
            validation_state="approved",
            title="Restricted policy title",
            source_version="v1",
            source_location="page 1",
            content="Employee files must be retained for seven years.",
        )

        result = answer_question(
            self.principal,
            "How many years must employee files be retained?",
            [other_tenant],
        )

        self.assertEqual(result.status, "insufficient")
        self.assertEqual(result.citations, ())

    def test_abstains_when_no_evidence_matches(self):
        result = answer_question(self.principal, "What is the council's budget?", [self.approved])

        self.assertEqual(result.status, "insufficient")
        self.assertIsNone(result.answer)

    def test_abstains_and_cites_both_sources_when_top_evidence_conflicts(self):
        contradictory = KnowledgeItem(
            record_id="knowledge-2",
            tenant_id="tenant-city",
            scope_id="node-policy-team",
            validation_state="approved",
            title="Updated Retention Policy",
            source_version="v2",
            source_location="page 3, section 5",
            content="Employee files must be retained for ten years.",
        )

        result = answer_question(
            self.principal,
            "How many years must employee files be retained?",
            [self.approved, contradictory],
        )

        self.assertEqual(result.status, "conflicting")
        self.assertIsNone(result.answer)
        self.assertEqual({citation.source_version for citation in result.citations}, {"v1", "v2"})


if __name__ == "__main__":
    unittest.main()
