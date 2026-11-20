from dataclasses import replace
import hashlib
import unittest

from bri.access.policy import AccessGrant, Principal
from bri.ingestion.csv_intake import extract_bounded_csv
from bri.knowledge.csv_questions import answer_csv_question
from bri.knowledge.query import EvidenceCitation, KnowledgeAnswer, KnowledgeItem


class CsvQuestionTests(unittest.TestCase):
    principal = Principal(
        "reader", frozenset({"city"}), (AccessGrant("city", "knowledge:read", "policy"),)
    )
    question = "How many years must employee files be retained?"
    seven_years = "Employee files must be retained for seven years."
    ten_years = "Employee files must be retained for ten years."

    def item(self, csv=None, record_id="record-1"):
        csv = csv or (
            'Policy,Evidence\r\nEmployee-file retention,"Administrative note.\r\n'
            'Employee files must be retained for seven years. Unrelated sentence."\r\n'
        ).encode()
        extraction = extract_bounded_csv(csv)
        first, last = extraction.first_line, extraction.last_line

        return KnowledgeItem(
            record_id, "city", "policy", "approved", "Governed CSV", "1",
            f"csv:lines={first}-{last}", extraction.text,
            source_id=f"source-{record_id}", source_version_id=f"version-{record_id}",
            extraction_id=f"extraction-{record_id}", content_sha256=extraction.extracted_sha256,
            extractor_name="governed-csv", extractor_version="1",
            original_sha256=hashlib.sha256(csv).hexdigest(), csv_first_line=first, csv_last_line=last,
        )

    def test_returns_exact_cell_sentence_and_enclosing_extraction_provenance(self):
        item = self.item()
        result = answer_csv_question(self.principal, self.question, [item])
        self.assertEqual(result.status, "supported")
        self.assertEqual(result.answer, self.seven_years)
        self.assertEqual(result.citations, (EvidenceCitation(
            item.record_id, item.title, item.source_version, "csv:lines=1-3", self.seven_years,
            item.source_id, item.source_version_id, item.extraction_id, item.content_sha256,
            "governed-csv", "1", item.original_sha256, 1, 3,
        ),))
        self.assertNotEqual(item.content_sha256, item.original_sha256)

    def test_filters_unapproved_other_tenant_other_node_and_stale_evidence(self):
        visible = self.item()
        other = self.item(f"Evidence\n{self.ten_years}\n".encode(), "other")
        expected = answer_csv_question(self.principal, self.question, [visible])
        self.assertEqual(expected.status, "supported")
        for fields in ({"tenant_id": "other"}, {"scope_id": "other"},
                       {"validation_state": "proposed"}, {"current": False}):
            with self.subTest(fields=fields):
                excluded = replace(other, **fields)
                self.assertEqual(answer_csv_question(self.principal, self.question, [excluded, visible]),
                                 expected)
                self.assertEqual(answer_csv_question(self.principal, self.question, [excluded]),
                                 KnowledgeAnswer("insufficient", None, ()))
        self.assertEqual(answer_csv_question(None, self.question, [visible]),
                         KnowledgeAnswer("insufficient", None, ()))

    def test_headers_and_json_structure_do_not_supply_answer_text(self):
        item = self.item(b"Policy,Years\nUnrelated,\n")
        for query in ("Policy", "Years", "headers rows"):
            with self.subTest(query=query):
                self.assertEqual(answer_csv_question(self.principal, query, [item]),
                                 KnowledgeAnswer("insufficient", None, ()))

    def test_ignores_entire_malformed_projection_even_with_matching_cells(self):
        item = self.item()
        for content in (
            f'{{"headers":["Evidence"],"rows":[["{self.seven_years}"]],"extra":0}}',
            f'{{"headers":["Evidence"],"rows":[],"rows":[["{self.seven_years}"]]}}',
            f'{{"headers":["Evidence"],"rows":[["{self.seven_years}"],[7]]}}',
            f'{{"headers":["Evidence"],"rows":[["{self.seven_years}"],[]]}}',
            f'{{"headers":["Evidence","Evidence"],"rows":[["{self.seven_years}",""]]}}',
            f'{{"headers":["Evidence"],"rows":[["{self.seven_years}"],["\\ud800"]]}}',
            "[" * 10000,
            self.seven_years,
        ):
            with self.subTest(content=content[:100]):
                malformed = replace(item, content=content,
                                    content_sha256=hashlib.sha256(content.encode()).hexdigest())
                self.assertEqual(answer_csv_question(self.principal, self.question, [malformed]),
                                 KnowledgeAnswer("insufficient", None, ()))

    def test_missing_physical_range_is_not_cited(self):
        item = replace(self.item(), csv_last_line=None)
        self.assertEqual(answer_csv_question(self.principal, self.question, [item]),
                         KnowledgeAnswer("insufficient", None, ()))

    def test_citation_cap_preserves_late_conflict_witness_and_order(self):
        items = [self.item(record_id=f"agree-{n}") for n in range(8)]
        items.append(self.item(f"Evidence\n{self.ten_years}\n".encode(), "z-conflict"))
        result = answer_csv_question(self.principal, self.question, items)
        self.assertEqual(result, answer_csv_question(self.principal, self.question, items[::-1]))
        self.assertEqual(result.status, "conflicting")
        self.assertIsNone(result.answer)
        self.assertEqual(len(result.citations), 5)
        self.assertEqual({c.excerpt for c in result.citations}, {self.seven_years, self.ten_years})

    def test_unquotable_top_match_cannot_hide_conflict(self):
        oversized = self.item(f"Evidence\n{'x' * 512} {self.ten_years}\n".encode(), "late")
        result = answer_csv_question(self.principal, self.question, [self.item(), oversized])
        self.assertEqual(result, KnowledgeAnswer("insufficient", None, ()))

    def test_work_overflow_never_returns_a_partial_match(self):
        oversized = self.item(f"Evidence\n{'x' * 2_000_000} {self.ten_years}\n".encode(), "late")
        many_sentences = self.item(b'Evidence\n' + b'Note. ' * 20_001 + b'\n', "many")
        for extra_items in ([oversized], [many_sentences], [self.item()] * 1024):
            with self.subTest(size=len(extra_items), record=extra_items[0].record_id):
                self.assertEqual(answer_csv_question(self.principal, self.question, [self.item(), *extra_items]),
                                 KnowledgeAnswer("insufficient", None, ()))

    def test_matches_unicode_without_normalizing_returned_text(self):
        text = 'Le Café conserve « les dossiers ».'
        item = self.item(f'Evidence\n  {text}  \n'.encode())
        result = answer_csv_question(self.principal, 'CAFÉ DOSSIERS', [item])
        self.assertEqual((result.status, result.answer), ("supported", text))
        self.assertEqual(result.citations[0].excerpt, text)

    def test_maximum_excerpt_length_is_inclusive(self):
        text = "x" * (512 - len(self.seven_years) - 1) + " " + self.seven_years
        item = self.item(f"Evidence\n{text}\n".encode())
        result = answer_csv_question(self.principal, self.question, [item])
        self.assertEqual((result.status, result.answer), ("supported", text))

    def test_denied_items_do_not_spend_authorized_item_budget(self):
        visible = self.item()
        denied = replace(visible, tenant_id="other")
        self.assertEqual(answer_csv_question(self.principal, self.question, [denied] * 1024 + [visible]),
                         answer_csv_question(self.principal, self.question, [visible]))

    def test_denied_projection_does_not_spend_content_budget(self):
        visible = self.item()
        denied = replace(visible, tenant_id="other", content="x" * 2_000_001)
        self.assertEqual(answer_csv_question(self.principal, self.question, [denied, visible]),
                         answer_csv_question(self.principal, self.question, [visible]))
