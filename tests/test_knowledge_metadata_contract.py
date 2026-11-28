"""A19.1 request validation is deliberately independent of authorization."""
from unittest import TestCase

from bri.knowledge.metadata import parse_proposed_metadata


class MetadataContractTests(TestCase):
    def setUp(self):
        self.payload = {
            'version': 1, 'primary_classification_id': 'governance.policy',
            'additional_classification_ids': ['operations.procedure'], 'title': 'Synthetic operating policy',
            'description': None, 'effective_date': '2026-01-02', 'review_date': None, 'expiry_date': '2027-01-02',
        }

    def test_valid_dates_are_independent_and_source_node_is_not_caller_input(self):
        command = parse_proposed_metadata(self.payload)
        self.assertEqual(command.title, self.payload['title'])
        self.assertEqual(command.effective_date.isoformat(), '2026-01-02')
        self.assertEqual(command.expiry_date.isoformat(), '2027-01-02')
        self.assertIsNone(command.review_date)
        self.assertEqual(command.additional_classification_ids, ('operations.procedure',))
        with self.assertRaises(ValueError):
            parse_proposed_metadata(self.payload | {'scope_node_id': 'other-node'})

    def test_typed_closed_contract_rejects_invalid_scalars_and_duplicate_classes(self):
        for bad in ({'version': True}, {'version': 2}, {'title': '\x00'}, {'title': '   '},
                    {'title': 'é' * 81}, {'description': 'é' * 1025}, {'effective_date': '2026-02-30'},
                    {'effective_date': '20260102'}, {'primary_classification_id': 'foreign/policy'},
                    {'primary_classification_id': 'policy\n'}, {'additional_classification_ids': 'procedure'},
                    {'additional_classification_ids': ['a', 'a']}, {'additional_classification_ids': [self.payload['primary_classification_id']]},
                    {'additional_classification_ids': [f'class-{i}' for i in range(9)]}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_proposed_metadata(self.payload | bad)
        with self.assertRaises(ValueError):
            parse_proposed_metadata({k: v for k, v in self.payload.items() if k != 'title'})

    def test_utf8_and_association_caps_are_inclusive(self):
        command = parse_proposed_metadata(self.payload | {'title': 'é' * 80, 'description': 'é' * 1024,
            'additional_classification_ids': [f'class-{i}' for i in range(8)]})
        self.assertEqual(len(command.title.encode('utf-8')), 160)
        self.assertEqual(len(command.description.encode('utf-8')), 2048)
        self.assertEqual(len(command.additional_classification_ids), 8)
