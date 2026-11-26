"""Dispatch against real quarantine and synthetic workbook bytes."""
from dataclasses import replace
import hashlib
from io import BytesIO
from tempfile import TemporaryDirectory
from threading import Event, Thread
import unittest
from unittest.mock import patch
from uuid import uuid4

from openpyxl import Workbook


class FakeRepository:
    def __init__(self, claimed):
        self.claimed = claimed
        self.calls = []
        self.completion_error: Exception | None = None

    def claim(self, *args):
        self.calls.append(('claim', args))
        return self.claimed

    def complete(self, *args):
        self.calls.append(('complete', args))
        if self.completion_error:
            raise self.completion_error

    def fail(self, *args):
        self.calls.append(('fail', args))


class XlsxDispatchTests(unittest.TestCase):
    def setUp(self):
        from bri.ingestion import xlsx_intake as intake

        self.intake = intake
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.store = intake.LocalXlsxQuarantine(directory.name)
        self.job, self.cid, tenant, key = uuid4(), uuid4(), 'fixture-tenant', self.store.new_key()
        workbook = Workbook()
        sheet = workbook.worksheets[0]
        sheet.title = 'Résumé'
        sheet.append(['Column'])
        sheet.append([123])
        buffer = BytesIO()
        workbook.save(buffer)
        self.raw = buffer.getvalue()
        receipt = self.store.install(tenant, self.job, key, self.raw)
        self.repo = FakeRepository(intake.ClaimedXlsxJob(
            self.job, tenant, key, receipt.byte_count, receipt.original_sha256, 7))
        self.dispatcher = intake.XlsxIntakeDispatcher(self.store, self.repo)

    def test_completes_with_exact_canonical_text_and_fenced_sheet_evidence(self):
        outcome = self.dispatcher.dispatch(self.job, self.cid)
        text = ('{"rows":[[["text","Column"]],[["number","1.23e2"]]],"version":1,'
                '"worksheet":{"identity":"1","range":"A1:A2","title":"Résumé"}}')
        self.assertEqual(outcome, 'completed')
        self.assertEqual(self.repo.calls, [('claim', (self.job, self.cid)), ('complete', (
            self.job, 7, text, hashlib.sha256(text.encode()).hexdigest(), 1, 1,
            '1', 'Résumé', 'A1:A2', self.cid))])

    def test_ambiguous_completion_never_competes_with_failure(self):
        self.repo.completion_error = RuntimeError('unacknowledged commit')
        with self.assertRaises(RuntimeError):
            self.dispatcher.dispatch(self.job, self.cid)
        self.assertEqual([kind for kind, _ in self.repo.calls], ['claim', 'complete'])

    def test_malformed_whole_frame_is_rejected_even_with_matching_hash(self):
        result = self.intake.extract_xlsx_strict(self.raw)
        malformed = result.canonical_bytes.replace(b'1.23e2', b'1.230e2')
        forged = replace(result, canonical_bytes=malformed, evidence=replace(
            result.evidence, canonical_sha256=hashlib.sha256(malformed).hexdigest()))
        with patch.object(self.intake, 'extract_xlsx_strict', return_value=forged):
            self.assertEqual(self.dispatcher.dispatch(self.job, self.cid), 'failed')
        self.assertEqual(self.repo.calls[-1], ('fail', (self.job, 7, 'integrity_failure', self.cid)))

    def test_only_one_active_dispatch_per_instance(self):
        entered, release = Event(), Event()
        read = self.store.read_verified

        def held_read(*args):
            entered.set()
            if not release.wait(5):
                raise RuntimeError('test barrier timeout')
            return read(*args)

        result = []
        with patch.object(self.store, 'read_verified', side_effect=held_read):
            thread = Thread(target=lambda: result.append(self.dispatcher.dispatch(self.job, self.cid)))
            thread.start()
            try:
                self.assertTrue(entered.wait(5))
                self.assertEqual(self.dispatcher.dispatch(uuid4(), uuid4()), 'busy')
                self.assertEqual(self.repo.calls, [('claim', (self.job, self.cid))])
            finally:
                release.set()
                thread.join(5)
        self.assertEqual(result, ['completed'])

    def test_rechecks_versions_digests_and_all_sheet_evidence(self):
        result = self.intake.extract_xlsx_strict(self.raw)
        for field, value in dict(extractor_version=True, canonicalization_version=2,
                                 original_sha256='0' * 64, canonical_sha256='0' * 64,
                                 worksheet_identity='2', worksheet_title='Spoof',
                                 worksheet_range='A1').items():
            with self.subTest(field=field):
                forged = replace(result, evidence=replace(result.evidence, **{field: value}))
                self.repo.calls.clear()
                with patch.object(self.intake, 'extract_xlsx_strict', return_value=forged):
                    self.assertEqual(self.dispatcher.dispatch(self.job, self.cid), 'failed')
                self.assertEqual(self.repo.calls, [('claim', (self.job, self.cid)),
                    ('fail', (self.job, 7, 'integrity_failure', self.cid))])

    def test_only_fixed_failure_reasons_cross_repository_boundary(self):
        for code, reason in dict(invalid_workbook='unsupported_workbook', invalid_archive='unsupported_workbook',
                                 output_limit='resource_limit', timeout='resource_limit',
                                 worker_unavailable='infrastructure_unavailable',
                                 worker_failure='processing_failed', PRIVATE_SENTINEL='processing_failed').items():
            with self.subTest(code=code):
                self.repo.calls.clear()
                with patch.object(self.intake, 'extract_xlsx_strict', side_effect=self.intake.StrictXlsxError(code)):
                    self.assertEqual(self.dispatcher.dispatch(self.job, self.cid), 'failed')
                self.assertEqual(self.repo.calls, [('claim', (self.job, self.cid)),
                    ('fail', (self.job, 7, reason, self.cid))])
