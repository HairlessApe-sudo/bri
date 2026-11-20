import hashlib
import os
import stat
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from unittest.mock import patch
from uuid import UUID, uuid4

from bri.ingestion.csv_intake import (
    ClaimedCsvJob,
    CsvIntakeError,
    IntakeReason,
    LocalCsvQuarantine,
    QuarantinedCsv,
)


class BoundedExtractionTests(unittest.TestCase):
    def test_preserves_literals_and_exact_physical_ranges(self):
        from bri.ingestion.csv_intake import extract_bounded_csv

        content = ('\ufeff"label\r\nname",value\r\n'
                   '"one\rtwo","=SUM(1,2)"\n'
                   '"a""b",+123').encode()
        result = extract_bounded_csv(content)
        self.assertEqual(result.header_line_range, (1, 2))
        self.assertEqual(result.source_line_ranges, ((3, 4), (5, 5)))
        self.assertEqual(result.text, '{"headers":["label\\r\\nname","value"],'
                                     '"rows":[["one\\rtwo","=SUM(1,2)"],["a\\\"b","+123"]]}')
        self.assertEqual(result.extracted_sha256, hashlib.sha256(result.text.encode()).hexdigest())
        self.assertEqual((result.first_line, result.last_line), (1, 5))

    def test_accepts_header_only_and_does_not_count_terminal_newline_as_row(self):
        from bri.ingestion.csv_intake import extract_bounded_csv

        result = extract_bounded_csv(b'"a\rb"\r\n')
        self.assertEqual(result.text, '{"headers":["a\\rb"],"rows":[]}')
        self.assertEqual(result.source_line_ranges, ())
        self.assertEqual((result.first_line, result.last_line), (1, 2))

    def test_extracted_utf8_limit_accepts_exact_size_and_rejects_one_byte_more(self):
        from bri.ingestion.csv_intake import MAX_EXTRACTED_BYTES, extract_bounded_csv

        self.assertEqual(MAX_EXTRACTED_BYTES, 20_000_000)
        content = 'a\né\n\x01'.encode('utf-8')
        expected = '{"headers":["a"],"rows":[["é"],["\\u0001"]]}'
        encoded = expected.encode('utf-8')
        with patch('bri.ingestion.csv_intake.MAX_EXTRACTED_BYTES', len(encoded)):
            result = extract_bounded_csv(content)
            self.assertEqual(result.text, expected)
            self.assertEqual(result.extracted_sha256, hashlib.sha256(encoded).hexdigest())
            with self.assertRaises(CsvIntakeError) as caught:
                extract_bounded_csv(content + b'x')
        self.assertEqual(str(caught.exception), 'invalid_csv')
        self.assertFalse(caught.exception.transient)

    def test_rejects_invalid_inputs_with_stable_private_reasons(self):
        from bri.ingestion.csv_intake import extract_bounded_csv

        for content, reason in (
            (b'', 'invalid_headers'),
            (b'a,\t\n1,2', 'invalid_headers'),
            (b'a,a\n1,2', 'invalid_headers'),
            (b'a\n\xffSYNTHETIC', 'invalid_utf8'),
            (b'a\n"SYNTHETIC', 'invalid_csv'),
            (b'a\nSYNTHETIC"', 'invalid_csv'),
            (b'a\n"SYNTHETIC" ', 'invalid_csv'),
            (b'a,b\nSYNTHETIC', 'row_width'),
            (b'a\n\n', 'row_width'),
            (b'a\nSYNTHETIC,b', 'row_width'),
        ):
            with self.subTest(reason=reason), self.assertRaises(CsvIntakeError) as caught:
                extract_bounded_csv(content)
            self.assertEqual(caught.exception.reason.value, reason)
            self.assertNotIn('SYNTHETIC', str(caught.exception))
            self.assertFalse(caught.exception.transient)

    def test_enforces_exact_byte_row_and_column_limits(self):
        from bri.ingestion.csv_intake import extract_bounded_csv

        max_bytes = b'a\n' + b'x' * 4_999_998
        max_rows = b'a\n' + b'x\n' * 10_000
        max_columns = ','.join(f'col{i}' for i in range(50)).encode()
        self.assertEqual(extract_bounded_csv(max_bytes).source_line_ranges, ((2, 2),))
        self.assertEqual(extract_bounded_csv(max_rows).last_line, 10_001)
        self.assertEqual(extract_bounded_csv(max_columns).last_line, 1)
        for content, reason in ((max_bytes + b'x', 'byte_limit'),
                                (max_rows + b'x', 'row_limit'),
                                (max_columns + b',extra', 'column_limit'),
                                (max_columns + b'\n' + b',' * 50, 'column_limit')):
            with self.subTest(reason=reason), self.assertRaises(CsvIntakeError) as caught:
                extract_bounded_csv(content)
            self.assertEqual(caught.exception.reason.value, reason)


class _RecordingRepo:
    def __init__(self, job: ClaimedCsvJob | None):
        self.job = job
        self.calls = []

    def claim(self, *args):
        self.calls.append(('claim', args))
        return self.job

    def complete(self, *args):
        self.calls.append(('complete', args))

    def fail(self, *args):
        self.calls.append(('fail', args))


class ProcessingTests(unittest.TestCase):
    def setUp(self):
        from bri.ingestion.csv_intake import CsvIntakeProcessor

        self.store = LocalCsvQuarantine(Path(self.enterContext(tempfile.TemporaryDirectory())))
        self.job_id = uuid4()
        self.correlation = uuid4()
        self.tenant = 'synthetic-job-tenant'
        self.key = self.store.new_key()
        self.content = b'a,b\n"SYNTHETIC\nline",=fake'
        digest = hashlib.sha256(self.content).hexdigest()
        self.repo = _RecordingRepo(ClaimedCsvJob(self.job_id, self.tenant, self.key, digest,
                                                len(self.content), 2))
        self.process = CsvIntakeProcessor(self.store, self.repo).process

    def test_completes_verified_attempt_with_extraction_hash_and_full_range(self):
        self.store.install(self.tenant, self.key, self.content)
        self.assertEqual(self.process(self.job_id, self.correlation).value, 'completed')
        text = '{"headers":["a","b"],"rows":[["SYNTHETIC\\nline","=fake"]]}'
        self.assertEqual(self.repo.calls, [
            ('claim', (self.job_id, self.correlation)),
            ('complete', (self.job_id, 2, text, hashlib.sha256(text.encode()).hexdigest(),
                          1, 3, self.correlation)),
        ])

    def test_reports_only_bounded_reasons_and_marks_storage_missing_transient(self):
        self.store.install('synthetic-OTHER-tenant', self.key, self.content)
        self.assertEqual(self.process(self.job_id, self.correlation).value, 'failed')
        self.assertEqual(self.repo.calls[-1],
                         ('fail', (self.job_id, 2, 'storage_missing', True, self.correlation)))
        self.store.install(self.tenant, self.key, b'a\n' + b'x' * (len(self.content) - 2))
        self.assertEqual(self.process(self.job_id, self.correlation).value, 'failed')
        self.assertEqual(self.repo.calls[-1],
                         ('fail', (self.job_id, 2, 'storage_mismatch', False, self.correlation)))

    def test_verified_malformed_input_fails_permanently_without_diagnostics(self):
        from dataclasses import replace

        receipt = self.store.install(self.tenant, self.key, b'a\n"SYNTHETIC broken')
        assert self.repo.job is not None
        self.repo.job = replace(self.repo.job, sha256=receipt.sha256, byte_count=receipt.byte_count)
        self.assertEqual(self.process(self.job_id, self.correlation).value, 'failed')
        self.assertEqual(self.repo.calls[-1],
                         ('fail', (self.job_id, 2, 'invalid_csv', False, self.correlation)))

    def test_verified_output_overflow_fails_without_completion_or_retry(self):
        self.store.install(self.tenant, self.key, self.content)
        with patch('bri.ingestion.csv_intake.MAX_EXTRACTED_BYTES', len(self.content)):
            self.assertEqual(self.process(self.job_id, self.correlation).value, 'failed')
        self.assertEqual(self.repo.calls, [
            ('claim', (self.job_id, self.correlation)),
            ('fail', (self.job_id, 2, 'invalid_csv', False, self.correlation)),
        ])

    def test_no_claim_is_a_noop_and_mismatched_claim_does_not_mutate(self):
        job, self.repo.job = self.repo.job, None
        self.assertEqual(self.process(self.job_id, self.correlation).value, 'not_claimed')
        self.repo.job = job
        with self.assertRaises(CsvIntakeError) as caught:
            self.process(uuid4(), self.correlation)
        self.assertEqual(caught.exception.reason, IntakeReason.INVALID_METADATA)
        self.assertEqual([action for action, _ in self.repo.calls], ['claim', 'claim'])

    def test_ambiguous_completion_is_not_converted_to_a_failure_callback(self):
        self.store.install(self.tenant, self.key, self.content)
        with patch.object(self.repo, 'complete', side_effect=RuntimeError('synthetic commit')):
            with self.assertRaises(RuntimeError):
                self.process(self.job_id, self.correlation)
        self.assertEqual([action for action, _ in self.repo.calls], ['claim'])


class QuarantineTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.store = LocalCsvQuarantine(self.root)
        self.tenant = 'synthetic/../../tenant'
        self.content = b'a,b\n1,2\n'
        self.key = self.store.new_key()

    def test_immutable_tenant_scoped_install_and_verified_read(self):
        receipt = self.store.install(self.tenant, self.key, self.content)
        namespace, = self.root.iterdir()
        stored, = namespace.iterdir()
        self.assertEqual(namespace.name, hashlib.sha256(self.tenant.encode()).hexdigest())
        self.assertEqual(stat.S_IMODE(namespace.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(stored.stat().st_mode), 0o400)
        self.assertEqual(stored.name, self.key)
        self.assertEqual(UUID(receipt.storage_key).version, 4)
        self.assertEqual(receipt.sha256, hashlib.sha256(self.content).hexdigest())
        self.assertEqual(receipt.byte_count, len(self.content))
        self.assertEqual(self.store.read_verified(self.tenant, self.key, receipt.sha256,
                                                  receipt.byte_count), self.content)
        self.assertEqual(self.store.install(self.tenant, self.key, self.content), receipt)
        with self.assertRaises(CsvIntakeError) as caught:
            self.store.install(self.tenant, self.key, b'a,b\n3,4\n')
        self.assertEqual(caught.exception.reason, IntakeReason.STORAGE_MISMATCH)
        self.assertEqual(stored.read_bytes(), self.content)
        with self.assertRaises(CsvIntakeError) as caught:
            self.store.read_verified('synthetic-other', self.key, receipt.sha256,
                                     receipt.byte_count)
        self.assertEqual(caught.exception.reason, IntakeReason.STORAGE_MISSING)
        self.assertEqual(list(self.root.iterdir()), [namespace])

    def test_configuration_rejects_public_root_mode_symlink_and_relative_path(self):
        web = self.root / 'web'
        web.mkdir(mode=0o700)
        private = web / 'quarantine'
        private.mkdir(mode=0o700)
        alias = self.root / 'alias'
        alias.symlink_to(private)
        insecure = self.root / 'insecure'
        insecure.mkdir(mode=0o755)
        for path, excluded in ((private, (web,)), (alias, ()), (insecure, ()),
                               (Path('relative'), ()), (Path.cwd(), ())):
            with self.subTest(path=path.name), self.assertRaises(CsvIntakeError) as caught:
                LocalCsvQuarantine(path, excluded_roots=excluded)
            self.assertEqual(caught.exception.reason, IntakeReason.STORAGE_CONFIGURATION)
            self.assertNotIn(str(path), str(caught.exception))

    def test_missing_or_interrupted_install_never_exposes_partial_final(self):
        digest = hashlib.sha256(self.content).hexdigest()
        with patch('bri.ingestion.csv_intake.os.link', side_effect=OSError('synthetic path')):
            with self.assertRaises(CsvIntakeError) as caught:
                self.store.install(self.tenant, self.key, self.content)
        self.assertEqual(caught.exception.reason, IntakeReason.STORAGE_UNAVAILABLE)
        self.assertNotIn('synthetic path', str(caught.exception))
        with self.assertRaises(CsvIntakeError) as caught:
            self.store.read_verified(self.tenant, self.key, digest, len(self.content))
        self.assertEqual(caught.exception.reason, IntakeReason.STORAGE_MISSING)
        namespace, = self.root.iterdir()
        staging, = namespace.iterdir()
        self.assertEqual(staging.read_bytes(), self.content)
        self.store.install(self.tenant, self.key, self.content)
        self.assertTrue(staging.exists())
        self.assertEqual(self.store.read_verified(self.tenant, self.key, digest, len(self.content)),
                         self.content)

    def test_retry_after_directory_sync_failure_preserves_installed_blob(self):
        fsync = os.fsync

        def fail_after_publish(fd):
            if any(self.root.glob(f'*/{self.key}')):
                raise OSError('synthetic directory sync failure')
            fsync(fd)

        with patch('bri.ingestion.csv_intake.os.fsync', side_effect=fail_after_publish):
            with self.assertRaises(CsvIntakeError) as caught:
                self.store.install(self.tenant, self.key, self.content)
        self.assertEqual(caught.exception.reason, IntakeReason.STORAGE_UNAVAILABLE)
        stored, = self.root.glob(f'*/{self.key}')
        inode = stored.stat().st_ino
        receipt = self.store.install(self.tenant, self.key, self.content)
        self.assertEqual(stored.stat().st_ino, inode)
        self.assertEqual(self.store.read_verified(self.tenant, self.key, receipt.sha256,
                                                  receipt.byte_count), self.content)

    def test_concurrent_different_installs_cannot_replace_winning_blob(self):
        link = os.link
        publishing = Barrier(2, timeout=5)

        def competing_link(*args, **kwargs):
            publishing.wait()
            return link(*args, **kwargs)

        def install(content):
            try:
                return self.store.install(self.tenant, self.key, content)
            except CsvIntakeError as exc:
                return exc.reason

        inputs = (self.content, b'a,b\n3,4\n')
        with patch('bri.ingestion.csv_intake.os.link', side_effect=competing_link):
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(install, inputs))
        self.assertEqual(results.count(IntakeReason.STORAGE_MISMATCH), 1)
        winner, = [result for result in results if isinstance(result, QuarantinedCsv)]
        self.assertEqual(self.store.read_verified(self.tenant, self.key, winner.sha256,
                                                  winner.byte_count), inputs[results.index(winner)])

    def test_rejects_tampering_unsafe_keys_and_non_regular_files(self):
        receipt = self.store.install(self.tenant, self.key, self.content)
        stored, = self.root.glob(f'*/{self.key}')
        for key, digest, size, reason in (
            ('../synthetic-path', receipt.sha256, receipt.byte_count, IntakeReason.INVALID_METADATA),
            (self.key, 'not-a-digest', receipt.byte_count, IntakeReason.INVALID_METADATA),
            (self.key, receipt.sha256, 5_000_001, IntakeReason.INVALID_METADATA),
            (self.key, '0' * 64, receipt.byte_count, IntakeReason.STORAGE_MISMATCH),
            (self.key, receipt.sha256, receipt.byte_count - 1, IntakeReason.STORAGE_MISMATCH),
        ):
            with self.subTest(reason=reason), self.assertRaises(CsvIntakeError) as caught:
                self.store.read_verified(self.tenant, key, digest, size)
            self.assertEqual(caught.exception.reason, reason)
        stored.unlink()
        for make_file in (lambda: stored.symlink_to('/synthetic-target'),
                          lambda: os.mkfifo(stored, 0o400)):
            make_file()
            with self.assertRaises(CsvIntakeError) as caught:
                self.store.read_verified(self.tenant, self.key, receipt.sha256, receipt.byte_count)
            self.assertEqual(caught.exception.reason, IntakeReason.STORAGE_MISMATCH)
            stored.unlink()
