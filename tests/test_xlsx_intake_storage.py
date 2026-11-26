"""Private XLSX quarantine contracts on a disposable UNIX filesystem."""
import hashlib
import errno
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Barrier, Thread
import unittest
from unittest.mock import patch
from uuid import uuid4


class XlsxStorageTests(unittest.TestCase):
    def test_text_tenant_binding_is_exact_and_path_safe(self):
        from bri.ingestion.xlsx_intake import LocalXlsxQuarantine, XlsxIntakeError

        with TemporaryDirectory() as root:
            store = LocalXlsxQuarantine(root)
            tenant, job, key = '../Client:é ', uuid4(), store.new_key()
            raw = b'fixture'
            receipt = store.install(tenant, job, key, raw)
            artifact, = Path(root).rglob(key)
            self.assertRegex(artifact.parent.name, r'^[0-9a-f]{64}$')
            self.assertEqual(artifact.parent.parent, Path(root))
            args = key, receipt.original_sha256, receipt.byte_count
            self.assertEqual(store.read_verified(tenant, str(job), *args), raw)
            for alias in (tenant.strip(), tenant.lower(), '../Client:e\u0301 '):
                with self.subTest(alias=alias), self.assertRaises(XlsxIntakeError):
                    store.read_verified(alias, job, *args)
            for invalid in ('', '\ud800', 'x' * 257, uuid4()):
                with self.subTest(invalid=invalid), self.assertRaisesRegex(XlsxIntakeError, '^integrity_failure$'):
                    store.install(invalid, job, key, raw)
            for alias in (job.hex, '{' + str(job) + '}', ' ' + str(job)):
                with self.subTest(job=alias), self.assertRaisesRegex(XlsxIntakeError, '^integrity_failure$'):
                    store.read_verified(tenant, alias, *args)

    def test_install_is_bound_to_both_tenant_and_job_and_never_replaces(self):
        from bri.ingestion.xlsx_intake import LocalXlsxQuarantine, XlsxIntakeError

        with TemporaryDirectory() as root:
            store = LocalXlsxQuarantine(root)
            tenant, job, key = str(uuid4()), uuid4(), store.new_key()
            raw = b'synthetic workbook'
            receipt = store.install(tenant, job, key, raw)
            digest = hashlib.sha256(raw).hexdigest()
            self.assertEqual((receipt.artifact_key, receipt.original_sha256, receipt.byte_count),
                             (key, digest, len(raw)))
            artifact, = Path(root).rglob(key)
            inode = artifact.stat().st_ino
            self.assertEqual(store.install(tenant, job, key, raw), receipt)
            with self.assertRaisesRegex(XlsxIntakeError, '^integrity_failure$'):
                store.install(tenant, job, key, b'different content!')
            self.assertEqual(artifact.stat().st_ino, inode)
            for other_tenant, other_job in (('other-tenant', job), (tenant, uuid4())):
                with self.assertRaises(XlsxIntakeError):
                    store.read_verified(other_tenant, other_job, key, digest, len(raw))
            reopened = LocalXlsxQuarantine(root)
            self.assertEqual(reopened.read_verified(tenant, job, key, digest, len(raw)), raw)

    def test_interrupted_link_and_ambiguous_directory_sync_can_retry(self):
        from bri.ingestion.xlsx_intake import LocalXlsxQuarantine, XlsxIntakeError

        with TemporaryDirectory() as root:
            store = LocalXlsxQuarantine(root)
            tenant, job, key = str(uuid4()), uuid4(), store.new_key()
            raw = b'fixture'
            fsync = os.fsync

            with patch.object(os, 'link', side_effect=OSError(errno.EIO, 'PRIVATE_SENTINEL')):
                with self.assertRaisesRegex(XlsxIntakeError, '^infrastructure_unavailable$'):
                    store.install(tenant, job, key, raw)
            self.assertEqual(list(Path(root).rglob(key)), [])

            def fail_after_link(fd):
                if list(Path(root).rglob(key)):
                    raise OSError(errno.EIO, 'PRIVATE_SENTINEL')
                fsync(fd)

            with patch.object(os, 'fsync', side_effect=fail_after_link):
                with self.assertRaisesRegex(XlsxIntakeError, '^infrastructure_unavailable$'):
                    store.install(tenant, job, key, raw)
            artifact, = Path(root).rglob(key)
            inode = artifact.stat().st_ino
            store.install(tenant, job, key, raw)
            self.assertEqual(artifact.stat().st_ino, inode)

    def test_competing_writes_race_at_atomic_publication(self):
        from bri.ingestion.xlsx_intake import LocalXlsxQuarantine, XlsxIntakeError

        with TemporaryDirectory() as root:
            store = LocalXlsxQuarantine(root)
            tenant, job, key = str(uuid4()), uuid4(), store.new_key()
            rendezvous = Barrier(2)
            link = os.link
            successes, failures = [], []

            def write(content):
                try:
                    successes.append((content, store.install(tenant, job, key, content)))
                except XlsxIntakeError as exc:
                    failures.append(exc.reason.value)

            def raced_link(*args, **kwargs):
                rendezvous.wait(5)
                return link(*args, **kwargs)

            threads = [Thread(target=write, args=(content,)) for content in (b'first', b'other')]
            with patch.object(os, 'link', side_effect=raced_link):
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(6)
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual(failures, ['integrity_failure'])
            (raw, receipt), = successes
            self.assertEqual(store.read_verified(tenant, job, key, receipt.original_sha256, receipt.byte_count), raw)
