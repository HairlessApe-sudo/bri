"""Synthetic tests for the strict XLSX process boundary."""

from contextlib import nullcontext
from dataclasses import FrozenInstanceError
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import sys
from tempfile import TemporaryDirectory
import unittest
import zlib
from unittest.mock import patch
from zipfile import ZipFile, ZIP_STORED

from bri.ingestion import xlsx_strict as strict


@unittest.skipUnless(sys.platform == "linux", "strict worker requires Linux")
class StrictProcessTests(unittest.TestCase):
    CANONICAL_PREFIX = b'{"rows":[[["text","'
    CANONICAL_SUFFIX = b'"]]],"version":1,"worksheet":{"identity":"1","range":"A1","title":"Sheet"}}'

    @classmethod
    def canonical_document(cls, size):
        return cls.CANONICAL_PREFIX + b"x" * (size - len(cls.CANONICAL_PREFIX) - len(cls.CANONICAL_SUFFIX)) + cls.CANONICAL_SUFFIX

    @staticmethod
    def frame(canonical):
        return b"\x00" + len(canonical).to_bytes(4, "big") + canonical

    def run_worker(self, script, content=b"synthetic", **limits):
        with patch.object(strict, "_worker_command", return_value=[sys.executable, "-I", "-S", "-c", script]):
            with patch.multiple(strict, **limits) if limits else nullcontext():
                return strict.extract_xlsx_strict(content)

    def assert_failure(self, code, script, **limits):
        with self.assertRaises(strict.StrictXlsxError) as exc:
            self.run_worker(script, **limits)
        self.assertEqual(exc.exception.code, code)
        self.assertNotIn("PRIVATE_SENTINEL", str(exc.exception))

    def test_input_limit_rejects_without_launching(self):
        with patch.object(strict, "MAX_INPUT_BYTES", 3), patch.object(strict, "_worker_command") as command:
            with self.assertRaises(strict.StrictXlsxError) as exc:
                strict.extract_xlsx_strict(b"1234")
        self.assertEqual(exc.exception.code, "input_limit")
        command.assert_not_called()

    def test_timeout_covers_blocked_input_and_reaps(self):
        original = strict.subprocess.Popen
        children = []

        def track(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            return child

        with patch.object(strict.subprocess, "Popen", side_effect=track):
            with self.assertRaises(strict.StrictXlsxError) as exc:
                self.run_worker("import time; time.sleep(60)", b"x" * 100_000, WALL_SECONDS=0.2)
        self.assertEqual(exc.exception.code, "timeout")
        self.assertEqual(len(children), 1)
        self.assertEqual(children[0].returncode, -signal.SIGKILL)
        with self.assertRaises(ChildProcessError):
            os.waitpid(children[0].pid, os.WNOHANG)

    def test_output_is_bounded_while_worker_is_alive(self):
        self.assert_failure("output_limit", "import os\nwhile True: os.write(1, b'x' * 4096)", MAX_OUTPUT_BYTES=32)

    def test_partial_stdout_from_aborted_worker_is_never_success(self):
        valid = self.frame(self.canonical_document(128))
        self.assert_failure(
            "worker_failure",
            "import os, signal; os.read(0, 65536); os.write(2, b'PRIVATE_SENTINEL'); "
            f"os.write(1, {valid!r}); os.kill(os.getpid(), signal.SIGTERM)",
        )

    def test_parent_interruption_kills_and_reaps(self):
        original = strict.subprocess.Popen
        children = []

        def track(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            return child

        with patch.object(strict.subprocess, "Popen", side_effect=track):
            with patch.object(strict.selectors.DefaultSelector, "select", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    self.run_worker("import time; time.sleep(60)")
        self.assertEqual(len(children), 1)
        self.assertEqual(children[0].returncode, -signal.SIGKILL)
        with self.assertRaises(ChildProcessError):
            os.waitpid(children[0].pid, os.WNOHANG)

    def test_zero_exit_with_incomplete_response_is_rejected(self):
        frame = self.frame(self.canonical_document(128))
        for invalid in (frame[:-1], frame + b"x"):
            with self.subTest(size=len(invalid)):
                self.assert_failure("worker_failure", f"import sys; sys.stdin.buffer.read(); sys.stdout.buffer.write({invalid!r})")

    def test_zero_exit_with_duplicate_metadata_is_rejected(self):
        canonical = self.canonical_document(128).replace(b'"version":1', b'"version":2,"version":1')
        self.assert_failure("worker_failure", f"import sys; sys.stdin.buffer.read(); sys.stdout.buffer.write({self.frame(canonical)!r})")

    def test_zero_exit_with_invalid_canonical_payload_is_rejected(self):
        suffix = b',"version":1,"worksheet":{"identity":"1","range":"A1","title":"Sheet"}}'
        cases = {
            "invalid UTF-8": (b'[[["text","\xff"]]]', suffix),
            "broken JSON": (b'[[["text",]]]', suffix),
            "noncanonical string escape": (br'[[["text","\u0061"]]]', suffix),
            "unknown tag": (b'[[["formula","x"]]]', suffix),
            "wrong boolean type": (b'[[["boolean","true"]]]', suffix),
            "noncanonical number": (b'[[["number","1.0e0"]]]', suffix),
            "invalid date": (b'[[["date","2025-02-29"]]]', suffix),
            "invalid XML text": (br'[[["text","\u0000"]]]', suffix),
            "OOXML escape": (b'[[["text","_x0041_"]]]', suffix),
            "text too long": (b'[[["text","' + b'x' * 4097 + b'"]]]', suffix),
            "invalid row": (b'[null]', suffix),
            "truncated row": (b'[[["text","a"],["text","b"]],[null]]', suffix.replace(b'A1', b'A1:B2')),
            "leading blank row": (b'[[null],[["text","a"]]]', suffix.replace(b'A1', b'A1:A2')),
            "trailing blank row": (b'[[["text","a"]],[null]]', suffix.replace(b'A1', b'A1:A2')),
            "leading blank column": (b'[[null,["text","a"]]]', suffix.replace(b'A1', b'A1:B1')),
            "trailing blank column": (b'[[["text","a"],null]]', suffix.replace(b'A1', b'A1:B1')),
            "empty rows with range": (b'[]', suffix),
            "noncanonical singleton range": (b'[[["text","a"]]]', suffix.replace(b'A1', b'A1:A1')),
            "invalid sheet identity": (b'[[["text","a"]]]', suffix.replace(b'"1"', b'"01"')),
            "invalid sheet title": (b'[[["text","a"]]]', suffix.replace(b'Sheet', b'Invalid/Sheet')),
        }
        cell_cases = {"invalid UTF-8", "broken JSON", "noncanonical string escape", "unknown tag",
                      "wrong boolean type", "noncanonical number", "invalid date", "invalid XML text",
                      "OOXML escape", "text too long"}
        for name, (rows, trailer) in cases.items():
            if name in cell_cases:
                rows = b'[[["text","Header"]],' + rows[1:]
                trailer = trailer.replace(b'A1', b'A1:A2')
            with self.subTest(name=name):
                frame = self.frame(b'{"rows":' + rows + trailer)
                self.assert_failure("worker_failure", f"import sys; sys.stdin.buffer.read(); sys.stdout.buffer.write({frame!r})")

    def assert_canonical_frame(self, rows, cell_range, accepted):
        canonical = json.dumps(
            {'rows': rows, 'version': 1,
             'worksheet': {'identity': '1', 'range': cell_range, 'title': 'Sheet'}},
            ensure_ascii=False, separators=(',', ':'), sort_keys=True,
        ).encode('utf-8')
        script = f"import sys, zlib; sys.stdin.buffer.read(); "
        script += f"sys.stdout.buffer.write(zlib.decompress({zlib.compress(self.frame(canonical))!r}))"
        if accepted:
            self.assertEqual(self.run_worker(script).canonical_bytes, canonical)
        else:
            self.assert_failure('worker_failure', script)

    def test_parent_normalized_decimal_exponent_limit(self):
        for number, accepted in (('-1.23e-1022', True), ('-1.23e-1023', False), ('1e-1024', True)):
            with self.subTest(number=number):
                self.assert_canonical_frame([[['text', 'Amount']], [['number', number]]], 'A1:A2', accepted)

    def test_parent_requires_complete_unique_physical_header(self):
        for name, rows, cell_range in (
            ('empty', [], None),
            ('late row', [[['text', 'Name']]], 'A2'),
            ('offset column', [[['text', 'Name']]], 'B1'),
            ('nontext', [[['text', 'Name'], ['number', '1e0']]], 'A1:B1'),
            ('empty text', [[['text', '']]], 'A1'),
            ('whitespace text', [[['text', '\u00a0\t']]], 'A1'),
            ('missing interior', [[['text', 'Name'], None, ['text', 'Other']]], 'A1:C1'),
            ('missing trailing', [[['text', 'Name'], None], [None, ['number', '1e0']]], 'A1:B2'),
            ('normalized duplicate', [[['text', '  CAFÉ'], ['text', 'cafe\u0301 ']]], 'A1:B1'),
            ('casefold duplicate', [[['text', 'Straße'], ['text', 'STRASSE']]], 'A1:B1'),
        ):
            with self.subTest(name=name):
                self.assert_canonical_frame(rows, cell_range, False)
        self.assert_canonical_frame([[['text', '  cafe\u0301 '], ['text', 'Other']]], 'A1:B1', True)

    def test_valid_payload_preserves_all_tags_and_interior_holes(self):
        header = [['text', 'Text'], ['text', 'Boolean'], ['text', 'Number']]
        data = [['text', 'É\\"[]{},:\n\r\t'], ['boolean', False], ['number', '-1.2e-1023']]
        last = [['date', '2024-02-29'], ['time', '01:02:03.000004'], ['datetime', '2024-02-29T01:02:03']]
        # Exercise each exact coordinate cap in a rectangle within the area cap.
        self.assert_canonical_frame([header, data] + [[None] * 3] * 9997 + [last], 'A1:C10000', True)
        for width, cell_range, accepted in ((64, 'A1:BL1', True), (65, 'A1:BM1', False)):
            with self.subTest(width=width):
                self.assert_canonical_frame([[['text', str(n)] for n in range(width)]], cell_range, accepted)
        self.assert_canonical_frame([header, data] + [[None] * 3] * 9998 + [last], 'A1:C10001', False)

    def test_deep_rows_are_rejected_before_json_decode(self):
        script = (
            "import sys; sys.stdin.buffer.read(); "
            "data = b'{\"rows\":[' + b'[' * 500_000 + b'0' + b']' * 500_000 + "
            "b'],\"version\":1,\"worksheet\":{\"identity\":\"1\",\"range\":\"A1\",\"title\":\"Sheet\"}}'; "
            "sys.stdout.buffer.write(b'\\x00' + len(data).to_bytes(4, 'big') + data)"
        )
        with patch.object(strict.json, "loads", side_effect=AssertionError("decoded unbounded nesting")):
            self.assert_failure("worker_failure", script)

    def assert_real_worker_failure(self, code, parser, **limits):
        # Use the real worker/bootstrap with synthetic modules in a disposable package.
        with TemporaryDirectory() as directory:
            package = Path(directory) / "bri" / "ingestion"
            package.mkdir(parents=True)
            worker = package / "_xlsx_strict_worker.py"
            command = strict._worker_command()
            if limits:
                with patch.multiple(strict, **limits):
                    command = strict._worker_command()
            shutil.copyfile(command[4], worker)
            command[4] = str(worker)
            (package / "_xlsx_strict_archive.py").write_text(
                "class StrictArchiveError(ValueError): pass\ndef read_package(content): return {}\n"
            )
            (package / "_xlsx_strict_parser.py").write_text(
                "class StrictParseError(ValueError): pass\n" + parser
            )
            with patch.object(strict, "_worker_command", return_value=command):
                with self.assertRaises(strict.StrictXlsxError) as exc:
                    strict.extract_xlsx_strict(b"synthetic")
            self.assertEqual(exc.exception.code, code)

    def test_real_worker_cpu_limit_applies_before_parser_import(self):
        self.assert_real_worker_failure("resource_limit", "while True: pass\n", CPU_SECONDS=1)

    def test_real_worker_address_space_limit_applies_before_parser_import(self):
        self.assert_real_worker_failure("resource_limit", "allocation = bytearray(400 * 1024**2)\n")

    def test_real_worker_rejects_oversized_canonical_bytes(self):
        self.assert_real_worker_failure("output_limit", "def parse_package(parts): return b'x' * 2_097_153\n")

    def test_parent_transports_exact_cap_but_rejects_one_more_byte(self):
        prefix = b'{"rows":['
        cell_prefix = self.CANONICAL_PREFIX[len(prefix):]
        row = cell_prefix + b"x" * 4096 + b'"]],'
        suffix = self.CANONICAL_SUFFIX.replace(b'A1', b'A1:A511')
        count = 2_097_152 - len(prefix) - 510 * len(row) - len(cell_prefix) - len(suffix)
        expected = prefix + row * 510 + cell_prefix + b"x" * count + suffix
        self.assertEqual(len(expected), 2_097_152)
        script = (
            "import sys; sys.stdin.buffer.read(); "
            "canonical = %r + %r * 510 + %r + b'x' * %d + %r; "
            "sys.stdout.buffer.write(b'\\x00' + len(canonical).to_bytes(4, 'big') + canonical)"
        )
        result = self.run_worker(script % (prefix, row, cell_prefix, count, suffix))
        self.assertEqual(result.canonical_bytes, expected)
        self.assertEqual(result.evidence.canonical_sha256, hashlib.sha256(expected).hexdigest())
        self.assert_failure("output_limit", script % (prefix, row, cell_prefix, count + 1, suffix))

    def test_real_workbook_at_exact_canonical_cap(self):
        from openpyxl import Workbook

        rows = [[["text", "x" * 4096]] for _ in range(510)] + [[["text", ""]]]
        document = {"rows": rows, "version": 1,
                    "worksheet": {"identity": "1", "range": "A1:A511", "title": "Sheet"}}

        def encode():
            return json.dumps(document, separators=(",", ":"), sort_keys=True).encode("utf-8")

        rows[-1][0][1] = "x" * (2_097_152 - len(encode()))
        expected = encode()
        self.assertEqual(len(expected), 2_097_152)
        workbook = Workbook()
        sheet = workbook.active
        assert sheet is not None
        for row in rows:
            sheet.append([row[0][1]])
        compressed, stored = io.BytesIO(), io.BytesIO()
        workbook.save(compressed)
        workbook.close()
        # Repack without compression so this tests the canonical cap, not the ZIP ratio cap.
        with ZipFile(compressed) as source, ZipFile(stored, "w", compression=ZIP_STORED) as target:
            for name in source.namelist():
                target.writestr(name, source.read(name))
        result = strict.extract_xlsx_strict(stored.getvalue())
        self.assertEqual(result.canonical_bytes, expected)

    def test_non_archive_is_content_free_failure(self):
        with self.assertRaises(strict.StrictXlsxError) as exc:
            strict.extract_xlsx_strict(b"PRIVATE_SENTINEL")
        self.assertEqual(str(exc.exception), "invalid_archive")

    def test_invalid_workbook_is_a_distinct_content_free_failure(self):
        from openpyxl import Workbook

        stream = io.BytesIO()
        workbook = Workbook()
        sheet = workbook.active
        assert sheet is not None
        sheet["A1"] = "=1+1"
        workbook.save(stream)
        workbook.close()
        with self.assertRaises(strict.StrictXlsxError) as exc:
            strict.extract_xlsx_strict(stream.getvalue())
        self.assertEqual(str(exc.exception), "invalid_workbook")

    def test_workbook_returns_canonical_bytes_and_artifact_scoped_evidence(self):
        from openpyxl import Workbook

        from bri.ingestion._xlsx_strict_archive import read_package
        from bri.ingestion._xlsx_strict_parser import parse_package

        stream = io.BytesIO()
        workbook = Workbook()
        sheet = workbook.active
        assert sheet is not None
        sheet.title = "Résumé"
        sheet.append(["Description", "Amount"])
        sheet["A2"] = "PRIVATE_SENTINEL"
        sheet["B3"] = 4
        workbook.save(stream)
        workbook.close()
        original = stream.getvalue()
        canonical = parse_package(read_package(original))
        result = strict.extract_xlsx_strict(original)
        self.assertIs(type(result.canonical_bytes), bytes)
        self.assertEqual(result.canonical_bytes, canonical)
        self.assertEqual(result.evidence, strict.StrictXlsxEvidence(
            worksheet_identity="1", worksheet_title="Résumé", worksheet_range="A1:B3",
            extractor_version=1, canonicalization_version=1,
            original_sha256=hashlib.sha256(original).hexdigest(),
            canonical_sha256=hashlib.sha256(result.canonical_bytes).hexdigest(),
        ))
        with self.assertRaises(FrozenInstanceError):
            setattr(result, "canonical_bytes", b"")
        self.assertNotIn("PRIVATE_SENTINEL", repr(result))
