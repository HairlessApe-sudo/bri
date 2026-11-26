import io
import random
import struct
import unittest
import warnings
import zipfile
import zlib


def make_zip(entries=(("xl/workbook.xml", b"synthetic"),), compression=zipfile.ZIP_DEFLATED):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression) as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return stream.getvalue()


class StrictArchiveTests(unittest.TestCase):
    def test_reads_standard_stored_and_deflated_members(self):
        from bri.ingestion._xlsx_strict_archive import read_package

        entries = (("[Content_Types].xml", b"types"), ("_rels/.rels", b"relationships"))
        for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            with self.subTest(method=method):
                self.assertEqual(read_package(make_zip(entries, method)), dict(entries))

    def assert_rejected(self, content, message):
        from bri.ingestion._xlsx_strict_archive import StrictArchiveError, read_package

        with self.assertRaises(StrictArchiveError) as caught:
            read_package(content)
        self.assertEqual(str(caught.exception), message)

    def test_rejects_ambiguous_names(self):
        for name in ("/xl/workbook.xml", "xl/../workbook.xml", "xl\\workbook.xml",
                     "xl//workbook.xml", "xl/%77orkbook.xml", "xl/workbook.xml.",
                     "xl/workbook.xml ", "xl/CON.xml", "xl/workbook.xml:", "xl/./workbook.xml"):
            with self.subTest(name=name):
                self.assert_rejected(make_zip(((name, b"data"),)), "Invalid ZIP member name.")

    def test_rejects_duplicate_names_case_aliases_and_file_prefixes(self):
        for names in (("xl/a.xml", "xl/a.xml"), ("xl/a.xml", "XL/A.XML"),
                      ("xl/a", "XL/A/child.xml")):
            with self.subTest(names=names), warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                self.assert_rejected(make_zip([(name, b"data") for name in names]),
                                     "Conflicting ZIP member names.")

    def test_rejects_unsupported_compression(self):
        self.assert_rejected(make_zip(compression=zipfile.ZIP_BZIP2),
                             "Unsupported ZIP member encoding.")

    def test_rejects_encryption_flags(self):
        content = bytearray(make_zip())
        central = content.index(b"PK\x01\x02")
        content[6] |= 1
        content[central + 8] |= 1
        self.assert_rejected(bytes(content), "Unsupported ZIP member encoding.")

    def test_rejects_invalid_zip_layout(self):
        content = make_zip()
        local_mismatch = bytearray(content)
        local_mismatch[30] = ord("y")
        for candidate in (b"not zip", b"prefix" + content, content + b"suffix", content[:-1],
                          bytes(local_mismatch)):
            with self.subTest(candidate_length=len(candidate)):
                self.assert_rejected(candidate, "Invalid ZIP structure.")

    def test_rejects_output_inconsistent_with_declared_size_and_crc(self):
        payload = b"synthetic suffixed output"
        content = bytearray(make_zip((("a.xml", payload),)))
        central = content.index(b"PK\x01\x02")
        crc = zlib.crc32(payload[:9])
        for pointer in (14, central + 16):
            struct.pack_into("<I", content, pointer, crc)
            struct.pack_into("<I", content, pointer + 8, 9)
        self.assert_rejected(bytes(content), "Invalid ZIP member data.")

    def test_rejects_bad_crc_even_when_local_and_central_agree(self):
        content = bytearray(make_zip())
        central = content.index(b"PK\x01\x02")
        struct.pack_into("<I", content, 14, 0)
        struct.pack_into("<I", content, central + 16, 0)
        self.assert_rejected(bytes(content), "Invalid ZIP member data.")

    def test_rejects_trailing_data_inside_compressed_member(self):
        content = bytearray(make_zip())
        central = content.index(b"PK\x01\x02")
        compressed = struct.unpack_from("<I", content, 18)[0]
        struct.pack_into("<I", content, 18, compressed + 1)
        struct.pack_into("<I", content, central + 20, compressed + 1)
        end = len(content) - 22
        struct.pack_into("<I", content, end + 16, central + 1)
        content[central:central] = b"x"
        self.assert_rejected(bytes(content), "Invalid ZIP member data.")

    def test_rejects_archive_entry_size_and_ratio_limits(self):
        cases = (
            (b"x" * 5_000_001, "ZIP archive exceeds size limit."),
            (make_zip((f"{i}.xml", b"") for i in range(257)), "ZIP archive exceeds entry limit."),
            (make_zip((("a.xml", b"x" * 100_000),)), "ZIP expansion exceeds limit."),
        )
        for content, message in cases:
            with self.subTest(message=message):
                self.assert_rejected(content, message)

    def test_enforces_member_expansion_limit(self):
        from bri.ingestion._xlsx_strict_archive import read_package

        prefix = random.Random(0).randbytes(250_000)
        payload = prefix + b"x" * (10_000_000 - len(prefix))
        self.assertEqual(read_package(make_zip((("a.xml", payload),)))["a.xml"], payload)
        self.assert_rejected(make_zip((("a.xml", payload + b"x"),)),
                             "ZIP expansion exceeds limit.")

    def test_enforces_aggregate_expansion_limit(self):
        from bri.ingestion._xlsx_strict_archive import read_package

        prefix = random.Random(0).randbytes(125_000)
        payload = prefix + b"x" * (5_000_000 - len(prefix))
        entries = [(f"{i}.xml", payload) for i in range(5)]
        self.assertEqual(read_package(make_zip(entries)), dict(entries))
        entries.append(("overflow.xml", b"x"))
        self.assert_rejected(make_zip(entries), "ZIP expansion exceeds limit.")

    def test_reads_openpyxl_output(self):
        from openpyxl import Workbook

        from bri.ingestion._xlsx_strict_archive import read_package

        workbook = Workbook()
        workbook["Sheet"].append(["synthetic", 2])
        stream = io.BytesIO()
        workbook.save(stream)
        parts = read_package(stream.getvalue())
        with zipfile.ZipFile(stream) as archive:
            self.assertEqual(parts, {name: archive.read(name) for name in archive.namelist()})

    def test_checks_streaming_zip_descriptor(self):
        from bri.ingestion._xlsx_strict_archive import read_package

        class Stream(io.BytesIO):
            def seek(self, *args):
                raise io.UnsupportedOperation

        stream = Stream()
        with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.comment = b"archive comment"
            archive.writestr("a.xml", b"synthetic")
        self.assertEqual(read_package(stream.getvalue()), {"a.xml": b"synthetic"})
        content = bytearray(stream.getvalue())
        descriptor = content.index(b"PK\x07\x08")
        content[descriptor + 4] ^= 1
        self.assert_rejected(bytes(content), "Invalid ZIP structure.")
