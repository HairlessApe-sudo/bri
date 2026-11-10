import hashlib
import unittest

from bri.ingestion.csv_extractor import CsvExtractionError, extract_csv


class ExtractCsvTests(unittest.TestCase):
    def test_extracts_headers_rows_and_source_line_ranges(self):
        content = b"policy_id,title\nP-1,Records policy\nP-2,Retention policy\n"

        result = extract_csv(content)

        self.assertEqual(result.headers, ("policy_id", "title"))
        self.assertEqual(result.rows, (("P-1", "Records policy"), ("P-2", "Retention policy")))
        self.assertEqual(result.source_line_ranges, ((2, 2), (3, 3)))
        self.assertEqual(result.content_sha256, hashlib.sha256(content).hexdigest())

    def test_accepts_utf8_bom_and_tracks_multiline_record_lines(self):
        content = "\ufeffid,text\n1,\"first line\nsecond line\"\n".encode("utf-8")

        result = extract_csv(content)

        self.assertEqual(result.headers, ("id", "text"))
        self.assertEqual(result.rows, (("1", "first line\nsecond line"),))
        self.assertEqual(result.source_line_ranges, ((2, 3),))

    def test_rejects_content_over_byte_limit(self):
        with self.assertRaises(CsvExtractionError):
            extract_csv(b"a\n1234\n", max_bytes=5)

    def test_rejects_invalid_utf8(self):
        with self.assertRaises(CsvExtractionError):
            extract_csv(b"a\n\xff\n")

    def test_rejects_inconsistent_row_width(self):
        with self.assertRaises(CsvExtractionError):
            extract_csv(b"a,b\n1,2\n3\n")

    def test_rejects_malformed_csv_quoting(self):
        with self.assertRaises(CsvExtractionError):
            extract_csv(b"a,b\n1,\"unfinished\n")

    def test_rejects_empty_or_duplicate_headers(self):
        for content in (b"\n", b"a,a\n1,2\n", b"a,\n1,2\n"):
            with self.subTest(content=content):
                with self.assertRaises(CsvExtractionError):
                    extract_csv(content)

    def test_rejects_row_count_over_limit(self):
        with self.assertRaises(CsvExtractionError):
            extract_csv(b"a\n1\n2\n", max_rows=1)


if __name__ == "__main__":
    unittest.main()
