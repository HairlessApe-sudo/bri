import io
import unittest
import zipfile

from openpyxl import Workbook

from bri.ingestion.xlsx_extractor import XlsxExtractionError, extract_xlsx


def make_xlsx() -> bytes:
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "Policy"
    sheet.append(["rule_id", "policy_text", "formula_text"])
    sheet.append(["retention", "Synthetic records are retained for seven years.", "=1+1"])
    hidden = workbook.create_sheet("Hidden notes")
    hidden.append(["synthetic", "not published automatically"])
    hidden.sheet_state = "hidden"
    stream = io.BytesIO()
    workbook.save(stream)
    return stream.getvalue()


def add_external_link(content: bytes) -> bytes:
    source = io.BytesIO(content)
    target = io.BytesIO()
    with zipfile.ZipFile(source) as original, zipfile.ZipFile(target, "w") as changed:
        for info in original.infolist():
            changed.writestr(info, original.read(info.filename))
        changed.writestr("xl/externalLinks/externalLink1.xml", "<externalLink/>")
    return target.getvalue()


class ExtractXlsxTests(unittest.TestCase):
    def test_extracts_cells_and_keeps_formula_as_unexecuted_text(self):
        result = extract_xlsx(make_xlsx())

        self.assertEqual(result.sheets[0].title, "Policy")
        self.assertEqual(result.sheets[0].rows[1][1], "Synthetic records are retained for seven years.")
        self.assertEqual(result.sheets[0].rows[1][2], "=1+1")
        self.assertEqual(result.sheets[0].sheet_state, "visible")
        self.assertEqual(result.sheets[1].sheet_state, "hidden")

    def test_rejects_non_xlsx_content(self):
        with self.assertRaises(XlsxExtractionError):
            extract_xlsx(b"not an Excel workbook")

    def test_rejects_content_over_byte_limit(self):
        with self.assertRaises(XlsxExtractionError):
            extract_xlsx(make_xlsx(), max_bytes=8)

    def test_rejects_workbook_with_external_links(self):
        with self.assertRaises(XlsxExtractionError):
            extract_xlsx(add_external_link(make_xlsx()))

    def test_rejects_excessive_uncompressed_archive_size(self):
        with self.assertRaises(XlsxExtractionError):
            extract_xlsx(make_xlsx(), max_uncompressed_bytes=128)

    def test_rejects_cell_count_over_limit(self):
        with self.assertRaises(XlsxExtractionError):
            extract_xlsx(make_xlsx(), max_cells=1)


if __name__ == "__main__":
    unittest.main()
