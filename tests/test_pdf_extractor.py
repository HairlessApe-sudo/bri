import io
import unittest

from bri.ingestion.pdf_extractor import PdfExtractionError, extract_pdf


def make_pdf(text: str) -> bytes:
    escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    stream = f"BT /F1 12 Tf 20 70 Td ({escaped}) Tj ET".encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 100] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    result = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, body in enumerate(objects, start=1):
        offsets.append(len(result))
        result.extend(f"{index} 0 obj\n".encode("ascii"))
        result.extend(body + b"\nendobj\n")
    xref_offset = len(result)
    result.extend(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    result.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        result.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    result.extend(
        f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    )
    return bytes(result)


class ExtractPdfTests(unittest.TestCase):
    def test_extracts_text_with_page_provenance_and_hash(self):
        content = make_pdf("Synthetic policy text for testing.")

        result = extract_pdf(content)

        self.assertEqual(len(result.pages), 1)
        self.assertEqual(result.pages[0].page_number, 1)
        self.assertIn("Synthetic policy text for testing.", result.pages[0].text)
        self.assertEqual(len(result.content_sha256), 64)

    def test_rejects_non_pdf_content(self):
        with self.assertRaises(PdfExtractionError):
            extract_pdf(b"not a PDF")

    def test_rejects_content_over_byte_limit(self):
        with self.assertRaises(PdfExtractionError):
            extract_pdf(make_pdf("small"), max_bytes=8)

    def test_rejects_pdf_without_selectable_text(self):
        with self.assertRaises(PdfExtractionError):
            extract_pdf(make_pdf(""))


if __name__ == "__main__":
    unittest.main()
