"""Text-only PDF extraction with byte/page limits and page provenance."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from io import BytesIO

from pypdf import PdfReader
from pypdf.errors import PdfReadError


class PdfExtractionError(ValueError):
    """Raised when a PDF is invalid, unsupported, or exceeds safe limits."""


@dataclass(frozen=True, slots=True)
class ExtractedPdfPage:
    page_number: int
    text: str


@dataclass(frozen=True, slots=True)
class ExtractedPdf:
    pages: tuple[ExtractedPdfPage, ...]
    content_sha256: str


def extract_pdf(
    content: bytes,
    *,
    max_bytes: int = 20_000_000,
    max_pages: int = 500,
) -> ExtractedPdf:
    """Extract selectable text only; never render, execute, or follow PDF content."""
    if not isinstance(content, bytes):
        raise PdfExtractionError("PDF content must be bytes")
    if max_bytes < 1 or max_pages < 1:
        raise PdfExtractionError("Extraction limits must be positive")
    if len(content) > max_bytes:
        raise PdfExtractionError("PDF exceeds the configured byte limit")
    if b"%PDF-" not in content[:1024]:
        raise PdfExtractionError("File does not have a PDF header")

    try:
        reader = PdfReader(BytesIO(content), strict=True)
        if reader.is_encrypted:
            raise PdfExtractionError("Encrypted PDFs are not supported")
        if len(reader.pages) > max_pages:
            raise PdfExtractionError("PDF exceeds the configured page limit")
        pages = tuple(
            ExtractedPdfPage(page_number=index, text=page.extract_text() or "")
            for index, page in enumerate(reader.pages, start=1)
        )
    except PdfExtractionError:
        raise
    except (PdfReadError, ValueError, KeyError, IndexError, TypeError) as exc:
        raise PdfExtractionError("PDF could not be safely parsed") from exc

    if not any(page.text.strip() for page in pages):
        raise PdfExtractionError("PDF contains no selectable text; OCR is not supported")

    return ExtractedPdf(
        pages=pages,
        content_sha256=hashlib.sha256(content).hexdigest(),
    )
