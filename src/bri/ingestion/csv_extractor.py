"""Safe, deterministic CSV extraction with row-level source provenance."""

from __future__ import annotations

import csv
import hashlib
import io
from dataclasses import dataclass


class CsvExtractionError(ValueError):
    """Raised when CSV input is invalid or exceeds configured limits."""


@dataclass(frozen=True, slots=True)
class ExtractedCsv:
    headers: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]
    source_line_ranges: tuple[tuple[int, int], ...]
    content_sha256: str


def extract_csv(
    content: bytes,
    *,
    max_bytes: int = 10_000_000,
    max_rows: int = 100_000,
) -> ExtractedCsv:
    """Parse UTF-8 CSV without evaluating cell content.

    Source line ranges use one-based physical line numbers and retain multiline
    fields' complete ranges. The content hash covers the exact original bytes,
    including any UTF-8 BOM. Formula-like cell text is preserved literally.
    """
    if not isinstance(content, bytes):
        raise CsvExtractionError("CSV content must be bytes")
    if max_bytes < 1 or max_rows < 1:
        raise CsvExtractionError("Extraction limits must be positive")
    if len(content) > max_bytes:
        raise CsvExtractionError("CSV exceeds the configured byte limit")

    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise CsvExtractionError("CSV must be valid UTF-8") from exc

    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    try:
        headers = next(reader, None)
        if not headers or any(not header.strip() for header in headers):
            raise CsvExtractionError("CSV must have non-empty column headers")
        if len(set(headers)) != len(headers):
            raise CsvExtractionError("CSV column headers must be unique")

        rows: list[tuple[str, ...]] = []
        line_ranges: list[tuple[int, int]] = []
        previous_line = reader.line_num
        for row in reader:
            if len(rows) >= max_rows:
                raise CsvExtractionError("CSV exceeds the configured row limit")
            if len(row) != len(headers):
                raise CsvExtractionError(
                    f"CSV row ending at line {reader.line_num} has an unexpected number of columns"
                )
            rows.append(tuple(row))
            line_ranges.append((previous_line + 1, reader.line_num))
            previous_line = reader.line_num
    except csv.Error as exc:
        raise CsvExtractionError("CSV syntax is invalid") from exc

    return ExtractedCsv(
        headers=tuple(headers),
        rows=tuple(rows),
        source_line_ranges=tuple(line_ranges),
        content_sha256=hashlib.sha256(content).hexdigest(),
    )
