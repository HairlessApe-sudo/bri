"""Resource-bounded XLSX extraction without formula execution or network access."""

from __future__ import annotations

import hashlib
import io
import zipfile
from dataclasses import dataclass
from datetime import date, datetime, time
from pathlib import PurePosixPath

from openpyxl import load_workbook
from openpyxl.xml import DEFUSEDXML


class XlsxExtractionError(ValueError):
    """Raised when an XLSX file is invalid, unsupported, or exceeds limits."""


@dataclass(frozen=True, slots=True)
class ExtractedWorksheet:
    title: str
    sheet_state: str
    rows: tuple[tuple[str | None, ...], ...]
    source_row_numbers: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class ExtractedXlsx:
    sheets: tuple[ExtractedWorksheet, ...]
    content_sha256: str


def _cell_text(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    return str(value)


def extract_xlsx(
    content: bytes,
    *,
    max_bytes: int = 20_000_000,
    max_uncompressed_bytes: int = 100_000_000,
    max_entries: int = 20_000,
    max_sheets: int = 50,
    max_cells: int = 250_000,
    max_rows_per_sheet: int = 100_000,
    max_columns: int = 512,
) -> ExtractedXlsx:
    """Extract XLSX cells while retaining sheet and row provenance.

    Formulas remain literal strings; macros and external-link relationships are
    rejected. Hidden worksheets are retained with their visibility state so a
    reviewer can govern them explicitly rather than silently dropping content.
    """
    if not isinstance(content, bytes):
        raise XlsxExtractionError("XLSX content must be bytes")
    limits = (
        max_bytes,
        max_uncompressed_bytes,
        max_entries,
        max_sheets,
        max_cells,
        max_rows_per_sheet,
        max_columns,
    )
    if any(limit < 1 for limit in limits):
        raise XlsxExtractionError("Extraction limits must be positive")
    if len(content) > max_bytes:
        raise XlsxExtractionError("XLSX exceeds the configured byte limit")
    if not content.startswith(b"PK\x03\x04"):
        raise XlsxExtractionError("File is not an XLSX zip archive")
    if not DEFUSEDXML:
        raise XlsxExtractionError("Secure XML parser support is unavailable")

    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            infos = archive.infolist()
            if len(infos) > max_entries:
                raise XlsxExtractionError("XLSX exceeds the configured archive-entry limit")
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise XlsxExtractionError("XLSX contains duplicate archive paths")
            for info in infos:
                path = PurePosixPath(info.filename)
                if path.is_absolute() or ".." in path.parts:
                    raise XlsxExtractionError("XLSX contains an unsafe archive path")
                if info.flag_bits & 0x1:
                    raise XlsxExtractionError("Encrypted XLSX entries are not supported")
            if sum(info.file_size for info in infos) > max_uncompressed_bytes:
                raise XlsxExtractionError("XLSX exceeds the configured uncompressed-size limit")
            if "[Content_Types].xml" not in names or "xl/workbook.xml" not in names:
                raise XlsxExtractionError("XLSX archive is missing required workbook files")
            lowered_names = [name.casefold() for name in names]
            if any("externallinks/" in name for name in lowered_names):
                raise XlsxExtractionError("XLSX external links are not supported")
            if any(name.endswith("xl/vbaproject.bin") for name in lowered_names):
                raise XlsxExtractionError("Macro-enabled workbooks are not supported")
            content_types = archive.read("[Content_Types].xml")
            if b"macroEnabled" in content_types or b"vbaProject" in content_types:
                raise XlsxExtractionError("Macro-enabled workbooks are not supported")
    except XlsxExtractionError:
        raise
    except (zipfile.BadZipFile, OSError, KeyError, ValueError) as exc:
        raise XlsxExtractionError("XLSX archive could not be safely inspected") from exc

    workbook = None
    try:
        workbook = load_workbook(
            io.BytesIO(content),
            read_only=True,
            data_only=False,
            keep_links=False,
        )
        if len(workbook.worksheets) > max_sheets:
            raise XlsxExtractionError("XLSX exceeds the configured worksheet limit")

        total_cells = 0
        sheets: list[ExtractedWorksheet] = []
        for worksheet in workbook.worksheets:
            if worksheet.max_row and worksheet.max_row > max_rows_per_sheet:
                raise XlsxExtractionError("XLSX worksheet exceeds the configured row limit")
            if worksheet.max_column and worksheet.max_column > max_columns:
                raise XlsxExtractionError("XLSX worksheet exceeds the configured column limit")
            sheet_rows: list[tuple[str | None, ...]] = []
            row_numbers: list[int] = []
            for row_number, row in enumerate(worksheet.iter_rows(), start=1):
                total_cells += len(row)
                if total_cells > max_cells:
                    raise XlsxExtractionError("XLSX exceeds the configured cell limit")
                sheet_rows.append(tuple(_cell_text(cell.value) for cell in row))
                row_numbers.append(row_number)
            sheets.append(
                ExtractedWorksheet(
                    title=worksheet.title,
                    sheet_state=worksheet.sheet_state,
                    rows=tuple(sheet_rows),
                    source_row_numbers=tuple(row_numbers),
                )
            )
    except XlsxExtractionError:
        raise
    except Exception as exc:
        raise XlsxExtractionError("XLSX workbook could not be safely parsed") from exc
    finally:
        if workbook is not None:
            workbook.close()

    if not sheets:
        raise XlsxExtractionError("XLSX contains no worksheets")
    return ExtractedXlsx(
        sheets=tuple(sheets),
        content_sha256=hashlib.sha256(content).hexdigest(),
    )
