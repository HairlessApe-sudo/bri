"""Opt-in, Linux-only strict XLSX extraction; independent of the legacy extractor."""

from dataclasses import dataclass, field
from datetime import date, datetime, time as clock_time
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import sysconfig
import time

from ._xlsx_strict_schema import valid_header

MAX_INPUT_BYTES = 5_000_000
EXTRACTOR_VERSION = 1
CANONICALIZATION_VERSION = 1
MAX_CANONICAL_BYTES = 2_097_152
_FRAME_HEADER_BYTES = 5  # Success marker followed by unsigned 32-bit byte count.
MAX_OUTPUT_BYTES = MAX_CANONICAL_BYTES + _FRAME_HEADER_BYTES
CPU_SECONDS = 2
ADDRESS_SPACE_BYTES = 256 * 1024 * 1024
WALL_SECONDS = 5.0


class StrictXlsxError(ValueError):
    """Fail-closed extraction error with a fixed, content-free code."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class StrictXlsxEvidence:
    """Evidence for one worksheet in the artifact identified by original_sha256."""

    worksheet_identity: str
    worksheet_title: str
    worksheet_range: str
    extractor_version: int
    canonicalization_version: int
    original_sha256: str
    canonical_sha256: str


@dataclass(frozen=True, slots=True)
class StrictXlsxResult:
    """Canonical UTF-8 JSON and evidence derived from the same extraction."""

    canonical_bytes: bytes = field(repr=False)
    evidence: StrictXlsxEvidence


def _worker_command() -> list[str]:
    worker = Path(__file__).resolve().with_name("_xlsx_strict_worker.py")
    return [sys.executable, "-I", "-S", "-B", str(worker), str(CPU_SECONDS),
            str(ADDRESS_SPACE_BYTES), str(MAX_INPUT_BYTES), str(MAX_CANONICAL_BYTES),
            sysconfig.get_path("purelib")]


def _remaining(deadline: float) -> float:
    seconds = deadline - time.monotonic()
    if seconds <= 0:
        raise StrictXlsxError("timeout")
    return seconds


def _exchange(child: subprocess.Popen, content: bytes, deadline: float) -> tuple[bytearray, int, bool]:
    """Pump both pipes under one deadline; never collect more than the response cap."""
    output = bytearray()
    sent = 0
    assert child.stdin is not None and child.stdout is not None
    with selectors.DefaultSelector() as mux, memoryview(content) as source:
        if content:
            os.set_blocking(child.stdin.fileno(), False)
            mux.register(child.stdin, selectors.EVENT_WRITE)
        else:
            child.stdin.close()
        os.set_blocking(child.stdout.fileno(), False)
        mux.register(child.stdout, selectors.EVENT_READ)
        while mux.get_map():
            for key, event in mux.select(_remaining(deadline)):
                if event == selectors.EVENT_WRITE:
                    try:
                        sent += os.write(key.fd, source[sent:sent + 65536])
                    except BlockingIOError:
                        continue
                    except BrokenPipeError:
                        pass
                    else:
                        if sent < len(content):
                            continue
                    mux.unregister(key.fileobj)
                    child.stdin.close()
                else:
                    try:
                        data = os.read(key.fd, min(65536, MAX_OUTPUT_BYTES + 1 - len(output)))
                    except BlockingIOError:
                        continue
                    if not data:
                        mux.unregister(key.fileobj)
                        child.stdout.close()
                    elif len(output) + len(data) > MAX_OUTPUT_BYTES:
                        raise StrictXlsxError("output_limit")
                    else:
                        output.extend(data)
    return output, child.wait(timeout=_remaining(deadline)), sent == len(content)


def _run(content: bytes) -> bytes:
    deadline = time.monotonic() + WALL_SECONDS
    try:
        child = subprocess.Popen(
            _worker_command(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, close_fds=True, bufsize=0, env={},
            start_new_session=True,
        )
        try:
            response, status, complete = _exchange(child, content, deadline)
        finally:
            # Also runs for caller interruption (KeyboardInterrupt/SystemExit).
            if child.poll() is None:
                child.kill()
                child.wait()
            if child.stdin is not None:
                child.stdin.close()
            if child.stdout is not None:
                child.stdout.close()
    except subprocess.TimeoutExpired:
        failure_code = "timeout"
    except StrictXlsxError:
        raise
    except (OSError, ValueError):
        failure_code = "worker_failure"
    else:
        return _checked_response(response, status, complete)
    raise StrictXlsxError(failure_code)


def _checked_response(response: bytearray, status: int, complete: bool) -> bytes:
    failure = {
        2: "invalid_archive", 3: "invalid_workbook", 4: "resource_limit",
        5: "output_limit", -signal.SIGXCPU: "resource_limit",
    }.get(status)
    if failure is not None and not response:
        raise StrictXlsxError(failure)
    if (status != 0 or not complete or len(response) < _FRAME_HEADER_BYTES
            or not response.startswith(b"\x00")):
        raise StrictXlsxError("worker_failure")
    declared = int.from_bytes(response[1:_FRAME_HEADER_BYTES], "big")
    if declared != len(response) - _FRAME_HEADER_BYTES or not declared:
        raise StrictXlsxError("worker_failure")
    if declared > MAX_CANONICAL_BYTES:
        raise StrictXlsxError("output_limit")
    return bytes(memoryview(response)[_FRAME_HEADER_BYTES:])


# Canonical v1 protocol limits mirror the worker parser. Keep the XML parser
# and its dependencies out of the parent process.
_MAX_ROWS, _MAX_COLUMNS, _MAX_CELLS, _MAX_TEXT = 10_000, 64, 100_000, 4096
_STRUCTURE = re.compile(rb'["\\\[\]{},:]')
_COORDINATE = r'([A-Z]{1,2})([1-9][0-9]{0,4})'
_RANGE = re.compile(_COORDINATE + '(?::' + _COORDINATE + ')?')
_INVALID_XML_CHAR = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]')
_OOXML_ESCAPE = re.compile(r'_x[0-9a-fA-F]{4}_')
_BAD_TITLE = re.compile(r'[\x00-\x1f\[\]:*?/\\]')
_SHEET_ID = re.compile(r'[1-9][0-9]{0,9}')
_NUMBER = re.compile(r'-?[1-9](?:\.([0-9]{0,254}[1-9]))?e(0|-?[1-9][0-9]{0,3})')
_CALENDAR = {'date': (date.fromisoformat, 10, 10),
             'time': (clock_time.fromisoformat, 8, 15),
             'datetime': (datetime.fromisoformat, 19, 26)}


def _guard_json_structure(canonical: bytes) -> None:
    # Scan without building a token list. JSON grammar is checked by json.loads;
    # this guard bounds depth and object/element counts before that allocation.
    depth = containers = separators = 0
    in_string = False
    escaped_at = -1
    for match in _STRUCTURE.finditer(canonical):
        token = match[0]
        if in_string:
            if match.start() == escaped_at:
                continue
            if token == b'\\':
                escaped_at = match.end()
            elif token == b'"':
                in_string = False
        elif token == b'"':
            in_string = True
        elif token in (b'[', b'{'):
            depth += 1
            containers += 1
            if depth > 4 or containers > _MAX_ROWS + _MAX_CELLS + 3:
                raise StrictXlsxError("worker_failure")
        elif token in (b']', b'}'):
            depth -= 1
            if depth < 0:
                raise StrictXlsxError("worker_failure")
        elif token in (b',', b':'):
            separators += 1
            if separators > _MAX_ROWS + 2 * _MAX_CELLS + 10:
                raise StrictXlsxError("worker_failure")
        else:
            raise StrictXlsxError("worker_failure")
    if in_string or depth:
        raise StrictXlsxError("worker_failure")


def _version_token(token: str) -> int:
    # Version is the only JSON number. Reject floats, constants, and arbitrarily
    # large integer tokens without converting them to numbers.
    if token != str(CANONICALIZATION_VERSION):
        raise ValueError
    return CANONICALIZATION_VERSION


def _valid_cell(cell: object) -> bool:
    if type(cell) is not list or len(cell) != 2 or type(cell[0]) is not str:
        return False
    tag, value = cell
    if tag == "boolean":
        return type(value) is bool
    if type(value) is not str:
        return False
    if tag == "text":
        return (len(value) <= _MAX_TEXT and not _INVALID_XML_CHAR.search(value)
                and not _OOXML_ESCAPE.search(value) and len(value.encode("utf-8")) <= _MAX_TEXT)
    if tag == "number":
        if value == "0":
            return True
        if not (match := _NUMBER.fullmatch(value)):
            return False
        fractional, exponent = match.groups()
        adjusted = int(exponent)
        return -1024 <= adjusted - len(fractional or "") and adjusted <= 1024
    if tag in _CALENDAR:
        parse, short, long = _CALENDAR[tag]
        if len(value) not in (short, long):
            return False
        stamp = parse(value)
        return getattr(stamp, "tzinfo", None) is None and stamp.isoformat() == value
    return False


def _column_index(name: str) -> int:
    index = 0
    for letter in name:
        index = index * 26 + ord(letter) - ord('A') + 1
    return index


def _valid_rows(rows: object, cell_range: object) -> bool:
    if type(rows) is not list or not rows:
        return False
    if type(cell_range) is not str or not (match := _RANGE.fullmatch(cell_range)):
        return False
    start_col, start_row, end_col, end_row = match.groups()
    if (start_col, start_row) != ('A', '1') or (end_col, end_row) == ('A', '1'):
        return False  # Anchored at A1; a single cell has no colon.
    width, height = _column_index(end_col or 'A'), int(end_row or '1')
    if not (height <= _MAX_ROWS and width <= _MAX_COLUMNS
            and len(rows) == height and height * width <= _MAX_CELLS):
        return False
    for index, row in enumerate(rows):
        if type(row) is not list or len(row) != width:
            return False
        if any(cell is not None and not _valid_cell(cell) for cell in row):
            return False
        if index == 0 and not valid_header(row):
            return False
    return any(cell is not None for cell in rows[-1])


def _canonical_metadata(canonical: bytes) -> tuple[int, str, str, str]:
    _guard_json_structure(canonical)
    try:
        document = json.loads(canonical.decode("utf-8"), parse_int=_version_token,
                              parse_float=_version_token, parse_constant=_version_token)
        if type(document) is not dict or document.keys() != {"rows", "version", "worksheet"}:
            raise ValueError
        version, sheet = document["version"], document["worksheet"]
        if (type(version) is not int or version != CANONICALIZATION_VERSION
                or type(sheet) is not dict or sheet.keys() != {"identity", "title", "range"}):
            raise ValueError
        identity, title, cell_range = sheet["identity"], sheet["title"], sheet["range"]
        if (type(identity) is not str or not _SHEET_ID.fullmatch(identity) or int(identity) > 4_294_967_295
                or type(title) is not str or not 0 < len(title) <= 31 or _BAD_TITLE.search(title)
                or _INVALID_XML_CHAR.search(title) or _OOXML_ESCAPE.search(title)
                or title.startswith("'") or title.endswith("'")
                or not _valid_rows(document["rows"], cell_range)):
            raise ValueError
        # Compare the whole frame, not a header reconstructed from its suffix.
        # Also rejects duplicate keys, nonminimal escapes, and extra whitespace.
        encoded = json.dumps(document, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        if encoded == canonical:
            return version, identity, title, cell_range
    except ValueError:
        pass
    raise StrictXlsxError("worker_failure")


def extract_xlsx_strict(content: bytes) -> StrictXlsxResult:
    """Return canonical bytes with evidence, or raise a content-free StrictXlsxError.

    Linux process isolation here bounds parser resources; it is not a general
    filesystem or network sandbox. The strict OOXML parser handles XML policy.
    """
    if type(content) is not bytes:
        raise StrictXlsxError("invalid_input")
    if len(content) > MAX_INPUT_BYTES:
        raise StrictXlsxError("input_limit")
    if sys.platform != "linux":
        raise StrictXlsxError("worker_unavailable")
    canonical = _run(content)
    version, identity, title, cell_range = _canonical_metadata(canonical)
    evidence = StrictXlsxEvidence(
        worksheet_identity=identity, worksheet_title=title, worksheet_range=cell_range,
        extractor_version=EXTRACTOR_VERSION, canonicalization_version=version,
        original_sha256=hashlib.sha256(content).hexdigest(),
        canonical_sha256=hashlib.sha256(canonical).hexdigest(),
    )
    return StrictXlsxResult(canonical, evidence)
