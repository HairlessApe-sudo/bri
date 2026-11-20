"""Local, synthetic-only CSV intake core. Nothing activates it implicitly."""

from __future__ import annotations

import errno
import hashlib
import hmac
import json
import os
import re
import stat
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Protocol
from uuid import UUID, uuid4

MAX_CSV_BYTES = 5_000_000
MAX_CSV_ROWS = 10_000
MAX_CSV_COLUMNS = 50
MAX_EXTRACTED_BYTES = 20_000_000  # SQL completion octet_length limit.


class IntakeReason(str, Enum):
    STORAGE_CONFIGURATION = "storage_configuration"
    STORAGE_MISSING = "storage_missing"
    STORAGE_MISMATCH = "storage_mismatch"
    STORAGE_UNAVAILABLE = "storage_unavailable"
    INVALID_METADATA = "invalid_metadata"
    BYTE_LIMIT = "byte_limit"
    ROW_LIMIT = "row_limit"
    COLUMN_LIMIT = "column_limit"
    INVALID_UTF8 = "invalid_utf8"
    INVALID_CSV = "invalid_csv"
    INVALID_HEADERS = "invalid_headers"
    ROW_WIDTH = "row_width"


class CsvIntakeError(ValueError):
    """Stable, log-safe reason; never use raw storage or parser exceptions."""

    def __init__(self, reason: IntakeReason):
        super().__init__(reason.value)
        self.reason = reason

    @property
    def transient(self) -> bool:
        return self.reason in (IntakeReason.STORAGE_MISSING, IntakeReason.STORAGE_UNAVAILABLE)


@dataclass(frozen=True, slots=True)
class QuarantinedCsv:
    storage_key: str
    sha256: str
    byte_count: int


_KEY = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


def _check_content(content: bytes) -> None:
    if not isinstance(content, bytes):
        raise CsvIntakeError(IntakeReason.INVALID_METADATA)
    if len(content) > MAX_CSV_BYTES:
        raise CsvIntakeError(IntakeReason.BYTE_LIMIT)


def _tenant_namespace(verified_tenant_id: str) -> str:
    if not isinstance(verified_tenant_id, str) or not 0 < len(verified_tenant_id) <= 256:
        raise CsvIntakeError(IntakeReason.INVALID_METADATA)
    try:
        return hashlib.sha256(verified_tenant_id.encode("utf-8")).hexdigest()
    except UnicodeError:
        raise CsvIntakeError(IntakeReason.INVALID_METADATA) from None


def _validate_key(key: str) -> None:
    if not isinstance(key, str) or not _KEY.fullmatch(key):
        raise CsvIntakeError(IntakeReason.INVALID_METADATA)


def _private_dir(fd: int, reason: IntakeReason) -> os.stat_result:
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise CsvIntakeError(reason)
    return info


class LocalCsvQuarantine:
    """Explicitly injected, pre-provisioned owner-only directory on a local UNIX FS.

    Provision the absolute root with mode 0700 under trusted parents, outside
    all served trees and workspaces. Pass non-CWD workspace and web roots as
    ``excluded_roots``. Only the server may call this class: keys come from
    ``new_key`` and tenant IDs from verified authorization or a trusted job.
    The owning OS account is trusted; 0400 is not protection from that account.
    """

    def __init__(self, root: str | Path, *, excluded_roots: Sequence[str | Path] = ()):
        if os.name != "posix":
            raise CsvIntakeError(IntakeReason.STORAGE_CONFIGURATION)
        try:
            path = Path(root)
            if not path.is_absolute() or path.resolve(strict=True) != path:
                raise CsvIntakeError(IntakeReason.STORAGE_CONFIGURATION)
            excluded = (Path.cwd(), *(Path(item).resolve() for item in excluded_roots))
            if any(path.is_relative_to(base) or base.is_relative_to(path) for base in excluded):
                raise CsvIntakeError(IntakeReason.STORAGE_CONFIGURATION)
            with self._open_dir(path) as fd:
                info = _private_dir(fd, IntakeReason.STORAGE_CONFIGURATION)
        except (OSError, RuntimeError, ValueError, TypeError) as exc:
            if isinstance(exc, CsvIntakeError):
                raise
            raise CsvIntakeError(IntakeReason.STORAGE_CONFIGURATION) from None
        self._root = path
        self._root_identity = (info.st_dev, info.st_ino)

    @staticmethod
    def new_key() -> str:
        """Allocate once, server-side; retain and reuse for an ambiguous retry."""
        return str(uuid4())

    @staticmethod
    @contextmanager
    def _open_dir(path: str | Path, *, dir_fd: int | None = None) -> Iterator[int]:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=dir_fd)
        try:
            yield fd
        finally:
            os.close(fd)

    @contextmanager
    def _namespace(self, name: str, *, create: bool) -> Iterator[int]:
        try:
            with self._open_dir(self._root) as root_fd:
                info = _private_dir(root_fd, IntakeReason.STORAGE_CONFIGURATION)
                if (info.st_dev, info.st_ino) != self._root_identity:
                    raise CsvIntakeError(IntakeReason.STORAGE_CONFIGURATION)
                if create:
                    try:
                        os.mkdir(name, 0o700, dir_fd=root_fd)
                    except FileExistsError:
                        pass
                with self._open_dir(name, dir_fd=root_fd) as tenant_fd:
                    _private_dir(tenant_fd, IntakeReason.STORAGE_MISMATCH)
                    if create:
                        # Also sync on retry: a previous writer may have made the directory.
                        os.fsync(root_fd)
                    yield tenant_fd
        except FileNotFoundError:
            raise CsvIntakeError(IntakeReason.STORAGE_MISSING) from None
        except OSError as exc:
            reason = (IntakeReason.STORAGE_MISMATCH if exc.errno in (errno.ELOOP, errno.ENOTDIR)
                      else IntakeReason.STORAGE_UNAVAILABLE)
            raise CsvIntakeError(reason) from None

    @staticmethod
    def _read(tenant_fd: int, receipt: QuarantinedCsv) -> bytes:
        fd = os.open(receipt.storage_key, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                     dir_fd=tenant_fd)
        with os.fdopen(fd, "rb") as blob:
            info = os.fstat(blob.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o400 or info.st_size != receipt.byte_count):
                raise CsvIntakeError(IntakeReason.STORAGE_MISMATCH)
            content = blob.read(receipt.byte_count + 1)
        if (len(content) != receipt.byte_count or not hmac.compare_digest(
                hashlib.sha256(content).hexdigest(), receipt.sha256)):
            raise CsvIntakeError(IntakeReason.STORAGE_MISMATCH)
        return content

    def read_verified(self, verified_tenant_id: str, key: str, sha256: str,
                      byte_count: int) -> bytes:
        _validate_key(key)
        if (not isinstance(sha256, str) or not _SHA256.fullmatch(sha256)
                or type(byte_count) is not int or not 0 <= byte_count <= MAX_CSV_BYTES):
            raise CsvIntakeError(IntakeReason.INVALID_METADATA)
        namespace = _tenant_namespace(verified_tenant_id)
        with self._namespace(namespace, create=False) as tenant_fd:
            return self._read(tenant_fd, QuarantinedCsv(key, sha256, byte_count))

    def install(self, verified_tenant_id: str, key: str, content: bytes) -> QuarantinedCsv:
        """Publish once without replacing; same key and bytes may be retried.

        Interrupted staging files are intentionally retained, and are never
        addressable as blobs. Only the redundant staging name of a successful
        hard link is removed. No published name or unique content is deleted.
        """
        _validate_key(key)
        namespace = _tenant_namespace(verified_tenant_id)
        _check_content(content)
        receipt = QuarantinedCsv(key, hashlib.sha256(content).hexdigest(), len(content))
        with self._namespace(namespace, create=True) as tenant_fd:
            try:
                self._read(tenant_fd, receipt)
            except FileNotFoundError:
                self._publish(tenant_fd, receipt, content)
            os.fsync(tenant_fd)
        return receipt

    def _publish(self, tenant_fd: int, receipt: QuarantinedCsv, content: bytes) -> None:
        staging = f".pending-{uuid4().hex}"
        fd = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=tenant_fd)
        with os.fdopen(fd, "wb") as blob:
            blob.write(content)
            blob.flush()
            os.fchmod(blob.fileno(), 0o400)
            os.fsync(blob.fileno())
        try:
            os.link(staging, receipt.storage_key, src_dir_fd=tenant_fd, dst_dir_fd=tenant_fd,
                    follow_symlinks=False)
        except FileExistsError:
            # A concurrent writer won. Verify its blob without replacing it.
            self._read(tenant_fd, receipt)
        else:
            os.unlink(staging, dir_fd=tenant_fd)


@dataclass(frozen=True, slots=True)
class BoundedCsv:
    text: str = field(repr=False)
    extracted_sha256: str
    header_line_range: tuple[int, int]
    source_line_ranges: tuple[tuple[int, int], ...]

    @property
    def first_line(self) -> int:
        return self.header_line_range[0]

    @property
    def last_line(self) -> int:
        return (self.source_line_ranges[-1] if self.source_line_ranges
                else self.header_line_range)[1]


_UNQUOTED = re.compile(r'[^",\r\n]*')
_QUOTE = re.compile(r'""|"')


def _records(text: str) -> Iterator[tuple[list[str], tuple[int, int]]]:
    # Scan incrementally: no global csv.field_size_limit and no wide-row allocation.
    pos = 0
    line = 1
    while pos < len(text):
        first_line = line
        values: list[str] = []
        if text[pos] not in "\r\n":
            while True:
                if len(values) == MAX_CSV_COLUMNS:
                    raise CsvIntakeError(IntakeReason.COLUMN_LIMIT)
                if text.startswith('"', pos):
                    for quote in _QUOTE.finditer(text, pos + 1):
                        if quote.end() - quote.start() == 1:
                            literal = text[pos + 1:quote.start()]
                            line += literal.count("\r") + literal.count("\n") - literal.count("\r\n")
                            values.append(literal.replace('""', '"'))
                            pos = quote.end()
                            break
                    else:
                        raise CsvIntakeError(IntakeReason.INVALID_CSV)
                else:
                    match = _UNQUOTED.match(text, pos)
                    assert match is not None  # the pattern can always match an empty field
                    values.append(match[0])
                    pos = match.end()
                if text.startswith(",", pos):
                    pos += 1
                else:
                    break
        end_line = line
        if pos < len(text):
            if text[pos] not in "\r\n":
                raise CsvIntakeError(IntakeReason.INVALID_CSV)
            pos += 2 if text.startswith("\r\n", pos) else 1
            line += 1
        yield values, (first_line, end_line)


def extract_bounded_csv(content: bytes) -> BoundedCsv:
    """Parse bounded UTF-8 CSV; serialize literal strings as compact JSON.

    The JSON has ordered keys ``headers`` and ``rows``, no trailing newline,
    and retains Unicode, with JSON string escaping. No formula is evaluated.
    JSON escaping can expand even a valid CSV within the input limits past
    the separate 20,000,000-byte UTF-8 output limit. Such input fails with
    terminal ``invalid_csv``; the extraction is never truncated or rewritten.

    Physical provenance is one-based, inclusive, covers the header as well
    as all rows, and treats CRLF, CR and LF as physical line breaks even
    inside quoted cells. A final record terminator adds no empty row.
    """
    _check_content(content)
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise CsvIntakeError(IntakeReason.INVALID_UTF8) from None
    records = _records(text)
    header_record = next(records, None)
    if header_record is None:
        raise CsvIntakeError(IntakeReason.INVALID_HEADERS)
    headers, header_range = header_record
    if (not headers or any(not header.strip() for header in headers)
            or len(set(headers)) != len(headers)):
        raise CsvIntakeError(IntakeReason.INVALID_HEADERS)

    rows: list[list[str]] = []
    ranges: list[tuple[int, int]] = []
    for values, line_range in records:
        if len(rows) == MAX_CSV_ROWS:
            raise CsvIntakeError(IntakeReason.ROW_LIMIT)
        if len(values) != len(headers):
            raise CsvIntakeError(IntakeReason.ROW_WIDTH)
        rows.append(values)
        ranges.append(line_range)
    extracted = json.dumps({"headers": headers, "rows": rows}, ensure_ascii=False,
                           separators=(",", ":"))
    encoded = extracted.encode("utf-8")
    if len(encoded) > MAX_EXTRACTED_BYTES:
        raise CsvIntakeError(IntakeReason.INVALID_CSV)
    return BoundedCsv(extracted, hashlib.sha256(encoded).hexdigest(),
                      header_range, tuple(ranges))


@dataclass(frozen=True, slots=True)
class ClaimedCsvJob:
    job_id: UUID
    tenant_id: str
    storage_key: str
    sha256: str
    byte_count: int
    attempt: int


class CsvIntakeRepo(Protocol):
    """Trusted adapter: return only committed claims and fence transitions by attempt.

    The adapter takes tenant context from the claimed job, never the request.
    A transition must raise on stale fences or unacknowledged commits, not
    silently report success to the processor. Retry policy lives in the adapter.
    """

    def claim(self, job: UUID, correlation: UUID, /) -> ClaimedCsvJob | None: ...

    def complete(self, job: UUID, attempt: int, text: str, extracted_sha256: str,
                 first_line: int, last_line: int, correlation: UUID, /) -> None: ...

    def fail(self, job: UUID, attempt: int, reason: str, transient: bool,
             correlation: UUID, /) -> None: ...


class ProcessOutcome(str, Enum):
    NOT_CLAIMED = "not_claimed"
    COMPLETED = "completed"
    FAILED = "failed"  # This attempt failed; the repository may schedule another.


class CsvIntakeProcessor:
    """Run one explicitly dispatched attempt without opening a network connection."""

    def __init__(self, store: LocalCsvQuarantine, repo: CsvIntakeRepo):
        self._store = store
        self._repo = repo

    def process(self, job: UUID, correlation: UUID) -> ProcessOutcome:
        claimed = self._repo.claim(job, correlation)
        if claimed is None:
            return ProcessOutcome.NOT_CLAIMED
        if claimed.job_id != job or type(claimed.attempt) is not int or claimed.attempt < 1:
            raise CsvIntakeError(IntakeReason.INVALID_METADATA)
        try:
            content = self._store.read_verified(claimed.tenant_id, claimed.storage_key,
                                                claimed.sha256, claimed.byte_count)
            extracted = extract_bounded_csv(content)
        except CsvIntakeError as exc:
            self._repo.fail(job, claimed.attempt, exc.reason.value, exc.transient, correlation)
            return ProcessOutcome.FAILED

        # An adapter exception may mean an ambiguous commit. Do not send a
        # competing fail transition; let the trusted caller reconcile it.
        self._repo.complete(job, claimed.attempt, extracted.text, extracted.extracted_sha256,
                            extracted.first_line, extracted.last_line, correlation)
        return ProcessOutcome.COMPLETED
