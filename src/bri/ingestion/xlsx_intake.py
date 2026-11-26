"""Private local quarantine and explicit durable processing for strict XLSX intake."""

from __future__ import annotations

import errno
import hashlib
import hmac
import os
import re
import stat
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from threading import Lock
from typing import Protocol
from uuid import UUID, uuid4

from .xlsx_strict import (
    EXTRACTOR_VERSION,
    MAX_CANONICAL_BYTES,
    MAX_INPUT_BYTES,
    StrictXlsxError,
    StrictXlsxEvidence,
    StrictXlsxResult,
    _canonical_metadata,
    extract_xlsx_strict,
)


class XlsxIntakeReason(StrEnum):
    UNSUPPORTED_WORKBOOK = "unsupported_workbook"
    RESOURCE_LIMIT = "resource_limit"
    INTEGRITY_FAILURE = "integrity_failure"
    PROCESSING_FAILED = "processing_failed"
    INFRASTRUCTURE_UNAVAILABLE = "infrastructure_unavailable"


class XlsxIntakeError(ValueError):
    """Content-free failure reason safe to persist on an intake attempt."""

    def __init__(self, reason: XlsxIntakeReason):
        super().__init__(reason.value)
        self.reason = reason

    @property
    def transient(self) -> bool:
        return self.reason is XlsxIntakeReason.INFRASTRUCTURE_UNAVAILABLE


@dataclass(frozen=True, slots=True)
class QuarantinedXlsx:
    artifact_key: str
    original_sha256: str
    byte_count: int


_SHA256 = re.compile(r"[0-9a-f]{64}")
_INTEGRITY = XlsxIntakeReason.INTEGRITY_FAILURE
_INFRASTRUCTURE = XlsxIntakeReason.INFRASTRUCTURE_UNAVAILABLE
_DIR_FLAGS = os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0) | getattr(os, 'O_NOFOLLOW', 0)


def _uuid_text(value: UUID | str) -> str:
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, str) and len(value) == 36:
        try:
            if str(UUID(value)) == value:
                return value
        except ValueError:
            pass
    raise XlsxIntakeError(_INTEGRITY)


def _receipt(key: str, digest: str, count: int) -> QuarantinedXlsx:
    if not isinstance(key, str) or _uuid_text(key) != key:
        raise XlsxIntakeError(_INTEGRITY)
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest) or type(count) is not int or count < 0:
        raise XlsxIntakeError(_INTEGRITY)
    if count > MAX_INPUT_BYTES:
        raise XlsxIntakeError(XlsxIntakeReason.RESOURCE_LIMIT)
    return QuarantinedXlsx(key, digest, count)


def _namespace(tenant: str, job: UUID | str) -> str:
    # Use the same exact text identity as CSV; never normalize or use it as a path.
    if not isinstance(tenant, str) or not 0 < len(tenant) <= 256:
        raise XlsxIntakeError(_INTEGRITY)
    try:
        tenant_bytes = tenant.encode('utf-8')
    except UnicodeError:
        raise XlsxIntakeError(_INTEGRITY) from None
    job_bytes = UUID(_uuid_text(job)).bytes
    binding = b'bri:xlsx-quarantine:v2\0' + len(tenant_bytes).to_bytes(4, 'big') + tenant_bytes + job_bytes
    return hashlib.sha256(binding).hexdigest()


def _private_dir(fd: int, reason: XlsxIntakeReason) -> os.stat_result:
    info = os.fstat(fd)
    if info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise XlsxIntakeError(reason)
    return info


class LocalXlsxQuarantine:
    """Use a dedicated, pre-provisioned 0700 root on a local POSIX filesystem.

    Pass the CSV quarantine and any non-CWD workspace/web roots as excluded
    roots. The owning OS account and the configured root's parents are trusted.
    Only the server chooses artifact keys and supplies verified tenant/job IDs.
    """

    def __init__(self, root: str | Path, *, excluded_roots: Sequence[str | Path] = ()):
        if os.name != 'posix':
            raise XlsxIntakeError(_INFRASTRUCTURE)
        try:
            path = Path(root)
            if not path.is_absolute() or path.resolve(strict=True) != path:
                raise XlsxIntakeError(_INFRASTRUCTURE)
            excluded = (Path.cwd().resolve(), *(Path(other).resolve() for other in excluded_roots))
            if any(path.is_relative_to(base) or base.is_relative_to(path) for base in excluded):
                raise XlsxIntakeError(_INFRASTRUCTURE)
            self._root = path
            with self._open_root() as fd:
                info = _private_dir(fd, _INFRASTRUCTURE)
                self._identity = (info.st_dev, info.st_ino)
        except (OSError, RuntimeError, TypeError, ValueError):
            raise XlsxIntakeError(_INFRASTRUCTURE) from None

    @staticmethod
    def new_key() -> str:
        return str(uuid4())

    @contextmanager
    def _open_root(self) -> Iterator[int]:
        fd = os.open(self._root.anchor, _DIR_FLAGS)
        try:
            for part in self._root.parts[1:]:
                child = os.open(part, _DIR_FLAGS, dir_fd=fd)
                os.close(fd)
                fd = child
            yield fd
        finally:
            os.close(fd)

    @contextmanager
    def _open_namespace(self, namespace: str, *, create: bool) -> Iterator[int]:
        try:
            with self._open_root() as root_fd:
                info = _private_dir(root_fd, _INFRASTRUCTURE)
                if (info.st_dev, info.st_ino) != self._identity:
                    raise XlsxIntakeError(_INFRASTRUCTURE)
                try:
                    if create:
                        try:
                            os.mkdir(namespace, 0o700, dir_fd=root_fd)
                        except FileExistsError:
                            pass
                        os.fsync(root_fd)
                    fd = os.open(namespace, _DIR_FLAGS, dir_fd=root_fd)
                    try:
                        _private_dir(fd, _INTEGRITY)
                        yield fd
                    finally:
                        os.close(fd)
                except OSError as exc:
                    if exc.errno in (errno.ENOENT, errno.ELOOP, errno.ENOTDIR):
                        raise XlsxIntakeError(_INTEGRITY) from None
                    raise
        except OSError:
            raise XlsxIntakeError(_INFRASTRUCTURE) from None

    @staticmethod
    def _read(fd: int, receipt: QuarantinedXlsx) -> bytes:
        item = os.open(receipt.artifact_key, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(item, 'rb') as blob:
            info = os.fstat(blob.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o400 or info.st_size != receipt.byte_count):
                raise XlsxIntakeError(_INTEGRITY)
            content = blob.read(receipt.byte_count + 1)
        if (len(content) != receipt.byte_count or not hmac.compare_digest(
                hashlib.sha256(content).hexdigest(), receipt.original_sha256)):
            raise XlsxIntakeError(_INTEGRITY)
        return content

    def read_verified(self, tenant_id: str, job_id: UUID | str, artifact_key: str,
                      original_sha256: str, byte_count: int) -> bytes:
        receipt = _receipt(artifact_key, original_sha256, byte_count)
        with self._open_namespace(_namespace(tenant_id, job_id), create=False) as fd:
            return self._read(fd, receipt)

    def install(self, tenant_id: str, job_id: UUID | str, artifact_key: str,
                content: bytes) -> QuarantinedXlsx:
        """Publish without replacement; retry identical bytes after ambiguous I/O."""
        if type(content) is not bytes:
            raise XlsxIntakeError(_INTEGRITY)
        if len(content) > MAX_INPUT_BYTES:
            raise XlsxIntakeError(XlsxIntakeReason.RESOURCE_LIMIT)
        receipt = _receipt(artifact_key, hashlib.sha256(content).hexdigest(), len(content))
        with self._open_namespace(_namespace(tenant_id, job_id), create=True) as fd:
            try:
                self._read(fd, receipt)
            except FileNotFoundError:
                self._publish(fd, receipt, content)
            os.fsync(fd)
        return receipt

    def _publish(self, fd: int, receipt: QuarantinedXlsx, content: bytes) -> None:
        pending = f'.pending-{uuid4().hex}'
        item = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        try:
            with os.fdopen(item, 'wb') as blob:
                blob.write(content)
                blob.flush()
                os.fchmod(blob.fileno(), 0o400)
                os.fsync(blob.fileno())
            try:
                os.link(pending, receipt.artifact_key, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            except FileExistsError:
                self._read(fd, receipt)
        finally:
            os.unlink(pending, dir_fd=fd)


@dataclass(frozen=True, slots=True)
class ClaimedXlsxJob:
    job_id: UUID
    tenant_id: str
    artifact_key: str
    byte_count: int
    original_sha256: str
    attempt: int


class XlsxIntakeRepo(Protocol):
    """Each call closes its own transaction before returning.

    Return only a committed claim. A transition must raise when unacknowledged
    or fenced out. SQL decides retry eligibility from the fixed reason alone.
    """

    def claim(self, job: UUID, correlation: UUID, /) -> ClaimedXlsxJob | None: ...

    def complete(self, job: UUID, attempt: int, canonical_text: str, canonical_sha256: str,
                 extractor_version: int, canonicalization_version: int, sheet_id: str,
                 sheet_title: str, cell_range: str, correlation: UUID, /) -> None: ...

    def fail(self, job: UUID, attempt: int, reason: str, correlation: UUID, /) -> None: ...


class XlsxProcessOutcome(StrEnum):
    BUSY = 'busy'
    NOT_CLAIMED = 'not_claimed'
    COMPLETED = 'completed'
    FAILED = 'failed'  # Failed attempt; the repository may make the job ready again.


def _verified_result(content: bytes, expected_sha256: str) -> tuple[str, StrictXlsxEvidence]:
    extracted = extract_xlsx_strict(content)
    if type(extracted) is not StrictXlsxResult or type(extracted.canonical_bytes) is not bytes:
        raise XlsxIntakeError(_INTEGRITY)
    canonical, evidence = extracted.canonical_bytes, extracted.evidence
    if len(canonical) > MAX_CANONICAL_BYTES:
        raise XlsxIntakeError(XlsxIntakeReason.RESOURCE_LIMIT)
    # Reuse the strict supervisor's complete canonical v1 validator unchanged.
    try:
        version, identity, title, cell_range = _canonical_metadata(canonical)
    except StrictXlsxError:
        raise XlsxIntakeError(_INTEGRITY) from None
    if (type(evidence) is not StrictXlsxEvidence
            or type(evidence.extractor_version) is not int or evidence.extractor_version != EXTRACTOR_VERSION
            or type(evidence.canonicalization_version) is not int or evidence.canonicalization_version != version
            or (evidence.worksheet_identity, evidence.worksheet_title, evidence.worksheet_range)
            != (identity, title, cell_range)
            or evidence.original_sha256 != expected_sha256
            or evidence.canonical_sha256 != hashlib.sha256(canonical).hexdigest()):
        raise XlsxIntakeError(_INTEGRITY)
    return canonical.decode('utf-8'), evidence


def _extract_failure(code: str) -> XlsxIntakeReason:
    if code in ('invalid_archive', 'invalid_workbook'):
        return XlsxIntakeReason.UNSUPPORTED_WORKBOOK
    if code in ('input_limit', 'output_limit', 'resource_limit', 'timeout'):
        return XlsxIntakeReason.RESOURCE_LIMIT
    if code == 'worker_unavailable':
        return _INFRASTRUCTURE
    return XlsxIntakeReason.PROCESSING_FAILED


class XlsxIntakeDispatcher:
    """Run one active attempt per instance, only when explicitly dispatched."""

    def __init__(self, store: LocalXlsxQuarantine, repo: XlsxIntakeRepo):
        self._store = store
        self._repo = repo
        self._active = Lock()

    def dispatch(self, job: UUID, correlation: UUID) -> XlsxProcessOutcome:
        if not isinstance(job, UUID) or not job.int or not isinstance(correlation, UUID) or not correlation.int:
            raise XlsxIntakeError(_INTEGRITY)
        if not self._active.acquire(blocking=False):
            return XlsxProcessOutcome.BUSY
        try:
            return self._dispatch(job, correlation)
        finally:
            self._active.release()

    def _dispatch(self, job: UUID, correlation: UUID) -> XlsxProcessOutcome:
        claimed = self._repo.claim(job, correlation)
        if claimed is None:
            return XlsxProcessOutcome.NOT_CLAIMED
        if claimed.job_id != job or type(claimed.attempt) is not int or claimed.attempt < 1:
            # Never send a transition on a claim with an unverified job or fence.
            raise XlsxIntakeError(_INTEGRITY)
        try:
            content = self._store.read_verified(claimed.tenant_id, claimed.job_id, claimed.artifact_key,
                                                claimed.original_sha256, claimed.byte_count)
            text, evidence = _verified_result(content, claimed.original_sha256)
        except XlsxIntakeError as exc:
            reason = exc.reason
        except StrictXlsxError as exc:
            reason = _extract_failure(exc.code)
        except Exception:
            reason = XlsxIntakeReason.PROCESSING_FAILED
        else:
            # A raised adapter error may be an ambiguous commit, not permission
            # to send a competing transition. The lease and fence permit recovery.
            self._repo.complete(job, claimed.attempt, text, evidence.canonical_sha256,
                                evidence.extractor_version, evidence.canonicalization_version,
                                evidence.worksheet_identity, evidence.worksheet_title,
                                evidence.worksheet_range, correlation)
            return XlsxProcessOutcome.COMPLETED
        self._repo.fail(job, claimed.attempt, reason.value, correlation)
        return XlsxProcessOutcome.FAILED
