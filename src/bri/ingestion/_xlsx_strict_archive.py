"""Bounded ZIP32 reader for the strict local XLSX profile; never extracts files."""

import re
import stat
import struct
import zlib
from bisect import bisect_left
from dataclasses import dataclass


MAX_ARCHIVE_BYTES = 5_000_000
MAX_MEMBER_BYTES = 10_000_000
MAX_TOTAL_BYTES = 25_000_000
MAX_ENTRIES = 256
MAX_RATIO = 100
_CHUNK = 65_536

_END = struct.Struct("<4s4H2IH")
_CENTRAL = struct.Struct("<4s6H3I5H2I")
_LOCAL = struct.Struct("<4s5H3I2H")
_EXTRA = struct.Struct("<HH")
_DESCRIPTOR = struct.Struct("<III")
_NAME = re.compile(rb"[A-Za-z0-9_.~/-]+")
_DEVICE = re.compile(r"(?:aux|con|nul|prn|com[0-9]|lpt[0-9])", re.IGNORECASE)
_STRUCTURE = "Invalid ZIP structure."
_DATA = "Invalid ZIP member data."
_EXPANSION = "ZIP expansion exceeds limit."


class StrictArchiveError(ValueError):
    """The input is not an accepted ZIP package."""


@dataclass(frozen=True, slots=True)
class _Member:
    raw_name: bytes
    name: str
    offset: int
    version: int
    flags: int
    method: int
    time: int
    date: int
    crc: int
    compressed: int
    size: int


def _name(raw: bytes) -> str:
    if raw != b"[Content_Types].xml" and not _NAME.fullmatch(raw):
        raise StrictArchiveError("Invalid ZIP member name.")
    name = raw.decode("ascii")
    if any(not part or part.endswith(".") or _DEVICE.fullmatch(part.partition(".")[0])
           for part in name.split("/")):
        raise StrictArchiveError("Invalid ZIP member name.")
    return name


def _check_names(members: list[_Member]) -> None:
    names = sorted(member.name.lower() for member in members)
    if len(set(names)) != len(names):
        raise StrictArchiveError("Conflicting ZIP member names.")
    for name in names:
        prefix = name + "/"
        child = bisect_left(names, prefix)
        if child < len(names) and names[child].startswith(prefix):
            raise StrictArchiveError("Conflicting ZIP member names.")


def _directory(content: bytes) -> tuple[int, int, int]:
    # A comment may contain a signature. Require exactly one candidate whose
    # declared comment ends at EOF, and no ZIP64 or multi-disk directory.
    end = len(content) - _END.size
    floor = max(0, end - 65_535)
    found = None
    offset = content.find(b"PK\x05\x06", floor, end + 4) if end >= 0 else -1
    while offset != -1:
        record = _END.unpack_from(content, offset)
        if offset + record[-1] == end:
            if found is not None:
                raise StrictArchiveError(_STRUCTURE)
            found = (offset, record)
        offset = content.find(b"PK\x05\x06", offset + 1, end + 4)
    if found is None:
        raise StrictArchiveError(_STRUCTURE)
    offset, (_, disk, start_disk, disk_count, count, size, start, _) = found
    if disk or start_disk or disk_count != count or start + size != offset or not count:
        raise StrictArchiveError(_STRUCTURE)
    if count > MAX_ENTRIES:
        raise StrictArchiveError("ZIP archive exceeds entry limit.")
    return start, offset, count


def _check_extra(content: bytes, start: int, end: int) -> None:
    seen: set[int] = set()
    # Accept common timestamp/Unix ownership metadata, but not alternate path,
    # encryption, ZIP64 or unknown extension records that change interpretation.
    while start < end:
        if end - start < _EXTRA.size:
            raise StrictArchiveError(_STRUCTURE)
        field, length = _EXTRA.unpack_from(content, start)
        start += _EXTRA.size + length
        if start > end or field in seen or field not in (0x000A, 0x5455, 0x5855, 0x7855, 0x7875):
            raise StrictArchiveError(_STRUCTURE)
        seen.add(field)


def _read_directory(content: bytes, start: int, end: int, count: int) -> list[_Member]:
    members: list[_Member] = []
    for _ in range(count):
        if end - start < _CENTRAL.size:
            raise StrictArchiveError(_STRUCTURE)
        (signature, _, version, flags, method, time, date, crc, compressed, size,
         names, extras, comment, disk, _, attributes, offset) = _CENTRAL.unpack_from(content, start)
        name_start = start + _CENTRAL.size
        extra_start = name_start + names
        extra_end = extra_start + extras
        start = extra_end + comment
        if signature != b"PK\x01\x02" or start > end or disk:
            raise StrictArchiveError(_STRUCTURE)
        # Reject non-files (for example Unix symlinks and DOS directories).
        if attributes & 0x18 or stat.S_IFMT(attributes >> 16) not in (0, stat.S_IFREG):
            raise StrictArchiveError(_STRUCTURE)
        allowed_flags = 0x0808 | (0x0006 if method == 8 else 0)
        if method not in (0, 8) or flags & ~allowed_flags or version > 20:
            raise StrictArchiveError("Unsupported ZIP member encoding.")
        raw_name = content[name_start:extra_start]
        _check_extra(content, extra_start, extra_end)
        members.append(_Member(raw_name, _name(raw_name), offset, version, flags, method,
                               time, date, crc, compressed, size))
    if start != end:
        raise StrictArchiveError(_STRUCTURE)
    _check_names(members)
    return sorted(members, key=lambda member: member.offset)


def _member_start(content: bytes, member: _Member, boundary: int) -> int:
    if boundary - member.offset < _LOCAL.size:
        raise StrictArchiveError(_STRUCTURE)
    (signature, version, flags, method, time, date, crc, compressed, size,
     names, extras) = _LOCAL.unpack_from(content, member.offset)
    name_start = member.offset + _LOCAL.size
    extra_start = name_start + names
    data_start = extra_start + extras
    data_end = data_start + member.compressed
    if (signature != b"PK\x03\x04" or data_end > boundary
            or (version, flags, method, time, date) != (member.version, member.flags, member.method,
                                                       member.time, member.date)
            or content[name_start:extra_start] != member.raw_name):
        raise StrictArchiveError(_STRUCTURE)
    _check_extra(content, extra_start, data_start)
    declared = (member.crc, member.compressed, member.size)
    if flags & 8:
        if (crc, compressed, size) not in ((0, 0, 0), declared):
            raise StrictArchiveError(_STRUCTURE)
        if boundary - data_end == 16 and content[data_end:data_end + 4] == b"PK\x07\x08":
            data_end += 4
        if boundary - data_end != _DESCRIPTOR.size or _DESCRIPTOR.unpack_from(content, data_end) != declared:
            raise StrictArchiveError(_STRUCTURE)
    elif (crc, compressed, size) != declared or data_end != boundary:
        raise StrictArchiveError(_STRUCTURE)
    return data_start


def _inflate(content: bytes, member: _Member, start: int, available: int) -> bytes:
    limit = min(MAX_MEMBER_BYTES, available, MAX_RATIO * member.compressed)
    if member.size > limit:
        raise StrictArchiveError(_EXPANSION)
    # Limit actual output even when both headers advertise a false size.
    budget = min(limit, member.size)
    end = start + member.compressed
    if member.method == 0:
        if member.compressed != member.size:
            raise StrictArchiveError(_DATA)
        result = content[start:end]
        if zlib.crc32(result) != member.crc:
            raise StrictArchiveError(_DATA)
        return result

    inflater = zlib.decompressobj(-zlib.MAX_WBITS)
    result_chunks: list[bytes] = []
    written = crc = 0
    try:
        for offset in range(start, end, _CHUNK):
            next_offset = min(offset + _CHUNK, end)
            pending = content[offset:next_offset]
            while True:
                max_output = min(_CHUNK, budget - written + 1)
                chunk = inflater.decompress(pending, max_output)
                written += len(chunk)
                if written > budget or inflater.unused_data or (inflater.eof and next_offset != end):
                    raise StrictArchiveError(_DATA)
                if chunk:
                    crc = zlib.crc32(chunk, crc)
                    result_chunks.append(chunk)
                pending = inflater.unconsumed_tail
                if inflater.eof or (not pending and len(chunk) < max_output):
                    break
    except zlib.error:
        raise StrictArchiveError(_DATA) from None
    if not inflater.eof or written != member.size or crc != member.crc:
        raise StrictArchiveError(_DATA)
    return b"".join(result_chunks)


def read_package(content: bytes) -> dict[str, bytes]:
    """Return validated member bytes keyed by canonical ZIP member names."""
    if len(content) > MAX_ARCHIVE_BYTES:
        raise StrictArchiveError("ZIP archive exceeds size limit.")
    start, end, count = _directory(content)
    members = _read_directory(content, start, end, count)
    if members[0].offset != 0:
        raise StrictArchiveError(_STRUCTURE)
    compressed = sum(member.compressed for member in members)
    budget = min(MAX_TOTAL_BYTES, MAX_RATIO * compressed)
    parts: dict[str, bytes] = {}
    for member, boundary in zip(members, [next_member.offset for next_member in members[1:]] + [start]):
        data_start = _member_start(content, member, boundary)
        data = _inflate(content, member, data_start, budget)
        budget -= len(data)
        parts[member.name] = data
    return parts
