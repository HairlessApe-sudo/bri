"""Staged format screening; full validation belongs to each native worker."""
from codecs import getincrementaldecoder
from threading import BoundedSemaphore

BASE = '/v1/knowledge-administration'
CSV_UPLOAD = BASE + '/csv/uploads'
XLSX_UPLOAD = BASE + '/xlsx/uploads'


class UploadAdmission:
    """One in-flight administration upload per staged listener, no waiters."""

    def __init__(self, path: str):
        self.path = path
        self.slot = BoundedSemaphore(1)


def is_administration(path: str) -> bool:
    return path == BASE or path.startswith(BASE + '/')


def plausible_csv(body: bytes) -> bool:
    # CSV has no magic bytes. Screen for UTF-8 text without retaining another
    # whole-body copy; the native worker alone interprets rows and columns.
    if not body or b'\0' in body or body.startswith((b'PK\x03\x04', b'%PDF-')):
        return False
    decode = getincrementaldecoder('utf-8')().decode
    try:
        view = memoryview(body)
        for start in range(0, len(body), 65_536):
            decode(view[start:start + 65_536])
        decode(b'', final=True)
    except UnicodeError:
        return False
    return True


def plausible_xlsx(body: bytes) -> bool:
    # Required on-wire markers from the native ZIP32/OPC profile. Do not walk
    # the directory, inflate members, or interpret XML during upload. Matching
    # markers do not establish a supported, valid, or even readable workbook.
    return (body.startswith(b'PK\x03\x04')
            and body.find(b'PK\x05\x06', max(0, len(body) - 65_557), len(body) - 18) != -1
            and all(name in body for name in (b'[Content_Types].xml', b'_rels/.rels', b'xl/_rels/workbook.xml.rels')))
