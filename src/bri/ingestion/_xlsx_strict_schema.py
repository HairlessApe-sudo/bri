"""Canonical header rule shared by the strict XLSX worker and parent."""

from collections.abc import Iterable
from unicodedata import normalize


def valid_header(cells: Iterable[object]) -> bool:
    keys = set()
    for cell in cells:
        if (type(cell) is not list or len(cell) != 2 or cell[0] != 'text'
                or type(cell[1]) is not str):
            return False
        key = normalize('NFC', normalize('NFC', cell[1].strip()).casefold())
        if not key or key in keys:
            return False
        keys.add(key)
    return bool(keys)
