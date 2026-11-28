"""Closed A19.1 metadata command contract; SQL separately checks authority."""

from dataclasses import dataclass
from datetime import date
import re

_KEYS = frozenset({'version', 'primary_classification_id', 'additional_classification_ids', 'title',
                   'description', 'effective_date', 'review_date', 'expiry_date'})
_CLASS_ID = re.compile(r'[a-z0-9][a-z0-9_.-]{0,63}', re.ASCII)
_ISO_DATE = re.compile(r'[0-9]{4}-[0-9]{2}-[0-9]{2}', re.ASCII)


@dataclass(frozen=True, slots=True)
class MetadataProposal:
    primary_classification_id: str
    additional_classification_ids: tuple[str, ...]
    title: str
    description: str | None
    effective_date: date | None
    review_date: date | None
    expiry_date: date | None


def _class_id(value: object) -> str:
    if type(value) is not str or not _CLASS_ID.fullmatch(value):
        raise ValueError('Invalid classification identifier')
    return value


def _text(value: object, max_bytes: int) -> str:
    if (type(value) is not str or not value.strip() or '\x00' in value
            or len(value.encode('utf-8')) > max_bytes):
        raise ValueError('Invalid metadata text')
    return value


def _date(value: object) -> date | None:
    if value is None:
        return None
    if type(value) is not str or not _ISO_DATE.fullmatch(value):
        raise ValueError('Invalid metadata date')
    return date.fromisoformat(value)


def parse_proposed_metadata(value: object) -> MetadataProposal:
    if type(value) is not dict or value.keys() != _KEYS or type(value['version']) is not int or value['version'] != 1:
        raise ValueError('Invalid metadata contract')
    primary = _class_id(value['primary_classification_id'])
    extra = value['additional_classification_ids']
    if type(extra) is not list or len(extra) > 8:
        raise ValueError('Invalid additional classifications')
    additional = tuple(_class_id(item) for item in extra)
    if primary in additional or len(set(additional)) != len(additional):
        raise ValueError('Duplicate classification identifier')
    description = value['description']
    return MetadataProposal(primary, additional, _text(value['title'], 160),
                            None if description is None else _text(description, 2048),
                            _date(value['effective_date']), _date(value['review_date']), _date(value['expiry_date']))
