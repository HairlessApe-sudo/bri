"""Deterministic excerpts from published A12 CSV extractions."""

from __future__ import annotations

import json
import re
from collections.abc import Sequence

from bri.access.policy import Principal, Resource, is_authorized
from bri.ingestion.csv_intake import MAX_CSV_COLUMNS, MAX_CSV_ROWS
from bri.knowledge.query import (
    KnowledgeAnswer, KnowledgeItem, _MINIMUM_MATCH, _citation, _excerpt_key,
    _excerpts, _match_score, _terms,
)

_MAX_QUESTION_CHARS = 512
_MAX_EXCERPT_CHARS = 512
_MAX_CITATIONS = 5
_MAX_INPUT_ITEMS = 1_024
_MAX_PROJECTION_CHARS = 2_000_000  # Aggregate serialized characters, not bytes.
_MAX_FRAGMENTS = 20_000  # Includes nonmatching nonempty fragments.
_INSUFFICIENT = KnowledgeAnswer("insufficient", None, ())
_SURROGATE = re.compile(r"[\ud800-\udfff]")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("duplicate projection key")
    return obj


def _cell(value: object) -> bool:
    return isinstance(value, str) and not _SURROGATE.search(value)


def _project(content: str) -> list[list[str]] | None:
    try:
        data = json.loads(content, object_pairs_hook=_unique_object)
    except (ValueError, RecursionError):
        return None
    if not isinstance(data, dict) or data.keys() != {"headers", "rows"}:
        return None
    headers, rows = data["headers"], data["rows"]
    if (not isinstance(headers, list) or not 1 <= len(headers) <= MAX_CSV_COLUMNS
            or any(not _cell(h) or not h.strip() for h in headers)
            or len(set(headers)) != len(headers)
            or not isinstance(rows, list) or len(rows) > MAX_CSV_ROWS):
        return None
    if any(not isinstance(row, list) or len(row) != len(headers)
           or not all(map(_cell, row)) for row in rows):
        return None
    return rows


def _has_range(item: KnowledgeItem) -> bool:
    first, last = item.csv_first_line, item.csv_last_line
    return type(first) is int and type(last) is int and 1 <= first <= last


def answer_csv_question(
    principal: Principal | None, q: str, items: Sequence[KnowledgeItem],
) -> KnowledgeAnswer:
    """Answer using already integrity-verified A12 v1 reader items only.

    Recheck approval, currency and exact tenant/node permission before parsing.
    Match only data cells, independently, using the legacy lexical scorer and
    sentence splitting. Headers, sibling cells and metadata do not boost a
    fragment's score. Answers and citation excerpts are literal substrings;
    citation locations always enclose the full extraction, not a row or cell.

    Limits: 512 question characters, 1,024 eligible items, 2,000,000 aggregate
    authorized projection characters, 20,000 nonempty fragments, 512 excerpt
    characters and five citations. Never decide from a partial scan: overflow
    or an overlong top match yields insufficient. The display cap is applied
    after tie checking, with at least two distinct witnesses for a conflict.
    """
    if len(q) > _MAX_QUESTION_CHARS:
        return _INSUFFICIENT
    query_terms = _terms(q)
    if not query_terms:
        return _INSUFFICIENT

    best_score = _MINIMUM_MATCH
    best: list[tuple[KnowledgeItem, str]] = []
    eligible = chars = fragments = 0
    for item in items:
        if (item.validation_state != "approved" or not item.current
                or not is_authorized(principal, "knowledge:read", Resource(item.tenant_id, item.scope_id))
                or (item.extractor_name, item.extractor_version) != ("governed-csv", "1")
                or not _has_range(item) or not isinstance(item.content, str)):
            continue
        eligible += 1
        chars += len(item.content)
        if eligible > _MAX_INPUT_ITEMS or chars > _MAX_PROJECTION_CHARS:
            return _INSUFFICIENT
        rows = _project(item.content)
        if rows is None:
            continue
        for row in rows:
            for cell in row:
                for excerpt in _excerpts(cell):
                    fragments += 1
                    if fragments > _MAX_FRAGMENTS:
                        return _INSUFFICIENT
                    score = _match_score(query_terms, excerpt)
                    if score > best_score:
                        best_score = score
                        best.clear()
                    if score == best_score:
                        best.append((item, excerpt))

    if not best or any(len(text) > _MAX_EXCERPT_CHARS for _, text in best):
        return _INSUFFICIENT

    best.sort(key=lambda entry: (entry[0].record_id, entry[1], entry[0].source_id,
                                 entry[0].source_version_id, entry[0].extraction_id))
    first_text = best[0][1]
    first_key = _excerpt_key(first_text)
    alternate = next((i for i, (_, text) in enumerate(best) if _excerpt_key(text) != first_key), None)
    citations = []
    for item, text in best:
        citation = _citation(item, text)
        if citation not in citations:
            citations.append(citation)
            if len(citations) == _MAX_CITATIONS:
                break
    if alternate is not None:
        if all(_excerpt_key(c.excerpt) == first_key for c in citations):
            citations[-1] = _citation(*best[alternate])
        return KnowledgeAnswer("conflicting", None, tuple(citations))
    return KnowledgeAnswer("supported", first_text, tuple(citations))
