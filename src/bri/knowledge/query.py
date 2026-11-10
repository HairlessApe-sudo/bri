"""Deterministic, evidence-first Knowledge Intelligence mock."""

from __future__ import annotations

import re
from dataclasses import dataclass

from bri.access.policy import Principal, Resource, is_authorized


_STOP_WORDS = frozenset(
    "a an and are as at be by for from how in is it of on or the to was were what when where which who why with".split()
)
_WORDS = re.compile(r"[^\W_]+", re.UNICODE)
_SENTENCES = re.compile(r"(?<=[.!?])\s+|\n+")


@dataclass(frozen=True, slots=True)
class KnowledgeItem:
    record_id: str
    tenant_id: str
    scope_id: str
    validation_state: str
    title: str
    source_version: str
    source_location: str
    content: str
    current: bool = True


@dataclass(frozen=True, slots=True)
class EvidenceCitation:
    record_id: str
    title: str
    source_version: str
    source_location: str
    excerpt: str


@dataclass(frozen=True, slots=True)
class KnowledgeAnswer:
    status: str
    answer: str | None
    citations: tuple[EvidenceCitation, ...]


def _terms(value: str) -> frozenset[str]:
    return frozenset(
        token.casefold()
        for token in _WORDS.findall(value)
        if token.casefold() not in _STOP_WORDS
    )


def _citation(item: KnowledgeItem, excerpt: str) -> EvidenceCitation:
    return EvidenceCitation(
        record_id=item.record_id,
        title=item.title,
        source_version=item.source_version,
        source_location=item.source_location,
        excerpt=excerpt,
    )


def answer_question(
    principal: Principal | None,
    question: str,
    items: tuple[KnowledgeItem, ...] | list[KnowledgeItem],
    *,
    minimum_match: float = 0.30,
) -> KnowledgeAnswer:
    """Return literal supported evidence or abstain; never call a model.

    Authorization and validation are applied before record content is scored.
    The lexical matcher is intentionally conservative and is a local test mock,
    not a substitute for production semantic retrieval or answer generation.
    """
    query_terms = _terms(question)
    if not query_terms or not 0 < minimum_match <= 1:
        return KnowledgeAnswer("insufficient", None, ())

    scored: list[tuple[float, KnowledgeItem, str]] = []
    stale: list[tuple[float, KnowledgeItem, str]] = []
    for item in items:
        if item.validation_state != "approved":
            continue
        resource = Resource(item.tenant_id, item.scope_id)
        if not is_authorized(principal, "knowledge:read", resource):
            continue
        for sentence in _SENTENCES.split(item.content.strip()):
            excerpt = sentence.strip()
            if not excerpt:
                continue
            sentence_terms = _terms(excerpt)
            if not sentence_terms:
                continue
            score = len(query_terms & sentence_terms) / len(query_terms)
            if score < minimum_match:
                continue
            target = scored if item.current else stale
            target.append((score, item, excerpt))

    if not scored:
        if stale:
            best_stale = max(score for score, _, _ in stale)
            citations = tuple(
                _citation(item, excerpt)
                for score, item, excerpt in stale
                if score == best_stale
            )
            return KnowledgeAnswer("outdated", None, citations)
        return KnowledgeAnswer("insufficient", None, ())

    best_score = max(score for score, _, _ in scored)
    best = [entry for entry in scored if entry[0] == best_score]
    distinct_text = {re.sub(r"\s+", " ", excerpt).casefold() for _, _, excerpt in best}
    citations = tuple(
        _citation(item, excerpt)
        for _, item, excerpt in sorted(best, key=lambda entry: (entry[1].record_id, entry[2]))
    )
    if len(distinct_text) > 1:
        return KnowledgeAnswer("conflicting", None, citations)

    return KnowledgeAnswer("supported", best[0][2], citations)
