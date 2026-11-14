"""Local, deterministic signatures for common Dutch sensitive information.

Detections retain spans and categories only, never matched values. This is a
baseline signature detector, not a complete personal-data classifier.
"""

from __future__ import annotations

import re
from datetime import date
from typing import Protocol, Sequence

from bri.privacy.models import Detection, DetectionCategory, TenantSignature


_BSN_CANDIDATE = re.compile(r"(?<![0-9])[0-9](?:[ \t.-]?[0-9]){7,8}(?![0-9])")
_EMAIL = re.compile(
    r"(?<![\w.+-])[\w.!#$%&'*+/=?^`{|}~-]+@(?:[\w-]+\.)+[\w-]{2,63}(?![\w.-])",
    re.UNICODE,
)
_DUTCH_PHONE = re.compile(
    r"(?<![0-9])(?:(?:\+31|0031)[ \t()./-]*[1-9](?:[ \t()./-]*[0-9]){8}|"
    r"0[ \t()./-]*[1-9](?:[ \t()./-]*[0-9]){8})(?![0-9])"
)
_IBAN_LENGTHS = {
    "AT": 20,
    "BE": 16,
    "CH": 21,
    "DE": 22,
    "DK": 18,
    "ES": 24,
    "FI": 18,
    "FR": 27,
    "GB": 22,
    "IE": 22,
    "IT": 27,
    "LU": 20,
    "NL": 18,
    "NO": 15,
    "PL": 28,
    "PT": 25,
    "SE": 24,
}
_IBAN_CANDIDATE = re.compile(
    r"(?<![A-Z0-9])[A-Z]{2}[ \t]?[0-9][ \t]?[0-9](?:[ \t]?[A-Z0-9]){11,30}(?![A-Z0-9])",
    re.IGNORECASE,
)
_ACCOUNT_CONTEXT = re.compile(
    r"(?i)\b(?:rekening(?:nummer|nr)?|bankrekening|account(?:nummer| number| no\.?)?)\b"
    r"[ \t:;=#-]*(?P<number>(?:[0-9][ \t-]?){6,10}[0-9])"
)
_DUTCH_ADDRESS = re.compile(
    r"(?<!\w)(?P<street>(?:[^\W\d_][\w'’.-]*[ \t]+){1,5}"
    r"[0-9]{1,4}[A-Za-z]?(?:[-/][0-9]{1,4})?)\s*,?\s*"
    r"(?P<postcode>[1-9][0-9]{3}[ \t]?[A-Z]{2})(?![\w])",
    re.IGNORECASE | re.UNICODE,
)
_DOB_CONTEXT = re.compile(
    r"(?i)(?:geboortedatum|geboren(?:e)?(?:[ \t]+op)?|date of birth|dob)"
    r"[ \t:=-]*(?P<date>(?:[0-3]?[0-9][-/.][01]?[0-9][-/.](?:18|19|20)[0-9]{2}|"
    r"(?:18|19|20)[0-9]{2}[-/.][01]?[0-9][-/.][0-3]?[0-9]))"
)


class Detector(Protocol):
    def detect(self, text: str) -> tuple[Detection, ...]:
        """Return value-free spans for supported sensitive signatures."""
        ...


class SignatureDetector:
    """Deterministic local detector for validated common Dutch signatures."""

    def __init__(
        self,
        *,
        tenant_signatures: Sequence[TenantSignature] = (),
        tenant_terms: Sequence[str] = (),
    ) -> None:
        self._tenant_signatures = tuple(tenant_signatures)
        if any(not isinstance(term, str) or not term or len(term) > 256 for term in tenant_terms):
            raise ValueError("invalid_tenant_signature")
        self._tenant_terms = tuple(tenant_terms)

    def detect(self, text: str) -> tuple[Detection, ...]:
        if not isinstance(text, str):
            raise TypeError("content_must_be_text")
        findings: set[Detection] = set()

        for match in _BSN_CANDIDATE.finditer(text):
            digits = re.sub(r"[^0-9]", "", match.group(0))
            if _valid_bsn(digits):
                findings.add(Detection(DetectionCategory.BSN, match.start(), match.end()))

        for match in _EMAIL.finditer(text):
            findings.add(Detection(DetectionCategory.EMAIL, match.start(), match.end()))

        for match in _DUTCH_PHONE.finditer(text):
            findings.add(Detection(DetectionCategory.PHONE, match.start(), match.end()))
        for start, end in _international_phone_spans(text):
            findings.add(Detection(DetectionCategory.PHONE, start, end))

        for match in _IBAN_CANDIDATE.finditer(text):
            if _valid_iban(match.group(0)):
                findings.add(Detection(DetectionCategory.IBAN, match.start(), match.end()))

        for match in _ACCOUNT_CONTEXT.finditer(text):
            number = re.sub(r"[^0-9]", "", match.group("number"))
            if 7 <= len(number) <= 11:
                findings.add(
                    Detection(
                        DetectionCategory.BANK_ACCOUNT,
                        match.start("number"),
                        match.end("number"),
                    )
                )

        for match in _DUTCH_ADDRESS.finditer(text):
            findings.add(
                Detection(DetectionCategory.POSTAL_ADDRESS, match.start(), match.end())
            )

        for match in _DOB_CONTEXT.finditer(text):
            raw_date = match.group("date")
            if _valid_contextual_date(raw_date):
                findings.add(
                    Detection(
                        DetectionCategory.DATE_OF_BIRTH,
                        match.start("date"),
                        match.end("date"),
                    )
                )

        for signature in self._tenant_signatures:
            flags = 0 if signature.case_sensitive else re.IGNORECASE
            pattern = re.compile(
                r"(?<!\w)" + re.escape(signature.literal) + r"(?!\w)",
                flags | re.UNICODE,
            )
            for match in pattern.finditer(text):
                findings.add(
                    Detection(signature.category, match.start(), match.end())
                )

        for term in self._tenant_terms:
            pattern = re.compile(re.escape(term), re.IGNORECASE | re.UNICODE)
            for match in pattern.finditer(text):
                findings.add(
                    Detection(DetectionCategory.TENANT_SENSITIVE, match.start(), match.end())
                )

        return tuple(
            sorted(findings, key=lambda item: (item.start, item.end, item.category.value))
        )


def _international_phone_spans(text: str) -> tuple[tuple[int, int], ...]:
    spans: list[tuple[int, int]] = []
    index = 0
    separators = " ()./-"
    while index < len(text):
        if text[index] == "+":
            cursor = index + 1
        elif text.startswith("00", index):
            cursor = index + 2
        else:
            index += 1
            continue
        if index and (text[index - 1].isalnum() or text[index - 1] == "_"):
            index += 1
            continue
        if cursor >= len(text) or text[cursor] not in "123456789":
            index += 1
            continue
        digits: list[str] = []
        end = cursor
        while cursor < len(text) and (text[cursor] in "0123456789" or text[cursor] in separators):
            if text[cursor] in "0123456789":
                digits.append(text[cursor])
                end = cursor + 1
                if len(digits) > 15:
                    break
            cursor += 1
        next_char = text[end] if end < len(text) else ""
        if (
            8 <= len(digits) <= 15
            and not (next_char and (next_char.isalnum() or next_char == "_"))
        ):
            spans.append((index, end))
            index = end
        else:
            index += 1
    return tuple(spans)


def _valid_bsn(digits: str) -> bool:
    if len(digits) == 8:
        digits = "0" + digits
    if len(digits) != 9:
        return False
    total = sum(
        int(digit) * weight for digit, weight in zip(digits[:8], range(9, 1, -1))
    ) - int(digits[8])
    return total > 0 and total % 11 == 0


def _valid_iban(candidate: str) -> bool:
    normalized = re.sub(r"\s", "", candidate).upper()
    country = normalized[:2]
    expected_length = _IBAN_LENGTHS.get(country)
    if not 15 <= len(normalized) <= 34:
        return False
    if expected_length is None or len(normalized) != expected_length:
        return False
    if country == "NL" and not re.fullmatch(r"NL[0-9]{2}[A-Z]{4}[0-9]{10}", normalized):
        return False
    rearranged = normalized[4:] + normalized[:4]
    remainder = 0
    for character in rearranged:
        expanded = str(ord(character) - 55) if character.isalpha() else character
        for digit in expanded:
            remainder = (remainder * 10 + int(digit)) % 97
    return remainder == 1


def _valid_contextual_date(raw_date: str) -> bool:
    normalized = raw_date.replace("/", "-").replace(".", "-")
    parts = normalized.split("-")
    try:
        if len(parts[0]) == 4:
            year, month, day = map(int, parts)
        else:
            day, month, year = map(int, parts)
        date(year, month, day)
    except (TypeError, ValueError):
        return False
    return True
