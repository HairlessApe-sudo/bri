"""Typed, deterministic Privacy Shield domain values."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class DetectionCategory(str, Enum):
    BSN = "bsn"
    EMAIL = "email"
    PHONE = "phone"
    IBAN = "iban"
    BANK_ACCOUNT = "bank_account"
    POSTAL_ADDRESS = "postal_address"
    DATE_OF_BIRTH = "date_of_birth"
    TENANT_SENSITIVE = "tenant_sensitive"
    TAX_FILE_NUMBER = "tax_file_number"


class InputType(str, Enum):
    DOCUMENT = "document"
    HISTORICAL_CASE = "historical_case"
    RETRIEVED_CONTEXT = "retrieved_context"
    USER_QUESTION = "user_question"


class ProcessingPurpose(str, Enum):
    DOCUMENT_EXTRACTION = "document_extraction"
    HISTORICAL_CASE_ANALYSIS = "historical_case_analysis"
    RETRIEVAL = "retrieval"
    QUESTION_ANSWERING = "question_answering"
    INTERNAL_REVIEW = "internal_review"


class ProcessingDestination(str, Enum):
    AI_PROVIDER = "ai_provider"
    BRI_INTERNAL = "bri_internal"
    HUMAN_REVIEW = "human_review"


class PolicyAction(str, Enum):
    ALLOW = "allow"
    MASK = "mask"
    BLOCK = "block"


class ProcessingStatus(str, Enum):
    APPROVED = "approved"
    BLOCKED = "blocked"


@dataclass(frozen=True, slots=True)
class Detection:
    """A location and category only; never retains the detected substring."""

    category: DetectionCategory
    start: int
    end: int

    def __post_init__(self) -> None:
        if not isinstance(self.category, DetectionCategory):
            raise ValueError("invalid_detection_category")
        if self.start < 0 or self.end <= self.start:
            raise ValueError("invalid_detection_span")


@dataclass(frozen=True, slots=True)
class TenantSignature:
    """A literal tenant-defined signature, deliberately not an arbitrary regex."""

    signature_id: str
    literal: str = field(repr=False)
    category: DetectionCategory = DetectionCategory.TENANT_SENSITIVE
    case_sensitive: bool = False

    def __post_init__(self) -> None:
        import re

        if not isinstance(self.signature_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", self.signature_id):
            raise ValueError("invalid_signature_id")
        if not isinstance(self.literal, str) or not self.literal or len(self.literal) > 256:
            raise ValueError("invalid_signature_literal")
        if any(ord(char) < 32 for char in self.literal):
            raise ValueError("invalid_signature_literal")
        if not isinstance(self.category, DetectionCategory):
            raise ValueError("invalid_signature_category")
        if not isinstance(self.case_sensitive, bool):
            raise ValueError("invalid_signature_configuration")


@dataclass(frozen=True, slots=True)
class TenantContext:
    tenant_id: str
    principal_id: str
    action: str
    scope_id: str
    input_type: InputType
    purpose: ProcessingPurpose
    destination: ProcessingDestination
    issued_at: datetime
    expires_at: datetime
    proof: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class ProcessingRequest:
    tenant_context: TenantContext | None
    resource_scope_id: str
    input_type: InputType
    text: str = field(repr=False)
    purpose: ProcessingPurpose
    destination: ProcessingDestination


@dataclass(frozen=True, slots=True)
class DetectionCount:
    category: DetectionCategory
    count: int


@dataclass(frozen=True, slots=True)
class AuditSummary:
    processing_id: str
    tenant_id: str | None
    input_type: InputType | None
    purpose: ProcessingPurpose | None
    destination: ProcessingDestination | None
    decision: PolicyAction
    detection_counts: tuple[DetectionCount, ...]
    tenant_policy_id: str | None
    tenant_policy_version: str | None
    platform_policy_id: str
    platform_policy_version: str
    failure_reason: str | None
    recorded_at: datetime


@dataclass(frozen=True, slots=True)
class SignatureVersionProvenance:
    engine_version: str
    global_package_version: str
    regional_package_versions: tuple[tuple[str, str], ...]
    tenant_signature_version: str
    effective_configuration_version: str


@dataclass(frozen=True, slots=True)
class GatewayEnvelope:
    processing_id: str
    tenant_id: str
    resource_scope_id: str
    input_type: InputType
    purpose: ProcessingPurpose
    destination: ProcessingDestination
    decision: PolicyAction
    sanitised_content: str = field(repr=False)
    tenant_policy_id: str
    tenant_policy_version: str
    platform_policy_id: str
    platform_policy_version: str
    detection_counts: tuple[DetectionCount, ...]
    issued_at: datetime
    expires_at: datetime
    attestation: str
    signature_versions: SignatureVersionProvenance | None = None


@dataclass(frozen=True, slots=True)
class VerifiedShieldedContent:
    processing_id: str
    tenant_id: str
    resource_scope_id: str
    input_type: InputType
    purpose: ProcessingPurpose
    destination: ProcessingDestination
    decision: PolicyAction
    sanitised_content: str = field(repr=False)
    signature_versions: SignatureVersionProvenance | None = None


@dataclass(frozen=True, slots=True)
class ProcessingResult:
    status: ProcessingStatus
    decision: PolicyAction
    sanitised_content: str | None = field(repr=False)
    detection_categories: tuple[DetectionCategory, ...]
    detection_counts: tuple[DetectionCount, ...]
    tenant_policy_id: str | None
    tenant_policy_version: str | None
    platform_policy_id: str
    platform_policy_version: str
    audit_summary: AuditSummary
    failure_reason: str | None
    gateway_envelope: GatewayEnvelope | None
    signature_versions: SignatureVersionProvenance | None = None