"""Fail-closed Privacy Shield processing service; no network or AI calls."""

from __future__ import annotations

import re
import uuid
from collections import Counter
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Protocol, Sequence, TypeVar

from bri.privacy.contracts import ShieldAttestor, TenantContextVerifier
from bri.privacy.detection import Detector, SignatureDetector
from bri.privacy.models import (
    AuditSummary,
    Detection,
    DetectionCategory,
    DetectionCount,
    GatewayEnvelope,
    InputType,
    PolicyAction,
    ProcessingDestination,
    ProcessingPurpose,
    ProcessingRequest,
    ProcessingResult,
    ProcessingStatus,
    SignatureVersionProvenance,
    TenantSignature,
)
from bri.privacy.policy import (
    DEFAULT_PLATFORM_POLICY,
    PlatformPolicy,
    PolicyEngine,
    PolicyProvider,
    TenantPolicy,
)
from bri.privacy.regional import (
    RegionalSignatureDetector,
    ResolvedSignatureConfiguration,
    SignatureConfigurationProvider,
)


_MAX_TEXT_CHARS = 1_000_000
_SAFE_PROCESSING_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_REDACTION_MARKERS = {
    DetectionCategory.BSN: "[BSN_REDACTED]",
    DetectionCategory.EMAIL: "[EMAIL_REDACTED]",
    DetectionCategory.PHONE: "[PHONE_REDACTED]",
    DetectionCategory.IBAN: "[IBAN_REDACTED]",
    DetectionCategory.BANK_ACCOUNT: "[BANK_ACCOUNT_REDACTED]",
    DetectionCategory.POSTAL_ADDRESS: "[POSTAL_ADDRESS_REDACTED]",
    DetectionCategory.DATE_OF_BIRTH: "[DATE_OF_BIRTH_REDACTED]",
    DetectionCategory.TENANT_SENSITIVE: "[TENANT_SENSITIVE_REDACTED]",
    DetectionCategory.TAX_FILE_NUMBER: "[TAX_FILE_NUMBER_REDACTED]",
}


class AuditSink(Protocol):
    def record(self, summary: AuditSummary) -> None:
        """Persist safe metadata only; implementations must not accept content."""
        ...


class InMemoryAuditSink:
    """In-memory safe audit sink for tests and local examples."""

    def __init__(self) -> None:
        self._entries: list[AuditSummary] = []

    @property
    def entries(self) -> tuple[AuditSummary, ...]:
        return tuple(self._entries)

    def record(self, summary: AuditSummary) -> None:
        if not isinstance(summary, AuditSummary):
            raise ValueError("invalid_audit_summary")
        self._entries.append(summary)


class DetectorFactory(Protocol):
    def __call__(
        self,
        signatures: Sequence[TenantSignature],
        sensitive_terms: Sequence[str],
    ) -> Detector:
        """Build a local detector pipeline for the approved tenant config."""
        ...


class PrivacyShieldService:
    """Process one authorized tenant input and emit only an attested result.

    The context authority must be held by server code that has already applied
    BRI authentication, action authorization, and resource/tenant scope checks.
    """

    def __init__(
        self,
        *,
        context_authority: TenantContextVerifier,
        policy_provider: PolicyProvider,
        audit_sink: AuditSink,
        attestor: ShieldAttestor,
        platform_policy: PlatformPolicy = DEFAULT_PLATFORM_POLICY,
        detector_factory: DetectorFactory | None = None,
        clock: Callable[[], datetime] | None = None,
        id_factory: Callable[[], str] | None = None,
        max_text_chars: int = _MAX_TEXT_CHARS,
        signature_configuration_provider: SignatureConfigurationProvider | None = None,
    ) -> None:
        if not isinstance(max_text_chars, int) or not 1 <= max_text_chars <= _MAX_TEXT_CHARS:
            raise ValueError("invalid_shield_configuration")
        if (
            not callable(getattr(context_authority, "verify", None))
            or not callable(getattr(policy_provider, "load", None))
            or not callable(getattr(audit_sink, "record", None))
            or not callable(getattr(attestor, "issue", None))
            or (signature_configuration_provider is not None and not callable(getattr(signature_configuration_provider, "load", None)))
        ):
            raise ValueError("invalid_shield_configuration")
        self._context_authority = context_authority
        self._policy_provider = policy_provider
        self._audit_sink = audit_sink
        self._attestor = attestor
        self._engine = PolicyEngine(platform_policy)
        self._detector_factory = detector_factory or (
            lambda signatures, terms: SignatureDetector(
                tenant_signatures=signatures,
                tenant_terms=terms,
            )
        )
        self._custom_detector_factory = detector_factory is not None
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._id_factory = id_factory or (lambda: uuid.uuid4().hex)
        self._max_text_chars = max_text_chars
        self._signature_configuration_provider = signature_configuration_provider

    def process(self, request: ProcessingRequest) -> ProcessingResult:
        processing_id = self._new_processing_id()
        now, clock_failed = self._now()
        if not isinstance(request, ProcessingRequest):
            return self._finish_blocked(
                processing_id, now, "invalid_request", None, None, None, None, (), None, None
            )
        if clock_failed:
            return self._finish_blocked(
                processing_id,
                now,
                "clock_unavailable",
                None,
                _enum_or_none(request.input_type, InputType),
                _enum_or_none(request.purpose, ProcessingPurpose),
                _enum_or_none(request.destination, ProcessingDestination),
                (),
                None,
                None,
            )

        context = request.tenant_context
        if context is None:
            return self._finish_blocked(
                processing_id,
                now,
                "missing_tenant_context",
                None,
                _enum_or_none(request.input_type, InputType),
                _enum_or_none(request.purpose, ProcessingPurpose),
                _enum_or_none(request.destination, ProcessingDestination),
                (),
                None,
                None,
            )
        try:
            context_valid = self._context_authority.verify(context, now=now) is True
        except Exception:
            context_valid = False
        if not context_valid:
            return self._finish_blocked(
                processing_id,
                now,
                "invalid_tenant_context",
                None,
                _enum_or_none(request.input_type, InputType),
                _enum_or_none(request.purpose, ProcessingPurpose),
                _enum_or_none(request.destination, ProcessingDestination),
                (),
                None,
                None,
            )

        tenant_id = context.tenant_id
        if (
            not isinstance(request.input_type, InputType)
            or not isinstance(request.purpose, ProcessingPurpose)
            or not isinstance(request.destination, ProcessingDestination)
            or request.input_type is not context.input_type
            or request.purpose is not context.purpose
            or request.destination is not context.destination
            or not isinstance(request.resource_scope_id, str)
            or request.resource_scope_id != context.scope_id
            or not isinstance(request.text, str)
            or len(request.text) > self._max_text_chars
        ):
            return self._finish_blocked(
                processing_id,
                now,
                "invalid_processing_context",
                tenant_id,
                _enum_or_none(request.input_type, InputType),
                _enum_or_none(request.purpose, ProcessingPurpose),
                _enum_or_none(request.destination, ProcessingDestination),
                (),
                None,
                None,
            )

        try:
            policy = self._policy_provider.load(tenant_id)
        except Exception:
            policy = None
            load_failure = "policy_unavailable"
        else:
            load_failure = None
        if load_failure:
            return self._finish_blocked(
                processing_id,
                now,
                load_failure,
                tenant_id,
                request.input_type,
                request.purpose,
                request.destination,
                (),
                None,
                None,
            )
        if policy is None:
            return self._finish_blocked(
                processing_id,
                now,
                "policy_unavailable",
                tenant_id,
                request.input_type,
                request.purpose,
                request.destination,
                (),
                None,
                None,
            )

        if not isinstance(policy, TenantPolicy) or policy.tenant_id != tenant_id:
            return self._finish_blocked(
                processing_id,
                now,
                "invalid_policy",
                tenant_id,
                request.input_type,
                request.purpose,
                request.destination,
                (),
                None,
                None,
            )
        try:
            policy.__post_init__()
        except Exception:
            return self._finish_blocked(
                processing_id,
                now,
                "invalid_policy",
                tenant_id,
                request.input_type,
                request.purpose,
                request.destination,
                (),
                None,
                None,
            )

        if self._signature_configuration_provider is None:
            return self._finish_blocked(
                processing_id, now, "signature_configuration_unavailable", tenant_id,
                request.input_type, request.purpose, request.destination, (), policy, None,
            )

        signature_versions = None
        try:
            resolved = self._signature_configuration_provider.load(tenant_id)
            if not isinstance(resolved, ResolvedSignatureConfiguration) or resolved.config.tenant_id != tenant_id:
                raise ValueError("signature_configuration_unavailable")
            effective = resolved.effective
            signature_versions = SignatureVersionProvenance(
                engine_version=effective.engine_version,
                global_package_version=effective.package_versions["global"],
                regional_package_versions=tuple(sorted((key, value) for key, value in effective.package_versions.items() if key != "global")),
                tenant_signature_version=effective.tenant_signature_version,
                effective_configuration_version=effective.configuration_version,
            )
            if policy.signatures or policy.sensitive_terms:
                raise ValueError("legacy_signature_configuration_unversioned")
            if self._custom_detector_factory:
                detector = self._detector_factory(policy.signatures, policy.sensitive_terms)
            else:
                detector = RegionalSignatureDetector(resolved.config, resolved.registry, tenant_signatures=resolved.tenant_signatures)
            findings = detector.detect(request.text)
            if not isinstance(findings, (tuple, list)) or any(
                not isinstance(item, Detection)
                or not isinstance(item.category, DetectionCategory)
                or not isinstance(item.start, int)
                or not isinstance(item.end, int)
                or item.start < 0
                or item.end <= item.start
                or item.end > len(request.text)
                for item in findings
            ):
                raise ValueError("invalid_detector_result")
            findings = tuple(sorted(set(findings), key=lambda item: (item.start, item.end, item.category.value)))
        except Exception:
            return self._finish_blocked(
                processing_id,
                now,
                "detection_unavailable",
                tenant_id,
                request.input_type,
                request.purpose,
                request.destination,
                (),
                policy,
                None,
            )

        try:
            evaluation = self._engine.evaluate(
                policy,
                findings,
                tenant_id=tenant_id,
                input_type=request.input_type,
                purpose=request.purpose,
                destination=request.destination,
            )
        except Exception:
            return self._finish_blocked(
                processing_id,
                now,
                "invalid_policy",
                tenant_id,
                request.input_type,
                request.purpose,
                request.destination,
                _counts(findings),
                policy,
                tuple(sorted({item.category for item in findings}, key=lambda item: item.value)),
            )
        counts = _counts(findings)
        categories = tuple(item.category for item in counts)
        if evaluation.failure_reason or evaluation.decision is PolicyAction.BLOCK:
            return self._finish_blocked(
                processing_id,
                now,
                evaluation.failure_reason or "policy_blocked",
                tenant_id,
                request.input_type,
                request.purpose,
                request.destination,
                counts,
                policy,
                categories,
            )

        if evaluation.mask_all:
            sanitised = "[CONTENT_REDACTED]"
        elif evaluation.decision is PolicyAction.MASK:
            sanitised = _mask_content(request.text, evaluation.actions)
        else:
            sanitised = request.text

        envelope = None
        if request.destination is ProcessingDestination.AI_PROVIDER:
            try:
                envelope = self._attestor.issue(
                    processing_id=processing_id,
                    tenant_id=tenant_id,
                    resource_scope_id=request.resource_scope_id,
                    input_type=request.input_type,
                    purpose=request.purpose,
                    destination=request.destination,
                    decision=evaluation.decision,
                    sanitised_content=sanitised,
                    tenant_policy_id=policy.policy_id,
                    tenant_policy_version=policy.version,
                    platform_policy_id=self._engine.platform_policy.policy_id,
                    platform_policy_version=self._engine.platform_policy.version,
                    detection_counts=counts,
                    issued_at=now,
                    signature_versions=signature_versions,
                )
            except Exception:
                return self._finish_blocked(
                    processing_id,
                    now,
                    "attestation_unavailable",
                    tenant_id,
                    request.input_type,
                    request.purpose,
                    request.destination,
                    counts,
                    policy,
                    categories,
                )

        summary = self._summary(
            processing_id,
            now,
            tenant_id,
            request.input_type,
            request.purpose,
            request.destination,
            evaluation.decision,
            counts,
            policy,
            None,
        )
        try:
            self._audit_sink.record(summary)
        except Exception:
            failed_summary = self._summary(
                processing_id,
                now,
                tenant_id,
                request.input_type,
                request.purpose,
                request.destination,
                PolicyAction.BLOCK,
                counts,
                policy,
                "audit_unavailable",
            )
            return ProcessingResult(
                ProcessingStatus.BLOCKED,
                PolicyAction.BLOCK,
                None,
                categories,
                counts,
                policy.policy_id,
                policy.version,
                self._engine.platform_policy.policy_id,
                self._engine.platform_policy.version,
                failed_summary,
                "audit_unavailable",
                None,
                signature_versions,
            )

        return ProcessingResult(
            ProcessingStatus.APPROVED,
            evaluation.decision,
            sanitised,
            categories,
            counts,
            policy.policy_id,
            policy.version,
            self._engine.platform_policy.policy_id,
            self._engine.platform_policy.version,
            summary,
            None,
            envelope,
            signature_versions,
        )

    def _finish_blocked(
        self,
        processing_id: str,
        now: datetime,
        reason: str,
        tenant_id: str | None,
        input_type: InputType | None,
        purpose: ProcessingPurpose | None,
        destination: ProcessingDestination | None,
        counts: tuple[DetectionCount, ...],
        policy: TenantPolicy | None,
        categories: tuple[DetectionCategory, ...] | None,
    ) -> ProcessingResult:
        summary = self._summary(
            processing_id,
            now,
            tenant_id,
            input_type,
            purpose,
            destination,
            PolicyAction.BLOCK,
            counts,
            policy,
            reason,
        )
        final_reason = reason
        try:
            self._audit_sink.record(summary)
        except Exception:
            final_reason = "audit_unavailable"
            summary = self._summary(
                processing_id,
                now,
                tenant_id,
                input_type,
                purpose,
                destination,
                PolicyAction.BLOCK,
                counts,
                policy,
                final_reason,
            )
        return ProcessingResult(
            ProcessingStatus.BLOCKED,
            PolicyAction.BLOCK,
            None,
            categories or tuple(item.category for item in counts),
            counts,
            policy.policy_id if policy else None,
            policy.version if policy else None,
            self._engine.platform_policy.policy_id,
            self._engine.platform_policy.version,
            summary,
            final_reason,
            None,
        )

    def _summary(
        self,
        processing_id: str,
        now: datetime,
        tenant_id: str | None,
        input_type: InputType | None,
        purpose: ProcessingPurpose | None,
        destination: ProcessingDestination | None,
        decision: PolicyAction,
        counts: tuple[DetectionCount, ...],
        policy: TenantPolicy | None,
        failure_reason: str | None,
    ) -> AuditSummary:
        return AuditSummary(
            processing_id,
            tenant_id,
            input_type,
            purpose,
            destination,
            decision,
            counts,
            policy.policy_id if policy else None,
            policy.version if policy else None,
            self._engine.platform_policy.policy_id,
            self._engine.platform_policy.version,
            failure_reason,
            now,
        )

    def _new_processing_id(self) -> str:
        try:
            value = self._id_factory()
            if isinstance(value, str) and _SAFE_PROCESSING_ID.fullmatch(value):
                return value
        except Exception:
            pass
        return uuid.uuid4().hex

    def _now(self) -> tuple[datetime, bool]:
        try:
            value = self._clock()
            if isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None:
                return value, False
        except Exception:
            pass
        return datetime.now(timezone.utc), True


def _counts(findings: Sequence[Detection]) -> tuple[DetectionCount, ...]:
    counter = Counter(item.category for item in findings)
    return tuple(
        DetectionCount(category, counter[category])
        for category in sorted(counter, key=lambda item: item.value)
    )


def _mask_content(
    content: str,
    actions: Sequence[tuple[Detection, PolicyAction]],
) -> str:
    spans = [
        (finding.start, finding.end, {finding.category})
        for finding, action in actions
        if action is PolicyAction.MASK
    ]
    spans.sort(key=lambda item: (item[0], item[1]))
    merged: list[tuple[int, int, set[DetectionCategory]]] = []
    for start, end, categories in spans:
        if merged and start < merged[-1][1]:
            prior_start, prior_end, prior_categories = merged[-1]
            merged[-1] = (prior_start, max(prior_end, end), prior_categories | categories)
        else:
            merged.append((start, end, set(categories)))
    output = content
    for start, end, categories in reversed(merged):
        marker = (
            _REDACTION_MARKERS[next(iter(categories))]
            if len(categories) == 1
            else "[SENSITIVE_REDACTED]"
        )
        output = output[:start] + marker + output[end:]
    return output


_E = TypeVar("_E", bound=Enum)


def _enum_or_none(value: object, enum_type: type[_E]) -> _E | None:
    return value if isinstance(value, enum_type) else None
