"""Signed tenant-context and Gateway-envelope contracts.

HMAC keys are injected by the trusted server composition and must never be
placed in request data, client configuration, logs, or audit summaries.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime, timedelta, timezone
from typing import Callable, Protocol

from bri.privacy.models import (
    DetectionCategory,
    DetectionCount,
    GatewayEnvelope,
    InputType,
    ProcessingDestination,
    ProcessingPurpose,
    PolicyAction,
    SignatureVersionProvenance,
    TenantContext,
    VerifiedShieldedContent,
)


_SAFE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_CONTEXT_ACTION = "privacy:process"


class UnverifiedShieldResult(ValueError):
    """Raised when a Gateway envelope is invalid, stale, or misbound."""

    def __init__(self) -> None:
        super().__init__("unverified_processing_result")


class TenantContextVerifier(Protocol):
    def verify(self, context: TenantContext, *, now: datetime) -> bool:
        """Verify an authorization-bound tenant context and its expiry."""
        ...


class TenantContextAuthority:
    """Issue short-lived context tokens only after server-side authorization.

    The caller that owns this authority must first complete BRI authentication,
    membership, action, and resource-scope checks. A tenant ID in a request is
    never sufficient to issue a context.
    """

    def __init__(
        self,
        key: bytes,
        *,
        clock: Callable[[], datetime] | None = None,
        max_lifetime: timedelta = timedelta(minutes=15),
    ) -> None:
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("invalid_context_key")
        if max_lifetime <= timedelta(0) or max_lifetime > timedelta(hours=1):
            raise ValueError("invalid_context_lifetime")
        self._key = key
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._max_lifetime = max_lifetime

    def issue(
        self,
        tenant_id: str,
        principal_id: str,
        scope_id: str,
        input_type: InputType,
        purpose: ProcessingPurpose,
        destination: ProcessingDestination,
        expires_at: datetime,
        *,
        action: str = _CONTEXT_ACTION,
    ) -> TenantContext:
        now = self._clock()
        if (
            not _valid_id(tenant_id)
            or not _valid_id(principal_id)
            or not _valid_id(scope_id)
            or not isinstance(input_type, InputType)
            or not isinstance(purpose, ProcessingPurpose)
            or not isinstance(destination, ProcessingDestination)
            or action != _CONTEXT_ACTION
            or not _aware(now)
            or not _aware(expires_at)
            or expires_at <= now
            or expires_at - now > self._max_lifetime
        ):
            raise ValueError("invalid_tenant_context")
        payload = _context_payload(
            tenant_id,
            principal_id,
            action,
            scope_id,
            input_type,
            purpose,
            destination,
            now,
            expires_at,
        )
        proof = hmac.new(self._key, b"tenant-context\0" + payload, hashlib.sha256).hexdigest()
        return TenantContext(
            tenant_id,
            principal_id,
            action,
            scope_id,
            input_type,
            purpose,
            destination,
            now,
            expires_at,
            proof,
        )

    def verify(self, context: TenantContext, *, now: datetime) -> bool:
        if not isinstance(context, TenantContext) or not _aware(now):
            return False
        if (
            not _valid_id(context.tenant_id)
            or not _valid_id(context.principal_id)
            or context.action != _CONTEXT_ACTION
            or not _valid_id(context.scope_id)
            or not isinstance(context.input_type, InputType)
            or not isinstance(context.purpose, ProcessingPurpose)
            or not isinstance(context.destination, ProcessingDestination)
            or not _aware(context.issued_at)
            or not _aware(context.expires_at)
            or context.issued_at > now
            or context.expires_at <= now
            or context.expires_at - context.issued_at > self._max_lifetime
            or not isinstance(context.proof, str)
            or not re.fullmatch(r"[0-9a-f]{64}", context.proof)
        ):
            return False
        expected = hmac.new(
            self._key,
            b"tenant-context\0"
            + _context_payload(
                context.tenant_id,
                context.principal_id,
                context.action,
                context.scope_id,
                context.input_type,
                context.purpose,
                context.destination,
                context.issued_at,
                context.expires_at,
            ),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, context.proof)


class ShieldAttestor:
    """Sign and verify short-lived, destination-bound sanitized envelopes."""

    def __init__(
        self,
        key: bytes,
        *,
        clock: Callable[[], datetime] | None = None,
        lifetime: timedelta = timedelta(minutes=2),
    ) -> None:
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("invalid_attestation_key")
        if lifetime <= timedelta(0) or lifetime > timedelta(minutes=10):
            raise ValueError("invalid_attestation_lifetime")
        self._key = key
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lifetime = lifetime

    def issue(
        self,
        *,
        processing_id: str,
        tenant_id: str,
        resource_scope_id: str,
        input_type: InputType,
        purpose: ProcessingPurpose,
        destination: ProcessingDestination,
        decision: PolicyAction,
        sanitised_content: str,
        tenant_policy_id: str,
        tenant_policy_version: str,
        platform_policy_id: str,
        platform_policy_version: str,
        detection_counts: tuple[DetectionCount, ...],
        issued_at: datetime | None = None,
        signature_versions: SignatureVersionProvenance | None = None,
    ) -> GatewayEnvelope:
        now = issued_at or self._clock()
        if (
            not _aware(now)
            or not _valid_id(processing_id)
            or not _valid_id(tenant_id)
            or not _valid_id(resource_scope_id)
            or not isinstance(input_type, InputType)
            or not isinstance(purpose, ProcessingPurpose)
            or destination is not ProcessingDestination.AI_PROVIDER
            or not isinstance(decision, PolicyAction)
            or decision is PolicyAction.BLOCK
        ):
            raise ValueError("invalid_attestation_context")
        unsigned = GatewayEnvelope(
            processing_id=processing_id,
            tenant_id=tenant_id,
            resource_scope_id=resource_scope_id,
            input_type=input_type,
            purpose=purpose,
            destination=destination,
            decision=decision,
            sanitised_content=sanitised_content,
            tenant_policy_id=tenant_policy_id,
            tenant_policy_version=tenant_policy_version,
            platform_policy_id=platform_policy_id,
            platform_policy_version=platform_policy_version,
            detection_counts=detection_counts,
            issued_at=now,
            expires_at=now + self._lifetime,
            attestation="",
            signature_versions=signature_versions,
        )
        signature = self._sign(unsigned)
        return GatewayEnvelope(
            **{
                field: getattr(unsigned, field)
                for field in unsigned.__dataclass_fields__
                if field != "attestation"
            },
            attestation=signature,
        )

    def verify(
        self,
        envelope: GatewayEnvelope,
        *,
        expected_tenant_id: str,
        expected_scope_id: str,
        expected_input_type: InputType,
        expected_destination: ProcessingDestination,
        expected_purpose: ProcessingPurpose,
        now: datetime | None = None,
    ) -> VerifiedShieldedContent:
        current = now or self._clock()
        if not self._valid_envelope(envelope, current):
            raise UnverifiedShieldResult()
        if (
            envelope.tenant_id != expected_tenant_id
            or envelope.resource_scope_id != expected_scope_id
            or not isinstance(expected_input_type, InputType)
            or envelope.input_type is not expected_input_type
            or envelope.destination is not expected_destination
            or envelope.purpose is not expected_purpose
        ):
            raise UnverifiedShieldResult()
        expected = self._sign(
            GatewayEnvelope(
                **{
                    field: getattr(envelope, field)
                    for field in envelope.__dataclass_fields__
                }
            )
        )
        if not hmac.compare_digest(expected, envelope.attestation):
            raise UnverifiedShieldResult()
        return VerifiedShieldedContent(
            processing_id=envelope.processing_id,
            tenant_id=envelope.tenant_id,
            resource_scope_id=envelope.resource_scope_id,
            input_type=envelope.input_type,
            purpose=envelope.purpose,
            destination=envelope.destination,
            decision=envelope.decision,
            sanitised_content=envelope.sanitised_content,
            signature_versions=envelope.signature_versions,
        )

    def _valid_envelope(self, envelope: object, now: datetime) -> bool:
        if not isinstance(envelope, GatewayEnvelope) or not _aware(now):
            return False
        if (
            not _valid_id(envelope.processing_id)
            or not _valid_id(envelope.tenant_id)
            or not _valid_id(envelope.resource_scope_id)
            or not isinstance(envelope.input_type, InputType)
            or not isinstance(envelope.purpose, ProcessingPurpose)
            or not isinstance(envelope.destination, ProcessingDestination)
            or envelope.destination is not ProcessingDestination.AI_PROVIDER
            or not isinstance(envelope.decision, PolicyAction)
            or envelope.decision is PolicyAction.BLOCK
            or not isinstance(envelope.sanitised_content, str)
            or not isinstance(envelope.tenant_policy_id, str)
            or not _valid_id(envelope.tenant_policy_id)
            or not isinstance(envelope.tenant_policy_version, str)
            or not _valid_id(envelope.tenant_policy_version)
            or not isinstance(envelope.platform_policy_id, str)
            or not _valid_id(envelope.platform_policy_id)
            or not isinstance(envelope.platform_policy_version, str)
            or not _valid_id(envelope.platform_policy_version)
            or not _aware(envelope.issued_at)
            or not _aware(envelope.expires_at)
            or envelope.issued_at > now
            or envelope.expires_at <= now
            or envelope.expires_at - envelope.issued_at > self._lifetime
            or not isinstance(envelope.attestation, str)
            or not re.fullmatch(r"[0-9a-f]{64}", envelope.attestation)
            or not _valid_signature_versions(envelope.signature_versions)
            or not isinstance(envelope.detection_counts, tuple)
            or any(
                not isinstance(item, DetectionCount)
                or not isinstance(item.category, DetectionCategory)
                or not isinstance(item.count, int)
                or item.count <= 0
                for item in envelope.detection_counts
            )
        ):
            return False
        return True

    def _sign(self, envelope: GatewayEnvelope) -> str:
        return hmac.new(
            self._key,
            b"privacy-shield-envelope\0" + _envelope_payload(envelope),
            hashlib.sha256,
        ).hexdigest()


def _context_payload(
    tenant_id: str,
    principal_id: str,
    action: str,
    scope_id: str,
    input_type: InputType,
    purpose: ProcessingPurpose,
    destination: ProcessingDestination,
    issued_at: datetime,
    expires_at: datetime,
) -> bytes:
    return _canonical(
        {
            "tenant_id": tenant_id,
            "principal_id": principal_id,
            "action": action,
            "scope_id": scope_id,
            "input_type": input_type.value,
            "purpose": purpose.value,
            "destination": destination.value,
            "issued_at": issued_at.isoformat(),
            "expires_at": expires_at.isoformat(),
        }
    )


def _envelope_payload(envelope: GatewayEnvelope) -> bytes:
    return _canonical(
        {
            "processing_id": envelope.processing_id,
            "tenant_id": envelope.tenant_id,
            "resource_scope_id": envelope.resource_scope_id,
            "input_type": getattr(envelope.input_type, "value", None),
            "purpose": getattr(envelope.purpose, "value", None),
            "destination": getattr(envelope.destination, "value", None),
            "decision": getattr(envelope.decision, "value", None),
            "sanitised_content": envelope.sanitised_content,
            "tenant_policy_id": envelope.tenant_policy_id,
            "tenant_policy_version": envelope.tenant_policy_version,
            "platform_policy_id": envelope.platform_policy_id,
            "platform_policy_version": envelope.platform_policy_version,
            "detection_counts": [
                {"category": item.category.value, "count": item.count}
                for item in envelope.detection_counts
            ],
            "issued_at": envelope.issued_at.isoformat(),
            "expires_at": envelope.expires_at.isoformat(),
            "signature_versions": None if envelope.signature_versions is None else {
                "engine_version": envelope.signature_versions.engine_version,
                "global_package_version": envelope.signature_versions.global_package_version,
                "regional_package_versions": list(envelope.signature_versions.regional_package_versions),
                "tenant_signature_version": envelope.signature_versions.tenant_signature_version,
                "effective_configuration_version": envelope.signature_versions.effective_configuration_version,
            },
        }
    )


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8", "strict")


def _valid_signature_versions(value: object) -> bool:
    if value is None:
        return True
    if not isinstance(value, SignatureVersionProvenance):
        return False
    if not all(_valid_id(item) for item in (
        value.engine_version,
        value.global_package_version,
        value.tenant_signature_version,
        value.effective_configuration_version,
    )):
        return False
    if not isinstance(value.regional_package_versions, tuple):
        return False
    pairs = value.regional_package_versions
    return (
        all(isinstance(pair, tuple) and len(pair) == 2 and _valid_id(pair[0]) and _valid_id(pair[1]) for pair in pairs)
        and tuple(sorted(pairs)) == pairs
        and len({pair[0] for pair in pairs}) == len(pairs)
        and "global" not in {pair[0] for pair in pairs}
    )


def _valid_id(value: object) -> bool:
    return isinstance(value, str) and _SAFE_ID.fullmatch(value) is not None


def _aware(value: object) -> bool:
    return isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() is not None
