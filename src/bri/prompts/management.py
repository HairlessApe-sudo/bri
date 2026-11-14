"""Versioned platform/client prompt contracts and deterministic assembly.

The in-memory repository is an isolated reference implementation. Production
adapters must implement the same compare-and-swap operations transactionally.
"""
from __future__ import annotations

import hashlib
import re
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Protocol

from bri.access.policy import AccessGrant, Principal, Resource, is_authorized

PLATFORM_TENANT_ID = "brs-platform"
PLATFORM_PROMPT_SCOPE = "platform-prompt"
MAX_PROMPT_CHARS = 32_000
MAX_CHANGE_DESCRIPTION_CHARS = 512


class PromptLayer(str, Enum):
    PLATFORM = "platform"
    CLIENT = "client"


class PromptError(Exception):
    """Base class for safe prompt-management errors."""


class PromptAuthorizationError(PermissionError, PromptError):
    pass


class PromptValidationError(ValueError, PromptError):
    pass


class PromptNotFoundError(LookupError, PromptError):
    pass


class PromptVersionConflict(RuntimeError, PromptError):
    pass


class PromptNotApprovedError(PromptError):
    pass


@dataclass(frozen=True, slots=True)
class PromptVersion:
    layer: PromptLayer
    tenant_id: str | None
    version: int
    version_id: str
    author_id: str
    created_at: datetime
    change_description: str
    previous_version_ref: str | None
    content_hash: str
    content: str = field(repr=False)
    restored_from_version_id: str | None = None


@dataclass(frozen=True, slots=True)
class PromptAuditEvent:
    layer: PromptLayer
    tenant_id: str | None
    action: str
    version_id: str
    actor_id: str
    occurred_at: datetime
    status: str
    content_hash: str


@dataclass(frozen=True, slots=True)
class PromptProvenance:
    platform_version_id: str
    platform_version: int
    platform_content_hash: str
    client_version_id: str
    client_version: int
    client_content_hash: str


@dataclass(frozen=True, slots=True)
class PromptSection:
    layer: PromptLayer
    trust_level: str
    version_id: str
    content: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class AssembledPrompt:
    tenant_id: str
    sections: tuple[PromptSection, ...]
    provenance: PromptProvenance


class PromptRepository(Protocol):
    """Repository contract; append/activate calls must be atomic CAS writes."""

    def latest_version_number(self, layer: PromptLayer, tenant_id: str | None) -> int: ...
    def version(self, layer: PromptLayer, tenant_id: str | None, version: int) -> PromptVersion | None: ...
    def versions(self, layer: PromptLayer, tenant_id: str | None) -> tuple[PromptVersion, ...]: ...
    def active_version(self, layer: PromptLayer, tenant_id: str | None) -> PromptVersion | None: ...
    def active_pair(self, tenant_id: str) -> tuple[PromptVersion | None, PromptVersion | None]: ...
    def append_version(self, value: PromptVersion, expected_latest_version: int) -> None: ...
    def approve(self, layer: PromptLayer, tenant_id: str | None, version: int, event: PromptAuditEvent) -> None: ...
    def activate(self, layer: PromptLayer, tenant_id: str | None, version: int, expected_active_version: int, event: PromptAuditEvent, deactivation_event: PromptAuditEvent | None) -> None: ...
    def events(self, layer: PromptLayer, tenant_id: str | None) -> tuple[PromptAuditEvent, ...]: ...


class InMemoryPromptRepository:
    """Thread-safe append-only repository for tests and local composition."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._versions: dict[tuple[PromptLayer, str | None], list[PromptVersion]] = {}
        self._events: dict[tuple[PromptLayer, str | None], list[PromptAuditEvent]] = {}
        self._active: dict[tuple[PromptLayer, str | None], int] = {}

    @staticmethod
    def _key(layer: PromptLayer, tenant_id: str | None) -> tuple[PromptLayer, str | None]:
        if not isinstance(layer, PromptLayer):
            raise PromptValidationError("invalid_prompt_layer")
        if layer is PromptLayer.PLATFORM and tenant_id is not None:
            raise PromptValidationError("platform_prompt_has_no_tenant")
        if layer is PromptLayer.CLIENT and not _valid_tenant_id(tenant_id):
            raise PromptValidationError("invalid_tenant_context")
        return layer, tenant_id

    def latest_version_number(self, layer: PromptLayer, tenant_id: str | None) -> int:
        key = self._key(layer, tenant_id)
        with self._lock:
            values = self._versions.get(key, ())
            return values[-1].version if values else 0

    def version(self, layer: PromptLayer, tenant_id: str | None, version: int) -> PromptVersion | None:
        key = self._key(layer, tenant_id)
        with self._lock:
            return next((item for item in self._versions.get(key, ()) if item.version == version), None)

    def versions(self, layer: PromptLayer, tenant_id: str | None) -> tuple[PromptVersion, ...]:
        key = self._key(layer, tenant_id)
        with self._lock:
            return tuple(self._versions.get(key, ()))

    def active_version(self, layer: PromptLayer, tenant_id: str | None) -> PromptVersion | None:
        key = self._key(layer, tenant_id)
        with self._lock:
            active = self._active.get(key)
            if active is None:
                return None
            return next((item for item in self._versions.get(key, ()) if item.version == active), None)

    def active_pair(self, tenant_id: str) -> tuple[PromptVersion | None, PromptVersion | None]:
        _require_tenant(tenant_id)
        platform_key = (PromptLayer.PLATFORM, None)
        client_key = (PromptLayer.CLIENT, tenant_id)
        with self._lock:
            def resolve(key: tuple[PromptLayer, str | None]) -> PromptVersion | None:
                active = self._active.get(key)
                if active is None:
                    return None
                return next((item for item in self._versions.get(key, ()) if item.version == active), None)
            return resolve(platform_key), resolve(client_key)

    def append_version(self, value: PromptVersion, expected_latest_version: int) -> None:
        key = self._key(value.layer, value.tenant_id)
        with self._lock:
            values = self._versions.setdefault(key, [])
            latest = values[-1].version if values else 0
            if latest != expected_latest_version or value.version != latest + 1:
                raise PromptVersionConflict("prompt_latest_version_conflict")
            if value.previous_version_ref != (values[-1].version_id if values else None):
                raise PromptVersionConflict("prompt_previous_version_conflict")
            if any(item.version_id == value.version_id for item in values):
                raise PromptVersionConflict("prompt_version_id_conflict")
            values.append(value)
            self._events.setdefault(key, []).append(
                PromptAuditEvent(value.layer, value.tenant_id, "created", value.version_id, value.author_id, value.created_at, "draft", value.content_hash)
            )

    def approve(self, layer: PromptLayer, tenant_id: str | None, version: int, event: PromptAuditEvent) -> None:
        key = self._key(layer, tenant_id)
        with self._lock:
            item = next((entry for entry in self._versions.get(key, ()) if entry.version == version), None)
            if item is None:
                raise PromptNotFoundError("prompt_version_not_found")
            if not any(entry.action == "approved" and entry.version_id == item.version_id for entry in self._events.get(key, ())):
                self._events.setdefault(key, []).append(event)

    def activate(self, layer: PromptLayer, tenant_id: str | None, version: int, expected_active_version: int, event: PromptAuditEvent, deactivation_event: PromptAuditEvent | None) -> None:
        key = self._key(layer, tenant_id)
        with self._lock:
            active = self._active.get(key, 0)
            if active != expected_active_version:
                raise PromptVersionConflict("prompt_active_version_conflict")
            values = self._versions.get(key, ())
            target = next((item for item in values if item.version == version), None)
            if target is None:
                raise PromptNotFoundError("prompt_version_not_found")
            if not any(entry.action == "approved" and entry.version_id == target.version_id for entry in self._events.get(key, ())):
                raise PromptNotApprovedError("prompt_version_not_approved")
            if active and deactivation_event is not None:
                self._events.setdefault(key, []).append(deactivation_event)
            self._active[key] = version
            self._events.setdefault(key, []).append(event)

    def events(self, layer: PromptLayer, tenant_id: str | None) -> tuple[PromptAuditEvent, ...]:
        key = self._key(layer, tenant_id)
        with self._lock:
            return tuple(self._events.get(key, ()))


class PromptManager:
    """Authorization-enforcing prompt service; principals must be server-resolved."""

    def __init__(
        self,
        repository: PromptRepository,
        *,
        clock: Callable[[], datetime] | None = None,
        id_factory: Callable[[], str] | None = None,
    ) -> None:
        if not all(callable(getattr(repository, name, None)) for name in (
            "latest_version_number", "version", "versions", "active_version", "active_pair", "append_version", "approve", "activate", "events"
        )):
            raise ValueError("invalid_prompt_repository")
        self._repository = repository
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._id_factory = id_factory or (lambda: uuid.uuid4().hex)

    def create_platform_version(self, principal: Principal, content: str, change_description: str, *, expected_latest_version: int) -> PromptVersion:
        self._authorize_platform_manage(principal)
        return self._create(PromptLayer.PLATFORM, None, principal, content, change_description, expected_latest_version)

    def create_client_version(self, principal: Principal, tenant_id: str, content: str, change_description: str, *, expected_latest_version: int) -> PromptVersion:
        self._authorize_client_manage(principal, tenant_id)
        return self._create(PromptLayer.CLIENT, tenant_id, principal, content, change_description, expected_latest_version)

    def current_platform(self, principal: Principal, *, tenant_id: str | None = None) -> PromptVersion:
        if tenant_id is None:
            self._authorize_platform_read(principal)
        else:
            self._authorize_tenant_platform_read(principal, tenant_id)
        return self._current(PromptLayer.PLATFORM, None)

    def current_client(self, principal: Principal, tenant_id: str) -> PromptVersion:
        self._authorize_client_read(principal, tenant_id)
        return self._current(PromptLayer.CLIENT, tenant_id)

    def platform_history(self, principal: Principal) -> tuple[PromptVersion, ...]:
        self._authorize_platform_manage(principal)
        return self._repository.versions(PromptLayer.PLATFORM, None)

    def client_history(self, principal: Principal, tenant_id: str) -> tuple[PromptVersion, ...]:
        self._authorize_client_read(principal, tenant_id)
        return self._repository.versions(PromptLayer.CLIENT, tenant_id)

    def compare_platform_versions(self, principal: Principal, first: int, second: int) -> tuple[PromptVersion, PromptVersion]:
        self._authorize_platform_manage(principal)
        return self._compare(PromptLayer.PLATFORM, None, first, second)

    def compare_client_versions(self, principal: Principal, tenant_id: str, first: int, second: int) -> tuple[PromptVersion, PromptVersion]:
        self._authorize_client_read(principal, tenant_id)
        return self._compare(PromptLayer.CLIENT, tenant_id, first, second)

    def approve_platform_version(self, principal: Principal, version: int) -> None:
        self._authorize_platform_manage(principal)
        self._approve(PromptLayer.PLATFORM, None, principal, version)

    def approve_client_version(self, principal: Principal, tenant_id: str, version: int) -> None:
        self._authorize_client_manage(principal, tenant_id)
        self._approve(PromptLayer.CLIENT, tenant_id, principal, version)

    def activate_platform_version(self, principal: Principal, version: int, *, expected_active_version: int) -> None:
        self._authorize_platform_manage(principal)
        self._activate(PromptLayer.PLATFORM, None, principal, version, expected_active_version)

    def activate_client_version(self, principal: Principal, tenant_id: str, version: int, *, expected_active_version: int) -> None:
        self._authorize_client_manage(principal, tenant_id)
        self._activate(PromptLayer.CLIENT, tenant_id, principal, version, expected_active_version)

    def restore_platform_version(self, principal: Principal, version: int, *, expected_latest_version: int, change_description: str | None = None) -> PromptVersion:
        self._authorize_platform_manage(principal)
        return self._restore(PromptLayer.PLATFORM, None, principal, version, expected_latest_version, change_description)

    def restore_client_version(self, principal: Principal, tenant_id: str, version: int, *, expected_latest_version: int, change_description: str | None = None) -> PromptVersion:
        self._authorize_client_manage(principal, tenant_id)
        return self._restore(PromptLayer.CLIENT, tenant_id, principal, version, expected_latest_version, change_description)

    def audit_events(self, principal: Principal, layer: PromptLayer, tenant_id: str | None = None) -> tuple[PromptAuditEvent, ...]:
        if layer is PromptLayer.PLATFORM:
            self._authorize_platform_manage(principal)
            tenant_id = None
        else:
            if tenant_id is None:
                raise PromptValidationError("invalid_tenant_context")
            self._authorize_client_read(principal, tenant_id)
        return self._repository.events(layer, tenant_id if layer is PromptLayer.CLIENT else None)

    def assemble(self, principal: Principal, tenant_id: str) -> AssembledPrompt:
        self._authorize_tenant_platform_read(principal, tenant_id)
        self._authorize_client_read(principal, tenant_id)
        platform, client = self._repository.active_pair(tenant_id)
        if platform is None or client is None:
            raise PromptNotFoundError("active_prompt_not_found")
        return AssembledPrompt(
            tenant_id,
            (
                PromptSection(PromptLayer.PLATFORM, "trusted_platform", platform.version_id, platform.content),
                PromptSection(PromptLayer.CLIENT, "untrusted_tenant_instruction", client.version_id, client.content),
            ),
            PromptProvenance(platform.version_id, platform.version, platform.content_hash, client.version_id, client.version, client.content_hash),
        )

    def _create(self, layer: PromptLayer, tenant_id: str | None, principal: Principal, content: str, description: str, expected_latest_version: int, *, restored_from: str | None = None) -> PromptVersion:
        clean_content = _validate_content(content)
        clean_description = _validate_description(description)
        if type(expected_latest_version) is not int or expected_latest_version < 0:
            raise PromptValidationError("invalid_expected_version")
        latest = self._repository.latest_version_number(layer, tenant_id)
        if latest != expected_latest_version:
            raise PromptVersionConflict("prompt_latest_version_conflict")
        previous = self._repository.version(layer, tenant_id, latest) if latest else None
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise PromptValidationError("invalid_prompt_clock")
        version_id = self._id_factory()
        if not isinstance(version_id, str) or re.fullmatch(r"[A-Za-z0-9._-]{1,128}", version_id) is None:
            raise PromptValidationError("invalid_prompt_version_id")
        version = PromptVersion(
            layer=layer,
            tenant_id=tenant_id,
            version=latest + 1,
            version_id=version_id,
            author_id=principal.subject_id,
            created_at=now,
            change_description=clean_description,
            previous_version_ref=previous.version_id if previous else None,
            content_hash=hashlib.sha256(clean_content.encode("utf-8", "strict")).hexdigest(),
            content=clean_content,
            restored_from_version_id=restored_from,
        )
        self._repository.append_version(version, expected_latest_version)
        return version

    def _current(self, layer: PromptLayer, tenant_id: str | None) -> PromptVersion:
        version = self._repository.active_version(layer, tenant_id)
        if version is None:
            raise PromptNotFoundError("active_prompt_not_found")
        return version

    def _compare(self, layer: PromptLayer, tenant_id: str | None, first: int, second: int) -> tuple[PromptVersion, PromptVersion]:
        _require_version_number(first)
        _require_version_number(second)
        left = self._repository.version(layer, tenant_id, first)
        right = self._repository.version(layer, tenant_id, second)
        if left is None or right is None:
            raise PromptNotFoundError("prompt_version_not_found")
        return left, right

    def _approve(self, layer: PromptLayer, tenant_id: str | None, principal: Principal, version: int) -> None:
        _require_version_number(version)
        target = self._repository.version(layer, tenant_id, version)
        if target is None:
            raise PromptNotFoundError("prompt_version_not_found")
        event = self._event(target, "approved", principal.subject_id, "approved")
        self._repository.approve(layer, tenant_id, version, event)

    def _activate(self, layer: PromptLayer, tenant_id: str | None, principal: Principal, version: int, expected_active_version: int) -> None:
        if type(expected_active_version) is not int or expected_active_version < 0:
            raise PromptValidationError("invalid_expected_version")
        _require_version_number(version)
        target = self._repository.version(layer, tenant_id, version)
        if target is None:
            raise PromptNotFoundError("prompt_version_not_found")
        prior = self._repository.active_version(layer, tenant_id)
        event = self._event(target, "activated", principal.subject_id, "active")
        deactivation = self._event(prior, "deactivated", principal.subject_id, "inactive") if prior else None
        self._repository.activate(layer, tenant_id, version, expected_active_version, event, deactivation)

    def _restore(self, layer: PromptLayer, tenant_id: str | None, principal: Principal, source_version: int, expected_latest_version: int, description: str | None) -> PromptVersion:
        _require_version_number(source_version)
        source = self._repository.version(layer, tenant_id, source_version)
        if source is None:
            raise PromptNotFoundError("prompt_version_not_found")
        label = description or f"Restore prompt version {source.version}"
        return self._create(layer, tenant_id, principal, source.content, label, expected_latest_version, restored_from=source.version_id)

    def _event(self, version: PromptVersion, action: str, actor_id: str, status: str) -> PromptAuditEvent:
        now = self._clock()
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            raise PromptValidationError("invalid_prompt_clock")
        return PromptAuditEvent(version.layer, version.tenant_id, action, version.version_id, actor_id, now, status, version.content_hash)

    @staticmethod
    def _authorize_platform_manage(principal: Principal | None) -> None:
        if not _has_platform_grant(principal, "prompt:platform:manage"):
            raise PromptAuthorizationError("platform_prompt_management_forbidden")

    @staticmethod
    def _authorize_platform_read(principal: Principal | None) -> None:
        if not (
            _has_platform_grant(principal, "prompt:platform:read")
            or _has_platform_grant(principal, "prompt:platform:manage")
        ):
            raise PromptAuthorizationError("platform_prompt_read_forbidden")

    @staticmethod
    def _authorize_tenant_platform_read(principal: Principal | None, tenant_id: str) -> None:
        _require_tenant(tenant_id)
        if not is_authorized(principal, "prompt:platform:read", Resource(tenant_id, tenant_id)):
            raise PromptAuthorizationError("platform_prompt_read_forbidden")

    @staticmethod
    def _authorize_client_manage(principal: Principal | None, tenant_id: str) -> None:
        _require_tenant(tenant_id)
        if not (
            is_authorized(principal, "prompt:client:manage", Resource(tenant_id, tenant_id))
            or is_authorized(principal, "platform:prompt:tenant:manage", Resource(tenant_id, tenant_id))
        ):
            raise PromptAuthorizationError("client_prompt_management_forbidden")

    @staticmethod
    def _authorize_client_read(principal: Principal | None, tenant_id: str) -> None:
        _require_tenant(tenant_id)
        if not (
            is_authorized(principal, "prompt:client:read", Resource(tenant_id, tenant_id))
            or is_authorized(principal, "prompt:client:manage", Resource(tenant_id, tenant_id))
            or is_authorized(principal, "platform:prompt:tenant:manage", Resource(tenant_id, tenant_id))
        ):
            raise PromptAuthorizationError("client_prompt_read_forbidden")


def _has_platform_grant(principal: Principal | None, action: str) -> bool:
    return (
        principal is not None
        and bool(principal.subject_id)
        and AccessGrant(PLATFORM_TENANT_ID, action, PLATFORM_PROMPT_SCOPE) in principal.grants
    )


def _require_version_number(version: object) -> None:
    if type(version) is not int or version < 1:
        raise PromptValidationError("invalid_prompt_version")


def _valid_tenant_id(tenant_id: object) -> bool:
    return isinstance(tenant_id, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", tenant_id) is not None


def _require_tenant(tenant_id: object) -> None:
    if not _valid_tenant_id(tenant_id):
        raise PromptValidationError("invalid_tenant_context")


def _validate_content(content: object) -> str:
    if not isinstance(content, str) or not content.strip() or len(content) > MAX_PROMPT_CHARS:
        raise PromptValidationError("invalid_prompt_content")
    try:
        content.encode("utf-8", "strict")
    except UnicodeEncodeError:
        raise PromptValidationError("invalid_prompt_content") from None
    if "\x00" in content or any(ord(char) < 32 and char not in "\t\n\r" for char in content):
        raise PromptValidationError("invalid_prompt_content")
    # Reject common credential-bearing material; this is a guard, not a secret scanner.
    secret_patterns = (
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
        r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
        r"\b(?:sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{20,})\b",
        r"(?im)\bauthorization\s*[:=]\s*bearer\s+[^\s'\"]{8,}",
        r"(?im)\b(?:api[_-]?key|password|client[_-]?secret|access[_-]?token|secret|credential|authorization)\s*[:=]\s*['\"]?[^\s'\"]{8,}",
    )
    if any(re.search(pattern, content) for pattern in secret_patterns):
        raise PromptValidationError("prompt_must_not_contain_credentials")
    return content


def _validate_description(description: object) -> str:
    if not isinstance(description, str) or not description.strip() or len(description) > MAX_CHANGE_DESCRIPTION_CHARS:
        raise PromptValidationError("invalid_change_description")
    if any(ord(char) < 32 and char not in "\t\n\r" for char in description):
        raise PromptValidationError("invalid_change_description")
    return description.strip()
