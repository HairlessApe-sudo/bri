"""Versioned regional packages and tenant-scoped signature management.

The in-memory store is a local/test reference implementation. Production callers
must supply a durable, tenant-isolated repository and trusted resolved Principal.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Callable, Mapping, Protocol, Sequence

from bri.access.policy import Principal, Resource, is_authorized
from bri.privacy.detection import SignatureDetector
from bri.privacy.models import Detection, DetectionCategory, TenantSignature


class SignatureAuthorizationError(PermissionError):
    """The trusted principal has no exact tenant-scoped management grant."""


class SignatureValidationError(ValueError):
    """A supplied tenant signature is invalid or outside the safe regex subset."""


@dataclass(frozen=True, slots=True)
class ManagedTenantSignature:
    signature_id: str
    pattern: str = field(repr=False)
    category: DetectionCategory = DetectionCategory.TENANT_SENSITIVE
    case_sensitive: bool = False
    is_regex: bool = False
    active: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.signature_id, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", self.signature_id):
            raise SignatureValidationError("invalid_signature_id")
        if not isinstance(self.pattern, str) or not self.pattern or len(self.pattern) > 128:
            raise SignatureValidationError("invalid_signature")
        if any(ord(ch) < 32 for ch in self.pattern):
            raise SignatureValidationError("invalid_signature")
        if self.category is not DetectionCategory.TENANT_SENSITIVE:
            raise SignatureValidationError("tenant_signature_category_not_allowed")
        if not isinstance(self.case_sensitive, bool) or not isinstance(self.is_regex, bool) or not isinstance(self.active, bool):
            raise SignatureValidationError("invalid_signature")
        if self.is_regex:
            _validate_safe_regex(self.pattern)

    def as_literal_signature(self) -> TenantSignature:
        if self.is_regex:
            raise SignatureValidationError("regex_requires_regional_detector")
        return TenantSignature(self.signature_id, self.pattern, self.category, self.case_sensitive)


@dataclass(frozen=True, slots=True)
class PrivacyShieldConfig:
    tenant_id: str
    primary_jurisdiction: str
    additional_regions: tuple[str, ...] = ()
    version: int = 1

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}", self.tenant_id):
            raise ValueError("invalid_tenant_configuration")
        if not isinstance(self.primary_jurisdiction, str) or not re.fullmatch(r"[A-Z]{2}", self.primary_jurisdiction):
            raise ValueError("unsupported_primary_jurisdiction")
        if not isinstance(self.additional_regions, tuple) or any(not isinstance(region, str) or not re.fullmatch(r"[A-Z]{2}", region) for region in self.additional_regions):
            raise ValueError("invalid_additional_regions")
        if self.primary_jurisdiction in self.additional_regions or len(set(self.additional_regions)) != len(self.additional_regions):
            raise ValueError("duplicate_region")
        if not isinstance(self.version, int) or self.version < 1:
            raise ValueError("invalid_configuration_version")


@dataclass(frozen=True, slots=True)
class SignaturePackage:
    package_id: str
    version: str
    jurisdiction: str | None
    available: bool = True

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,63}", self.package_id) or not re.fullmatch(r"[A-Za-z0-9._-]{1,40}", self.version):
            raise ValueError("invalid_signature_package")
        if self.jurisdiction is not None and (not isinstance(self.jurisdiction, str) or not re.fullmatch(r"[A-Z]{2}", self.jurisdiction)) or not isinstance(self.available, bool):
            raise ValueError("invalid_signature_package")


@dataclass(frozen=True, slots=True)
class EffectiveSignatureConfig:
    tenant_id: str
    package_ids: tuple[str, ...]
    package_versions: Mapping[str, str]
    tenant_signature_version: str
    configuration_version: str
    engine_version: str


@dataclass(frozen=True, slots=True)
class ResolvedSignatureConfiguration:
    config: PrivacyShieldConfig
    effective: EffectiveSignatureConfig
    tenant_signatures: tuple[ManagedTenantSignature, ...]
    registry: RegionalSignatureRegistry


class SignatureConfigurationProvider(Protocol):
    def load(self, tenant_id: str) -> ResolvedSignatureConfiguration | None:
        ...


class MappingSignatureConfigurationProvider:
    """Explicit in-memory provider; missing tenant config is never defaulted."""
    def __init__(self, configs: Mapping[str, PrivacyShieldConfig] | InMemoryShieldConfigurationStore, registry: RegionalSignatureRegistry, store: InMemoryTenantSignatureStore | None = None) -> None:
        self._configs = dict(configs) if isinstance(configs, Mapping) else None
        self._configuration_store = None if isinstance(configs, Mapping) else configs
        self._registry = registry
        self._store = store or InMemoryTenantSignatureStore()

    def load(self, tenant_id: str) -> ResolvedSignatureConfiguration | None:
        if self._configs is not None:
            config = self._configs.get(tenant_id)
        else:
            revision = self._configuration_store.current(tenant_id) if self._configuration_store is not None else None
            config = revision.config if revision is not None else None
        if config is None or config.tenant_id != tenant_id:
            return None
        revision = self._store.current(tenant_id)
        effective = self._registry.resolve(config, tenant_signature_version=str(revision.version))
        return ResolvedSignatureConfiguration(config, effective, revision.signatures, self._registry)


class RegionalSignatureRegistry:
    def __init__(
        self,
        packages: Sequence[SignaturePackage],
        *,
        engine_version: str = "1",
        engine_history: Sequence[str] | None = None,
        jurisdiction_packages: Mapping[str, str] | None = None,
        regional_detectors: Mapping[str, Callable[[str], Sequence[Detection]]] | None = None,
    ) -> None:
        histories: dict[str, list[SignaturePackage]] = {}
        for package in packages:
            histories.setdefault(package.package_id, []).append(package)
        if "global" not in histories:
            raise ValueError("invalid_signature_registry")
        for package_id, versions in histories.items():
            if len({package.version for package in versions}) != len(versions):
                raise ValueError("duplicate_signature_package_version")
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,40}", engine_version):
            raise ValueError("invalid_engine_version")
        history = tuple(engine_history) if engine_history is not None else (engine_version,)
        if not history or history[-1] != engine_version or any(not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9._-]{1,40}", item) for item in history):
            raise ValueError("invalid_engine_version_history")
        self._package_history = MappingProxyType({key: tuple(value) for key, value in histories.items()})
        self._packages = {key: value[-1] for key, value in histories.items()}
        discovered = {package.jurisdiction: package.package_id for package in self._packages.values() if package.jurisdiction is not None}
        configured = {**discovered, **dict(jurisdiction_packages or {})}
        if any(not re.fullmatch(r"[A-Z]{2}", region) or package_id not in self._packages or self._packages[package_id].jurisdiction != region for region, package_id in configured.items()):
            raise ValueError("invalid_jurisdiction_package_mapping")
        if len(set(configured.values())) != len(configured):
            raise ValueError("duplicate_jurisdiction_package")
        self.jurisdiction_packages = MappingProxyType(configured)
        self.regional_detectors = MappingProxyType(dict(regional_detectors or {}))
        if any(region not in configured or not callable(detector) for region, detector in self.regional_detectors.items()):
            raise ValueError("invalid_regional_detector")
        self.engine_version = engine_version
        self._engine_history = history

    def package_history(self, package_id: str) -> tuple[SignaturePackage, ...]:
        return self._package_history.get(package_id, ())

    @property
    def engine_history(self) -> tuple[str, ...]:
        return self._engine_history

    @classmethod
    def with_defaults(cls) -> "RegionalSignatureRegistry":
        return cls((SignaturePackage("global", "1", None), SignaturePackage("netherlands", "1", "NL"), SignaturePackage("australia", "1", "AU")))

    def resolve(self, config: PrivacyShieldConfig, *, tenant_signature_version: str = "0") -> EffectiveSignatureConfig:
        if not isinstance(config, PrivacyShieldConfig):
            raise ValueError("invalid_tenant_configuration")
        active_regions = (config.primary_jurisdiction, *sorted(config.additional_regions))
        try:
            package_ids = ("global", *(self.jurisdiction_packages[region] for region in active_regions))
        except KeyError:
            raise RuntimeError("required_signature_package_unavailable") from None
        versions: dict[str, str] = {}
        for package_id in package_ids:
            package = self._packages.get(package_id)
            if package is None or not package.available:
                raise RuntimeError("required_signature_package_unavailable")
            versions[package_id] = package.version
        material = {"tenant": config.tenant_id, "config": config.version, "packages": versions, "tenant_signatures": tenant_signature_version, "engine": self.engine_version}
        fingerprint = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]
        return EffectiveSignatureConfig(config.tenant_id, package_ids, MappingProxyType(versions), tenant_signature_version, f"cfg-{fingerprint}", self.engine_version)


class RegionalSignatureDetector:
    """Global detections plus only the configured regional signatures."""
    def __init__(self, config: PrivacyShieldConfig, registry: RegionalSignatureRegistry | None = None, *, tenant_signatures: Sequence[ManagedTenantSignature] = ()) -> None:
        self.registry = registry or RegionalSignatureRegistry.with_defaults()
        self.effective_config = self.registry.resolve(config)
        self.config = config
        if any(not isinstance(signature, ManagedTenantSignature) for signature in tenant_signatures):
            raise ValueError("invalid_tenant_signature")
        self._tenant_signatures = tuple(signature for signature in tenant_signatures if signature.active)

    def detect(self, text: str) -> tuple[Detection, ...]:
        if not isinstance(text, str) or len(text) > 100_000:
            raise ValueError("content_out_of_bounds")
        findings: set[Detection] = set()
        # Package order is deterministic: mandatory global, then selected regions.
        global_detector = SignatureDetector(jurisdiction=None)
        findings.update(global_detector.detect(text))
        active_regions = (self.config.primary_jurisdiction, *sorted(self.config.additional_regions))
        for region in active_regions:
            detector = self.registry.regional_detectors.get(region)
            if detector is None:
                if region not in {"NL", "AU"}:
                    raise RuntimeError("regional_detector_unavailable")
                detected = SignatureDetector(jurisdiction=region).detect(text)
            else:
                detected = detector(text)
            if not isinstance(detected, (tuple, list)) or any(
                not isinstance(item, Detection) or item.start < 0 or item.end > len(text)
                for item in detected
            ):
                raise RuntimeError("invalid_regional_detector_result")
            findings.update(detected)
        for signature in self._tenant_signatures:
            pattern = signature.pattern if signature.is_regex else re.escape(signature.pattern)
            compiled = re.compile(pattern, 0 if signature.case_sensitive else re.IGNORECASE | re.UNICODE)
            for match in compiled.finditer(text):
                if match.end() > match.start():
                    findings.add(Detection(signature.category, match.start(), match.end()))
        return tuple(sorted(findings, key=lambda item: (item.start, item.end, item.category.value)))


@dataclass(frozen=True, slots=True)
class TenantSignatureRevision:
    tenant_id: str
    version: int
    signatures: tuple[ManagedTenantSignature, ...]


class InMemoryTenantSignatureStore:
    """Append-only revision store intended for tests and local composition."""
    def __init__(self) -> None:
        self._history: dict[str, list[TenantSignatureRevision]] = {}

    def history(self, tenant_id: str) -> tuple[TenantSignatureRevision, ...]:
        return tuple(self._history.get(tenant_id, ()))

    def current(self, tenant_id: str) -> TenantSignatureRevision:
        history = self._history.get(tenant_id, [])
        return history[-1] if history else TenantSignatureRevision(tenant_id, 0, ())

    def append(self, tenant_id: str, signatures: Sequence[ManagedTenantSignature]) -> TenantSignatureRevision:
        current = self.current(tenant_id)
        revision = TenantSignatureRevision(tenant_id, current.version + 1, tuple(signatures))
        self._history.setdefault(tenant_id, []).append(revision)
        return revision


class TenantSignatureManager:
    def __init__(self, store: InMemoryTenantSignatureStore) -> None:
        self._store = store

    def create(self, principal: Principal, tenant_id: str, signature: ManagedTenantSignature) -> TenantSignatureRevision:
        current = self._authorized_current(principal, tenant_id)
        if not isinstance(signature, ManagedTenantSignature):
            raise SignatureValidationError("invalid_signature")
        if any(item.signature_id == signature.signature_id for item in current.signatures):
            raise SignatureValidationError("signature_already_exists")
        return self._store.append(tenant_id, (*current.signatures, signature))

    def read(self, principal: Principal, tenant_id: str) -> tuple[ManagedTenantSignature, ...]:
        self._authorize_read(principal, tenant_id)
        return self._store.current(tenant_id).signatures

    def update(self, principal: Principal, tenant_id: str, signature_id: str, replacement: ManagedTenantSignature) -> TenantSignatureRevision:
        current = self._authorized_current(principal, tenant_id)
        if not isinstance(replacement, ManagedTenantSignature):
            raise SignatureValidationError("invalid_signature")
        if signature_id != replacement.signature_id or not any(item.signature_id == signature_id for item in current.signatures):
            raise SignatureValidationError("signature_not_found")
        return self._store.append(tenant_id, tuple(replacement if item.signature_id == signature_id else item for item in current.signatures))

    def deactivate(self, principal: Principal, tenant_id: str, signature_id: str) -> TenantSignatureRevision:
        current = self._authorized_current(principal, tenant_id)
        if not any(item.signature_id == signature_id for item in current.signatures):
            raise SignatureValidationError("signature_not_found")
        return self._store.append(tenant_id, tuple(ManagedTenantSignature(item.signature_id, item.pattern, item.category, item.case_sensitive, item.is_regex, False) if item.signature_id == signature_id else item for item in current.signatures))

    def history(self, principal: Principal, tenant_id: str) -> tuple[TenantSignatureRevision, ...]:
        self._authorize_read(principal, tenant_id)
        return self._store.history(tenant_id)

    def restore(self, principal: Principal, tenant_id: str, version: int) -> TenantSignatureRevision:
        self._authorize(principal, tenant_id)
        source = next((item for item in self._store.history(tenant_id) if item.version == version), None)
        if source is None:
            raise SignatureValidationError("signature_version_not_found")
        return self._store.append(tenant_id, source.signatures)

    def test(self, principal: Principal, tenant_id: str, signature: ManagedTenantSignature, synthetic_text: str) -> tuple[Detection, ...]:
        self._authorize_read(principal, tenant_id)
        if not isinstance(signature, ManagedTenantSignature):
            raise SignatureValidationError("invalid_signature")
        if not isinstance(synthetic_text, str) or len(synthetic_text) > 100_000:
            raise SignatureValidationError("synthetic_text_out_of_bounds")
        pattern = signature.pattern if signature.is_regex else re.escape(signature.pattern)
        compiled = re.compile(pattern, 0 if signature.case_sensitive else re.IGNORECASE | re.UNICODE)
        return tuple(
            Detection(signature.category, match.start(), match.end())
            for match in compiled.finditer(synthetic_text)
            if match.end() > match.start()
        )

    def _authorized_current(self, principal: Principal, tenant_id: str) -> TenantSignatureRevision:
        self._authorize(principal, tenant_id)
        return self._store.current(tenant_id)

    @staticmethod
    def _authorize_read(principal: Principal, tenant_id: str) -> None:
        if not (
            is_authorized(principal, "privacy:signature:read", Resource(tenant_id, tenant_id))
            or is_authorized(principal, "privacy:signature:manage", Resource(tenant_id, tenant_id))
        ):
            raise SignatureAuthorizationError("signature_read_forbidden")

    @staticmethod
    def _authorize(principal: Principal, tenant_id: str) -> None:
        if not is_authorized(principal, "privacy:signature:manage", Resource(tenant_id, tenant_id)):
            raise SignatureAuthorizationError("signature_management_forbidden")


@dataclass(frozen=True, slots=True)
class PrivacyShieldInspection:
    configuration: ShieldConfigurationRevision
    effective: EffectiveSignatureConfig
    capabilities: tuple[tuple[str, tuple[str, ...]], ...]


@dataclass(frozen=True, slots=True)
class ShieldConfigurationRevision:
    tenant_id: str
    version: int
    config: PrivacyShieldConfig


class InMemoryShieldConfigurationStore:
    """Append-only jurisdiction/configuration history for tests and local use."""
    def __init__(self) -> None:
        self._history: dict[str, list[ShieldConfigurationRevision]] = {}

    def history(self, tenant_id: str) -> tuple[ShieldConfigurationRevision, ...]:
        return tuple(self._history.get(tenant_id, ()))

    def current(self, tenant_id: str) -> ShieldConfigurationRevision | None:
        history = self._history.get(tenant_id, ())
        return history[-1] if history else None

    def append(self, config: PrivacyShieldConfig) -> ShieldConfigurationRevision:
        current = self.current(config.tenant_id)
        expected = 1 if current is None else current.version + 1
        if config.version != expected:
            raise ValueError("configuration_version_must_increase")
        revision = ShieldConfigurationRevision(config.tenant_id, config.version, config)
        self._history.setdefault(config.tenant_id, []).append(revision)
        return revision


class PrivacyShieldConfigurationManager:
    def __init__(self, store: InMemoryShieldConfigurationStore) -> None:
        self._store = store

    def configure(self, principal: Principal, tenant_id: str, primary_jurisdiction: str, additional_regions: tuple[str, ...] = ()) -> ShieldConfigurationRevision:
        self._authorize(principal, tenant_id)
        current = self._store.current(tenant_id)
        version = 1 if current is None else current.version + 1
        return self._store.append(PrivacyShieldConfig(tenant_id, primary_jurisdiction, additional_regions, version))

    def read(self, principal: Principal, tenant_id: str) -> ShieldConfigurationRevision | None:
        self._authorize_read(principal, tenant_id)
        return self._store.current(tenant_id)

    def inspect(self, principal: Principal, tenant_id: str, registry: RegionalSignatureRegistry) -> PrivacyShieldInspection | None:
        revision = self.read(principal, tenant_id)
        if revision is None:
            return None
        effective = registry.resolve(revision.config)
        capability_map = {
            "global": ("email", "phone", "iban", "bank_account", "date_of_birth"),
            "netherlands": ("bsn", "phone", "postal_address", "date_of_birth"),
            "australia": ("tax_file_number", "date_of_birth"),
        }
        capabilities = tuple((package_id, capability_map.get(package_id, ())) for package_id in effective.package_ids)
        return PrivacyShieldInspection(revision, effective, capabilities)

    def history(self, principal: Principal, tenant_id: str) -> tuple[ShieldConfigurationRevision, ...]:
        self._authorize_read(principal, tenant_id)
        return self._store.history(tenant_id)

    def restore(self, principal: Principal, tenant_id: str, version: int) -> ShieldConfigurationRevision:
        self._authorize(principal, tenant_id)
        original = next((item for item in self._store.history(tenant_id) if item.version == version), None)
        if original is None:
            raise ValueError("configuration_version_not_found")
        return self.configure(principal, tenant_id, original.config.primary_jurisdiction, original.config.additional_regions)

    @staticmethod
    def _authorize_read(principal: Principal, tenant_id: str) -> None:
        if not (
            is_authorized(principal, "privacy:configuration:read", Resource(tenant_id, tenant_id))
            or is_authorized(principal, "privacy:configuration:manage", Resource(tenant_id, tenant_id))
        ):
            raise SignatureAuthorizationError("configuration_read_forbidden")

    @staticmethod
    def _authorize(principal: Principal, tenant_id: str) -> None:
        if not is_authorized(principal, "privacy:configuration:manage", Resource(tenant_id, tenant_id)):
            raise SignatureAuthorizationError("configuration_management_forbidden")


def _validate_safe_regex(pattern: str) -> None:
    """Allow a bounded linear subset: atoms, classes and finite quantifiers only."""
    if len(pattern) > 128 or any(token in pattern for token in ("(", ")", "|", "*", "+", "?", "\\1", "\\g", "(?")):
        raise SignatureValidationError("unsafe_signature_pattern")
    if re.search(r"\{\s*\d{1,4}(?:\s*,\s*\d{0,4})?\s*\}", pattern) is None and "{" in pattern:
        raise SignatureValidationError("unsafe_signature_pattern")
    quantifiers = tuple(re.finditer(r"\{(\d+)(?:,(\d*))?\}", pattern))
    if len(quantifiers) > 1:
        raise SignatureValidationError("unsafe_signature_pattern")
    for match in quantifiers:
        if match.group(2) == "":
            raise SignatureValidationError("unsafe_signature_pattern")
        lower = int(match.group(1))
        upper = int(match.group(2) or match.group(1)) if match.group(2) is not None else lower
        if lower > 64 or upper > 64 or upper < lower:
            raise SignatureValidationError("unsafe_signature_pattern")
    # Prevent all unbounded operators and group/alternation constructs; then compile.
    if any(token in pattern for token in ("*", "+", "?", "(", ")", "|")):
        raise SignatureValidationError("unsafe_signature_pattern")
    try:
        re.compile(pattern)
    except re.error:
        raise SignatureValidationError("invalid_signature_pattern") from None
