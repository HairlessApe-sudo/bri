"""PostgreSQL stores for tenant-owned Privacy Shield configuration histories.

A scope factory is supplied by trusted server composition. It opens one database
transaction and sets tenant context from the verified request; it must never
accept an untrusted client tenant header as authority.
"""
from __future__ import annotations

import hashlib
import json
from contextlib import AbstractContextManager
from typing import Callable, Sequence

import psycopg
from psycopg.types.json import Jsonb

from bri.privacy.models import DetectionCategory
from bri.privacy.regional import (
    ManagedTenantSignature, PrivacyShieldConfig, ShieldConfigurationRevision,
    RegionalSignatureRegistry, ResolvedSignatureConfiguration,
    SignaturePackage, TenantSignatureRevision,
)

TenantScope = Callable[[str], AbstractContextManager[psycopg.Connection]]


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _signature_data(values: Sequence[ManagedTenantSignature]) -> list[dict[str, object]]:
    return [{"signature_id": item.signature_id, "pattern": item.pattern,
             "category": item.category.value, "case_sensitive": item.case_sensitive,
             "is_regex": item.is_regex, "active": item.active} for item in values]


def _signatures(value: list[dict[str, object]]) -> tuple[ManagedTenantSignature, ...]:
    return tuple(ManagedTenantSignature(
        str(item["signature_id"]), str(item["pattern"]),
        DetectionCategory(str(item["category"])), bool(item["case_sensitive"]),
        bool(item["is_regex"]), bool(item["active"]),
    ) for item in value)


class PostgresTenantSignatureStore:
    """Append-only, CAS-protected tenant signature revisions and metadata audit."""
    def __init__(self, scope: TenantScope) -> None:
        self._scope = scope

    def history(self, tenant_id: str) -> tuple[TenantSignatureRevision, ...]:
        with self._scope(tenant_id) as conn:
            rows = conn.execute("SELECT tenant_id,version,signatures FROM bri.tenant_signature_revisions WHERE tenant_id=%s ORDER BY version", (tenant_id,)).fetchall()
            return tuple(TenantSignatureRevision(row[0], row[1], _signatures(row[2])) for row in rows)

    def current(self, tenant_id: str) -> TenantSignatureRevision:
        history = self.history(tenant_id)
        return history[-1] if history else TenantSignatureRevision(tenant_id, 0, ())

    def append(self, tenant_id: str, signatures: Sequence[ManagedTenantSignature]) -> TenantSignatureRevision:
        current = self.current(tenant_id)
        return self.append_version(tenant_id, signatures, current.version)

    def append_version(self, tenant_id: str, signatures: Sequence[ManagedTenantSignature], expected_version: int, *, author_id: str = "system", restored_from_version: int | None = None) -> TenantSignatureRevision:
        payload = _signature_data(signatures)
        digest = _digest(payload)
        with self._scope(tenant_id) as conn:
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", (f"shield-signatures:{tenant_id}",))
            row = conn.execute("SELECT coalesce(max(version),0) FROM bri.tenant_signature_revisions WHERE tenant_id=%s", (tenant_id,)).fetchone()
            if row[0] != expected_version:
                raise RuntimeError("signature_revision_conflict")
            version = expected_version + 1
            conn.execute("INSERT INTO bri.tenant_signature_revisions(tenant_id,version,signatures,restored_from_version,created_by) VALUES (%s,%s,%s,%s,%s)", (tenant_id, version, Jsonb(payload), restored_from_version, author_id))
            conn.execute("INSERT INTO bri.configuration_audit_events(tenant_id,actor_id,action,resource_type,resource_version,content_hash) VALUES (%s,%s,%s,'tenant_signatures',%s,%s)", (tenant_id, author_id, "restored" if restored_from_version is not None else "revised", str(version), digest))
            return TenantSignatureRevision(tenant_id, version, tuple(signatures))


class PostgresShieldConfigurationStore:
    """Append-only tenant jurisdiction configuration and metadata-only audit."""
    def __init__(self, scope: TenantScope) -> None:
        self._scope = scope

    @staticmethod
    def _revision(row) -> ShieldConfigurationRevision:
        config = PrivacyShieldConfig(row[0], row[2], tuple(row[3]), row[1])
        return ShieldConfigurationRevision(row[0], row[1], config)

    def history(self, tenant_id: str) -> tuple[ShieldConfigurationRevision, ...]:
        with self._scope(tenant_id) as conn:
            rows = conn.execute("SELECT tenant_id,version,primary_jurisdiction,additional_regions FROM bri.shield_config_revisions WHERE tenant_id=%s ORDER BY version", (tenant_id,)).fetchall()
            return tuple(self._revision(row) for row in rows)

    def current(self, tenant_id: str) -> ShieldConfigurationRevision | None:
        history = self.history(tenant_id)
        return history[-1] if history else None

    def append(self, config: PrivacyShieldConfig) -> ShieldConfigurationRevision:
        current = self.current(config.tenant_id)
        return self.append_version(config, current.version if current else 0)

    def append_version(self, config: PrivacyShieldConfig, expected_version: int, *, author_id: str = "system", restored_from_version: int | None = None) -> ShieldConfigurationRevision:
        tenant_id = config.tenant_id
        data = {"primary": config.primary_jurisdiction, "additional": list(config.additional_regions)}
        digest = _digest(data)
        with self._scope(tenant_id) as conn:
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", (f"shield-config:{tenant_id}",))
            row = conn.execute("SELECT coalesce(max(version),0) FROM bri.shield_config_revisions WHERE tenant_id=%s", (tenant_id,)).fetchone()
            if row[0] != expected_version or config.version != expected_version + 1:
                raise RuntimeError("configuration_version_conflict")
            conn.execute("INSERT INTO bri.shield_config_revisions(tenant_id,version,primary_jurisdiction,additional_regions,restored_from_version,created_by) VALUES (%s,%s,%s,%s,%s,%s)", (tenant_id, config.version, config.primary_jurisdiction, list(config.additional_regions), restored_from_version, author_id))
            conn.execute("INSERT INTO bri.configuration_audit_events(tenant_id,actor_id,action,resource_type,resource_version,content_hash) VALUES (%s,%s,%s,'shield_configuration',%s,%s)", (tenant_id, author_id, "restored" if restored_from_version is not None else "revised", str(config.version), digest))
        return ShieldConfigurationRevision(tenant_id, config.version, config)


class PostgresSignaturePackageStore:
    """Platform-only immutable package catalog and activation pointer store."""
    def __init__(self, scope: Callable[[str | None], AbstractContextManager[psycopg.Connection]]) -> None:
        self._scope = scope

    def history(self, package_id: str) -> tuple[SignaturePackage, ...]:
        with self._scope(None) as conn:
            rows = conn.execute("SELECT package_id,version,jurisdiction,available FROM bri.signature_package_versions WHERE package_id=%s ORDER BY created_at,version", (package_id,)).fetchall()
            return tuple(SignaturePackage(*row) for row in rows)

    def active_versions(self, tenant_id: str | None = None) -> dict[str, str]:
        with self._scope(tenant_id) as conn:
            rows = conn.execute("SELECT package_id,version FROM bri.signature_package_activation ORDER BY package_id").fetchall()
            return dict(rows)

    def active_catalog(self, tenant_id: str | None = None) -> tuple[SignaturePackage, ...]:
        with self._scope(tenant_id) as conn:
            rows = conn.execute("SELECT p.package_id,p.version,p.jurisdiction,p.available FROM bri.signature_package_activation a JOIN bri.signature_package_versions p ON p.package_id=a.package_id AND p.version=a.version ORDER BY p.package_id").fetchall()
            return tuple(SignaturePackage(*row) for row in rows)

    def append_version(self, package: SignaturePackage, expected_latest_version: str | None, *, actor_id: str, metadata: dict[str, object] | None = None) -> None:
        data = metadata or {}
        with self._scope(None) as conn:
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", (f"signature-package:{package.package_id}",))
            row = conn.execute("SELECT version FROM bri.signature_package_versions WHERE package_id=%s ORDER BY created_at DESC,version DESC LIMIT 1", (package.package_id,)).fetchone()
            latest = row[0] if row else None
            if latest != expected_latest_version:
                raise RuntimeError("signature_package_version_conflict")
            conn.execute("INSERT INTO bri.signature_package_versions(package_id,version,jurisdiction,available,metadata) VALUES (%s,%s,%s,%s,%s)", (package.package_id, package.version, package.jurisdiction, package.available, Jsonb(data)))
            conn.execute("INSERT INTO bri.configuration_audit_events(tenant_id,actor_id,action,resource_type,resource_version,content_hash) VALUES (NULL,%s,'package_version_created','signature_package',%s,%s)", (actor_id, f"{package.package_id}:{package.version}", _digest(data)))

    def activate(self, package_id: str, version: str, expected_active_version: str | None, *, actor_id: str) -> None:
        with self._scope(None) as conn:
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", (f"signature-activation:{package_id}",))
            row = conn.execute("SELECT version FROM bri.signature_package_activation WHERE package_id=%s FOR UPDATE", (package_id,)).fetchone()
            current = row[0] if row else None
            if current != expected_active_version:
                raise RuntimeError("signature_package_active_version_conflict")
            target = conn.execute("SELECT available FROM bri.signature_package_versions WHERE package_id=%s AND version=%s", (package_id, version)).fetchone()
            if target is None:
                raise LookupError("signature_package_version_not_found")
            if not target[0]:
                raise ValueError("signature_package_unavailable")
            conn.execute("INSERT INTO bri.signature_package_activation(package_id,version) VALUES (%s,%s) ON CONFLICT(package_id) DO UPDATE SET version=EXCLUDED.version,activated_at=now()", (package_id, version))
            conn.execute("INSERT INTO bri.configuration_audit_events(tenant_id,actor_id,action,resource_type,resource_version,content_hash) VALUES (NULL,%s,'package_activated','signature_package',%s,NULL)", (actor_id, f"{package_id}:{version}"))


class PostgresSignatureConfigurationProvider:
    """Resolve one coherent tenant/config/package snapshot from PostgreSQL."""
    def __init__(self, scope: TenantScope, engine_registry: RegionalSignatureRegistry) -> None:
        self._scope = scope
        self._engine = engine_registry

    def load(self, tenant_id: str) -> ResolvedSignatureConfiguration | None:
        with self._scope(tenant_id) as conn:
            row = conn.execute("""
                WITH cfg AS (
                    SELECT tenant_id,version,primary_jurisdiction,additional_regions
                    FROM bri.shield_config_revisions WHERE tenant_id=%s ORDER BY version DESC LIMIT 1
                ), sig AS (
                    SELECT tenant_id,version,signatures FROM bri.tenant_signature_revisions
                    WHERE tenant_id=%s ORDER BY version DESC LIMIT 1
                ), packages AS (
                    SELECT coalesce(jsonb_agg(jsonb_build_object(
                        'package_id',p.package_id,'version',p.version,
                        'jurisdiction',p.jurisdiction,'available',p.available
                    ) ORDER BY p.package_id),'[]'::jsonb) AS values
                    FROM bri.signature_package_activation a
                    JOIN bri.signature_package_versions p
                      ON p.package_id=a.package_id AND p.version=a.version
                )
                SELECT (SELECT version FROM cfg),
                       (SELECT primary_jurisdiction FROM cfg),
                       (SELECT additional_regions FROM cfg),
                       coalesce((SELECT version FROM sig),0),
                       coalesce((SELECT signatures FROM sig),'[]'::jsonb),
                       packages.values
                FROM packages
            """, (tenant_id,tenant_id)).fetchone()
        if row is None or row[0] is None:
            return None
        config = PrivacyShieldConfig(tenant_id, row[1], tuple(row[2]), row[0])
        signatures = _signatures(row[4])
        active = {item["package_id"]: SignaturePackage(
            item["package_id"], item["version"], item["jurisdiction"], item["available"]
        ) for item in row[5]}
        package_ids = {"global", *self._engine.jurisdiction_packages.values()}
        catalog: list[SignaturePackage] = []
        for package_id in sorted(package_ids):
            package = active.get(package_id)
            if package is None:
                previous = self._engine.package_history(package_id)
                if not previous:
                    continue
                prior = previous[-1]
                package = SignaturePackage(package_id, prior.version, prior.jurisdiction, False)
            catalog.append(package)
        registry = RegionalSignatureRegistry(
            catalog, engine_version=self._engine.engine_version,
            engine_history=self._engine.engine_history,
            jurisdiction_packages=self._engine.jurisdiction_packages,
            regional_detectors=self._engine.regional_detectors,
        )
        effective = registry.resolve(config, tenant_signature_version=str(row[3]))
        return ResolvedSignatureConfiguration(config, effective, signatures, registry)
