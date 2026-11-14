"""PostgreSQL adapters for the prompt repository contract.

The supplied scope factory must open one transaction and establish trusted
``bri.tenant_id`` / ``bri.auth_user_id`` context before yielding a connection.
It is intentionally injected rather than deriving database authority from the
caller-provided tenant argument.
"""
from __future__ import annotations

from contextlib import AbstractContextManager
import psycopg
from typing import Callable

from bri.prompts.management import (
    PromptAuditEvent, PromptLayer, PromptNotApprovedError, PromptNotFoundError,
    PromptVersion, PromptVersionConflict,
)

ConnectionScope = Callable[[str | None], AbstractContextManager[psycopg.Connection]]


class PostgresPromptRepository:
    """Transaction-backed repository; writes use database CAS and advisory locks."""

    def __init__(self, connection_scope: ConnectionScope) -> None:
        if not callable(connection_scope):
            raise ValueError("invalid_connection_scope")
        self._scope = connection_scope

    @staticmethod
    def _tenant(layer: PromptLayer, tenant_id: str | None) -> str | None:
        if layer is PromptLayer.PLATFORM:
            if tenant_id is not None:
                raise ValueError("platform_prompt_has_no_tenant")
            return None
        if layer is not PromptLayer.CLIENT or not isinstance(tenant_id, str) or not tenant_id:
            raise ValueError("invalid_tenant_context")
        return tenant_id

    @staticmethod
    def _version(row: tuple) -> PromptVersion:
        layer, tenant, number, version_id, author, created, description, previous, restored, digest, content = row
        return PromptVersion(PromptLayer(layer), tenant, number, version_id, author, created, description, previous, digest, content, restored)

    @staticmethod
    def _event(row: tuple) -> PromptAuditEvent:
        layer, tenant, action, version_id, actor, occurred, status, digest = row
        return PromptAuditEvent(PromptLayer(layer), tenant, action, version_id, actor, occurred, status, digest)

    @staticmethod
    def _read(connection, query: str, params: tuple):
        return connection.execute(query, params)

    def latest_version_number(self, layer: PromptLayer, tenant_id: str | None) -> int:
        tenant = self._tenant(layer, tenant_id)
        with self._scope(tenant) as conn:
            return conn.execute("SELECT coalesce(max(version),0) FROM bri.prompt_versions WHERE layer=%s AND tenant_id IS NOT DISTINCT FROM %s", (layer.value, tenant)).fetchone()[0]

    def version(self, layer: PromptLayer, tenant_id: str | None, version: int) -> PromptVersion | None:
        tenant = self._tenant(layer, tenant_id)
        with self._scope(tenant) as conn:
            row = conn.execute("SELECT layer,tenant_id,version,version_id,author_id,created_at,change_description,previous_version_ref,restored_from_version_id,content_hash,content FROM bri.prompt_versions WHERE layer=%s AND tenant_id IS NOT DISTINCT FROM %s AND version=%s", (layer.value, tenant, version)).fetchone()
            return self._version(row) if row else None

    def versions(self, layer: PromptLayer, tenant_id: str | None) -> tuple[PromptVersion, ...]:
        tenant = self._tenant(layer, tenant_id)
        with self._scope(tenant) as conn:
            rows = conn.execute("SELECT layer,tenant_id,version,version_id,author_id,created_at,change_description,previous_version_ref,restored_from_version_id,content_hash,content FROM bri.prompt_versions WHERE layer=%s AND tenant_id IS NOT DISTINCT FROM %s ORDER BY version", (layer.value, tenant)).fetchall()
            return tuple(map(self._version, rows))

    def active_version(self, layer: PromptLayer, tenant_id: str | None) -> PromptVersion | None:
        tenant = self._tenant(layer, tenant_id)
        with self._scope(tenant) as conn:
            row = conn.execute("SELECT v.layer,v.tenant_id,v.version,v.version_id,v.author_id,v.created_at,v.change_description,v.previous_version_ref,v.restored_from_version_id,v.content_hash,v.content FROM bri.prompt_active_versions a JOIN bri.prompt_versions v ON v.layer=a.layer AND v.tenant_id IS NOT DISTINCT FROM a.tenant_id AND v.version=a.version WHERE a.layer=%s AND a.tenant_id IS NOT DISTINCT FROM %s", (layer.value, tenant)).fetchone()
            return self._version(row) if row else None

    def active_pair(self, tenant_id: str) -> tuple[PromptVersion | None, PromptVersion | None]:
        if not isinstance(tenant_id, str) or not tenant_id:
            raise ValueError("invalid_tenant_context")
        with self._scope(tenant_id) as conn:
            rows = conn.execute("SELECT v.layer,v.tenant_id,v.version,v.version_id,v.author_id,v.created_at,v.change_description,v.previous_version_ref,v.restored_from_version_id,v.content_hash,v.content FROM bri.prompt_active_versions a JOIN bri.prompt_versions v ON v.layer=a.layer AND v.tenant_id IS NOT DISTINCT FROM a.tenant_id AND v.version=a.version WHERE (a.layer='platform' AND a.tenant_id IS NULL) OR (a.layer='client' AND a.tenant_id=%s) ORDER BY a.layer", (tenant_id,)).fetchall()
            found = {PromptLayer(row[0]): self._version(row) for row in rows}
            return found.get(PromptLayer.PLATFORM), found.get(PromptLayer.CLIENT)

    def append_version(self, value: PromptVersion, expected_latest_version: int) -> None:
        tenant = self._tenant(value.layer, value.tenant_id)
        with self._scope(tenant) as conn:
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (f"prompt:{value.layer.value}:{tenant or ''}",))
            row = conn.execute("SELECT version,version_id FROM bri.prompt_versions WHERE layer=%s AND tenant_id IS NOT DISTINCT FROM %s ORDER BY version DESC LIMIT 1", (value.layer.value, tenant)).fetchone()
            latest, prior = row if row else (0, None)
            if latest != expected_latest_version or value.version != latest + 1:
                raise PromptVersionConflict("prompt_latest_version_conflict")
            if value.previous_version_ref != prior:
                raise PromptVersionConflict("prompt_previous_version_conflict")
            conn.execute("INSERT INTO bri.prompt_versions(layer,tenant_id,version,version_id,author_id,created_at,change_description,previous_version_ref,restored_from_version_id,content_hash,content) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)", (value.layer.value, tenant, value.version, value.version_id, value.author_id, value.created_at, value.change_description, value.previous_version_ref, value.restored_from_version_id, value.content_hash, value.content))
            self._insert_event(conn, PromptAuditEvent(value.layer, tenant, "created", value.version_id, value.author_id, value.created_at, "draft", value.content_hash))

    @staticmethod
    def _insert_event(conn, event: PromptAuditEvent) -> None:
        conn.execute("INSERT INTO bri.prompt_lifecycle_events(layer,tenant_id,version,version_id,action,actor_id,occurred_at,status,content_hash) VALUES (%s,%s,(SELECT version FROM bri.prompt_versions WHERE version_id=%s),%s,%s,%s,%s,%s,%s)", (event.layer.value, event.tenant_id, event.version_id, event.version_id, event.action, event.actor_id, event.occurred_at, event.status, event.content_hash))

    def approve(self, layer: PromptLayer, tenant_id: str | None, version: int, event: PromptAuditEvent) -> None:
        tenant = self._tenant(layer, tenant_id)
        with self._scope(tenant) as conn:
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s,0))", (f"prompt-approval:{layer.value}:{tenant or ''}:{version}",))
            row = conn.execute("SELECT version_id,content_hash FROM bri.prompt_versions WHERE layer=%s AND tenant_id IS NOT DISTINCT FROM %s AND version=%s", (layer.value, tenant, version)).fetchone()
            if not row:
                raise PromptNotFoundError("prompt_version_not_found")
            exists = conn.execute("SELECT 1 FROM bri.prompt_lifecycle_events WHERE layer=%s AND tenant_id IS NOT DISTINCT FROM %s AND version=%s AND action='approved'", (layer.value, tenant, version)).fetchone()
            if not exists:
                self._insert_event(conn, event)

    def activate(self, layer: PromptLayer, tenant_id: str | None, version: int, expected_active_version: int, event: PromptAuditEvent, deactivation_event: PromptAuditEvent | None) -> None:
        tenant = self._tenant(layer, tenant_id)
        with self._scope(tenant) as conn:
            conn.execute("SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))", (f"prompt-active:{layer.value}:{tenant or ''}",))
            active = conn.execute("SELECT version FROM bri.prompt_active_versions WHERE layer=%s AND tenant_id IS NOT DISTINCT FROM %s FOR UPDATE", (layer.value, tenant)).fetchone()
            current = active[0] if active else 0
            if current != expected_active_version:
                raise PromptVersionConflict("prompt_active_version_conflict")
            target = conn.execute("SELECT version_id FROM bri.prompt_versions WHERE layer=%s AND tenant_id IS NOT DISTINCT FROM %s AND version=%s", (layer.value, tenant, version)).fetchone()
            if target is None:
                raise PromptNotFoundError("prompt_version_not_found")
            approved = conn.execute("SELECT 1 FROM bri.prompt_lifecycle_events WHERE layer=%s AND tenant_id IS NOT DISTINCT FROM %s AND version=%s AND action='approved'", (layer.value, tenant, version)).fetchone()
            if approved is None:
                raise PromptNotApprovedError("prompt_version_not_approved")
            if current and deactivation_event:
                self._insert_event(conn, deactivation_event)
            active_sql = "INSERT INTO bri.prompt_active_versions(layer,tenant_id,version,version_id,changed_at) VALUES (%s,%s,%s,%s,%s) ON CONFLICT (layer,tenant_id) WHERE layer='client' DO UPDATE SET version=EXCLUDED.version,version_id=EXCLUDED.version_id,changed_at=EXCLUDED.changed_at" if tenant is not None else "INSERT INTO bri.prompt_active_versions(layer,tenant_id,version,version_id,changed_at) VALUES (%s,%s,%s,%s,%s) ON CONFLICT (layer) WHERE layer='platform' DO UPDATE SET version=EXCLUDED.version,version_id=EXCLUDED.version_id,changed_at=EXCLUDED.changed_at"
            conn.execute(active_sql, (layer.value, tenant, version, target[0], event.occurred_at))
            self._insert_event(conn, event)

    def events(self, layer: PromptLayer, tenant_id: str | None) -> tuple[PromptAuditEvent, ...]:
        tenant = self._tenant(layer, tenant_id)
        with self._scope(tenant) as conn:
            rows = conn.execute("SELECT layer,tenant_id,action,version_id,actor_id,occurred_at,status,content_hash FROM bri.prompt_lifecycle_events WHERE layer=%s AND tenant_id IS NOT DISTINCT FROM %s ORDER BY occurred_at,event_id", (layer.value, tenant)).fetchall()
            return tuple(map(self._event, rows))
