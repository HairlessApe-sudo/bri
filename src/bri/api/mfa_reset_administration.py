"""Read-only MFA reset administration adapter for the private approvals stage."""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Literal
from uuid import UUID

import psycopg
from fastapi import HTTPException
from pydantic import BaseModel, StrictBool

from bri.api.authentication import AuthenticatedIdentity
from bri.api.database import Database, DatabaseUnavailable

State = Literal[
    "PENDING", "APPROVED", "REJECTED", "EXPIRED", "EXECUTING", "COMPLETED", "FAILED"
]
Reason = Literal["LOST_FACTOR", "COMPROMISED_FACTOR", "REPLACED_DEVICE"]
Reconciliation = Literal["NONE", "PENDING", "UNRESOLVED", "SAFE_HANDOFF", "VERIFIED_ABSENT"]


class QueueItem(BaseModel):
    approval_id: UUID
    target_id: UUID
    target_name: str | None
    requester_label: Literal["Restricted requester"] = "Restricted requester"
    reason: Reason
    requested_at: datetime
    expires_at: datetime
    state: State
    reconciliation: Reconciliation
    can_decide: StrictBool


class QueuePage(BaseModel):
    items: list[QueueItem]
    next_cursor: UUID | None


class Eligibility(BaseModel):
    eligible: StrictBool


def invalid_queue_query() -> HTTPException:
    return HTTPException(400, "Invalid approval queue query")


def queue_parameters(pairs: list[tuple[str, str]]) -> tuple[int, UUID | None]:
    values: dict[str, str] = {}
    for key, value in pairs:
        if key not in {"limit", "cursor"} or key in values:
            raise invalid_queue_query()
        values[key] = value
    limit = values.get("limit", "25")
    if not (1 <= len(limit) <= 3 and limit.isascii() and limit.isdecimal() and 1 <= int(limit) <= 100):
        raise invalid_queue_query()
    cursor = values.get("cursor")
    if cursor is None:
        return int(limit), None
    try:
        parsed = UUID(cursor) if len(cursor) == 36 else None
    except ValueError:
        parsed = None
    if parsed is None or str(parsed) != cursor.lower():
        raise invalid_queue_query()
    return int(limit), parsed


@dataclass(frozen=True, slots=True)
class AdministrationReader:
    """The tenant, principal and BRI session must come from verified server state."""

    database: Database
    tenant: str
    actor: str
    identity: AuthenticatedIdentity

    @contextmanager
    def _read(self) -> Iterator[tuple[psycopg.Connection, tuple]]:
        with self.database.protected_tenant_context(
            self.tenant, auth_user_id=self.identity.auth_user_id,
            session_id=self.identity.session_id, principal_id=self.actor, issuer=self.identity.issuer,
        ) as session:
            if session.connection is None:
                raise DatabaseUnavailable("Approval read context unavailable")
            try:
                yield session.connection, (
                    self.tenant, UUID(self.actor), UUID(self.identity.session_id), self.identity.issuer,
                )
            except psycopg.errors.InsufficientPrivilege:
                # Translate inside the scope before its generic database wrapper.
                raise PermissionError("Approval denied") from None

    def queue(self, limit: int, *, cursor: UUID | None = None, item: UUID | None = None) -> list[QueueItem]:
        with self._read() as (db, authority):
            try:
                rows = db.execute(
                    "SELECT approval_id,target_id,target_name,reason,requested_at,expires_at,state,reconciliation,can_decide "
                    "FROM bri.read_mfa_reset_queue(%s,%s,%s,%s,%s,%s,%s)",
                    (*authority, limit, cursor, item),
                ).fetchall()
            except psycopg.errors.InvalidParameterValue:
                if cursor is None:
                    raise
                raise invalid_queue_query() from None
        return [QueueItem(
            approval_id=row[0], target_id=row[1], target_name=row[2], reason=row[3],
            requested_at=row[4], expires_at=row[5], state=row[6], reconciliation=row[7], can_decide=row[8],
        ) for row in rows]

    def eligibility(self, target: UUID) -> Eligibility:
        with self._read() as (db, authority):
            row = db.execute(
                "SELECT bri.can_request_mfa_reset(%s,%s,%s,%s,%s)", (*authority, target),
            ).fetchone()
            if row is None:
                raise DatabaseUnavailable("Approval eligibility unavailable")
            return Eligibility(eligible=row[0])

    def require_visible_target(self, target: UUID) -> None:
        # Visibility, not current eligibility: an A10 replay may legitimately
        # read its committed outcome after the target's eligibility changes.
        with self._read() as (db, authority):
            if db.execute(
                "SELECT id FROM bri.read_user_directory(%s,%s,%s,%s,%s,NULL,NULL,1,0)",
                (*authority, target),
            ).fetchone() != (target,):
                raise PermissionError("Approval denied")
