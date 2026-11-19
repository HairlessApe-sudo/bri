"""A10's server-only repository. No environment/config discovery, HTTP routes or provider credentials.

Inject fresh, idle connections for the restricted app and the *separate* worker.
Each command commits before it returns: in particular no provider call can occur
inside, or before commit of, the quarantine/dispatch transaction. Never bind this
module to browser-supplied identity, tenant, assurance, provider or worker outcomes.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

import psycopg
from psycopg.pq import TransactionStatus

from bri.api.authentication import AuthenticatedIdentity, has_recent_mfa
from bri.api.provider_mfa import ProviderMfaAdmin, ProviderMfaError

ACTION = "USER_MFA_RESET"
Scope = Callable[[], AbstractContextManager[psycopg.Connection]]


@dataclass(frozen=True, slots=True)
class ApprovalContext:
    """Server-derived tenant + provider-verified identity + middleware correlation UUID."""

    tenant_id: str
    identity: AuthenticatedIdentity
    correlation_id: UUID

    def bind(self, db: psycopg.Connection) -> None:
        ident = self.identity
        if (
            not has_recent_mfa(ident)
            or not self.tenant_id
            or not isinstance(self.correlation_id, UUID)
        ):
            raise PermissionError("approval step-up required")
        if ident.totp_authenticated_at is None:
            raise PermissionError("verified TOTP event missing")
        stamp = datetime.fromtimestamp(ident.totp_authenticated_at, UTC)
        db.execute(
            "SELECT set_config('bri.tenant_id',%s,true),set_config('bri.auth_user_id',%s,true),"
            "set_config('bri.session_id',%s,true),set_config('bri.aal',%s,true),"
            "set_config('bri.totp_at',%s,true),set_config('bri.correlation_id',%s,true),"
            "set_config('bri.auth_issuer',%s,true)",
            (
                self.tenant_id,
                str(UUID(ident.auth_user_id)),
                str(UUID(ident.session_id)),
                ident.assurance_level,
                stamp.isoformat(),
                str(self.correlation_id),
                ident.issuer,
            ),
        )


def _command(
    scope: Scope,
    ctx: ApprovalContext,
    query: str,
    params: tuple,
    *,
    role: str = "bri_app",
):
    with scope() as db:
        if db.info.transaction_status != TransactionStatus.IDLE:
            raise RuntimeError("approval requires its own transaction")
        with db.transaction():
            if not db.execute(
                "SELECT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname=current_user "
                "AND rolname=session_user AND rolname=%s AND NOT rolsuper AND NOT rolbypassrls "
                "AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolinherit)",
                (role,),
            ).fetchone()[0]:
                raise PermissionError("restricted approval role required")
            ctx.bind(db)
            return db.execute(query, (ctx.tenant_id, ACTION, *params)).fetchone()


class ApprovalRepository:
    def __init__(self, scope: Scope):
        self._scope = scope

    def request(
        self, ctx: ApprovalContext, *, target: UUID, reason: str, request_id: UUID
    ) -> str:
        """request_id is the stable idempotency key AND approval ID, not a bearer capability."""
        return _command(
            self._scope,
            ctx,
            "SELECT bri.approval_request(%s,%s,%s,%s,%s)",
            (target, reason, request_id),
        )[0]

    def decide(self, ctx: ApprovalContext, approval_id: UUID, decision: str) -> str:
        return _command(
            self._scope,
            ctx,
            "SELECT bri.approval_decide(%s,%s,%s,%s)",
            (approval_id, decision),
        )[0]

    def status(self, ctx: ApprovalContext, approval_id: UUID) -> str:
        return _command(
            self._scope, ctx, "SELECT bri.approval_status(%s,%s,%s)", (approval_id,)
        )[0]


class ResetProvider(Protocol):
    async def list_totp_factor_ids(self, user_id: str) -> Sequence[str]: ...
    async def remove_totp_factor(self, user_id: str, factor_id: str) -> None: ...
    async def factor_absent(self, user_id: str, factor_id: str) -> bool: ...


class ReconciliationMfaAdmin(ProviderMfaAdmin):
    """Read-only proof includes *unverified* factors; no second DELETE on a lost ack."""

    async def factor_absent(self, user_id: str, factor_id: str) -> bool:
        user_id, factor_id = str(UUID(user_id)), str(UUID(factor_id))
        async with self._client() as client:
            return factor_id not in await self._inventory(client, user_id)


class FactorInventoryReader:
    """GET-only observation adapter, no DELETE method or live credentials.

    Use a separately provisioned read-only provider capability if hosted execution
    is ever approved. The checked-in provider client supports mock transport only.
    """

    def __init__(self, *, test_transport=None):
        self._client_factory = ProviderMfaAdmin(test_transport=test_transport)._client

    async def snapshot(self, user_id: str) -> tuple[list[UUID], list[UUID]]:
        async with self._client_factory() as client:
            inventory = await ProviderMfaAdmin._inventory(client, str(UUID(user_id)))
        return (
            [UUID(f) for f in inventory],
            [UUID(f) for f, eligible in inventory.items() if eligible],
        )


class ApprovalObserver:
    """Discover interrupted operations by ID; attest readback independently of stale voters.

    The login has only USAGE on bri and EXECUTE on observation_queue/observe.
    Keep it separate from the reset worker and ordinary HTTP process. ``FAILED``
    with an unresolved dispatch never authorizes another external mutation.
    """

    def __init__(self, scope: Scope, reader: FactorInventoryReader):
        self._scope, self._reader = scope, reader

    def pending(self, after: UUID | None = None, batch: int = 50) -> list[UUID]:
        with self._scope() as db:
            if db.info.transaction_status != TransactionStatus.IDLE:
                raise RuntimeError("observer requires a dedicated idle connection")
            with db.transaction():
                return [
                    row[0]
                    for row in db.execute(
                        "SELECT * FROM bri.approval_observation_queue(%s,%s)",
                        (after, batch),
                    )
                ]

    async def observe(self, approval_id: UUID, *, correlation_id: UUID) -> str:
        from bri.api.database import EXPECTED_PROJECT_REF

        with self._scope() as db:
            if db.info.transaction_status != TransactionStatus.IDLE:
                raise RuntimeError("observer requires a dedicated idle connection")

            def observe(op, present=None, verified=None):
                with db.transaction():
                    return db.execute(
                        "SELECT * FROM bri.approval_observe(%s,%s,%s,%s::uuid[],%s::uuid[])",
                        (approval_id, op, correlation_id, present, verified),
                    ).fetchone()

            # PLAN commits before provider I/O. RECORD validates the unchanged
            # durable plan under the same per-operation lock used for dispatch.
            # A concurrent dispatch or lost connection can prevent recording, not
            # manufacture evidence. Retry a conflicting observation with a fresh ID.
            state, user, issuer = observe("PLAN")
            if user is None:
                return state
            if issuer != f"https://{EXPECTED_PROJECT_REF}.supabase.co/auth/v1":
                raise PermissionError("observer issuer mismatch")
            try:
                present, verified = await self._reader.snapshot(str(user))
            except ProviderMfaError:
                return observe("UNAVAILABLE")[0]
            return observe("RECORD", present, verified)[0]


class ApprovalWorker:
    """Trusted reconciliation runner. SQL role needs only USAGE and approval_work EXECUTE.

    Restart by re-invoking execute with the durable ID. An unconfirmed delete
    that still appears present cannot safely be reissued; leave FAILED and the
    subject suspended pending governed recovery. No automatic account activation.
    """

    def __init__(self, scope: Scope, provider: ResetProvider):
        self._scope = scope
        self._provider = provider

    async def execute(self, ctx: ApprovalContext, approval_id: UUID) -> str:
        # Serialize only this approval across provider I/O, without holding any
        # table lock or open DB transaction. Disconnect releases the advisory
        # lock; the durable per-factor dispatch receipt survives disconnection.
        lock_key = str(approval_id)
        with self._scope() as db:
            if db.info.transaction_status != TransactionStatus.IDLE:
                raise RuntimeError("worker requires a dedicated idle connection")

            def work(op, ids=None):
                return _command(
                    lambda: nullcontext(db),
                    ctx,
                    "SELECT * FROM bri.approval_work(%s,%s,%s,%s,%s::uuid[])",
                    (approval_id, op, ids),
                    role="bri_approval_worker",
                )

            with db.transaction():
                held = db.execute(
                    "SELECT pg_try_advisory_lock(hashtextextended(%s, 1010))",
                    (lock_key,),
                ).fetchone()[0]
            if not held:
                return work("STATUS")[0]
            try:
                return await self._reconcile(work)
            finally:
                with db.transaction():
                    db.execute(
                        "SELECT pg_advisory_unlock(hashtextextended(%s, 1010))",
                        (lock_key,),
                    )

    @staticmethod
    async def _provider_call(operation, *args):
        # Translate adapter exceptions only: a DB commit/cutoff failure must
        # *not* be classified as a known provider result. Process cancellation
        # leaves the committed EXECUTING state/dispatch receipt for readback.
        try:
            return await operation(*args)
        except Exception:  # noqa: BLE001 -- errors must not carry private provider response content
            raise ProviderMfaError("Provider outcome unavailable") from None

    async def _inventory(self, user: str) -> tuple[UUID, ...]:
        raw = await self._provider_call(self._provider.list_totp_factor_ids, user)
        if not isinstance(raw, (tuple, list)) or len(raw) > 256:
            raise ProviderMfaError("Invalid inventory")
        try:
            parsed = tuple(UUID(v) for v in raw if type(v) is str)
            if len(parsed) == len(raw) == len(set(parsed)) and all(
                v.int and str(v) == original
                for v, original in zip(parsed, raw, strict=True)
            ):
                return parsed
        except ValueError:
            pass
        raise ProviderMfaError("Invalid inventory")

    async def _reconcile(self, work) -> str:
        state, user_id, pinned, _ = work("BEGIN")
        if state != "EXECUTING":
            return state
        user = str(user_id)
        try:
            if pinned is None:
                initial = await self._inventory(user)
                if not initial:
                    return work("FAILED")[0]
                state, _, pinned, _ = work("PIN", list(initial))
                if state != "EXECUTING":
                    return state
            for factor in pinned:
                state, _, _, permit = work("DISPATCH", [factor])
                if state != "EXECUTING":
                    return state
                if permit:
                    await self._provider_call(
                        self._provider.remove_totp_factor, user, str(factor)
                    )
                if (
                    await self._provider_call(
                        self._provider.factor_absent, user, str(factor)
                    )
                    is not True
                ):
                    return work("FAILED")[0]
                state = work("ABSENT", [factor])[0]
                if state != "EXECUTING":
                    return state
            if await self._inventory(user):
                return work("FAILED")[0]  # Replacement: do not touch it.
            return work("VERIFIED", [])[0]
        except ProviderMfaError:
            return work("FAILED")[0]  # No provider error text or response persisted.
