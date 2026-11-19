"""A10 approval routes. The ordinary mount has no writable backend, by design.

The standalone stage constructor is a programmatic integration harness, not an
ASGI factory accepting environment configuration. Bind only a loopback listener,
without proxy header handling. Its auth and provider transports are in-process;
its two DB scopes must target the same explicit private PostgreSQL socket.
"""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from uuid import UUID, uuid4

import httpx
import psycopg
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict
from starlette.routing import Match

from bri.access.approvals import (
    ApprovalContext,
    ApprovalRepository,
    ApprovalWorker,
    ReconciliationMfaAdmin,
    Scope,
)
from bri.access.policy import Principal
from bri.api.authentication import (
    AuthenticationRejected,
    AuthenticationUnavailable,
    MfaRejected,
    SupabaseTokenVerifier,
    has_recent_mfa,
)
from bri.api.boundary_audit import audit_denial, mark
from bri.api.database import EXPECTED_PROJECT_REF, Database, DatabaseUnavailable

PREFIX = "/v1/privileged-approvals"
State = Literal[
    "PENDING", "APPROVED", "REJECTED", "EXPIRED", "EXECUTING", "COMPLETED", "FAILED"
]


class CreateApproval(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: UUID
    reason: Literal["LOST_FACTOR", "COMPROMISED_FACTOR", "REPLACED_DEVICE"]
    request_id: UUID  # idempotency key, NOT the middleware correlation


class DecideApproval(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["APPROVE", "REJECT"]


class ApprovalReply(BaseModel):
    approval_id: UUID
    state: State
    correlation_id: UUID


# Route names, not raw paths, are the action vocabulary. No incoming UUIDs.
_ACTION = {"create": "approval_request", "decide": "approval_decision", "status": "approval_status"}


class _SafeRoute(APIRoute):
    def get_route_handler(self):
        handle = super().get_route_handler()

        async def safe(request):
            mark(request, _ACTION[self.name], "input")
            try:
                return await handle(request)
            except RequestValidationError:
                request.state.audit_phase = "input"
                raise HTTPException(422, "Invalid approval request") from None
            except (PermissionError, psycopg.errors.InsufficientPrivilege):
                raise HTTPException(403, "Approval denied") from None
            except (
                psycopg.errors.UniqueViolation,
                psycopg.errors.ObjectNotInPrerequisiteState,
            ):
                raise HTTPException(409, "Approval conflict") from None
            except (DatabaseUnavailable, psycopg.Error):
                raise HTTPException(503, "Approval service unavailable") from None

        return safe


@dataclass(frozen=True, slots=True)
class _Stage:
    owner: FastAPI
    repo: ApprovalRepository


def _guard(request: Request, stage: _Stage | None):
    if stage is None or request.app is not stage.owner:
        raise HTTPException(403, "Approval stage is disabled")
    # Do not accept forwarded identity, routing, host or tenant selectors. Peer,
    # actual listener and Host must all be local. Never infer locality from Host.
    server = request.scope.get("server")
    try:
        local = (
            request.client is not None
            and ipaddress.ip_address(request.client.host).is_loopback
            and server
            and ipaddress.ip_address(server[0]).is_loopback
            and request.url.hostname == server[0]
        )
    except ValueError:
        local = False
    if not local or any(
        h in ("forwarded", "via", "x-real-ip") or h.startswith("x-forwarded-")
        for h in request.headers
    ):
        raise HTTPException(403, "Private loopback listener required")
    if request.query_params or any(
        h in request.headers
        for h in ("x-dev-identity", "x-tenant-id", "x-bri-tenant-context")
    ):
        raise HTTPException(400, "Authority is server-controlled")


def create_approval_router(*, principal_dependency: Callable) -> APIRouter:
    """Normal mount: all paths fail closed, including status (it can persist expiry)."""
    return _router(principal_dependency, None)


def _router(principal_dependency, stage):
    def gate(request: Request):
        request.state.audit_phase = "authority"
        _guard(request, stage)

    router = APIRouter(
        prefix=PREFIX,
        tags=["approvals"],
        route_class=_SafeRoute,
        dependencies=[Depends(gate)],
    )

    principal_dep = Depends(principal_dependency)

    def context(request: Request, principal: Principal = principal_dep):
        ident = getattr(request.state, "authenticated_identity", None)
        if not has_recent_mfa(ident):
            request.state.audit_phase = "mfa"
            raise HTTPException(403, "Eligible client administrator and verified step-up required")
        request.state.audit_phase = "authority"
        if (
            principal.platform_superadmin
            or len(principal.tenant_ids) != 1
        ):
            raise HTTPException(
                403, "Eligible client administrator and verified step-up required"
            )
        tenant = next(iter(principal.tenant_ids))
        if principal.role_bindings != ((tenant, "admin"),):
            raise HTTPException(403, "Eligible client administrator required")
        return ApprovalContext(tenant, ident, UUID(request.state.request_id)), principal

    def require(bound, *permissions):
        ctx, principal = bound
        if not any(
            g.tenant_id == ctx.tenant_id and g.action in permissions and g.scope_id
            for g in principal.grants
        ):
            raise HTTPException(403, "Approval permission required")
        return ctx  # SQL additionally checks the pinned root scope, person and vote.

    context_dep = Depends(context)

    @router.post("", response_model=ApprovalReply)
    def create(body: CreateApproval, bound=context_dep):
        ctx = require(bound, "user:mfa_reset:request")
        state = stage.repo.request(
            ctx, target=body.target, reason=body.reason, request_id=body.request_id
        )
        return ApprovalReply(
            approval_id=body.request_id, state=state, correlation_id=ctx.correlation_id
        )

    @router.post("/{approval_id}/decision", response_model=ApprovalReply)
    def decide(approval_id: UUID, body: DecideApproval, bound=context_dep):
        ctx = require(bound, "user:mfa_reset:decide")
        state = stage.repo.decide(ctx, approval_id, body.decision)
        return ApprovalReply(
            approval_id=approval_id, state=state, correlation_id=ctx.correlation_id
        )

    @router.get("/{approval_id}", response_model=ApprovalReply)
    def status(approval_id: UUID, bound=context_dep):
        ctx = require(bound, "user:mfa_reset:request", "user:mfa_reset:decide")
        state = stage.repo.status(ctx, approval_id)
        return ApprovalReply(
            approval_id=approval_id, state=state, correlation_id=ctx.correlation_id
        )

    return router


def create_staged_approval_app(
    *,
    app_scope: Scope,
    worker_scope: Scope,
    private_socket: Path,
    auth_transport: httpx.MockTransport,
    factor_transport: httpx.MockTransport,
    dbname: str = "postgres",
    port: int = 5432,
) -> FastAPI:
    """Build an isolated loopback harness. No supplied URLs, tokens, env flags or real transports.

    ``app.state.approval_worker.execute(verified_reviewer_context, approval_id)`` is server-only.
    Recording/replaying an APPROVE over HTTP never dispatches provider work.
    """
    socket = Path(private_socket).resolve(strict=True)
    st = socket.stat()
    if (
        not socket.is_dir()
        or st.st_mode & 0o077
        or st.st_uid != os.getuid()
        or app_scope is worker_scope
        or not isinstance(auth_transport, httpx.MockTransport)
        or not isinstance(factor_transport, httpx.MockTransport)
    ):
        raise ValueError(
            "Private disposable database and distinct isolated dependencies required"
        )

    def restricted(scope, role):
        @contextmanager
        def connect():
            with scope() as db:
                if (
                    db.info.host != str(socket)
                    or db.info.port != port
                    or db.info.dbname != dbname
                    or db.info.user != role
                    or db.info.transaction_status != psycopg.pq.TransactionStatus.IDLE
                ):
                    raise DatabaseUnavailable("Unexpected staged database scope")
                yield db

        return connect

    app_db = restricted(app_scope, "bri_app")

    class LocalIdentityDatabase(Database):
        def _connect(self):
            return app_db()

    registry = LocalIdentityDatabase("", "")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    stage = _Stage(app, ApprovalRepository(app_db))
    app.state.approval_worker = ApprovalWorker(
        restricted(worker_scope, "bri_approval_worker"),
        ReconciliationMfaAdmin(test_transport=factor_transport),
    )

    @app.middleware("http")
    async def private_request(request, call_next):
        cid = str(uuid4())
        request.state.request_id = cid
        try:
            _guard(request, stage)
            response = await call_next(request)
        except HTTPException as err:
            # The outer transport guard runs before routing or body parsing.
            for route in router.routes:
                if isinstance(route, APIRoute) and route.matches(request.scope)[0] is Match.FULL:
                    mark(request, _ACTION[route.name], "authority")
                    break
            response = JSONResponse({"detail": err.detail}, status_code=err.status_code)
        except Exception:  # Never expose transport or repository details.
            if not getattr(request.state, "audit_action", None):
                raise
            response = JSONResponse({"detail": "Approval service unavailable"}, status_code=503)
        response = await audit_denial(request, response, registry)
        response.headers["X-Request-ID"] = cid
        response.headers["Cache-Control"] = "no-store"
        return response

    async def authenticated(request: Request):
        request.state.audit_phase = "authentication"
        auth = request.headers.getlist("authorization")
        if (
            len(auth) != 1
            or not auth[0].startswith("Bearer ")
            or " " in auth[0][7:]
            or not auth[0][7:]
        ):
            raise HTTPException(401, "Verified bearer identity required")
        async with httpx.AsyncClient(
            transport=auth_transport, trust_env=False
        ) as client:
            verifier = SupabaseTokenVerifier(
                f"https://{EXPECTED_PROJECT_REF}.supabase.co",
                "stage-only",
                client=client,
            )
            try:
                identity = await verifier.verify(auth[0][7:])
            except MfaRejected:
                request.state.audit_phase = "mfa"
                raise HTTPException(401, "Authentication rejected") from None
            except AuthenticationRejected:
                raise HTTPException(401, "Authentication rejected") from None
            except AuthenticationUnavailable:
                raise HTTPException(503, "Authentication unavailable") from None
        request.state.authenticated_identity = identity
        request.state.audit_phase = "membership"
        principal = registry.resolve_authenticated_principal(
            identity.auth_user_id, identity.issuer, identity.auth_user_id
        )
        if not principal:
            raise HTTPException(403, "Active BRI session required")
        request.state.audit_phase = "session"
        if not registry.auth_session_is_active(
            identity.auth_user_id, identity.session_id
        ):
            raise HTTPException(403, "Active BRI session required")
        return principal

    router = _router(authenticated, stage)
    app.include_router(router)
    return app
