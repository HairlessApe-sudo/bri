"""A11 provisioning. The normal mount has no auth, DB or provider capability.

The staged app is an explicit in-process assembly for a disposable database.
Bind only an IP loopback listener without proxy-header processing or forwarding.
HTTP never dispatches the worker. Fixture results show local transitions only;
they prove neither provider behavior nor invitation delivery.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from collections.abc import Callable
from contextlib import AbstractContextManager, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal
from uuid import UUID, uuid4

import httpx
import psycopg
from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, StringConstraints, ValidationError
from starlette.concurrency import run_in_threadpool

from bri.api.authentication import (
    AuthenticatedIdentity,
    AuthenticationRejected,
    AuthenticationUnavailable,
    SupabaseTokenVerifier,
    has_recent_mfa,
)
from bri.api.database import Database, DatabaseUnavailable
from bri.api.provider_provisioning import (
    ISSUER,
    FixtureInvitationProvider,
    ProvisioningWorker,
)

PREFIX = '/v1/users/provisioning'
ProvisioningStatus = Literal[
    'pending_setup', 'inviting', 'invitation_sent', 'invitation_retryable',
    'invitation_unresolved', 'active',
]
_NO_STORE = {'Cache-Control': 'no-store'}
_BODY_LIMIT = 4096
_INVALID = 'Invalid provisioning request'
_EMAIL = re.compile(r"[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+", re.ASCII | re.IGNORECASE)
_UNSAFE_NAME = re.compile(r'[\x00-\x1f\x7f-\x9f\ud800-\udfff]')
_APP, _WORKER, _ACTIVATOR = 'bri_app', 'bri_provision_worker', 'bri_provision_activator'
Scope = Callable[[], AbstractContextManager[psycopg.Connection]]

_REQUEST = 'SELECT id,status FROM bri.request_user_provisioning(%s,%s,%s,%s,%s,%s,%s,%s,%s)'
_STATUS = 'SELECT id,status FROM bri.status_user_provisioning(%s,%s,%s,%s,%s)'
_WORK = 'SELECT id,status,email FROM bri.work_user_provisioning(%s,%s,%s,%s,%s)'
_ACTIVATE = 'SELECT id,status FROM bri.activate_user_provisioning(%s,%s,%s,%s,%s)'


class ProvisioningRequest(BaseModel):
    model_config = ConfigDict(extra='forbid')
    request_id: UUID
    display_name: Annotated[str, StringConstraints(strict=True, strip_whitespace=True,
                                                    min_length=1, max_length=128)]
    email: Annotated[str, StringConstraints(strict=True, strip_whitespace=True,
                                             min_length=3, max_length=254)]


class ProvisioningReply(BaseModel):
    id: UUID
    status: ProvisioningStatus


class _DisabledRoute(APIRoute):
    def get_route_handler(self):
        async def disabled(request: Request):
            raise HTTPException(403, 'Provisioning stage is disabled', headers=_NO_STORE)

        return disabled


def create_user_provisioning_router() -> APIRouter:
    """Mount before the directory's /v1/users/{id} route. Always disabled."""
    router = APIRouter(prefix=PREFIX, tags=['user provisioning'], route_class=_DisabledRoute)
    router.add_api_route('', _disabled, methods=['POST'], response_model=ProvisioningReply)
    router.add_api_route('/activate', _disabled, methods=['POST'], response_model=ProvisioningReply)
    router.add_api_route('/{request_id}', _disabled, methods=['GET'], response_model=ProvisioningReply)
    return router


def _disabled():
    raise HTTPException(403, 'Provisioning stage is disabled', headers=_NO_STORE)


def _private_request(request: Request, owner: FastAPI) -> None:
    server = request.scope.get('server')
    try:
        local = (
            request.app is owner and request.client is not None and server
            and ipaddress.ip_address(request.client.host).is_loopback
            and ipaddress.ip_address(server[0]).is_loopback
            and len(request.headers.getlist('host')) == 1
            and ipaddress.ip_address(request.url.hostname or '') == ipaddress.ip_address(server[0])
        )
    except ValueError:
        local = False
    if not local or any(
        h in {'forwarded', 'via', 'x-real-ip'} or h.startswith('x-forwarded-')
        for h in request.headers
    ):
        raise HTTPException(403, 'Private loopback listener required')
    if request.url.query or any(
        h in request.headers for h in ('x-dev-identity', 'x-tenant-id', 'x-bri-tenant-context')
    ):
        raise HTTPException(400, 'Authority is server-controlled')


async def _body(request: Request, *, limit: int) -> bytes:
    lengths = request.headers.getlist('content-length')
    if lengths:
        if len(lengths) != 1 or not re.fullmatch(r'[0-9]+', lengths[0]):
            raise HTTPException(400, _INVALID)
        if len(lengths[0]) > 10 or int(lengths[0]) > limit:
            raise HTTPException(413 if limit else 400, _INVALID)
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > limit:
            raise HTTPException(413 if limit else 400, _INVALID)
        body.extend(chunk)
    return bytes(body)


def _unique_fields(items: list[tuple]) -> dict:
    fields = dict(items)
    if len(fields) != len(items):
        raise ValueError
    return fields


async def _request_input(request: Request) -> ProvisioningRequest:
    media = request.headers.getlist('content-type')
    if len(media) != 1 or media[0].split(';', 1)[0].strip().lower() != 'application/json':
        raise HTTPException(415, _INVALID)
    raw = await _body(request, limit=_BODY_LIMIT)
    try:
        body = ProvisioningRequest.model_validate(json.loads(raw.decode('utf-8'),
                                                             object_pairs_hook=_unique_fields))
        if not body.request_id.int or _UNSAFE_NAME.search(body.display_name) or not _EMAIL.fullmatch(body.email):
            raise ValueError
    except (ValidationError, ValueError, RecursionError):
        raise HTTPException(422, _INVALID) from None
    return body


def _restricted(scope: Scope, socket: Path, dbname: str, port: int, role: str) -> Scope:
    @contextmanager
    def connect():
        with scope() as db:
            info = db.info
            if (info.host, info.port, info.dbname, info.user, info.transaction_status) != (
                str(socket), port, dbname, role, psycopg.pq.TransactionStatus.IDLE,
            ):
                raise DatabaseUnavailable('Unexpected provisioning database scope')
            yield db

    return connect


def _command(scope: Scope, role: str, query: str, args: tuple, *,
             binding: tuple[str, str] | None = None, read_only: bool = False):
    with scope() as db, db.transaction():
        if read_only:
            db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
        role_ok = db.execute(
            'SELECT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname=current_user '
            'AND rolname=session_user AND rolname=%s AND NOT rolsuper AND NOT rolbypassrls '
            'AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolinherit)', (role,),
        ).fetchone()
        if not role_ok or not role_ok[0]:
            raise DatabaseUnavailable('Restricted provisioning role required')
        if binding is not None:
            db.execute("SELECT set_config('bri.tenant_id',%s,true),"
                       "set_config('bri.auth_user_id',%s,true)", binding)
        return db.execute(query, args).fetchone()


def _reply(row: tuple | None) -> ProvisioningReply:
    if row is None:
        raise HTTPException(404, 'Provisioning request not found')
    return ProvisioningReply(id=row[0], status=row[1])


def create_staged_user_provisioning_app(
    *, app_scope: Scope, worker_scope: Scope, activator_scope: Scope, private_socket: Path,
    auth_transport: httpx.MockTransport, invite_transport: httpx.MockTransport,
    dbname: str = 'postgres', port: int = 5432,
) -> FastAPI:
    """Only for a private PostgreSQL socket and trusted, synthetic mock handlers.

    Call ``app.state.provisioning_worker.dispatch(operation_id)`` in process;
    this takes the server-issued provisioning row ID, not a browser request key.
    The same worker's ``reconcile(operation_id, attempt_id)`` is read-only at
    the provider and commits only exact operation/attempt/UID evidence to SQL.
    """
    socket = Path(private_socket).resolve(strict=True)
    stat = socket.stat()
    if (not socket.is_dir() or stat.st_uid != os.getuid() or stat.st_mode & 0o077
            or len({id(app_scope), id(worker_scope), id(activator_scope)}) != 3
            or type(auth_transport) is not httpx.MockTransport):
        raise ValueError('Private disposable database and distinct fixture scopes required')
    app_db = _restricted(app_scope, socket, dbname, port, _APP)
    work_db = _restricted(worker_scope, socket, dbname, port, _WORKER)
    activate_db = _restricted(activator_scope, socket, dbname, port, _ACTIVATOR)

    class LocalIdentityDatabase(Database):
        def _connect(self):
            return app_db()

    registry = LocalIdentityDatabase('', '')
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False)
    app.state.provisioning_worker = ProvisioningWorker(
        lambda *args: _command(work_db, _WORKER, _WORK, args),
        FixtureInvitationProvider(invite_transport),
    )

    @app.middleware('http')
    async def private(request, call_next):
        cid = uuid4()
        request.state.provisioning_correlation = cid
        try:
            _private_request(request, app)
            response = await call_next(request)
        except HTTPException as exc:
            response = JSONResponse({'detail': exc.detail}, status_code=exc.status_code)
        except (PermissionError, psycopg.errors.InsufficientPrivilege):
            response = JSONResponse({'detail': 'Provisioning denied'}, status_code=403)
        except (psycopg.errors.UniqueViolation, psycopg.errors.ObjectNotInPrerequisiteState):
            response = JSONResponse({'detail': 'Provisioning conflict'}, status_code=409)
        except psycopg.errors.InvalidParameterValue:
            response = JSONResponse({'detail': _INVALID}, status_code=422)
        except Exception:  # noqa: BLE001 -- Do not reflect provider or database details.
            response = JSONResponse({'detail': 'Provisioning service unavailable'}, status_code=503)
        response.headers.update({**_NO_STORE, 'X-Request-ID': str(cid)})
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid_path(_request, _exc):
        return JSONResponse({'detail': _INVALID}, status_code=422)

    async def verified(request: Request) -> AuthenticatedIdentity:
        _private_request(request, app)
        auth = request.headers.getlist('authorization')
        if len(auth) != 1 or not re.fullmatch(r'Bearer [^\s]{1,16384}', auth[0]):
            raise HTTPException(401, 'Verified bearer identity required')
        async with httpx.AsyncClient(transport=auth_transport, trust_env=False) as client:
            verifier = SupabaseTokenVerifier(ISSUER.removesuffix('/auth/v1'), 'stage-only', client=client)
            try:
                return await verifier.verify(auth[0][7:])
            except AuthenticationRejected:
                raise HTTPException(401, 'Authentication rejected') from None
            except AuthenticationUnavailable:
                raise HTTPException(503, 'Authentication unavailable') from None

    def principal(ident: AuthenticatedIdentity):
        return registry.resolve_authenticated_principal(ident.auth_user_id, ident.issuer, ident.auth_user_id)

    def admin(ident: AuthenticatedIdentity) -> tuple[str, UUID, UUID, str]:
        person = principal(ident)
        if person and not person.platform_superadmin and len(person.tenant_ids) == 1:
            tenant = next(iter(person.tenant_ids))
            if (person.role_bindings == ((tenant, 'admin'),)
                    and registry.auth_session_is_active(ident.auth_user_id, ident.session_id)):
                # SQL authorizes the actual root grant and rechecks live authority
                # in the command transaction. The registry does not grant access.
                return tenant, UUID(person.subject_id), UUID(ident.session_id), ident.issuer
        raise HTTPException(403, 'Current client Admin session required')

    router = APIRouter(prefix=PREFIX)

    @router.post('', response_model=ProvisioningReply)
    async def provision(request: Request):
        body = await _request_input(request)
        ident = await verified(request)
        if not has_recent_mfa(ident) or ident.totp_authenticated_at is None:
            raise HTTPException(403, 'Recent verified TOTP required')
        authority = await run_in_threadpool(admin, ident)
        row = await run_in_threadpool(
            _command, app_db, _APP, _REQUEST,
            (*authority, datetime.fromtimestamp(ident.totp_authenticated_at, UTC), body.request_id,
             body.display_name, body.email, request.state.provisioning_correlation),
            binding=(authority[0], ident.auth_user_id),
        )
        return _reply(row)

    @router.post('/activate', response_model=ProvisioningReply)
    async def activate(request: Request):
        await _body(request, limit=0)
        ident = await verified(request)
        primary, totp = ident.primary_authenticated_at, ident.totp_authenticated_at
        if primary is None or totp is None or not 0 < primary <= totp:
            raise HTTPException(403, 'Verified invitee setup required')
        person = await run_in_threadpool(principal, ident)
        if person and (person.platform_superadmin or any(role == 'admin' for _, role in person.role_bindings)):
            raise HTTPException(403, 'Verified invitee setup required')
        # No membership or BRI session is required/created. SQL authorizes only
        # a stored, operation-bound subject and post-invitation setup evidence.
        row = await run_in_threadpool(
            _command, activate_db, _ACTIVATOR, _ACTIVATE,
            (ident.issuer, UUID(ident.auth_user_id), datetime.fromtimestamp(primary, UTC),
             datetime.fromtimestamp(totp, UTC), request.state.provisioning_correlation),
            binding=('', ident.auth_user_id),
        )
        return _reply(row)

    @router.get('/{request_id}', response_model=ProvisioningReply)
    async def status(request: Request, request_id: UUID):
        await _body(request, limit=0)
        ident = await verified(request)
        authority = await run_in_threadpool(admin, ident)
        row = await run_in_threadpool(
            _command, app_db, _APP, _STATUS, (*authority, request_id),
            binding=(authority[0], ident.auth_user_id), read_only=True,
        )
        return _reply(row)

    app.include_router(router)
    return app
