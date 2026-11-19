"""A11.3 user lifecycle; the normal mount has no execution capability.

The isolated app is for a disposable database. If served over HTTP, bind an
IP loopback listener only, without proxy-header processing or forwarding.
"""
from __future__ import annotations

import json
import os
import re
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal
from uuid import UUID, uuid4

import httpx
import psycopg
from fastapi import APIRouter, Body, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, TypeAdapter
from starlette.concurrency import run_in_threadpool

from bri.api.authentication import (
    AuthenticatedIdentity,
    AuthenticationRejected,
    AuthenticationUnavailable,
    SupabaseTokenVerifier,
    has_recent_mfa,
)
from bri.api.database import EXPECTED_PROJECT_REF, Database, DatabaseUnavailable
from bri.api.user_provisioning import (
    _NO_STORE,
    _UNSAFE_NAME,
    Scope,
    _body,
    _DisabledRoute,
    _private_request,
    _restricted,
    _unique_fields,
)

_PATH = '/v1/users/{id}/lifecycle'
_INVALID = 'Invalid user lifecycle request'
_APP = 'bri_app'
_AUTH_ORIGIN = f'https://{EXPECTED_PROJECT_REF}.supabase.co'
_FIELDS = ('id', 'display_name', 'status', 'role', 'version', 'can_edit', 'can_suspend', 'can_reactivate')
_SELECT = 'SELECT ' + ','.join(_FIELDS) + ' FROM bri.'
_READ = _SELECT + 'read_user_lifecycle(%s::text,%s::uuid,%s::uuid,%s::text,%s::uuid)'
_CHANGE = _SELECT + ('change_user_lifecycle(%s::text,%s::uuid,%s::uuid,%s::text,%s::uuid,'
                     '%s::text,%s::bigint,%s::text,%s::text,%s::timestamptz,%s::uuid)')


class _Change(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    expected_version: Annotated[int, Field(ge=0, le=2**63 - 1)]


class _Edit(_Change):
    action: Literal['edit']
    display_name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=128)]


class _Suspend(_Change):
    action: Literal['suspend']
    reason: Literal['policy_violation', 'access_review', 'temporary_leave']


class _Reactivate(_Change):
    action: Literal['reactivate']
    reason: Literal['review_complete', 'access_restored']


_PATCH_INPUT = TypeAdapter(Annotated[_Edit | _Suspend | _Reactivate, Field(discriminator='action')])


class LifecycleReply(BaseModel):
    model_config = ConfigDict(strict=True)
    id: UUID
    display_name: str | None
    status: str
    role: str
    version: int
    can_edit: bool
    can_suspend: bool
    can_reactivate: bool


def _disabled(id: UUID):
    raise HTTPException(403, 'User lifecycle stage is disabled', headers=_NO_STORE)


def _disabled_patch(id: UUID, body: Annotated[_Edit | _Suspend | _Reactivate, Body(discriminator='action')]):
    return _disabled(id)


def create_user_lifecycle_router() -> APIRouter:
    """Normal mount: deny both methods without parsing, auth, or database I/O."""
    router = APIRouter(tags=['user lifecycle'], route_class=_DisabledRoute)
    router.add_api_route(_PATH, _disabled, methods=['GET'], response_model=LifecycleReply)
    router.add_api_route(_PATH, _disabled_patch, methods=['PATCH'], response_model=LifecycleReply)
    return router


async def _read_body(request: Request, limit: int) -> bytes:
    try:
        return await _body(request, limit=limit)
    except HTTPException as exc:
        raise HTTPException(exc.status_code, _INVALID) from None


async def _parse_change(request: Request) -> _Edit | _Suspend | _Reactivate:
    media = request.headers.getlist('content-type')
    if len(media) != 1 or media[0].split(';', 1)[0].strip().lower() != 'application/json':
        raise HTTPException(415, _INVALID)
    raw = await _read_body(request, 4096)
    try:
        body = _PATCH_INPUT.validate_python(json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_fields))
        if isinstance(body, _Edit) and _UNSAFE_NAME.search(body.display_name):
            raise ValueError
    except (ValueError, RecursionError):
        raise HTTPException(422, _INVALID) from None
    return body


def _require_app_role(db: psycopg.Connection) -> None:
    row = db.execute(
        'SELECT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname=current_user '
        'AND rolname=session_user AND rolname=%s AND NOT rolsuper AND NOT rolbypassrls '
        'AND NOT rolcreaterole AND NOT rolcreatedb AND NOT rolinherit AND NOT rolreplication)', (_APP,),
    ).fetchone()
    if not row or row[0] is not True:
        raise DatabaseUnavailable('Restricted lifecycle role required')


def create_staged_user_lifecycle_app(
    *, app_scope: Scope, private_socket: Path, auth_transport: httpx.MockTransport,
    dbname: str = 'postgres', port: int = 5432,
) -> FastAPI:
    """Assemble the stage explicitly; only the pinned Auth verifier uses the mock."""
    socket = Path(private_socket).resolve(strict=True)
    stat = socket.stat()
    if (not socket.is_dir() or stat.st_uid != os.getuid() or stat.st_mode & 0o077
            or type(auth_transport) is not httpx.MockTransport):
        raise ValueError('Private disposable database and fixture auth transport required')
    restricted = _restricted(app_scope, socket, dbname, port, _APP)

    @contextmanager
    def app_db():
        with restricted() as db:
            if db.info.hostaddr or db.autocommit:
                raise DatabaseUnavailable('Unexpected lifecycle database scope')
            yield db

    class LocalIdentityDatabase(Database):
        @contextmanager
        def _connect(self):
            with app_db() as db:
                # Registry methods start their own read-only transaction and bind
                # the verified UID locally; check login privileges before use.
                with db.transaction():
                    _require_app_role(db)
                yield db

    registry = LocalIdentityDatabase('', '')
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False)

    @app.middleware('http')
    async def private(request, call_next):
        cid = uuid4()
        request.state.lifecycle_correlation = cid
        try:
            _private_request(request, app)
            response = await call_next(request)
        except HTTPException as exc:
            response = JSONResponse({'detail': exc.detail}, status_code=exc.status_code)
        except psycopg.errors.InsufficientPrivilege:
            response = JSONResponse({'detail': 'User lifecycle denied'}, status_code=403)
        except (psycopg.errors.SerializationFailure, psycopg.errors.ObjectNotInPrerequisiteState):
            response = JSONResponse({'detail': 'User lifecycle conflict'}, status_code=409)
        except psycopg.errors.InvalidParameterValue:
            response = JSONResponse({'detail': _INVALID}, status_code=422)
        except Exception:  # noqa: BLE001 -- Never reflect provider or DB diagnostics.
            response = JSONResponse({'detail': 'User lifecycle service unavailable'}, status_code=503)
        response.headers.update({**_NO_STORE, 'X-Request-ID': str(cid)})
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid_path(_request, _exc):
        return JSONResponse({'detail': _INVALID}, status_code=422)

    async def verified(request: Request) -> AuthenticatedIdentity:
        auth = request.headers.getlist('authorization')
        if len(auth) != 1 or not re.fullmatch(r'Bearer [^\s]{1,16384}', auth[0]):
            raise HTTPException(401, 'Verified bearer identity required')
        async with httpx.AsyncClient(transport=auth_transport, trust_env=False, follow_redirects=False) as client:
            try:
                return await SupabaseTokenVerifier(_AUTH_ORIGIN, 'stage-only', client=client).verify(auth[0][7:])
            except AuthenticationRejected:
                raise HTTPException(401, 'Authentication rejected') from None
            except AuthenticationUnavailable:
                raise HTTPException(503, 'Authentication unavailable') from None

    def admin(ident: AuthenticatedIdentity) -> tuple[str, UUID, UUID, str]:
        person = registry.resolve_authenticated_principal(ident.auth_user_id, ident.issuer, ident.auth_user_id)
        if person and not person.platform_superadmin and len(person.tenant_ids) == 1:
            tenant = next(iter(person.tenant_ids))
            if (person.role_bindings == ((tenant, 'admin'),)
                    and registry.auth_session_is_active(ident.auth_user_id, ident.session_id)):
                return tenant, UUID(person.subject_id), UUID(ident.session_id), ident.issuer
        raise HTTPException(403, 'Current client Admin session required')

    def command(ident: AuthenticatedIdentity, target: UUID, change: _Edit | _Suspend | _Reactivate | None,
                correlation: UUID) -> LifecycleReply:
        authority = admin(ident)
        args: tuple = (*authority, target)
        query = _READ
        if change is not None:
            name, reason = None, None
            stamp = ident.totp_authenticated_at
            if stamp is None:
                raise HTTPException(403, 'Verified TOTP event required')
            # All writes are fenced against obsolete authentication in SQL;
            # only suspension/reactivation require the 15-minute step-up.
            totp_at = datetime.fromtimestamp(stamp, UTC)
            if isinstance(change, _Edit):
                name = change.display_name
            else:
                if not has_recent_mfa(ident):
                    raise HTTPException(403, 'Recent verified TOTP required')
                reason = change.reason
            query = _CHANGE
            args = (*args, change.action, change.expected_version, name, reason, totp_at, correlation)
        # SQL rechecks authority and performs each write atomically. Return the
        # projected result only once the restricted command has committed.
        with app_db() as db, db.transaction():
            if change is None:
                db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            _require_app_role(db)
            db.execute("SELECT set_config('bri.tenant_id',%s,true),set_config('bri.auth_user_id',%s,true)",
                       (authority[0], ident.auth_user_id))
            row = db.execute(query, args).fetchone()
            if row is None:
                raise HTTPException(404, 'User not found')
            return LifecycleReply.model_validate(dict(zip(_FIELDS, row)))

    @app.get(_PATH, response_model=LifecycleReply)
    async def read(request: Request, id: UUID):
        await _read_body(request, 0)
        ident = await verified(request)
        return await run_in_threadpool(command, ident, id, None, request.state.lifecycle_correlation)

    @app.patch(_PATH, response_model=LifecycleReply)
    async def change(request: Request, id: UUID):
        body = await _parse_change(request)
        ident = await verified(request)
        return await run_in_threadpool(command, ident, id, body, request.state.lifecycle_correlation)

    return app
