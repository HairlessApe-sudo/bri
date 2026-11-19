"""A11.5 deactivation API. The normal mount has no execution capability.

The fixture app is for disposable PostgreSQL only. If served over HTTP,
bind an IP loopback listener with proxy-header processing and forwarding off.
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
from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator
from starlette.concurrency import run_in_threadpool

from bri.api.authentication import (
    AuthenticatedIdentity,
    AuthenticationRejected,
    AuthenticationUnavailable,
    SupabaseTokenVerifier,
    has_recent_mfa,
)
from bri.api.database import Database, DatabaseUnavailable
from bri.api.user_lifecycle import _APP, _AUTH_ORIGIN, _require_app_role
from bri.api.user_provisioning import _NO_STORE, Scope, _body, _private_request, _restricted, _unique_fields

_PATH = '/v1/users/{id}/deactivation'
_DISABLED = 'User deactivation stage is disabled'
_INVALID = 'Invalid user deactivation request'
_MAX_VERSION = (1 << 63) - 1
_VERSION_PATTERN = r'^(0|[1-9][0-9]{0,18})$'
_Version = Annotated[str, StringConstraints(min_length=1, max_length=19, pattern=_VERSION_PATTERN)]
_READ = ('SELECT version, status FROM bri.read_user_deactivation('
         '%s::text,%s::uuid,%s::uuid,%s::text,%s::uuid)')
_CHANGE = ('SELECT version, status FROM bri.deactivate_user_account('
           '%s::text,%s::uuid,%s::uuid,%s::text,%s::uuid,%s::bigint,%s::text,%s::timestamptz,%s::uuid)')


class DeactivationRequest(BaseModel):
    model_config = ConfigDict(strict=True, extra='forbid')
    expected_version: _Version
    reason: Literal['account_closed', 'access_review', 'policy_violation']

    @field_validator('expected_version')
    @classmethod
    def canonical_bigint(cls, value: str) -> str:
        if not re.fullmatch(_VERSION_PATTERN, value) or int(value) > _MAX_VERSION:
            raise ValueError('Invalid version')
        return value


class DeactivationReply(BaseModel):
    model_config = ConfigDict(strict=True)
    version: _Version
    status: Literal['active', 'suspended', 'deactivated']


class _DisabledDeactivationRoute(APIRoute):
    def get_route_handler(self):
        async def disabled(request: Request):
            raise HTTPException(403, _DISABLED, headers=_NO_STORE)

        return disabled


def _disabled_read(id: UUID):
    raise HTTPException(403, _DISABLED, headers=_NO_STORE)


def _disabled_patch(id: UUID, body: DeactivationRequest):
    raise HTTPException(403, _DISABLED, headers=_NO_STORE)


def create_user_deactivation_router() -> APIRouter:
    """Normal mount: deny both methods before reading input or authenticating."""
    router = APIRouter(tags=['user deactivation'], route_class=_DisabledDeactivationRoute)
    router.add_api_route(_PATH, _disabled_read, methods=['GET'], response_model=DeactivationReply)
    router.add_api_route(_PATH, _disabled_patch, methods=['PATCH'], response_model=DeactivationReply)
    return router


async def _read_body(request: Request, limit: int) -> bytes:
    try:
        return await _body(request, limit=limit)
    except HTTPException as exc:
        raise HTTPException(exc.status_code, _INVALID) from None


async def _parse_change(request: Request) -> DeactivationRequest:
    media = request.headers.getlist('content-type')
    if len(media) != 1 or media[0].split(';', 1)[0].strip().lower() != 'application/json':
        raise HTTPException(415, _INVALID)
    raw = await _read_body(request, 4096)
    try:
        return DeactivationRequest.model_validate(json.loads(raw.decode('utf-8'), object_pairs_hook=_unique_fields))
    except (ValueError, RecursionError):
        raise HTTPException(422, _INVALID) from None


def create_staged_user_deactivation_app(
    *, app_scope: Scope, private_socket: Path, auth_transport: httpx.MockTransport,
    dbname: str = 'postgres', port: int = 5432,
) -> FastAPI:
    """Assemble explicitly with a private Unix socket and fixture-only Supabase Auth."""
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
                raise DatabaseUnavailable('Unexpected deactivation database scope')
            yield db

    class LocalIdentityDatabase(Database):
        @contextmanager
        def _connect(self):
            with app_db() as db:
                # The registry starts a separate read-only transaction.
                with db.transaction():
                    _require_app_role(db)
                yield db

    registry = LocalIdentityDatabase('', '')
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False)

    @app.middleware('http')
    async def private(request: Request, call_next):
        cid = uuid4()
        request.state.deactivation_correlation = cid
        try:
            _private_request(request, app)
            response = await call_next(request)
        except HTTPException as exc:
            response = JSONResponse({'detail': exc.detail}, status_code=exc.status_code)
        except psycopg.errors.InsufficientPrivilege:
            response = JSONResponse({'detail': 'User deactivation denied'}, status_code=403)
        except psycopg.errors.SerializationFailure:
            response = JSONResponse({'detail': 'User deactivation version is stale'}, status_code=409)
        except psycopg.errors.ObjectNotInPrerequisiteState:
            response = JSONResponse({'detail': 'User deactivation state conflict'}, status_code=409)
        except psycopg.errors.InvalidParameterValue:
            response = JSONResponse({'detail': _INVALID}, status_code=422)
        except Exception:  # Never reflect provider or database diagnostics.
            response = JSONResponse({'detail': 'User deactivation service unavailable'}, status_code=503)
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

    def command(ident: AuthenticatedIdentity, target: UUID, change: DeactivationRequest | None,
                correlation: UUID) -> DeactivationReply:
        authority = admin(ident)
        args: tuple = (*authority, target)
        query = _READ
        if change is not None:
            stamp = ident.totp_authenticated_at
            if stamp is None or not has_recent_mfa(ident):
                raise HTTPException(403, 'Recent verified TOTP required')
            query = _CHANGE
            args = (*args, int(change.expected_version), change.reason, datetime.fromtimestamp(stamp, UTC), correlation)
        # SQL rechecks authority and owns target eligibility, CAS and auditing.
        # Validate the projected result inside the transaction; respond after commit.
        with app_db() as db, db.transaction():
            if change is None:
                db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY')
            else:
                db.execute('SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ WRITE')
            _require_app_role(db)
            db.execute("SELECT set_config('bri.tenant_id',%s,true),set_config('bri.auth_user_id',%s,true)",
                       (authority[0], ident.auth_user_id))
            row = db.execute(query, args).fetchone()
            if row is None:
                raise HTTPException(404, 'User not found')
            version, status = row
            if type(version) is not int or not 0 <= version <= _MAX_VERSION:
                raise DatabaseUnavailable('Invalid deactivation result')
            reply = DeactivationReply(version=str(version), status=status)
        return reply

    @app.get(_PATH, response_model=DeactivationReply)
    async def read(request: Request, id: UUID):
        await _read_body(request, 0)
        ident = await verified(request)
        return await run_in_threadpool(command, ident, id, None, request.state.deactivation_correlation)

    @app.patch(_PATH, response_model=DeactivationReply)
    async def change(request: Request, id: UUID):
        body = await _parse_change(request)
        ident = await verified(request)
        return await run_in_threadpool(command, ident, id, body, request.state.deactivation_correlation)

    return app
