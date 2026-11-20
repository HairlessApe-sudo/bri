"""Read-only directory of a verified client Admin's ordinary accounts."""
from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Any, Literal, get_args
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from psycopg.errors import InsufficientPrivilege
from pydantic import BaseModel, StrictBool

from bri.access.policy import Principal
from bri.api.authentication import AuthenticatedIdentity
from bri.api.database import DatabaseUnavailable, TenantSession

_DEFAULT_LIMIT = 25
_MAX_LIMIT = 100
_MAX_OFFSET = 10_000
_MAX_QUERY = 128
_PERMISSION = 'user:directory:read'
_NO_STORE = 'no-store'
DirectoryStatus = Literal['pending', 'active', 'suspended', 'deactivated']
DirectoryRole = Literal['user', 'superuser']
DirectoryMfaStatus = Literal['verified', 'unknown']
_LIST_FILTERS = {
    'status': get_args(DirectoryStatus),
    'role': get_args(DirectoryRole),
    'mfa_status': get_args(DirectoryMfaStatus),
}
_USER_COLUMNS = ('id', 'display_name', 'status', 'role', 'mfa_status')
_LIST_QUERY_SCHEMA = {'parameters': [
    {'in': 'query', 'name': 'q', 'description': 'Literal display-name substring or exact account UUID',
     'schema': {'type': 'string', 'maxLength': _MAX_QUERY}},
    {'in': 'query', 'name': 'limit',
     'schema': {'type': 'integer', 'minimum': 1, 'maximum': _MAX_LIMIT, 'default': _DEFAULT_LIMIT}},
    {'in': 'query', 'name': 'offset',
     'schema': {'type': 'integer', 'minimum': 0, 'maximum': _MAX_OFFSET, 'default': 0}},
    *({'in': 'query', 'name': name, 'schema': {'type': 'string', 'enum': list(choices)}}
      for name, choices in _LIST_FILTERS.items()),
]}


class DirectoryUser(BaseModel):
    id: UUID
    display_name: str | None
    status: DirectoryStatus
    role: DirectoryRole
    mfa_status: DirectoryMfaStatus


class DirectoryListUser(DirectoryUser):
    can_view_grants: StrictBool


class DirectoryPage(BaseModel):
    items: list[DirectoryListUser]
    has_more: bool


def _invalid_query() -> HTTPException:
    return HTTPException(400, 'Invalid directory query')


def _not_found() -> HTTPException:
    return HTTPException(404, 'Not Found', headers={'Cache-Control': _NO_STORE})


def _query_parameters(request: Request, allowed: frozenset[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for key, value in request.query_params.multi_items():
        if key not in allowed or key in values:
            raise _invalid_query()
        values[key] = value
    return values


def _bounded_number(value: str, minimum: int, maximum: int) -> int:
    if len(value) > len(str(maximum)) or not value.isascii() or not value.isdecimal():
        raise _invalid_query()
    number = int(value)
    if not minimum <= number <= maximum:
        raise _invalid_query()
    return number


def _uuid(value: str) -> UUID | None:
    if len(value) != 36:
        return None
    try:
        parsed = UUID(value)
    except ValueError:
        return None
    return parsed if str(parsed) == value.lower() else None


def create_user_directory_router(
    *,
    principal_dependency: Callable[..., Any],
    protected_scope: Callable[..., AbstractContextManager[TenantSession]],
) -> APIRouter:
    router = APIRouter(prefix='/v1/users', tags=['user directory'])
    principal_dep = Depends(principal_dependency)

    def read(
        request: Request, principal: Principal, *, target: UUID | None = None,
        query: str | None = None, limit: int = _DEFAULT_LIMIT, offset: int = 0,
        status: str | None = None, role: str | None = None, mfa_status: str | None = None,
    ) -> list[tuple[Any, ...]]:
        identity = getattr(request.state, 'authenticated_identity', None)
        if not isinstance(identity, AuthenticatedIdentity) or principal.platform_superadmin or len(principal.tenant_ids) != 1:
            raise HTTPException(403, 'Client access is not authorized')
        tenant = next(iter(principal.tenant_ids))
        # This early ceiling is not authority: the DB verifies the current role,
        # actual root node, permission, tenant and session in its read snapshot.
        if (tenant, 'admin') not in principal.role_bindings or not any(
            grant.tenant_id == tenant and grant.action == _PERMISSION for grant in principal.grants
        ):
            raise HTTPException(403, 'Client access is not authorized')
        with protected_scope(
            tenant, auth_user_id=identity.auth_user_id, session_id=identity.session_id,
            principal_id=principal.subject_id, issuer=identity.issuer,
        ) as session:
            connection: Any = session.connection
            if connection is None:
                raise DatabaseUnavailable('directory connection unavailable')
            try:
                actor = (tenant, principal.subject_id, identity.session_id, identity.issuer)
                if target is None:
                    return connection.execute(
                        'SELECT id, display_name, status, role, mfa_status, can_view_grants '
                        'FROM bri.read_user_directory_overview(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) ORDER BY id',
                        (*actor, query, _uuid(query) if query is not None else None,
                         limit, offset, status, role, mfa_status),
                    ).fetchall()
                return connection.execute(
                    'SELECT id, display_name, status, role, mfa_status '
                    'FROM bri.read_user_directory(%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                    (*actor, target, None, None, limit, offset),
                ).fetchall()
            except InsufficientPrivilege as exc:
                # Translate before the transaction wrapper sees a generic psycopg error.
                raise HTTPException(403, 'Client access is not authorized') from exc

    @router.get('', response_model=DirectoryPage, summary='Search ordinary users in the verified client',
                openapi_extra=_LIST_QUERY_SCHEMA)
    def list_users(
        request: Request, response: Response, principal: Principal = principal_dep,
    ) -> DirectoryPage:
        values = _query_parameters(request, frozenset({'q', 'limit', 'offset', *_LIST_FILTERS}))
        query = values.get('q') or None
        if query is not None and (len(query) > _MAX_QUERY or '\x00' in query):
            raise _invalid_query()
        if any(name in values and values[name] not in choices for name, choices in _LIST_FILTERS.items()):
            raise _invalid_query()
        limit = _bounded_number(values.get('limit', str(_DEFAULT_LIMIT)), 1, _MAX_LIMIT)
        offset = _bounded_number(values.get('offset', '0'), 0, _MAX_OFFSET)
        rows = read(request, principal, query=query, limit=limit, offset=offset,
                    status=values.get('status'), role=values.get('role'), mfa_status=values.get('mfa_status'))
        users = [DirectoryListUser(**dict(zip((*_USER_COLUMNS, 'can_view_grants'), row, strict=True)))
                 for row in rows[:limit]]
        response.headers['Cache-Control'] = _NO_STORE
        return DirectoryPage(items=users, has_more=len(rows) > limit)

    @router.get('/{id}', response_model=DirectoryUser, summary='Inspect one ordinary user in the verified client')
    def get_user(
        id: str, request: Request, response: Response, principal: Principal = principal_dep,
    ) -> DirectoryUser:
        _query_parameters(request, frozenset())
        target = _uuid(id)
        if target is None:
            raise _not_found()
        rows = read(request, principal, target=target, limit=1)
        if not rows:
            raise _not_found()
        response.headers['Cache-Control'] = _NO_STORE
        return DirectoryUser(**dict(zip(_USER_COLUMNS, rows[0], strict=True)))

    return router
