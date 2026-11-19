"""Read-only projection of current grants on a directory-visible account."""
from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from psycopg import Error as PostgresError
from psycopg.errors import InsufficientPrivilege
from pydantic import BaseModel, ConfigDict, ValidationError

from bri.access.policy import Principal
from bri.access.roles import role_allows_permission
from bri.api.authentication import AuthenticatedIdentity
from bri.api.database import DatabaseUnavailable, TenantSession

_PERMISSIONS = frozenset({'user:directory:read', 'account:grants:read'})
_EMPTY_GRANT = (None,) * 4


class CurrentGrant(BaseModel):
    model_config = ConfigDict(strict=True)

    scope_id: str
    scope_name: str
    permission: Literal['organisation:read', 'knowledge:read']


class AccountCurrentGrants(BaseModel):
    model_config = ConfigDict(strict=True)

    account_class: Literal['user', 'superuser']
    account_status: Literal['active', 'pending', 'suspended', 'deactivated']
    assigned: list[CurrentGrant]
    effective: list[CurrentGrant]


def _denied() -> HTTPException:
    return HTTPException(403, 'Client access is not authorized')


def _project(rows: list[tuple[Any, ...]]) -> AccountCurrentGrants:
    if not rows:
        raise HTTPException(404, 'Not Found')
    try:
        account_class, account_status, *grant_fields = rows[0]
        result = AccountCurrentGrants(account_class=account_class, account_status=account_status,
                                      assigned=[], effective=[])
        if len(rows) == 1 and tuple(grant_fields) == _EMPTY_GRANT:
            return result
        seen: set[tuple[str, str]] = set()
        scope_names: dict[str, str] = {}
        for row_class, row_status, scope_id, scope_name, permission, eligible in rows:
            grant = CurrentGrant(scope_id=scope_id, scope_name=scope_name, permission=permission)
            key = (grant.scope_id, grant.permission)
            if ((row_class, row_status) != (account_class, account_status) or type(eligible) is not bool
                    or not grant.scope_id or '\x00' in grant.scope_id or '\x00' in grant.scope_name
                    or key in seen or scope_names.setdefault(grant.scope_id, grant.scope_name) != grant.scope_name):
                raise ValueError('inconsistent current grants result')
            seen.add(key)
            result.assigned.append(grant)
            if (result.account_status == 'active' and eligible
                    and role_allows_permission(result.account_class, grant.permission)):
                result.effective.append(grant)
        return result
    except (ValidationError, TypeError, ValueError):
        raise DatabaseUnavailable('invalid current grants result') from None


def create_account_current_grants_router(
    *,
    principal_dependency: Callable[..., Any],
    protected_scope: Callable[..., AbstractContextManager[TenantSession]],
) -> APIRouter:
    router = APIRouter(prefix='/v1/users', tags=['user directory'])
    principal_dep = Depends(principal_dependency)

    @router.get('/{id}/grants', response_model=AccountCurrentGrants, summary='Read current ordinary account grants')
    def get_current_grants(id: str, request: Request, principal: Principal = principal_dep) -> AccountCurrentGrants:
        identity = getattr(request.state, 'authenticated_identity', None)
        if (not isinstance(identity, AuthenticatedIdentity) or principal.platform_superadmin
                or len(principal.tenant_ids) != 1):
            raise _denied()
        tenant = next(iter(principal.tenant_ids))
        grants = {grant.action for grant in principal.grants if grant.tenant_id == tenant}
        # This early check is only a ceiling; SQL rechecks the session, actor,
        # target and exact scope visibility in its protected snapshot.
        if (tenant, 'admin') not in principal.role_bindings or not _PERMISSIONS <= grants:
            raise _denied()
        if request.scope['query_string']:
            raise HTTPException(400, 'Invalid grants query')
        try:
            target = UUID(id) if len(id) == 36 else None
        except ValueError:
            target = None
        if target is None or str(target) != id.lower():  # Same UUID syntax as directory detail.
            raise HTTPException(404, 'Not Found')
        with protected_scope(
            tenant, auth_user_id=identity.auth_user_id, session_id=identity.session_id,
            principal_id=principal.subject_id, issuer=identity.issuer,
        ) as session:
            connection: Any = session.connection
            if connection is None or session.tenant_id != tenant:
                raise DatabaseUnavailable('current grants connection unavailable')
            try:
                rows = connection.execute(
                    'SELECT account_class, account_status, scope_id, scope_name, permission, eligible '
                    'FROM bri.read_account_current_grants(%s,%s,%s,%s,%s) ORDER BY scope_id, permission',
                    (tenant, UUID(principal.subject_id), identity.session_id, identity.issuer, target),
                ).fetchall()
            except InsufficientPrivilege:
                raise _denied() from None
            except PostgresError:
                raise DatabaseUnavailable('current grants read unavailable') from None
            return _project(rows)

    return router
