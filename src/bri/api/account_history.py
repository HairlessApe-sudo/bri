"""Read-only administration history for a directory-visible ordinary account."""
from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from psycopg import Error as PostgresError
from psycopg.errors import InsufficientPrivilege, InvalidParameterValue
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, ValidationError

from bri.access.policy import Principal
from bri.api.authentication import AuthenticatedIdentity
from bri.api.database import DatabaseUnavailable, TenantSession

_DEFAULT_LIMIT = 25
_MAX_LIMIT = 100
_PERMISSIONS = frozenset({'user:directory:read', 'account:history:read'})
_EMPTY_ROW = (None,) * 7
_REASON_CODES = {
    'suspended': {'policy_violation', 'access_review', 'temporary_leave'},
    'reactivated': {'review_complete', 'access_restored'},
    'deactivated': {'account_closed', 'access_review', 'policy_violation'},
}
_QUERY_SCHEMA = {'parameters': [
    {'in': 'query', 'name': 'limit',
     'schema': {'type': 'integer', 'minimum': 1, 'maximum': _MAX_LIMIT, 'default': _DEFAULT_LIMIT}},
    {'in': 'query', 'name': 'cursor', 'description': 'Canonical UUID of the last event from the previous page',
     'schema': {'type': 'string', 'format': 'uuid'}},
]}


class HistoryActor(BaseModel):
    model_config = ConfigDict(strict=True)

    id: UUID | None
    display_name: Annotated[str, Field(max_length=128)] | None


class HistoryEvent(BaseModel):
    model_config = ConfigDict(strict=True)

    id: UUID
    occurred_at: AwareDatetime
    action: Literal['provisioned', 'activated', 'display_name_changed', 'suspended', 'reactivated',
                    'permission_granted', 'permission_revoked', 'deactivated']
    outcome: Literal['success', 'denied', 'failure']
    reason_code: str | None
    actor: HistoryActor


class HistoryPage(BaseModel):
    items: list[HistoryEvent]
    next_cursor: UUID | None


def _invalid_query() -> HTTPException:
    return HTTPException(400, 'Invalid history query')


def _denied() -> HTTPException:
    return HTTPException(403, 'Client access is not authorized')


def _uuid(value: str, *, canonical: bool = True) -> UUID | None:
    if len(value) != 36:
        return None
    try:
        parsed = UUID(value)
    except ValueError:
        return None
    return parsed if str(parsed) == (value if canonical else value.lower()) else None


def _page_parameters(request: Request) -> tuple[int, UUID | None]:
    values: dict[str, str] = {}
    for key, value in request.query_params.multi_items():
        if key not in {'limit', 'cursor'} or key in values:
            raise _invalid_query()
        values[key] = value
    raw_limit = values.get('limit', str(_DEFAULT_LIMIT))
    if len(raw_limit) > len(str(_MAX_LIMIT)) or not raw_limit.isascii() or not raw_limit.isdecimal():
        raise _invalid_query()
    limit = int(raw_limit)
    if not 1 <= limit <= _MAX_LIMIT:
        raise _invalid_query()
    cursor = _uuid(values['cursor']) if 'cursor' in values else None
    if 'cursor' in values and cursor is None:
        raise _invalid_query()
    return limit, cursor


def _project_page(rows: list[tuple[Any, ...]], limit: int, cursor: UUID | None) -> HistoryPage:
    if not rows:
        raise HTTPException(404, 'Not Found')
    if rows == [_EMPTY_ROW]:
        return HistoryPage(items=[], next_cursor=None)
    if len(rows) > limit + 1:
        raise DatabaseUnavailable('invalid history result')

    items: list[HistoryEvent] = []
    seen = {cursor} if cursor is not None else set()
    try:
        for event_id, occurred_at, action, outcome, reason, actor_id, actor_name in rows:
            event = HistoryEvent(
                id=event_id, occurred_at=occurred_at, action=action, outcome=outcome, reason_code=reason,
                actor=HistoryActor(id=actor_id, display_name='Restricted actor' if actor_id is None else actor_name),
            )
            if event.id in seen or (reason is not None and reason not in _REASON_CODES.get(event.action, ())):
                raise DatabaseUnavailable('invalid history result')
            seen.add(event.id)
            items.append(event)
    except (ValidationError, TypeError, ValueError):
        raise DatabaseUnavailable('invalid history result') from None
    return HistoryPage(items=items[:limit], next_cursor=items[limit - 1].id if len(items) > limit else None)


def create_account_history_router(
    *,
    principal_dependency: Callable[..., Any],
    protected_scope: Callable[..., AbstractContextManager[TenantSession]],
) -> APIRouter:
    router = APIRouter(prefix='/v1/users', tags=['user directory'])
    principal_dep = Depends(principal_dependency)

    @router.get('/{id}/history', response_model=HistoryPage, summary='Read ordinary account administration history',
                openapi_extra=_QUERY_SCHEMA)
    def get_history(id: str, request: Request, principal: Principal = principal_dep) -> HistoryPage:
        identity = getattr(request.state, 'authenticated_identity', None)
        if (not isinstance(identity, AuthenticatedIdentity) or principal.platform_superadmin
                or len(principal.tenant_ids) != 1):
            raise _denied()
        tenant = next(iter(principal.tenant_ids))
        grants = {grant.action for grant in principal.grants if grant.tenant_id == tenant}
        # This is only a ceiling; SQL revalidates the current grants, directory
        # target visibility, actor visibility and cursor in the protected snapshot.
        if (tenant, 'admin') not in principal.role_bindings or not _PERMISSIONS <= grants:
            raise _denied()

        limit, cursor = _page_parameters(request)
        target = _uuid(id, canonical=False)  # Match the existing directory's target syntax.
        if target is None:
            raise HTTPException(404, 'Not Found')
        with protected_scope(
            tenant, auth_user_id=identity.auth_user_id, session_id=identity.session_id,
            principal_id=principal.subject_id, issuer=identity.issuer,
        ) as session:
            connection: Any = session.connection
            if connection is None or session.tenant_id != tenant:
                raise DatabaseUnavailable('history connection unavailable')
            try:
                rows = connection.execute(
                    'SELECT event_id, occurred_at, action, outcome, reason_code, actor_id, actor_display_name '
                    'FROM bri.read_account_history(%s,%s,%s,%s,%s,%s,%s) '
                    'ORDER BY occurred_at DESC, event_id DESC',
                    (tenant, principal.subject_id, identity.session_id, identity.issuer, target, limit, cursor),
                ).fetchall()
            except InsufficientPrivilege:
                raise _denied() from None
            except InvalidParameterValue:
                raise _invalid_query() from None
            except PostgresError:
                raise DatabaseUnavailable('history read unavailable') from None
            return _project_page(rows, limit, cursor)

    return router
