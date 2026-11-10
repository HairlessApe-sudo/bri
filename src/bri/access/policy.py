"""Fail-closed authorization primitives for exact tenant and resource scopes.

The caller must supply active memberships and effective grants produced by the
identity/role-assignment layer. This module intentionally performs no hierarchy
inheritance or implicit tenant-wide expansion.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AccessGrant:
    tenant_id: str
    action: str
    scope_id: str


@dataclass(frozen=True, slots=True)
class Principal:
    subject_id: str
    tenant_ids: frozenset[str]
    grants: tuple[AccessGrant, ...]


@dataclass(frozen=True, slots=True)
class Resource:
    tenant_id: str
    scope_id: str | None


def is_authorized(principal: Principal | None, action: str, resource: Resource | None) -> bool:
    """Return true only for a valid active-tenant, action, and exact-scope grant."""
    if principal is None or resource is None:
        return False
    if not principal.subject_id or not action or not resource.tenant_id or not resource.scope_id:
        return False
    if resource.tenant_id not in principal.tenant_ids:
        return False
    return any(
        grant.tenant_id == resource.tenant_id
        and grant.action == action
        and grant.scope_id == resource.scope_id
        for grant in principal.grants
    )
