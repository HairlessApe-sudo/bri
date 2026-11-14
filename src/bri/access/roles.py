"""Approved role-to-service permission ceilings.

Role membership is a capability ceiling, never a grant by itself. Effective
operations still require an explicit role-permission row and exact tenant scope.
"""
from __future__ import annotations

from types import MappingProxyType


USER_CAPABILITIES = frozenset({
    "historical_case:read",
    "document:read",
    "ai_question:ask",
})
SUPERUSER_CAPABILITIES = USER_CAPABILITIES | frozenset(
    f"{resource}:{verb}"
    for resource in ("historical_case", "document")
    for verb in ("create", "read", "update", "delete")
)
TENANT_ADMIN_CAPABILITIES = SUPERUSER_CAPABILITIES | frozenset(
    f"{resource}:{verb}"
    for resource in ("standard_user", "ai_gateway_config", "approved_website")
    for verb in ("create", "read", "update", "delete")
) | frozenset({
    "prompt:client:read",
    "prompt:client:manage",
    "prompt:platform:read",
    "privacy:configuration:read",
    "privacy:configuration:manage",
    "privacy:signature:read",
    "privacy:signature:manage",
})

ROLE_PERMISSION_CEILINGS = MappingProxyType({
    "user": USER_CAPABILITIES,
    "superuser": SUPERUSER_CAPABILITIES,
    "admin": TENANT_ADMIN_CAPABILITIES,
    "platform_superadmin": TENANT_ADMIN_CAPABILITIES | frozenset({
        "prompt:platform:manage",
        "platform:prompt:tenant:manage",
        "signature_package:manage",
        "platform:tenant:manage",
        "platform:client_admin:manage",
    }),
})

CONFIGURATION_PERMISSIONS = frozenset({
    "prompt:client:read",
    "prompt:client:manage",
    "prompt:platform:read",
    "prompt:platform:manage",
    "platform:prompt:tenant:manage",
    "privacy:configuration:read",
    "privacy:configuration:manage",
    "privacy:signature:read",
    "privacy:signature:manage",
    "signature_package:manage",
})


def role_allows_permission(role: str, permission: str) -> bool:
    """Apply a role ceiling to governed capabilities; preserve other explicit grants."""
    if permission in CONFIGURATION_PERMISSIONS or permission in {
        "historical_case:read", "document:read", "ai_question:ask",
        *(f"{resource}:{verb}" for resource in ("historical_case", "document") for verb in ("create", "read", "update", "delete")),
        *(f"{resource}:{verb}" for resource in ("standard_user", "ai_gateway_config", "approved_website") for verb in ("create", "read", "update", "delete")),
    }:
        return permission in ROLE_PERMISSION_CEILINGS.get(role, frozenset())
    return True
