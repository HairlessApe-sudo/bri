"""Existing synthetic tenants plus a small API-only knowledge catalog."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from bri.access.policy import AccessGrant, Principal
from bri.access.roles import CONFIGURATION_PERMISSIONS, role_allows_permission


_FIXTURE_PATH = Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "synthetic_municipalities.json"


@dataclass(frozen=True, slots=True)
class OrganizationNode:
    node_id: str
    node_type: str
    display_name: str
    parent_node_id: str | None


@dataclass(frozen=True, slots=True)
class OrganizationRelationship:
    relationship_id: str
    from_node_id: str
    to_node_id: str
    relationship_type: str
    grants_access: bool


@dataclass(frozen=True, slots=True)
class SyntheticOrganization:
    tenant_id: str
    display_name: str
    sector: str
    nodes: tuple[OrganizationNode, ...]
    relationships: tuple[OrganizationRelationship, ...]


@dataclass(frozen=True, slots=True)
class SyntheticCatalog:
    organizations: Mapping[str, SyntheticOrganization]
    principals: Mapping[str, Principal]


def load_catalog(fixture_path: Path = _FIXTURE_PATH) -> SyntheticCatalog:
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    if fixture.get("synthetic_only") is not True:
        raise ValueError("development identity catalog must be explicitly synthetic")

    organizations: dict[str, SyntheticOrganization] = {}
    principals: dict[str, Principal] = {}
    for tenant in fixture.get("tenants", []):
        tenant_id = tenant["tenant_id"]
        nodes = tuple(
            OrganizationNode(
                node_id=node["node_id"],
                node_type=node["node_type"],
                display_name=node["display_name"],
                parent_node_id=node.get("parent_id"),
            )
            for node in tenant.get("org_nodes", [])
        )
        node_ids = {node.node_id for node in nodes}
        if len(node_ids) != len(nodes):
            raise ValueError("synthetic tenant has duplicate organization nodes")
        relationships = tuple(
            OrganizationRelationship(
                relationship_id=relationship["relationship_id"],
                from_node_id=relationship["from_node_id"],
                to_node_id=relationship["to_node_id"],
                relationship_type=relationship["relationship_type"],
                grants_access=relationship["grants_access"],
            )
            for relationship in tenant.get("relationships", [])
        )
        organizations[tenant_id] = SyntheticOrganization(
            tenant_id=tenant_id,
            display_name=tenant["display_name"],
            sector=tenant["sector"],
            nodes=nodes,
            relationships=relationships,
        )

        roles = {role["role_id"]: role for role in tenant.get("roles", [])}
        for user in tenant.get("users", []):
            subject_id = user["user_id"]
            if subject_id in principals:
                raise ValueError("synthetic identities must be globally unique")
            membership_type = user.get("membership_type", "user")
            if membership_type not in {"user", "superuser", "admin", "platform_superadmin"}:
                raise ValueError("synthetic identity has an unknown approved role")
            role_bindings = ((tenant_id, membership_type),)
            grants: list[AccessGrant] = []
            for assignment in user.get("role_assignments", []):
                role = roles.get(assignment["role_id"])
                scope_id = assignment["scope_node_id"]
                if role is None or scope_id not in node_ids:
                    raise ValueError("synthetic role assignment refers to an unknown role or scope")
                for permission in role.get("permissions", []):
                    if not role_allows_permission(membership_type, permission):
                        continue
                    grant_scope = tenant_id if (
                        permission in CONFIGURATION_PERMISSIONS
                        and membership_type in {"admin", "platform_superadmin"}
                    ) else scope_id
                    grants.append(AccessGrant(tenant_id, permission, grant_scope))
            principals[subject_id] = Principal(
                subject_id=subject_id,
                tenant_ids=frozenset({tenant_id}),
                grants=tuple(dict.fromkeys(grants)),
                role_bindings=role_bindings,
                platform_superadmin=membership_type == "platform_superadmin",
            )

    return SyntheticCatalog(organizations, principals)
