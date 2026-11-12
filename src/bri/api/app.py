"""FastAPI application with explicitly local synthetic authentication."""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ContextManager, Iterator, Protocol, cast

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict

from bri.access.policy import Principal, Resource, is_authorized
from bri.api.catalog import (
    OrganizationNode,
    OrganizationRelationship,
    SyntheticCatalog,
    SyntheticOrganization,
    load_catalog,
)
from bri.api.database import Database, DatabaseUnavailable, TenantSession
from bri.knowledge.query import EvidenceCitation, KnowledgeItem, answer_question


_PROJECT_ROOT = Path(__file__).resolve().parents[3]


@dataclass(frozen=True, slots=True)
class ApiSettings:
    environment: str = ""
    dev_auth_enabled: bool = False
    supabase_url: str = field(default="", repr=False)
    database_url: str = field(default="", repr=False)

    def __post_init__(self) -> None:
        if self.dev_auth_enabled and self.environment.strip().lower() != "development":
            raise ValueError("synthetic authentication can only be enabled in development")

    @classmethod
    def from_environment(cls) -> ApiSettings:
        load_dotenv(_PROJECT_ROOT / ".env.local", override=False)
        return cls(
            environment=os.environ.get("BRI_ENVIRONMENT", ""),
            dev_auth_enabled=os.environ.get("BRI_DEV_AUTH_ENABLED", "").strip().lower() == "true",
            supabase_url=os.environ.get("SUPABASE_URL", ""),
            database_url=os.environ.get("DATABASE_URL", ""),
        )


class DatabaseProtocol(Protocol):
    def healthcheck(self) -> None: ...

    def tenant_context(self, tenant_id: str) -> ContextManager[TenantSession]: ...


class OrganizationNodeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    node_id: str
    node_type: str
    display_name: str
    parent_node_id: str | None


class OrganizationRelationshipResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    relationship_id: str
    from_node_id: str
    to_node_id: str
    relationship_type: str
    grants_access: bool


class OrganizationStructureResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    nodes: list[OrganizationNodeResponse]
    relationships: list[OrganizationRelationshipResponse]


class KnowledgeRecordResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    record_id: str
    title: str
    scope_id: str
    validation_state: str
    source_version: str
    source_location: str
    content: str


class SourceReferenceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    record_id: str
    title: str
    source_version: str
    source_location: str


class CitationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    record_id: str
    title: str
    source_version: str
    source_location: str
    excerpt: str


class KnowledgeSearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str
    answer: str | None
    citations: list[CitationResponse]


def _record_response(item: KnowledgeItem) -> KnowledgeRecordResponse:
    return KnowledgeRecordResponse(
        record_id=item.record_id,
        title=item.title,
        scope_id=item.scope_id,
        validation_state=item.validation_state,
        source_version=item.source_version,
        source_location=item.source_location,
        content=item.content,
    )


def _citation_response(citation: EvidenceCitation) -> CitationResponse:
    return CitationResponse(
        record_id=citation.record_id,
        title=citation.title,
        source_version=citation.source_version,
        source_location=citation.source_location,
        excerpt=citation.excerpt,
    )


def _is_loopback(request: Request) -> bool:
    if request.client is None:
        return False
    try:
        return ipaddress.ip_address(request.client.host).is_loopback
    except ValueError:
        return False


def _has_action(principal: Principal, action: str) -> bool:
    return any(
        grant.action == action and grant.tenant_id in principal.tenant_ids
        for grant in principal.grants
    )


def _organization_for_tenant(
    session: TenantSession,
    tenant_id: str,
    fallback: SyntheticOrganization | None,
) -> SyntheticOrganization | None:
    if session.tenant_id != tenant_id:
        raise DatabaseUnavailable("tenant session does not match the authenticated identity")
    if session.connection is None:
        return fallback

    connection = cast(Any, session.connection)
    tenant = connection.execute(
        "SELECT tenant_id, display_name, sector FROM bri.tenants WHERE tenant_id=%s",
        (tenant_id,),
    ).fetchone()
    if tenant is None:
        return fallback
    if tenant[0] != tenant_id:
        raise DatabaseUnavailable("RLS returned an unexpected tenant")
    nodes = tuple(
        OrganizationNode(
            node_id=row[0],
            node_type=row[1],
            display_name=row[2],
            parent_node_id=row[3],
        )
        for row in connection.execute(
            "SELECT node_id, node_type, display_name, parent_node_id "
            "FROM bri.org_nodes WHERE tenant_id=%s ORDER BY node_id",
            (tenant_id,),
        ).fetchall()
    )
    relationships = tuple(
        OrganizationRelationship(
            relationship_id=row[0],
            from_node_id=row[1],
            to_node_id=row[2],
            relationship_type=row[3],
            grants_access=row[4],
        )
        for row in connection.execute(
            "SELECT relationship_id, from_node_id, to_node_id, relationship_type, grants_access "
            "FROM bri.org_relationships WHERE tenant_id=%s ORDER BY relationship_id",
            (tenant_id,),
        ).fetchall()
    )
    return SyntheticOrganization(tenant[0], tenant[1], tenant[2], nodes, relationships)


def create_app(
    *,
    settings: ApiSettings | None = None,
    database: DatabaseProtocol | None = None,
    catalog: SyntheticCatalog | None = None,
) -> FastAPI:
    active_settings = settings or ApiSettings.from_environment()
    active_database = database or Database(
        supabase_url=active_settings.supabase_url,
        database_url=active_settings.database_url,
    )
    active_catalog = catalog or (
        load_catalog() if active_settings.dev_auth_enabled else SyntheticCatalog({}, {}, ())
    )

    app = FastAPI(
        title="BRI Development API",
        version="0.1.0",
        description=(
            "Development-only API using synthetic identities and fixture-backed records. "
            "Synthetic identity selection is local-only and is not production authentication."
        ),
        openapi_tags=[
            {"name": "health", "description": "Restricted-role database readiness."},
            {"name": "organizations", "description": "Read only exact-scope organizational structures."},
            {"name": "knowledge", "description": "Approved synthetic knowledge and source references."},
        ],
    )
    app.state.settings = active_settings
    app.state.database = active_database
    app.state.catalog = active_catalog

    @app.exception_handler(DatabaseUnavailable)
    async def database_unavailable_handler(request: Request, exc: DatabaseUnavailable) -> JSONResponse:
        return JSONResponse(
            status_code=503,
            content={"status": "unavailable", "database": "unavailable"},
        )

    async def current_principal(
        request: Request,
        x_dev_identity: str | None = Header(
            default=None,
            alias="X-Dev-Identity",
            description="Synthetic fixture identity; local development only.",
        ),
    ) -> Principal:
        if "x-tenant-id" in request.headers or "tenant_id" in request.query_params:
            raise HTTPException(status_code=400, detail="Tenant selection is server-controlled")
        if await request.body():
            raise HTTPException(status_code=400, detail="Request bodies are not accepted on read endpoints")
        if not active_settings.dev_auth_enabled or active_settings.environment.strip().lower() != "development":
            raise HTTPException(status_code=503, detail="Development identity adapter is disabled")
        if not _is_loopback(request):
            raise HTTPException(status_code=403, detail="Development identities are restricted to loopback clients")
        if not x_dev_identity:
            raise HTTPException(status_code=401, detail="A synthetic development identity is required")
        principal = active_catalog.principals.get(x_dev_identity)
        if principal is None:
            raise HTTPException(status_code=401, detail="Unknown synthetic development identity")
        return principal

    def tenant_session(
        request: Request,
        principal: Principal = Depends(current_principal),
    ) -> Iterator[TenantSession]:
        if len(principal.tenant_ids) != 1:
            raise HTTPException(status_code=403, detail="Synthetic identity must map to exactly one tenant")
        tenant_id = next(iter(principal.tenant_ids))
        try:
            with request.app.state.database.tenant_context(tenant_id) as session:
                yield session
        except DatabaseUnavailable:
            raise

    def require_permission(principal: Principal, action: str) -> None:
        if not _has_action(principal, action):
            raise HTTPException(status_code=403, detail="Required permission is missing")

    @app.get("/health", tags=["health"], summary="Check restricted-role database readiness")
    def health() -> dict[str, str]:
        active_database.healthcheck()
        return {"status": "ok", "database": "ok"}

    @app.get(
        "/v1/organizations/structure",
        response_model=OrganizationStructureResponse,
        tags=["organizations"],
        summary="List individually authorized organizational nodes and relationships",
    )
    def organization_structure(
        principal: Principal = Depends(current_principal),
        session: TenantSession = Depends(tenant_session),
    ) -> OrganizationStructureResponse:
        authorized: list[tuple[str, OrganizationNode]] = []
        organizations: dict[str, SyntheticOrganization] = {}
        for tenant_id in principal.tenant_ids:
            organization = _organization_for_tenant(
                session,
                tenant_id,
                active_catalog.organizations.get(tenant_id),
            )
            if organization is None:
                continue
            organizations[tenant_id] = organization
            authorized.extend(
                (tenant_id, node)
                for node in organization.nodes
                if is_authorized(principal, "organisation:read", Resource(tenant_id, node.node_id))
            )
        if not authorized:
            raise HTTPException(status_code=403, detail="No organizational nodes are authorized")
        visible_node_ids = {node.node_id for _, node in authorized}
        nodes = [
            OrganizationNodeResponse(
                node_id=node.node_id,
                node_type=node.node_type,
                display_name=node.display_name,
                parent_node_id=(node.parent_node_id if node.parent_node_id in visible_node_ids else None),
            )
            for _, node in authorized
        ]
        relationships = [
            OrganizationRelationshipResponse(
                relationship_id=relationship.relationship_id,
                from_node_id=relationship.from_node_id,
                to_node_id=relationship.to_node_id,
                relationship_type=relationship.relationship_type,
                grants_access=relationship.grants_access,
            )
            for tenant_id, organization in organizations.items()
            for relationship in organization.relationships
            if relationship.from_node_id in visible_node_ids
            and relationship.to_node_id in visible_node_ids
        ]
        return OrganizationStructureResponse(nodes=nodes, relationships=relationships)

    @app.get(
        "/v1/organizations/nodes/{node_id}",
        response_model=OrganizationNodeResponse,
        tags=["organizations"],
        summary="Read one organization node at its exact authorized scope",
    )
    def organization_node(
        node_id: str,
        principal: Principal = Depends(current_principal),
        session: TenantSession = Depends(tenant_session),
    ) -> OrganizationNodeResponse:
        for tenant_id in principal.tenant_ids:
            organization = _organization_for_tenant(
                session,
                tenant_id,
                active_catalog.organizations.get(tenant_id),
            )
            if organization is None:
                continue
            for node in organization.nodes:
                if node.node_id == node_id and is_authorized(
                    principal, "organisation:read", Resource(tenant_id, node_id)
                ):
                    parent = node.parent_node_id
                    if parent is not None and not is_authorized(
                        principal, "organisation:read", Resource(tenant_id, parent)
                    ):
                        parent = None
                    return OrganizationNodeResponse(
                        node_id=node.node_id,
                        node_type=node.node_type,
                        display_name=node.display_name,
                        parent_node_id=parent,
                    )
        raise HTTPException(status_code=404, detail="Organization node not found")

    @app.get(
        "/v1/knowledge",
        response_model=list[KnowledgeRecordResponse],
        tags=["knowledge"],
        summary="List approved knowledge records in explicitly authorized scopes",
    )
    def list_knowledge(
        principal: Principal = Depends(current_principal),
        _session: TenantSession = Depends(tenant_session),
    ) -> list[KnowledgeRecordResponse]:
        require_permission(principal, "knowledge:read")
        return [
            _record_response(item)
            for item in active_catalog.knowledge_items
            if item.validation_state == "approved"
            and item.tenant_id in principal.tenant_ids
            and is_authorized(principal, "knowledge:read", Resource(item.tenant_id, item.scope_id))
        ]

    @app.get(
        "/v1/knowledge/search",
        response_model=KnowledgeSearchResponse,
        tags=["knowledge"],
        summary="Search approved synthetic evidence using the existing deterministic retriever",
    )
    def search_knowledge(
        q: str = Query(min_length=1, max_length=512),
        principal: Principal = Depends(current_principal),
        _session: TenantSession = Depends(tenant_session),
    ) -> KnowledgeSearchResponse:
        require_permission(principal, "knowledge:read")
        result = answer_question(principal, q, active_catalog.knowledge_items)
        return KnowledgeSearchResponse(
            status=result.status,
            answer=result.answer,
            citations=[_citation_response(citation) for citation in result.citations],
        )

    @app.get(
        "/v1/knowledge/{record_id}",
        response_model=KnowledgeRecordResponse,
        tags=["knowledge"],
        summary="Read one approved record at its exact authorized scope",
    )
    def get_knowledge(
        record_id: str,
        principal: Principal = Depends(current_principal),
        _session: TenantSession = Depends(tenant_session),
    ) -> KnowledgeRecordResponse:
        require_permission(principal, "knowledge:read")
        for item in active_catalog.knowledge_items:
            if (
                item.record_id == record_id
                and item.validation_state == "approved"
                and item.tenant_id in principal.tenant_ids
                and is_authorized(principal, "knowledge:read", Resource(item.tenant_id, item.scope_id))
            ):
                return _record_response(item)
        raise HTTPException(status_code=404, detail="Knowledge record not found")

    @app.get(
        "/v1/sources/{record_id}",
        response_model=SourceReferenceResponse,
        tags=["knowledge"],
        summary="Read the source reference for an approved authorized record",
    )
    def source_reference(
        record_id: str,
        principal: Principal = Depends(current_principal),
        _session: TenantSession = Depends(tenant_session),
    ) -> SourceReferenceResponse:
        require_permission(principal, "knowledge:read")
        for item in active_catalog.knowledge_items:
            if (
                item.record_id == record_id
                and item.validation_state == "approved"
                and item.tenant_id in principal.tenant_ids
                and is_authorized(principal, "knowledge:read", Resource(item.tenant_id, item.scope_id))
            ):
                return SourceReferenceResponse(
                    record_id=item.record_id,
                    title=item.title,
                    source_version=item.source_version,
                    source_location=item.source_location,
                )
        raise HTTPException(status_code=404, detail="Source reference not found")

    return app
