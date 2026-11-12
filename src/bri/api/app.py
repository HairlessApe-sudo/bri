"""FastAPI application with explicitly local synthetic authentication."""
from __future__ import annotations

import hashlib
import ipaddress
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, ContextManager, Iterator, Literal, Protocol, cast
from uuid import uuid4

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

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

    def write_tenant_context(self, tenant_id: str) -> ContextManager[TenantSession]: ...


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
    source_id: str
    source_version_id: str
    source_version: str
    extraction_id: str
    content_sha256: str
    extractor_name: str
    extractor_version: str
    source_location: str
    content: str


class SourceReferenceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    record_id: str
    title: str
    source_id: str
    source_version_id: str
    source_version: str
    extraction_id: str
    content_sha256: str
    extractor_name: str
    extractor_version: str
    source_location: str


class CitationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    record_id: str
    title: str
    source_id: str
    source_version_id: str
    source_version: str
    extraction_id: str
    content_sha256: str
    extractor_name: str
    extractor_version: str
    source_location: str
    excerpt: str


class KnowledgeSearchResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: str
    answer: str | None
    citations: list[CitationResponse]


class ProposedKnowledgeResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    proposal_id: str
    scope_id: str
    source_id: str
    source_version_id: str
    source_version: str
    extraction_id: str
    content_sha256: str
    extractor_name: str
    extractor_version: str
    source_location: str
    title: str
    content: str
    proposed_by: str
    proposed_at: datetime
    status: Literal["proposed"] = "proposed"


class CreateProposalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    extraction_id: str = Field(min_length=1, max_length=200)


class ValidationDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["approved", "rejected"]
    comment: str | None = Field(default=None, max_length=1000)


class ValidationDecisionResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    proposal_id: str
    decision_id: str
    decision: Literal["approved", "rejected"]
    reviewer_id: str
    decided_at: datetime


def _record_response(item: KnowledgeItem) -> KnowledgeRecordResponse:
    return KnowledgeRecordResponse(
        record_id=item.record_id,
        title=item.title,
        scope_id=item.scope_id,
        validation_state=item.validation_state,
        source_id=item.source_id,
        source_version_id=item.source_version_id,
        source_version=item.source_version,
        extraction_id=item.extraction_id,
        content_sha256=item.content_sha256,
        extractor_name=item.extractor_name,
        extractor_version=item.extractor_version,
        source_location=item.source_location,
        content=item.content,
    )


def _citation_response(citation: EvidenceCitation) -> CitationResponse:
    return CitationResponse(
        record_id=citation.record_id,
        title=citation.title,
        source_id=citation.source_id,
        source_version_id=citation.source_version_id,
        source_version=citation.source_version,
        extraction_id=citation.extraction_id,
        content_sha256=citation.content_sha256,
        extractor_name=citation.extractor_name,
        extractor_version=citation.extractor_version,
        source_location=citation.source_location,
        excerpt=citation.excerpt,
    )


def _connection(session: TenantSession) -> Any:
    if session.connection is None:
        raise DatabaseUnavailable("persistent knowledge storage is unavailable")
    return cast(Any, session.connection)


_PROPOSAL_SELECT = """
SELECT p.proposal_id, p.tenant_id, p.scope_node_id, p.proposed_by, p.proposed_at,
       s.title, s.source_id, sv.source_version_id, sv.version_label,
       x.extraction_id, x.content, x.content_sha256, x.extractor_name,
       x.extractor_version, x.source_location
FROM bri.knowledge_proposals p
JOIN bri.source_extractions x
  ON x.tenant_id=p.tenant_id AND x.extraction_id=p.extraction_id
 AND x.scope_node_id=p.scope_node_id
JOIN bri.source_records s
  ON s.tenant_id=x.tenant_id AND s.source_id=x.source_id
JOIN bri.source_versions sv
  ON sv.tenant_id=x.tenant_id AND sv.source_id=x.source_id
 AND sv.source_version_id=x.source_version_id
"""


def _verified_content(row: tuple[Any, ...]) -> str:
    content = row[10]
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    if digest != row[11]:
        raise DatabaseUnavailable("stored source content failed integrity verification")
    return content


def _knowledge_item(row: tuple[Any, ...]) -> KnowledgeItem:
    content = _verified_content(row)
    return KnowledgeItem(
        record_id=row[0],
        tenant_id=row[1],
        scope_id=row[2],
        validation_state="approved",
        title=row[5],
        source_version=row[8],
        source_location=row[14],
        content=content,
        source_id=row[6],
        source_version_id=row[7],
        extraction_id=row[9],
        content_sha256=row[11],
        extractor_name=row[12],
        extractor_version=row[13],
    )


def _proposal_response(row: tuple[Any, ...]) -> ProposedKnowledgeResponse:
    _verified_content(row)
    return ProposedKnowledgeResponse(
        proposal_id=row[0],
        scope_id=row[2],
        proposed_by=row[3],
        proposed_at=row[4],
        title=row[5],
        source_id=row[6],
        source_version_id=row[7],
        source_version=row[8],
        extraction_id=row[9],
        content=row[10],
        content_sha256=row[11],
        extractor_name=row[12],
        extractor_version=row[13],
        source_location=row[14],
    )


def _authorized_scopes(principal: Principal, action: str) -> tuple[str, ...]:
    tenant_ids = principal.tenant_ids
    return tuple(sorted({
        grant.scope_id
        for grant in principal.grants
        if grant.tenant_id in tenant_ids and grant.action == action
    }))


def _validated_items(session: TenantSession, principal: Principal) -> tuple[KnowledgeItem, ...]:
    scopes = _authorized_scopes(principal, "knowledge:read")
    if not scopes:
        return ()
    rows = _connection(session).execute(
        _PROPOSAL_SELECT
        + " JOIN bri.validated_knowledge v "
        "ON v.tenant_id=p.tenant_id AND v.proposal_id=p.proposal_id "
        "WHERE p.tenant_id=%s AND p.scope_node_id = ANY(%s) "
        "ORDER BY p.proposed_at, p.proposal_id",
        (next(iter(principal.tenant_ids)), list(scopes)),
    ).fetchall()
    return tuple(
        item for row in rows
        if is_authorized(
            principal,
            "knowledge:read",
            Resource(row[1], row[2]),
        )
        for item in (_knowledge_item(row),)
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
        load_catalog() if active_settings.dev_auth_enabled else SyntheticCatalog({}, {})
    )

    app = FastAPI(
        title="BRI Development API",
        version="0.1.0",
        description=(
            "Development-only API using synthetic identities and PostgreSQL-backed knowledge. "
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
        if request.method in {"GET", "HEAD"} and await request.body():
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

    def tenant_write_session(
        request: Request,
        principal: Principal = Depends(current_principal),
    ) -> Iterator[TenantSession]:
        if len(principal.tenant_ids) != 1:
            raise HTTPException(status_code=403, detail="Synthetic identity must map to exactly one tenant")
        tenant_id = next(iter(principal.tenant_ids))
        try:
            with request.app.state.database.write_tenant_context(tenant_id) as session:
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
        summary="List approved knowledge records from persistent tenant-scoped storage",
    )
    def list_knowledge(
        principal: Principal = Depends(current_principal),
        session: TenantSession = Depends(tenant_session),
    ) -> list[KnowledgeRecordResponse]:
        require_permission(principal, "knowledge:read")
        return [_record_response(item) for item in _validated_items(session, principal)]

    @app.get(
        "/v1/knowledge/proposals",
        response_model=list[ProposedKnowledgeResponse],
        tags=["knowledge"],
        summary="List pending proposals in the reviewer's exact authorized scopes",
    )
    def list_proposals(
        principal: Principal = Depends(current_principal),
        session: TenantSession = Depends(tenant_session),
    ) -> list[ProposedKnowledgeResponse]:
        require_permission(principal, "knowledge:review")
        scopes = _authorized_scopes(principal, "knowledge:review")
        if not scopes:
            raise HTTPException(status_code=403, detail="No review scopes are authorized")
        rows = _connection(session).execute(
            _PROPOSAL_SELECT
            + " LEFT JOIN bri.validation_decisions d "
            "ON d.tenant_id=p.tenant_id AND d.proposal_id=p.proposal_id "
            "WHERE p.tenant_id=%s AND p.scope_node_id = ANY(%s) "
            "AND d.proposal_id IS NULL ORDER BY p.proposed_at, p.proposal_id",
            (next(iter(principal.tenant_ids)), list(scopes)),
        ).fetchall()
        return [
            _proposal_response(row)
            for row in rows
            if is_authorized(principal, "knowledge:review", Resource(row[1], row[2]))
        ]

    @app.post(
        "/v1/knowledge/proposals",
        response_model=ProposedKnowledgeResponse,
        status_code=201,
        tags=["knowledge"],
        summary="Create a proposed knowledge item from an authorized source extraction",
    )
    def create_proposal(
        request_body: CreateProposalRequest,
        principal: Principal = Depends(current_principal),
        session: TenantSession = Depends(tenant_write_session),
    ) -> ProposedKnowledgeResponse:
        require_permission(principal, "knowledge:propose")
        tenant_id = next(iter(principal.tenant_ids))
        connection = _connection(session)
        source = connection.execute(
            "SELECT x.scope_node_id, s.title, s.source_id, sv.source_version_id, "
            "sv.version_label, x.extraction_id, x.content, x.content_sha256, "
            "x.extractor_name, x.extractor_version, x.source_location "
            "FROM bri.source_extractions x "
            "JOIN bri.source_records s ON s.tenant_id=x.tenant_id AND s.source_id=x.source_id "
            "JOIN bri.source_versions sv ON sv.tenant_id=x.tenant_id AND sv.source_id=x.source_id "
            "AND sv.source_version_id=x.source_version_id "
            "WHERE x.tenant_id=%s AND x.extraction_id=%s",
            (tenant_id, request_body.extraction_id),
        ).fetchone()
        if source is None:
            raise HTTPException(status_code=404, detail="Source extraction not found")
        if not is_authorized(
            principal,
            "knowledge:propose",
            Resource(tenant_id, source[0]),
        ):
            raise HTTPException(status_code=403, detail="Proposal scope is not authorized")
        source_content = source[6]
        source_digest = hashlib.sha256(source_content.encode("utf-8")).hexdigest()
        if source_digest != source[7]:
            raise DatabaseUnavailable("stored source content failed integrity verification")
        proposal_id = str(uuid4())
        inserted = connection.execute(
            "INSERT INTO bri.knowledge_proposals "
            "(tenant_id, proposal_id, extraction_id, scope_node_id, proposed_by) "
            "VALUES (%s, %s, %s, %s, %s) RETURNING proposed_at",
            (tenant_id, proposal_id, source[5], source[0], principal.subject_id),
        ).fetchone()
        if inserted is None:
            raise DatabaseUnavailable("proposal was not persisted")
        return ProposedKnowledgeResponse(
            proposal_id=proposal_id,
            scope_id=source[0],
            source_id=source[2],
            source_version_id=source[3],
            source_version=source[4],
            extraction_id=source[5],
            content=source_content,
            content_sha256=source[7],
            extractor_name=source[8],
            extractor_version=source[9],
            source_location=source[10],
            title=source[1],
            proposed_by=principal.subject_id,
            proposed_at=inserted[0],
        )

    @app.post(
        "/v1/knowledge/proposals/{proposal_id}/decision",
        response_model=ValidationDecisionResponse,
        tags=["knowledge"],
        summary="Approve or reject a pending proposal with server-attributed reviewer identity",
    )
    def decide_proposal(
        proposal_id: str,
        request_body: ValidationDecisionRequest,
        principal: Principal = Depends(current_principal),
        session: TenantSession = Depends(tenant_write_session),
    ) -> ValidationDecisionResponse:
        require_permission(principal, "knowledge:review")
        tenant_id = next(iter(principal.tenant_ids))
        connection = _connection(session)
        proposal = connection.execute(
            _PROPOSAL_SELECT + " WHERE p.tenant_id=%s AND p.proposal_id=%s",
            (tenant_id, proposal_id),
        ).fetchone()
        if proposal is None:
            raise HTTPException(status_code=404, detail="Knowledge proposal not found")
        if not is_authorized(
            principal,
            "knowledge:review",
            Resource(tenant_id, proposal[2]),
        ):
            raise HTTPException(status_code=403, detail="Review scope is not authorized")
        if proposal[3] == principal.subject_id:
            raise HTTPException(status_code=403, detail="Proposers cannot review their own proposal")
        _verified_content(proposal)
        decision_id = str(uuid4())
        decided = connection.execute(
            "INSERT INTO bri.validation_decisions "
            "(tenant_id, decision_id, proposal_id, reviewer_id, decision, comment) "
            "VALUES (%s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (tenant_id, proposal_id) DO NOTHING RETURNING decided_at",
            (
                tenant_id,
                decision_id,
                proposal_id,
                principal.subject_id,
                request_body.decision,
                request_body.comment,
            ),
        ).fetchone()
        if decided is None:
            raise HTTPException(status_code=409, detail="Proposal has already been decided")
        if request_body.decision == "approved":
            connection.execute(
                "INSERT INTO bri.validated_knowledge (tenant_id, proposal_id, decision_id) "
                "VALUES (%s, %s, %s)",
                (tenant_id, proposal_id, decision_id),
            )
        return ValidationDecisionResponse(
            proposal_id=proposal_id,
            decision_id=decision_id,
            decision=request_body.decision,
            reviewer_id=principal.subject_id,
            decided_at=decided[0],
        )

    @app.get(
        "/v1/knowledge/search",
        response_model=KnowledgeSearchResponse,
        tags=["knowledge"],
        summary="Search validated PostgreSQL evidence with source/version citations",
    )
    def search_knowledge(
        q: str = Query(min_length=1, max_length=512),
        principal: Principal = Depends(current_principal),
        session: TenantSession = Depends(tenant_session),
    ) -> KnowledgeSearchResponse:
        require_permission(principal, "knowledge:read")
        result = answer_question(principal, q, _validated_items(session, principal))
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
        session: TenantSession = Depends(tenant_session),
    ) -> KnowledgeRecordResponse:
        require_permission(principal, "knowledge:read")
        for item in _validated_items(session, principal):
            if item.record_id == record_id:
                return _record_response(item)
        raise HTTPException(status_code=404, detail="Knowledge record not found")

    @app.get(
        "/v1/sources/{record_id}",
        response_model=SourceReferenceResponse,
        tags=["knowledge"],
        summary="Read provenance for an approved authorized knowledge record",
    )
    def source_reference(
        record_id: str,
        principal: Principal = Depends(current_principal),
        session: TenantSession = Depends(tenant_session),
    ) -> SourceReferenceResponse:
        require_permission(principal, "knowledge:read")
        for item in _validated_items(session, principal):
            if item.record_id == record_id:
                return SourceReferenceResponse(
                    record_id=item.record_id,
                    title=item.title,
                    source_id=item.source_id,
                    source_version_id=item.source_version_id,
                    source_version=item.source_version,
                    extraction_id=item.extraction_id,
                    content_sha256=item.content_sha256,
                    extractor_name=item.extractor_name,
                    extractor_version=item.extractor_version,
                    source_location=item.source_location,
                )
        raise HTTPException(status_code=404, detail="Source reference not found")

    return app
