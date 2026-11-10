# BRI Logical Data Model

Status: Conceptual design for discussion; not a physical schema, migration plan or approved database choice

## 1. Storage roles

Proposed: PostgreSQL as the local-MVP transactional system of record (explicitly approved for shared tenant isolation in AD-01/02); local filesystem may be used only for development artifacts until an object-storage adapter is selected; separate/rebuildable full-text, vector and analytical indexes; durable task state for ingestion; minimised audit/event records. S3-compatible storage and pgvector remain proposed options, not approved production infrastructure. See `architecture-decisions.md` AD-01/02/03.

## 2. Entity groups

### Tenant and access
- `tenants` / `organisations`: customer boundary, status, configuration reference.
- `principals`: platform identity reference for human, service, application or agent.
- `memberships`: principal-to-tenant relationship and validity.
- `org_nodes`, `org_edges`, `org_memberships`: configurable hierarchy and memberships.
- `roles`, `permissions`, `role_assignments`, `policies`, `resource_grants`: action rights and resource constraints.
- `integration_clients`: machine identities, scopes, credential references and status.

### Integration and source information
- `source_systems`, `connector_instances`, `source_objects`, `source_versions`.
- `ingestion_jobs`, `processing_tasks`, `import_events`, `idempotency_keys`.
- `artifacts`: object keys, hashes, media metadata, tenant and access scope.
- `extractions`: extractor/version, status, extracted artefact reference, source locations, error codes.
- `classification_proposals`, `sensitivity_assessments`, `review_tasks`, `review_decisions`.

### Knowledge
- `knowledge_collections`: scope, owner, policy reference and lifecycle.
- `knowledge_records`: type, content/structured data, validation state, temporal fields and version.
- `knowledge_sources`: many-to-many provenance to exact source/record versions and locations.
- `knowledge_relationships`: typed edges with evidence, confidence/support and validation state.
- `index_generations`: source/model/embedding version and processing status for rebuildable indexes.

### Decision and intelligence
- `decisions`, `decision_evidence`, `decision_actions`, `decision_outcomes`.
- `intelligence_runs`: tenant, principal, request scope, request/config versions, status and timestamps.
- `evidence_references`: source type/id/version/location and access-validated reference used in a result.
- `responses` / `reports`: content reference, structured result, limitations and report spec version.
- Optional `conversations`, `messages`, and `feedback` only after retention and content-storage approval; never auto-promote messages to shared knowledge.

### Governance and analytics
- `audit_events`, `retention_policies`, `deletion_requests`, `legal_holds` (subject to legal review).
- `metric_definitions`, `report_definitions`, `report_runs`, `export_jobs`.

Names are illustrative and may change after domain review.

## 3. Integrity and tenant invariants

- Every tenant-owned row must have an explicit tenant key or a provably tenant-preserving parent path; composite foreign keys should prevent cross-tenant references.
- Hierarchy parent/child must share tenant; cycle prevention and transactional reparenting need an approved algorithm.
- Cross-tenant references are prohibited unless a specifically approved cross-organisation relationship model authorizes them; a relationship edge is not automatically an access grant.
- Unique constraints include tenant scope where identifiers may repeat across organisations.
- Every external/source reference has a stable source identity and imported-at timestamp; version/hash where available.
- Audit and derived records carry tenant and correlation context; avoid embedding sensitive content in metadata.
- All event and timestamp semantics (occurred/effective/recorded/validated) are explicit and timezone-aware.

## 4. Temporal and version model

Recommendation for design: immutable source version rows; knowledge/decision revisions rather than destructive overwrite; supersession pointers; distinct valid/effective time and system-recorded/validation time. The full bitemporal query contract is unresolved. Define treatment of corrected imports, source deletion, retroactive policy changes and “what was known at time T” before final schema.

## 5. Search, analytics and derived storage

Search and analytical stores are projections, not authorities. Each index record must retain tenant, permission-relevant scope, source version, source location, lifecycle/index generation and embedding model/dimension identifiers. Permission changes and deletion must invalidate or revalidate derived results. Analytics snapshots must preserve metric-definition and source-data versions sufficient for the required reproducibility level.

Alternatives: keep vectors and full-text within PostgreSQL initially versus separate search service. Initial Postgres option lowers operational surface; dedicated search may scale/rank better but adds synchronization and isolation risks. Selection awaits representative volume, latency and filtering benchmarks.

## 6. Retention and deletion

Deletion workflow must identify original artifact, extracted artefact, chunks/embeddings, knowledge/decision derivatives, caches, reports/exports, logs/audit references, replicas and backups. Preserve only what an approved legal hold or retention rule permits. Deletion semantics, backup expiry, tombstones, evidence of completion and export rights are unresolved legal/product dependencies.

## 7. Physical design decisions required

Database engine and tenancy layout; row-level policy strategy; hierarchy representation; JSON extensibility limits; source/version hash strategy; encryption/key ownership; event/job persistence; vector dimensions/index strategy; analytic read model; retention/deletion implementation; migration compatibility and rollback. Do not write migrations until AD-01 through AD-07 and the relevant ownership/temporal questions have an approved status.
