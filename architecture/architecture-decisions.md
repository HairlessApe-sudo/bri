# Architecture Decision Register

Status: Register of proposed/relevant decisions; nothing here is approved unless explicitly marked and signed below.

## Status rules

User-provided baseline = direction in the initiating brief. Proposed = recommendation for review. Assumption = temporary design premise. Unresolved = options remain. Approved = explicitly accepted by a named accountable approver, with date and rationale. No decision below is marked Approved.

## Decision records

### AD-01 — System-of-record and persistence architecture
- Status: Partially approved for local MVP on 2026-11-10: PostgreSQL as the shared relational database, consistent with the explicitly approved AD-02 topology. Other persistence decisions remain unresolved.
- Problem/options: relational transactional store; document database; hybrid; event-sourced system. Relational provides constraints and reporting, document store flexible structures, event sourcing auditability but significant complexity.
- Recommendation: PostgreSQL relational system of record for local MVP; immutable source/knowledge revisions where required; object storage for original files (provider still open); rebuildable search/analytics projections. Do not adopt event sourcing as a platform-wide pattern without a demonstrated need.
- Consequences: explicit schema evolution and tenant constraints; avoid unrestricted JSON as core model.
- Still unresolved: exact schema/version semantics, local file storage adapter, production object store, migrations/rollback, backups, encryption/key ownership and analytic projections. Dependencies: temporal model, deployment, workload and legal retention.

### AD-02 — Tenant isolation topology
- Status: Approved for the local MVP by explicit product-owner instruction on 2026-11-10; production deployment topology remains unresolved.
- Options: shared database with tenant keys/RLS; schema-per-tenant; database-per-tenant; hybrid tiering.
- Decision: shared PostgreSQL database for the local MVP; every tenant-owned record carries tenant_id; composite tenant-scoped foreign keys prevent cross-tenant references; forced row-level security (including table-owner cases) plus service-layer authorization. The application role must not own tables or have BYPASSRLS. This does not approve the SaaS production topology.
- Consequences: every query/task must establish tenant context transaction-locally; test direct SQL, jobs, search and all API paths. Maintain isolation tests and plan a dedicated-tenant option only if requirements justify it.
- Dependencies: SaaS/private offers, customer risk/contract, operator model, scale. RLS alone is insufficient.

### AD-03 — API/service structure
- Status: Proposed: API-first modular monolith plus asynchronous workers initially.
- Alternatives: microservices from inception; full-stack single deployable; distributed domain services.
- Rationale: infrastructure-first domains need boundaries, not premature network complexity. Extract services only with measured isolation/scale/release need.
- Dependencies: team/operations, private packaging, workload.

### AD-04 — Experience and backend technology
- Status: Proposed initial stack; not formally approved. Implementation may use it provisionally for reversible scaffolding; dependency pins and production use require review.
- Recommendation: Next.js 16 App Router + TypeScript for the BRI consumer UI; FastAPI/Python for a separately versioned API and ingestion/AI domain modules; SQLAlchemy 2.x and Alembic for persistence and migrations; PostgreSQL 18.6 as relational system of record; PostgreSQL full-text search initially, with pgvector 0.8.7 as an optional PostgreSQL extension after benchmark. Keep original files behind a storage interface (local filesystem for development; S3-compatible adapter later). Use a separate worker process consuming durable PostgreSQL-backed jobs/outbox initially rather than adding Redis/Celery before measured need. Version check on 2026-11-10: Next.js 16 is Active LTS; FastAPI official release notes list 0.162.0; PostgreSQL 18.6 is the current 18 minor; pgvector 0.8.7 publishes PostgreSQL 18-compatible images.
- Alternatives: (1) TypeScript end-to-end (Next.js + Node API/workers) minimizes language/runtime count but is less aligned with document extraction and Python AI tooling; (2) Django + Django REST Framework provides integrated admin/auth/data conventions but couples the API and UI choices more tightly and requires validating the desired API/worker boundaries; (3) selected two-runtime approach gives a strong UI ecosystem and Python document/AI ecosystem with a cost of maintaining two toolchains and contracts.
- Consequences: OpenAPI is the backend contract; UI and external clients are consumers, not sources of authorization. Pin supported runtime/dependency versions and license inventory. Keep modules in one backend codebase; no microservices. Use Python 3.14 only after all chosen wheels/tests pass; otherwise pin an explicitly supported Python minor. PostgreSQL 18.6 is the current stable branch evidenced for this recommendation; do not use PostgreSQL 19 RC in the MVP. Versions are proposed, not permanent commitments.
- Environment evidence: local WSL has Node 26.12.1 and Python 3.14.9; Docker CLI is installed but Docker Desktop WSL integration is unavailable; no PostgreSQL client/server or `uv` is present. Parser packages are isolated in `.venv`; the test suite is run through that environment.
- Dependencies: AD-02/05/06/07/16 before schema, identity, authorization or model data flow; AD-10 before semantic index; local container/database setup before persistence integration. Prior technology recommendations are not automatically adopted.

### AD-05 — Organisational hierarchy and relationship semantics
- Status: Partially decided: no automatic parent-to-child permission inheritance was explicitly approved for the MVP on 2026-11-10. The hierarchy representation itself remains proposed.
- Alternatives: strict tree, forest, DAG/multiple parents, arbitrary graph.
- Dependencies: access inheritance, membership, analytics, cross-organisation sharing, temporal changes. Decide cycle, reparent, shared-node and inheritance semantics before schema.

### AD-06 — Authorization model
- Status: Approved for the first slice by explicit product-owner instruction on 2026-11-10: RBAC actions plus explicit resource/organisational-node scopes, default deny, no automatic parent-to-child permission inheritance.
- Alternatives: RBAC only; policy engine; ACL-centric; hybrid.
- Remaining unresolved: exact role/permission catalogue, explicit-deny precedence, delegated administration, cross-tenant sharing, policy editing/versioning, identity proofing, service identity scopes and failure behavior. Recommendation: implement a small pure policy contract first, then enforce it in API and PostgreSQL; RLS is defense in depth.
- Dependencies: identity, hierarchy, tenant topology, delegated admin, cache/index enforcement, agents.

### AD-07 — Provenance, versions and time
- Status: Proposed: immutable source versions, versioned knowledge/decision revisions, explicit provenance; separate effective and recorded times.
- Unresolved: full bitemporal semantics, correction/deletion behavior, historical “known as-of” requirements.
- Dependencies: citation, decision history, audit, analytics reproducibility, retention.

### AD-08 — Knowledge ontology/configurability
- Status: Proposed: stable core types plus governed customer-configurable taxonomies/metadata.
- Alternatives: fixed universal ontology; arbitrary schema extensions; graph-first knowledge model.
- Dependencies: API compatibility, validation, migrations, search and cross-sector interoperability.

### AD-09 — Ingestion and connector execution
- Status: Proposed: canonical connector contracts, quarantine, async idempotent jobs; connector code isolated from core domain.
- Unresolved: push/pull mix, plugin execution, event protocol, malware/OCR services and connector packaging.
- Dependencies: identity/secrets, network/egress, job system, data classification, source deletion signals.

### AD-10 — Search and vector retrieval
- Status: Unresolved.
- Options: relational full-text/vector extension; separate search service; hybrid.
- Recommendation: benchmark an integrated candidate first for synthetic representative workloads; require permission filters, versioning, deletion and rebuild tests. No vector similarity is an authorization control.
- Dependencies: data volume, languages, latency, tenancy, embedding model/provider, operations.

### AD-11 — AI provider abstraction and routing
- Status: User-provided baseline: provider-independent architecture. Implementation details unresolved.
- Options: common capability interface plus adapters; orchestration framework; direct per-provider calls.
- Recommendation: own minimal capability contracts and compliance metadata; avoid leaking provider-specific types into domain APIs; permit policy-controlled adapters and explicit fallback.
- Dependencies: data-classification policy, private/local deployment, tools, evals, provider contracts and cost.

### AD-12 — SaaS/private deployment model
- Status: User-provided baseline; topology/package unresolved.
- Options: shared SaaS, dedicated tenant, customer-operated private, managed private; combinations.
- Recommendation: common core artefact/contracts and one initially supported profile per selected mode; do not promise air-gap/HA until tested.
- Dependencies: tenant isolation, identity, key ownership, updates, support, region and RTO/RPO.

### AD-13 — Audit, retention and deletion
- Status: User-provided baseline; semantics unresolved.
- Options: event log, audit table, append-only external store, combinations.
- Recommendation: tamper-resistant access-controlled audit metadata with minimised content; lifecycle dependency graph and verifiable deletion workflow.
- Dependencies: legal review, backup expiry, legal hold, source ownership, derived indexes, conversation retention.

### AD-14 — Reporting and analytics execution
- Status: Proposed: versioned report specifications and deterministic calculations; optional constrained narrative.
- Options: compute-on-read; materialized read models; customer BI direct database access.
- Recommendation: begin compute-on-read for bounded use; evaluate controlled API/export before materialization. No direct internal DB access for external tools.
- Dependencies: metric ownership, privacy thresholds, workload, reproducibility, API contracts.

### AD-15 — Identity federation and service identities
- Status: Local-development decision approved on 2026-11-10: use a development-only synthetic identity adapter, hard-disabled outside explicitly enabled local development. This is not a production login or identity-provider decision.
- Options: OIDC, SAML, both; tenant-managed identity vs local accounts; machine client credentials/mTLS.
- Production identity remains unresolved. Dependencies: customer sectors, private/offline environment, MFA, user lifecycle, delegated administration and agent scopes.

### AD-16 — Data classification and external-model policy
- Status: Unresolved; foundational risk gate.
- Options: per-tenant policy matrix, deployment-only allowlist, source-classified controls; hosted/local provider tiers.
- Recommendation: classify before provider routing; default restrict and minimize; require explicit policy/contract approval for external processing.
- Dependencies: legal/privacy review, residency, provider retention/training, encryption/key custody.

### AD-17 — Temporal decision model
- Status: Proposed minimum: decision, evidence, recorded reasoning status, actor/time, action/outcome links; advanced causal analysis deferred.
- Unresolved: decision lifecycle, alternatives, dissent, legal record requirements and outcome attribution.
- Dependencies: customer discovery, domain governance and reporting semantics.

## Decision dependencies (partial order)

1. AD-02, AD-05, AD-06, AD-07 and AD-16 establish isolation, authorization, scope and data trust.
2. AD-01 and AD-08 depend on identifiers, tenant, temporal and domain boundaries from step 1.
3. AD-09 depends on AD-01/02/06/07/16 and integration security/secret capabilities.
4. AD-10 depends on knowledge versioning, policy filters, retention and workload evidence.
5. AD-11 depends on data classification, deployment modes, capability use cases and evaluation criteria.
6. AD-12 depends on isolation, identity, keys, update/support and recovery decisions.
7. AD-13 depends on legal/retention review and the derived-data dependency graph (AD-07/09/10/11/14).
8. AD-14 depends on metric definitions, access controls, reproducibility and deletion semantics.

## Approval log

No architecture decisions approved in this foundation assignment. Record: ID, decision, alternatives considered, approver, date, rationale, consequences, review trigger and linked requirements before changing a status to Approved.

## Assessment of prior reports (reference-only synthesis)

The previous five assessment reports were considered as lessons, not copied as the new baseline. Given the new infrastructure-first direction:

- Retain as principles: tenant/resource isolation from inception; explicit authorization rather than UI-only filtering; source traceability; conservative handling of sensitive information; provider abstraction; staged delivery, testing and risk review.
- Redesign: the earlier application-oriented architecture framing into independently consumable platform capabilities and versioned APIs; simple department/team assumptions into configurable organisational graphs with explicit inheritance rules; document/AI flows into a governed source-to-validated-knowledge lifecycle; decision support into a distinct Decision Intelligence domain; deployment options into one core foundation with explicit SaaS/private profiles.
- Do not carry forward as approved: any prior framework, database, hosting, model, vector-store or integration recommendation. Re-evaluate via AD-01–AD-16 against the new product needs and permitted deployment profiles.
- Correct known risk patterns: service-role or broad backend access must not bypass tenant/resource authorization; authenticated-only access is not sufficient scope control; sensitive content must not be emitted into logs or sent to external models without explicit data policy and approval; application filtering is not a database/security boundary.
- Newly introduce: API/agent consumers as first-class clients; tenant-specific policy/configuration; explicit provider/data-class routing; auditable human validation of interaction-derived knowledge; reproducible reporting; derived-data deletion propagation; connector contracts and private deployment parity.

These are design lessons from the permitted assessment material and task context; they do not establish that any prior implementation defect exists in this new project. No prior application source or municipal artefact is part of this baseline.
