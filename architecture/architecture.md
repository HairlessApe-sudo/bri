# BRI System Architecture

Status: Proposed logical baseline; local-MVP choices explicitly approved in the ADR register, production technology and deployment remain open

## 1. Context and guiding boundary

BRI is an organisation-independent intelligence infrastructure platform. The platform—not a single web application—is the product boundary. People, BRI UI, external applications, reporting tools and AI agents consume governed capabilities through APIs. BRI connects to customer-controlled sources only through explicit, scoped and audited integration arrangements.

The core architecture must support multiple sectors, configurable organisational structures, inbound information, governed knowledge, decision intelligence, analytics, outbound APIs, model choice and SaaS/private operation. Sector-specific schemas and workflows belong in configuration or extension modules, not hardcoded core assumptions.

## 2. Proposed logical layers

1. Experience and consumer layer: BRI web UI, public/customer APIs, admin experience, external application and agent clients.
2. API and access edge: authentication integration, request validation, tenant context resolution, rate limits/quotas, policy decision call, API versioning and audit correlation.
3. Platform foundation: tenant/organisation registry, identity/membership references, configurable organisational graph, RBAC/ABAC policy evaluation, configuration, audit, retention/deletion orchestration and service identities.
4. Integration layer: inbound API/file adapters, connector registry, credential references, import jobs, webhooks/events, outbound APIs and export adapters.
5. Knowledge infrastructure: source registry, immutable source versions, extraction/classification proposals, review workflow, validated knowledge records, provenance, lifecycle and permission-aware retrieval.
6. Intelligence engines: Knowledge Intelligence and Decision Intelligence as separate bounded capabilities; question orchestration, evidence assembly, AI gateway and response validation.
7. Analytics/reporting: governed metric definitions, deterministic calculations, report specifications, dashboards and export/read APIs.
8. Data and processing: relational system of record, object storage, search/indexes, asynchronous task execution, cache and observability. Derived indexes are rebuildable, not authority.

## 3. Module boundaries

Proposed bounded contexts: Organisation & Identity Context, Access Policy Context, Integration Context, Information/Source Context, Knowledge Context, Decision Context, Intelligence Context, Analytics Context, Governance Context, and Experience/API Context. Each owns its domain rules and public interface. A module must not write another module’s tables directly without an approved ownership contract. Shared identifiers and event contracts are versioned.

Knowledge Intelligence answers “what is known and supported by accessible sources?” Decision Intelligence answers “what decisions were recorded, what evidence/reasoning/outcomes exist, and what patterns can be responsibly analysed?” They share evidence/provenance contracts but retain separate domain semantics.

## 4. Initial deployment shape

Recommendation for evaluation: modular monolith with clear in-process module interfaces and separate worker processes for long-running ingestion/indexing. This avoids premature distributed systems while preserving later extraction boundaries. A service split is justified only by measured scaling, isolation, independent release or customer deployment requirements. This remains proposed.

Technology baseline for implementation is tracked in the decision register. PostgreSQL is approved by the user for the shared-tenant local MVP (AD-01/02); object storage and vector technology remain candidates, not approved infrastructure.

## 5. Primary data flows

### Inbound information

Customer source or authorised user → authenticated connector/API → tenant/policy resolution → quarantine and validation → source/version registration → isolated extraction → deterministic/AI-assisted classification proposal → policy-driven review → approved knowledge/decision record → indexes updated → audit and status returned.

### Query/intelligence

User/application/agent → authenticate client and resolve tenant context → authorize requested capabilities and scope → parse/clarify request → retrieve permission-filtered sources/records → revalidate permissions and versions → assess sufficiency/conflicts → deterministic calculations and/or model analysis → validate claims/citations/output → respond with evidence/limitations → audit minimised metadata.

### Outbound information

Authorised consumer → scope and purpose check → stable versioned API/report contract → filter/redact according to policy → return permitted validated records/intelligence → audit delivery. External destinations and events are explicitly configured; no implicit data export.

## 6. Cross-cutting invariants

- No tenant/resource data enters search results, caches, AI context, exports, or agents before a trusted authorization decision.
- Original information, extracted information, interpretations, validated knowledge and derived intelligence remain distinguishable.
- Important outputs include provenance and source version/location.
- Imported/user/external content is untrusted and cannot change platform policy or tool authorization.
- Secrets are referenced from an approved deployment secret facility, never embedded in prompts, logs or ordinary tenant records.
- Deletion/restriction follows dependencies through object storage, extracted text, indexes, caches, reports and backups subject to approved legal hold.
- SaaS and private use the same core product contracts and release artefacts; deployment-specific controls are explicit.

## 7. Architecture decision dependencies

Tenancy and policy semantics precede data/API design. Organisation graph semantics precede membership and scope schema. Provenance/version/time semantics precede knowledge, decision, citations and deletion. Connector identity and canonical ingestion contracts precede individual connectors. Model capability/data policy precedes provider routing and embeddings. Deployment/operations decisions precede packaging, recovery and service boundaries. See `architecture-decisions.md`.

## 8. Quality attributes and open status

Tenant isolation, source traceability, extensibility, security/privacy, provider portability, deployment portability and recoverability are product direction. Numeric performance/availability, scale, connector throughput, API compatibility policy, SLOs, RTO/RPO and support model remain unresolved. Define measurement and acceptance before commitments.
