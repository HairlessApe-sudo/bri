# BRI Deployment Architecture

Status: Proposed deployment principles; providers, regions and topology are unresolved

## 1. Deployment goals

Offer SaaS and private deployment using the same underlying platform and core product semantics. Deployment configuration may vary, but tenant/access contracts, APIs, lifecycle and audit semantics remain consistent. “Private” ownership, control, connectivity, support and update model must be defined with customers; do not assume offline or air-gapped capability.

## 2. Logical runtime components

- API/experience application.
- Domain modules and policy enforcement.
- Asynchronous workers for imports, extraction, indexing, reports and deletion.
- System-of-record database candidate.
- Object storage candidate.
- Search/index components.
- Queue/task persistence.
- AI provider adapter and optional local/customer endpoints.
- Identity provider integration.
- Observability and audit.

This is a logical list, not a commitment to deploy each as a separate service.

## 3. SaaS options

A. Shared application and shared database with tenant-qualified records/RLS: lower operational overhead, higher blast radius if isolation is misconfigured.
B. Shared application, database/schema per tenant: stronger compartmentalization, more provisioning/migration/operational burden.
C. Hybrid tiers: shared default plus dedicated tenant deployment/database for contractual or risk needs; most flexible, but increases support complexity.

Recommendation for evaluation: design logical tenant isolation independently of physical deployment, then cost a shared default and dedicated option. Do not approve SaaS physical isolation without threat model, operator-access model, scale and customer requirements.

## 4. Private deployment options

- Single-node container package for bounded development/reference environment: simplest, not presumed high availability.
- Orchestrated customer cluster: supports scale/HA but requires customer operations and compatibility matrix.
- Managed private/dedicated BRS deployment: operationally different from customer-controlled installation; contract and support responsibilities must be explicit.

Recommend one supported private profile for the first pilot; decide orchestration based on named customer operational capabilities, scale, network and recovery requirements. No cloud vendor is assumed.

## 5. Packaging and configuration

Candidate approach: immutable versioned container artefacts and signed manifests, with versioned migrations, compatibility rules, health/readiness checks, upgrade/rollback or forward-fix procedure, secrets references and configuration schema. Deployment settings, tenant settings, policy settings and user preferences have explicit precedence; lower-trust settings cannot weaken mandatory security. The container/orchestrator choice remains open.

## 6. Security and operations

Define tenant separation for database, object storage, index, queue, cache, logs, metrics and backups. Restrict and audit operator access; no routine content access without approved purpose and controls. Configure egress allowlists for external connectors and models. Specify encryption/key ownership, secrets rotation, region/data residency, support access, incident response, monitoring, patching, backups, restore drills, export and deletion.

## 7. Resilience and release

RTO/RPO, backup cadence/retention, availability target, maintenance policy, reference load and provider-failure treatment are unresolved. Test restore from database and object store together; test schema migration from supported prior versions; publish release notes and compatibility matrix. SaaS and private use the same core release unless an explicitly accepted ADR states otherwise.

## 8. Deployment decision dependencies

Tenancy layout depends on security and product contracts. Identity, secrets and customer-managed keys depend on deployment ownership. Queue/search selection depends on workload and operations. External AI connectivity depends on data policy and legal/provider approval. Packaging/update model depends on private customer ops. Decide these through AD-02, AD-12 and dependent ADRs; no infrastructure is provisioned by this architecture assignment.
