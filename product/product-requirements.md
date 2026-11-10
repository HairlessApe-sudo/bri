# Product Requirements — BRI

Status: Initial requirements derived from the user-provided product direction; detailed acceptance and priority are proposed, not approved.

## Requirement status

The high-level product identity and capability direction in this document comes from the initiating brief. IDs below organise that direction; they do not imply that detailed workflow or acceptance thresholds have been formally approved. “MVP” means a proposed first demonstrator, pending product-owner approval.

## 1. Product and organisation

- PRD-ORG-01: Support multiple independent organisations/tenants.
- PRD-ORG-02: Allow each organisation to configure its own units, departments, teams, groups and projects without a fixed industry hierarchy.
- PRD-ORG-03: Represent cross-organisational relationships separately from within-organisation hierarchy.
- PRD-ORG-04: Support users and service identities with scoped access to one or more organisational contexts; exact membership and delegation semantics require approval.
- PRD-ORG-05: Provide organisation-specific policies and configuration without changing core product code.

## 2. Identity, access and governance

- PRD-SEC-01: Enforce tenant and resource authorization server-side across UI, APIs, integrations, jobs, storage, search, analytics and AI context.
- PRD-SEC-02: Support role-based action permissions and attribute/resource-based scope decisions.
- PRD-SEC-03: Default to deny when identity, tenant context or policy evaluation is missing or ambiguous.
- PRD-SEC-04: Audit security-relevant access, configuration, validation, integration and intelligence actions while minimising sensitive content.
- PRD-SEC-05: Configure data retention and deletion by policy; propagate lifecycle to derived data.

## 3. Integration and ingestion

- PRD-INT-01: Ingest information through authenticated APIs and file workflows including CSV, Excel and PDF.
- PRD-INT-02: Support future connectors without requiring core domain rewrites for each connector.
- PRD-INT-03: Register source identity, import time, version/hash where applicable, owner/scope, processing status and errors.
- PRD-INT-04: Validate, classify and route information for review before publication according to organisation policy.
- PRD-INT-05: Preserve original source material separately from extracted or interpreted content.
- PRD-INT-06: Provide controlled outbound APIs and an extensible integration contract for future consumers including analytics and enterprise platforms.

## 4. Knowledge and decisions

- PRD-KNW-01: Maintain governed organisational knowledge with provenance, validation status, version and lifecycle.
- PRD-KNW-02: Distinguish source facts, extracted text, proposed interpretations, validated knowledge and derived intelligence.
- PRD-KNW-03: Search and retrieve only information the requesting identity may access.
- PRD-DEC-01: Model historical decisions separately from general knowledge, with evidence and recorded reasoning where available.
- PRD-DEC-02: Distinguish documented, partial, inferred and unknown decision reasoning; never present missing history as fact.
- PRD-DEC-03: Connect decisions to knowledge/evidence, actions and outcomes with temporal and provenance context.
- PRD-DEC-04: Require human validation before interaction-derived content is published as shared organisational knowledge.

## 5. Intelligence, analytics and experience

- PRD-AI-01: Support natural-language access to knowledge and decision intelligence.
- PRD-AI-02: Return traceable sources and communicate limitations, uncertainty, conflicts and evidence gaps.
- PRD-AI-03: Support multiple providers/models through a provider-independent capability layer, subject to organisation and deployment policy.
- PRD-AN-01: Provide configurable dashboards, analytics and reports for authorised scopes.
- PRD-AN-02: Calculate numerical metrics deterministically where practical and disclose report scope, data and method.
- PRD-EXP-01: Provide a BRI interface while exposing equivalent governed capabilities to applications and AI agents through documented APIs.

## 6. Deployment

- PRD-DEP-01: Support SaaS and private deployment from the same underlying platform codebase.
- PRD-DEP-02: Permit deployment-specific configuration and integrations without a product fork, subject to a supported deployment matrix.
- PRD-DEP-03: Do not assume cloud provider, region, network access, orchestration or identity provider before approval.

## 7. Non-functional requirements (direction; thresholds open)

Security/privacy by design; strong tenant and organisational isolation; provenance; extensibility; API compatibility/versioning; reliability and recovery; accessible user experience; observable processing; safe upgrades; configurable retention/deletion; synthetic-data testing; and provider/deployment portability. Quantitative SLOs, throughput, latency, RTO/RPO and support targets require workload and owner approval.

## 8. Proposed MVP acceptance scenarios

These are recommendations for approval, not new binding requirements:
1. Two synthetic tenants define different organisational structures and cannot access each other’s information through any tested interface.
2. One synthetic inbound API flow and file import flow accept CSV, Excel and text-based PDF within explicitly stated format limits, register provenance and processing state, and safely reject unsupported or malformed input. OCR is excluded unless separately approved and tested.
3. An authorised reviewer can inspect proposed classification/knowledge and approve or reject it; unapproved content is not generally searchable.
4. A generic decision record can link to source evidence and retain “unknown/not recorded” where reasoning is absent.
5. Knowledge and decision query endpoints return only permitted evidence, source/version references, limitations and an abstention when evidence is insufficient.
6. A deterministic sample report is reproducible from a disclosed scope and input set.
7. A versioned outbound API exposes a narrow approved result to a synthetic consumer; no Power BI, SharePoint or Cognos production integration is implied.
8. Cross-tenant, cross-unit, revoked-access, prompt-injection and deletion tests meet approved pass/fail thresholds.
9. The same release artefact is demonstrated in a SaaS-like and private-like test configuration without real customer data.

## 9. Explicit exclusions for the proposed MVP

No live customer/municipal data, production integrations, unrestricted web crawling, autonomous decisions, broad catalog of enterprise connectors, arbitrary customer-authored executable policies, OCR claims without validation, or full multi-region HA commitment. Product owner approval is required for the final MVP scope.
