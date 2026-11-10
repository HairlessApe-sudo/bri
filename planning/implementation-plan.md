# Proposed Implementation Plan — BRI MVP

Status: Proposed implementation plan. Assignment 01 authorizes local synthetic implementation within this workspace; security-critical unresolved decisions remain approval gates.

## 1. Proposed MVP objective

Demonstrate BRI as reusable organisation-independent infrastructure through one synthetic municipal Knowledge Intelligence use case: configurable municipal structure; governed policy-document ingestion; human validation; permission-aware natural-language Q&A with source references and abstention; and access through both a versioned API and BRI UI. A second synthetic tenant verifies isolation. Decision Intelligence is architecturally accommodated but is not an implementation objective for this first slice.

## 2. Proposed scope

- Tenant and configurable municipal organisational structure sufficient for synthetic scenarios; no hardcoded municipal types in platform logic.
- Human and machine identity integration chosen by approved ADR; least-privilege RBAC and explicit resource/node scopes.
- Versioned source registry and authenticated file upload for CSV/XLSX/text-PDF limits; a generic inbound API contract may follow as a separate slice.
- Quarantine, validation, extraction status, provenance, review and publish/reject workflow.
- Validated knowledge record with exact source/version/location evidence links.
- Permission-filtered knowledge search and one evidence-grounded question flow with source references, insufficiency handling and deterministic mock/provider adapter.
- Versioned, documented API for the approved Knowledge Intelligence capability, sharing policy enforcement with the BRI UI.
- Basic administration and review UI; clearly label any feature not yet implemented.
- Audit metadata, retention/deletion demonstration, integration mocks and operator visibility.
- Synthetic fixtures, threat-driven tests, API docs and deployment runbook.

## 3. Explicit exclusions

No live customer or municipal data, production account/API, external model without explicit data/provider approval, connector to Power BI/SharePoint/Cognos, broad connector marketplace, Decision Intelligence implementation beyond future-compatible domain contracts, autonomous decision/action, unbounded agent tools, OCR, full enterprise HA/multi-region commitment, or migration of prior implementation. Reconsider only through approved scope change.

## 4. Sequenced work packages

0. Authorization and design closure: identify owners; approve PRD acceptance; close high-risk ADRs; threat model, legal/license and data-flow review.
1. Contracts and domain: tenant/org/principal/resource identifiers; authorization interfaces; version/provenance/time semantics; API schema and error conventions.
2. Platform foundation: identity boundary, tenant context, policy evaluation, audit, configuration and test harness; prove cross-tenant denial before adding content features.
3. Ingestion/knowledge: API/file adapters, quarantine, safe parser constraints, async idempotency, source versions, review, lifecycle and deletion.
4. Decision model/intelligence: decision/evidence structures, permission-filtered retrieval, evidence/response validation, abstention, model adapter behind policy.
5. Analytics/consumers: deterministic report contract, outbound API, minimal UI and synthetic consumer/agent.
6. Deployment/operations: selected SaaS-like/private profiles, secret references, backups/restore, observability, upgrade/deletion runbooks.
7. Verification: security, privacy, reliability, usability, performance and acceptance tests; release review.

Work package ordering may change only through explicit ADR/plan update; access isolation and data provenance are foundational gates.

## 5. Acceptance evidence

For each requirement/scenario, capture test ID, synthetic fixture, exact build/config, expected result, actual result and reviewer. Minimum evidence: tenant and org negative tests across API/search/index/cache/worker/report; source-version citation checks; human validation gate; decision unknown-state behavior; prompt injection/tool authorization tests; deletion propagation; deterministic report repeatability; API contract tests; package parity for selected deployment modes; restore drill. Numeric thresholds require owner approval before coding.

## 6. Sequencing dependencies

Do not finalize physical schema before AD-02/05/06/07. Do not implement ingestion before AD-09 and format/security limits. Do not route real data to models before AD-11/16 and legal review. Do not commit deployment topology before AD-12. Do not claim deletion compliance before AD-13 and backup/derivative semantics are approved. Track all as blockers in progress and risks.

## 7. Resource/capacity uncertainty

Team size, budget, vendor availability, schedule, customer workload, operational ownership and commercial target are not supplied; no delivery dates or cost estimate are asserted. Estimate only after approved architecture and a representative synthetic workload/spike.
