# BRI Project Context

## Identity and status

- Product: BRI — Organisational Intelligence Infrastructure.
- Owner: Black Raven Studios (BRS), subject to applicable rights and contracts.
- Product direction: organisation-independent intelligence infrastructure, not a single-organisation case application.
- Workspace: this new project directory, separate from the previous `agent-pilot/BRI/` workspace.
- Stage: Assignment 01 local synthetic foundation implementation.
- Implementation: explicitly authorised by the current assignment within this workspace using synthetic data; production systems, real customer data, external providers and external infrastructure remain out of scope.
- Data: synthetic examples only.

## Product definition

BRI connects to existing business systems, transforms organisational information into governed knowledge, supports distinct but connected knowledge and decision intelligence capabilities, and exposes validated intelligence to people, applications and AI agents. The BRI UI is one consumer; APIs and integrations are first-class product surfaces.

## User-provided product baseline

The initiating brief establishes the direction for this assignment: industry independence; configurable structures and access; inbound APIs, CSV, Excel, PDF and future connectors; classification, validation, versioning, provenance and lifecycle; knowledge and decision intelligence as separate but connected; configurable analytics/reporting; secure outbound APIs/integrations; multiple AI providers; SaaS/private on one platform; organisation-specific policies.

Treat this as the working product baseline, not an assertion of legal ownership, regulatory compliance, or approval by an unmentioned authority. Do not silently add, remove or narrow requirements.

## Non-negotiable boundaries

- Work only in this workspace for new project documentation and any later explicitly authorised work.
- Do not inspect, copy, import or reuse previous BRI source, municipal implementations, municipal systems, credentials, case data, confidential documentation or historical reports/materials unless a specific item is separately cleared for this assignment and its provenance/rights are reviewed.
- Human validation is required before interaction-derived material becomes organisational knowledge.
- Preserve source/provenance and enforce access before retrieval, model context, export and agent/API response.
- No implementation begins before explicit authorisation.
- Legal ownership, licensing, confidentiality and permitted clean-room process remain subject to specialist legal review.

## Architecture position

Proposed, not approved: API-first modular platform with distinct platform foundation, integration, knowledge, intelligence, analytics/reporting and experience capabilities. Keep Knowledge Intelligence and Decision Intelligence as separate bounded capabilities linked by provenance/evidence. Prefer a modular monolith and asynchronous processing boundaries until scale or isolation evidence justifies services. Technology selections remain open in `architecture/architecture-decisions.md`.

## Status legend

- User-provided baseline: direction explicitly in the initiating brief.
- Proposed: recommendation awaiting designated approval.
- Approved: only when approval is explicitly recorded.
- Assumption: temporary and must be validated.
- Unresolved: no implementation choice may be inferred.

## Navigation

- `README.md` — document map and statuses.
- `product/` — product definition and requirements.
- `architecture/` — system/domain/data/security/integration/knowledge/intelligence/analytics/deployment designs and decision register.
- `governance/` — independent-development boundary and ownership dependencies.
- `planning/` — roadmap, MVP plan, risks, tests and progress.
