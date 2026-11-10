# BRI Integration Architecture

Status: Proposed integration contracts and controls; protocols and connectors remain unapproved

## 1. Purpose and boundaries

Integrations make BRI an infrastructure platform rather than a document silo. Every integration is a bounded adapter around canonical BRI contracts; connector-specific fields and behavior must not become hidden core assumptions. Inbound and outbound paths are both first-class and tenant/purpose/policy scoped.

## 2. Integration categories

Inbound:
- Versioned BRI API for authorised source/application submissions.
- File import for CSV, Excel and PDF in the initial capability direction.
- Future customer-system connectors (e.g. document, collaboration, CRM/ERP, education, healthcare or public-sector systems) only after separately approved scope and legal/security review.

Outbound:
- Versioned read APIs for validated knowledge, decision records and approved intelligence/report results.
- Controlled export and report delivery.
- Future event/webhook and platform-specific adapters such as Power BI, SharePoint and Cognos.
- Scoped machine/agent APIs; never give a model direct database or unrestricted connector access.

## 3. Canonical inbound contract

Recommended envelope: tenant context derived from authenticated integration identity; source-system and source-object identifiers; source version/ETag/hash where available; event/import time; schema/media type; payload reference; requested data classification/scope; idempotency key; correlation ID. Validate caller scopes and schema before quarantine/processing. Reject tenant context that conflicts with the authenticated connection. Record source deletion/update events where the source supports them.

Acceptance of payload is not publication: imported data moves through registration, quarantine, validation, extraction, classification, review and policy-controlled publication. Return job ID/status for asynchronous processing and stable error codes without sensitive payloads.

## 4. Connector contract and lifecycle

A connector adapter should declare: supported source/destination, authentication method, credential scope, capabilities, version, rate/size limits, pagination/cursor behavior, change detection, retry/backoff, idempotency, error taxonomy, deletion/revocation semantics, data residency, test fixture and audit events. Connector manifests must be versioned and reviewed. Connector credentials are stored in an approved secret facility; records carry references only.

MVP recommendation: implement one generic authenticated inbound API contract and file import; use mock/synthetic connectors for conformance. Do not implement live SharePoint/Power BI/Cognos or customer-system access in this foundation assignment.

## 5. Outbound API and event design

Provide stable, versioned APIs with documented schemas, pagination, filtering, authorization, quotas and deprecation policy. APIs return only validated, scope-permitted entities with provenance and lifecycle state. Distinguish source records from derived knowledge and generated intelligence in resource types and response schemas.

For push delivery, compare transactional outbox + webhook/event delivery with direct synchronous callbacks. Recommendation: if/when outbound events are approved, use durable outbox, signed webhooks, retries, idempotent consumer semantics and replay controls. Do not promise exactly-once delivery; define at-least-once behavior and deduplication.

## 6. Security and reliability

- Per-integration machine identities, least-privilege scopes, expiry, revocation and rotation.
- Validate TLS/hostnames and destination allowlists; block loopback/private/link-local/metadata targets and validate redirects/DNS resolution to mitigate SSRF.
- Authenticate webhooks and prevent replay; never trust inbound tenant IDs alone.
- Apply per-tenant quotas, size limits, rate limits and backpressure.
- Use durable jobs, bounded retries, idempotency keys, dead-letter/failed-job review and safe replay.
- Redact secrets and customer content from logs and errors.
- Ensure access changes and source deletion propagate to all derived records and exports according to policy.

## 7. Options and open decisions

- Push versus pull: push gives freshness but requires webhook/network exposure; pull offers controlled egress but needs polling/cursor semantics. Support both through connector contracts only if customer needs justify both.
- Synchronous versus asynchronous: synchronous suits small validated API operations; asynchronous is recommended for bulk imports, extraction and indexing.
- REST/OpenAPI versus event-first contracts: recommend versioned REST for request/response and ingestion acknowledgments; use events/outbox for asynchronous state changes if consumers require them. Protocol is an ADR.
- API keys versus OAuth client credentials/mTLS: select per deployment and client capabilities; no credential style is approved.
- Connector marketplace/plugin execution model is unresolved; do not load arbitrary third-party code in-process.

## 8. Dependencies

Depends on tenant/auth policy, canonical domain identifiers, data classification/retention, source/version model, job/idempotency model, outbound API ownership, secret management, egress controls and deployment capabilities. No external account or production service is assumed configured.
