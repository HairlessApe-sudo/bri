# BRI Security and Privacy Model

Status: Proposed baseline controls; threat model and decisions require owner approval

## 1. Security objectives

Protect organisational information from unauthorized disclosure, modification, loss and misuse across tenants, organisational units, integrations, derived knowledge, analytics, AI providers and SaaS/private operations. An AI or connector must never increase a principal’s authority.

## 2. Trust boundaries

- Tenant/organisation boundary.
- Configurable organisational-unit boundary.
- Resource boundary: source, version, extracted content, knowledge, decision, report and derived artefact.
- Human identity versus service/application/agent identity.
- Integration and outbound destination boundary.
- BRS-operated SaaS operator boundary versus customer-controlled private environment.
- Model-provider boundary: hosted or local, BRS-managed or customer-provided.
- Untrusted input boundary: imported files, external pages, API payloads, user prompts and model output.

## 3. Identity and authentication

Use an external standards-based identity integration as a candidate, not an assumed IdP. Define OIDC/SAML support, MFA, session assurance, account lifecycle and federation in an ADR. Separate authentication identity from tenant membership and organizational membership. Machine identities require scoped credentials, rotation/revocation and independent audit; do not share human sessions or broad service keys with agents.

## 4. Authorization: RBAC plus contextual policy

Proposed model: RBAC defines allowed actions; ABAC/resource policy limits data scope using tenant, active membership, node/relationship, resource owner, classification, purpose, time-valid grants and deployment policy. Default deny. Derive tenant context from authenticated membership; reject client-supplied tenant/scope as authority.

Decision semantics still unresolved: explicit deny precedence, hierarchy inheritance, cross-node/tenant grants, multiple simultaneous memberships, delegated administration, break-glass access, temporary access, policy editing/approval, policy versioning and fail-closed behavior during policy-service errors.

Authorization must apply before data retrieval and again before response/citation/export. Enforce across APIs, database, object storage, search, cache, queues, reports, outbound connectors and AI tools. Revoke/invalidate cached/indexed access on policy changes.

## 5. Tenancy options and controls

Options: shared DB with tenant keys and RLS; schema-per-tenant; database-per-tenant; supported hybrid. No option is approved. Regardless of physical model, use tenant-qualified references, service-level scope checks, isolated storage/index/cache/task context, negative tests and audited operator access. RLS is defense in depth, not sole control. Private deployment must use the same logical policy contracts.

## 6. Information protection

- Classify data and define handling/retention before connecting real sources.
- Encrypt transport and stored data using deployment-approved mechanisms; key ownership and customer-managed keys are open.
- Store credential material in a deployment secret facility; persist references and metadata only in ordinary records.
- Minimize content in logs, traces, audit events and analytics telemetry.
- Define data residency, subprocessors, provider retention/training settings and customer export/deletion with legal review.
- Keep original, extracted, proposed, validated and derived content separately identifiable and access-controlled.

## 7. AI and agent security

- Authorize before retrieval/context construction; do not retrieve broad data and ask a model to filter it.
- Treat user, file, web and retrieved text as untrusted data; defend against prompt injection with isolation, constrained tools and evaluation, not prompt wording alone.
- Tool/API calls run under least-privilege identities and separately enforced policy; the model cannot grant itself access.
- Validate structured outputs, evidence IDs, source versions and access before returning results.
- Separate facts, calculations, interpretations, recommendations and unknowns; abstain per approved sufficiency policy.
- External models receive only data explicitly allowed by tenant/deployment/purpose policy.
- Agent-facing APIs use explicit scopes, quotas, revocation and audit; no ambient admin access.

## 8. Integration security

Use per-connector identity and least privilege; scope source and destination allowlists; validate payloads and schemas; protect secrets; enforce outbound egress allowlists and SSRF protections; authenticate webhooks; use replay protection/idempotency; redact error bodies; record sync/deletion events. Customer integration credentials must not be exposed to models, logs, other tenants or unrelated services.

## 9. Threat baseline

| Threat | Minimum proposed response |
|---|---|
| Cross-tenant/unit leak | tenant-qualified access, RLS/app checks, negative tests at every API/data path |
| Privilege escalation | server-side policy evaluation, default deny, auditable grants and revocation tests |
| Malicious file/parser | quarantine, content validation, malware scan, sandbox and resource limits |
| Prompt injection | untrusted-content controls, constrained tools, red-team/evaluation cases |
| Connector compromise | least privilege, credential isolation/rotation, destination allowlist, audit |
| Data in logs | content minimisation, redaction tests, retention/access controls |
| Stale permissions | policy revalidation, cache/index invalidation, bounded cache lifetime |
| Incomplete deletion | provenance dependency graph, deletion workflow and verification |
| Model/provider retention | approved-provider matrix, contractual/configuration review, data minimisation |
| Operator misuse | just-in-time access, reason, approval, audit and customer-visible controls as approved |

## 10. Testing and governance

Before implementation, approve a threat model and data-flow inventory. Require negative tenant, node, resource, identity revocation, integration, agent and model-context tests. Use synthetic data. Before any production deployment, define security review, vulnerability management, incident response, penetration testing, backup/restore and legal/privacy review. Numeric release gates and accountable owners remain open.
