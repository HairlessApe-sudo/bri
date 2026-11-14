# BRI Security and Privacy Model

Status: Proposed security baseline; development-MVP tenant isolation decisions in approved AD-02 are authoritative. Production security approval remains outstanding. See `architecture-decisions.md` for governance precedence.

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

For the Assignment 06 native-authentication baseline, use Supabase Auth for individual native accounts; require TOTP MFA before protected BRI access; and keep provider authentication distinct from BRI principal, tenant membership, role and resource authorization. The application server must verify the provider identity and required MFA assurance, then map the exact verified issuer/subject to an active BRI principal. The approved role hierarchy is User, SuperUser, Admin and SuperAdmin, with User/SuperUser/Admin each bound to one client organisation and SuperAdmins reserved for authorized BRI/BRS employees who may administer multiple organisations. Their capability hierarchy must be implemented through explicit action permissions and tenant/resource scope checks, not role-name-only conditionals. Admin cannot manage client Admin accounts; only SuperAdmin can.

Design the federation boundary for client-managed standards-based identity providers, including Entra ID, without requiring BRS to own an Entra tenant. Full SSO connection setup/JIT is deferred. The existing synthetic identity adapter remains loopback-only for local development. Account recovery and factor recovery require controlled identity verification, MFA preservation and secret-free audit. Production identity/provider settings remain unresolved and are not authorized for change. See `authentication-and-identity.md` for staged scope and explicit open decisions.

Machine identities require scoped credentials, rotation/revocation and independent audit; do not share human sessions or broad service keys with agents.

## 4. Authorization: RBAC + contextual policy

The role hierarchy establishes capability ceilings; it does not substitute for the permission system. The approved roles are:

- User: `historical_case:read`, `document:read`, and `ai_question:ask`.
- SuperUser: all User capabilities plus `create/read/update/delete` for historical cases and documents.
- Admin: all SuperUser capabilities plus `create/read/update/delete` for standard user accounts, AI Gateway configuration and approved websites. Admin cannot create, promote or manage client Admin accounts.
- SuperAdmin: authorized BRI/BRS employees only; full platform-wide CRUD and exclusive authority to create, promote and manage client Admin accounts. SuperAdmins may administer multiple client organisations.

These action names define the required permission contract, not an implementation of those future APIs. `app_roles`/`role_permissions` and scoped assignments remain the source of effective grants. Every decision must verify authentication, active account/membership, action permission, tenant and exact resource scope on the server. Role labels alone, UI visibility and client-supplied context are not authorization. A SuperAdmin may span organizations; ordinary client accounts have exactly one client organisation. Default deny remains mandatory.

Do not infer hierarchy inheritance, cross-node access or a tenant-wide grant from a role label. Keep explicit deny precedence, delegated scope, policy versioning and failure handling fail-closed; document and test them before implementing new privileged routes.

Authorization must apply before data retrieval and again before response/citation/export. Enforce across APIs, database, object storage, search, cache, queues, reports, outbound connectors and AI tools. Revoke/invalidate cached/indexed access on policy changes.

## 5. Tenancy options and controls

For the development MVP, approved AD-02 selects a shared PostgreSQL database with tenant identifiers, tenant-qualified references/composite foreign keys and RLS plus FORCE ROW LEVEL SECURITY on tenant-owned application tables. Application-level scope authorization is mandatory; access is default-deny with explicit resource scopes and no implicit hierarchy inheritance. Dedicated `bri_app` and `bri_migrator` roles are restricted to BRI-schema responsibilities; the application role must not own tables or have BYPASSRLS/superuser privileges. Use synthetic identities/data only. Do not modify Supabase-managed schemas or the previous BRI Supabase project. This development decision does not approve production topology/security. The application role has no access to Supabase service schemas or non-BRI application tables, sequences or functions in the verified development project. Supabase's database defaults still grant `PUBLIC` temporary-table privilege and execute on `pg_catalog.lo_create`; `bri_app` retains those global defaults. This foundation is synthetic-development-only; production approval requires a separate decision about these provider-level privileges. Do not change Supabase-managed/system schemas or global grants under this assignment. The app sets `bri.tenant_id` transaction-locally only after deriving tenant and scope from the authenticated principal; this PostgreSQL setting is caller-settable by a holder of the app credential, so RLS is defense-in-depth, not identity authentication. Keep the database credential server-side. Regardless of physical model, use isolated storage/index/cache/task context, negative tests and audited operator access. Private deployment must use the same logical policy contracts.

## 6. Information protection

- Classify data and define handling/retention before connecting real sources.
- Encrypt transport and stored data using deployment-approved mechanisms; key ownership and customer-managed keys are open.
- Store credential material in a deployment secret facility; persist references and metadata only in ordinary records.
- Minimize content in logs, traces, audit events and analytics telemetry.
- Define data residency, subprocessors, provider retention/training settings and customer export/deletion with legal review.
- Keep original, extracted, proposed, validated and derived content separately identifiable and access-controlled.

### Mandatory Privacy Shield before AI egress

Every document, historical case, user question, attachment and retrieved context item must pass the server-side BRI Privacy Shield before any content is sent to any AI model. The Privacy Shield is a mandatory AI Gateway boundary, not an optional UI filter, per-user setting or bypassable feature. The AI Gateway must reject provider-bound requests unless it verifies a server-generated, request-bound shield result covering every input and retrieved item.

The baseline detector must include signature-based detection of AVG/GDPR-sensitive information. Signatures are mandatory but not sufficient for compliance or complete detection. Design the pipeline for additional detectors and policy checks (for example, entity recognition, contextual classification, tenant/purpose rules, and human review where required), with versioned rules and traceable decisions. Minimize, redact or tokenize content before provider egress; keep any re-identification mapping inside the trusted BRI boundary. Never log raw prompts, documents, retrieved passages, attachments, signatures or sensitive findings.

Fail closed if parsing, detection, policy evaluation, attestation binding or the Privacy Shield is unavailable, incomplete, stale or ambiguous. The attestation must bind the request, content hashes, detector/policy versions and permitted provider/purpose; clients cannot assert or override it. Every model entry point—including ingestion/extraction, retrieval-augmented questions, attachments and background jobs—must use the same gateway enforcement. Signature checks do not by themselves establish AVG/GDPR compliance; legal/privacy review and additional controls remain required.

## 7. AI and agent security

- Route every provider-bound operation through the AI Gateway, which must reject requests without a verified Privacy Shield pass for every prompt, source/case, retrieved passage and attachment; no connector, worker, UI or model adapter may call a provider directly.
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
