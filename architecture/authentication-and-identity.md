# Authentication, Identity and Governance Architecture

Status: User-approved Assignment 06 baseline and staged implementation plan, recorded 2026-11-13. Assignment 09 adds local trusted composition for tenant configuration APIs, recorded 2026-11-14; it does not approve changes to Supabase settings, shared migrations, deployment, or production credentials/data. See `architecture-decisions.md` for decision status and precedence.

## 1. Authority and status

This document separates the user's approved security/product requirements from implementation choices and unfinished work.

Approved for Assignment 06:

- Supabase Auth is the initial native identity provider. Native accounts use individual email/password credentials; unrestricted public registration is disabled.
- TOTP MFA is mandatory before protected BRI access. Enrollment, verification, factor management and controlled recovery are required.
- The approved role hierarchy is User, SuperUser, Admin and SuperAdmin. User, SuperUser and Admin accounts belong to exactly one client organisation; SuperAdmins are authorised BRI/BRS employees and may administer multiple organisations.
- Preserve resource-level permissions and server-side authorization. Role labels are not sufficient to authorize a request: effective operations require explicit action permissions and applicable tenant/resource scope. A role hierarchy may define permission ceilings/default sets, but it must not bypass exact-scope evaluation.
- User may read historical cases and documents and use the AI question window. SuperUser inherits User capabilities and may CRUD historical cases/documents. Admin inherits SuperUser capabilities and may CRUD standard user accounts, manage AI Gateway configuration and approved websites; Admin cannot create, promote or manage client Admin accounts. SuperAdmin has full platform-wide CRUD authority and exclusively creates, promotes and manages client Admin accounts.
- A SuperAdmin’s platform authority is distinct from client membership. Platform administration may span multiple organisations, but each operation is server-authorized and audited; resource-level permission checks remain in force.
- The design must support client-managed standards-based federation, including Microsoft Entra ID, without requiring BRS to own an Entra tenant. Full enterprise SSO is deferred unless required by the native foundation.
- Native, individually attributable emergency administrators are required for each tenant, with a design minimum of two, tenant scope and MFA; they do not bypass Supabase Auth or BRI authorization.

Proposed implementation details, not separate product approvals:

- Verify Supabase Auth access tokens server-side against the configured project and Auth user endpoint; do not treat decoded browser claims as verified identity. Require exact issuer, authenticated audience/role, subject match, valid time claims and the verified MFA assurance/factor evidence before protected access.
- Map the verified provider issuer and subject to one BRI principal. Only the BRI database grants active memberships, tenant-scoped roles and exact resource scopes.
- Use transaction-local server-derived database identity and tenant context with the existing restricted application role and forced RLS. The database setting is not a substitute for authenticating the caller.
- Keep provider administrative credentials, database credentials and token-verification configuration server-side. The browser must not supply tenant selection or permissions.
- Use a secure, one-time, expiring credential setup/recovery mechanism provided by the identity provider; never expose an existing password or store a plaintext password in BRI tables. Revoke or review sessions after sensitive recovery.

Open for later decision/review: exact browser-to-Next session/cookie mechanics, sensitive-action reauthentication windows, credential recovery proofing procedure, audit retention, client-specific admin caps, provider/region selection for hosting, production identity configuration, and production deployment topology. These open items must not be silently treated as approved.

## 2. Trust and authorization flow

1. Supabase Auth authenticates an individual account and performs TOTP enrollment/challenge. Protected BRI access is denied until the verified session meets the required MFA assurance.
2. The server validates the token/session with the configured Supabase project. Browser-supplied identity headers, tenant IDs, role claims or unverified token payloads are rejected as authorization inputs.
3. The server maps the verified issuer/subject to an active `auth_identity_links` row and active BRI principal. Unknown, suspended, revoked or mismatched identities fail closed.
4. The BRI database returns only active memberships and explicit tenant-scoped role/resource grants. Membership is not an administrative permission by itself.
5. For each protected data operation, the API selects a tenant only from the authenticated principal's authorized memberships and applies exact-scope authorization. The database transaction sets the corresponding context locally; RLS and tenant-qualified foreign keys provide an additional enforcement boundary.
6. SuperAdmin authority is established by an active platform grant and may cover multiple organisations. It does not depend on ordinary one-client membership, but every requested operation is still checked against explicit action permission, tenant and resource scope; platform privileges never come from a client-controlled role or tenant value.
7. Session expiry, account suspension, identity-link revocation and BRI-session revocation are checked server-side. Revocation must fail closed; provider logout and BRI-session invalidation are distinct operations and both must be handled where the flow requires them.

## 3. Account classes and governance invariants

| Account class | Required capability ceiling | Organisation scope and privileged boundary |
|---|---|---|
| User | Read historical cases/documents; use the AI question window | Exactly one client organisation; no historical-content writes or account/policy administration |
| SuperUser | All User capabilities; CRUD historical cases and documents | Exactly one client organisation; no account, gateway or approved-website administration |
| Admin | All SuperUser capabilities; CRUD standard user accounts; manage AI Gateway configuration and approved websites | Exactly one client organisation; cannot create, promote or manage client Admin accounts |
| SuperAdmin | Full platform-wide CRUD authority; exclusively create, promote and manage client Admin accounts | Reserved for authorized BRI/BRS employees; may administer multiple organisations |

Role classes define capability ceilings, not standalone authorization decisions. The current `app_roles`/`role_permissions` and `auth_role_assignments` model remains the source of explicit action permissions and tenant/resource scope. `membership_type` identifies the scoped membership class (including SuperAdmin membership when explicitly assigned); the separate `platform_superadmins` record establishes global platform authority. Every protected operation must still be authorized server-side against the requested action, tenant and resource scope; the browser cannot choose or assert any of these as authority.

Administrator creation is a controlled provisioning workflow, not open registration, email-domain matching, or SSO/JIT promotion. An authorized SuperAdmin creates or promotes a client Admin, binds the account to exactly one client organisation, and audits the operation. The user establishes a credential through a secure expiring setup flow and enrolls/verifies TOTP before administrative access is activated. No email invitation is mandatory as the only creation mechanism.

Password recovery must verify the requester's identity, use a short-lived provider-managed reset/setup mechanism, review/revoke affected sessions, retain MFA enforcement, and audit the initiator, subject, tenant, time, outcome and security context. Resetting a password does not bypass MFA. Lost-factor recovery requires a separate controlled identity-verification and approval process; an administrator may not silently remove MFA.

The database foundation's `tenant_admin_policies` default of two is a configuration/backfill value, not proof that two emergency administrators are provisioned or that the minimum is enforced. Do not claim the invariant is operational until provisioning, count enforcement, recovery and audit paths are implemented and tested.

## 4. Federation and JIT boundary

Future client federation is tenant-configured and standards-based. A trusted server-side provider connection binds the external issuer/connection to exactly one tenant; the browser and email domain do not choose that binding. A successful SSO login may create or refresh a pending standard-user identity record when JIT is enabled, but it must not create an active BRI membership, role, Client Admin or Platform SuperAdmin. An authorized BRI workflow grants membership and permissions. Suspension/revocation in BRI remains independently enforceable even if the upstream account remains active.

Enterprise SSO connection setup, provider settings, domain eligibility and JIT provisioning are deferred from the native-auth foundation. Do not create or configure an external identity connection without separate authorization.

## 5. Staged scope and exit gates

### Stage 0 — Existing local synthetic foundation (complete)

Preserve loopback-only synthetic authentication for local development. It is not an online identity and must not be accepted in hosted mode. Preserve existing tenant/RLS and exact-scope policy behavior.

### Stage 1 — Native Supabase Auth and BRI identity foundation (partially implemented; corrected local validation passed)

Scope: server-side Supabase Auth verification; mandatory TOTP assurance; provider-independent BRI identity mapping; active membership/role lookup; fail-closed BRI session expiry and revocation; safe additive migration source; tests for unauthenticated, unverified, MFA-deficient, unmapped, suspended and cross-tenant identities.

Exit gate: the corrected migration 0001–0006 and catalog/security checks passed on a fresh disposable PostgreSQL 16 database; the shared development database and Supabase-managed compatibility remain unverified. Auth verification, identity/session methods and local UI exist, but provider-backed live end-to-end login and operator workflows remain unverified.

### Stage 2 — Hosted-development API and Vercel server-side integration (partially implemented locally)

Scope: environment-aware FastAPI startup using the hosting platform's port; distinct liveness/readiness checks; server-only HTTPS API origin and credentials; same-origin Next.js proxy integration; hosted requests reject development identity headers and browser-selected tenant context; protected session propagation; redacted request-ID/status/duration logs.

Candidate only: Railway may be evaluated for FastAPI compatibility; it is not selected or approved for provisioning/deployment. The existing Vercel frontend URL is user-provided context, not a fresh deployment verification. No cloud resources, provider settings or deployment are changed in this stage without explicit approval.

Exit gate: local configuration and tests prove hosted-mode fail-closed behavior, proxy allowlists and spoof resistance; local API/proxy preparation is present, but no external deployment or production validation has occurred.

### Stage 3 — Native login, MFA and recovery experience (local UI implemented; provider flow unverified)

Scope: individual email/password login; disabled public registration; TOTP setup/verification; secure recovery; protected session lifecycle and complete logout; reauthentication for sensitive actions. Keep identity tokens and privileged credentials out of public/browser configuration.

Exit gate: UI, server proxy and local tests are present. Live Auth settings, real provider enrollment/challenge/recovery and production end-to-end behavior were not changed or verified; no live Auth settings change absent explicit approval.

### Stage 4 — Administrator governance and provisioning (pending; bounded follow-up)

Scope: SuperAdmin-only platform governance and client Admin creation/promotion/suspension; tenant Admins may manage standard user accounts, AI Gateway configuration and approved websites within their one client organisation; User/SuperUser/Admin permission ceilings are expressed through explicit role permissions and resource scopes; enforceable account-to-organisation cardinality; secure credential setup/recovery and MFA recovery; append-only, secret-free audit records; SuperAdmins may administer multiple organisations. Assignment 09 implements only tenant prompt and tenant Privacy Shield configuration API workflows; it does not implement these broader governance or provisioning workflows.

Exit gate: server-side authorization and database grants/policies reject privilege escalation, enforce exactly one client organisation for ordinary accounts, permit authorized SuperAdmin administration across multiple organisations, and audit privileged actions. UI visibility alone is not an enforcement control.

### Stage 5 — Client-managed enterprise SSO/JIT (deferred)

Scope only after a separate decision: standards-based client IdP configuration, trusted tenant binding, optional eligibility restrictions, pending-standard-user JIT and default-deny activation. No automatic administrator provisioning.

### Stage 6 — Explicitly approved deployment and production hardening (not authorized here)

Requires owner approval for target project/host, migration application, external authentication settings and infrastructure. Then separately establish production project identity, secrets, security review, monitoring/incident response, backup/restore, legal/privacy review and release gates. Local/disposable PostgreSQL validation is not production approval.

## 6. Non-goals and security prohibitions

- No unrestricted self-registration, shared public development identity, browser-selected tenant, or client-supplied permission.
- No unscoped platform action based only on client-supplied role/tenant/scope; SuperAdmin authority is server-verified and still subject to explicit operation, resource and audit checks.
- No Client Admin promotion of administrators or privilege expansion across tenants.
- No email-domain-only identity mapping or automatic SSO/JIT administrator creation.
- No plaintext passwords, tokens, MFA secrets or recovery codes in BRI tables, logs or audit payloads.
- No service-role/database secret in browser-accessible environment variables.
- No weakening of RLS, authorization, or existing negative tests to make a flow pass.
- No remote migrations, external Supabase Auth changes, cloud-resource creation, deployment, production-data access or Git push without explicit authorization.

## 8. Assignment 09 — trusted configuration API composition (local, 2026-11-14)

`src/bri/api/configuration.py` composes the existing prompt and Privacy Shield services with PostgreSQL repositories through a `TrustedRequestContext`. The context contains the server-resolved `Principal`, one authorized tenant, effective role and surviving explicit grants, verified authentication source, auth user/session identifiers when present, AAL/method assurance, and middleware-generated request ID. Role/tenant/principal headers are never used as authority. Role ceilings filter configuration/platform grants before domain services receive the principal; domain services still enforce exact permission and tenant scope. Platform SuperAdmin authority comes from the active server-queried platform grant record; a stale platform membership does not preserve platform or tenant-admin privileges.

Repository scopes are created from that trusted context. They reject a repository tenant that differs from the authorized tenant and call `Database.configuration_context`, which connects only through the existing `bri_app` target, sets `bri.tenant_id` and verified auth or development-synthetic identity transaction-locally, checks the established context, and makes read scopes read-only. Existing forced RLS and restricted grants are unchanged; no service-role or BYPASSRLS path was added.

The mounted endpoints are `GET /v1/configuration/prompts/active`, `GET /v1/configuration/prompts/versions`, `POST /v1/configuration/prompts/versions`, `POST /v1/configuration/prompts/versions/{version}/restore`, `GET /v1/configuration/privacy-signatures/active`, `POST /v1/configuration/privacy-signatures`, and `PUT /v1/configuration/privacy-signatures/{signature_id}`. Handlers delegate to `PromptManager`, `TenantSignatureManager` and `PrivacyShieldConfigurationManager`/the existing signature configuration provider. Writes are enabled only for the explicitly local, loopback synthetic identity mode; the hosted-development Supabase API remains read-only while no production auth project is approved. Tenant routes do not accept a caller-selected tenant.

Verification covers request/service behavior with synthetic principals and an isolated PostgreSQL 16 database migrated only through the checked-in runner. No migration was added for Assignment 09; migration 0007 remains unchanged. The hosted Supabase project, production identity configuration, deployment, and production database composition remain unverified and unchanged. Platform prompt/package management endpoints are not part of this API slice; only server-derived SuperAdmin grants can carry platform management authority in the principal model.

## 9. Verification and current status

The current code and verification evidence are summarized in `../planning/progress.md`. A passing disposable PostgreSQL validation establishes local PostgreSQL behavior only; it does not prove compatibility with every managed Supabase setting or authorize application to the shared development project.
