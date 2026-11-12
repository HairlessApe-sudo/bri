# BRI Project Progress

Last updated: 2026-11-12
Stage: 3 — platform foundation MVP, synthetic development implementation

## Current status

- Product identity and direction recorded from the initiating brief.
- Authoritative workspace confirmed as `/mnt/c/Users/black/Documents/BRS/BRI`; it was not a Git checkout. Local Git initialized on `main` and `origin` set to the supplied GitHub URL. `git ls-remote --heads` returned no refs; local history now has root commit `660adcb`.
- This assignment did not access prior historical reports, source code, municipal implementations, production systems, credentials or case data. Existing BRI architecture documents were read as current project inputs; no disputed historical materials were reused.
- All 21 foundation documents were read in full before implementation; the enumerated project files and initial source structure were inspected.
- Assignment 01 explicitly authorizes local implementation using synthetic data. No production deployment, external AI provider, real customer data or production system is authorized.
- TDD slices added: bounded UTF-8 CSV extraction; selectable-text PDF extraction; bounded XLSX extraction with XML hardening, no formula evaluation, sheet visibility and row provenance; fail-closed exact-tenant/action/scope policy; deterministic evidence-first question answering with citations, conflict detection and abstention. Two fictional municipal tenants with configurable units, teams, relationships, users, roles and scopes are test fixtures. Thirty-one automated tests pass in the project `.venv`.
- No database, migration, external integration, or real municipal/customer data has been created or used. Docker Desktop WSL integration is unavailable; PostgreSQL is not installed. Local parser dependencies are pinned and their license metadata recorded.

## Approval status

- User-provided product direction: recorded as baseline for this assignment.
- Proposed architecture recommendations: documented; technology stack remains proposed.
- Approved for the local development MVP on 2026-11-10/12: AD-01 PostgreSQL system-of-record selection (partial); AD-02 shared database with tenant_id/composite-FK/forced-RLS plus mandatory application authorization, explicit resource scopes, default deny and no implicit permission inheritance; AD-06 RBAC with explicit scopes; AD-15 development-only synthetic identity adapter. Production identity and SaaS topology remain unresolved.
- Named product, security, privacy, legal and operations approvers: not supplied.
- On 2026-11-12 the product owner resolved the AD-02 development-MVP scope and governance precedence. Approved only for the new BRI development Supabase project: shared PostgreSQL tenant isolation, composite tenant FKs, RLS + FORCE RLS, mandatory application authorization, default-deny exact scopes/no implicit inheritance, synthetic development identities, separate least-privilege application/migration roles. Supabase-managed schemas and the previous BRI Supabase project are explicitly excluded. No production approval is implied.
- Numeric SLOs, workload, budget and schedule: unresolved.

## Decision and risk focus

See `../architecture/architecture-decisions.md` for AD-01–AD-17 and dependencies. Highest priority before any implementation or real data: tenant isolation/access semantics; source/version/provenance and temporal design; data classification/model policy; retention/deletion; legal clean-room/ownership review; identity/deployment profile; named accountable owners.

## Work log

| Stage | State | Evidence / note |
|---|---|---|
| Apply historical-material restriction | Complete | No previous reports, source code, municipal implementations, or case data accessed in this assignment. |
| Synthesize new product direction and clean boundary | Complete | Product and governance documents. |
| Read existing documentation and inspect workspace | Complete | All 21 Markdown files read; `src/` was empty; no existing code, tests or Git metadata were present. |
| Verify Git remote/history | Complete with setup | Initialized local Git metadata on `main`, configured specified `origin`; remote returned no refs and had no prior history. Local commits are recorded in `git log`; author identity supplied by user. |
| Technology recommendation | Proposed | AD-04 stack recommendation remains unapproved; AD-02/06 and local-only AD-15 were explicitly approved for this MVP. |
| CSV extraction and access-policy tracer slices | Complete | Test-first; covered by current test suite. |
| Deterministic Knowledge Intelligence + municipal fixtures | Complete as domain slice | 21 tests pass across extraction, policy, citations, abstention, conflict, and two-tenant seed structure; no UI/API/database integration yet. |
| PDF/XLSX extraction and local dependency setup | Complete as parser slice | 31-test suite passes; parser libraries pinned/licensed; PDF text-only, no OCR; XLSX formulas not executed. |
| Supabase PostgreSQL foundation | Blocked before connection | Safe preflight confirmed `BRI_ENVIRONMENT` is development and the Supabase API URL has a project reference, but both PostgreSQL URL host formats do not expose a safely comparable project reference. No database connection, role provisioning, migration or data operation was attempted. Require connection URLs whose project identity can be matched to `SUPABASE_URL`, or an equivalent independently verifiable project identifier, then resume. |

## Next decisions / questions

1. Supply PostgreSQL connection URLs with a safely matchable Supabase project reference (or an independently verifiable project identifier) before any database connection or modification.
2. Decide production identity federation, policy/role catalogue and detailed organisational hierarchy semantics before building production auth or schema.
3. Define the approved data classification/provider policy before any external AI provider is configured; default to deterministic mock.
4. Confirm accountable product/security/privacy/legal/operations owners and future SaaS/private profiles.

## Change log

- 2026-11-10: Assignment 01 began; local Git repository configured to the specified remote and approved author identity; user approved local tenant-isolation, access-scope and dev-identity decisions. CSV, PDF, XLSX, policy, deterministic knowledge-answering and synthetic municipal fixture slices pass 31 tests. PostgreSQL-backed work awaits Docker WSL integration.
- 2026-11-12: Product owner confirmed development-only AD-02 details and governance precedence. Updated AD-02, security model, data model and project context to align. Assignment 02 preflight stopped before any database connection or modification because the PostgreSQL connection host formats do not expose a project reference that can be compared with the configured Supabase API project reference.
