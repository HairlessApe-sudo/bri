# BRI Project Progress

Last updated: 2026-11-10
Stage: 3 — platform foundation MVP, local synthetic implementation

## Current status

- Product identity and direction recorded from the initiating brief.
- Authoritative workspace confirmed as `/mnt/c/Users/black/Documents/BRS/BRI`; it was not a Git checkout. Local Git initialized on `main` and `origin` set to the supplied GitHub URL. `git ls-remote --heads` returned no refs; there are no local commits or prior commit history.
- Prior five assessment reports were reviewed as reference lessons only; no prior source code, municipal implementation, production system, credential or case data was accessed for this assignment.
- All 21 foundation documents were read in full before implementation; the enumerated project files and initial source structure were inspected.
- Assignment 01 explicitly authorizes local implementation using synthetic data. No production deployment, external AI provider, real customer data or production system is authorized.
- First TDD slices added: bounded UTF-8 CSV extraction with row-line provenance and exact-byte SHA-256; fail-closed exact-tenant/action/scope policy primitive. Fourteen automated tests were run and pass.
- No database, migration, external integration, or real municipal/customer data has been created or used. Docker Desktop WSL integration is unavailable; PostgreSQL is not installed.

## Approval status

- User-provided product direction: recorded as baseline for this assignment.
- Proposed architecture recommendations: documented; technology stack remains proposed.
- Approved for the local MVP on 2026-11-10: AD-02 shared PostgreSQL tenant_id/composite-FK/forced-RLS plus service authorization; AD-06 RBAC with explicit resource/node scopes, default deny, no parent-to-child permission inheritance; AD-15 development-only synthetic identity adapter. Production identity and SaaS topology remain unresolved.
- Named product, security, privacy, legal and operations approvers: not supplied.
- Numeric SLOs, workload, budget and schedule: unresolved.

## Decision and risk focus

See `../architecture/architecture-decisions.md` for AD-01–AD-17 and dependencies. Highest priority before any implementation or real data: tenant isolation/access semantics; source/version/provenance and temporal design; data classification/model policy; retention/deletion; legal clean-room/ownership review; identity/deployment profile; named accountable owners.

## Work log

| Stage | State | Evidence / note |
|---|---|---|
| Review permitted reference reports | Complete | Prior assessment reports only; reference-only use. |
| Synthesize new product direction and clean boundary | Complete | Product and governance documents. |
| Read existing documentation and inspect workspace | Complete | All 21 Markdown files read; `src/` was empty; no existing code, tests or Git metadata were present. |
| Verify Git remote/history | Complete with setup | Initialized local Git metadata on `main`, configured the specified `origin`; remote returned no heads and local history is empty. No author identity is configured, so commits are blocked. |
| Technology recommendation | Proposed | See AD-04; no architecture decision is marked approved. |
| CSV extraction tracer slice | Complete | Test-first; 8/8 `unittest` tests pass. |
| Municipal vertical slice | In progress / blocked at security gates | Need approval of tenant/access model and dev identity; local PostgreSQL runtime also unavailable. |

## Next decisions / questions

1. Enable Docker Desktop WSL integration; user selected this route, but it is not yet available in WSL.
2. Decide production identity federation, policy/role catalogue and detailed organisational hierarchy semantics before building production auth or schema.
3. Define the approved data classification/provider policy before any external AI provider is configured; default to deterministic mock.
4. Confirm accountable product/security/privacy/legal/operations owners and future SaaS/private profiles.

## Change log

- 2026-11-10: Assignment 01 began; local Git repository configured to the specified remote and approved author identity; user approved local tenant-isolation, access-scope and dev-identity decisions; CSV and policy slices pass 14 tests. PostgreSQL-backed work awaits Docker WSL integration.
