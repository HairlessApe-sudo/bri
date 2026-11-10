# BRI Testing Strategy

Status: Proposed verification strategy; Assignment 01 implementation and testing have begun (see progress log).

## 1. Test principles

Use synthetic, purpose-built fixtures with distinct tenants, organizational structures, sensitivity labels, source versions, access grants, decisions and deletion states. Never load real municipal/customer case data. Test authorization as a system invariant, not only UI behavior. Separate static evidence, automated tests, manual review and deployed operational evidence; do not claim a capability from a test stub alone.

## 2. Test layers

- Domain unit tests: lifecycle transitions, hierarchy invariants, provenance, temporal semantics, decision states, metric calculations and policy rules.
- Module contract tests: identity/policy, connector, source/knowledge, intelligence, reporting and audit interfaces.
- API tests: authentication, scopes, schema validation, versioning, pagination, idempotency, errors and rate limits.
- Integration tests: database constraints/RLS, object storage, queue retry, index freshness, identity adapter, provider adapters and deletion propagation.
- End-to-end tests: import → review → publish → retrieve → cite → report/export through UI and API.
- Security tests: tenant/unit/resource IDOR, privilege escalation, revocation, cache/index leakage, agent scopes, SSRF, webhook replay, secret/log leakage, malicious files and prompt injection.
- AI evaluation: retrieval relevance, citation precision, unsupported claims, abstention, conflict handling, temporal and decision reasoning, provider regression and data-boundary compliance.
- Operational tests: backup/restore, upgrade/rollback, job replay, provider outage, queue backlog, key rotation and deletion verification for selected deployment profile.
- Accessibility/usability/performance: thresholds set from user needs and workload; not yet defined.

## 3. Required synthetic scenarios

1. Two tenants with differently configured trees; attempt reads/writes/search/exports using wrong tenant and cross-linked node.
2. User with multiple valid memberships and one revoked membership; verify scope resolution and cache/index invalidation.
3. Same external source object reimported with unchanged and changed versions; verify idempotency and provenance.
4. Malformed, oversized, hostile and unsupported CSV/XLSX/PDF files; verify quarantine, safe errors and resource limits.
5. Candidate classification rejected; ensure not published/searchable to ordinary users.
6. Interaction-derived suggestion awaiting review; ensure it cannot become shared knowledge without authorized validation.
7. Historical decision with missing reasoning/outcome; verify answer says not recorded rather than inventing.
8. Conflicting and stale evidence; verify source/version visibility and uncertainty.
9. Prompt injection in a document; verify it cannot change policy, select tenant or invoke an unauthorized tool.
10. Delete source/knowledge; verify downstream extraction/index/cache/report/export behavior matches approved policy.
11. Identical deterministic report inputs/spec version; verify stable numerical output and methodology.
12. SaaS-like and private-like configuration parity for core access behavior.

## 4. Test data and privacy

Generate synthetic names, organizations, decisions and documents; use obvious synthetic markers and avoid realistic identifying details derived from actual cases. Keep fixtures in authorized project test locations only after implementation is approved. No external provider receives test content unless explicitly approved; default evaluation uses mocks/local controlled fixtures.

## 5. CI and release gates (proposed)

- Required unit/contract/integration/e2e suite passes on supported release build.
- No known critical/high unresolved security issue in in-scope threat model; any exception requires named risk acceptance and expiry.
- Tenant isolation and revoked-access tests pass for every supported data path.
- Provenance/citation and no-fabricated-decision tests meet approved thresholds.
- Dependency/license/security scans and secrets checks pass.
- Migration, restore, deletion and upgrade evidence recorded for supported deployment profiles.
- API compatibility and accessibility review completed at agreed scope.

Exact coverage, latency, quality, availability and vulnerability thresholds are unresolved and must be agreed before implementation/release; do not substitute arbitrary percentages.

## 6. Evidence discipline

For each acceptance criterion record requirement ID, test ID, fixture/version, build/config, expected and actual result, environment, reviewer and defects. Mark tests not run as not run. A successful unit test does not establish production configuration, external provider retention, legal compliance or operational readiness.
