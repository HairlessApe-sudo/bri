# BRI Risk Register

Status: Initial qualitative register; owners, likelihood/impact scoring and risk appetite require approval. Ratings below are provisional planning judgments, not measured facts.

| ID | Risk | Provisional severity | Mitigation / gate | Owner/status |
|---|---|---|---|---|
| R-01 | Cross-tenant or cross-unit data exposure through APIs, search, jobs, reports, caches, indexes or AI context | Critical | Threat model; tenant-qualified data; default-deny policy; negative tests at every layer; block pilot on any leak | Security owner unassigned; open |
| R-02 | Ambiguous hierarchy/authorization inheritance causes overbroad access | High | Decide graph and scope semantics before schema; test multiple memberships, reparenting and cross-links | Product/security owners unassigned |
| R-03 | Historical-source boundary or ownership/licensing issue compromises independent development | High | Enforce clean-room boundary; provenance/approval for every reference; specialist legal review before implementation | Legal owner unassigned; open |
| R-04 | Personal/sensitive information sent to unapproved model, logs or analytics vendor | Critical | Mandatory server-side Privacy Shield and AI Gateway; signature-based AVG/GDPR-sensitive detection plus layered detectors/policy; fail closed on absent or uncertain checks; provider allowlist by purpose/deployment; content minimization; legal approval; synthetic tests | Privacy/security owner unassigned; no code enforcement yet |
| R-05 | Generated answer/report is unsupported or fabricates historical decision rationale | High | Exact versioned citations; unknown/partial status; deterministic metrics; evals and abstention; human review for consequential use | Product/AI owner unassigned |
| R-06 | Prompt injection or malicious source invokes unauthorized tools/exports | High | Treat content as untrusted; constrained tool APIs; independent auth; adversarial tests; no ambient credentials | Security owner unassigned |
| R-07 | Incomplete deletion leaves content in embeddings, caches, reports, logs, backups or exports | High | Data dependency map; lifecycle workflow; revocation/invalidation; deletion tests; legal retention review | Data/privacy owner unassigned |
| R-08 | Source updates/version changes make knowledge stale or citations irreproducible | High | Immutable source versions; sync status; stale-source signals; versioned indexes and reports | Data owner unassigned |
| R-09 | SaaS and private deployment diverge into separate products | Medium-high | Same contracts/release artefact; supported profile matrix; parity tests; explicit deviations via ADR | Architecture/ops owners unassigned |
| R-10 | Premature microservices/connector breadth increases cost, attack surface and delay | Medium-high | Modular boundaries first; stage connector demand; defer service extraction until measured need | Architecture owner unassigned |
| R-11 | Ingestion/parser vulnerability, resource exhaustion or incorrect extraction | High | Quarantine, sandbox, malware scanning, limits, format matrix, parser regression/fuzz tests | Security/engineering owner unassigned |
| R-12 | Customer-specific ontology/configuration breaks compatibility or creates ungoverned semantics | Medium-high | Stable core types; schema validation/versioning; migration and API compatibility rules | Product/data owner unassigned |
| R-13 | Analytics re-identification or misleading comparisons from sparse/inconsistent data | High | Scope filters before aggregation; suppression policy; data quality/method disclosure; synthetic privacy tests | Privacy/analytics owner unassigned |
| R-14 | External connector credentials or outbound destination abused (including SSRF) | High | Scoped credentials, secret facility, destination allowlists, DNS/redirect checks, signed webhooks and rotation | Security/integration owner unassigned |
| R-15 | Provider abstraction leaks vendor-specific behavior or fails on model changes | Medium | Capability contracts, version pinning, provider eval suites, explicit fallback and index generation | AI owner unassigned |
| R-16 | No named owners, workload or operational target makes design untestable | High | Assign product/security/privacy/ops owners; define synthetic workload, SLO/RTO/RPO before release gate | Sponsor action required |
| R-17 | Technical documents interpreted as authorization or legal/compliance assurance | High | Prominent status labels, separate approval gates, legal review, no compliance claims | Project lead unassigned |
| R-18 | Data export/report consumer exposes derived intelligence beyond source permissions | High | Treat export as a new access decision; scoped API identities, destination review, audit and revocation | Product/security owner unassigned |

## A15-AM2 production gate — residual reporting availability channel

Unresolved; conditional local synthetic-only risk acceptance requires renewed independent sign-off. Hidden candidate rows are excluded from counts, evidence and logical overflow, but can increase scan work, potentially turning a complete response into an observable, fail-closed unavailable response. Verification did not demonstrate a hidden-row-induced timeout; review identified no direct unauthorized count or evidence disclosure. No quantitative likelihood or severity is assigned.

Real customer data and hosted production execution are blocked pending the separate production security assessment and approved risk treatment specified in [the reporting architecture](../architecture/published-knowledge-inventory.md#residual-availability-risk-a15-am2).

## A18.2-AM4 — scope-discovery workload and mandatory A20 gate

The architecture owner conditionally accepts the documented revoked-assignment and permission-catalog workload, and associated potential timing/availability inference, for local synthetic development only, subject to renewed independent review of the AM3 implementation. This is not remediation or production acceptance. The [scope-discovery decision](../architecture/a18-scope-discovery-local-risk.md) records measured and structural findings, explicit exclusions, and the mandatory A20 deployment-readiness assessment. No real data, hosted or production execution until approved treatment and independent verification of the actual deployment. The active-only assignment access path remains an assessment candidate, not an approved index. A15 and A18.1 gates remain separate.

## A18.1-AM4 — separate residual workload, timing and availability gate

The architecture owner conditionally accepts the documented physical workload, timing and availability-inference risk for local synthetic-data development only. This is not implementation acceptance. AM2 measured a 3.901 to 18.102 ms sibling-node median increase; it did not observe a complete-to-unavailable transition or establish timing noninterference. Unilateral grant-population dependence is a structural finding, not a measured timing series. No severity or likelihood is assigned. Real customer data, hosted and production use are prohibited pending the separate [A18 production security gate](../architecture/a18-backend-local-risk.md#production-prohibition). A15's separate gate is unchanged.

AM5-R1 closed the implementation HOLD for local synthetic use only after preserving XLSX evidence v1, verifying the separately authorized local v2 and passing the full verifier and independent review. The PostgreSQL 16.16 CSV reservation discrepancy remains open: both the committed baseline and AM4 tree reject with RLS SQLSTATE `42501` instead of the expected `23505`; the unchanged test passes on native PostgreSQL 16.2. Before deployment, independently qualify a maintained PostgreSQL release and resolve this discrepancy without weakening CSV enforcement. No production PostgreSQL version is selected. The separate timing/availability and A15 production gates are unchanged.

## Dedicated ingestion worker qualification — open

[A17 interim closeout](../architecture/a17-interim-closeout.md) records AM3 as partial evidence only and retains the independent HOLD. Track supervisor-controlled containment and deployment-profile portability under deployment and operational readiness. Do not treat local process limits as group limits, or containment as exact PDF decoded-work accounting. No existing gate or risk rating is changed.

## Immediate blockers

R-01, R-03, R-04, R-07 and R-16 must have reviewed controls and accountable owners before any real data, external model or production pilot. No implementation begins until separately authorized. Reassess likelihood/severity after threat modeling and customer discovery.
