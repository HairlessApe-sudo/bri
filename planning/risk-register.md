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

## Immediate blockers

R-01, R-03, R-04, R-07 and R-16 must have reviewed controls and accountable owners before any real data, external model or production pilot. No implementation begins until separately authorized. Reassess likelihood/severity after threat modeling and customer discovery.
