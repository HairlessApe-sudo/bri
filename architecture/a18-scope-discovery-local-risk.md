# A18.2-AM4 — conditional local risk decision

This decision applies only to local synthetic development, and only if renewed independent prerequisite review accepts the exact AM3 implementation tree `6a9aa982084f36a1294e0b7891e9a5437dd957fa`. The previous HOLD (`deleg_32bacc46`) stays in force until that review; its technical findings are not withdrawn, downgraded, or declared resolved. Close the optimization investigation for this development phase. Do not change 0036 or runtime to address the accepted workload, add an active-only index, broaden privileges, or expand permission infrastructure.

## Closed technical findings

AM1 tree `1e9f635763bb278c237b2260ba21d652b4538932` (HOLD `deleg_bccebf7a`) enumerated and sorted unrelated grants in HTTP identity preflight. AM2 tree `04ce940b5d7fa15ea5404d29d3a551087824fb85` (HOLD `deleg_baedc21e`) closed that blocker with a bounded live native identity/session lookup. Its protected discovery still repeated permission evaluation for assignments under roles without `knowledge:read`. AM3 confirmed the preflight closure and eliminated those per-assignment permission checks using permission-first discovery and the existing tenant/principal/role key. Preserve both corrections without reopening them absent contradictory evidence.

## Accepted dependency and limits

The owner conditionally accepts only the documented workload from revoked assignments under qualifying roles, additional heap filtering and buffer activity, the observed permission catalog scan, and associated possible timing and availability inference. In AM3 both plan modes fetched and rejected 5,000 revoked qualifying-role assignments. Status remained a heap filter; candidate-stage shared-buffer hits rose from 7 or 8 to 203 and the query touched 83 heap blocks. The permission scan read the full 71-row fixture relation. Larger permission catalogs were not qualified. The 500-node logical output cap does not bound all physical work.

The signed HTTP comparison measured 1,300 requests across 13 interleaved conditions. With 5,000 retained revoked assignments, median latency was 68.36 to 68.64 ms for empty scopes and 71.18 to 71.74 ms for two scopes. Expected private/no-store HTTP 200 responses were observed throughout, with no unauthorized label disclosure or complete-to-unavailable transition. This does not establish timing noninterference, absence of side channels, constant physical work, production scalability, or production severity or likelihood.

Not accepted: unauthorized labels or metadata, incorrect effective permissions or scope eligibility, cross-tenant access, authentication/session defects, hidden nodes contributing to logical limits, partial results represented as complete, privilege expansion, RLS bypass, any materially different workload finding, or any other implementation or verification blocker. Such findings require HOLD and separate architectural review. Prerequisite acceptance does not replace exact integrated review.

## Mandatory A20 deployment-readiness gate

No real customer data, hosted use, or production use of scope discovery until a separate production assessment, approved risk treatment, and independent verification of the actual deployment. Assess representative tenant, principal, role and permission cardinalities; active and revoked distributions and history accumulation; duplicate effective assignments; permission catalog growth; custom and generic plans; index selectivity and maintenance; dead tuples and vacuum; representative contention; repeated timing and availability inference; resource isolation; and a maintained production PostgreSQL version. Assess an active-only assignment access path as a possible mitigation. A partial index is an assessment candidate, not an approved production design, and must not be implemented in A18.2. A15 and A18.1 gates remain separate and unchanged.

## Preserved verification

AM1–AM3 candidates, commands, plans, measurements and verdicts are preserved under `/home/black/.hermes/evidence/BRI/A18.2-AM{1,2,3}/`. Exact AM3 evidence was reverified: 769 backend passes with zero failures, errors or skips; 36 verified migration checksums; no-op replay; 70 forced-RLS non-ledger tables; 48 focused passes; one signed compatibility pass. The private native suites ran on PostgreSQL 16.2, with separate cached PostgreSQL 16.16 Docker fixtures. The 16.16 CSV reservation compatibility finding remains unresolved. No suite or workload was rerun just for this decision.
