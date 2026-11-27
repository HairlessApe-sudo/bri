# A16.4 — Integrated XLSX lifecycle acceptance

A16 is accepted for the approved local synthetic-data-only governed XLSX lifecycle. This acceptance does not authorize real customer data, hosted execution or production deployment.

## Traceability and verification

All three accepted implementation commits are ancestors of, or equal to, the directly verified GitHub main tip at delivery, `d326dcbb54429b4ab78149c2ff20f8877cd5f88a`.

| Slice | Accepted commit | Verified implementation tree | Historical evidence | Independent review |
|---|---|---|---|---|
| E — A16.1 | `da4789176270655dd1e27c3e44090a486e15abfb` | `8f717dd67ea8142906858754c31b10887cda1124` | 59 XLSX and 676 backend tests, exit 0 | `deleg_fbfc2e08`, PASS, 59 XLSX tests reproduced |
| I — A16.2 | `500f782f29c13efb3741c36534127c8e3d5b4508` | `0b9037bead0237eb73d67aa2c6144ae126e71c04` | 707 backend tests, signed HTTP upload-to-proposal, exit 0 | `deleg_b189d924`, PASS, 31 focused tests reproduced |
| G — A16.3 | `d326dcbb54429b4ab78149c2ff20f8877cd5f88a` | `672434a2cafe930b06eab5a05b1426a12c4bcf23` | Final integrated run below | `deleg_2aac81ae`, PASS, 23 governance tests and signed Chromium reproduced |

Git comparison confirmed each acceptance commit differs from its verified tree only by its named architecture note and `planning/progress.md`. For G the note is `architecture/governed-xlsx-review.md`. Final G evidence recovered from runs `proc_605b084bf01d` (backend/catalog), `proc_bbcf2a2e50b8` (web), and `proc_c6ee08bb38f1` (Chromium): all exit 0; 730 backend and 165 frontend tests, no reported failures/errors/skips; both TypeScript checks and optimized release build passed; 34 migration checksums matched, replay applied zero migrations, 70 non-ledger tables retained forced RLS. No acceptance suite was rerun for consolidation. Historical counts are not additive.

## Lifecycle acceptance matrix

All accepted statuses below mean local synthetic only. E/I/G identify the exact commit and independent review above. B = backend or database tests; F = frontend tests; H = signed HTTP; C = signed Chromium. Listed evidence is representative, not a claim every negative case ran in every modality.

| Requirement | Implemented capability | Slice | Evidence | Limitation | Status |
|---|---|---|---|---|---|
| Native identity | Verified session at local API and protected DB boundary | I/G | B,H,C | Synthetic provider | Accepted |
| Exact-node submission | Current explicit source:submit, no inheritance | I | B,H | Not deployed ACL evidence | Accepted |
| Bounded upload | Streamed original-byte cap | I | B,H,C | Boundary negatives in tests | Accepted |
| Idempotent reservation | Fingerprint and owner-scoped replay | I | B | Race cases not browser tests | Accepted |
| Private immutable quarantine | Tenant/job namespace, no-replace storage | I | B,H | Trusted local filesystem | Accepted |
| Original integrity | Verify length and SHA-256 before extraction | I | B,H,C | No malware verdict | Accepted |
| Strict extraction | ZIP/XML, allocation and process budgets | E | B | Not an OS sandbox | Accepted |
| Canonical representation | Typed, deterministic JSON; separate digest | E | B | Supported subset only | Accepted |
| Worksheet provenance | Artifact-scoped sheet ID/title and physical A1 range | E/I/G | B,H,C | Trust worker interpretation | Accepted |
| Durable processing | Attempt/lease fencing and bounded retries | I | B,H,C | Browser sees normal dispatch, not crash/retry matrix | Accepted |
| Atomic pending proposal | Immutable exact lineage and pending state | I | B,H,C | Pending is not validation | Accepted |
| Independent reviewer eligibility | Current exact-node review before visibility/lock and again after lock | G | B,C | Lock-wait negatives verified in dedicated tests/review, not browser | Accepted |
| Uploader/creator exclusion | Both barred from review visibility and both decisions | G | B | Separate identity negatives in tests | Accepted |
| Atomic approve/reject | One terminal decision, audit, approval-only validation | G | B,F,C,H | Competing rejection via signed HTTP; race and rollback in tests | Accepted |
| Immutable validated knowledge | Approving decision and exact version required | G | B | No legacy promotion | Accepted |
| Separate publication | Explicit authorized maintenance; serialized history | G | B,C | Maintenance fixture-side | Accepted |
| Record allow | Principal-targeted independent, default deny | G | B,C | Maintenance fixture-side | Accepted |
| Exact-version allow | Separate gate for exact record/source/version | G | B,C | Maintenance fixture-side | Accepted |
| Fresh record retrieval | Publication and both gates in one protected read | G | B,F,C | No catalogue or search | Accepted |
| Exact evidence follow-through | Bounded cell navigation, inert rendering | G | B,F,C | Dense/limit edges in tests | Accepted |
| Withdrawal and revocation | Fresh reads deny after withdrawal or either gate changes | G | B,F,C | Withdrawal in tests; browser checks version revocation and identity switch; no recall | Accepted |
| Immutable audit | Lifecycle/governance atomic events and replay receipts | I/G | B,C | Browser verifies review history, not all audit internals | Accepted |

## Security, compatibility and supported profile

The [strict profile](../architecture/strict-xlsx-extraction.md) supports one visible unencrypted XLSX worksheet, a valid A1-anchored header, literals, finite numbers, supported dates/times and blank cells. It excludes hidden content, formulas even with caches, relationships to external resources, hyperlinks, macros, embeddings, merges, unsupported workbook features and malformed archives/XML. Separate hashes bind exact originals and bounded canonical extraction. The [intake](../architecture/governed-xlsx-intake.md) and [governance](../architecture/governed-xlsx-review.md) contracts describe role isolation, tenant keys, bounds and lock ordering.

Backend checks and exact-tree reviews support tenant and exact-node isolation, current native-session authorization, forced RLS, named execution without direct runtime table grants, reviewer independence and pre-lock visibility, concurrent decisions, publication/read separation, exact-version evidence, immutable audit and legacy exclusion. Browser/frontend checks support inert display, bounded traversal and fresh authorization clearing. Equivalent denials are not proof of eliminating timing or resource channels. Earlier review `deleg_1ee1c630` held `c140e10d7942d8af4d8bfaee0e5b6c10f8cd46eb`: delayed publish or access retries could undo withdrawal or revocation. The accepted fix uses tenant-scoped durable audit receipts including no-ops, returns exact authorized replays without mutation, and rejects conflicting reuse after live authority and target checks. Regression tests and renewed independent review cleared the finding.

Final regression evidence covers CSV extraction and governed intake, legacy XLSX/PDF extraction, A10 identity/session, A11 accounts, A12 governance, A13 retrieval, A14 workspace and A15 reporting. Same-database signed comparison before and after XLSX publication showed unchanged A13 CSV list/search/record/source and A15 v1 inventory. A13 CSV question answering is unchanged; A15 v1 is CSV-only. XLSX uses dedicated protected routes, never incidental legacy/CSV reads. Release checks show no hosted XLSX execution paths. Dedicated XLSX retrieval is not cross-format retrieval.

## Repeat the signed demonstration

Manual prerequisites: from the repository root as a non-root Linux/WSL user, use the existing Linux Python venv, installed web dependencies, Linux Node 26, Chromium, local PostgreSQL 16.2 executables, and cached matching Linux SWC where needed. Linux user/network/PID namespaces, `ip` and `setpriv` are required. Unset inherited PG environment variables; never supply a live database or real workbook. Use the [accepted launcher instructions](../scripts/a16_3-demo.md); no new dependencies or public listeners.

Run `.venv/bin/python -B scripts/a16_3_demo.py --pg-bin <local-pg16.2-bin> --swc-archive <cached-linux-swc.tgz>`. The launcher automatically creates a disposable socket-only cluster and isolated Chromium profile, starts the loopback workspace and signed synthetic issuer transport, uploads deterministic workbooks and observes owner status. The private fixture dispatches processing. Chromium independently reviews and approves, follows exact worksheet evidence only after separate fixture-side publication and both allows, and verifies denied/revoked displays and stale recovery without auto-resubmit. Competing rejection uses signed HTTP; publication and access maintenance use restricted fixture calls rather than browser forms. There is no HTTP-only fallback. Manual completion: require exit 0 and the fixture shutdown/cleanup PASS line; do not point a retry at persistent state. No manual database writes or public startup steps are required.

## Outstanding gates

Still required before production: deployed identity and deployed roles/ACLs, production storage and quarantine, malware scanning, parser filesystem and network isolation, global workload isolation, approved worker interpretation trust, real-data retention/deletion propagation, recovery/restore, and deployment-profile parity. Fresh revocation cannot recall earlier disclosures. The [A15 unresolved availability risk and mandatory production security gate](risk-register.md#a15-am2-production-gate--residual-reporting-availability-channel) remain unchanged.
