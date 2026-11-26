# A14 — Knowledge review workspace

A14 is a local, synthetic-only workspace for the A12 CSV review workflow. It is not a new validation engine, a hosted review feature, or a grant of publication authority. See [governed CSV intake](governed-csv-intake.md) for the decision and evidence invariants and [local knowledge questions](local-knowledge-questions.md) for the existing fixture session and published-read surface.

## Review contract

The A12 decision command accepts only `approved` or `rejected`. It serializes against the authoritative proposal state and checks the current active native session, same tenant, exact-node `knowledge:review`, and separation from both the uploader and the proposal creator. The decision, validation (on approval), and immutable audit record commit together. A repeat or competing decision cannot create a second outcome. A12 defines neither decision-specific reason codes nor an additional MFA freshness rule; A14 does not add either. Allowlisted processing reason codes describe failed processing, not a reviewer's reasoning.

The review projection is separately authorized from published knowledge. The default queue shows pending proposals. Approved and rejected decisions remain distinguishable from pending items; failed processing is a separate terminal state, not a proposal a reviewer can decide. Queue pages and details omit inaccessible rows, do not expose hidden counts, and do not write state or audit. Detail shows only the authorized proposal and scope, immutable source/version and extraction identity, bounded pages of literal extracted evidence, original and extracted SHA-256 values, the inclusive A12 extraction line range, and a bounded review lifecycle history. Original bytes, quarantine paths, object keys, raw audit records, and unrelated policy events are not shown. A failed job can lack an extraction and therefore has no displayed source evidence.

Approval does not grant `knowledge:read`, a record allow, or an exact-version allow. Those checks remain independent and current on the published reader. A reviewer's authorized preview is not a grant to read published knowledge.

## Execution boundary

The fixture workspace uses the existing signed synthetic session on its dedicated loopback host. The review bridge forwards only its canonical queue, detail, and approve/reject operations to a private review listener. The listener has no upload, worker, quarantine-read or access-policy routes. Database read projections run read-only with exact-scope authorization; the decision still uses the existing A12 transaction. Production/release roles and the normal proxy do not receive the staged authority. There is no hosted enablement or real-data processing in this slice.
