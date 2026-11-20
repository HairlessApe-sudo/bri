# A12 — Governed CSV intake

The owner approved a local, synthetic-only AD-09 slice. This is not hosted ingestion, a malware-scanning service, production storage, or a general file import system. See the [A12 acceptance verdict and verification evidence](../planning/progress.md#a12--governed-csv-intake-2026-11-20).

## Boundaries

- A verified active User or SuperUser can submit only to an independently authorized exact node in the server-resolved tenant, with an explicit, unseeded `source:submit` assignment. The approved local harness uses synthetic accounts and isolated verification. `knowledge:review` remains a separate exact-node permission. Neither the uploader nor the proposal creator can approve the proposal, including when processing is performed by a worker.
- Original bytes stay in private local quarantine outside the web root under server-issued keys. No SQL byte store, direct URL, download route or disclosure of storage paths. Capture SHA-256 over the byte stream before decoding. Derived text has a separate digest. Keep the existing version/extraction integrity contract and physical CSV line references; filenames and contents are untrusted.
- Intake accepts strict UTF-8 CSV with optional BOM and at most 5,000,000 bytes, 10,000 data rows and 50 columns. Headers are nonempty and unique, widths are consistent, and cells remain inert. Limit input and parser resources independently. Validation does not certify the file malware-free.

## Workflow

Bind submission identity, exact scope, idempotency key and request fingerprint durably. Exact retries find the same job; changed requests conflict. A private worker processes the quarantined bytes with bounded, fenced attempts; missing or mismatched bytes cannot lead to a proposal. Completed processing records immutable source/version/extraction provenance and a reviewable proposal once. The existing human decision model validates or rejects; approval never grants read access. A separate maintenance decision under migration `0020` must allow both the record and the exact version, and the reader still needs current `knowledge:read` at the exact scope. No independent publication authority is seeded or exposed to the intake or review interface.

## Local operation and recovery

The normal API and web proxy do not mount the intake workflow or give the release role access to governed records. The disposable harness constructs the staged API with mock identity verification, a private PostgreSQL Unix socket, and separate restricted intake, worker and published-reader logins. Migration `0030` creates none of those logins and grants no `source:submit` assignments; the fixture verifies release denial before granting narrowly scoped test access. A tenant-specific database binding identifies the worker's actual proposal creator, separate from the uploader and the legacy compatibility identity. Review excludes both the uploader and the actual creator. The private published reader rechecks the native session and exact-scope permission in the same database query as both publication decisions. It returns derived text, the exact source-version reference, the extracted digest, the original digest, and the inclusive physical line range, but never the original file. The workspace components understand that response shape; the release backend remains on legacy reads.

The derived JSON has its own 20,000,000 UTF-8 byte ceiling. If escaping would exceed it, processing fails permanently rather than truncating cells or retrying. The parser does not certify that a file is synthetic or malware-free; the local harness supplies only synthetic fixtures.

A submission reserves a job before writing the original. An exact retry can finish an interrupted `creating` submission without replacing an installed object. The worker is dispatched by the local harness, not by a browser endpoint. A stale processing lease can be reclaimed with a new attempt number; a previous worker cannot commit against that new attempt. No more than three attempts are admitted. There is no automatic cleanup, retention clock, or hosted worker scheduler. The local queue shows at most 20 pending proposals.

Run the private verification with `.venv/bin/python -IB scripts/db/verify_disposable.py --pg-bin "$TMPDIR/a10-approval-pgbin/pgserver/pginstall/bin"` when that disposable PostgreSQL 16 toolchain is present. The fixture generates its own synthetic CSV and uses no live identity provider. Do not submit real documents or treat CSV validation as a malware safety verdict.

Audit records carry scoped IDs, timestamps, correlation and bounded outcomes only. Original bytes, paths, secrets and raw parser diagnostics do not belong in audit or user-facing errors. No retention term or irreversible deletion is authorized; local test stores exist only for their disposable synthetic fixtures. Production storage, malware handling, real data, connectors, AI/Gateway egress, OCR, and generic Data Disposition remain separate decisions.
