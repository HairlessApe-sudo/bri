# A16.2 signed loopback demonstration

From the repository root, use the Linux test venv and an installed PostgreSQL 16.2 binary directory. Run as a non-root user with no inherited `PG*` variables. This command puts the HTTP listeners in a loopback-only network namespace; the fixture creates its own disposable PostgreSQL cluster with TCP disabled. No hosted environment, browser, or existing database is used.

```sh
BRI_TEST_PG_BIN=/absolute/path/to/postgresql-16.2/bin PYTHONPATH=src:tests \
  unshare --map-current-user --keep-caps -npf --kill-child sh -ec '
    ip link set lo up
    exec setpriv --bounding-set=-all --inh-caps=-all --ambient-caps=-all -- \
      .venv/bin/python -B -m unittest -v test_xlsx_intake_api.StagedXlsxLoopbackTests
  '
```

Expect the `test_signed_xlsx_proposal_does_not_change_a13_a15_or_publication_tables` test to run and pass; a skip does not verify this flow.

- The test uploads a synthetic CSV, dispatches it, approves it as a separate reviewer, and configures both legacy read gates for that CSV. It confirms the signed A13 search is supported with one CSV citation and that the signed A15 v1 inventory has count `1` with the same CSV evidence.
- A submit-only identity then streams a synthetic XLSX with a contradictory answer to a separate staged listener. Signed status goes from `ready` to `proposed` after the in-process worker returns `completed`. SQL ties the sole XLSX source, source version, extraction, and pending proposal to the exact job and checks the original workbook digest.
- Against the same tenant and database, fresh signed A13 list, search, record, and source responses and the full A15 v1 inventory response match the pre-XLSX values. The submit-only identity continues to receive `403` on A13 list and A15 inventory. Full before/after snapshots of legacy lineage, validation/publication, both read-gate tables, and application grants are identical.

The HTTP clients and listeners, quarantine, worker, and PostgreSQL are real local components. Only the upstream provider call is replaced by a synthetic fixture transport that checks the short-lived JWT signature. This is not a hosted-provider or release-surface demonstration.
