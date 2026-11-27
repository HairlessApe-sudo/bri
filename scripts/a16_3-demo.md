# A16.3 signed Chromium XLSX demonstration

Run from the BRI root as a non-root Linux/WSL user with the Linux Python venv, `web/node_modules`, Linux Node 26, Chromium, PostgreSQL 16.2, and the matching cached SWC binding if needed on WSL. The launcher requires Linux user/network/PID namespaces, `ip`, and `setpriv`. It does not install dependencies. Unset inherited `PG*` variables.

```sh
.venv/bin/python -B scripts/a16_3_demo.py \
  --pg-bin /absolute/path/to/postgresql-16.2/bin \
  --swc-archive "$HOME/.cache/next-swc/swc-linux-x64-gnu-16.4.6.tgz"
```

Pass `--chromium` and `--node` to override the defaults. There is no HTTP-only fallback. Each run uses an isolated Chromium profile, Next copy, and disposable socket-only PostgreSQL cluster. The signed fixture uses a loopback JWKS issuer and an injected provider transport that recognizes only the short-lived fixture tokens issued over a private pipe. It signs six distinct users: submitter, reviewer, publisher, access maintainer, reader, and unauthorized tenant member. No existing database, real identity, or hosted service is used.

The browser drives the real forms and asserts their response status and DOM. It uploads two copies of one synthetic workbook, checks `ready`, and checks `proposed` after each real worker dispatch. The reviewer sees the exact pending queue and typed worksheet cells, including inert markup and formula-like text. Cancel sends no POST; confirmation commits approval and freshly renders read-only approval history. For the second job, a separate signed API client commits rejection while Chromium has the approval confirmation open: the browser's stale POST must receive `409`, clear evidence and decision controls, and require explicit refresh. That refresh reads current rejected history without another POST.

Publication and access changes are deliberately not browser controls: separate identities invoke the restricted SQL routines, while Chromium verifies record and exact-version evidence denial after approval alone, after publication alone, and after record-only allow. Both allows expose the exact record/version and worksheet. A signed unauthorized identity switch and then live exact-version gate revocation each cause a fresh request to clear previously visible evidence. On the same tenant/database, the five signed A13/A15 results (list, search, record, source, inventory) are compared before XLSX intake and after publication with both allows active; the conflicting XLSX cannot alter the CSV result or inventory.

This is a local integration demo, not a hosted, release, or exhaustive browser check. Worker dispatch and governance maintenance are fixture-side, and only the competing rejection uses a direct signed HTTP client; neither is a substitute for the browser assertions.
