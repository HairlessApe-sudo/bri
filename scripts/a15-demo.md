# A15 local signed inventory parity

Run from the repository root with the BRI Linux Python venv, installed `web/node_modules`, Linux Node 26, offline PostgreSQL 16.2 binaries, and Linux Chromium. Use the same non-root, loopback-only network/PID namespace prerequisites as `scripts/a13-demo.md`. A15 needs migration 0032 and the reporting-enabled staged reader. No real credentials, external requests, or pre-existing database are used.

```sh
.venv/bin/python -B scripts/a15_demo.py \
  --pg-bin /path/to/postgresql-16.2/bin \
  --swc-archive /path/to/matching-linux-swc.tgz
```

Omit the SWC override if the installed Next dependencies already contain the matching Linux native binding. Override `--node` / `--chromium` with explicit local paths as needed. `--http-only` runs real PostgreSQL, direct API, and Next bridge checks without exercising Chromium or the rendered UI.

The harness signs only synthetic identities through the existing private fixture signer, publishes governed CSV records using staged intake and review, then compares the consumer's direct bearer-authenticated `GET` with the same read through the workspace's verified HttpOnly-cookie bridge. It checks exact-node counts, authorized empty and generic denial, tenant isolation, evidence parity and source follow-through, and fresh evaluation after resource unavailability and native-session revocation. It also stops the reader to check that the UI distinguishes a dependency outage from an unavailable metric. This does not validate hosted behavior.

For another synthetic consumer in the same harness, import `read_inventory(bearer=token, scope_node_id=node)` from `a15_consumer.py`. It targets the fixed loopback Uvicorn endpoint directly, ignores environment proxies, never follows redirects, and does not mint or print tokens.
