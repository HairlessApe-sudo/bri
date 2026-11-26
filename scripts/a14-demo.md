# A14 signed Chromium review demo

Run from the BRI root with the existing Linux Python venv, `web/node_modules`, Linux Node, Chromium, PostgreSQL 16.2, and cached matching Linux SWC binding. The launcher requires non-root Linux/WSL with user, network and PID namespaces, `ip`, and `setpriv`; it does not install packages.

```sh
LD_LIBRARY_PATH="$TMPDIR/a13-chromium-libs.bSpP3Y/root/usr/lib/x86_64-linux-gnu" \
  .venv/bin/python -B scripts/a14_demo.py \
    --pg-bin "$TMPDIR/a10-approval-pgbin/pgserver/pginstall/bin" \
    --swc-archive "$HOME/.cache/next-swc/swc-linux-x64-gnu-16.4.6.tgz"
```

Pass `--chromium` and `--node` to override the cached executables. On WSL the private library path may be needed for Chromium; use only existing local dependencies. A14 has no HTTP-only fallback. The default A13 run stays independent.

The launcher migrates a new socket-only PostgreSQL cluster and uses the staged A12 intake adapter and worker in-process to seed two pending proposals and one failed processing job. The Next workspace (127.0.0.2:3013) calls the real review-only Uvicorn app (127.0.0.1:8114). The separate reader-only Uvicorn app (127.0.0.1:8013) verifies published-read authority independently. The A13 issuer serves only JWKS on 127.0.0.1:9013; backend provider verification uses an injected transport accepting only the short-lived synthetic tokens issued on the private pipe. No browser profile or service is reused; the subprocesses, cookies, fixture database, and generated Next files are disposable.

The run requires browser-side signed non-reviewer denial, an exact pending queue and source version/digests/line range, inert formula and markup text, cancel without POST, and an explicit approval followed by a fresh authorized history read. A separate signed HTTP client then rejects the second proposal while Chromium has its confirmation open. The stale browser submit must receive 409, remove stale evidence and controls, and show rejected history only after an explicit fresh detail read. The empty pending queue and approved, rejected, and failed filters are asserted, including the failed history and absence of failed evidence/controls. Finally, the harness reads back the committed decisions, checks for zero record/version access rows, and requires an empty published read through restricted SQL and the signed reader API.

This is a local synthetic integration demo, not a hosted-provider, release deployment, or exhaustive browser suite. The rejection is committed through the second HTTP client, not by clicking Chromium's reject control; the demo does not exercise pagination or BFCache restoration.
