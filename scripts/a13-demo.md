# A13 local signed-fixture demo

From the repo root, use a Linux Python venv with the BRI test dependencies, installed `web/node_modules`, Linux Node 26, cached PostgreSQL **16.2** binaries, and a runnable Linux Chromium. The launcher requires non-root Linux (or WSL) with `unshare`, `ip`, `setpriv`, and user/network/PID namespaces. It fails closed if it cannot isolate the listeners.

```sh
.venv/bin/python -B scripts/a13_demo.py \
  --pg-bin "$HOME/.hermes/cache/scratch/a10-approval-pgbin/pgserver/pginstall/bin" \
  --swc-archive "$HOME/.cache/next-swc/swc-linux-x64-gnu-16.4.6.tgz"
```

Use `--chromium /path/to/chrome` or `--node /path/to/node` for other **local** installations. Omit `--swc-archive` when the installed Next dependencies already include the matching Linux native SWC. The script never installs packages. If Chromium exits with code 127, `ldd /path/to/chrome` identifies missing OS libraries. Add `--http-only` to the command for signed HTTP/DB diagnostics only; it does **not** verify Chromium, browser cookie transmission, or history restoration.

The harness publishes synthetic records in two tenants using staged intake, worker, and review. It runs reader-only Uvicorn and a JWKS-only fixture signer on `127.0.0.1:8013` and `127.0.0.1:9013`, with the isolated Next workspace on `127.0.0.2:3013`. Its trusted SSR adapter creates a host-only HttpOnly cookie scoped to `/api/bri-local`, using a fresh RSA key. It does not open a token mint endpoint or read a real provider/DB credential.

The Chromium path checks actual outgoing cookie headers, all three answer states, the citation and linked source, then revokes the native session in PostgreSQL. It verifies an explicit refresh removes evidence and a Back navigation exposes no parked provenance while a real source revalidation is held, then receives 403. It reports whether Back restored from BFCache or made a cold navigation. The HTTP-only path independently exercises the signed bridge and committed DB revocation. Next's generated files, browser profile, quarantine, and the private database are disposable.
