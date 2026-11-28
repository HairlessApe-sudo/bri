# A19.1 AM2 signed Chromium verification

Run from BRI’s repository root as a non-root Linux/WSL user. Use the existing `.venv`, installed `web/node_modules`, cached Linux SWC, and the toolchain below. The launcher needs `ip`, `unshare`, `setpriv`, and a working user/network/PID namespace. It does not install packages, contact a hosted service, or use an existing database. Run only against a frozen integrated candidate for acceptance; earlier runs are diagnostic.

```sh
pg="$HOME/.hermes/cache/scratch/bri16.2.DGQrGAFq/pgserver/pginstall/bin"
node="$HOME/.hermes/tools/node-26.12.1-linux-x64/bin/node"
chrome="$HOME/.hermes/tools/chromium-1248/chrome-linux64/chrome"
swc="$HOME/.cache/next-swc/swc-linux-x64-gnu-16.4.6.tgz"
umask 077
# Run both. Each invocation uses a fresh isolated fixture and browser profile.
for demo in scripts/a19_1_am2_off.py scripts/a19_1_demo.py; do
  env -i HOME="$HOME" PATH="${node%/*}:/usr/bin:/bin" TMPDIR="$HOME/.hermes/cache/scratch" \
    .venv/bin/python -B "$demo" \
    --pg-bin "$pg" --node "$node" --chromium "$chrome" --swc-archive "$swc" || exit "$?"
done
```

The local toolchain is PostgreSQL **16.2**, Node **26.12.1**, Chrome for Testing **156.0.8078.80** (cache `chromium-1248`), Next/SWC **16.4.6**, and Python **3.14.9**. The established A13 launcher runs loopback-only listeners and Chromium in a disposable namespace and removes the browser profile, PostgreSQL cluster, quarantine, and temporary logs. The two entry points explicitly compose the private workspace with `BRI_LOCAL_METADATA_ENABLED=0` (OFF) and `=1` (ON), respectively; do not set a browser header or use an HTTP failure to select legacy mode. Both must exit `0` and separately confirm assertion completion and cleanup. The ON flow also verifies its screenshot batch. No HTTP-only or mocked product fallback is available.

## Coverage boundaries

- **OFF browser actions:** verify the native detail is genuinely pending and contains its extracted evidence. Independently confirm a native approval and rejection per format and read back each committed state with no application metadata requests. A classified native approval must fail with no state change even though the browser renders the legacy controls. A live signed member without review rights has no decision controls; a separately labelled same-origin native POST probe proves authorization still denies the mutation.
- **ON browser actions:** both formats approve a genuinely unclassified native proposal only after a successful metadata read; while the real metadata read returns `503`, signed native detail still renders and neither legacy nor classified approvals are offered. Preserve catalogue provisioning/create/rename/retire; classified XLSX selection/upload/native status; classified CSV approval as proposed and XLSX corrected approval; exact-version metadata and historical labels; correction preview/acknowledgement, independent CSV correction approval, XLSX stale/revoked decision recovery; and the legacy question, approval, inventory, mixed search, and exact worksheet. Signed browser-origin requests independently exercise stale correction rejection in CSV and XLSX; they are not clicks on the UI's disabled stale controls. Chromium CDP activates DOM controls; no pointer-test coverage is claimed.
- **Fixture-side operations:** pending inputs prepared through genuine signed native intake and worker dispatch. OFF classified pending inputs are prepared through separate fixture-only signed metadata intake listeners, not browser bridge routes. A restricted database connection independently checks the exact classified native approval guard. ON unavailable metadata is induced by removing only the metadata detail function's execute grant in disposable PostgreSQL, then restoring it and verifying a fresh browser read. Other fixture operations are versioned CSV submission, access overlays and gates, XLSX publication, the competing correction, and session revocation. Provider-user responses are synthetic; signed session verification, real application code, bridge, HTTP, and persistence checks are not mocked.
- **Evidence:** OFF is assertion/log-only. ON captures eight synthetic 1440×1000 PNGs with a SHA-256 manifest in a new owner-only `~/.hermes/evidence/BRI/A19.1/AM2/browser/run-*` batch after all browser assertions and service teardown. No signed headers, cookie material, request traces, private database files, or uploaded originals are exported. Inspect the pixels before sharing any screenshots. No hosted, release, external identity, or production claim is made.

An HTTP 200 for a correction proposal is not enough: the UI must display the independently issued proposal identifier. If it renders an error despite verified persistence, the harness exits nonzero with a separate `diagnostic-*` snapshot, never an acceptance batch. For original/RED runs, use a new export of the held candidate and copy only these test harness deltas; compare all other archive member bytes before and after. Do not interpret the original's opted-in historical pass as evidence of OFF behavior.
