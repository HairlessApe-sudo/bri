# A19.2-AM1 bounded signed Chromium demo

Run from BRI's repository root against a frozen integrated export. The two runs use separate loopback-only Linux/WSL user/network/PID namespaces, profiles, socket-only disposable PostgreSQL clusters and fixture originals. Use the existing environment and caches; no installation, hosted application, shared database, or persistent identity is used.

```sh
pg="$HOME/.hermes/cache/scratch/bri16.2.DGQrGAFq/pgserver/pginstall/bin"
node="$HOME/.hermes/tools/node-26.12.1-linux-x64/bin/node"
chrome="$HOME/.hermes/tools/chromium-1248/chrome-linux64/chrome"
swc="$HOME/.cache/next-swc/swc-linux-x64-gnu-16.4.6.tgz"
umask 077
for demo in scripts/a19_2_demo_off.py scripts/a19_2_demo.py; do
  env -i HOME="$HOME" PATH="${node%/*}:/usr/bin:/bin" TMPDIR="$HOME/.hermes/cache/scratch" \
    .venv/bin/python -B "$demo" \
    --pg-bin "$pg" --node "$node" --chromium "$chrome" --swc-archive "$swc" || exit "$?"
done
```

Pinned offline toolchain from A19.1: PostgreSQL **16.2**, Node **26.12.1**, Chrome for Testing **156.0.8078.80**, Next/SWC **16.4.6**, Python **3.14.9**. `ip`, `unshare`, and `setpriv` must be available to the non-root caller. A13's launcher supplies isolation/teardown, A19.1 supplies the signed role-scoped fixture, navigation assertions and native governance drivers, and the added scripts run only the bounded A19.2 scenario. The OFF script sets `BRI_LOCAL_METADATA_ENABLED=0`; ON sets `=1` and opts in to A19.2 on both staged intake listeners. Only unsigned page shells are warmed. CDP uses real file inputs and activates browser DOM controls; it does not cover mouse hit testing.

| Surface | Proof and limit |
| --- | --- |
| Administration ON | Actual CSV and XLSX files are attached and submitted independently. Exact signed 202, server ID, published UI acknowledgement, separate explicit native status reads, classification round-trip, committed original SHA-256 and no parser fallback are verified. A deliberately mislabeled workbook is rejected without creating another job. Receiving a job or its pending proposal is not approval or publication. |
| Full parsing | **Fixture-side dispatch**, once per returned job with the established restricted worker, never an exposed browser endpoint, scheduler, or automatic retry. The browser explicitly reads the resulting `proposed` state. |
| Authority | Live exact scope, same-scope different owner, wrong node, other tenant, wrong format, unknown job, and separated reader/catalogue/reviewer roles. Browser-origin route probes (not clicked controls) exercise forbidden worker/list paths and spoofed authority. Existing native CSV/XLSX denial codes are not normalized into a new status API. |
| Protected state | The same tab switches to a different signed fixture account and explicitly clears workspace context while a real previously authorized response is held at ASGI send. Old inputs, selected file, choices and status must disappear before release and stay absent after settlement, without automatic status/retry. Another fixture operation removes only the uploader's live exact-node submit grant and tests the now-denied explicit lookup. |
| Integration | Use the actual workspace navigation to governed search and the two native review queues; use the linked native detail and independent reviewer decisions. Native detail still responds if the real metadata dependency becomes unavailable, but all decisions are hidden until an explicit successful refresh. The separately authorized catalogue link exposes no catalogue rows during discovery. Search is empty before approval/publication/access. Open the newly integrated correction control through exact search evidence, propose a CSV correction, and independently approve it in the native metadata view. Assert the server proposal ID, exact version, and independent reader projection. The accepted search UI is not a replacement administration library. |
| Fixture-only work | Role and session provisioning, catalogue seed and one classification creation, the separate restricted worker calls, accepted existing publication/access prerequisites after review (not new workspace actions), the response-hold instrumentation, a temporary revoke/restore of only the metadata detail function, live grant removal, and OFF preparation of classified and unclassified jobs. The provider-user transport for synthetic identities is fixture-controlled. The browser driver observes JSON by cloning the real same-origin Administration responses in memory alongside CDP status/cache assertions; responses are not mocked. It does not collect session headers, cookies, uploads or debugger traces. |
| OFF | The bounded page exposes no submission/status feature controls or application feature calls. Signed upload probes cannot reach the staged routes. Genuine eligible native approvals still work for both formats; classified native bypass is denied and independently verified not to commit. |

No shared job enumeration, library claim, publication/access controls, browser authority, production deployment, or external identity verification is qualified. Read-only browser signals and native authorization checks do not establish recall of bytes already delivered.

ON publishes a fresh private `~/.hermes/evidence/BRI/A19.2/am1/browser/candidate-*` batch only after all browser assertions and service teardown, with eight synthetic 1440×1000 PNGs and a SHA-256 manifest. Keep the source export ID, each launcher command, full exit status and cleanup line with independent evidence. Verify PNG dimensions, hashes and pixels before sharing; no login, credential or debugger screen, tokens, signed traffic, private DB or cached originals are exported. A run against an unfrozen working tree is diagnostic even when it exits 0; the parent owns the independent exact-export rerun.
