# A18.2 signed Chromium demonstration

Run from the BRI repo root as a non-root Linux/WSL user. Requires the existing project `.venv`, installed `web/node_modules`, Linux Node 26, Chromium, PostgreSQL **16.2**, `ip`, `setpriv`, Linux user/network/PID namespaces, and a matching cached Linux SWC binding if needed. Unset inherited `PG*` variables. The demo does not install dependencies or use hosted services.

```sh
TMPDIR="$HOME/.hermes/cache/scratch" .venv/bin/python -B scripts/a18_2_demo.py \
  --pg-bin /absolute/path/to/postgresql-16.2/bin \
  --swc-archive "$HOME/.cache/next-swc/swc-linux-x64-gnu-16.4.6.tgz"
```

Set `TMPDIR` to an existing private scratch directory; `--swc-archive` is only needed if the installed Next dependencies lack the matching native Linux binding. Override executable paths with `--node` and `--chromium`. There is **no HTTP-only fallback**. Only exit 0 with `PASS A18.2 signed Chromium demonstration complete` is a complete run; preflight and intermediate PASS lines are not acceptance. Run against the exact candidate to use a successful transcript for acceptance. Runs during concurrent edits are diagnostics, not exact-candidate evidence.

The launcher reuses the A13/A15 isolated namespace, signer and CDP setup, the A15 API consumer, and the A16.3 split CSV-reader/XLSX-governance listener recipe. PostgreSQL is a new Unix-socket-only disposable cluster. Next runs in scratch at `127.0.0.2:3013` against the signed loopback listeners on `127.0.0.1:8013` (legacy CSV/A15), `:8018` (unified), `:8117` (XLSX governance) and `:9013` (JWKS only). The private signer pipe issues short-lived native fixture identities, installed by CDP as HTTP-only cookies scoped to the local bridge. The staged APIs use the existing injected provider-user transport; signatures, issuer binding, database sessions, grants and SQL reads are real within the disposable stack. SQL fixture operations seed and revoke data before verifying effects through fresh signed reads. No credentials, cookies, or context bindings are emitted in the matrix output. The launcher cleans up the browser, processes and scratch state.

## Matrix

| # | Browser assertion |
|---|---|
| 1 | The Knowledge Interface loads and discovers exactly the authorised labelled scope options; no scope is selected by default. |
| 2 | A single selected exact scope returns both CSV and XLSX. |
| 3 | Exact matches beat substring matches, with preserved deterministic cross-format tie order and identical normalized repeat results. |
| 4 | With XLSX access revoked, the same search returns only CSV. |
| 5 | With CSV access revoked, the same search returns only XLSX. |
| 6 | Matching but hidden CSV and XLSX records never appear in the ordered receipt or corresponding DOM. |
| 7 | An authorized unmatched query gives a successful empty state with no cards. |
| 8 | Candidate overflow gives 503/unavailable with neither partial cards nor a results field; a fresh search recovers after excluding the overflow batch. |
| 9 | CSV follows the matching exact version; matched physical lines 3–5 and the full receipt's lines 1–6 are distinct. |
| 10 | XLSX follows the separate A16 v2 path and renders the exact worksheet, matched cell, and typed values; its real cursor advances within that version. |
| 11 | Opening Technical provenance shows the exact record, version, and applicable digests; XLSX also shows extractor, canonicalization and worksheet identifiers. |
| 12 | Synthetic markup is text, not a DOM element. |
| 13 | Changing the selected scope immediately clears search and evidence from the old scope. |
| 14 | Replacing the signed cookie in the same page clears the old workspace at refresh start, while replacement discovery is held. Releasing the old successful search while discovery is still pending cannot repopulate the workspace. After release, only the replacement identity’s authorized scopes appear, without a selected scope, query, or automatic search. |
| 15 | A real successful response held after SQL evaluation cannot republish after changing scope and completing a newer query, whether Chromium aborts or receives the old response. |
| 16 | Revoking the record gate alone denies fresh exact-version evidence and removes the hit in both formats. |
| 17 | Revoking the version gate alone has the same effect, independently of the record gate, in both formats. |
| 18 | A revoked native session denies fresh search/discovery; a revoked exact node denies the same signed principal with a fresh session while its separate grant still works. |
| 19 | Same-database A13 list/search/detail/source and A15 v1 inventory receipts remain equal; A16 v1 keeps the same JSON receipt and still renders the worksheet in Chromium. |
| 20 | Root and a sibling with `organisation:read` only are absent from the selectable scopes. |
| 21 | The exact `empty-team` grant is discoverable despite no readable records and supports a successful zero-result search. |
| 22 | A different active signed tenant member with no knowledge grants gets HTTP 200 with empty discovery, not denial. |
| 23 | Withholding only the restricted discovery execute privilege gives a genuine held 503 after replacing the cookie. Both pending and unavailable views have no old query, scopes, selection, findings, evidence or provenance; search stays disabled. Restoring the privilege allows explicit refresh to recover. |
| 24 | After revoking the selected exact node, refreshing with a new signed session of the same principal removes that option and clears the prior selection, results and evidence. |
| 25 | While a same-cookie refresh is held, the query, scope controls, cards, evidence and expanded provenance are redacted. A valid reply restores the exact still-eligible selection only; no query or findings return and no search is dispatched. |

The harness drives the real forms through Chromium and checks same-origin network receipts and rendered DOM. Direct signed API calls are fixture/compatibility controls, not substitutes for the Chromium matrix. Independent, one-shot ASGI latches hold genuine staged search and discovery responses without changing response data. This is limited to local synthetic evidence; it does not validate a release build, hosted deployment, network-facing authorization, or all browser history behavior.
