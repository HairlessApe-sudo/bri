# A18.3 local synthetic product demo

Run from the BRI repository root as a non-root Linux/WSL user with the existing `.venv`, `web/node_modules`, `ip`, `setpriv`, and working user/network/PID namespaces. The qualified local toolchain is PostgreSQL **16.2**, Linux Node **26.12.1**, cached Chromium **1248**, and the cached Linux SWC for installed Next **16.4.6**. No packages are installed. Do not point this command at a persistent database, an existing workspace, or a hosted provider.

```sh
# Replace the scratch-local PostgreSQL location only if your existing 16.2 differs.
pg="$HOME/.hermes/cache/scratch/bri16.2.DGQrGAFq/pgserver/pginstall/bin"
node="$HOME/.hermes/tools/node-26.12.1-linux-x64/bin/node"
chrome="$HOME/.hermes/tools/chromium-1248/chrome-linux64/chrome"
swc="$HOME/.cache/next-swc/swc-linux-x64-gnu-16.4.6.tgz"
env -i HOME="$HOME" PATH="${node%/*}:/usr/bin:/bin" TMPDIR="$HOME/.hermes/cache/scratch" \
  .venv/bin/python -B scripts/a18_3_demo.py \
  --pg-bin "$pg" --node "$node" --chromium "$chrome" --swc-archive "$swc"
```

Run the exact candidate for acceptance; a successful run during parallel edits is diagnostic. There is no HTTP-only or mocked data fallback. A complete run exits zero, prints `PASS A18.3 signed Chromium product demo` with the unique evidence directory, and confirms private temporary state cleanup. Captures are made with Chromium CDP `Page.captureScreenshot` in private scratch. A successful run atomically installs an independently complete owner-only batch under `~/.hermes/evidence/BRI/A18.3/screenshots/run-*/`; failures do not replace prior evidence. The authenticated synthetic IDs and SHA-256s visible in the product may change between runs. No passwords, bearer tokens, fixture cookies, API traces, original artifacts, or signed context headers are saved in the screenshot batch.

| PNG | Actual rendered surface |
| --- | --- |
| `01-initial.png` | Knowledge Interface after scope discovery; no search or selected scope |
| `02-scope-selector.png` | Real exact-scope select control after choosing the authorized department |
| `03-mixed-results.png` | Ordered exact XLSX then substring CSV results in one scope |
| `04-csv-multiline-evidence.png` | Matched physical multiline range and full exact-version CSV evidence range |
| `05-xlsx-worksheet.png` | Exact v2 worksheet and matched cell in unified search |
| `06-expanded-provenance.png` | Record, version, SHA-256 and worksheet identifiers expanded; **980×1000** |
| `07-zero-results.png` | Authorized empty department, no matches |
| `08-unavailable.png` | Genuine protected search failure, distinct from zero and with no partial evidence |
| `09-csv-review.png` | Approved CSV review detail after explicitly confirming the decision as independent reviewer |
| `10-csv-reporting.png` | Exact-node CSV-only published knowledge inventory, as employee |
| `11-csv-question.png` | Supported A13 question and CSV citation, as employee |
| `12-xlsx-v1-evidence.png` | Separate A16 v1 exact worksheet page, as employee |
| `13-csv-review-confirmation.png` | Actual confirmation panel before the independent review decision |

All other PNGs are **1440×1000**. The selector screenshot shows the committed value; the browser separately verifies all available options. CDP drives the actual controls, captures the visible viewport, and verifies signed same-origin HTTP receipts and their corresponding DOM; this is not pointer-testing coverage.

The fictional municipality is Alder Reach Public Services. As the employee, choose **Social Services** and search `Visit coordination guidance`: the worksheet's exact match precedes the CSV substring, whose record spans physical lines 2–3. The **Community Liaison (empty)** node is authorized but yields zero results for the same query. **HR** and **Information Management** are independently selectable; the employee cannot discover the restricted service or read a foreign tenant's evidence. The browser also verifies each negative against the real signed fixture dataset.

The private launcher creates a disposable Unix-socket PostgreSQL cluster and confines the signed fixture, Next, Chromium and JWKS to a fresh loopback-only namespace. A13 fixture signing and staged provider-user transport supply native synthetic identities; protected HTTP routes, authorization/session resolution, database reads, intake, worker extraction, independent review and publication/access decisions are real within the disposable stack. Fixture-side operations are not browser governance features. A14 opens a real pending proposal from the queue, confirms approval once, and verifies the committed state with a fresh browser read; the approved proposal without a CSV access decision remains unreadable by the employee. To show unavailability without fabricating HTTP, the demo holds a genuine successful search response past the existing bridge deadline, verifies the bridge's own 503, and releases the response before a fresh successful search. For identity clearing, it holds a genuine replacement scope response at ASGI send and inspects the still-pending browser. Independent XLSX record and version revocations use the restricted fixture maintenance routine; each must deny fresh evidence and remove the hit without affecting the CSV hit. Native session revocation is also checked after its database commit. A13 CSV question evidence is separate from unified literal search; reporting is CSV-only; v1 worksheet compatibility is checked against v2.

This does not verify release or hosted behavior, external identity services, physical workload isolation, browser-history behavior, recall of already delivered data, or production readiness. The accepted A18.2 run and release-smoke evidence are separate (`~/.hermes/evidence/BRI/A18.2-AM5/`). See the [original MVP reconciliation](../architecture/a18-3-mvp-reconciliation.md) for coverage limits and outstanding production gates.
