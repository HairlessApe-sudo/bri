# A13/A14 local fixture workspace

From `web/`, with the existing dependencies installed, run `node local-workspace/server.mjs` in the same network namespace as the fixture servers. Open `http://127.0.0.2:3013/knowledge` for published evidence or `http://127.0.0.2:3013/review` for review. This is a separate Next app; ordinary `npm run dev`, `npm run build` and `npm start` do not mount it. The numeric listener addresses are fixed.

| Listener | Role |
| --- | --- |
| `127.0.0.2:3013` | Separate Next workspace plus its exact `/api/bri-local/v1/...` bridge. Use this exact numeric host, not `localhost` or `127.0.0.1`. |
| `127.0.0.1:8013` | `create_staged_csv_reader_app` only. Bind directly to loopback; disable proxy headers and access logs. Do **not** use the mixed A12 intake listener or the normal API. |
| `127.0.0.1:8114` | `create_staged_csv_review_app` only, backed by the disposable fixture database. Bind directly to loopback; disable proxy headers and access logs. |
| `127.0.0.1:9013` | Synthetic Supabase-compatible provider. The bridge only reads `/auth/v1/.well-known/jwks.json` over this socket. Use the same ephemeral signing keys for the backend's independent verifier. |

The parent demo harness authenticates the fixed synthetic user against the mock provider and collects `@supabase/ssr`'s `createServerClient` `setAll` output, including any cookie chunks. Install the cookies only on `127.0.0.2`, **host-only** (omit the `Domain` attribute), with `name: 'sb-bri-local-auth-token'`, `path: '/api/bri-local'`, `httpOnly: true`, and `sameSite: 'lax'`. Browser cookie scope does not include the port: the different numeric host keeps the cookie away from the reader, JWKS and release UI on `127.0.0.1`; the path keeps it off workspace page and asset requests. Use a dedicated browser context.

`LOCAL_AUTH_OPTIONS` in `bridge.mjs` lists the fixture key, cookie name/path, and expected issuer. The JWT must be signed with the fixture's asymmetric key and carry `aud: 'authenticated'`, `role: 'authenticated'`, `aal: 'aal2'`, valid `iat` and `exp` NumericDates, and the known BRI `sub` and `session_id`. Include a timestamped TOTP `amr` entry (`{ "method": "totp", "timestamp": <epoch seconds> }`) and return the matching user from the backend's mock Auth verification endpoint with `factors` containing a verified TOTP factor (`factor_type: 'totp'`, `status: 'verified'`). The hosted-form `iss` claim matches the existing fixture registry mapping; it is not used as a network destination. The session must also be active in the disposable BRI database. The bridge does not expose a login/mint endpoint, refresh sessions, send identity headers, or accept browser-supplied bearer tokens. When a fixture expires, authenticate a fresh fixture via the harness.

Published bridge reads are `/v1/knowledge`, `/v1/knowledge/search?q=...`, `/v1/knowledge/csv%3A<uuid>` and `/v1/sources/csv%3A<uuid>` under `/api/bri-local`. Of these, only search accepts a query. The list remains an array with bounded previews; the knowledge detail returns the full approved extraction. The bridge caps the streamed upstream body at **48,000,000 bytes** for knowledge detail only: up to 20,000,000 UTF-8 bytes of A12 JSON can nearly double when escaped inside a JSON string, with room left for metadata. List, search, source detail, and JWKS retain the **16 MiB** cap. Oversized reader responses fail closed with a generic `503`, not partial data.

The review bridge uses the same signed fixture session, but routes only these operations to `:8114` (not the reader or ordinary `/api/bri` proxy):

- `GET /api/bri-local/v1/knowledge/proposals/csv` with optional `status` (`proposed` by default, `approved`, `rejected`, or `failed`), `after` (bare UUID), and `limit` (1–50, default 50).
- `GET /api/bri-local/v1/knowledge/proposals/csv/csv%3A<uuid>` with optional `offset` (0–20,000,000; the server pages evidence in 4,096-character chunks).
- `POST /api/bri-local/v1/knowledge/proposals/csv/csv%3A<uuid>/decision` with exact `Origin: http://127.0.0.2:3013` and `Content-Type: application/json`. Its only member is `decision`, either `approved` or `rejected`; bodies are limited to 512 bytes and 1.5 seconds. A stale/replayed decision returns `409`. The UI does not retry automatically.

Failed processing is terminal and has no extraction or decision controls. Approval records a review outcome; it does not publish a record or authorize access. Review responses are checked against the bounded queue/detail/acknowledgement contract before being shown.

The local UI displays no previous result while revalidating. On `pagehide`, it removes evidence and aborts pending reads synchronously. While parked, focus and visibility changes cannot restart reads. A persisted `pageshow` starts fresh reads under a new refresh key. User refresh and tab focus/visibility also revalidate while the page is active. This is request-time revocation, not a push guarantee for previously delivered data in a continuously open tab.

Checks from `web/`: `node --test tests/*.test.mjs`, `npm run typecheck`, `node node_modules/typescript/bin/tsc --noEmit -p local-workspace/tsconfig.json`, and `npm run build` for the ordinary release app.
