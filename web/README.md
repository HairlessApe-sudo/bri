# BRI Web UI — local development

Next.js App Router + TypeScript interface for the existing loopback FastAPI API. The browser talks only to the same-origin `/api/bri/...` routes; the Next.js server forwards an allowlisted set of GET requests to `127.0.0.1:8000` and adds the one fixed synthetic identity configured in this server's private `.env.local`. No database URL, Supabase URL, or credential is exposed to browser code.

## Start locally

Use two WSL terminals from the repository root.

Terminal 1 — backend:

```sh
BRI_ENVIRONMENT=development BRI_DEV_AUTH_ENABLED=true PYTHONPATH=src .venv/bin/uvicorn bri.api.main:app --host 127.0.0.1 --port 8000
```

The backend uses the restricted `bri_app` database role from the root `.env.local`. See `../api/README.md` and `../db/README.md` for the existing synthetic-development setup. Do not run migrations or seed data as part of UI startup.

Terminal 2 — frontend:

```sh
cd web
cp .env.example .env.local
npm ci
npm run dev
```

Open `http://127.0.0.1:3000`. Keep both services bound to loopback; do not change either host to `0.0.0.0`. For a production-mode local preview, run `npm run build` then `npm start` (still loopback-only).

## Development identity and access

`BRI_UI_DEV_IDENTITY` is read only by the Next.js server. Set it in `web/.env.local` to one exact identity from `../tests/fixtures/synthetic_municipalities.json`, then restart Next.js. The browser cannot choose an identity or tenant, and incoming identity/tenant headers are not forwarded. The proxy only allows health, organization read, validated-knowledge read/search, and source-reference GET routes; proposal/review writes are deliberately unavailable from this UI.

The fixture includes `user-noordlicht-workspace-reader`, an additional synthetic, read-only workspace identity. It has `organisation:read` for exactly the six Noordlicht organisation nodes and `knowledge:read` only for `org-noordlicht-policy-team`, the scope of the synthetic policy record. It has no propose, review, manage, write, or Zilvermeer grants. The original organisation-only, knowledge-only, proposer, reviewer and admin identities remain unchanged. The default `.env.example` uses this combined identity to allow the read-only UI workflow in one session. Set `BRI_UI_DEV_IDENTITY` to another fixture identity and restart Next.js when testing its narrower access; the browser cannot change identities.

The API remains the authorization boundary. It resolves tenant membership and exact scopes from the configured server-side fixture identity, performs RLS-scoped reads, and returns only authorized records. The proxy does not accept tenant selectors, does not expose arbitrary API paths or mutations, and requires a loopback HTTP backend origin. Keep the Next.js server loopback-bound so its server-to-server API calls cannot become a network-facing development-auth relay.

## Screens

- Overview dashboard: backend readiness and counts/previews from organization and validated-knowledge API responses (never fabricated).
- Organisation: authorized structure tree, client-side filter over returned nodes, and authorized relationships.
- Knowledge: validated record list and evidence-first search with source/version citations.
- Knowledge detail: approved content and scope.
- Source detail: source/version/extraction/hash/location metadata from the authorized source endpoint.

Loading, empty, API error, 401 and 403 states are shown. Search is read-only; the frontend has no direct Supabase/database client.

## Checks

```sh
npm test
npm run typecheck
npm run build
```

The Node test suite covers the proxy's fixed identity, route allowlist, query allowlist, and loopback/backend configuration. Existing FastAPI tests cover unknown/missing identity, non-loopback rejection, permission checks, tenant-selector rejection, and scope isolation. Database integration tests are opt-in and write synthetic rows inside rollback-only transactions; do not run them against the shared development database unless separately approved.

## Read-only user directory (A11.1)

The Users screen (`/users`) is available in authenticated mode, not synthetic development mode. The browser uses the existing same-origin proxy for `GET /api/bri/v1/users` and `GET /api/bri/v1/users/{uuid}`. The proxy verifies the SSR session token; FastAPI independently enforces the active client Admin session and explicit directory grant. Search by name or UUID and page through results; there are no writes. Directory tests use in-process fixtures rather than provider or deployed API credentials.

## Create User (A11.2): release disabled

After an authorized directory list, the Create User entry explains why provisioning is unavailable and shows disabled display name and email fields. Synthetic mode has no directory access. Neither release mode forwards provisioning requests; there is no feature flag or provider setup screen.

The frontend contract is exercised with an injected transport in local tests only. A manual retry after a missing acknowledgement uses the same UUID and payload while the form remains open. After acknowledgement, a manual status GET uses the original request key, not the returned account UUID. The screen does not poll, resend invitations, or treat an invitation acknowledgement as account activation.

## User lifecycle (A11.3): release read-only

Authenticated directory details show the account's status and explain that lifecycle changes are disabled in this release. Neither hosted nor synthetic mode proxies lifecycle requests. There is no environment switch to enable them.

The isolated `StagedDirectoryDetail` takes an explicitly injected transport for local exercises. Its staged GET and PATCH use `/v1/users/{id}/lifecycle`. A validated server snapshot provides the displayed name, status, role, version, and action permissions. Editing changes only the display name; suspension and reactivation require a reason and confirmation. PATCH uses the last server version and the UI updates only from a confirmed response. A conflict or unconfirmed change requires an explicit refresh and a new action; nothing is retried automatically.

## Controlled password recovery (A10): hosted flow unavailable

Both `/auth/recover` and `/auth/update-password` render the same static support notice. Neither page prompts for TOTP or reads provider credentials. They do not request reset mail, collect a password, reserve an operation, sign the user out, or start a BRI session. Normal password sign-in and TOTP remain separate. No public environment setting enables controlled recovery.

The in-process web tests exercise a proposed contract only. Before accessing browser credentials, it requires the exact approved development origin `https://bwqdyibvuecgthtatrtv.supabase.co` (optional trailing slash) and an explicitly injected reservation adapter. There is no network fallback or hosted adapter. In the contract, the reservation request is a same-origin, bodyless `POST /api/bri/v1/auth/recovery/invalidate`; only the SSR bearer goes upstream. A `204` acknowledges a committed reservation and cutoff. The bearer digest checks session equality, **not** a causal link to a password change. Only a transport supplied by the test reservation receives the simulated provider PUT. No new password goes to BRI or its audit.

A successful provider reply means **provider acknowledged**, not **BRI recovery confirmed**. Provider or cleanup failure does not roll back a cutoff. Neither a browser callback, a matching bearer, nor a recent event for the same user proves that a particular reservation caused the change. Only an independently authenticated provider event linked to the exact pending operation, project and subject can confirm it. Unbound changes may fence sessions; they must not release a pending operation. See `../architecture/provider-event-source.md`.

**API owner release gate:** Reject direct `POST /v1/auth/recovery/invalidate` requests as unavailable *before* creating a reservation, advancing a cutoff or revoking sessions unless the server has a separately authorized, operational mechanism to bind the provider change to that reservation. A valid bearer and fresh TOTP alone are not sufficient. Do not use a browser flag, browser-supplied operation ID, or the existence of an event consumer as that gate. Test a direct authenticated request with the mechanism absent and assert no state change. Hosted provider-mediated proof remains externally blocked.
