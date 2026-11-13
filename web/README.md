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
