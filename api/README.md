# BRI local development API

This is a loopback-only development API. Synthetic identity selection is not production authentication. The API uses the restricted `DATABASE_URL` role only; it validates the approved development project and `bri_app` username before connecting. It never reads the bootstrap or migration role URLs. If the connection URL omits an SSL mode, the API forces TLS with `sslmode=require`; insecure or duplicate SSL mode parameters are rejected.

## Start

From the repository root, after installing `requirements.txt` and completing the database-role setup in `db/README.md`:

```sh
BRI_ENVIRONMENT=development BRI_DEV_AUTH_ENABLED=true PYTHONPATH=src .venv/bin/uvicorn bri.api.main:app --host 127.0.0.1 --port 8000
```

The app reads `.env.local` through `python-dotenv`; it does not print or log its values. The synthetic identity adapter is enabled only when `BRI_ENVIRONMENT=development` and `BRI_DEV_AUTH_ENABLED=true`. Protected routes also reject non-loopback clients. Keep the bind address at `127.0.0.1`.

OpenAPI JSON is at `/openapi.json`; interactive docs are at `/docs`; ReDoc is at `/redoc`.

## Synthetic identity and tenant context

For local tests, send `X-Dev-Identity` with a user ID from `tests/fixtures/synthetic_municipalities.json`, for example `user-noordlicht-reader` or `user-noordlicht-org-reader`. The server maps that identity to a `Principal`, tenant membership, permissions and exact node scopes from the synthetic fixture. The request cannot supply or select a tenant. `X-Tenant-ID`, a `tenant_id` query parameter, and request bodies on protected read routes are rejected. An unknown or missing synthetic identity is denied.

Every protected request opens a read-only transaction as `bri_app`, derives the tenant ID from the server-side principal, sets `bri.tenant_id` transaction-locally, and exercises the RLS-protected tenant table. Organizational nodes and relationships are read from the `bri` database tables when that tenant has a persisted row; on the clean development project, where no tenant seed rows are persisted, the API falls back to the existing synthetic municipality fixture. Organization scopes are checked per node; a grant on a parent does not expose descendants. Relationships are returned only when both endpoints are authorized.

The current migrations do not define knowledge-record tables. The API's approved/proposed knowledge examples and source references are synthetic in-memory fixtures used with the existing `KnowledgeItem` model and deterministic `answer_question` retrieval. Only approved, exactly scoped records and source metadata are returned. No fixture records are written to the database.

## Read-only endpoints

- `GET /health` — database readiness using `bri_app`.
- `GET /v1/organizations/structure` — individually authorized nodes and relationships.
- `GET /v1/organizations/nodes/{node_id}` — one exactly authorized node; inaccessible IDs return 404.
- `GET /v1/knowledge` — approved records in authorized scopes.
- `GET /v1/knowledge/{record_id}` — one approved, authorized record.
- `GET /v1/knowledge/search?q=...` — deterministic evidence retrieval with citations; no external model call.
- `GET /v1/sources/{record_id}` — source version and location for an approved authorized record.

There are no write, upload, frontend, or external AI routes in this milestone.

## Tests

Run the full suite:

```sh
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
```

Opt into the live database/RLS tests only on the verified development environment:

```sh
PYTHONPATH=src BRI_RUN_DB_TESTS=1 .venv/bin/python -m unittest discover -s tests -v
```

All live database fixtures use synthetic rows in rollback-only transactions; API routes themselves do not write data.
