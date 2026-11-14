# BRI local development API

This is a loopback-only development API. Synthetic identity selection is not production authentication. The API uses the restricted `DATABASE_URL` role only; it validates the approved development project and `bri_app` username before connecting. It never reads the bootstrap or migration role URLs. Reads use read-only transactions; knowledge proposal and validation writes use a separate tenant-scoped write transaction, still as `bri_app`. Configuration writes use the trusted tenant transaction factory and are enabled only for loopback synthetic local development. If the connection URL omits an SSL mode, the API forces TLS with `sslmode=require`; insecure or duplicate SSL mode parameters are rejected.

## Start

From the repository root, after installing `requirements.txt` and completing the database-role setup in `db/README.md`:

```sh
BRI_ENVIRONMENT=development BRI_DEV_AUTH_ENABLED=true PYTHONPATH=src .venv/bin/uvicorn bri.api.main:app --host 127.0.0.1 --port 8000
```

The app reads `.env.local` through `python-dotenv`; it does not print or log its values. The synthetic identity adapter is enabled only when `BRI_ENVIRONMENT=development` and `BRI_DEV_AUTH_ENABLED=true`. Protected routes also reject non-loopback clients. Keep the bind address at `127.0.0.1`.

OpenAPI JSON is at `/openapi.json`; interactive docs are at `/docs`; ReDoc is at `/redoc`.

## Synthetic identity and tenant context

For local tests, send `X-Dev-Identity` with a user ID from `tests/fixtures/synthetic_municipalities.json`, for example `user-noordlicht-reader` or `user-noordlicht-org-reader`. The server maps that identity to a `Principal`, tenant membership, permissions and exact node scopes from the synthetic fixture. Each protected API request must resolve to exactly one tenant; multi-tenant principals are denied until a deliberate tenant-selection model is approved. The request cannot supply or select a tenant. `X-Tenant-ID`, a `tenant_id` query parameter, and request bodies on protected read routes are rejected. An unknown or missing synthetic identity is denied.

Every protected request derives the tenant ID from the server-side principal and establishes transaction-local `bri.tenant_id` as `bri_app`. Configuration routes use a `TrustedRequestContext` carrying principal, one tenant, effective role and explicit grants, identity/session assurance and correlation ID. The repository-scope factory rejects mismatched tenant arguments, sets the authenticated `bri.auth_user_id` or local synthetic principal GUC in the same transaction, and verifies it; read scopes are read-only. Prompt/Privacy Shield handlers call existing service methods; they do not make direct SQL or duplicate service rules. Configuration writes are local synthetic-only; hosted Supabase mode remains read-only. Proposal/review writes use the separate knowledge write context. Existing forced RLS and `bri_app` grants remain in force. All knowledge and source content is retrieved from RLS-protected PostgreSQL tables; there is no in-memory knowledge fallback. Organizational nodes and relationships use persisted `bri` rows when seeded; otherwise the organization route retains its synthetic fixture fallback. Organization scopes are checked per node; a grant on a parent does not expose descendants. Relationships are returned only when both endpoints are authorized.

Migration `0004_knowledge_lifecycle` adds source records/versions/extractions, proposals, immutable validation decisions and validated records. Migration `0005_source_version_provenance_fk` ties an extraction's existing tenant/source/version/hash/location tuple to the exact source-version row with a composite foreign key; no provenance columns are dropped or rewritten. Proposals refer to an existing extraction and cannot be retrieved as validated knowledge until a reviewer approves them. Rejections are terminal; a proposal cannot be decided twice, and proposers cannot review their own proposal. Search uses only approved records within the caller's authorized exact scopes and verifies each extracted-content SHA-256 before returning it or citing it. API writes persist through `bri_app`; the migration role is never used for runtime requests.

### Trusted API configuration context

Configuration routes use a server-created request context; `X-Role`, principal headers and caller-supplied tenant headers are ignored or rejected, and route payloads contain no tenant selector. The context carries the authenticated BRI principal, its one authorized tenant for these operations, effective role and explicit filtered grants, session/authentication assurance, and the request correlation ID. Prompt and Privacy Shield services receive only this context's principal and tenant; they remain responsible for domain permission checks.

The configuration repository scope enforces exact equality between its tenant argument and the trusted request tenant, then opens `Database.configuration_context` as restricted `bri_app`. The transaction sets and reads back `bri.tenant_id` and the verified identity setting locally. Read scopes are PostgreSQL read-only; write scopes remain transactional. Forced RLS and migration 0007 grants are unchanged. A GUC is not authentication by itself: only the trusted API constructs the scope and server authorization runs before the service call.

The existing Supabase verifier requires server-verified Auth identity, an active mapped BRI principal/membership, active BRI session, `aal2` and verified TOTP evidence. It is currently hosted-development only, not an approved production identity configuration. Configuration reads may use that verified identity; configuration writes are deliberately restricted to the existing loopback-only synthetic development mode. Synthetic writes cannot be enabled in hosted mode. The API remains read-only for hosted-development Supabase until production auth is separately approved.

Configuration endpoints: GET active tenant prompt; GET prompt version history; POST prompt version; POST restore from prior tenant version; GET active tenant Privacy Shield configuration/signatures; POST tenant signature; PUT tenant signature. They delegate to existing services/repositories. There are no platform prompt or mandatory package management routes, no Admin UI, no AI Gateway/provider, and no production writes in this assignment.


Seeding is never run at API startup. After applying migrations to the verified development target, explicitly run:

```sh
PYTHONPATH=src .venv/bin/python -m scripts.db.seed_synthetic_data --apply
```

The command requires `--apply`, checks the development environment/project and `bri_app` target, and inserts only the two checked-in synthetic municipality/source fixtures. Existing rows are compared and left untouched; any mismatch stops the run. The seed is idempotent. Do not run it against the previous BRI project or production.

## HTTP endpoints

- `GET /health` — database readiness using `bri_app`.
- `GET /v1/organizations/structure` — individually authorized nodes and relationships.
- `GET /v1/organizations/nodes/{node_id}` — one exactly authorized node; inaccessible IDs return 404.
- `GET /v1/knowledge` — approved records in authorized scopes.
- `GET /v1/knowledge/proposals` — pending proposals for authorized reviewers.
- `POST /v1/knowledge/proposals` — create a proposal from an authorized seeded extraction.
- `POST /v1/knowledge/proposals/{proposal_id}/decision` — approve or reject with server-attributed reviewer identity.
- `GET /v1/knowledge/{record_id}` — one approved, authorized record.
- `GET /v1/knowledge/search?q=...` — deterministic evidence retrieval with citations; no external model call.
- `GET /v1/sources/{record_id}` — source version and location for an approved authorized record.
- `GET /v1/configuration/prompts/active` — active tenant prompt version.
- `GET /v1/configuration/prompts/versions` — tenant prompt history.
- `POST /v1/configuration/prompts/versions` — create a tenant prompt draft with expected-latest compare-and-swap.
- `POST /v1/configuration/prompts/versions/{version}/restore` — append a new tenant prompt version from a historical version.
- `GET /v1/configuration/privacy-signatures/active` — tenant jurisdiction, active package metadata and current tenant signatures.
- `POST /v1/configuration/privacy-signatures` — create a tenant signature revision.
- `PUT /v1/configuration/privacy-signatures/{signature_id}` — update a tenant signature as a new revision.

There are no upload, Admin UI, external AI, or production configuration-write routes in this milestone. Hosted-development Supabase authentication is not a production-ready identity configuration; remote configuration mutations fail closed and only local loopback synthetic Admins can write tenant configuration.

## Tests

Run the full suite:

```sh
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
```

Opt into the live database/RLS tests only on the verified development environment:

```sh
PYTHONPATH=src BRI_RUN_DB_TESTS=1 .venv/bin/python -m unittest discover -s tests -v
```

Database integration tests use synthetic rows in rollback-only transactions. The explicit seed command is the only setup workflow that persists the checked-in synthetic municipality/source fixtures. API tests cover tenant/scope isolation, reviewer/proposer permissions, approval/rejection transitions, rejected/unapproved search exclusion, revoked grants, provenance/hash integrity and fail-closed database errors. A live development API check also approved a seeded proposal, restarted uvicorn, and retrieved/search-cited the same approved record with its source/version/extraction/hash intact.
