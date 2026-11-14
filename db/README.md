# Supabase PostgreSQL development database

Scope: the new BRI development Supabase project only, project reference `bwqdyibvuecgthtatrtv`. Use synthetic data only. The previous BRI project, Supabase-managed schemas (`auth`, `storage`, etc.), and production remain out of scope. No Docker is required.

## Local configuration and roles

Keep `.env.local` on the developer machine; it is ignored by Git. Never print, log, paste, commit or expose its values. Required initial configuration is `BRI_ENVIRONMENT=development`, `SUPABASE_URL`, and the privileged one-time setup `MIGRATION_DATABASE_URL`. The API URL's project reference and the PostgreSQL connection's project reference must match the approved reference before setup proceeds. The API project reference is extracted only from `https://PROJECT_REF.supabase.co`. For this project's shared Session Pooler URL, require the exact host `aws-1-eu-west-1.pooler.supabase.com`, port `5432`, and a username ending in `.PROJECT_REF`; do not infer identity from a matching username or arbitrary `*.pooler.supabase.com` host. Direct database connections require `db.PROJECT_REF.supabase.co:5432`.

Install requirements, then bootstrap the dedicated database roles:

```sh
.venv/bin/pip install -r requirements.txt
.venv/bin/python scripts/db/bootstrap_roles.py
```

The bootstrap uses `MIGRATION_DATABASE_URL` only for one-time role/schema provisioning. It creates `bri_app` and `bri_migrator` as non-superuser, non-BYPASSRLS, non-CREATEDB, non-CREATEROLE, NOINHERIT login roles that are not members of any other role; development connection limits are 10 app sessions and 2 migration sessions as conservative pilot ceilings, subject to measured-demand review. Supabase creates one provider-managed membership edge per role: `postgres` is granted that role by `supabase_admin` with admin option on but inheritance and SET ROLE disabled. The bootstrap rejects every other membership edge. This provider-managed grant cannot be revoked through the project SQL role; it allows the trusted `postgres` administrator to manage the role but does not grant it inherited or `SET ROLE` privileges. See the [Supabase role-membership guidance](https://supabase.com/kb/troubleshooting/cant-revoke-a-role-membership-granted-by-supabase_admin-d08922). It creates the `bri` schema owned by `bri_migrator`, without changing Supabase-managed schemas. Generated passwords and role-specific pooler URLs are written locally to ignored `.env.local`; they are never printed. `DATABASE_URL` is set to the restricted application role. `BRI_MIGRATION_ROLE_DATABASE_URL` is set to the restricted migration role. The privileged `MIGRATION_DATABASE_URL` is not for app traffic or ordinary migrations.

Application/runtime code must use only `DATABASE_URL`. Run schema changes with the restricted migration URL:

```sh
.venv/bin/python scripts/db/migrate.py
```

Keep `.env.local` private. Re-running bootstrap validates existing roles and preserves their locally stored URLs; it does not rotate passwords for existing roles. For a missing role URL or password recovery, use the Supabase project administrator's approved role-management process, then update the corresponding local URL without printing it. Never paste a URL into chat or a log. For manual configuration, set `DATABASE_URL` to the Supabase Session Pooler URL with username `bri_app.PROJECT_REF` and the password already generated/stored locally by bootstrap; do not use the privileged `postgres.PROJECT_REF` credentials. This project has a dedicated expected reference; verify it locally rather than copying secrets between projects.

## Tenant context and authorization

All tenant-owned application tables live in `bri`; tenant identifiers participate in primary/composite foreign keys, including hierarchy, relationship, role and assignment references. Every tenant-owned table has RLS enabled and FORCE ROW LEVEL SECURITY. Policies fail closed when transaction context `bri.tenant_id` is absent and reject writes whose tenant does not match that context.

After authenticating a principal and resolving its active tenant membership and exact resource scope, the application must begin a transaction and set context transaction-locally, using a parameterized call such as:

```sql
SELECT set_config('bri.tenant_id', $1, true);
```

Do not accept tenant context as authority from an untrusted client. The custom PostgreSQL setting is caller-settable by a holder of the application database credential; RLS here is a tenant filter/defense-in-depth boundary, not authentication or a replacement for application authorization. Keep `DATABASE_URL` exclusively on the trusted server. Apply explicit scope authorization in application logic; do not infer scope inheritance from organizational hierarchy or relationship edges. All database requests/tasks must execute in transactions that establish context and clear it automatically at transaction end.

`synthetic_principals` is explicitly constrained to synthetic records. Database/API startup never seeds fixture data. Integration tests load fixtures in rollback-only transactions; the separate `scripts.db.seed_synthetic_data --apply` command is the explicit, idempotent path for persisting the two fictional municipalities, their synthetic identities/permissions and synthetic source/version/extraction rows. It requires the approved development target and `bri_app`; it verifies existing keys and fails on differing values rather than overwriting them.

## Migrations and tests

Migrations are ordered SQL files under `db/migrations/` and recorded with SHA-256 checksums in `bri.schema_migrations`. Applied migration files are immutable; the runner rejects checksum mismatches. The one-time legacy upgrade accepts only the pinned hashes for `0001_tenant_foundation` and `0002_immediate_parent_fk`; changed or unknown legacy files fail closed rather than being re-baselined. For migrations after the initial legacy files, include only schema/data statements: the runner wraps each new file and its ledger/checksum entry in one transaction. Do not add `BEGIN`/`COMMIT` or manual ledger inserts to new migration files. Apply them with `bri_migrator`; do not run as the application role or privileged bootstrap role. Migration `0004_knowledge_lifecycle.sql` adds tenant-scoped source records/versions/extractions, proposals, validation decisions and approved knowledge. Migration `0005_source_version_provenance_fk.sql` adds the composite tenant/source/version/hash/location FK to the exact source-version row. All six knowledge tables use forced RLS; `bri_app` receives SELECT/INSERT only, and validated rows reference an approved decision. The application performs permission/scope checks and verifies extracted-content hashes. Migration `0006_auth_identity_and_sessions.sql` adds provider-independent principals, tenant memberships, exact role assignments, SuperAdmin status, tenant-admin governance, server sessions and metadata-only security audit events. Migration `0007_durable_configuration.sql` adds immutable prompt/signature/configuration revisions, approval/activation pointers, forced RLS, platform SuperAdmin boundaries, metadata-only audit, and append-only runtime grants. The migration seeds version 1 activation metadata for the code-owned global, Netherlands and Australia detector packages; the actual detector algorithms remain in Python and are not replaced by database data. It does not add a service-role or BYPASSRLS path. The durable repository tests require a separate loopback disposable PostgreSQL instance and explicit `BRI_DURABLE_TEST_ADMIN_DSN` / `BRI_DURABLE_TEST_APP_DSN`; never point these at shared Supabase. The local test suite's database helpers are not permission to apply migrations remotely.

Run the complete unit suite:

```sh
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
```

Run all live Supabase integration tests explicitly on the verified development target:

```sh
PYTHONPATH=src BRI_RUN_DB_TESTS=1 .venv/bin/python -m unittest discover -s tests -v
```

For first-time synthetic seed creation or exact-value verification, run this explicitly after migrations; it is not part of tests or API startup:

```sh
PYTHONPATH=src .venv/bin/python -m scripts.db.seed_synthetic_data --apply
```

Database integration tests require `DATABASE_URL` to connect as `bri_app`. Each test inserts the synthetic fixture in its own transaction and registers unconditional rollback/close cleanup, including when setup fails. Tests never truncate, delete, or reset persistent data. They cover tenant-filtered reads/writes, missing-context denial, composite-FK rejection, forced RLS and table privileges for all knowledge lifecycle tables, plus role attributes, non-ownership and the role-membership allowlist. Pure unit tests cover endpoint validation, seed no-overwrite/idempotency, legacy migration pinning and ledger states.

## Trusted API configuration context

Configuration repository operations are built from `TrustedRequestContext`, not request headers. The API uses a server-resolved single tenant and rejects repository scope arguments that differ from it. `Database.configuration_context` establishes transaction-local tenant and verified identity GUCs using `bri_app`; it confirms the resulting values and marks read transactions read-only. Synthetic identity GUCs are used only in loopback local development. Hosted Supabase reads require the existing verified Auth-to-BRI identity map, active BRI session and AAL2/TOTP assurance; no production identity project is approved. Configuration writes remain synthetic-development-only. This does not weaken or bypass forced RLS, replace service authorization, or add a service-role path.

The tenant configuration API composes migration 0007's prompt, tenant signature and Shield-configuration repositories with their existing managers. Its endpoints are documented in `api/README.md`. No Assignment 09 migration was needed; migration 0007 was not edited or applied to the shared database.

## Known limits

Read-only privilege review found that `bri_app` has no access to Supabase service schemas or non-BRI application relations, sequences or functions, but retains the Supabase defaults that grant database `TEMP` and execute on `pg_catalog.lo_create` to `PUBLIC`. Supabase states these grants cannot be removed without affecting its services and recommends limiting role connections; this project caps `bri_app` at 10 and `bri_migrator` at 2 (conservative pilot ceilings, to be revisited against measured demand). The limits do not remove per-session temporary/large-object disk-use risk. The current project has no observed `net` schema access; re-audit before enabling `pg_net`, which Supabase notes can expose queued request headers to roles with `net` access. See [Supabase's PUBLIC privilege guidance](https://supabase.com/kb/troubleshooting/custom-role-inherits-privileges-that-were-not-explicitly-granted-ddaa1c). Treat this as synthetic-development-only; production security approval must decide whether a stricter isolated database/role model is required. Context is set by trusted application code; a compromised application credential could choose another tenant context. Application authorization, credential isolation/rotation, audited access, threat modeling, backup/recovery, migration rollback policy, production identity and deployment remain separate gates. Supabase documents direct connections for migration/backup/restore tasks and the shared Session Pooler as an IPv4-accessible alternative; this assignment used the configured Session Pooler (`5432`) and verified migrations there. Direct-connection mode has not been tested; if switching connection mode, re-check the project reference before connecting. Do not use real customer or municipal data.
