"""Apply checked-in SQL migrations through the non-privileged migration role."""
from __future__ import annotations

import hashlib
import hmac
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

import psycopg

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_REF = "bwqdyibvuecgthtatrtv"
EXPECTED_POOLER_HOST = "aws-1-eu-west-1.pooler.supabase.com"
# Immutable digests for the two already-applied legacy migrations; don't rebaseline edited SQL.
LEGACY_MIGRATION_CHECKSUMS = {
    "0001_tenant_foundation": "63c6db848986b4dfd1a4c91c6005667b929a9b1d39ad648ea734cb55d3e81a1b",
    "0002_immediate_parent_fk": "f57d9b41a21665394e9c79add79ecbdc32d74d4eb556840cb86a149b33e638ca",
}


def env_values() -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in (ROOT / ".env.local").read_text(encoding="utf-8").splitlines():
        line = raw.strip().removeprefix("export ").strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        result[key.strip()] = value
    return result


def ref_from(value: str) -> str | None:
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower()
    username = unquote(parsed.username or "")
    try:
        port = parsed.port
    except ValueError:
        return None
    if parsed.scheme == "https" and port in (None, 443):
        api_match = re.fullmatch(r"([a-z0-9]{20})\.supabase\.co", host)
        if api_match:
            return api_match.group(1)
    match = re.fullmatch(r"db\.([a-z0-9]{20})\.supabase\.co", host) if port == 5432 else None
    if match:
        return match.group(1)
    if host != EXPECTED_POOLER_HOST or port != 5432:
        return None
    match = re.fullmatch(r"[^.]+\.([a-z0-9]{20})", username)
    return match.group(1) if match else None


def validate_ledger_checksum_state(
    *, ledger_exists: bool, checksums_enabled: bool, marker_exists: bool
) -> None:
    """Reject an impossible ledger state instead of blessing an old baseline."""
    if marker_exists and (not ledger_exists or not checksums_enabled):
        raise ValueError("checksum migration marker exists without checksum support")


def validate_role_memberships(
    *, member_of_roles: bool, grants: list[tuple[str, str, bool, bool, bool]]
) -> None:
    """Allow no inherited grants; tolerate only Supabase's fixed postgres admin edge."""
    allowed = ("postgres", "supabase_admin", True, False, False)
    if member_of_roles or (grants and grants != [allowed]):
        raise ValueError("dedicated role has unexpected role memberships")


def validate_legacy_ledger_versions(recorded_versions: set[str], *, require_complete: bool) -> None:
    """Allow only the pinned legacy versions; require both before checksum baseline."""
    trusted = set(LEGACY_MIGRATION_CHECKSUMS)
    if not recorded_versions <= trusted:
        raise ValueError("legacy migration ledger contains unknown versions")
    if require_complete and recorded_versions != trusted:
        raise ValueError("legacy migration ledger is incomplete")


def validate_checksum(recorded: str | None, actual: str, *, version: str, allow_baseline: bool) -> bool:
    """Validate a recorded digest or an immutable, explicitly trusted legacy baseline."""
    if recorded is None:
        if allow_baseline:
            trusted = LEGACY_MIGRATION_CHECKSUMS.get(version)
            if trusted and hmac.compare_digest(trusted, actual):
                return False
            raise ValueError("legacy migration differs from its trusted checksum baseline")
        raise ValueError("applied migration has no checksum")
    if not hmac.compare_digest(recorded, actual):
        raise ValueError("applied migration checksum differs from the checked-in file")
    return True


def file_checksum(path: Path) -> str:
    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def validate_legacy_migration_files(migrations: list[Path]) -> None:
    """Require the checked-in legacy SQL to match pinned digests before execution."""
    paths = {path.stem: path for path in migrations if path.stem in LEGACY_MIGRATION_CHECKSUMS}
    if set(paths) != set(LEGACY_MIGRATION_CHECKSUMS):
        raise ValueError("a trusted legacy migration file is missing")
    for version, path in paths.items():
        validate_checksum(None, file_checksum(path), version=version, allow_baseline=True)


def checksum_column_exists(conn: psycopg.Connection) -> bool:
    return conn.execute(
        "SELECT EXISTS (SELECT 1 FROM information_schema.columns "
        "WHERE table_schema='bri' AND table_name='schema_migrations' AND column_name='checksum')"
    ).fetchone()[0]


def verify_ledger(conn: psycopg.Connection, migrations: list[Path]) -> None:
    known = {path.stem: file_checksum(path) for path in migrations}
    rows = conn.execute("SELECT version, checksum FROM bri.schema_migrations ORDER BY version").fetchall()
    if not any(version == "0003_migration_checksums" for version, _ in rows):
        raise ValueError("checksum migration marker is missing")
    for version, recorded in rows:
        if version not in known:
            raise ValueError("database contains a migration absent from this checkout")
        validate_checksum(recorded, known[version], version=version, allow_baseline=False)


def main() -> int:
    try:
        env = env_values()
    except Exception:
        print("MIGRATE_STOP environment_file_unavailable")
        return 2
    api_ref = ref_from(env.get("SUPABASE_URL", ""))
    migration_url = env.get("BRI_MIGRATION_ROLE_DATABASE_URL", "")
    if env.get("BRI_ENVIRONMENT", "").lower() not in {"development", "dev", "local"}:
        print("MIGRATE_STOP environment_not_development")
        return 2
    if api_ref != EXPECTED_REF or ref_from(migration_url) != api_ref or not migration_url:
        print("MIGRATE_STOP project_reference_mismatch")
        return 2

    migrations = sorted((ROOT / "db/migrations").glob("[0-9]*_*.sql"))
    if not migrations:
        print("MIGRATE_STOP no_migrations_found")
        return 2
    try:
        validate_legacy_migration_files(migrations)
    except ValueError:
        print("MIGRATE_STOP legacy_migration_baseline_mismatch")
        return 4
    applied: list[str] = []
    try:
        with psycopg.connect(migration_url, connect_timeout=12, autocommit=True) as conn:
            row = conn.execute(
                "SELECT current_user, r.rolsuper, r.rolbypassrls, r.rolcreatedb, "
                "r.rolcreaterole, r.rolinherit, r.rolcanlogin, r.rolconnlimit "
                "FROM pg_roles r WHERE r.rolname=current_user"
            ).fetchone()
            if not row or row != ("bri_migrator", False, False, False, False, False, True, 2):
                print("MIGRATE_STOP migration_connection_not_restricted_role")
                return 3
            member_of_roles = conn.execute(
                "SELECT EXISTS (SELECT 1 FROM pg_auth_members m "
                "JOIN pg_roles r ON r.oid=m.member WHERE r.rolname=current_user)"
            ).fetchone()[0]
            grants = conn.execute(
                "SELECT member.rolname, grantor.rolname, m.admin_option, m.inherit_option, m.set_option "
                "FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid "
                "JOIN pg_roles member ON member.oid=m.member "
                "JOIN pg_roles grantor ON grantor.oid=m.grantor "
                "WHERE r.rolname=current_user ORDER BY member.rolname"
            ).fetchall()
            try:
                validate_role_memberships(member_of_roles=member_of_roles, grants=grants)
            except ValueError:
                print("MIGRATE_STOP migration_role_membership_not_restricted")
                return 3

            ledger_exists = conn.execute(
                "SELECT to_regclass('bri.schema_migrations') IS NOT NULL"
            ).fetchone()[0]
            checksums_enabled = checksum_column_exists(conn)
            marker_exists = bool(
                conn.execute(
                    "SELECT 1 FROM bri.schema_migrations WHERE version='0003_migration_checksums'"
                ).fetchone()
            ) if ledger_exists else False
            validate_ledger_checksum_state(
                ledger_exists=ledger_exists,
                checksums_enabled=checksums_enabled,
                marker_exists=marker_exists,
            )
            if ledger_exists and not checksums_enabled:
                legacy_versions = {
                    row[0] for row in conn.execute("SELECT version FROM bri.schema_migrations").fetchall()
                }
                validate_legacy_ledger_versions(legacy_versions, require_complete=False)
            if checksums_enabled:
                verify_ledger(conn, migrations)

            for path in migrations:
                version = path.stem
                if not re.fullmatch(r"[0-9]{4}_[a-z0-9_]+", version):
                    print("MIGRATE_STOP invalid_migration_filename")
                    return 4
                digest = file_checksum(path)
                exists = conn.execute("SELECT to_regclass('bri.schema_migrations')").fetchone()[0]
                recorded = None
                if exists:
                    if checksum_column_exists(conn):
                        row = conn.execute(
                            "SELECT checksum FROM bri.schema_migrations WHERE version=%s", (version,)
                        ).fetchone()
                        if row:
                            recorded = row[0]
                            validate_checksum(recorded, digest, version=version, allow_baseline=False)
                            continue
                    elif conn.execute(
                        "SELECT 1 FROM bri.schema_migrations WHERE version=%s", (version,)
                    ).fetchone():
                        continue

                if version in {"0001_tenant_foundation", "0002_immediate_parent_fk"}:
                    # Original migrations manage their own transaction and ledger row.
                    conn.execute(path.read_text(encoding="utf-8"))
                    if not conn.execute(
                        "SELECT 1 FROM bri.schema_migrations WHERE version=%s", (version,)
                    ).fetchone():
                        raise RuntimeError("legacy migration did not record its version")
                else:
                    # New migrations and their checksums commit atomically.
                    with conn.transaction():
                        conn.execute(path.read_text(encoding="utf-8"))
                        if not checksum_column_exists(conn):
                            raise RuntimeError("checksum support must precede new migrations")
                        if version == "0003_migration_checksums":
                            # One-time checksum baseline for the exact pinned legacy ledger.
                            recorded_legacy = {
                                row[0] for row in conn.execute(
                                    "SELECT version FROM bri.schema_migrations"
                                ).fetchall()
                            }
                            validate_legacy_ledger_versions(recorded_legacy, require_complete=True)
                            for old_path in migrations:
                                if old_path.stem >= version:
                                    continue
                                old_row = conn.execute(
                                    "SELECT checksum FROM bri.schema_migrations WHERE version=%s",
                                    (old_path.stem,),
                                ).fetchone()
                                if not old_row:
                                    raise RuntimeError("legacy migration record is missing")
                                old_digest = file_checksum(old_path)
                                validate_checksum(
                                    old_row[0], old_digest, version=old_path.stem, allow_baseline=True
                                )
                                conn.execute(
                                    "UPDATE bri.schema_migrations SET checksum=%s WHERE version=%s",
                                    (old_digest, old_path.stem),
                                )
                        conn.execute(
                            "INSERT INTO bri.schema_migrations (version, checksum) VALUES (%s, %s)",
                            (version, digest),
                        )
                applied.append(version)

            if not checksum_column_exists(conn):
                raise RuntimeError("checksum migration support is missing")
            verify_ledger(conn, migrations)
    except Exception as exc:
        print("MIGRATE_FAIL " + type(exc).__name__)
        return 5
    print("MIGRATE_OK")
    print("applied_count=" + str(len(applied)))
    print("applied_versions=" + (",".join(applied) if applied else "none"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
