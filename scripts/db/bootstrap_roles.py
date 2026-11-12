"""One-time least-privilege BRI development-role bootstrap.

Reads credentials only from the ignored local .env.local and never displays them.
The privileged MIGRATION_DATABASE_URL is used only for this setup operation.
"""
from __future__ import annotations

import os
import re
import secrets
import tempfile
from pathlib import Path
from urllib.parse import quote, unquote, urlparse, urlunparse

import psycopg
from psycopg import sql

ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = ROOT / ".env.local"
EXPECTED_PROJECT_REF = "bwqdyibvuecgthtatrtv"
EXPECTED_POOLER_HOST = "aws-1-eu-west-1.pooler.supabase.com"
APP_ROLE = "bri_app"
MIGRATOR_ROLE = "bri_migrator"
ROLE_CONNECTION_LIMITS = {APP_ROLE: 10, MIGRATOR_ROLE: 2}


def read_env() -> tuple[dict[str, str], list[str]]:
    lines = ENV_FILE.read_text(encoding="utf-8").splitlines()
    values: dict[str, str] = {}
    for raw in lines:
        line = raw.strip().removeprefix("export ").strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values, lines


def project_ref(value: str) -> tuple[str | None, str]:
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower()
    username = unquote(parsed.username or "")
    try:
        port = parsed.port
    except ValueError:
        return None, "unrecognized"
    if parsed.scheme == "https" and port in (None, 443):
        api_match = re.fullmatch(r"([a-z0-9]{20})\.supabase\.co", host)
        if api_match:
            return api_match.group(1), "hostname"

    match = re.fullmatch(r"db\.([a-z0-9]{20})\.supabase\.co", host) if port == 5432 else None
    if match:
        return match.group(1), "hostname"
    if host != EXPECTED_POOLER_HOST or port != 5432:
        return None, "unrecognized"
    match = re.fullmatch(r"[^.]+\.([a-z0-9]{20})", username)
    if match:
        return match.group(1), "username"
    return None, "unrecognized"


def pooler_url(source: str, role: str, password: str, ref: str) -> str:
    parsed = urlparse(source)
    host = parsed.hostname or ""
    username = f"{role}.{ref}" if host.lower() == EXPECTED_POOLER_HOST else role
    hostport = f"[{host}]" if ":" in host else host
    if parsed.port:
        hostport += f":{parsed.port}"
    netloc = f"{quote(username, safe='')}:{quote(password, safe='')}@{hostport}"
    return urlunparse((parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))


def role_url_matches(value: str, role: str, ref: str) -> bool:
    if project_ref(value)[0] != ref:
        return False
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower()
    expected_username = f"{role}.{ref}" if host == EXPECTED_POOLER_HOST else role
    return unquote(parsed.username or "") == expected_username


def write_env(values: dict[str, str], original_lines: list[str]) -> None:
    managed = {
        "DATABASE_URL": values["DATABASE_URL"],
        "BRI_MIGRATION_ROLE_DATABASE_URL": values["BRI_MIGRATION_ROLE_DATABASE_URL"],
    }
    kept: list[str] = []
    for line in original_lines:
        stripped = line.strip().removeprefix("export ").strip()
        key = stripped.split("=", 1)[0].strip() if "=" in stripped else ""
        if key not in managed:
            kept.append(line)
    kept.extend(f"{key}={value}" for key, value in managed.items())
    fd, tmp_name = tempfile.mkstemp(prefix=".env.local.", dir=ROOT, text=True)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write("\n".join(kept) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp_name, ENV_FILE)
        try:
            os.chmod(ENV_FILE, 0o600)
        except OSError:
            pass
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def main() -> int:
    if not ENV_FILE.is_file():
        print("BOOTSTRAP_STOP env_file_missing")
        return 2
    values, original = read_env()
    api_ref, _ = project_ref(values.get("SUPABASE_URL", ""))
    admin_url = values.get("MIGRATION_DATABASE_URL", "")
    admin_ref, _ = project_ref(admin_url)
    if values.get("BRI_ENVIRONMENT", "").lower() not in {"development", "dev", "local"}:
        print("BOOTSTRAP_STOP environment_not_development")
        return 2
    if api_ref != EXPECTED_PROJECT_REF or admin_ref != api_ref or not admin_url:
        print("BOOTSTRAP_STOP project_reference_mismatch")
        return 2

    new_passwords: dict[str, str] = {}
    try:
        with psycopg.connect(admin_url, connect_timeout=12) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT current_user, rolcreaterole FROM pg_roles WHERE rolname=current_user")
                connected_role, can_create_roles = cur.fetchone()
                if not can_create_roles or connected_role != "postgres":
                    print("BOOTSTRAP_STOP privileged_role_lacks_required_role_admin")
                    return 3

                cur.execute("SELECT r.rolname FROM pg_namespace n JOIN pg_roles r ON r.oid=n.nspowner WHERE n.nspname='bri'")
                existing_owner = cur.fetchone()
                if existing_owner and existing_owner[0] != MIGRATOR_ROLE:
                    raise RuntimeError("application schema has an unexpected owner")

                for name in (APP_ROLE, MIGRATOR_ROLE):
                    cur.execute(
                        "SELECT rolcanlogin, rolsuper, rolbypassrls, rolcreatedb, rolcreaterole, rolinherit, rolconnlimit "
                        "FROM pg_roles WHERE rolname=%s",
                        (name,),
                    )
                    existing_attributes = cur.fetchone()
                    connection_limit = ROLE_CONNECTION_LIMITS[name]
                    if existing_attributes is None:
                        password = secrets.token_urlsafe(36)
                        statement = sql.SQL(
                            "CREATE ROLE {} LOGIN PASSWORD {} NOSUPERUSER NOCREATEDB "
                            "NOCREATEROLE NOINHERIT NOBYPASSRLS CONNECTION LIMIT {}"
                        ).format(sql.Identifier(name), sql.Literal(password), sql.Literal(connection_limit))
                        cur.execute(statement)
                        new_passwords[name] = password
                    else:
                        if existing_attributes[:6] != (True, False, False, False, False, False):
                            raise RuntimeError("existing dedicated role has unexpected attributes")
                        if existing_attributes[6] != connection_limit:
                            cur.execute(
                                sql.SQL("ALTER ROLE {} CONNECTION LIMIT {}").format(
                                    sql.Identifier(name), sql.Literal(connection_limit)
                                )
                            )

                    cur.execute(
                        "SELECT rolcanlogin, rolsuper, rolbypassrls, rolcreatedb, rolcreaterole, rolinherit, rolconnlimit "
                        "FROM pg_roles WHERE rolname=%s",
                        (name,),
                    )
                    if cur.fetchone() != (True, False, False, False, False, False, connection_limit):
                        raise RuntimeError("dedicated role attributes are not restricted")
                    cur.execute(
                        "SELECT EXISTS (SELECT 1 FROM pg_auth_members m "
                        "JOIN pg_roles r ON r.oid=m.member WHERE r.rolname=%s)",
                        (name,),
                    )
                    member_of_roles = cur.fetchone()[0]
                    cur.execute(
                        "SELECT member.rolname, grantor.rolname, m.admin_option, m.inherit_option, m.set_option "
                        "FROM pg_auth_members m JOIN pg_roles r ON r.oid=m.roleid "
                        "JOIN pg_roles member ON member.oid=m.member "
                        "JOIN pg_roles grantor ON grantor.oid=m.grantor "
                        "WHERE r.rolname=%s ORDER BY member.rolname",
                        (name,),
                    )
                    grants = cur.fetchall()
                    expected_supabase_grant = [("postgres", "supabase_admin", True, False, False)]
                    if member_of_roles or (grants and grants != expected_supabase_grant):
                        raise RuntimeError("dedicated role has unexpected role memberships")
                    url_key = "DATABASE_URL" if name == APP_ROLE else "BRI_MIGRATION_ROLE_DATABASE_URL"
                    if name not in new_passwords and not role_url_matches(values.get(url_key, ""), name, api_ref):
                        raise RuntimeError("existing dedicated role URL is missing or targets another project")

                cur.execute("SELECT 1 FROM pg_namespace WHERE nspname='bri'")
                if cur.fetchone() is None:
                    cur.execute(sql.SQL("GRANT {} TO postgres WITH SET TRUE, INHERIT FALSE").format(sql.Identifier(MIGRATOR_ROLE)))
                    cur.execute(sql.SQL("CREATE SCHEMA bri AUTHORIZATION {}").format(sql.Identifier(MIGRATOR_ROLE)))
                    cur.execute(sql.SQL("REVOKE {} FROM postgres").format(sql.Identifier(MIGRATOR_ROLE)))
                cur.execute(sql.SQL("REVOKE ALL ON SCHEMA bri FROM PUBLIC, {}").format(sql.Identifier(APP_ROLE)))

            # Transaction commits here; no credential-bearing values are returned.
        if APP_ROLE in new_passwords:
            values["DATABASE_URL"] = pooler_url(
                admin_url, APP_ROLE, new_passwords[APP_ROLE], api_ref
            )
        if MIGRATOR_ROLE in new_passwords:
            values["BRI_MIGRATION_ROLE_DATABASE_URL"] = pooler_url(
                admin_url, MIGRATOR_ROLE, new_passwords[MIGRATOR_ROLE], api_ref
            )
        if new_passwords:
            write_env(values, original)
    except psycopg.Error as exc:
        print("BOOTSTRAP_FAIL " + type(exc).__name__)
        print("sqlstate=" + str(exc.sqlstate or "unknown"))
        print("database_message=" + str(exc.diag.message_primary or "unavailable"))
        return 5
    except Exception as exc:
        print("BOOTSTRAP_FAIL " + type(exc).__name__)
        return 5

    print("BOOTSTRAP_OK")
    print("application_role=bri_app; superuser=false; bypassrls=false; createdb=false; createrole=false; connection_limit=10")
    print("migration_role=bri_migrator; superuser=false; bypassrls=false; createdb=false; createrole=false; connection_limit=2")
    if new_passwords:
        print("database_urls_written_to_ignored_env_file=true")
    else:
        print("existing_role_urls_preserved=true")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
