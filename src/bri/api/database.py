"""Restricted tenant-scoped connections for the local BRI API."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator
from urllib.parse import parse_qs, unquote, urlsplit

import psycopg

EXPECTED_PROJECT_REF = "bwqdyibvuecgthtatrtv"
EXPECTED_POOLER_HOST = "aws-1-eu-west-1.pooler.supabase.com"


class DatabaseUnavailable(RuntimeError):
    """A generic database failure safe to return to an API client."""


@dataclass(frozen=True, slots=True)
class TenantSession:
    tenant_id: str
    connection: object | None = field(repr=False, compare=False)


def is_approved_app_target(supabase_url: str, database_url: str) -> bool:
    """Accept only the approved development project and the bri_app login."""
    try:
        api = urlsplit(supabase_url)
        api_host = (api.hostname or "").lower()
        api_port = api.port
        db = urlsplit(database_url)
        db_host = (db.hostname or "").lower()
        db_port = db.port
        db_user = unquote(db.username or "")
        query = parse_qs(db.query, keep_blank_values=True)
    except ValueError:
        return False

    expected_api_host = f"{EXPECTED_PROJECT_REF}.supabase.co"
    if (
        api.scheme != "https"
        or api_host != expected_api_host
        or api_port not in (None, 443)
        or api.username is not None
        or api.password is not None
        or api.path not in ("", "/")
        or api.query
        or api.fragment
    ):
        return False

    ssl_modes = query.get("sslmode", [])
    if (
        db.scheme not in {"postgres", "postgresql"}
        or db.path != "/postgres"
        or db.fragment
        or set(query) - {"sslmode"}
        or len(ssl_modes) > 1
        or (ssl_modes and ssl_modes[0] not in {"require", "verify-ca", "verify-full"})
    ):
        return False

    if db_host == EXPECTED_POOLER_HOST and db_port == 5432:
        return db_user == f"bri_app.{EXPECTED_PROJECT_REF}"
    if db_host == f"db.{EXPECTED_PROJECT_REF}.supabase.co" and db_port == 5432:
        return db_user == "bri_app"
    return False


@dataclass(slots=True)
class Database:
    supabase_url: str = field(repr=False)
    database_url: str = field(repr=False)
    connect_timeout: int = 5

    def _connect(self):
        if not is_approved_app_target(self.supabase_url, self.database_url):
            raise DatabaseUnavailable("database target or role is not approved")
        try:
            ssl_modes = parse_qs(urlsplit(self.database_url).query).get("sslmode", [])
            ssl_mode = ssl_modes[0] if ssl_modes else "require"
            return psycopg.connect(
                self.database_url,
                connect_timeout=self.connect_timeout,
                sslmode=ssl_mode,
            )
        except psycopg.Error as exc:
            raise DatabaseUnavailable("database connection failed") from exc

    def healthcheck(self) -> None:
        try:
            with self._connect() as connection:
                connection.execute("SET TRANSACTION READ ONLY")
                row = connection.execute("SELECT current_user").fetchone()
                if not row or row[0] != "bri_app":
                    raise DatabaseUnavailable("database login is not the restricted application role")
        except DatabaseUnavailable:
            raise
        except psycopg.Error as exc:
            raise DatabaseUnavailable("database health check failed") from exc

    @contextmanager
    def _tenant_transaction(self, tenant_id: str, *, read_only: bool) -> Iterator[TenantSession]:
        try:
            with self._connect() as connection:
                if read_only:
                    connection.execute("SET TRANSACTION READ ONLY")
                role = connection.execute("SELECT current_user").fetchone()
                if not role or role[0] != "bri_app":
                    raise DatabaseUnavailable("database login is not the restricted application role")
                connection.execute(
                    "SELECT set_config('bri.tenant_id', %s, true)",
                    (tenant_id,),
                )
                context = connection.execute(
                    "SELECT current_setting('bri.tenant_id', true)"
                ).fetchone()
                if not context or context[0] != tenant_id:
                    raise DatabaseUnavailable("tenant context was not established")
                connection.execute("SELECT count(*) FROM bri.tenants").fetchone()
                yield TenantSession(tenant_id=tenant_id, connection=connection)
        except DatabaseUnavailable:
            raise
        except psycopg.Error as exc:
            raise DatabaseUnavailable("tenant database context failed") from exc

    @contextmanager
    def tenant_context(self, tenant_id: str) -> Iterator[TenantSession]:
        """Open a read-only RLS transaction for one server-resolved tenant."""
        with self._tenant_transaction(tenant_id, read_only=True) as session:
            yield session

    @contextmanager
    def write_tenant_context(self, tenant_id: str) -> Iterator[TenantSession]:
        """Open a read/write RLS transaction for one server-resolved tenant."""
        with self._tenant_transaction(tenant_id, read_only=False) as session:
            yield session
