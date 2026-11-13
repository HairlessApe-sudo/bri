"""Restricted tenant-scoped connections for the local BRI API."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterator
from urllib.parse import parse_qs, unquote, urlsplit
from uuid import UUID

import psycopg

from bri.access.policy import AccessGrant, Principal

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

    def resolve_authenticated_principal(
        self,
        auth_user_id: str,
        issuer: str,
        subject: str,
    ) -> Principal | None:
        """Resolve an Auth-verified provider subject to active BRI roles."""
        try:
            normalized_auth_user_id = str(UUID(auth_user_id))
            normalized_subject = str(UUID(subject))
        except (ValueError, TypeError, AttributeError):
            return None
        if not issuer or len(issuer) > 512:
            return None

        try:
            with self._connect() as connection:
                connection.execute("SET TRANSACTION READ ONLY")
                role = connection.execute("SELECT current_user").fetchone()
                if not role or role[0] != "bri_app":
                    raise DatabaseUnavailable("database login is not the restricted application role")
                connection.execute(
                    "SELECT set_config('bri.auth_user_id', %s, true)",
                    (normalized_auth_user_id,),
                )
                auth_context = connection.execute(
                    "SELECT current_setting('bri.auth_user_id', true)"
                ).fetchone()
                if not auth_context or auth_context[0] != normalized_auth_user_id:
                    raise DatabaseUnavailable("authenticated user context was not established")

                identity = connection.execute(
                    "SELECT p.principal_id::text, p.status "
                    "FROM bri.auth_identity_links i "
                    "JOIN bri.auth_principals p ON p.principal_id=i.principal_id "
                    "WHERE i.auth_user_id=%s AND i.auth_issuer=%s AND i.auth_subject=%s "
                    "AND i.status='active'",
                    (normalized_auth_user_id, issuer, normalized_subject),
                ).fetchone()
                if identity is None or identity[1] != "active":
                    return None

                principal_id = identity[0]
                membership_rows = connection.execute(
                    "SELECT tenant_id FROM bri.auth_tenant_memberships "
                    "WHERE principal_id=%s AND status='active' ORDER BY tenant_id",
                    (principal_id,),
                ).fetchall()
                tenant_ids = frozenset(row[0] for row in membership_rows)
                grants: list[AccessGrant] = []
                for tenant_id in sorted(tenant_ids):
                    connection.execute(
                        "SELECT set_config('bri.tenant_id', %s, true)",
                        (tenant_id,),
                    )
                    tenant_context = connection.execute(
                        "SELECT current_setting('bri.tenant_id', true)"
                    ).fetchone()
                    if not tenant_context or tenant_context[0] != tenant_id:
                        raise DatabaseUnavailable("tenant context was not established")
                    role_rows = connection.execute(
                        "SELECT a.scope_node_id, rp.permission "
                        "FROM bri.auth_role_assignments a "
                        "JOIN bri.role_permissions rp "
                        "ON rp.tenant_id=a.tenant_id AND rp.role_id=a.role_id "
                        "WHERE a.tenant_id=%s AND a.principal_id=%s AND a.status='active' "
                        "ORDER BY a.scope_node_id, rp.permission",
                        (tenant_id, principal_id),
                    ).fetchall()
                    grants.extend(
                        AccessGrant(tenant_id=tenant_id, action=row[1], scope_id=row[0])
                        for row in role_rows
                    )
                return Principal(
                    subject_id=principal_id,
                    tenant_ids=tenant_ids,
                    grants=tuple(grants),
                )
        except DatabaseUnavailable:
            raise
        except psycopg.Error as exc:
            raise DatabaseUnavailable("authenticated identity lookup failed") from exc

    def auth_session_is_active(self, auth_user_id: str, session_id: str) -> bool:
        """Return false for missing, revoked, or expired BRI sessions."""
        try:
            normalized_user = str(UUID(auth_user_id))
            normalized_session = str(UUID(session_id))
        except (ValueError, TypeError, AttributeError):
            return False
        try:
            with self._connect() as connection:
                connection.execute("SET TRANSACTION READ ONLY")
                role = connection.execute("SELECT current_user").fetchone()
                if not role or role[0] != "bri_app":
                    raise DatabaseUnavailable("database login is not the restricted application role")
                self._set_auth_user_context(connection, normalized_user)
                row = connection.execute(
                    "SELECT (expires_at > now() AND revoked_at IS NULL) "
                    "FROM bri.auth_sessions WHERE auth_user_id=%s AND session_id=%s",
                    (normalized_user, normalized_session),
                ).fetchone()
                return bool(row and row[0])
        except DatabaseUnavailable:
            raise
        except psycopg.Error as exc:
            raise DatabaseUnavailable("authenticated session lookup failed") from exc

    def start_auth_session(
        self,
        auth_user_id: str,
        issuer: str,
        subject: str,
        session_id: str,
    ) -> datetime | None:
        """Start an eight-hour BRI session once per Supabase Auth session."""
        try:
            normalized_user = str(UUID(auth_user_id))
            normalized_subject = str(UUID(subject))
            normalized_session = str(UUID(session_id))
        except (ValueError, TypeError, AttributeError):
            return None
        expected_issuer = f"{self.supabase_url.rstrip('/')}/auth/v1"
        if issuer != expected_issuer or normalized_subject != normalized_user:
            return None
        try:
            with self._connect() as connection:
                role = connection.execute("SELECT current_user").fetchone()
                if not role or role[0] != "bri_app":
                    raise DatabaseUnavailable("database login is not the restricted application role")
                self._set_auth_user_context(connection, normalized_user)
                connection.execute(
                    "INSERT INTO bri.auth_sessions (auth_user_id, principal_id, session_id) "
                    "SELECT i.auth_user_id, i.principal_id, %s "
                    "FROM bri.auth_identity_links i "
                    "JOIN bri.auth_principals p ON p.principal_id=i.principal_id "
                    "WHERE i.auth_user_id=%s AND i.auth_issuer=%s AND i.auth_subject=%s "
                    "AND i.status='active' AND p.status='active' "
                    "ON CONFLICT (auth_user_id, session_id) DO NOTHING",
                    (normalized_session, normalized_user, issuer, normalized_subject),
                )
                row = connection.execute(
                    "SELECT expires_at, revoked_at, (expires_at > now()) "
                    "FROM bri.auth_sessions WHERE auth_user_id=%s AND session_id=%s",
                    (normalized_user, normalized_session),
                ).fetchone()
                if row is None or row[1] is not None or not row[2]:
                    return None
                return row[0]
        except DatabaseUnavailable:
            raise
        except psycopg.Error as exc:
            raise DatabaseUnavailable("authenticated session could not be started") from exc

    def revoke_auth_session(self, auth_user_id: str, session_id: str) -> bool:
        """Revoke the current BRI application session without exposing token data."""
        try:
            normalized_user = str(UUID(auth_user_id))
            normalized_session = str(UUID(session_id))
        except (ValueError, TypeError, AttributeError):
            return False
        try:
            with self._connect() as connection:
                role = connection.execute("SELECT current_user").fetchone()
                if not role or role[0] != "bri_app":
                    raise DatabaseUnavailable("database login is not the restricted application role")
                self._set_auth_user_context(connection, normalized_user)
                row = connection.execute(
                    "UPDATE bri.auth_sessions SET revoked_at=now() "
                    "WHERE auth_user_id=%s AND session_id=%s AND revoked_at IS NULL "
                    "RETURNING session_id",
                    (normalized_user, normalized_session),
                ).fetchone()
                return row is not None
        except DatabaseUnavailable:
            raise
        except psycopg.Error as exc:
            raise DatabaseUnavailable("authenticated session could not be revoked") from exc

    @staticmethod
    def _set_auth_user_context(connection: Any, auth_user_id: str) -> None:
        connection.execute(
            "SELECT set_config('bri.auth_user_id', %s, true)",
            (auth_user_id,),
        )
        context = connection.execute(
            "SELECT current_setting('bri.auth_user_id', true)"
        ).fetchone()
        if not context or context[0] != auth_user_id:
            raise DatabaseUnavailable("authenticated user context was not established")

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
