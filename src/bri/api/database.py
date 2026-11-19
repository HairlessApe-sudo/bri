"""Restricted tenant-scoped connections for the local BRI API."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Iterator
from urllib.parse import parse_qs, unquote, urlsplit
from uuid import UUID, uuid4

import psycopg

from bri.access.policy import AccessGrant, Principal
from bri.access.roles import CONFIGURATION_PERMISSIONS, role_allows_permission

EXPECTED_PROJECT_REF = "bwqdyibvuecgthtatrtv"
EXPECTED_POOLER_HOST = "aws-1-eu-west-1.pooler.supabase.com"


# Shared by preflight and the independent protected transaction. Older rows
# may have a valid-looking stored expiry later than the hard BRI deadline.
_LIVE_SESSION_SQL = (
    "s.revoked_at IS NULL AND s.started_at <= clock_timestamp() "
    "AND clock_timestamp() < LEAST(s.expires_at, s.started_at + interval '8 hours')"
)


class ProtectedAccessDenied(PermissionError):
    """The verified request no longer has a live session and operational client."""


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

    def record_boundary_denial(self, action: str, phase: str, outcome: str, correlation: str,
                               verified_user: str | None, verified_issuer: str | None) -> None:
        """Independent commit, after the denied operation's transaction has unwound."""
        try:
            with self._connect() as connection:
                if connection.execute("SELECT current_user").fetchone() != ("bri_app",):
                    raise DatabaseUnavailable("unexpected boundary audit role")
                connection.execute("SELECT bri.record_boundary_denial(%s,%s,%s,%s,%s,%s)",
                                   (action, phase, outcome, correlation, verified_user, verified_issuer))
        except psycopg.Error as exc:
            raise DatabaseUnavailable("boundary audit unavailable") from exc

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
                platform_row = connection.execute(
                    "SELECT 1 FROM bri.platform_superadmins "
                    "WHERE principal_id=%s AND status='active'",
                    (principal_id,),
                ).fetchone()
                platform_superadmin = platform_row is not None
                membership_rows = connection.execute(
                    "SELECT tenant_id, membership_type FROM bri.auth_tenant_memberships "
                    "WHERE principal_id=%s AND status='active' ORDER BY tenant_id",
                    (principal_id,),
                ).fetchall()
                membership_types = {row[0]: row[1] for row in membership_rows}
                if not platform_superadmin and any(
                    membership_type == "platform_superadmin"
                    for membership_type in membership_types.values()
                ):
                    return None
                tenant_ids = frozenset(membership_types)
                grants: list[AccessGrant] = []
                for tenant_id in sorted(tenant_ids):
                    membership_type = membership_types[tenant_id]
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
                    for scope_id, permission in role_rows:
                        if not role_allows_permission(membership_type, permission):
                            continue
                        grant_scope = tenant_id if (
                            permission in CONFIGURATION_PERMISSIONS
                            and membership_type in {"admin", "platform_superadmin"}
                        ) else scope_id
                        grants.append(AccessGrant(tenant_id, permission, grant_scope))
                if platform_superadmin:
                    grants.extend((
                        AccessGrant("brs-platform", "prompt:platform:manage", "platform-prompt"),
                        AccessGrant("brs-platform", "signature_package:manage", "platform-signature-packages"),
                    ))
                return Principal(
                    subject_id=principal_id,
                    tenant_ids=tenant_ids,
                    grants=tuple(dict.fromkeys(grants)),
                    role_bindings=tuple(sorted(membership_types.items())),
                    platform_superadmin=platform_superadmin,
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
                    f"SELECT ({_LIVE_SESSION_SQL}) FROM bri.auth_sessions s "
                    "WHERE s.auth_user_id=%s AND s.session_id=%s",
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
        *,
        correlation_id: UUID | str | None = None,
        primary_authenticated_at: datetime | int | None = None,
        totp_authenticated_at: datetime | int | None = None,
    ) -> datetime | None:
        """Start once per verified provider session, never extend its deadline.

        Supply only middleware correlation and verified password/TOTP AMR times
        (UTC datetime or Unix seconds, never JWT issuance time).
        Missing primary evidence fails closed after an access/credential change.
        """
        try:
            user = str(UUID(auth_user_id))
            if issuer != f"{self.supabase_url.rstrip('/')}/auth/v1" or str(UUID(subject)) != user:
                return None
            params = (issuer, str(UUID(session_id)), self._verified_time(primary_authenticated_at),
                      self._verified_time(totp_authenticated_at), self._correlation(correlation_id))
        except (ValueError, TypeError, AttributeError, OSError, OverflowError):
            return None
        return self._security_call(user, "SELECT bri.start_security_session(%s,%s,%s,%s,%s)", params)

    @staticmethod
    def _verified_time(value: datetime | int | None) -> datetime | None:
        if value is None:
            return None
        if type(value) is int:
            return datetime.fromtimestamp(value, UTC)
        if not isinstance(value, datetime) or value.utcoffset() is None:
            raise ValueError("missing verified timezone-aware timestamp")
        return value

    @staticmethod
    def _correlation(value: UUID | str | None) -> str:
        return str(uuid4() if value is None else UUID(str(value)))

    def _security_call(self, user: str, sql: str, params: tuple) -> Any:
        try:
            with self._connect() as connection:
                role = connection.execute("SELECT current_user").fetchone()
                if not role or role[0] != "bri_app":
                    raise DatabaseUnavailable("database login is not the restricted application role")
                self._set_auth_user_context(connection, user)
                row = connection.execute(sql, params).fetchone()
                return row[0] if row else None
        except psycopg.Error as exc:
            raise DatabaseUnavailable("security lifecycle transaction failed") from exc

    def revoke_auth_session(self, auth_user_id: str, session_id: str, *,
                            correlation_id: UUID | str | None = None) -> bool:
        """True only after a durable session denial; an idempotent retry does not append another event."""
        try:
            user = str(UUID(auth_user_id))
            params = (str(UUID(session_id)), self._correlation(correlation_id))
        except (ValueError, TypeError, AttributeError):
            return False
        return self._security_call(user, "SELECT bri.revoke_security_session(%s,%s)", params) is True

    def invalidate_for_password_recovery(self, auth_user_id: str, session_id: str, *,
                                         correlation_id: UUID | str,
                                         recovery_authenticated_at: datetime | int | None = None) -> bool:
        """Consume one verified recovery session and quarantine BEFORE provider I/O.

        Caller must verify issuer/subject/session, active membership, authorized
        recovery and fresh TOTP. An unregistered session beyond a cutoff must
        present its verified original recovery/primary authentication timestamp,
        not a refresh, TOTP, browser callback, or API receipt time. A BRI session
        still active under the same guard is already bound. True means
        *reserved*, not password changed. False/retry: do not call the provider.
        On timeout/failure leave blocked. Never clear on a browser callback.
        A separate trusted event consumer reconciles using the SQL contract in
        0008; this server role deliberately cannot confirm provider changes.
        """
        try:
            user = str(UUID(auth_user_id))
            params = (str(UUID(session_id)), str(UUID(str(correlation_id))),
                      self._verified_time(recovery_authenticated_at))
        except (ValueError, TypeError, AttributeError, OSError, OverflowError):
            return False
        return self._security_call(user, "SELECT bri.reserve_password_recovery(%s,%s,%s)", params) is True

    def client_is_operational(self, tenant_id: str, auth_user_id: str) -> bool:
        """0009 gate: pass only the resolved tenant and verified Auth user ID."""
        if not auth_user_id:
            return False
        with self._tenant_transaction(tenant_id, read_only=True, auth_user_id=auth_user_id) as session:
            connection: Any = session.connection
            row = connection.execute("SELECT bri.client_is_operational(%s)", (tenant_id,)).fetchone()
            return bool(row and row[0] is True)

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
    def _tenant_transaction(
        self,
        tenant_id: str,
        *,
        read_only: bool,
        auth_user_id: str | None = None,
        synthetic_principal_id: str | None = None,
        protected: tuple[str, str, str] | None = None,
    ) -> Iterator[TenantSession]:
        if not isinstance(tenant_id, str) or not tenant_id or len(tenant_id) > 128:
            raise DatabaseUnavailable("tenant database context failed")
        if auth_user_id is not None and synthetic_principal_id is not None:
            raise DatabaseUnavailable("ambiguous identity context")
        try:
            if auth_user_id is not None:
                auth_user_id = str(UUID(auth_user_id))
            if synthetic_principal_id is not None and (
                not isinstance(synthetic_principal_id, str)
                or not synthetic_principal_id
                or len(synthetic_principal_id) > 255
                or any(ord(char) < 32 for char in synthetic_principal_id)
            ):
                raise DatabaseUnavailable("synthetic identity context is invalid")
            with self._connect() as connection:
                if protected is not None:
                    if not read_only or auth_user_id is None or synthetic_principal_id is not None:
                        raise ProtectedAccessDenied("invalid protected scope")
                    # Hosted data paths are read-only. Authorization and every
                    # business SELECT see one snapshot. A change that commits
                    # concurrently cannot expose newer rows under older grants.
                    connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
                elif read_only:
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
                if auth_user_id is not None:
                    self._set_auth_user_context(connection, auth_user_id)
                if synthetic_principal_id is not None:
                    connection.execute(
                        "SELECT set_config('bri.synthetic_principal_id', %s, true)",
                        (synthetic_principal_id,),
                    )
                    synthetic_context = connection.execute(
                        "SELECT current_setting('bri.synthetic_principal_id', true)"
                    ).fetchone()
                    if not synthetic_context or synthetic_context[0] != synthetic_principal_id:
                        raise DatabaseUnavailable("synthetic identity context was not established")
                if protected is not None:
                    session_id, principal_id, issuer = protected
                    row = connection.execute(
                        "SELECT bri.client_is_operational(%s) AND EXISTS ("
                        "SELECT 1 FROM bri.auth_sessions s JOIN bri.auth_identity_links i "
                        "USING(auth_user_id,principal_id) "
                        "WHERE s.auth_user_id=%s AND s.session_id=%s AND s.principal_id=%s "
                        "AND i.status='active' AND i.auth_issuer=%s AND i.auth_subject=i.auth_user_id::text "
                        f"AND {_LIVE_SESSION_SQL})",
                        (tenant_id, auth_user_id, session_id, principal_id, issuer),
                    ).fetchone()
                    if not row or row[0] is not True:
                        raise ProtectedAccessDenied("client access is no longer authorized")
                else:
                    connection.execute("SELECT count(*) FROM bri.tenants").fetchone()
                yield TenantSession(tenant_id=tenant_id, connection=connection)
        except DatabaseUnavailable:
            raise
        except (psycopg.Error, ValueError, TypeError) as exc:
            raise DatabaseUnavailable("tenant database context failed") from exc

    @contextmanager
    def protected_tenant_context(self, tenant_id: str, *, auth_user_id: str, session_id: str,
                                 principal_id: str, issuer: str) -> Iterator[TenantSession]:
        """Open the guarded data snapshot for an already verified hosted identity.

        0009 checks current principal, membership, activation and admin quorum;
        bind its result to this particular verified issuer, subject and BRI session.
        Prior lookup/auth_session_is_active is not authorization for this transaction.
        """
        if issuer != f"{self.supabase_url.rstrip('/')}/auth/v1":
            raise ProtectedAccessDenied("unexpected identity issuer")
        try:
            protected = (str(UUID(session_id)), str(UUID(principal_id)), issuer)
            user = str(UUID(auth_user_id))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ProtectedAccessDenied("invalid verified identity") from exc
        with self._tenant_transaction(tenant_id, read_only=True, auth_user_id=user, protected=protected) as session:
            yield session

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

    @contextmanager
    def configuration_context(
        self,
        tenant_id: str,
        *,
        auth_user_id: str | None,
        synthetic_principal_id: str | None,
        read_only: bool,
    ) -> Iterator[TenantSession]:
        """Local-only repository context; hosted reads require protected_tenant_context."""
        if auth_user_id is not None:
            raise ProtectedAccessDenied("hosted configuration requires a session-bound transaction")
        with self._tenant_transaction(
            tenant_id,
            read_only=read_only,
            auth_user_id=auth_user_id,
            synthetic_principal_id=synthetic_principal_id,
        ) as session:
            yield session
