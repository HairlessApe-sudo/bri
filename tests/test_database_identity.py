from __future__ import annotations

import unittest
from unittest.mock import patch

from bri.api.database import Database


AUTH_USER_ID = "1d99454f-7af6-4d88-9f89-8a8c028ff2a7"
PRINCIPAL_ID = "cdf6d6b6-039c-40df-9a5a-1721e6a79284"
ISSUER = "https://bwqdyibvuecgthtatrtv.supabase.co/auth/v1"
SUPABASE_URL = "https://bwqdyibvuecgthtatrtv.supabase.co"
DATABASE_URL = (
    "postgresql://bri_app.bwqdyibvuecgthtatrtv:unit-test@"
    "aws-1-eu-west-1.pooler.supabase.com:5432/postgres?sslmode=require"
)


class FakeCursor:
    def __init__(self, row=None, rows=()):
        self.row = row
        self.rows = list(rows)

    def fetchone(self):
        return self.row

    def fetchall(self):
        return self.rows


class IdentityConnection:
    def __init__(self):
        self.queries: list[tuple[str, tuple[object, ...]]] = []
        self.tenant_contexts: list[str] = []
        self.current_tenant: str | None = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql, params=()):
        normalized = " ".join(str(sql).split())
        params = tuple(params)
        self.queries.append((normalized, params))
        if normalized == "SET TRANSACTION READ ONLY":
            return FakeCursor()
        if normalized == "SELECT current_user":
            return FakeCursor(("bri_app",))
        if "set_config('bri.auth_user_id'" in normalized:
            return FakeCursor((AUTH_USER_ID,))
        if "current_setting('bri.auth_user_id'" in normalized:
            return FakeCursor((AUTH_USER_ID,))
        if "FROM bri.auth_identity_links" in normalized:
            if params == (AUTH_USER_ID, ISSUER, AUTH_USER_ID):
                return FakeCursor((PRINCIPAL_ID, "active"))
            return FakeCursor(None)
        if "FROM bri.auth_tenant_memberships" in normalized:
            return FakeCursor(rows=(("tenant-alpha", "active"), ("tenant-beta", "active")))
        if "FROM bri.auth_role_assignments" in normalized:
            tenant_id = params[0]
            if "tenant-alpha" == tenant_id:
                return FakeCursor(rows=(("org-alpha-root", "organisation:read"),))
            if "tenant-beta" == tenant_id:
                return FakeCursor(rows=(("knowledge-beta", "knowledge:read"),))
        if "current_setting('bri.tenant_id'" in normalized:
            return FakeCursor((self.current_tenant,))
        if "set_config('bri.tenant_id'" in normalized:
            self.current_tenant = str(params[0])
            self.tenant_contexts.append(self.current_tenant)
            return FakeCursor((self.current_tenant,))
        raise AssertionError(f"Unexpected database query: {normalized}")


class AuthenticatedPrincipalDatabaseTests(unittest.TestCase):
    def test_verified_provider_subject_maps_to_explicit_tenant_grants(self) -> None:
        connection = IdentityConnection()
        database = Database(SUPABASE_URL, DATABASE_URL)
        with patch("bri.api.database.psycopg.connect", return_value=connection):
            principal = database.resolve_authenticated_principal(AUTH_USER_ID, ISSUER, AUTH_USER_ID)

        self.assertIsNotNone(principal)
        self.assertEqual(principal.subject_id, PRINCIPAL_ID)
        self.assertEqual(principal.tenant_ids, frozenset({"tenant-alpha", "tenant-beta"}))
        self.assertEqual(
            {(grant.tenant_id, grant.action, grant.scope_id) for grant in principal.grants},
            {
                ("tenant-alpha", "organisation:read", "org-alpha-root"),
                ("tenant-beta", "knowledge:read", "knowledge-beta"),
            },
        )
        self.assertEqual(connection.tenant_contexts, ["tenant-alpha", "tenant-beta"])
        self.assertTrue(any("SET TRANSACTION READ ONLY" == sql for sql, _ in connection.queries))
        self.assertTrue(any("set_config('bri.auth_user_id'" in sql for sql, _ in connection.queries))

    def test_unknown_provider_subject_returns_no_bri_principal(self) -> None:
        connection = IdentityConnection()
        database = Database(SUPABASE_URL, DATABASE_URL)
        with patch("bri.api.database.psycopg.connect", return_value=connection):
            principal = database.resolve_authenticated_principal(AUTH_USER_ID, "https://other.invalid/auth/v1", AUTH_USER_ID)
        self.assertIsNone(principal)
        self.assertFalse(any("FROM bri.auth_tenant_memberships" in sql for sql, _ in connection.queries))


if __name__ == "__main__":
    unittest.main()
