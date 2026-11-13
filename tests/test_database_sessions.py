from __future__ import annotations

import datetime as dt
import unittest
from unittest.mock import patch

from bri.api.database import Database

AUTH_USER_ID = "1d99454f-7af6-4d88-9f89-8a8c028ff2a7"
PRINCIPAL_ID = "cdf6d6b6-039c-40df-9a5a-1721e6a79284"
SESSION_ID = "a82f2916-26f1-42c5-a430-78ee5aac4e49"
ISSUER = "https://bwqdyibvuecgthtatrtv.supabase.co/auth/v1"
SUPABASE_URL = "https://bwqdyibvuecgthtatrtv.supabase.co"
DATABASE_URL = (
    "postgresql://bri_app.bwqdyibvuecgthtatrtv:unit-test@"
    "aws-1-eu-west-1.pooler.supabase.com:5432/postgres?sslmode=require"
)


class Cursor:
    def __init__(self, row=None):
        self.row = row

    def fetchone(self):
        return self.row


class SessionConnection:
    def __init__(self, *, active: bool = True, revoke_found: bool = True):
        self.active = active
        self.revoke_found = revoke_found
        self.queries: list[tuple[str, tuple[object, ...]]] = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql, params=()):
        normalized = " ".join(str(sql).split())
        params = tuple(params)
        self.queries.append((normalized, params))
        if normalized == "SET TRANSACTION READ ONLY":
            return Cursor()
        if normalized == "SELECT current_user":
            return Cursor(("bri_app",))
        if "set_config('bri.auth_user_id'" in normalized:
            return Cursor((AUTH_USER_ID,))
        if "current_setting('bri.auth_user_id'" in normalized:
            return Cursor((AUTH_USER_ID,))
        if "INSERT INTO bri.auth_sessions" in normalized:
            return Cursor()
        if "SELECT expires_at, revoked_at" in normalized:
            expires = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=7) if self.active else dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)
            return Cursor((expires, None if self.active else dt.datetime.now(dt.timezone.utc), self.active))
        if "SELECT (expires_at > now()" in normalized:
            return Cursor((self.active,))
        if "UPDATE bri.auth_sessions" in normalized:
            return Cursor((SESSION_ID,) if self.revoke_found else None)
        raise AssertionError(f"Unexpected database query: {normalized}")


class AuthSessionDatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.database = Database(SUPABASE_URL, DATABASE_URL)

    def test_new_supabase_session_gets_one_immutable_eight_hour_bri_session(self) -> None:
        connection = SessionConnection()
        with patch("bri.api.database.psycopg.connect", return_value=connection):
            expires_at = self.database.start_auth_session(AUTH_USER_ID, ISSUER, AUTH_USER_ID, SESSION_ID)

        self.assertIsNotNone(expires_at)
        insert = next(sql for sql, _ in connection.queries if "INSERT INTO bri.auth_sessions" in sql)
        self.assertIn("ON CONFLICT (auth_user_id, session_id) DO NOTHING", insert)
        self.assertNotIn("expires_at", insert)

    def test_expired_session_cannot_be_renewed_with_a_refreshed_auth_token(self) -> None:
        connection = SessionConnection(active=False)
        with patch("bri.api.database.psycopg.connect", return_value=connection):
            expires_at = self.database.start_auth_session(AUTH_USER_ID, ISSUER, AUTH_USER_ID, SESSION_ID)
        self.assertIsNone(expires_at)

    def test_session_activity_check_fails_closed_for_expired_or_revoked_sessions(self) -> None:
        connection = SessionConnection(active=False)
        with patch("bri.api.database.psycopg.connect", return_value=connection):
            active = self.database.auth_session_is_active(AUTH_USER_ID, SESSION_ID)
        self.assertFalse(active)

    def test_logout_revokes_the_current_bri_session(self) -> None:
        connection = SessionConnection()
        with patch("bri.api.database.psycopg.connect", return_value=connection):
            revoked = self.database.revoke_auth_session(AUTH_USER_ID, SESSION_ID)
        self.assertTrue(revoked)
        update = next(sql for sql, _ in connection.queries if "UPDATE bri.auth_sessions" in sql)
        self.assertIn("revoked_at", update)


if __name__ == "__main__":
    unittest.main()
