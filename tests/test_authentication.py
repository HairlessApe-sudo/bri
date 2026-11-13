from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import unittest
import uuid

import httpx

from bri.api.authentication import (
    AuthenticationRejected,
    AuthenticationUnavailable,
    SupabaseTokenVerifier,
)


ISSUER = "https://bwqdyibvuecgthtatrtv.supabase.co/auth/v1"
PUBLISHABLE_KEY = "sb_publishable_unit_test"
USER_ID = str(uuid.UUID("1d99454f-7af6-4d88-9f89-8a8c028ff2a7"))
SESSION_ID = str(uuid.UUID("a82f2916-26f1-42c5-a430-78ee5aac4e49"))
TEST_SIGNING_KEY = "unit-test-only-not-a-secret-for-any-environment"


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def make_token(**overrides: object) -> str:
    claims: dict[str, object] = {
        "iss": ISSUER,
        "aud": "authenticated",
        "sub": USER_ID,
        "role": "authenticated",
        "session_id": SESSION_ID,
        "aal": "aal2",
        "amr": [
            {"method": "totp", "timestamp": int(time.time())},
            {"method": "password", "timestamp": int(time.time())},
        ],
        "iat": int(time.time()),
        "exp": int(time.time()) + 300,
    }
    claims.update(overrides)
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = _b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = hmac.new(TEST_SIGNING_KEY.encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{payload}.{_b64url(signature)}"


def auth_server_response(request: httpx.Request, *, status: int = 200, user_id: str = USER_ID) -> httpx.Response:
    try:
        header, payload, signature = request.headers["authorization"].removeprefix("Bearer ").split(".")
        signing_input = f"{header}.{payload}".encode("ascii")
        supplied = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        expected = hmac.new(TEST_SIGNING_KEY.encode(), signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(supplied, expected):
            return httpx.Response(401, json={"message": "invalid"})
    except (KeyError, ValueError):
        return httpx.Response(401, json={"message": "invalid"})
    return httpx.Response(status, json={"id": user_id})


class SupabaseTokenVerifierTests(unittest.IsolatedAsyncioTestCase):
    def verifier(self, token: str, *, status: int = 200, user_id: str = USER_ID, failure: Exception | None = None):
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            if failure:
                raise failure
            return auth_server_response(request, status=status, user_id=user_id)

        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        verifier = SupabaseTokenVerifier(ISSUER.removesuffix("/auth/v1"), PUBLISHABLE_KEY, client=client)
        return verifier, client, seen, token

    async def test_accepts_auth_server_verified_totp_aal2_access_token(self) -> None:
        token = make_token()
        verifier, client, seen, token = self.verifier(token)
        try:
            result = await verifier.verify(token)
        finally:
            await client.aclose()

        self.assertEqual(result.auth_user_id, USER_ID)
        self.assertEqual(result.session_id, SESSION_ID)
        self.assertEqual(result.issuer, ISSUER)
        self.assertEqual(seen[0].method, "GET")
        self.assertEqual(seen[0].url.path, "/auth/v1/user")
        self.assertEqual(seen[0].headers["apikey"], PUBLISHABLE_KEY)
        self.assertEqual(seen[0].headers["authorization"], f"Bearer {token}")

    async def test_rejects_token_not_accepted_by_supabase_auth(self) -> None:
        verifier, client, _, token = self.verifier(make_token(), status=401)
        try:
            with self.assertRaises(AuthenticationRejected):
                await verifier.verify(token)
        finally:
            await client.aclose()

    async def test_rejects_subject_mismatch_with_auth_server_user(self) -> None:
        token = make_token()
        verifier, client, _, token = self.verifier(token, user_id=str(uuid.uuid4()))
        try:
            with self.assertRaises(AuthenticationRejected):
                await verifier.verify(token)
        finally:
            await client.aclose()

    async def test_requires_exact_issuer_authenticated_audience_and_user_role(self) -> None:
        cases = [
            {"iss": "https://attacker.example/auth/v1"},
            {"aud": "anon"},
            {"role": "service_role"},
            {"sub": "not-a-uuid"},
            {"session_id": "not-a-uuid"},
            {"exp": int(time.time()) - 1},
        ]
        for claims in cases:
            with self.subTest(claims=claims):
                token = make_token(**claims)
                verifier, client, _, token = self.verifier(token)
                try:
                    with self.assertRaises(AuthenticationRejected):
                        await verifier.verify(token)
                finally:
                    await client.aclose()

    async def test_requires_aal2_and_a_verified_totp_method(self) -> None:
        cases = [
            {"aal": "aal1"},
            {"amr": [{"method": "password", "timestamp": int(time.time())}]},
            {"amr": [{"method": "otp", "timestamp": int(time.time())}]},
        ]
        for claims in cases:
            with self.subTest(claims=claims):
                token = make_token(**claims)
                verifier, client, _, token = self.verifier(token)
                try:
                    with self.assertRaises(AuthenticationRejected):
                        await verifier.verify(token)
                finally:
                    await client.aclose()

    async def test_auth_server_outage_fails_closed_as_unavailable(self) -> None:
        verifier, client, _, token = self.verifier(make_token(), failure=httpx.ConnectError("private test detail"))
        try:
            with self.assertRaises(AuthenticationUnavailable):
                await verifier.verify(token)
        finally:
            await client.aclose()


if __name__ == "__main__":
    unittest.main()
