from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import unittest
import uuid
from unittest.mock import patch

import httpx

from bri.api.authentication import (
    AuthenticatedIdentity,
    AuthenticationRejected,
    AuthenticationUnavailable,
    SupabaseTokenVerifier,
    has_recent_mfa,
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


def auth_server_response(
    request: httpx.Request,
    *,
    status: int = 200,
    user_id: str = USER_ID,
    factors: list[dict[str, str]] | None = None,
) -> httpx.Response:
    try:
        header, payload, signature = request.headers["authorization"].removeprefix("Bearer ").split(".")
        signing_input = f"{header}.{payload}".encode("ascii")
        supplied = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
        expected = hmac.new(TEST_SIGNING_KEY.encode(), signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(supplied, expected):
            return httpx.Response(401, json={"message": "invalid"})
    except (KeyError, ValueError):
        return httpx.Response(401, json={"message": "invalid"})
    return httpx.Response(
        status,
        json={
            "id": user_id,
            "factors": factors if factors is not None else [{"factor_type": "totp", "status": "verified"}],
        },
    )


class SupabaseTokenVerifierTests(unittest.IsolatedAsyncioTestCase):
    def verifier(
        self,
        token: str,
        *,
        status: int = 200,
        user_id: str = USER_ID,
        factors: list[dict[str, str]] | None = None,
        failure: Exception | None = None,
    ):
        seen: list[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            if failure:
                raise failure
            return auth_server_response(request, status=status, user_id=user_id, factors=factors)

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

    async def test_verified_amr_clocks_are_independent_of_refreshed_iat(self) -> None:
        now = 1_800_000_000
        with patch("bri.api.authentication.time.time", return_value=now) as clock:
            token = make_token(amr=[{"method": "password", "timestamp": now - 3600},
                                    {"method": "totp", "timestamp": now - 900}])
            verifier, client, _, _ = self.verifier(token)
            async with client:
                identity = await verifier.verify(token)
            self.assertEqual(identity.primary_authenticated_at, now - 3600)
            self.assertEqual(identity.totp_authenticated_at, now - 900)
            self.assertTrue(has_recent_mfa(identity))
            clock.return_value += 0.01
            self.assertFalse(has_recent_mfa(identity))
            legacy = AuthenticatedIdentity(USER_ID, SESSION_ID, ISSUER, "aal2", ("totp",))
            self.assertIsNone(legacy.recovery_authenticated_at)
            self.assertIsNone(legacy.primary_authenticated_at)
            self.assertFalse(has_recent_mfa(legacy))
            self.assertFalse(has_recent_mfa(None))

    async def test_bad_amr_timestamps_do_not_grant_step_up_or_primary_evidence(self) -> None:
        now = 1_800_000_000
        with patch("bri.api.authentication.time.time", return_value=now):
            for value in (None, True, "1800000000", 0, -1, now + 1, now - 0.5, 10**400):
                with self.subTest(value=value):
                    token = make_token(amr=[{"method": method, "timestamp": value}
                                            for method in ("totp", "password")])
                    verifier, client, _, _ = self.verifier(token)
                    async with client:
                        identity = await verifier.verify(token)
                    self.assertFalse(has_recent_mfa(identity))
                    self.assertIsNone(identity.recovery_authenticated_at)
                    self.assertIsNone(identity.primary_authenticated_at)
                    self.assertIsNone(identity.totp_authenticated_at)

    async def test_missing_or_ambiguous_evidence_is_not_inferred(self) -> None:
        now = int(time.time())
        for totp in ([{"method": "totp"}], [{"method": "totp", "timestamp": ts}
                                            for ts in (now, now - 901)]):
            token = make_token(amr=[*totp, {"method": "token_refresh", "timestamp": now}])
            verifier, client, _, _ = self.verifier(token)
            async with client:
                identity = await verifier.verify(token)
            self.assertIsNone(identity.primary_authenticated_at)
            self.assertFalse(has_recent_mfa(identity))

    async def test_provider_totp_aliases_normalize_only_after_verification(self):
        now = int(time.time())
        for other in ([], [{"method": "totp", "timestamp": now}], ["totp"]):
            amr = [{"method": "mfa/totp", "timestamp": now}, *other]
            token = make_token(amr=amr)
            verifier, client, _, _ = self.verifier(token)
            async with client:
                identity = await verifier.verify(token)
            self.assertEqual(identity.assurance_methods, ("totp",))
            self.assertEqual(has_recent_mfa(identity), not other)
        for amr in (["mfa/totp"], ["totp"], [{"method": "mfa/phone", "timestamp": now}],
                    [{"method": "mfa/recovery_code", "timestamp": now}]):
            token = make_token(amr=amr)
            verifier, client, _, _ = self.verifier(token)
            async with client:
                with self.assertRaises(AuthenticationRejected):
                    await verifier.verify(token)

    async def test_recovery_cutoff_requires_one_timestamped_native_primary(self):
        now = int(time.time())
        when = now - 3600
        for primary, expected in ((["recovery"], when), (["password"], when), (["otp"], None),
                                  (["magiclink"], None), (["password", "otp"], None),
                                  (["password", "recovery"], None), (["recovery", "recovery"], None),
                                  ([], None)):
            with self.subTest(primary=primary):
                amr = [{"method": name, "timestamp": when} for name in primary]
                amr += [{"method": "totp", "timestamp": now}, {"method": "token_refresh", "timestamp": now}]
                token = make_token(amr=amr, iat=now)
                verifier, client, _, _ = self.verifier(token)
                async with client:
                    identity = await verifier.verify(token)
                self.assertEqual(identity.recovery_authenticated_at, expected)
                self.assertEqual(identity.primary_authenticated_at, when if primary == ["password"] else None)

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

    async def test_requires_a_current_verified_totp_factor_in_supabase_user_state(self) -> None:
        invalid_factor_sets = [
            [],
            [{"factor_type": "phone", "status": "verified"}],
            [{"factor_type": "totp", "status": "unverified"}],
        ]
        for factors in invalid_factor_sets:
            with self.subTest(factors=factors):
                verifier, client, _, token = self.verifier(make_token(), factors=factors)
                try:
                    with self.assertRaises(AuthenticationRejected):
                        await verifier.verify(token)
                finally:
                    await client.aclose()

    async def test_rejects_malformed_base64url_header_or_payload_segments(self) -> None:
        token = make_token()
        original = token.split(".")
        for index in (0, 1):
            with self.subTest(segment=index):
                parts = original.copy()
                parts[index] += "!"
                signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
                signature = hmac.new(TEST_SIGNING_KEY.encode(), signing_input, hashlib.sha256).digest()
                parts[2] = _b64url(signature)
                malformed = ".".join(parts)
                verifier, client, _, malformed = self.verifier(malformed)
                try:
                    with self.assertRaises(AuthenticationRejected):
                        await verifier.verify(malformed)
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
