"""Server-side Supabase access-token verification."""
from __future__ import annotations

import base64
import json
import math
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID

import httpx

from bri.api.database import EXPECTED_PROJECT_REF


class AuthenticationRejected(Exception):
    """The supplied credential cannot access BRI."""


class AuthenticationUnavailable(Exception):
    """The identity provider could not be reached safely."""


@dataclass(frozen=True, slots=True)
class AuthenticatedIdentity:
    auth_user_id: str
    session_id: str
    issuer: str
    assurance_level: str
    assurance_methods: tuple[str, ...]


class SupabaseTokenVerifier:
    """Validate a Supabase JWT through Auth, then inspect its verified claims.

    Signature validation is delegated to Supabase Auth's ``/user`` endpoint.
    Claims are used only after that endpoint accepts the exact bearer token.
    """

    def __init__(self, supabase_url: str, publishable_key: str, *, client: Any = None) -> None:
        parsed = urlsplit(supabase_url)
        expected_host = f"{EXPECTED_PROJECT_REF}.supabase.co"
        if (
            parsed.scheme != "https"
            or parsed.hostname != expected_host
            or parsed.port not in (None, 443)
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in ("", "/")
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Supabase Auth must use the approved HTTPS project origin")
        if not publishable_key.strip():
            raise ValueError("Supabase publishable key is required")
        self.supabase_url = f"https://{expected_host}"
        self.publishable_key = publishable_key
        self.client = client

    @staticmethod
    def _decode_segment(segment: str) -> bytes:
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        if not segment or any(character not in alphabet for character in segment) or len(segment) % 4 == 1:
            raise ValueError("invalid base64url segment")
        encoded = segment.encode("ascii")
        decoded = base64.b64decode(
            encoded + b"=" * (-len(encoded) % 4),
            altchars=b"-_",
            validate=True,
        )
        if base64.urlsafe_b64encode(decoded).rstrip(b"=") != encoded:
            raise ValueError("non-canonical base64url segment")
        return decoded

    @staticmethod
    def _decode_claims(access_token: str) -> tuple[dict[str, Any], dict[str, Any]]:
        if not isinstance(access_token, str) or len(access_token) > 16_384:
            raise AuthenticationRejected("Invalid access token")
        try:
            header_part, payload_part, signature_part = access_token.split(".")
            header_bytes = SupabaseTokenVerifier._decode_segment(header_part)
            payload_bytes = SupabaseTokenVerifier._decode_segment(payload_part)
            SupabaseTokenVerifier._decode_segment(signature_part)
            header = json.loads(header_bytes)
            claims = json.loads(payload_bytes)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            raise AuthenticationRejected("Invalid access token") from exc
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise AuthenticationRejected("Invalid access token")
        if not isinstance(header.get("alg"), str) or header["alg"].lower() == "none":
            raise AuthenticationRejected("Invalid access token")
        return header, claims

    @staticmethod
    def _valid_time_claim(value: Any, *, now: float, allow_future: bool = False) -> bool:
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            return False
        return value > now if not allow_future else value <= now + 60

    async def verify(self, access_token: str) -> AuthenticatedIdentity:
        if not isinstance(access_token, str) or not access_token or len(access_token) > 16_384:
            raise AuthenticationRejected("Invalid access token")

        url = f"{self.supabase_url}/auth/v1/user"
        headers = {
            "apikey": self.publishable_key,
            "authorization": f"Bearer {access_token}",
            "accept": "application/json",
        }
        try:
            if self.client is None:
                async with httpx.AsyncClient(timeout=5.0, follow_redirects=False) as client:
                    response = await client.get(url, headers=headers)
            else:
                response = await self.client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            raise AuthenticationUnavailable("Supabase Auth verification is unavailable") from exc

        if response.status_code in (401, 403):
            raise AuthenticationRejected("Invalid access token")
        if response.status_code != 200:
            raise AuthenticationUnavailable("Supabase Auth verification is unavailable")
        try:
            user = response.json()
        except ValueError as exc:
            raise AuthenticationUnavailable("Supabase Auth verification is unavailable") from exc
        if not isinstance(user, dict) or not isinstance(user.get("id"), str):
            raise AuthenticationUnavailable("Supabase Auth verification is unavailable")

        header, claims = self._decode_claims(access_token)
        issuer = f"{self.supabase_url}/auth/v1"
        if claims.get("iss") != issuer:
            raise AuthenticationRejected("Invalid token issuer")
        if claims.get("aud") != "authenticated" and not (
            isinstance(claims.get("aud"), list) and "authenticated" in claims["aud"]
        ):
            raise AuthenticationRejected("Invalid token audience")
        if claims.get("role") != "authenticated" or claims.get("is_anonymous") is True:
            raise AuthenticationRejected("Invalid authenticated user token")

        try:
            subject = str(UUID(claims.get("sub", "")))
            auth_user_id = str(UUID(user["id"]))
            session_id = str(UUID(claims.get("session_id", "")))
        except (ValueError, TypeError, AttributeError) as exc:
            raise AuthenticationRejected("Invalid access token subject") from exc
        if subject != auth_user_id:
            raise AuthenticationRejected("Access token subject does not match Supabase Auth user")

        now = time.time()
        if not self._valid_time_claim(claims.get("exp"), now=now):
            raise AuthenticationRejected("Expired access token")
        if not self._valid_time_claim(claims.get("iat"), now=now, allow_future=True):
            raise AuthenticationRejected("Invalid access token issue time")

        factors = user.get("factors")
        has_verified_totp_factor = isinstance(factors, list) and any(
            isinstance(factor, dict)
            and factor.get("factor_type") == "totp"
            and factor.get("status") == "verified"
            for factor in factors
        )
        amr = claims.get("amr")
        has_totp = isinstance(amr, list) and any(
            isinstance(method, dict) and method.get("method") == "totp"
            for method in amr
        )
        if claims.get("aal") != "aal2" or not has_totp or not has_verified_totp_factor:
            raise AuthenticationRejected("Verified TOTP MFA is required")

        methods = tuple(sorted({
            method["method"]
            for method in amr
            if isinstance(method, dict) and isinstance(method.get("method"), str)
        })) if isinstance(amr, list) else ()
        return AuthenticatedIdentity(
            auth_user_id=auth_user_id,
            session_id=session_id,
            issuer=issuer,
            assurance_level=str(claims["aal"]),
            assurance_methods=methods,
        )
