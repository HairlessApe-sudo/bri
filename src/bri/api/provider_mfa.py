"""Server-only Supabase MFA admin wire contract. No live transport is enabled.

The caller must authorize the user/factor pair before removal. This module does
not authorize recovery, revoke BRI sessions, or read server credentials.
"""
from __future__ import annotations

import asyncio
import json
from uuid import UUID

import httpx

from bri.api.database import EXPECTED_PROJECT_REF

_ADMIN_USERS = f"https://{EXPECTED_PROJECT_REF}.supabase.co/auth/v1/admin/users"
_TIMEOUT = 5.0
_MAX_BYTES = 64 * 1024
_MAX_FACTORS = 256


class ProviderMfaError(Exception):
    """Operation disabled, rejected, unavailable, or not confirmed."""


def _uuid(value: object) -> str:
    if type(value) is str and len(value) == 36:
        try:
            if str(UUID(value)) == value:
                return value
        except ValueError:
            pass
    raise ValueError("Expected a canonical UUID")


class ProviderMfaAdmin:
    def __init__(self, *, test_transport: httpx.MockTransport | None = None) -> None:
        if test_transport is not None and not isinstance(test_transport, httpx.MockTransport):
            raise ValueError("Only an in-process MFA admin test transport is supported")
        self._transport = test_transport

    def _client(self) -> httpx.AsyncClient:
        if self._transport is None:
            raise ProviderMfaError("Provider MFA administration disabled")
        return httpx.AsyncClient(
            transport=self._transport, trust_env=False, follow_redirects=False, timeout=_TIMEOUT,
            headers={"accept": "application/json", "accept-encoding": "identity",
                     "apikey": "unit-test-only", "authorization": "Bearer unit-test-only"},
        )

    @staticmethod
    async def _inventory(client: httpx.AsyncClient, user_id: str) -> dict[str, bool]:
        # Keep all IDs internally: becoming unverified is not proof of removal.
        try:
            async with asyncio.timeout(_TIMEOUT), client.stream("GET", f"{_ADMIN_USERS}/{user_id}/factors") as res:
                if res.status_code != 200 or res.headers.get("content-encoding", "identity") != "identity":
                    raise ValueError
                body = bytearray()
                async for chunk in res.aiter_bytes():
                    if len(body) + len(chunk) > _MAX_BYTES:
                        raise ValueError
                    body.extend(chunk)
            rows = json.loads(body)
            if not isinstance(rows, list) or len(rows) > _MAX_FACTORS:
                raise ValueError
            inventory = {}
            for row in rows:
                if not isinstance(row, dict) or row.get("user_id", user_id) != user_id:
                    raise ValueError
                factor_id = _uuid(row.get("id"))
                kind, status = row.get("factor_type"), row.get("status")
                if (factor_id in inventory or not isinstance(kind, str) or not kind
                        or status not in ("verified", "unverified")):
                    raise ValueError
                inventory[factor_id] = kind == "totp" and status == "verified"
            return inventory
        except Exception:  # noqa: BLE001, S110 -- Discard provider errors; never log or chain their contents.
            pass
        # Do not attach an exception context containing provider data.
        raise ProviderMfaError("Provider factor inventory unavailable")

    async def list_totp_factor_ids(self, user_id: str) -> tuple[str, ...]:
        _uuid(user_id)
        async with self._client() as client:
            inventory = await self._inventory(client, user_id)
        return tuple(sorted(fid for fid, eligible in inventory.items() if eligible))

    async def remove_totp_factor(self, user_id: str, factor_id: str) -> None:
        """Ensure this exact approved ID is absent; never retry DELETE or select a replacement."""
        _uuid(user_id)
        _uuid(factor_id)
        async with self._client() as client:
            before = await self._inventory(client, user_id)
            if factor_id not in before:
                return
            if not before[factor_id]:
                raise ProviderMfaError("Factor not eligible for removal")
            url = f"{_ADMIN_USERS}/{user_id}/factors/{factor_id}"
            try:
                async with asyncio.timeout(_TIMEOUT), client.stream("DELETE", url) as res:
                    status = res.status_code
            except Exception:  # noqa: BLE001 -- Any transport failure leaves the DELETE outcome unknown.
                # A lost response does not imply the write failed. Re-list once.
                status = None
            if status is not None and not (200 <= status < 300 or status == 404 or 500 <= status < 600):
                raise ProviderMfaError("Provider factor removal rejected")
            if factor_id in await self._inventory(client, user_id):
                raise ProviderMfaError("Provider factor removal not confirmed")
