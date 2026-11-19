"""Server adapter conformance with in-process responses only."""
import unittest
from unittest.mock import patch

import httpx

from bri.api.database import EXPECTED_PROJECT_REF
from bri.api.provider_mfa import ProviderMfaAdmin, ProviderMfaError

USER = "d94e6f68-0000-4000-8000-000000000001"
TARGET = "d94e6f68-0000-4000-8000-000000000002"
OTHER = "d94e6f68-0000-4000-8000-000000000003"
BASE = f"https://{EXPECTED_PROJECT_REF}.supabase.co/auth/v1/admin/users/{USER}/factors"
ROW = {"id": TARGET, "factor_type": "totp", "status": "verified", "friendly_name": "private"}


class ProviderMfaTests(unittest.IsolatedAsyncioTestCase):
    def scripted(self, *replies):
        calls = []
        responses = iter(replies)

        def handle(request):
            calls.append((request.method, str(request.url)))
            reply = next(responses)
            if isinstance(reply, Exception):
                raise reply
            return reply if isinstance(reply, httpx.Response) else httpx.Response(200, json=reply)

        return ProviderMfaAdmin(test_transport=httpx.MockTransport(handle)), calls

    async def test_disabled_never_constructs_client(self):
        with patch("bri.api.provider_mfa.httpx.AsyncClient") as client:
            admin = ProviderMfaAdmin()
            with self.assertRaises(ProviderMfaError):
                await admin.list_totp_factor_ids(USER)
            with self.assertRaises(ProviderMfaError):
                await admin.remove_totp_factor(USER, TARGET)
            client.assert_not_called()
        with self.assertRaises(ValueError):
            ProviderMfaAdmin(test_transport=object())

    async def test_list_projects_only_verified_totp_ids(self):
        admin, calls = self.scripted([ROW, {**ROW, "id": OTHER, "factor_type": "phone"},
                                     {**ROW, "id": USER, "status": "unverified"}])
        self.assertEqual(await admin.list_totp_factor_ids(USER), (TARGET,))
        self.assertEqual(calls, [("GET", BASE)])

    async def test_exact_factor_is_deleted_once_and_reconciled(self):
        for reply in (httpx.Response(200, json=ROW), httpx.Response(404), httpx.Response(503),
                      httpx.ReadTimeout("private")):
            with self.subTest(reply=type(reply).__name__):
                other = {**ROW, "id": OTHER}
                admin, calls = self.scripted([ROW, other], reply, [other])
                self.assertIsNone(await admin.remove_totp_factor(USER, TARGET))
                self.assertEqual(calls, [("GET", BASE), ("DELETE", f"{BASE}/{TARGET}"), ("GET", BASE)])

    async def test_absent_target_does_not_remove_a_replacement(self):
        admin, calls = self.scripted([{**ROW, "id": OTHER}])
        await admin.remove_totp_factor(USER, TARGET)
        self.assertEqual(calls, [("GET", BASE)])

    async def test_ineligible_or_unconfirmed_target_fails_closed(self):
        for ineligible in ({**ROW, "status": "unverified"}, {**ROW, "factor_type": "phone"}):
            admin, calls = self.scripted([ineligible])
            with self.assertRaises(ProviderMfaError):
                await admin.remove_totp_factor(USER, TARGET)
            self.assertEqual(calls, [("GET", BASE)])
        for after in ([ROW], [{**ROW, "status": "unverified"}], httpx.Response(500), {}):
            admin, calls = self.scripted([ROW], httpx.Response(200), after)
            with self.assertRaises(ProviderMfaError):
                await admin.remove_totp_factor(USER, TARGET)
            self.assertEqual(len(calls), 3)

    async def test_rejects_noncanonical_ids_before_transport(self):
        admin, calls = self.scripted()
        for bad in ("../" + TARGET, TARGET.upper(), "{" + TARGET + "}", TARGET.replace("-", ""), None):
            for user, factor in ((USER, bad), (bad, TARGET)):
                with self.assertRaises(ValueError):
                    await admin.remove_totp_factor(user, factor)
        self.assertFalse(calls)

    async def test_redirects_not_followed_or_treated_as_success(self):
        redirect = httpx.Response(307, headers={"location": "https://example.invalid/private"})
        for sequence in ((redirect,), ([ROW], redirect)):
            admin, calls = self.scripted(*sequence)
            with self.assertRaises(ProviderMfaError):
                await admin.remove_totp_factor(USER, TARGET)
            self.assertEqual(len(calls), len(sequence))
            self.assertTrue(all(url.startswith(BASE) for _, url in calls))

    async def test_bad_list_never_becomes_empty_success_or_leaks_content(self):
        for reply in ({"factors": []}, [ROW, ROW], [{**ROW, "user_id": OTHER}], [{"id": "private"}], [{**ROW, "status": None}],
                      [ROW] * 257, httpx.Response(200, content=b" " * 65536 + b"[]"),
                      httpx.Response(200, content=b"private"), httpx.Response(403, text="private"),
                      httpx.ConnectError("private")):
            admin, calls = self.scripted(reply)
            with self.assertRaises(ProviderMfaError) as error:
                await admin.remove_totp_factor(USER, TARGET)
            self.assertNotIn("private", repr(error.exception))
            self.assertIsNone(error.exception.__context__)
            self.assertEqual(calls, [("GET", BASE)])
