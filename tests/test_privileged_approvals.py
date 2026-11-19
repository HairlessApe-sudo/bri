"""A10 context and provider readback contract, no real identities or services."""

import unittest
from uuid import uuid4

import httpx

from bri.access.approvals import ApprovalContext, ReconciliationMfaAdmin
from bri.api.authentication import AuthenticatedIdentity
from bri.api.database import EXPECTED_PROJECT_REF


class ApprovalBoundary(unittest.IsolatedAsyncioTestCase):
    def test_missing_verified_amr_never_binds_a_database_context(self):
        identity = AuthenticatedIdentity(
            str(uuid4()),
            str(uuid4()),
            f"https://{EXPECTED_PROJECT_REF}.supabase.co/auth/v1",
            "aal2",
            ("totp",),
        )
        with self.assertRaises(PermissionError):
            ApprovalContext("fixture", identity, uuid4()).bind(None)

    async def test_readback_never_confuses_unverified_with_absence(self):
        user, factor = str(uuid4()), str(uuid4())

        def inventory(request):
            self.assertEqual(request.method, "GET")
            return httpx.Response(
                200,
                json=[{"id": factor, "factor_type": "totp", "status": "unverified"}],
            )

        provider = ReconciliationMfaAdmin(test_transport=httpx.MockTransport(inventory))
        self.assertEqual(await provider.list_totp_factor_ids(user), ())
        self.assertFalse(await provider.factor_absent(user, factor))
        self.assertTrue(await provider.factor_absent(user, str(uuid4())))
