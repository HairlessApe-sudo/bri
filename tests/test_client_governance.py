"""No network, SQL login, credentials or production success simulation."""
import unittest
from datetime import UTC, datetime
from unittest.mock import Mock
from uuid import uuid4

import httpx

from bri.access.governance import refresh_totp_observation
from bri.api.provider_mfa import ProviderMfaAdmin


class ObserverTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.db = Mock()
        self.at = datetime.now(UTC)
        self.db.execute.return_value.fetchone.return_value = (self.at,)
        self.p, self.u = uuid4(), uuid4()

    async def refresh(self, provider):
        await refresh_totp_observation(self.db, provider, tenant_id='synthetic', principal_id=self.p, auth_user_id=self.u)
        args = self.db.execute.call_args.args[1]
        self.assertEqual(args[:3], ('synthetic', self.p, self.u))
        self.assertEqual(args[4],self.at)
        return args[-1]

    async def test_unavailable_directory_writes_unknown_not_last_good(self):
        self.assertIsNone(await self.refresh(ProviderMfaAdmin()))

    async def test_only_verified_totp_for_exact_subject_counts(self):
        for factor, ok in [({'factor_type':'phone','status':'verified'},False),
                           ({'factor_type':'totp','status':'unverified'},False),
                           ({'factor_type':'totp','status':'verified','user_id':str(uuid4())},False),
                           ({'factor_type':'totp','status':'verified'},True)]:
            with self.subTest(factor=factor):
                def inventory(request, *, factor=factor):
                    self.assertEqual(request.method,'GET')
                    self.assertTrue(request.url.path.endswith(f'/{self.u}/factors'))
                    return httpx.Response(200,json=[{'id':str(uuid4()),**factor}])
                until = await self.refresh(ProviderMfaAdmin(test_transport=httpx.MockTransport(inventory)))
                self.assertEqual(until is not None,ok)
                if ok:
                    self.assertGreater(until,self.at)
                    self.assertLessEqual((until-self.at).total_seconds(),900)
