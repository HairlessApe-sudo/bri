import hashlib
import hmac
import json
import unittest
from datetime import UTC, datetime
from secrets import token_bytes
from uuid import uuid4

from bri.access import reenrollment


def signed(key, fields):
    raw = json.dumps(fields).encode()
    return raw, hmac.digest(key, raw, hashlib.sha256)


class ProofAuthentication(unittest.TestCase):
    def test_reject_before_opening_database(self):
        key = token_bytes(32)
        witness = reenrollment.ProofReceiver('provider', 'https://synthetic.invalid/auth/v1', key,
                                             lambda: self.fail('opened database'))
        fields = {'kind': 'totp.created_and_challenge_verified.v1', 'tenant': 'synthetic',
                  'issuer': 'https://synthetic.invalid/auth/v1', 'subject': str(uuid4()), 'factor': str(uuid4()),
                  'case': str(uuid4()), 'operation': str(uuid4()), 'event': str(uuid4()),
                  'happened': datetime.now(UTC).isoformat(), 'created': datetime.now(UTC).isoformat()}
        cases = [signed(token_bytes(32), fields), signed(key, dict(fields, issuer='other')),
                 signed(key, dict(fields, kind='totp.current')), signed(key, dict(fields, case=None)),
                 signed(key, dict(fields, kind='identity.bound_to_factor.v1')),
                 signed(key, dict(fields, subject='')), signed(key, dict(fields, browser_outcome=True))]
        for payload, tag in cases:
            with self.assertRaises(ValueError):
                witness.consume(payload, tag)
