"""Private adapter contract; signed synthetic messages, no provider or network."""
import hashlib
import hmac
import json
import secrets
import unittest
from uuid import uuid4

ISSUER = 'https://synthetic.invalid/auth/v1'
DOMAIN = b'BRI.provider-security.v1\0'


class SourceAuthentication(unittest.TestCase):
    def test_unsigned_input_never_opens_database(self):
        from bri.api.provider_events import EventRejected, ProviderEventConsumer
        consumer = ProviderEventConsumer(ISSUER, secrets.token_bytes(32), lambda: self.fail('opened DB'))
        with self.assertRaises(EventRejected):
            consumer.consume(b'{}', '0' * 64)

    def test_even_signed_invalid_evidence_never_opens_database(self):
        from bri.api.provider_events import EventRejected, ProviderEventConsumer
        key = secrets.token_bytes(32)
        consumer = ProviderEventConsumer(ISSUER,key,lambda: self.fail('opened DB'))
        event = {'issuer': ISSUER,'event_id': str(uuid4()),'subject': str(uuid4()),'action': 'factor_deleted',
                     'occurred_at': '2026-01-01T00:00:00Z','outcome': 'success','operation_id': None}
        invalid = [{'issuer': 'https://other.invalid/auth/v1'},{'event_id': 'bad'},{'subject': 0},
                   {'action': 'arbitrary'},{'operation_id': str(uuid4())},{'occurred_at': '9999-01-01T00:00:00Z'},
                   {'occurred_at': '2026-01-01'},{'outcome': 'observed'},{'tenant': 'synthetic'},
                   {'principal': 'synthetic'},{'metadata': {}},{'session_id': str(uuid4())}]
        bodies = [json.dumps(dict(event,**invalid_event)).encode() for invalid_event in invalid]
        bodies += [b'{"issuer":"duplicate",'+json.dumps(event).encode()[1:], b'{}', b' ' * 2049]
        for body in bodies:
            with self.subTest(body=body), self.assertRaises(EventRejected):
                consumer.consume(body,hmac.new(key,DOMAIN+body,hashlib.sha256).hexdigest())
        body = json.dumps(event).encode()
        for domain, signer in [(b'',key),(DOMAIN,secrets.token_bytes(32))]:
            with self.assertRaises(EventRejected):
                consumer.consume(body,hmac.new(signer,domain+body,hashlib.sha256).hexdigest())
