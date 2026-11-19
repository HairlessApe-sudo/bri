"""Offline, single-authority receiver. No route, key discovery, provider SDK or hosted default."""
from __future__ import annotations

import hmac
import json
from collections.abc import Callable
from datetime import datetime
from uuid import UUID

import psycopg

_KINDS = {'platform': 'identity.bound_to_factor.v1', 'provider': 'totp.created_and_challenge_verified.v1'}
_FIELDS = {'kind', 'tenant', 'issuer', 'operation', 'subject', 'factor', 'case', 'event', 'happened', 'created'}


def _unique_fields(pairs):
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError('ambiguous proof')
    return obj


def _id(value: str) -> UUID:
    parsed = UUID(value)
    if not parsed.int or str(parsed) != value:
        raise ValueError('invalid proof identifier')
    return parsed


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.utcoffset() is None:
        raise ValueError('proof requires an absolute time')
    return parsed


class ProofReceiver:
    """Pin one signing channel to one login. Never give one service both keys/logins.

    A tag authenticates who made the assertion, not whether the upstream ceremony
    exists. Do not provision a signer without the causal sources described in
    architecture/controlled-reenrollment.md. No signing operation here.
    """

    def __init__(self, authority: str, issuer: str, key: bytes, connect: Callable[[], psycopg.Connection]):
        if authority not in _KINDS or not issuer or not isinstance(key, bytes) or len(key) < 32:
            raise ValueError('unconfigured proof receiver')
        self._authority, self._issuer, self._key, self._connect = authority, issuer, key, connect

    def consume(self, payload: bytes, tag: bytes) -> str:
        if (not isinstance(payload, bytes) or not 0 < len(payload) <= 4096 or not isinstance(tag, bytes)
                or not hmac.compare_digest(hmac.digest(self._key, payload, 'sha256'), tag)):
            raise ValueError('unauthenticated proof')
        try:
            obj = json.loads(payload.decode('utf-8'), object_pairs_hook=_unique_fields)
            platform = self._authority == 'platform'
            if (not isinstance(obj, dict) or set(obj) != _FIELDS or obj['issuer'] != self._issuer
                    or obj['kind'] != _KINDS[self._authority] or not isinstance(obj['tenant'], str)
                    or not obj['tenant'] or platform != (obj['created'] is None)):
                raise ValueError
            args = (obj['tenant'], _id(obj['operation']), self._issuer, _id(obj['subject']), _id(obj['factor']),
                    _id(obj['case']), _id(obj['event']), _time(obj['happened']),
                    None if platform else _time(obj['created']))
        except (AttributeError, TypeError, ValueError, RecursionError):
            raise ValueError('invalid authenticated proof') from None
        role = 'bri_reenrollment_' + self._authority
        with self._connect() as db:
            if db.execute('SELECT session_user,current_user').fetchone() != (role, role):
                raise PermissionError('incorrect proof receiver login')
            row = db.execute('SELECT bri.record_reenrollment_proof(%s,%s,%s,%s,%s,%s,%s,%s,%s)', args).fetchone()
            if row is None or row[0] not in ({'awaiting_provider', 'duplicate'} if platform else {'confirmed', 'duplicate'}):
                raise RuntimeError('unrecognized proof disposition')
            return row[0]
