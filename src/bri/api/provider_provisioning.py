"""Server-only provisioning worker and synthetic provider contract.

The fixture is an in-process trust boundary, not a Supabase adapter or an
assertion that any email, setup link or external provider user exists. No live
transport, credentials, environment options or email-based lookup are provided.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal
from uuid import UUID, uuid4

import httpx

from bri.api.database import EXPECTED_PROJECT_REF

ISSUER = f'https://{EXPECTED_PROJECT_REF}.supabase.co/auth/v1'
_FIXTURE = 'https://provisioning-fixture.invalid/v1/operations'
Action = Literal['CLAIM', 'INVITED', 'RETRYABLE', 'UNRESOLVED', 'RECONCILED_INVITED']
WorkCommand = Callable[[UUID, Action, str, UUID | None, UUID], tuple | None]


@dataclass(frozen=True, slots=True)
class _Evidence:
    outcome: Literal['invited', 'confirmed_no_effect', 'unresolved']
    provider_user: UUID | None = None


_UNRESOLVED = _Evidence('unresolved')


def _unique_fields(items: list[tuple]) -> dict:
    result = dict(items)
    if len(result) != len(items):
        raise ValueError('Duplicate fixture proof field')
    return result


class FixtureInvitationProvider:
    def __init__(self, transport: httpx.MockTransport):
        if type(transport) is not httpx.MockTransport:
            raise ValueError('In-process invitation fixture required')
        self._transport = transport

    def invite(self, operation: UUID, attempt: UUID, email: str) -> _Evidence:
        return self._verify(operation, attempt, email=email)

    def reconcile(self, operation: UUID, attempt: UUID) -> _Evidence:
        return self._verify(operation, attempt)

    def _verify(self, operation: UUID, attempt: UUID, *, email: str | None = None) -> _Evidence:
        url = f'{_FIXTURE}/{operation}/attempts/{attempt}'
        try:
            with httpx.Client(transport=self._transport, trust_env=False, follow_redirects=False) as client:
                response = client.get(url) if email is None else client.post(url, json={'email': email})
            if response.status_code != 200 or len(response.content) > 4096:
                return _UNRESOLVED
            proof = response.json(object_pairs_hook=_unique_fields)
            if not isinstance(proof, dict) or (
                proof.get('issuer'), proof.get('operation'), proof.get('attempt')
            ) != (ISSUER, str(operation), str(attempt)):
                return _UNRESOLVED
            keys = {'issuer', 'operation', 'attempt', 'outcome'}
            if email is not None and proof['outcome'] == 'confirmed_no_effect' and proof.keys() == keys:
                return _Evidence('confirmed_no_effect')
            if proof['outcome'] == 'invited' and proof.keys() == keys | {'provider_user'}:
                uid = UUID(proof['provider_user'])
                if uid.int and str(uid) == proof['provider_user']:
                    return _Evidence('invited', uid)
        except Exception:  # noqa: BLE001 -- Untrusted provider failures must not authorize a retry.
            # Malformed evidence, lost response or fixture handler failure never
            # authorizes binding or a retry. Do not expose provider diagnostics.
            return _UNRESOLVED
        return _UNRESOLVED


@dataclass(frozen=True, slots=True)
class WorkerResult:
    id: UUID
    status: str
    attempt_id: UUID


class ProvisioningWorker:
    """The injected command returns only after its own transaction commits."""

    def __init__(self, command: WorkCommand, provider: FixtureInvitationProvider):
        self._command = command
        self._provider = provider

    def _write(self, operation: UUID, action: Action, uid: UUID | None, attempt: UUID):
        if not isinstance(operation, UUID) or not isinstance(attempt, UUID):
            raise TypeError('Provisioning worker requires UUIDs')
        return self._command(operation, action, ISSUER, uid, attempt)

    def dispatch(self, operation: UUID) -> WorkerResult | None:
        # Every CLAIM has a fresh fence; every completion uses the same fence.
        attempt = uuid4()
        claim = self._write(operation, 'CLAIM', None, attempt)
        if not claim or claim[:2] != (operation, 'inviting') or not claim[2]:
            return None
        evidence = self._provider.invite(operation, attempt, claim[2])
        action: Action
        if evidence.outcome == 'invited':
            action = 'INVITED'
        elif evidence.outcome == 'confirmed_no_effect':
            action = 'RETRYABLE'
        else:
            action = 'UNRESOLVED'
        row = self._write(operation, action, evidence.provider_user, attempt)
        return WorkerResult(row[0], row[1], attempt) if row else None

    def reconcile(self, operation: UUID, attempt_id: UUID) -> WorkerResult | None:
        """Independently check authoritative fixture evidence; never issue an invite."""
        if not isinstance(operation, UUID) or not isinstance(attempt_id, UUID):
            raise TypeError('Provisioning worker requires UUIDs')
        proof = self._provider.reconcile(operation, attempt_id)
        if proof.outcome != 'invited':
            return None
        row = self._write(operation, 'RECONCILED_INVITED', proof.provider_user, attempt_id)
        return WorkerResult(row[0], row[1], attempt_id) if row else None
