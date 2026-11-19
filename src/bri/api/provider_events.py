"""A10 private worker adapter. No routes, environment loading, provider I/O or signer."""
from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID

import psycopg

_DOMAIN = b"BRI.provider-security.v1\0"
_FIELDS = {"issuer", "event_id", "subject", "action", "outcome", "occurred_at", "operation_id"}
_CHANGES = {"user_updated_password", "factor_deleted", "factor_unenrolled", "factor_updated",
            "generate_recovery_codes", "recovery_codes_deleted"}
_AUDIT = {"login", "logout", "user_recovery_requested", "user_reauthenticate_requested",
          "factor_in_progress", "challenge_created", "verification_attempted", "mfa_code_login"}


class EventRejected(ValueError):
    """Do not acknowledge as processed. Never include the original payload in logs."""


class IngestionUnavailable(RuntimeError):
    """No acknowledged commit; retain original message for replay/reconciliation."""


def _unique_object(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise EventRejected("duplicate field")
    return result


def _uuid(value: str) -> UUID:
    uid = UUID(value)
    if str(uid) != value or not uid.int:
        raise EventRejected("invalid identifier")
    return uid


class ProviderEventConsumer:
    def __init__(self, issuer: str, key: bytes, connect: Callable[[], psycopg.Connection]):
        if (not re.fullmatch(r"https://[a-z0-9.-]+/auth/v1", issuer) or len(issuer) > 512
                or type(key) is not bytes or len(key) < 32):
            raise ValueError("invalid trusted source configuration")
        self._issuer, self._key, self._connect = issuer, key, connect

    def consume(self, body: bytes, signature: str) -> str:
        """Verify exact bytes from a project-pinned forwarder, then commit or raise."""
        if (type(body) is not bytes or not 0 < len(body) <= 2048 or type(signature) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", signature)
                or not hmac.compare_digest(signature, hmac.digest(self._key, _DOMAIN + body,
                                                                   hashlib.sha256).hex())):
            raise EventRejected("unauthenticated delivery")
        try:
            obj = json.loads(body.decode("utf-8"), object_pairs_hook=_unique_object)
            if (type(obj) is not dict or obj.keys() != _FIELDS or obj["issuer"] != self._issuer
                    or any(type(obj[k]) is not str for k in _FIELDS - {"operation_id"})):
                raise ValueError
            action, outcome = obj["action"], obj["outcome"]
            if (action not in _CHANGES | _AUDIT or outcome not in {"observed", "success", "failure", "denied"}
                    or (action in _CHANGES and outcome != "success")):
                raise ValueError
            moment = obj["occurred_at"]
            if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z", moment):
                raise ValueError
            when = datetime.fromisoformat(moment)
            if when > datetime.now(UTC):
                raise ValueError
            op = obj["operation_id"]
            if op is not None and (type(op) is not str or action != "user_updated_password"):
                raise ValueError
            args = (self._issuer, _uuid(obj["event_id"]), _uuid(obj["subject"]), action, outcome,
                    when, None if op is None else _uuid(op))
        except (ValueError, TypeError, RecursionError):
            raise EventRejected("invalid security event") from None

        # A fresh connection authenticated as the infrastructure login (not SET ROLE).
        # No bootstrap/app DSN fallback, ambient transaction or early ack.
        try:
            with self._connect() as conn:
                if conn.autocommit or conn.info.transaction_status != psycopg.pq.TransactionStatus.IDLE:
                    raise IngestionUnavailable("fresh transactional connection required")
                if conn.execute("SELECT session_user, current_user").fetchone() != (
                    "bri_provider_ingest", "bri_provider_ingest"
                ):
                    raise IngestionUnavailable("restricted provider login required")
                row = conn.execute("SELECT bri.ingest_provider_security_event(%s,%s,%s,%s,%s,%s,%s)", args).fetchone()
                if not row or row[0] not in ("applied", "duplicate"):
                    raise IngestionUnavailable("unconfirmed event transaction")
            return row[0]
        except psycopg.Error:
            raise IngestionUnavailable("event transaction not acknowledged") from None
