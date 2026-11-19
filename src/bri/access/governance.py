"""Trusted observation worker seam. Not an HTTP endpoint or a dev-identity adapter."""
from datetime import timedelta
from uuid import UUID

import psycopg

from bri.api.database import EXPECTED_PROJECT_REF
from bri.api.provider_mfa import ProviderMfaAdmin, ProviderMfaError


async def refresh_totp_observation(
    connection: psycopg.Connection,
    provider: ProviderMfaAdmin,
    *,
    tenant_id: str,
    principal_id: UUID,
    auth_user_id: UUID,
) -> None:
    """Refresh one *platform-selected* binding using only server-side inventory.

    Call from a restricted, separately provisioned observer transaction (not
    bri_app). Commit negative observations too. Missing factors, disabled live
    transport and unavailable inventory all mean unknown/ineligible. Never feed
    this function browser-selected IDs, timestamps or a factor/eligibility flag.
    The SQL gate, not the return from this worker, decides eligibility.
    """
    # Use database time at the START of the lookup; delayed replies must not
    # extend freshness or overwrite a newer negative. No lock during I/O.
    row = connection.execute("SELECT clock_timestamp()").fetchone()
    if row is None:
        raise RuntimeError("database observation clock unavailable")
    observed = row[0]
    try:
        factors = await provider.list_totp_factor_ids(str(auth_user_id))
    except ProviderMfaError:
        factors = ()
    connection.execute(
        "SELECT bri.record_client_totp_observation(%s,%s,%s,%s,%s,%s)",
        (tenant_id, principal_id, auth_user_id, f"https://{EXPECTED_PROJECT_REF}.supabase.co/auth/v1",
         observed, observed + timedelta(minutes=15) if factors else None),
    )
