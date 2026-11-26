"""Small signed client for the disposable A15 Uvicorn listener only."""
import json
import re

import httpx

PATH = '/v1/reports/published-knowledge-inventory'
ORIGIN = 'http://127.0.0.1:8013'
MAX_BYTES = 512 * 1024


def read_inventory(*, bearer: str, scope_node_id: str):
    """Return (HTTP status, JSON) from the same authorized endpoint the UI uses.

    Pass an in-process fixture bearer (the token without its Bearer prefix).
    No endpoint override, auth mint, retries, redirect or response fallback.
    """
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', scope_node_id):
        raise ValueError('Invalid exact node ID')
    with httpx.Client(trust_env=False, timeout=8) as client, client.stream(
        'GET', ORIGIN + PATH, params={'scope_node_id': scope_node_id},
        headers={'Authorization': f'Bearer {bearer}', 'Accept': 'application/json'}, follow_redirects=False,
    ) as response:
        if response.headers.get('content-type', '').split(';')[0].strip().lower() != 'application/json':
            raise ValueError('Expected JSON from the local reporting listener')
        body = bytearray()
        for chunk in response.iter_bytes(chunk_size=65536):
            if len(body) + len(chunk) > MAX_BYTES:
                raise ValueError('Local reporting response exceeds its byte limit')
            body.extend(chunk)
        return response.status_code, json.loads(body)
