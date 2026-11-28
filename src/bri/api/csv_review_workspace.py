"""A14 fixture-only CSV review API. Not mounted by the release app."""
from __future__ import annotations

import re
from pathlib import Path
from uuid import UUID

import httpx
import psycopg
from fastapi import FastAPI, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from bri.api.csv_intake import (
    REVIEW_PREFIX, Scope, _APP, _INTAKE, _Authority, _body, _command, _decision, _restricted,
    _stage_socket, _staged_app,
)
from bri.api.database import DatabaseUnavailable
from bri.api.knowledge_metadata import mount_review
from bri.ingestion.csv_intake import MAX_EXTRACTED_BYTES

_QUEUE = 'SELECT bri.csv_review_queue(%s,%s,%s,%s,%s,%s,%s,%s)'
_DETAIL = 'SELECT bri.csv_review_detail(%s,%s,%s,%s,%s,%s,%s)'
_DECIDE = 'SELECT bri.csv_review_decide(%s,%s,%s,%s,%s,%s,%s)'
_RAW_PREFIX = REVIEW_PREFIX.encode('ascii')
_UUID = rb'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
_RAW_ITEM = re.compile(_RAW_PREFIX + rb'/csv:(' + _UUID + rb')(/decision)?')
_STATES = frozenset({b'proposed', b'approved', b'rejected', b'failed'})
_QUEUE_MAX = 50
_BAD_QUERY = 'Invalid CSV review query'
_NOT_FOUND = 'CSV proposal not found'
_AUTHORITY_HEADERS = frozenset({'sub', 'sid', 'node-id', 'scope-id', 'user-id', 'auth-user', 'permissions'})


def _decimal(value: bytes, minimum: int, maximum: int) -> int:
    if (len(value) <= len(str(maximum)) and re.fullmatch(rb'0|[1-9][0-9]*', value)
            and minimum <= (number := int(value)) <= maximum):
        return number
    raise HTTPException(400, _BAD_QUERY)


def _guard(request: Request) -> None:
    origins = request.headers.getlist('origin')
    if origins and origins != [f"{request.scope['scheme']}://{request.headers['host']}"]:
        raise HTTPException(403, 'Private loopback listener required')
    if _AUTHORITY_HEADERS.intersection(request.headers):
        raise HTTPException(400, 'Authority is server-controlled')
    raw = request.scope.get('raw_path', b'')
    if not raw or not raw.isascii() or raw.decode('ascii') != request.scope['path']:
        raise HTTPException(404, 'Not Found')
    item = None if raw == _RAW_PREFIX else _RAW_ITEM.fullmatch(raw)
    if raw == _RAW_PREFIX and request.method == 'GET':
        allowed = {b'status', b'after', b'limit'}
    elif item and UUID(item[1].decode('ascii')).int and request.method == ('POST' if item[2] else 'GET'):
        allowed = set() if item[2] else {b'offset'}
    else:
        raise HTTPException(404, 'Not Found')
    query = request.scope['query_string']
    if len(query) > 128:
        raise HTTPException(400, _BAD_QUERY)
    params = {}
    for field in query.split(b'&') if query else ():
        key, sep, value = field.partition(b'=')
        if key not in allowed or key in params or not sep or not value:
            raise HTTPException(400, _BAD_QUERY)
        params[key] = value
    if raw == _RAW_PREFIX:
        status = params.get(b'status', b'proposed')
        after_text = params.get(b'after')
        after = UUID(after_text.decode('ascii')) if after_text is not None and re.fullmatch(_UUID, after_text) else None
        if status not in _STATES or (after_text is not None and (after is None or not after.int)):
            raise HTTPException(400, _BAD_QUERY)
        request.state.csv_review_page = (
            status.decode('ascii'), after,
            _decimal(params[b'limit'], 1, _QUEUE_MAX) if b'limit' in params else _QUEUE_MAX,
        )
    elif allowed:
        request.state.csv_review_offset = _decimal(params.get(b'offset', b'0'), 0, MAX_EXTRACTED_BYTES)


def _read_args(authority: _Authority) -> tuple:
    return authority.tenant, authority.actor, UUID(authority.uid), authority.sid, authority.issuer


def create_staged_csv_review_app(
    *, identity_scope: Scope, review_scope: Scope, private_socket: Path, auth_transport: httpx.MockTransport,
    dbname: str = 'postgres', port: int = 5432, enable_metadata: bool = False,
) -> FastAPI:
    """Serve on the private IP loopback listener (:8114), without proxy headers or access logs."""
    socket = _stage_socket(private_socket, auth_transport, identity_scope, review_scope)
    identity_db = _restricted(identity_scope, socket, dbname, port, _APP)
    review_db = _restricted(review_scope, socket, dbname, port, _INTAKE)
    app, authorize = _staged_app(identity_db, auth_transport, private_guard=_guard, enable_metadata=enable_metadata)

    @app.get(REVIEW_PREFIX)
    async def queue(request: Request):
        await _body(request, 0)
        authority = await authorize(request, 'knowledge:review')
        row = await run_in_threadpool(_command, review_db, _INTAKE, _QUEUE, (
            *_read_args(authority), *request.state.csv_review_page,
        ), authority=authority, read_only=True)
        if not row or not isinstance(row[0], dict):
            raise DatabaseUnavailable('Unexpected CSV review queue result')
        return row[0]

    @app.get(REVIEW_PREFIX + '/{item_id}')
    async def detail(request: Request, item_id: str):
        await _body(request, 0)
        authority = await authorize(request, 'knowledge:review')
        row = await run_in_threadpool(_command, review_db, _INTAKE, _DETAIL, (
            *_read_args(authority), UUID(item_id[4:]), request.state.csv_review_offset,
        ), authority=authority, read_only=True)
        if row == (None,):
            raise HTTPException(404, _NOT_FOUND)
        if not row or not isinstance(row[0], dict):
            raise DatabaseUnavailable('Unexpected CSV review detail result')
        return row[0]

    @app.post(REVIEW_PREFIX + '/{item_id}/decision')
    async def decide(request: Request, item_id: str):
        decision = await _decision(request)
        authority = await authorize(request, 'knowledge:review')
        try:
            row = await run_in_threadpool(_command, review_db, _INTAKE, _DECIDE, (
                *authority.args, UUID(item_id[4:]), decision, request.state.csv_correlation,
            ), authority=authority)
        except psycopg.errors.InsufficientPrivilege as exc:
            # Keep A12's final authority recheck indistinguishable from an
            # unavailable item, but do not mask an unexpected database ACL failure.
            if exc.diag.message_primary == 'CSV review denied':
                raise HTTPException(404, _NOT_FOUND) from None
            raise DatabaseUnavailable('CSV review command unavailable') from None
        if row == (None,):
            raise HTTPException(404, _NOT_FOUND)
        if row != (decision,):
            raise DatabaseUnavailable('Unexpected CSV decision result')
        return {'id': item_id, 'decision': decision}

    if enable_metadata:
        mount_review(app, authorize, review_db, _INTAKE, 'csv')
    return app
