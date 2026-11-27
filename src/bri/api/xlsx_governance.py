"""Local-only XLSX governance. Never mount this assembly on the release API.

Bind to private IP loopback with proxy headers and access logging disabled.
Only signed fixture sessions and explicitly injected private DB scopes are used.
"""
from __future__ import annotations

import json
import re
from collections import OrderedDict
from pathlib import Path
from secrets import token_hex
from time import monotonic
from uuid import UUID, uuid4

import httpx
import psycopg
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from bri.api.csv_intake import (
    Scope, _APP, _NODE, _command, _private_request, _restricted, _stage_socket, _staged_app,
)
from bri.api.database import DatabaseUnavailable
from bri.api.xlsx_intake import _authority_args, _header, _identifier, _json, _upload_body
from bri.ingestion.xlsx_strict import _BAD_TITLE, _SHEET_ID, _valid_rows

REVIEW_PREFIX = '/v1/knowledge/proposals/xlsx'
PUBLISHED_PREFIX = '/v1/knowledge/xlsx'
_REVIEWER = 'bri_xlsx_reviewer'
_READER = 'bri_xlsx_reader'
_QUEUE = 'SELECT bri.xlsx_review_queue(%s,%s,%s,%s,%s,%s,%s)'
_DETAIL = 'SELECT bri.xlsx_review_detail(%s,%s,%s,%s,%s,%s)'
_DECIDE = 'SELECT bri.xlsx_review_decide(%s,%s,%s,%s,%s,%s,%s,%s,%s)'
_PUBLISHED = 'SELECT bri.xlsx_published_detail(%s,%s,%s,%s,%s,%s)'
_EVIDENCE = 'SELECT bri.xlsx_published_evidence(%s,%s,%s,%s,%s,%s,%s)'
_MAX_JSON_BYTES = 524288
_STATES = ('proposed', 'approved', 'rejected')
_RAW_PREFIX = REVIEW_PREFIX.encode('ascii')
_UUID = rb'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
_ITEM = re.compile(_RAW_PREFIX + rb'/xlsx:(' + _UUID + rb')(/decision)?')
_RECORD = re.compile(PUBLISHED_PREFIX.encode('ascii') + rb'/(' + _UUID + rb')(?:/evidence/(' + _UUID + rb'))?')
_NIL = b'00000000-0000-0000-0000-000000000000'
_RECORD_NOT_FOUND = 'XLSX record not found'
_INVALID = 'Invalid XLSX governance request'
_NOT_FOUND = 'XLSX proposal not found'
_AUTHORITY_HEADERS = {'sub', 'sid', 'node-id', 'scope-id', 'user-id', 'auth-user', 'permissions'}


def _guard(request: Request, *, reader: bool) -> dict[bytes, bytes]:
    headers = request.headers
    origins = headers.getlist('origin')
    if origins and origins != [f"{request.scope['scheme']}://{headers['host']}"]:
        raise HTTPException(403, 'Private loopback listener required')
    if (_AUTHORITY_HEADERS.intersection(headers)
            or any(h in headers for h in ('content-encoding', 'content-disposition', 'content-range', 'expect', 'range', 'trailer'))):
        raise HTTPException(400, _INVALID)
    raw = request.scope.get('raw_path', b'')
    if not raw.isascii() or raw.decode('ascii') != request.scope['path']:
        raise HTTPException(404, 'Not Found')
    item = _ITEM.fullmatch(raw)
    record = _RECORD.fullmatch(raw) if reader else None
    if raw == _RAW_PREFIX and request.method == 'GET':
        allowed = {b'limit', b'cursor'}
    elif item and item[1] != _NIL and request.method == ('POST' if item[2] else 'GET'):
        allowed = set() if item[2] else {b'cursor'}
    elif record and _NIL not in record.groups() and request.method == 'GET':
        allowed = {b'cursor'} if record[2] else set()
    else:
        raise HTTPException(404, 'Not Found')
    if request.method == 'GET' and any(h in headers for h in ('content-type', 'transfer-encoding', 'idempotency-key')):
        raise HTTPException(400, _INVALID)
    lengths = headers.getlist('content-length')
    if request.method == 'GET' and len(lengths) == 1 and re.fullmatch(r'[0-9]{1,10}', lengths[0]) and int(lengths[0]):
        raise HTTPException(413, _INVALID)
    if 'transfer-encoding' in headers and (headers.getlist('transfer-encoding') != ['chunked']
                                           or 'content-length' in headers):
        raise HTTPException(400, _INVALID)
    query = request.scope['query_string']
    if len(query) > 256:
        raise HTTPException(400, _INVALID)
    params = {}
    for field in query.split(b'&') if query else ():
        key, sep, value = field.partition(b'=')
        if key not in allowed or key in params or not sep or not value:
            raise HTTPException(400, _INVALID)
        params[key] = value
    if b'limit' in params and not re.fullmatch(rb'[1-9]|1[0-9]|20', params[b'limit']):
        raise HTTPException(400, _INVALID)
    if b'cursor' in params and not re.fullmatch(rb'[0-9a-f]{64}', params[b'cursor']):
        raise HTTPException(400, _INVALID)
    return params


class _Cursors:
    """Opaque, bounded, short-lived continuations for this local process only."""

    def __init__(self):
        self._entries = OrderedDict()

    def issue(self, scope, position) -> str:
        token = token_hex(32)
        self._entries[token] = (monotonic() + 600, scope, position)
        if len(self._entries) > 4096:
            self._entries.popitem(last=False)
        return token

    def read(self, params, scope):
        if b'cursor' not in params:
            return None
        entry = self._entries.get(params[b'cursor'].decode('ascii'))
        if entry is None or entry[0] <= monotonic() or entry[1] != scope:
            raise HTTPException(400, _INVALID)
        return entry[2]


def _item(data) -> tuple[UUID, dict]:
    job = _identifier(data['job_id'])
    node, state = data['node_id'], data['state']
    if not isinstance(node, str) or not _NODE.fullmatch(node) or state not in _STATES:
        raise DatabaseUnavailable('Invalid XLSX review item')
    return job, {'id': f'xlsx:{job}', 'node_id': node, 'state': state}


def _bounded(data) -> JSONResponse:
    response = JSONResponse(data)
    if len(response.body) > _MAX_JSON_BYTES:
        raise DatabaseUnavailable('Oversized XLSX review response')
    return response


def _page(data, start: int, scope, cursors: _Cursors, result: dict) -> JSONResponse:
    identity, title, cell_range, rows = (data[k] for k in ('sheet_id', 'sheet_title', 'cell_range', 'rows'))
    if (not isinstance(identity, str) or not _SHEET_ID.fullmatch(identity)
            or int(identity) > 2**32 - 1 or not isinstance(title, str) or not 1 <= len(title) <= 31
            or _BAD_TITLE.search(title) or not _valid_rows(rows, cell_range)):
        raise DatabaseUnavailable('Invalid XLSX worksheet receipt')
    cells = []
    result.update(sheet_id=identity, sheet_title=title, cell_range=cell_range, cells=cells, next_cursor='0' * 64)
    width = len(rows[0])
    end = len(rows) * width
    if not 0 <= start < end:
        raise DatabaseUnavailable('Invalid XLSX worksheet position')
    # Include the final envelope and continuation in the wire-byte budget.
    size = len(JSONResponse(result).body)
    for index in range(start, min(end, (start // width + 50) * width)):
        row, col = divmod(index, width)
        cell = {'row': row + 1, 'column': col + 1, 'value': rows[row][col]}
        cost = len(json.dumps(cell, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8'))
        cost += bool(cells)
        if size + cost > _MAX_JSON_BYTES:
            break
        cells.append(cell)
        size += cost
    if not cells:
        raise DatabaseUnavailable('XLSX worksheet page cannot advance')
    following = start + len(cells)
    result['next_cursor'] = cursors.issue(scope, following) if following < end else None
    return _bounded(result)


def create_staged_xlsx_governance_app(
    *, identity_scope: Scope, review_scope: Scope, private_socket: Path,
    auth_transport: httpx.MockTransport, dbname: str = 'postgres', port: int = 5432,
    reader_scope: Scope | None = None,
) -> FastAPI:
    scopes = (identity_scope, review_scope) + ((reader_scope,) if reader_scope is not None else ())
    socket = _stage_socket(private_socket, auth_transport, *scopes)
    reader_db = _restricted(reader_scope, socket, dbname, port, _READER) if reader_scope is not None else None
    identity_db = _restricted(identity_scope, socket, dbname, port, _APP)
    review_db = _restricted(review_scope, socket, dbname, port, _REVIEWER)
    _, authorize = _staged_app(identity_db, auth_transport)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False)

    @app.middleware('http')
    async def private(request: Request, call_next):
        cid = uuid4()
        request.state.xlsx_correlation = cid
        try:
            _private_request(request, app, guarded_routes=True)
            request.state.xlsx_params = _guard(request, reader=reader_db is not None)
            response = await call_next(request)
        except HTTPException as exc:
            response = JSONResponse({'detail': exc.detail}, status_code=exc.status_code)
        except psycopg.errors.InsufficientPrivilege:
            detail = _RECORD_NOT_FOUND if request.scope['path'].startswith(PUBLISHED_PREFIX + '/') else _NOT_FOUND
            response = JSONResponse({'detail': detail}, status_code=404)
        except (psycopg.errors.UniqueViolation, psycopg.errors.ObjectNotInPrerequisiteState):
            response = JSONResponse({'detail': 'XLSX governance conflict'}, status_code=409)
        except psycopg.errors.InvalidParameterValue:
            response = JSONResponse({'detail': _INVALID}, status_code=422)
        except Exception:
            response = JSONResponse({'detail': 'XLSX governance unavailable'}, status_code=503)
        response.headers.update({'Cache-Control': 'private, no-store', 'X-Request-ID': str(cid)})
        return response

    cursors = _Cursors()

    @app.get(REVIEW_PREFIX)
    async def queue(request: Request):
        await _upload_body(request, 0)
        authority = await authorize(request, 'knowledge:review')
        params = request.state.xlsx_params
        limit = int(params.get(b'limit', b'20'))
        args = _authority_args(authority)
        scope = (*args, 'queue', limit)
        after = cursors.read(params, scope)
        row = await run_in_threadpool(_command, review_db, _REVIEWER, _QUEUE, (*args, after, limit + 1),
                                      authority=authority, read_only=True)
        if not row or len(row) != 1 or not isinstance(row[0], list) or len(row[0]) > limit + 1:
            raise DatabaseUnavailable('Invalid XLSX review queue receipt')
        items = []
        last = after
        for data in row[0]:
            job, item = _item(data)
            if last is not None and job <= last:
                raise DatabaseUnavailable('Unordered XLSX review queue receipt')
            if len(items) == limit:
                break
            items.append(item)
            last = job
        return _bounded({'items': items, 'next_cursor': cursors.issue(scope, last) if len(row[0]) > limit else None})

    @app.get(REVIEW_PREFIX + '/{item_id}')
    async def detail(request: Request, item_id: str):
        await _upload_body(request, 0)
        authority = await authorize(request, 'knowledge:review')
        job = UUID(item_id[5:])
        args = _authority_args(authority)
        scope = (*args, 'review-detail', job)
        position = cursors.read(request.state.xlsx_params, scope) or 0
        row = await run_in_threadpool(_command, review_db, _REVIEWER, _DETAIL, (*args, job),
                                      authority=authority, read_only=True)
        if row == (None,):
            raise HTTPException(404, _NOT_FOUND)
        data = _json(row)
        found, result = _item(data)
        if found != job:
            raise DatabaseUnavailable('Invalid XLSX review detail receipt')
        return _page(data, position, scope, cursors, result)

    @app.post(REVIEW_PREFIX + '/{item_id}/decision')
    async def decide(request: Request, item_id: str):
        if _header(request, 'content-type', 415).lower() != 'application/json':
            raise HTTPException(415, _INVALID)
        raw, _ = await _upload_body(request, 1024)
        try:
            def unique(pairs):
                result = dict(pairs)
                if len(result) != len(pairs):
                    raise ValueError
                return result

            body = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
            if (type(body) is not dict or body.keys() != {'decision'}
                    or body['decision'] not in ('approve', 'reject')):
                raise ValueError
            key = _identifier(_header(request, 'idempotency-key'))
        except (ValueError, RecursionError):
            raise HTTPException(422, _INVALID) from None
        authority = await authorize(request, 'knowledge:review')
        job = UUID(item_id[5:])
        decision = body['decision']
        row = await run_in_threadpool(_command, review_db, _REVIEWER, _DECIDE,
                                      (*_authority_args(authority), job, decision, key,
                                       request.state.xlsx_correlation), authority=authority)
        if row == (None,):
            raise HTTPException(404, _NOT_FOUND)
        if row != (decision,):
            raise DatabaseUnavailable('Invalid XLSX decision acknowledgement')
        return _bounded({'id': item_id, 'decision': decision})

    if reader_db is not None:
        async def published(request: Request, record_id: str, version_id: str | None = None):
            await _upload_body(request, 0)
            authority = await authorize(request, 'knowledge:read')
            record = UUID(record_id)
            version = UUID(version_id) if version_id is not None else None
            args = _authority_args(authority)
            scope = (*args, 'published-evidence', record, version)
            position = cursors.read(request.state.xlsx_params, scope) or 0
            query, tail = (_EVIDENCE, (record, version)) if version is not None else (_PUBLISHED, (record,))
            row = await run_in_threadpool(_command, reader_db, _READER, query, (*args, *tail),
                                          authority=authority, read_only=True)
            if row == (None,):
                raise HTTPException(404, _RECORD_NOT_FOUND)
            data = _json(row)
            actual_version = _identifier(data['source_version_id'])
            node = data['node_id']
            if (_identifier(data['record_id']) != record or (version is not None and actual_version != version)
                    or not isinstance(node, str) or not _NODE.fullmatch(node)):
                raise DatabaseUnavailable('Invalid XLSX published receipt')
            result = {'record_id': str(record), 'source_version_id': str(actual_version), 'node_id': node}
            if version is None:
                return _bounded(result)
            return _page(data, position, scope, cursors, result)

        app.get(PUBLISHED_PREFIX + '/{record_id}')(published)
        app.get(PUBLISHED_PREFIX + '/{record_id}/evidence/{version_id}')(published)

    return app
