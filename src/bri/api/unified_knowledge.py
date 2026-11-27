"""Dedicated local signed-fixture API for unified governed knowledge reads."""
import asyncio
import json
import re
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import psycopg
from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse

from bri.api.authentication import (
    AuthenticatedIdentity, AuthenticationRejected, AuthenticationUnavailable, SupabaseTokenVerifier,
)
from bri.api.csv_intake import (
    Scope, _APP, _NODE, _ORIGIN, _check_role, _private_request, _restricted, _stage_socket, _staged_app,
)
from bri.api.database import Database, DatabaseUnavailable, _LIVE_SESSION_SQL
from bri.api.xlsx_intake import _authority_args, _upload_body
from bri.ingestion.xlsx_strict import _BAD_TITLE

SEARCH = '/v1/knowledge/search'
SEARCH_SCOPES = SEARCH + '/scopes'
CSV_EVIDENCE = '/v1/knowledge/csv/{record_id}/versions/{version_id}/evidence'
_ROLE = 'bri_unified_knowledge_reader'
_SEARCH_SQL = 'SELECT bri.unified_knowledge_search(%s,%s,%s,%s,%s,%s,%s)'
_SCOPES_SQL = 'SELECT bri.unified_knowledge_search_scopes(%s,%s,%s,%s,%s)'
_DISCOVERY_IDENTITY_SQL = f'''SELECT m.tenant_id,p.principal_id
    FROM bri.auth_identity_links i JOIN bri.auth_principals p USING (principal_id)
    JOIN bri.auth_sessions s USING (auth_user_id,principal_id)
    JOIN bri.auth_tenant_memberships m USING (principal_id)
    WHERE (i.auth_user_id,i.auth_issuer,i.auth_subject,s.session_id)=(%s,%s,%s,%s)
      AND i.status='active' AND i.provider_type='native'
      AND p.status='active' AND p.deletion_requested_at IS NULL
      AND m.status='active' AND m.membership_type IN ('user','superuser','admin')
      AND NOT EXISTS (SELECT FROM bri.platform_superadmins x WHERE x.principal_id=p.principal_id)
      AND ({_LIVE_SESSION_SQL})
    LIMIT 2'''
_EVIDENCE_SQL = 'SELECT bri.unified_csv_evidence(%s,%s,%s,%s,%s,%s,%s)'
_UUID = r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
_EVIDENCE_PATH = re.compile(CSV_EVIDENCE.replace('{record_id}', f'({_UUID})').replace('{version_id}', f'({_UUID})'))
_MAX_REQUEST_BYTES = 4096
_MAX_RECEIPT_BYTES = 131072
_MAX_QUERY_BYTES = 256
_ASCII_WHITESPACE = re.compile(r'[ \t\n\r\f\v]+')
_ASCII_FOLD = str.maketrans('ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')
_ID = re.compile(_UUID)
_SHEET_ID = re.compile(r'[1-9][0-9]{0,9}')
_CELL = re.compile(r'([A-Z]{1,2})([1-9][0-9]{0,4})')
_INVALID = 'Invalid knowledge request'
_EVIDENCE_DENIED = 'Knowledge evidence not found'
_SEARCH_DENIED = 'Current authorized BRI session required'
_XLSX_EVIDENCE = '/v2/knowledge/xlsx/{record_id}/evidence/{version_id}'
_HIT_KEYS = {'format', 'record_id', 'source_id', 'source_version_id', 'original_sha256', 'match',
             'excerpt', 'excerpt_truncated', 'evidence', 'evidence_url'}
_FORMAT_KEYS = {'csv': {'content_sha256'},
                'xlsx': {'canonical_sha256', 'extractor_version', 'canonicalization_version'}}


def _digest(value) -> bool:
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def _unique_fields(pairs):
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError('Duplicate field')
    return fields


async def _search_input(request: Request) -> tuple[str, str]:
    if request.headers.getlist('content-type') not in (['application/json'], ['application/json; charset=utf-8']):
        raise HTTPException(415, _INVALID)
    body, _ = await _upload_body(request, _MAX_REQUEST_BYTES)
    try:
        data = json.loads(body.decode('utf-8'), object_pairs_hook=_unique_fields)
        if not isinstance(data, dict) or data.keys() != {'scope_node_id', 'query'}:
            raise ValueError
        node, query = data['scope_node_id'], data['query']
        if (not isinstance(node, str) or not _NODE.fullmatch(node) or not isinstance(query, str)
                or any((ord(char) < 32 and char not in '\t\n\r\f\v') or char == '\x7f' for char in query)):
            raise ValueError
        # Match the SQL C-collation fold, not Python Unicode lower/whitespace.
        query = _ASCII_WHITESPACE.sub(' ', query).strip(' ').translate(_ASCII_FOLD)
        if not query or len(query.encode('utf-8')) > _MAX_QUERY_BYTES:
            raise ValueError
    except (RecursionError, ValueError):
        raise HTTPException(422, _INVALID) from None
    return node, query


def _read(scope: Scope, sql: str, args: tuple):
    with scope() as db, db.transaction():
        db.execute('SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY')
        db.execute("SET LOCAL statement_timeout = '5000ms'")
        _check_role(db, _ROLE)
        if db.execute("SELECT setting::integer BETWEEN 0 AND 16384 FROM pg_catalog.pg_settings "
                      "WHERE name = 'temp_file_limit'").fetchone() != (True,):
            raise DatabaseUnavailable('Finite knowledge reader temp budget required')
        row = db.execute(sql, args).fetchone()
    if type(row) is not tuple or len(row) != 1:
        raise DatabaseUnavailable('Invalid knowledge receipt')
    return row[0]


def _lines(data: dict) -> bool:
    first, last = data['first_line'], data['last_line']
    return type(first) is int and type(last) is int and 1 <= first <= last <= 2147483647


def _cell_reference(data: dict) -> bool:
    sheet, cell = data['sheet_id'], data['cell']
    if (not isinstance(sheet, str) or not _SHEET_ID.fullmatch(sheet) or int(sheet) > 4294967295
            or not isinstance(cell, str) or not (match := _CELL.fullmatch(cell))):
        return False
    column, row = match.groups()
    # Accepted strict XLSX profile: A through BL, rows 1 through 10000.
    return (len(column) == 1 or column <= 'BL') and int(row) <= 10000


def _search_receipt(data) -> JSONResponse:
    if (type(data) is not dict or data.keys() != {'version', 'status', 'results'}
            or type(data['version']) is not int or data['version'] != 1 or data['status'] != 'complete'
            or type(data['results']) is not list or len(data['results']) > 20):
        raise DatabaseUnavailable('Invalid search result envelope')
    seen = set()
    for item in data['results']:
        if (type(item) is not dict or not isinstance(kind := item.get('format'), str)
                or kind not in _FORMAT_KEYS or item.keys() != _HIT_KEYS | _FORMAT_KEYS[kind]):
            raise DatabaseUnavailable('Invalid search result')
        record, version, excerpt, evidence = (item[k] for k in
                                               ('record_id', 'source_version_id', 'excerpt', 'evidence'))
        if (not all(isinstance(v, str) and _ID.fullmatch(v) and UUID(v).int for v in (record, version))
                or not isinstance(excerpt, str) or not 1 <= len(excerpt.encode('utf-8')) <= 2048
                or type(item['excerpt_truncated']) is not bool or item['match'] not in ('exact', 'substring')
                or not _digest(item['original_sha256']) or type(evidence) is not dict
                or (kind, record) in seen):
            raise DatabaseUnavailable('Invalid search result provenance')
        if kind == 'csv':
            valid = (record == version and item['source_id'] == 'csv:' + version and _digest(item['content_sha256'])
                     and evidence.keys() == {'first_line', 'last_line'} and _lines(evidence))
            url = CSV_EVIDENCE.format(record_id=record, version_id=version)
        else:
            title = evidence.get('sheet_title')
            valid = (item['source_id'] == version and _digest(item['canonical_sha256'])
                     and all(type(item[key]) is int and item[key] == 1 for key in ('extractor_version', 'canonicalization_version'))
                     and evidence.keys() == {'sheet_id', 'sheet_title', 'cell'} and _cell_reference(evidence)
                     and isinstance(title, str) and 1 <= len(title) <= 31 and _BAD_TITLE.search(title) is None)
            url = _XLSX_EVIDENCE.format(record_id=record, version_id=version)
        if not valid or item['evidence_url'] != url:
            raise DatabaseUnavailable('Invalid search result provenance')
        seen.add((kind, record))
    return _bounded(data)


def _bounded(data) -> JSONResponse:
    response = JSONResponse(data)
    if len(response.body) > _MAX_RECEIPT_BYTES:
        raise DatabaseUnavailable('Knowledge receipt exceeds byte budget')
    return response


async def _verify_discovery_session(request: Request, transport: httpx.MockTransport) -> AuthenticatedIdentity:
    auth = request.headers.getlist('authorization')
    if len(auth) != 1 or not re.fullmatch(r'Bearer [^\s]{1,16384}', auth[0]):
        raise HTTPException(401, 'Verified bearer identity required')
    try:
        async with httpx.AsyncClient(transport=transport, trust_env=False, timeout=5, follow_redirects=False) as client:
            return await SupabaseTokenVerifier(_ORIGIN, 'csv-stage-only', client=client).verify(auth[0][7:])
    except AuthenticationRejected:
        raise HTTPException(401, 'Authentication rejected') from None
    except AuthenticationUnavailable:
        raise DatabaseUnavailable('Knowledge identity unavailable') from None


def _discovery_identity(scope: Scope, identity: AuthenticatedIdentity) -> tuple[str, UUID, UUID, UUID, str]:
    # Exact native identity, membership and live-session rows only. The
    # protected reader independently evaluates the issuer, guards, tenant and
    # exact-node permission. Do not construct a Principal or a grant inventory.
    uid, sid = UUID(identity.auth_user_id), UUID(identity.session_id)
    with scope() as db, db.transaction():
        db.execute('SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY')
        db.execute("SET LOCAL statement_timeout = '1000ms'")
        _check_role(db, _APP)
        Database._set_auth_user_context(db, str(uid))
        rows = db.execute(_DISCOVERY_IDENTITY_SQL, (uid, identity.issuer, str(uid), sid)).fetchall()
    if len(rows) != 1:
        raise HTTPException(403, _SEARCH_DENIED)
    tenant, actor = rows[0]
    return tenant, actor, uid, sid, identity.issuer


def _scope_receipt(data) -> JSONResponse:
    if (type(data) is not dict or data.keys() != {'version', 'status', 'scopes'}
            or type(data['version']) is not int or data['version'] != 1 or data['status'] != 'complete'
            or type(data['scopes']) is not list or len(data['scopes']) > 500):
        raise DatabaseUnavailable('Invalid scope receipt envelope')
    seen = set()
    previous = None
    for entry in data['scopes']:
        if type(entry) is not dict or entry.keys() != {'scope_node_id', 'display_label'}:
            raise DatabaseUnavailable('Invalid scope entry')
        node, label = entry['scope_node_id'], entry['display_label']
        if not isinstance(node, str) or not _NODE.fullmatch(node) or not isinstance(label, str) or node in seen:
            raise DatabaseUnavailable('Invalid scope association')
        key = (label, node)  # Unicode scalar order is UTF-8 byte order (PostgreSQL COLLATE C).
        if previous is not None and key <= previous:
            raise DatabaseUnavailable('Invalid scope ordering')
        previous = key
        seen.add(node)
    return _bounded(data)


def create_staged_unified_knowledge_app(
    *, identity_scope: Scope, reader_scope: Scope, private_socket: Path,
    auth_transport: httpx.MockTransport, dbname: str = 'postgres', port: int = 5432,
) -> FastAPI:
    socket = _stage_socket(private_socket, auth_transport, identity_scope, reader_scope)
    identity = _restricted(identity_scope, socket, dbname, port, _APP)
    reader = _restricted(reader_scope, socket, dbname, port, _ROLE)
    _, authorize = _staged_app(identity, auth_transport)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False)

    @app.middleware('http')
    async def private(request: Request, call_next):
        path = request.scope['path']
        evidence = _EVIDENCE_PATH.fullmatch(path)
        search = path == SEARCH and request.method == 'POST'
        discovery = path == SEARCH_SCOPES and request.method == 'GET'
        try:
            _private_request(request, app, guarded_routes=True)
            if (request.scope.get('raw_path') != path.encode('utf-8') or not (
                    search or discovery or (evidence and request.method == 'GET'
                                            and all(UUID(v).int for v in evidence.groups())))):
                raise HTTPException(404, 'Not Found')
            headers = request.headers
            origins = headers.getlist('origin')
            if origins and origins != [f"{request.scope['scheme']}://{headers['host']}"]:
                raise HTTPException(403, 'Private loopback listener required')
            if (request.scope['query_string'] or any(h in headers for h in (
                    'sub', 'sid', 'node-id', 'scope-id', 'user-id', 'auth-user', 'permissions', 'content-encoding',
                    'content-disposition', 'content-range', 'expect', 'range', 'trailer', 'idempotency-key'))
                    or (not search and any(h in headers for h in ('content-type', 'transfer-encoding')))
                    or (discovery and any(h in headers for h in ('permission', 'scope', 'scope-node-id',
                                                                 'identity', 'identity-id', 'membership')))
                    or ('transfer-encoding' in headers and (headers.getlist('transfer-encoding') != ['chunked']
                                                           or 'content-length' in headers))):
                raise HTTPException(400, _INVALID)
            response = await call_next(request)
        except HTTPException as exc:
            response = JSONResponse({'detail': exc.detail}, status_code=exc.status_code)
        except psycopg.errors.InsufficientPrivilege:
            response = JSONResponse({'detail': _SEARCH_DENIED if search or discovery else _EVIDENCE_DENIED},
                                    status_code=403 if search or discovery else 404)
        except Exception:
            response = JSONResponse({'version': 1, 'status': 'unavailable'} if search or discovery else {'detail': 'Knowledge evidence unavailable'},
                                    status_code=503)
        response.headers.update({'Cache-Control': 'private, no-store', 'X-Request-ID': str(uuid4())})
        return response

    @app.post(SEARCH)
    async def search(request: Request):
        node, query = await _search_input(request)
        try:
            authority = await authorize(request, 'knowledge:read', node)
        except HTTPException as exc:
            if exc.status_code == 503:
                raise DatabaseUnavailable('Knowledge identity unavailable') from None
            raise
        data = await run_in_threadpool(_read, reader, _SEARCH_SQL, (*_authority_args(authority), node, query))
        if data is None:
            raise HTTPException(403, _SEARCH_DENIED)
        return _search_receipt(data)

    @app.get(SEARCH_SCOPES)
    async def search_scopes(request: Request):
        try:
            async with asyncio.timeout(5):
                await _upload_body(request, 0)
                verified = await _verify_discovery_session(request, auth_transport)
                context = await run_in_threadpool(_discovery_identity, identity, verified)
        except (TimeoutError, psycopg.Error):
            raise DatabaseUnavailable('Knowledge identity unavailable') from None
        try:
            async with asyncio.timeout(7):
                data = await run_in_threadpool(_read, reader, _SCOPES_SQL, context)
        except psycopg.errors.InsufficientPrivilege as exc:
            if exc.diag.message_primary == 'Knowledge scope denied':
                raise HTTPException(403, _SEARCH_DENIED) from None
            raise DatabaseUnavailable('Knowledge scope dependency denied') from None
        return _scope_receipt(data)

    @app.get(CSV_EVIDENCE)
    async def csv_evidence(request: Request, record_id: str, version_id: str):
        await _upload_body(request, 0)
        try:
            authority = await authorize(request, 'knowledge:read')
        except HTTPException as exc:
            if exc.status_code == 403:
                raise HTTPException(404, _EVIDENCE_DENIED) from None
            if exc.status_code == 503:
                raise DatabaseUnavailable('Knowledge identity unavailable') from None
            raise
        data = await run_in_threadpool(_read, reader, _EVIDENCE_SQL,
                                      (*_authority_args(authority), UUID(record_id), UUID(version_id)))
        if data is None:
            raise HTTPException(404, _EVIDENCE_DENIED)
        if (type(data) is not dict or data.keys() != {'record_id', 'source_version_id', 'first_line',
                                                     'last_line', 'original_sha256', 'content_sha256'}
                or data['record_id'] != record_id or data['source_version_id'] != version_id
                or data['record_id'] != data['source_version_id']  # Governed CSV binds one job per record/version.
                or not _lines(data) or not all(isinstance(data[k], str) and re.fullmatch(r'[0-9a-f]{64}', data[k])
                                               for k in ('original_sha256', 'content_sha256'))):
            raise DatabaseUnavailable('Invalid CSV evidence receipt')
        return _bounded(data)

    return app
