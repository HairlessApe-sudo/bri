"""A19.1 signed fixture-only HTTP projection. Not mounted by the release app."""
from __future__ import annotations

import asyncio
import base64
import json
import re
from pathlib import Path
from uuid import UUID, uuid4

import httpx
import psycopg
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from psycopg import sql
from psycopg.types.json import Jsonb
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect

from bri.api.csv_intake import (
    _APP, _NODE, Scope, _body, _command, _private_request, _restricted, _stage_socket, _staged_app,
)
from bri.api.database import DatabaseUnavailable
from bri.api.knowledge_administration import UploadAdmission
from bri.knowledge.metadata import parse_proposed_metadata

BASE = '/v1/knowledge-metadata'
JSON_LIMIT = 8192
RESPONSE_LIMIT = 512 * 1024
PAGE_SIZE = 10
UUID_RE = r'(?!00000000-0000-0000-0000-000000000000)[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}'
CLASS_ID = re.compile(r'[a-z0-9][a-z0-9_.-]{0,63}')
_FORMAT = '/(?:csv|xlsx)'
_RECORD = _FORMAT + rf'/records/(?P<record>{UUID_RE})/versions/(?P<version>{UUID_RE})'
_OPERATIONS = '(?:csv_submit|xlsx_submit|csv_review|xlsx_review)'
_ADMIN = '(?:seed|create|rename|describe|retire)'
_AUTHORITY_HEADER = re.compile(r'(?:bri-)?(?:tenant|actor|principal|role|identity|issuer|auth-user|'
                               r'session|dev-identity|user-id|sub|sid|scope|node-id|permissions)(?:-.*)?')
_ROUTES = tuple((method, re.compile(BASE + path)) for method, path in (
    ('POST', _FORMAT + '/uploads'), ('GET', _FORMAT + f'/review/{UUID_RE}'),
    ('POST', _FORMAT + f'/review/{UUID_RE}/decision'), ('GET', _RECORD),
    ('GET', _RECORD + '/corrections'), ('POST', _RECORD + '/corrections'),
    ('POST', _RECORD + f'/corrections/{UUID_RE}/decision'),
    ('GET', '/catalogue/admin'), ('POST', '/catalogue/admin/' + _ADMIN),
    ('GET', f'/catalogue/selection/{_OPERATIONS}/{_NODE.pattern}'),
))
_INVALID = 'Invalid governed metadata request'
_DENIED = 'Governed metadata operation denied'
_HIDDEN = 'Governed metadata target not found'
_UNAVAILABLE = 'Governed metadata unavailable'


def is_metadata(request: Request) -> bool:
    path = request.scope['path']
    return path == BASE or path.startswith(BASE + '/')


def uuid_exact(value: object) -> UUID:
    if type(value) is not str or not re.fullmatch(UUID_RE, value):
        raise ValueError
    return UUID(value)


def _exact_keys(obj, keys):
    if type(obj) is not dict or obj.keys() != set(keys):
        raise ValueError


def _require(check):
    if not check:
        raise ValueError


def _revision(value, *, zero=False):
    _require(type(value) is str and re.fullmatch(r'0|[1-9][0-9]{0,18}', value))
    result = int(value)
    _require((0 if zero else 1) <= result <= 2**63 - 1)
    return result


def _text(value, limit, *, empty=False):
    _require(type(value) is str and (empty or value.strip(' ')) and '\x00' not in value
             and len(value.encode('utf-8')) <= limit)


def _class_id(value):
    _require(type(value) is str and CLASS_ID.fullmatch(value))


def _decode_json(raw):
    def pairs(items):
        obj = dict(items)
        _require(len(obj) == len(items))
        return obj

    def reject(_):
        raise ValueError

    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=reject)


def _proposal(value, *, response=False):
    typed = parse_proposed_metadata(value)
    ids = sorted(typed.additional_classification_ids)
    if response:
        _require(ids == value['additional_classification_ids'])
    return {**value, 'additional_classification_ids': ids}


def _one(request, name, *, status=400):
    values = request.headers.getlist(name)
    if len(values) != 1:
        raise HTTPException(status, _INVALID)
    return values[0]


def upload_metadata(request):
    try:
        value = _one(request, 'x-bri-metadata', status=422)
        _require(re.fullmatch(r'[A-Za-z0-9_-]{1,10923}', value))
        raw = base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))
        _require(len(raw) <= JSON_LIMIT and base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii') == value)
        return Jsonb(_proposal(_decode_json(raw)))
    except (ValueError, RecursionError):
        raise HTTPException(422, _INVALID) from None


async def _read_body(request, limit):
    try:
        async with asyncio.timeout(5):
            return await _body(request, limit)
    except TimeoutError:
        raise HTTPException(408, _INVALID) from None
    except ClientDisconnect:
        raise HTTPException(400, _INVALID) from None


async def upload_body(request, limit):
    return await _read_body(request, limit)


async def _json_body(request):
    raw, _ = await _read_body(request, JSON_LIMIT)
    try:
        obj = _decode_json(raw)
        _require(type(obj) is dict)
        return obj
    except (ValueError, RecursionError):
        raise HTTPException(422, _INVALID) from None


def _guard(request, app, *, administration_upload: str | None = None):
    path = request.scope['path']
    raw = request.scope.get('raw_path')
    if raw is None or not raw.isascii() or raw.decode('ascii') != path:
        raise HTTPException(404, _HIDDEN)
    if administration_upload is not None:
        if request.method != 'POST' or path != administration_upload:
            raise HTTPException(404, _HIDDEN)
    elif not any(method == request.method and route.fullmatch(path) for method, route in _ROUTES):
        raise HTTPException(404, _HIDDEN)
    # An exact path in another local assembly is not served by this listener.
    if not any((route.path == administration_upload if administration_upload else route.path.startswith(BASE + '/'))
               and request.method in route.methods and route.path_regex.fullmatch(path) for route in app.routes):
        raise HTTPException(404, _HIDDEN)
    upload = path.endswith('/uploads')
    _private_request(request, app, guarded_routes=not upload, metadata_upload=upload)
    headers = request.headers
    if (headers.getlist('origin') not in ([], [f"{request.scope['scheme']}://{headers['host']}"])
            or any('_' in name or _AUTHORITY_HEADER.fullmatch(name) for name in headers)):
        raise HTTPException(400, _INVALID)
    if any(h in headers for h in ('transfer-encoding', 'expect', 'content-encoding', 'content-disposition',
                                  'content-range', 'range', 'trailer')):
        raise HTTPException(400, _INVALID)
    request.state.metadata_after = None
    if query := request.scope['query_string']:
        if request.method == 'GET' and path.endswith('/corrections') and query.isascii():
            match = re.fullmatch(rf'after=({UUID_RE})', query.decode('ascii'))
            if match:
                request.state.metadata_after = UUID(match[1])
            else:
                raise HTTPException(400, _INVALID)
        else:
            raise HTTPException(400, _INVALID)
    if request.method == 'GET':
        if headers.getlist('content-length') not in ([], ['0']) or any(
            h in headers for h in ('content-type', 'idempotency-key')
        ):
            raise HTTPException(400, _INVALID)
    else:
        length = _one(request, 'content-length')
        if not re.fullmatch(r'[1-9][0-9]{0,7}', length):
            raise HTTPException(400, _INVALID)
        if not upload:
            if 'idempotency-key' in headers:
                raise HTTPException(400, _INVALID)
            if _one(request, 'content-type', status=415) != 'application/json':
                raise HTTPException(415, _INVALID)
            if int(length) > JSON_LIMIT:
                raise HTTPException(413, _INVALID)


async def metadata_boundary(request, app, call_next, *, administration_upload: UploadAdmission | None = None):
    cid = uuid4()
    request.state.metadata_correlation = cid
    try:
        _guard(request, app, administration_upload=administration_upload.path if administration_upload else None)
        if request.method == 'GET':
            await _read_body(request, 0)
        if administration_upload is None:
            response = await call_next(request)
        else:
            # Do not accumulate callers waiting for a body buffer, auth/DB
            # connection, or quarantine thread on this staged upload path.
            if not administration_upload.slot.acquire(blocking=False):
                raise HTTPException(503, _UNAVAILABLE)
            try:
                response = await call_next(request)
            finally:
                administration_upload.slot.release()
    except HTTPException as exc:
        response = JSONResponse({'detail': exc.detail}, status_code=exc.status_code)
    except psycopg.errors.InsufficientPrivilege as exc:
        # A missing fixture-only EXECUTE grant is configuration failure, not
        # an application denial. Never reflect database messages to callers.
        primary = exc.diag.message_primary or ''
        if (primary.startswith(('permission denied', 'must be owner'))):
            response = JSONResponse({'detail': _UNAVAILABLE}, status_code=503)
        elif '/records/' in request.scope['path'] or '/review/' in request.scope['path']:
            response = JSONResponse({'detail': _HIDDEN}, status_code=404)
        else:
            response = JSONResponse({'detail': _DENIED}, status_code=403)
    except (psycopg.errors.UniqueViolation, psycopg.errors.ObjectNotInPrerequisiteState):
        response = JSONResponse({'detail': 'Governed metadata conflict'}, status_code=409)
    except psycopg.errors.InvalidParameterValue:
        response = JSONResponse({'detail': _INVALID}, status_code=422)
    except psycopg.errors.ForeignKeyViolation:
        if request.scope['path'] == BASE + '/catalogue/admin/create':
            response = JSONResponse({'detail': _INVALID}, status_code=422)
        else:
            response = JSONResponse({'detail': _UNAVAILABLE}, status_code=503)
    except Exception:
        response = JSONResponse({'detail': _UNAVAILABLE}, status_code=503)
    response.headers.update({'Cache-Control': 'private, no-store', 'X-Request-ID': str(cid),
                             'X-Content-Type-Options': 'nosniff'})
    return response


def identity_args(authority):
    return authority.tenant, authority.actor, UUID(authority.uid), authority.sid, authority.issuer


def call(scope, role, routine, args, authority, *, read_only=False):
    query = sql.SQL('SELECT bri.{}({})').format(sql.Identifier(routine), sql.SQL(',').join(
        sql.Placeholder() for _ in args))
    row = _command(scope, role, query, args, authority=authority, read_only=read_only)
    if row is None or len(row) != 1:
        raise DatabaseUnavailable(_UNAVAILABLE)
    return row[0]


def _bounded(data):
    response = JSONResponse(data)
    if len(response.body) > RESPONSE_LIMIT:
        raise DatabaseUnavailable(_UNAVAILABLE)
    return response


def _found(data):
    if data is None:
        raise HTTPException(404, _HIDDEN)
    return data


async def _authorize_target(authorize, request, permission):
    try:
        return await authorize(request, permission)
    except HTTPException as exc:
        if exc.status_code == 403:
            raise HTTPException(404, _HIDDEN) from None
        raise


def _action(body, *, initial=False):
    replacement = initial and 'metadata' in body
    _exact_keys(body, ('action', 'request_id', 'metadata') if replacement else ('action', 'request_id'))
    action = body['action']
    _require(action in ('approve', 'reject') and (not replacement or action == 'approve'))
    return action, uuid_exact(body['request_id']), Jsonb(_proposal(body['metadata'])) if replacement else None


def mount_review(app, authorize, db, role, fmt):
    base = BASE + f'/{fmt}/review/{{job}}'

    @app.get(base)
    async def pending_metadata(request: Request, job: str):
        job_id = UUID(job)  # The raw route guard validated exact literal spelling.
        authority = await _authorize_target(authorize, request, 'knowledge:review')
        args = (*identity_args(authority), job_id) + ((0,) if fmt == 'csv' else ())
        data = _found(await run_in_threadpool(call, db, role, f'{fmt}_review_metadata_detail_v1', args,
                                               authority, read_only=True))
        _exact_keys(data, ('detail', 'proposed_metadata'))
        detail = data['detail']
        identity = detail['id'] if fmt == 'csv' else detail['job_id']
        _require(identity == (f'csv:{job}' if fmt == 'csv' else job) and detail['state'] == 'proposed')
        node, proposed = detail['node_id'], data['proposed_metadata']
        _require(type(node) is str and _NODE.fullmatch(node))
        if proposed is not None:
            proposed = _proposal(proposed, response=True)
        return _bounded({'job_id': job, 'node_id': node, 'proposed_metadata': proposed})

    @app.post(base + '/decision')
    async def decide_metadata(request: Request, job: str):
        body = await _json_body(request)
        try:
            action, key, replacement = _action(body, initial=True)
        except ValueError:
            raise HTTPException(422, _INVALID) from None
        authority = await _authorize_target(authorize, request, 'knowledge:review')
        args, decision = identity_args(authority), action
        if fmt == 'csv':
            args, decision = authority.args, {'approve': 'approved', 'reject': 'rejected'}[action]
        data = _found(await run_in_threadpool(call, db, role, f'{fmt}_review_metadata_v1', (
            *args, UUID(job), decision, key, request.state.metadata_correlation, replacement), authority))
        _exact_keys(data, ('job_id', 'decision', 'metadata_revision'))
        _require(data['job_id'] == job and data['decision'] == decision)
        revision = data['metadata_revision']
        _require(revision is None or (action == 'approve' and revision == '1'))
        _require(replacement is None or revision == '1')
        return _bounded({**data, 'decision': action})


def _record_fields(record, version):
    return {'record_id': record, 'source_version_id': version}


def _validate_record(data, record, version, *extra):
    ids = _record_fields(record, version)
    _exact_keys(data, (*ids, *extra))
    _require(all(data[key] == val for key, val in ids.items()))


def _validate_authoritative(value):
    fields = ('title', 'description', 'effective_date', 'review_date', 'expiry_date')
    _exact_keys(value, (*fields, 'revision', 'responsible_node_id', 'primary_classification',
                        'additional_classifications'))
    _revision(value['revision'])
    node = value['responsible_node_id']
    _require(type(node) is str and _NODE.fullmatch(node))

    def identifier(entry):
        _exact_keys(entry, ('classification_id', 'label', 'retired'))
        _class_id(entry['classification_id'])
        _text(entry['label'], 160)
        _require(type(entry['retired']) is bool)
        return entry['classification_id']

    additional = value['additional_classifications']
    _require(type(additional) is list and len(additional) <= 8)
    _proposal(dict(version=1, primary_classification_id=identifier(value['primary_classification']),
                   additional_classification_ids=[identifier(item) for item in additional],
                   **{key: value[key] for key in fields}), response=True)


def mount_records(app, authorize, db, role, fmt):
    base = BASE + f'/{fmt}/records/{{record}}/versions/{{version}}'

    async def invoke(request, record, version, suffix, *args, read_only=False):
        authority = await _authorize_target(authorize, request, 'knowledge:read')
        return _found(await run_in_threadpool(call, db, role, f'{fmt}_{suffix}_v1', (
            *identity_args(authority), UUID(record), UUID(version), *args), authority, read_only=read_only))

    @app.get(base)
    async def read_metadata(request: Request, record: str, version: str):
        data = await invoke(request, record, version, 'read_metadata', read_only=True)
        _validate_record(data, record, version, 'metadata')
        if data['metadata'] is not None:
            _validate_authoritative(data['metadata'])
        return _bounded(data)

    @app.get(base + '/corrections')
    async def list_corrections(request: Request, record: str, version: str):
        after = request.state.metadata_after
        data = await invoke(request, record, version, 'list_metadata_corrections', after, PAGE_SIZE, read_only=True)
        _exact_keys(data, ('items', 'next_after'))
        items = data['items']
        _require(type(items) is list and len(items) <= PAGE_SIZE)
        last = after
        for item in items:
            _exact_keys(item, ('proposal_id', 'expected_revision', 'proposed_metadata'))
            proposal = uuid_exact(item['proposal_id'])
            _require(last is None or last < proposal)
            last = proposal
            _revision(item['expected_revision'], zero=True)
            _proposal(item['proposed_metadata'], response=True)
        if data['next_after'] is not None:
            _require(len(items) == PAGE_SIZE and uuid_exact(data['next_after']) == last)
        return _bounded(data)

    @app.post(base + '/corrections')
    async def propose_correction(request: Request, record: str, version: str):
        body = await _json_body(request)
        try:
            _exact_keys(body, ('request_id', 'expected_revision', 'metadata'))
            key = uuid_exact(body['request_id'])
            expected = _revision(body['expected_revision'], zero=True)
            metadata = Jsonb(_proposal(body['metadata']))
        except ValueError:
            raise HTTPException(422, _INVALID) from None
        data = await invoke(request, record, version, 'propose_metadata_correction', expected, key,
                            request.state.metadata_correlation, metadata)
        _validate_record(data, record, version, 'proposal_id', 'expected_revision')
        uuid_exact(data['proposal_id'])
        _require(data['expected_revision'] == body['expected_revision'])
        return _bounded(data)

    @app.post(base + '/corrections/{proposal}/decision')
    async def review_correction(request: Request, record: str, version: str, proposal: str):
        body = await _json_body(request)
        try:
            action, key, _ = _action(body)
        except ValueError:
            raise HTTPException(422, _INVALID) from None
        data = await invoke(request, record, version, 'review_metadata_correction', UUID(proposal), action,
                            key, request.state.metadata_correlation)
        _validate_record(data, record, version, 'proposal_id', 'decision', 'metadata_revision')
        _require(data['proposal_id'] == proposal and data['decision'] == action)
        if action == 'approve':
            _revision(data['metadata_revision'])
        else:
            _require(data['metadata_revision'] is None)
        return _bounded(data)


_CATALOGUE_ROLE = 'bri_classification_catalogue'
_ADMIN_FIELDS = {'seed': (), 'create': ('category_id', 'classification_id', 'label', 'description'),
                 'rename': ('classification_id', 'label'), 'describe': ('classification_id', 'description'),
                 'retire': ('classification_id',)}


def create_staged_metadata_catalogue_app(*, identity_scope: Scope, catalogue_scope: Scope, private_socket: Path,
                                         auth_transport: httpx.MockTransport, dbname: str = 'postgres',
                                         port: int = 5432) -> FastAPI:
    """Separate local listener; DB must enforce each exact catalogue operation."""
    socket = _stage_socket(private_socket, auth_transport, identity_scope, catalogue_scope)
    identity = _restricted(identity_scope, socket, dbname, port, _APP)
    catalogue = _restricted(catalogue_scope, socket, dbname, port, _CATALOGUE_ROLE)
    app, authorize = _staged_app(identity, auth_transport, enable_metadata=True, metadata_identity_only=True)
    base = BASE + '/catalogue'

    async def list_entries(request, operation, node=None):
        authority = await authorize(request, None)
        result = await run_in_threadpool(call, catalogue, _CATALOGUE_ROLE, 'classification_catalogue_list',
                                        (*identity_args(authority), node, operation), authority, read_only=True)
        _require(type(result) is list)
        seen = set()
        for entry in result:
            _exact_keys(entry, ('category_id', 'category_label', 'classification_id', 'label', 'description', 'retired'))
            _class_id(entry['category_id'])
            _class_id(entry['classification_id'])
            _text(entry['category_label'], 160)
            _text(entry['label'], 160)
            if entry['description'] is not None:
                _text(entry['description'], 2048, empty=True)
            _require(type(entry['retired']) is bool and (operation == 'admin' or not entry['retired']))
            _require(entry['classification_id'] not in seen)
            seen.add(entry['classification_id'])
        return _bounded(result)

    @app.get(base + '/admin')
    async def administration(request: Request):
        return await list_entries(request, 'admin')

    @app.get(base + '/selection/{operation}/{node}')
    async def selection(request: Request, operation: str, node: str):
        return await list_entries(request, operation, node)

    @app.post(base + '/admin/{operation}', status_code=204)
    async def maintain(request: Request, operation: str):
        body = await _json_body(request)
        fields = _ADMIN_FIELDS[operation]
        try:
            _exact_keys(body, fields)
            for field in fields:
                value = body[field]
                if field.endswith('_id'):
                    _class_id(value)
                elif field == 'label':
                    _text(value, 160)
                elif value is not None:
                    _text(value, 2048, empty=True)
        except ValueError:
            raise HTTPException(422, _INVALID) from None
        authority = await authorize(request, None)
        result = await run_in_threadpool(call, catalogue, _CATALOGUE_ROLE, f'classification_catalogue_{operation}',
                                        (*identity_args(authority), *(body[f] for f in fields)), authority)
        # psycopg receives the PostgreSQL void value as an empty string.
        _require(result == '')
        return Response(status_code=204)

    return app
