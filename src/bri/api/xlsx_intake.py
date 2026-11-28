"""Fixture-only XLSX upload/status ASGI assembly; never mounted by the release app.

Serve only on loopback with proxy headers and access logging disabled. No
HTTP handler parses workbooks, runs workers, or reads quarantine artifacts.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Protocol
from uuid import UUID, uuid4

import httpx
import psycopg
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.requests import ClientDisconnect

from bri.api.csv_intake import (
    _APP, _NODE, _UUID, Scope, _body, _command, _private_request, _restricted, _stage_socket, _staged_app,
)
from bri.api.database import DatabaseUnavailable
from bri.api import knowledge_metadata as metadata_api
from bri.ingestion.xlsx_strict import MAX_INPUT_BYTES
from bri.ingestion.xlsx_intake import ClaimedXlsxJob, XlsxIntakeDispatcher

PREFIX = '/v1/intake/xlsx'
_MEDIA = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
_SUBMITTER = 'bri_xlsx_submitter'
_WORKER = 'bri_xlsx_worker'
_INVALID = 'Invalid XLSX intake request'
_NOT_FOUND = 'XLSX job not found'
_STATES = frozenset({'creating', 'ready', 'processing', 'proposed', 'failed'})
_REASONS = frozenset({'unsupported_workbook', 'resource_limit', 'integrity_failure', 'processing_failed',
                      'infrastructure_unavailable', 'authority_lost', 'lease_expired'})
_SUBMIT = 'SELECT bri.xlsx_submit(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'
_READY = 'SELECT bri.xlsx_mark_ready(%s,%s,%s,%s,%s,%s,%s)'
_STATUS = 'SELECT bri.xlsx_status(%s,%s,%s,%s,%s,%s)'
_CLAIM = 'SELECT bri.xlsx_claim(%s,%s)'
_COMPLETE = 'SELECT bri.xlsx_complete(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'
_FAIL = 'SELECT bri.xlsx_fail(%s,%s,%s,%s)'


class _Quarantine(Protocol):
    def install(self, tenant_id: UUID | str, job_id: UUID, artifact_key: str, content: bytes) -> object: ...

    def read_verified(self, tenant_id: UUID | str, job_id: UUID, artifact_key: str,
                      original_sha256: str, byte_count: int) -> bytes: ...


def _identifier(value: object) -> UUID:
    if isinstance(value, UUID) and value.int:
        return value
    if isinstance(value, str) and _UUID.fullmatch(value) and (value := UUID(value)).int:
        return value
    raise ValueError('Invalid XLSX identifier')


def _header(request: Request, name: str, status: int = 422) -> str:
    values = request.headers.getlist(name)
    if len(values) != 1:
        raise HTTPException(status, _INVALID)
    return values[0]


def _json(row):
    if row is None or row == (None,):
        return {}
    if len(row) != 1 or not isinstance(row[0], dict):
        raise DatabaseUnavailable('Invalid XLSX database receipt')
    return row[0]


def _receipt(data, expected_job: UUID | None = None):
    try:
        job = _identifier(data.get('job_id'))
        state = data['state']
        if state not in _STATES or (expected_job is not None and job != expected_job):
            raise ValueError
    except (KeyError, ValueError, TypeError):
        raise DatabaseUnavailable('Invalid XLSX job receipt') from None
    return job, state


def _authority_args(authority):
    return authority.tenant, authority.actor, UUID(authority.uid), authority.sid, authority.issuer


async def _upload_body(request: Request, limit: int):
    try:
        return await _body(request, limit)
    except HTTPException as exc:
        raise HTTPException(exc.status_code, _INVALID) from None
    except ClientDisconnect:
        raise HTTPException(400, _INVALID) from None


class _WorkerRepository:
    def __init__(self, scope: Scope):
        self._scope = scope

    def _call(self, query: str, args: tuple):
        try:
            return _command(self._scope, _WORKER, query, args)
        except Exception:
            raise DatabaseUnavailable('XLSX worker database unavailable') from None

    def claim(self, job: UUID, correlation: UUID, /) -> ClaimedXlsxJob | None:
        data = _json(self._call(_CLAIM, (job, correlation)))
        if not data:
            return None
        try:
            claimed = _identifier(data['job_id'])
            tenant = data['tenant_id']
            key = str(_identifier(data['artifact_key']))
            count, digest, attempt = data['byte_count'], data['original_sha256'], data['attempt']
            if (claimed != job or not isinstance(tenant, str) or not tenant
                    or type(count) is not int or not 0 < count <= MAX_INPUT_BYTES
                    or not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest)
                    or type(attempt) is not int or attempt < 1):
                raise ValueError
            return ClaimedXlsxJob(claimed, tenant, key, count, digest, attempt)
        except (KeyError, ValueError, TypeError):
            raise DatabaseUnavailable('Invalid XLSX claim receipt') from None

    def complete(self, job: UUID, attempt: int, canonical_text: str, canonical_sha256: str,
                 extractor_version: int, canonicalization_version: int, sheet_id: str,
                 sheet_title: str, cell_range: str, correlation: UUID, /) -> None:
        row = self._call(_COMPLETE, (job, attempt, canonical_text, canonical_sha256, extractor_version,
                                     canonicalization_version, sheet_id, sheet_title, cell_range, correlation))
        if row != ('proposed',):
            raise DatabaseUnavailable('XLSX completion did not create a proposal')

    def fail(self, job: UUID, attempt: int, reason: str, correlation: UUID, /) -> None:
        row = self._call(_FAIL, (job, attempt, reason, correlation))
        if row not in (('ready',), ('failed',)):
            raise DatabaseUnavailable('XLSX failure was not acknowledged')


def create_staged_xlsx_intake_app(
    *, identity_scope: Scope, submitter_scope: Scope, worker_scope: Scope, private_socket: Path,
    auth_transport: httpx.MockTransport, store: _Quarantine, dbname: str = 'postgres', port: int = 5432,
    enable_metadata: bool = False,
) -> FastAPI:
    """Compose a private listener from distinct, injected disposable DB scopes.

    A trusted in-process caller may explicitly invoke
    ``app.state.xlsx_worker.dispatch(job_id, correlation)``.
    """
    socket = _stage_socket(private_socket, auth_transport, identity_scope, submitter_scope, worker_scope)
    identity_db = _restricted(identity_scope, socket, dbname, port, _APP)
    submitter_db = _restricted(submitter_scope, socket, dbname, port, _SUBMITTER)
    # Borrow the fixture-native verifier and live BRI session preflight, not
    # the CSV router or its public/cache/error response handling.
    _, authorize = _staged_app(identity_db, auth_transport)
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False)
    worker_db = _restricted(worker_scope, socket, dbname, port, _WORKER)
    app.state.xlsx_worker_repository = _WorkerRepository(worker_db)
    app.state.xlsx_worker = XlsxIntakeDispatcher(store, app.state.xlsx_worker_repository)

    @app.middleware('http')
    async def private(request: Request, call_next):
        if enable_metadata and metadata_api.is_metadata(request):
            return await metadata_api.metadata_boundary(request, app, call_next)
        cid = uuid4()
        request.state.xlsx_correlation = cid
        try:
            if request.scope['query_string']:
                raise HTTPException(400, _INVALID)
            _private_request(request, app)
            if request.scope.get('raw_path') != request.scope['path'].encode('utf-8'):
                raise HTTPException(404, 'Not Found')
            if 'content-encoding' in request.headers:
                raise HTTPException(415, _INVALID)
            if any(h in request.headers for h in ('content-disposition', 'content-range', 'range', 'trailer')):
                raise HTTPException(400, _INVALID)
            transfers = request.headers.getlist('transfer-encoding')
            if transfers and (request.method != 'POST' or transfers != ['chunked']
                              or 'content-length' in request.headers):
                raise HTTPException(400, _INVALID)
            if request.method == 'GET' and ('x-node-id' in request.headers or 'idempotency-key' in request.headers
                                             or 'content-type' in request.headers):
                raise HTTPException(400, _INVALID)
            response = await call_next(request)
        except HTTPException as exc:
            response = JSONResponse({'detail': exc.detail}, status_code=exc.status_code)
        except psycopg.errors.InsufficientPrivilege:
            if request.method == 'GET':
                response = JSONResponse({'detail': _NOT_FOUND}, status_code=404)
            else:
                response = JSONResponse({'detail': 'XLSX intake denied'}, status_code=403)
        except (psycopg.errors.UniqueViolation, psycopg.errors.ObjectNotInPrerequisiteState):
            response = JSONResponse({'detail': 'XLSX intake conflict'}, status_code=409)
        except psycopg.errors.InvalidParameterValue:
            response = JSONResponse({'detail': _INVALID}, status_code=422)
        except Exception:  # Never serialize or log raw database/storage diagnostics here.
            response = JSONResponse({'detail': 'XLSX intake unavailable'}, status_code=503)
        response.headers.update({'Cache-Control': 'private, no-store', 'X-Request-ID': str(cid)})
        return response

    def validate_metadata_receipt(data, *, reserve):
        keys = {'job_id', 'state', 'reason'} | ({'artifact_key'} if reserve else set())
        if (type(data) is not dict or data.keys() != keys or
                (data['reason'] is not None and data['reason'] not in _REASONS) or
                (data['state'] == 'failed' and data['reason'] is None)):
            raise DatabaseUnavailable('Unexpected XLSX metadata reservation')
        metadata_api.uuid_exact(data['job_id'])
        if reserve:
            metadata_api.uuid_exact(data['artifact_key'])

    def submit(authority, node, key, body, digest, cid, metadata=None):
        args = _authority_args(authority)
        params = (*args, node, key, len(body), digest, cid)
        if metadata is None:
            data = _json(_command(submitter_db, _SUBMITTER, _SUBMIT, params, authority=authority))
        else:
            data = metadata_api.call(submitter_db, _SUBMITTER, 'xlsx_submit_metadata_v1', (*params, metadata), authority)
            validate_metadata_receipt(data, reserve=True)
        if not data.get('job_id'):
            raise HTTPException(403, 'XLSX intake denied')
        job, state = _receipt(data)
        if state == 'creating':
            store.install(authority.tenant, job, str(_identifier(data.get('artifact_key'))), body)
            ready = _json(_command(submitter_db, _SUBMITTER, _READY, (*args, job, cid), authority=authority))
            if metadata is not None:
                validate_metadata_receipt(ready, reserve=False)
            if not ready.get('job_id'):
                raise HTTPException(403, 'XLSX intake denied')
            _, state = _receipt(ready, job)
            if state == 'creating':
                raise DatabaseUnavailable('XLSX readiness was not acknowledged')
        return {'id': str(job), 'state': state}

    @app.post(PREFIX, status_code=202)
    async def upload(request: Request):
        if _header(request, 'content-type', 415).lower() != _MEDIA:
            raise HTTPException(415, _INVALID)
        node = _header(request, 'x-node-id')
        if not _NODE.fullmatch(node):
            raise HTTPException(422, _INVALID)
        try:
            key = _identifier(_header(request, 'idempotency-key'))
        except ValueError:
            raise HTTPException(422, _INVALID) from None
        authority = await authorize(request, 'source:submit', node)
        body, digest = await _upload_body(request, MAX_INPUT_BYTES)
        if not body:
            raise HTTPException(422, _INVALID)
        return await run_in_threadpool(submit, authority, node, key, body, digest, request.state.xlsx_correlation)

    async def upload_with_metadata(request: Request):
        if _header(request, 'content-type', 415).lower() != _MEDIA:
            raise HTTPException(415, _INVALID)
        node = _header(request, 'x-node-id')
        try:
            key = metadata_api.uuid_exact(_header(request, 'idempotency-key'))
            if not _NODE.fullmatch(node):
                raise ValueError
        except ValueError:
            raise HTTPException(422, _INVALID) from None
        metadata = metadata_api.upload_metadata(request)
        authority = await authorize(request, 'source:submit', node)
        body, digest = await metadata_api.upload_body(request, MAX_INPUT_BYTES)
        if not body:
            raise HTTPException(422, _INVALID)
        return await run_in_threadpool(submit, authority, node, key, body, digest,
                                       request.state.metadata_correlation, metadata)

    if enable_metadata:
        app.post(metadata_api.BASE + '/xlsx/uploads', status_code=202)(upload_with_metadata)

    @app.get(PREFIX + '/{job_id}')
    async def status(request: Request, job_id: str):
        try:
            job = _identifier(job_id)
        except ValueError:
            raise HTTPException(404, _NOT_FOUND) from None
        await _upload_body(request, 0)
        authority = await authorize(request, 'source:submit')
        row = await run_in_threadpool(_command, submitter_db, _SUBMITTER, _STATUS,
                                      (*_authority_args(authority), job), authority=authority, read_only=True)
        data = _json(row)
        if not data.get('job_id'):
            raise HTTPException(404, _NOT_FOUND)
        _, state = _receipt(data, job)
        return {'id': str(job), 'state': state}

    return app
