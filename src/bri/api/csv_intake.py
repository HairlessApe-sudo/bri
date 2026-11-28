"""Isolated CSV staging assemblies. Not imported or mounted by the release app.

The trusted caller supplies fixture-only connections and a MockTransport.
Serve on an IP loopback listener with proxy headers and access logs disabled.
No HTTP endpoint dispatches the worker or exposes quarantine objects.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from collections.abc import Awaitable, Callable
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from stat import S_ISDIR
from urllib.parse import unquote_plus, urlsplit
from uuid import UUID, uuid4

import httpx
import psycopg
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from bri.access.policy import Principal, Resource, is_authorized
from bri.api.authentication import (
    AuthenticationRejected,
    AuthenticationUnavailable,
    SupabaseTokenVerifier,
)
from bri.api.database import EXPECTED_PROJECT_REF, Database, DatabaseUnavailable
from bri.ingestion.csv_intake import (
    MAX_CSV_BYTES,
    ClaimedCsvJob,
    CsvIntakeProcessor,
    IntakeReason,
    LocalCsvQuarantine,
    ProcessOutcome,
)
from bri.knowledge.query import KnowledgeItem, answer_question

PREFIX = '/v1/sources/csv'
REVIEW_PREFIX = '/v1/knowledge/proposals/csv'

_INVALID = 'Invalid CSV intake request'
_APP, _INTAKE, _WORKER, _READER = 'bri_app', 'bri_csv_intake', 'bri_csv_worker', 'bri_csv_reader'
_ORIGIN = f'https://{EXPECTED_PROJECT_REF}.supabase.co'
Scope = Callable[[], AbstractContextManager[psycopg.Connection]]
_NODE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', re.ASCII)
_UUID = re.compile(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', re.ASCII)
_PROPOSAL = re.compile(r'csv:' + _UUID.pattern)
_READ_DETAIL = re.compile(rb'/v1/(?:knowledge|sources)/csv:([0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})')
_READ_LIST = b'/v1/knowledge'
_READ_SEARCH = b'/v1/knowledge/search'
_REPORT_PATH = '/v1/reports/published-knowledge-inventory'
_READ_REPORT = _REPORT_PATH.encode('ascii')
_REPORT_MAX_ROWS = 1000
_REPORT_MAX_BYTES = 512 * 1024
_REPORT_HASH = re.compile(r'[0-9a-f]{64}')
_A13_LIST_MAX_ITEMS = 100
_A13_LIST_PREVIEW_CHARS = 512
_A13_LIST_MAX_BYTES = 1024 * 1024  # Entire encoded JSON array, including delimiters.
_A13_LIST_TRUNCATED = 'X-BRI-Knowledge-List-Truncated'
_MEDIA = re.compile(r'text/csv(?:\s*;\s*charset\s*=\s*(?:utf-8|"utf-8"))?', re.IGNORECASE | re.ASCII)
_SUBMIT = 'SELECT * FROM bri.csv_submit(%s,%s,%s,%s,%s,%s,%s,%s,%s)'
_READY = 'SELECT bri.csv_mark_ready(%s,%s,%s,%s,%s,%s)'
_STATUS = 'SELECT bri.csv_status(%s,%s,%s,%s,%s,%s)'
_PENDING = 'SELECT proposal_id,scope_node_id,extracted_text FROM bri.csv_pending_review(%s,%s,%s,%s,%s)'
_REVIEW = 'SELECT bri.csv_review(%s,%s,%s,%s,%s,%s,%s)'
_CLAIM = 'SELECT job_id,tenant_id,object_key,original_sha256,byte_count,attempt FROM bri.csv_claim(%s,%s)'
_COMPLETE = 'SELECT bri.csv_complete(%s,%s,%s,%s,%s,%s,%s)'
_FAIL = 'SELECT bri.csv_fail(%s,%s,%s,%s,%s)'
_PUBLISHED = 'SELECT * FROM bri.csv_read_published(%s,%s,%s,%s,%s)'
_REPORT = '''SELECT proposal_id,source_version_id,original_sha256,content_sha256,first_line,last_line
    FROM bri.csv_read_reporting(%s,%s,%s,%s,%s,%s) LIMIT %s'''
_ROLE = '''SELECT EXISTS (
    SELECT FROM pg_catalog.pg_roles r
    WHERE r.rolname = current_user AND r.rolname = session_user AND r.rolname = %s
      AND inet_server_addr() IS NULL AND current_setting('listen_addresses') = ''
      AND r.rolcanlogin AND NOT (r.rolsuper OR r.rolinherit OR r.rolbypassrls OR
                               r.rolcreaterole OR r.rolcreatedb OR r.rolreplication)
      AND NOT EXISTS (SELECT FROM pg_catalog.pg_auth_members m WHERE r.oid IN (m.member, m.roleid))
      AND NOT EXISTS (SELECT FROM pg_catalog.pg_shdepend d
                      WHERE d.refclassid = 'pg_catalog.pg_authid'::regclass
                        AND d.refobjid = r.oid AND d.deptype = 'o')
)'''


@dataclass(frozen=True, slots=True)
class _Authority:
    tenant: str
    actor: UUID
    sid: UUID
    issuer: str
    uid: str
    principal: Principal

    @property
    def args(self):
        return self.tenant, self.actor, self.sid, self.issuer


def _private_request(request: Request, app: FastAPI, *, guarded_routes: bool = False,
                     metadata_upload: bool = False) -> None:
    hosts = request.headers.getlist('host')
    server = request.scope.get('server')
    try:
        host = urlsplit(f'//{hosts[0]}') if len(hosts) == 1 else None
        local = (
            request.app is app and request.client is not None and server and host
            and ipaddress.ip_address(request.client.host).is_loopback
            and ipaddress.ip_address(server[0]).is_loopback
            and ipaddress.ip_address(host.hostname or '') == ipaddress.ip_address(server[0])
            and host.username is None and not (host.path or host.query or host.fragment)
            and (host.port or (443 if request.scope['scheme'] == 'https' else 80)) == server[1]
        )
    except ValueError:
        local = False
    if not local or any(
        h in {'forwarded', 'via', 'x-real-ip', 'proxy-authorization'} or h.startswith('x-forwarded-')
        for h in request.headers
    ):
        raise HTTPException(403, 'Private loopback listener required')
    # A dedicated route guard validates the bounded raw query separately.
    query = () if guarded_routes else request.query_params.multi_items()
    if (query and not (request.method == 'GET' and request.url.path == '/v1/knowledge/search'
                       and len(query) == 1 and query[0][0] == 'q')) or any(
        h in {'tenant', 'tenant-id', 'actor', 'actor-id', 'principal', 'principal-id', 'role',
              'session-id', 'auth-user-id', 'issuer', 'cookie'}
        or (h.startswith('x-') and (guarded_routes or h != 'x-node-id')
            and not (metadata_upload and h == 'x-bri-metadata'))
        for h in request.headers
    ):
        raise HTTPException(400, 'Authority is server-controlled')


def _reader_request(request: Request) -> None:
    """Reject aliases and unapproved methods before auth or DB access."""
    raw = request.scope.get('raw_path', b'')
    if (request.method != 'GET' or not raw or not raw.isascii()
            or raw.decode('ascii') != request.scope['path']):
        raise HTTPException(404, 'Not Found')
    if raw not in (_READ_LIST, _READ_SEARCH, _READ_REPORT):
        detail = _READ_DETAIL.fullmatch(raw)
        if detail is None or not UUID(detail[1].decode('ascii')).int:
            raise HTTPException(404, 'Not Found')

    query = request.scope['query_string']
    if raw == _READ_REPORT:
        prefix = b'scope_node_id='
        if (len(query) <= len(prefix) + 128 * 3 and re.fullmatch(rb'scope_node_id=[^&]+', query)
                and not re.search(rb'%(?![0-9A-Fa-f]{2})', query)
                and not any(h.replace('_', '-') == 'scope-node-id' for h in request.headers)):
            try:
                node = unquote_plus(query[len(prefix):].decode('ascii'), errors='strict')
                if _NODE.fullmatch(node):
                    request.state.report_node = node
                    return
            except UnicodeError:
                pass
        raise HTTPException(400, 'Invalid CSV report scope')
    if raw == _READ_SEARCH:
        # At most 512 UTF-8 characters, even when all bytes are percent-escaped.
        if (len(query) <= 2 + 512 * 4 * 3 and re.fullmatch(rb'q=[^&]+', query)
                and not re.search(rb'%(?![0-9A-Fa-f]{2})', query)):
            try:
                if 1 <= len(unquote_plus(query[2:].decode('ascii'), errors='strict')) <= 512:
                    return
            except UnicodeError:
                pass
        raise HTTPException(400, 'Invalid CSV question')
    if query:
        raise HTTPException(400, 'Authority is server-controlled')


def _uuid(value: str) -> UUID:
    if not _UUID.fullmatch(value) or not (identifier := UUID(value)).int:
        raise HTTPException(422, _INVALID)
    return identifier


def _header(request: Request, name: str, *, status: int = 422) -> str:
    values = request.headers.getlist(name)
    if len(values) != 1:
        raise HTTPException(status, _INVALID)
    return values[0]


async def _body(request: Request, limit: int) -> tuple[bytes, str]:
    lengths = request.headers.getlist('content-length')
    expected = None
    too_large = 413 if limit else 400
    if lengths:
        if len(lengths) != 1 or not re.fullmatch(r'[0-9]{1,10}', lengths[0]):
            raise HTTPException(400, _INVALID)
        expected = int(lengths[0])
        if expected > limit:
            raise HTTPException(too_large, _INVALID)
    if 'content-encoding' in request.headers:
        raise HTTPException(415, _INVALID)
    body = bytearray()
    digest = sha256()
    async for chunk in request.stream():
        if len(body) + len(chunk) > limit:
            raise HTTPException(too_large, _INVALID)
        digest.update(chunk)
        body.extend(chunk)
    if expected is not None and expected != len(body):
        raise HTTPException(400, _INVALID)
    return bytes(body), digest.hexdigest()


async def _decision(request: Request) -> str:
    if _header(request, 'content-type', status=415).strip().lower() != 'application/json':
        raise HTTPException(415, _INVALID)
    raw, _ = await _body(request, 1024)
    try:
        def unique(items):
            result = dict(items)
            if len(result) != len(items):
                raise ValueError
            return result

        fields = json.loads(raw.decode('utf-8'), object_pairs_hook=unique)
        if (not isinstance(fields, dict) or fields.keys() != {'decision'}
                or fields['decision'] not in ('approved', 'rejected')):
            raise ValueError
        return fields['decision']
    except (ValueError, RecursionError):
        raise HTTPException(422, _INVALID) from None


def _socket_identity(socket: Path) -> tuple[int, int]:
    info = socket.lstat()
    if not S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('Owner-private database socket directory required')
    return info.st_dev, info.st_ino


def _restricted(scope: Scope, socket: Path, dbname: str, port: int, role: str) -> Scope:
    expected_socket = _socket_identity(socket)

    @contextmanager
    def connect():
        if _socket_identity(socket) != expected_socket:
            raise DatabaseUnavailable('Unexpected CSV stage socket directory')
        with scope() as db:
            info = db.info
            if (info.host, info.port, info.dbname, info.user, info.transaction_status) != (
                str(socket), port, dbname, role, psycopg.pq.TransactionStatus.IDLE,
            ):
                raise DatabaseUnavailable('Unexpected CSV stage database scope')
            yield db
    return connect


def _check_role(db, role: str) -> None:
    if db.execute(_ROLE, (role,)).fetchone() != (True,):
        raise DatabaseUnavailable('Restricted CSV stage database role required')


def _command(scope: Scope, role: str, query: str, args: tuple, *, authority: _Authority | None = None,
             many: bool = False, read_only: bool = False):
    with scope() as db, db.transaction():
        db.execute('SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY' if read_only else
                   'SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ WRITE')
        _check_role(db, role)
        if authority is not None:
            db.execute("SELECT set_config('bri.tenant_id',%s,true),"
                       "set_config('bri.auth_user_id',%s,true)", (authority.tenant, authority.uid))
        cursor = db.execute(query, args)
        return cursor.fetchall() if many else cursor.fetchone()


def _job_state(row) -> str:
    if not row or row[0] is None:
        raise HTTPException(404, 'CSV job not found')
    if row[0] not in {'creating', 'ready', 'processing', 'proposed', 'failed', 'approved', 'rejected'}:
        raise DatabaseUnavailable('Unexpected CSV job state')
    return row[0]


class _WorkerRepo:
    def __init__(self, scope: Scope):
        self._scope = scope

    def claim(self, job: UUID, correlation: UUID) -> ClaimedCsvJob | None:
        row = _command(self._scope, _WORKER, _CLAIM, (job, correlation))
        if not row or row[0] is None:
            return None
        job_id, tenant, key, digest, count, attempt = row
        return ClaimedCsvJob(job_id, tenant, str(key), digest, count, attempt)

    def complete(self, job, attempt, text, extracted_sha256, first_line, last_line, correlation):
        row = _command(self._scope, _WORKER, _COMPLETE,
                       (job, attempt, text, extracted_sha256, first_line, last_line, correlation))
        if row == ('failed',):
            raise _AuthorityLost
        if row != ('proposed',):
            raise DatabaseUnavailable('CSV completion was not acknowledged')

    def fail(self, job, attempt, reason, transient, correlation):
        reason = {
            IntakeReason.STORAGE_MISSING: 'object_missing',
            IntakeReason.STORAGE_MISMATCH: 'digest_mismatch',
            IntakeReason.STORAGE_UNAVAILABLE: 'storage_error',
            IntakeReason.STORAGE_CONFIGURATION: 'storage_error',
            IntakeReason.INVALID_METADATA: 'processing_error',
        }.get(reason, 'invalid_csv')
        row = _command(self._scope, _WORKER, _FAIL, (job, attempt, reason, transient, correlation))
        if row not in (('ready',), ('failed',)):
            raise DatabaseUnavailable('CSV failure was not acknowledged')


class _AuthorityLost(Exception):
    """Completion committed a terminal denial, not a proposal."""


class _Worker:
    def __init__(self, processor: CsvIntakeProcessor):
        self._processor = processor

    def dispatch(self, job: UUID) -> ProcessOutcome:
        """Run one private, fenced attempt; do not export diagnostics or source bytes."""
        if not isinstance(job, UUID) or not job.int:
            raise ValueError('A server-issued CSV job ID is required')
        try:
            return self._processor.process(job, uuid4())
        except _AuthorityLost:
            return ProcessOutcome.FAILED
        except Exception:
            raise DatabaseUnavailable('CSV worker unavailable') from None


def _stage_socket(private_socket: Path, auth_transport: httpx.MockTransport, *scopes: Scope) -> Path:
    socket = Path(private_socket).resolve(strict=True)
    if (len({id(scope) for scope in scopes}) != len(scopes)
            or type(auth_transport) is not httpx.MockTransport):
        raise ValueError('Private disposable database and distinct fixture scopes required')
    return socket


_Authorize = Callable[[Request, str | None, str | None], Awaitable[_Authority]]


def _staged_app(identity_db: Scope, auth_transport: httpx.MockTransport, *, reader_only: bool = False,
                private_guard: Callable[[Request], None] | None = None,
                enable_metadata: bool = False, metadata_identity_only: bool = False):
    from bri.api.knowledge_metadata import is_metadata, metadata_boundary

    class IdentityDatabase(Database):
        @contextmanager
        def _connect(self):
            with identity_db() as db, db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                _check_role(db, _APP)
                yield db

    registry = IdentityDatabase('', '')
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False)
    guard = _reader_request if reader_only else private_guard
    surface = 'CSV reader' if reader_only else 'CSV review' if private_guard is not None else 'CSV intake'

    @app.middleware('http')
    async def private(request: Request, call_next):
        if enable_metadata and is_metadata(request):
            return await metadata_boundary(request, app, call_next)
        cid = uuid4()
        request.state.csv_correlation = cid
        try:
            _private_request(request, app, guarded_routes=guard is not None)
            if guard is not None:
                guard(request)
            response = await call_next(request)
        except HTTPException as exc:
            response = JSONResponse({'detail': exc.detail}, status_code=exc.status_code)
        except psycopg.errors.InsufficientPrivilege:
            response = JSONResponse({'detail': f'{surface} denied'}, status_code=403)
        except (psycopg.errors.UniqueViolation, psycopg.errors.ObjectNotInPrerequisiteState):
            response = JSONResponse({'detail': f'{surface} conflict'}, status_code=409)
        except psycopg.errors.InvalidParameterValue:
            response = JSONResponse({'detail': _INVALID}, status_code=422)
        except Exception:  # Do not reflect SQL, storage, auth or parser diagnostics.
            response = JSONResponse({'detail': f'{surface} unavailable'}, status_code=503)
        cache = 'private, no-store' if reader_only and request.scope['path'].startswith(_REPORT_PATH) else 'no-store'
        response.headers.update({'Cache-Control': cache, 'X-Request-ID': str(cid)})
        return response

    def resolve(ident, action: str | None, node: str | None):
        principal = registry.resolve_authenticated_principal(ident.auth_user_id, ident.issuer, ident.auth_user_id)
        if principal is not None and not principal.platform_superadmin and len(principal.tenant_ids) == 1:
            tenant = next(iter(principal.tenant_ids))
            # The new catalogue RPCs enforce the live permissions themselves.
            # This mode is unavailable on other assemblies; never infer grants
            # from a role label or accept identity supplied by the caller.
            if action is None:
                if metadata_identity_only and registry.auth_session_is_active(ident.auth_user_id, ident.session_id):
                    return _Authority(tenant, UUID(principal.subject_id), UUID(ident.session_id),
                                      ident.issuer, ident.auth_user_id, principal)
                raise HTTPException(403, 'Current authorized BRI session required')
            role = dict(principal.role_bindings).get(tenant)
            matching_grant = (is_authorized(principal, action, Resource(tenant, node)) if node is not None else
                              any(g.tenant_id == tenant and g.action == action and g.scope_id
                                  for g in principal.grants))
            if (role in ({'user', 'superuser'} if action == 'source:submit' else {'user', 'superuser', 'admin'})
                    and matching_grant and registry.auth_session_is_active(ident.auth_user_id, ident.session_id)):
                return _Authority(tenant, UUID(principal.subject_id), UUID(ident.session_id),
                                  ident.issuer, ident.auth_user_id, principal)
        raise HTTPException(403, 'Current authorized BRI session required')

    async def authorize(request: Request, action: str | None, node: str | None = None):
        auth = request.headers.getlist('authorization')
        if len(auth) != 1 or not re.fullmatch(r'Bearer [^\s]{1,16384}', auth[0]):
            raise HTTPException(401, 'Verified bearer identity required')
        async with httpx.AsyncClient(transport=auth_transport, trust_env=False) as client:
            verifier = SupabaseTokenVerifier(_ORIGIN, 'csv-stage-only', client=client)
            try:
                ident = await verifier.verify(auth[0][7:])
            except AuthenticationRejected:
                raise HTTPException(401, 'Authentication rejected') from None
            except AuthenticationUnavailable:
                raise HTTPException(503, 'Authentication unavailable') from None
        return await run_in_threadpool(resolve, ident, action, node)

    return app, authorize


def create_staged_csv_intake_app(
    *, identity_scope: Scope, intake_scope: Scope, worker_scope: Scope, private_socket: Path,
    auth_transport: httpx.MockTransport, store: LocalCsvQuarantine, dbname: str = 'postgres', port: int = 5432,
    reader_scope: Scope | None = None, enable_metadata: bool = False,
) -> FastAPI:
    """Assemble with distinct disposable scopes and private storage.

    HTTP submits, checks status, lists pending proposals, and records decisions.
    A trusted in-process caller runs ``app.state.csv_worker.dispatch(job_id)``.
    The stage review queue returns the existing ``csv:<uuid>`` proposal ID;
    a review decision does not grant publication access. An optional fourth
    scope serves governed published reads only on this private listener.
    """
    from bri.api import knowledge_metadata as metadata_api

    scopes = (identity_scope, intake_scope, worker_scope) + ((reader_scope,) if reader_scope is not None else ())
    socket = _stage_socket(private_socket, auth_transport, *scopes)
    identity_db = _restricted(identity_scope, socket, dbname, port, _APP)
    intake_db = _restricted(intake_scope, socket, dbname, port, _INTAKE)
    worker_db = _restricted(worker_scope, socket, dbname, port, _WORKER)
    reader_db = _restricted(reader_scope, socket, dbname, port, _READER) if reader_scope is not None else None
    app, authorize = _staged_app(identity_db, auth_transport, enable_metadata=enable_metadata)
    app.state.csv_worker = _Worker(CsvIntakeProcessor(store, _WorkerRepo(worker_db)))

    def submit(authority, node, key, body, digest, cid, metadata=None):
        args = (*authority.args, node, key, digest, len(body), cid)
        if metadata is None:
            row = _command(intake_db, _INTAKE, _SUBMIT, args, authority=authority)
            if not row or not row[0]:
                raise HTTPException(403, 'CSV intake denied')
            job, state, object_key = row
        else:
            receipt = metadata_api.call(intake_db, _INTAKE, 'csv_submit_metadata_v1', (*args, metadata), authority)
            if type(receipt) is not dict or receipt.keys() != {'job_id', 'state', 'object_key'}:
                raise DatabaseUnavailable('Unexpected CSV metadata reservation')
            job, object_key = map(metadata_api.uuid_exact, (receipt['job_id'], receipt['object_key']))
            state = receipt['state']
            if not isinstance(state, str):
                raise DatabaseUnavailable('Unexpected CSV metadata reservation')
            _job_state((state,))
        if state == 'creating':
            store.install(authority.tenant, str(object_key), body)
            state = _job_state(_command(intake_db, _INTAKE, _READY, (*authority.args, job, cid),
                                        authority=authority))
            if metadata is not None and state == 'creating':
                raise DatabaseUnavailable('CSV metadata reservation was not acknowledged')
        return {'id': str(job), 'state': _job_state((state,))}

    @app.post(PREFIX, status_code=202)
    async def upload(request: Request):
        if not _MEDIA.fullmatch(_header(request, 'content-type', status=415).strip()):
            raise HTTPException(415, _INVALID)
        node = _header(request, 'x-node-id')
        if not _NODE.fullmatch(node):
            raise HTTPException(422, _INVALID)
        key = _uuid(_header(request, 'idempotency-key'))
        authority = await authorize(request, 'source:submit', node)
        body, digest = await _body(request, MAX_CSV_BYTES)
        if not body:
            raise HTTPException(422, _INVALID)
        return await run_in_threadpool(submit, authority, node, key, body, digest, request.state.csv_correlation)

    async def upload_with_metadata(request: Request):
        if not _MEDIA.fullmatch(_header(request, 'content-type', status=415).strip()):
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
        body, digest = await metadata_api.upload_body(request, MAX_CSV_BYTES)
        if not body:
            raise HTTPException(422, _INVALID)
        return await run_in_threadpool(submit, authority, node, key, body, digest,
                                       request.state.metadata_correlation, metadata)

    if enable_metadata:
        app.post(metadata_api.BASE + '/csv/uploads', status_code=202)(upload_with_metadata)

    @app.get(PREFIX + '/{job_id}')
    async def status(request: Request, job_id: str):
        job = _uuid(job_id)
        await _body(request, 0)
        authority = await authorize(request, 'source:submit')
        row = await run_in_threadpool(_command, intake_db, _INTAKE, _STATUS,
                                      (*authority.args, job, request.state.csv_correlation),
                                      authority=authority, read_only=True)
        return {'id': str(job), 'state': _job_state(row)}

    @app.get(REVIEW_PREFIX)
    async def pending_review(request: Request):
        await _body(request, 0)
        authority = await authorize(request, 'knowledge:review')
        rows = await run_in_threadpool(_command, intake_db, _INTAKE, _PENDING,
                                       (*authority.args, request.state.csv_correlation),
                                       authority=authority, many=True, read_only=True)
        return [{'id': str(proposal), 'node_id': node, 'text': text} for proposal, node, text in rows]

    @app.post(REVIEW_PREFIX + '/{proposal_id}/decision')
    async def review(request: Request, proposal_id: str):
        if not _PROPOSAL.fullmatch(proposal_id):
            raise HTTPException(422, _INVALID)
        proposal = f'csv:{_uuid(proposal_id[4:])}'
        decision = await _decision(request)
        authority = await authorize(request, 'knowledge:review')
        row = await run_in_threadpool(_command, intake_db, _INTAKE, _REVIEW,
                                      (*authority.args, proposal, decision, request.state.csv_correlation),
                                      authority=authority)
        if not row or row[0] is None:
            raise HTTPException(404, 'CSV proposal not found')
        if row[0] != decision:
            raise DatabaseUnavailable('Unexpected CSV decision result')
        return {'id': proposal, 'decision': decision}

    if reader_db is not None:
        _mount_reads(app, authorize, reader_db)

    return app


def create_staged_csv_reader_app(
    *, identity_scope: Scope, reader_scope: Scope, private_socket: Path,
    auth_transport: httpx.MockTransport, dbname: str = 'postgres', port: int = 5432, enable_metadata: bool = False,
) -> FastAPI:
    """Assemble the isolated reader with native identity and authorized published reads.

    Serve directly on loopback with proxy headers and access logs disabled.
    No intake or worker connection, quarantine store, or release route is mounted.
    """
    from bri.api.knowledge_metadata import mount_records

    socket = _stage_socket(private_socket, auth_transport, identity_scope, reader_scope)
    identity_db = _restricted(identity_scope, socket, dbname, port, _APP)
    reader_db = _restricted(reader_scope, socket, dbname, port, _READER)
    app, authorize = _staged_app(identity_db, auth_transport, reader_only=True, enable_metadata=enable_metadata)
    _mount_reads(app, authorize, reader_db, a13=True)
    _mount_reporting(app, authorize, reader_db)
    if enable_metadata:
        mount_records(app, authorize, reader_db, _READER, 'csv')
    return app


def _mount_reporting(app: FastAPI, authorize: _Authorize, reader_db: Scope) -> None:
    def report_response(authority: _Authority, node: str, metric: dict[str, str | int]) -> JSONResponse:
        with reader_db() as db, db.transaction():
            db.execute('SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY')
            _check_role(db, _READER)
            # Must precede the report statement so PostgreSQL arms its timer.
            db.execute("SET LOCAL statement_timeout = '5000ms'")
            rows = db.execute(_REPORT, (
                authority.tenant, authority.actor, UUID(authority.uid), authority.sid, authority.issuer, node,
                _REPORT_MAX_ROWS + 1,
            )).fetchmany(_REPORT_MAX_ROWS + 1)

        if len(rows) > _REPORT_MAX_ROWS:
            raise DatabaseUnavailable('CSV report exceeds row budget')
        evidence = []
        seen = set()
        for record, version, original, content, first, last in rows:
            # Validate the minimal projection and keep evidence compatible with the
            # guarded knowledge/source detail routes. Never emit partial evidence.
            if (not isinstance(record, str) or len(record) != 40 or record != record.lower()
                    or not _PROPOSAL.fullmatch(record) or not UUID(record[4:]).int
                    or version != record or record in seen
                    or not all(isinstance(v, str) and _REPORT_HASH.fullmatch(v) for v in (original, content))
                    or type(first) is not int or type(last) is not int or not 1 <= first <= last <= 2147483647):
                raise DatabaseUnavailable('Invalid CSV report provenance')
            seen.add(record)
            evidence.append({'record_id': record, 'source_version_id': version, 'original_sha256': original,
                             'content_sha256': content, 'first_line': first, 'last_line': last})

        evidence.sort(key=lambda entry: entry['record_id'])
        response = JSONResponse({'result': {**metric, 'status': 'complete', 'count': len(evidence),
                                            'evidence': evidence}})
        if len(response.body) > _REPORT_MAX_BYTES:
            raise DatabaseUnavailable('CSV report exceeds encoded byte budget')
        return response

    @app.get(_REPORT_PATH)
    async def published_knowledge_inventory(request: Request):
        await _body(request, 0)
        node = request.state.report_node
        metric: dict[str, str | int] = {'metric_id': 'published_knowledge_inventory', 'metric_version': 1,
                                        'scope_node_id': node}
        try:
            authority = await authorize(request, 'knowledge:read', node)
            return await run_in_threadpool(report_response, authority, node, metric)
        except psycopg.errors.InsufficientPrivilege:
            raise HTTPException(403, 'Current authorized BRI session required') from None
        except HTTPException as exc:
            if exc.status_code != 503:
                raise
        except Exception:
            pass  # Never reflect infrastructure, resource, or provenance diagnostics.
        return JSONResponse({'result': {**metric, 'status': 'unavailable'}}, status_code=503)


def _a13_csv_preview(content: str) -> str:
    def line(cells: object) -> str:
        if not isinstance(cells, list) or not all(isinstance(cell, str) for cell in cells):
            return ''
        return ' · '.join(filter(None, (' '.join(cell.split()) for cell in cells)))

    try:
        data = json.loads(content)
    except (ValueError, RecursionError):
        return ''
    if not isinstance(data, dict):
        return ''
    rows = data.get('rows')
    first_row = line(rows[0]) if isinstance(rows, list) and rows else ''
    preview = first_row or line(data.get('headers'))
    if len(preview) > _A13_LIST_PREVIEW_CHARS:
        preview = preview[:_A13_LIST_PREVIEW_CHARS - 1].rstrip() + '…'
    # Worker output is UTF-8, but do not emit unpaired surrogates from malformed JSON.
    return re.sub(r'[\ud800-\udfff]', '\ufffd', preview)


def _mount_reads(app: FastAPI, authorize: _Authorize, reader_db: Scope, *, a13: bool = False) -> None:
    from bri.api.app import (
        KnowledgeRecordResponse, KnowledgeSearchResponse, SourceReferenceResponse,
        _citation_response, _knowledge_item, _record_response, _source_response,
    )

    def read_published(authority: _Authority, *, list_order: bool = False) -> tuple[KnowledgeItem, ...]:
        rows = _command(reader_db, _READER, _PUBLISHED, (
            authority.tenant, authority.actor, UUID(authority.uid), authority.sid, authority.issuer,
        ), many=True, read_only=True)
        if list_order:
            rows = sorted(rows, key=lambda row: (row[4], row[0]))  # proposed_at, proposal_id
        return tuple(_knowledge_item(row, governed_csv=True) for row in rows
                     if is_authorized(authority.principal, 'knowledge:read', Resource(row[1], row[2])))

    async def published(request: Request, *, list_order: bool = False) -> tuple[Principal, tuple[KnowledgeItem, ...]]:
        await _body(request, 0)
        authority = await authorize(request, 'knowledge:read', None)
        return authority.principal, await run_in_threadpool(read_published, authority, list_order=list_order)

    def a13_list_response(items: tuple[KnowledgeItem, ...]) -> Response:
        # Apply both caps after exact authorization and full-content integrity verification.
        # Neither cap limits PostgreSQL transfer or changes what search/detail can read.
        encoded = []
        size = 2  # []
        for item in items[:_A13_LIST_MAX_ITEMS]:
            record = _record_response(item)
            record.content = _a13_csv_preview(item.content)
            entry = record.model_dump_json().encode('utf-8')
            size += len(entry) + bool(encoded)  # add comma after the first item
            if size > _A13_LIST_MAX_BYTES:
                break
            encoded.append(entry)
        return Response(b'[' + b','.join(encoded) + b']', media_type='application/json', headers={
            _A13_LIST_TRUNCATED: 'true' if len(encoded) < len(items) else 'false',
        })

    @app.get('/v1/knowledge', response_model=list[KnowledgeRecordResponse], description=(
        f'Oldest proposals first (proposal ID breaks ties). Returns at most {_A13_LIST_MAX_ITEMS} records '
        f'and {_A13_LIST_MAX_BYTES} JSON bytes. Content is a preview of the first data row (or headers '
        f'if blank or missing), up to {_A13_LIST_PREVIEW_CHARS} characters; hashes and provenance still '
        f'describe the full extraction. {_A13_LIST_TRUNCATED} is true if authorized records were omitted. '
        'Search and record/source detail are independent of this list.' if a13 else None
    ))
    async def list_published(request: Request):
        _, items = await published(request, list_order=a13)
        if a13:
            return await run_in_threadpool(a13_list_response, items)
        return [_record_response(item) for item in items]

    @app.get('/v1/knowledge/search', response_model=KnowledgeSearchResponse)
    async def search_published(request: Request, q: str = Query(min_length=1, max_length=512)):
        principal, items = await published(request)
        if a13:
            from bri.knowledge.csv_questions import answer_csv_question

            result = await run_in_threadpool(answer_csv_question, principal, q, items)
        else:
            result = answer_question(principal, q, items)
        return KnowledgeSearchResponse(status=result.status, answer=result.answer,
                                       citations=[_citation_response(c) for c in result.citations])

    @app.get('/v1/knowledge/{record_id}', response_model=KnowledgeRecordResponse)
    async def detail_published(request: Request, record_id: str):
        _, items = await published(request)
        for item in items:
            if item.record_id == record_id:
                return _record_response(item)
        raise HTTPException(404, 'Knowledge record not found')

    @app.get('/v1/sources/{record_id}', response_model=SourceReferenceResponse)
    async def source_published(request: Request, record_id: str):
        _, items = await published(request)
        for item in items:
            if item.record_id == record_id:
                return _source_response(item)
        raise HTTPException(404, 'Source reference not found')
