"""Isolated A12 staging assembly. Not imported or mounted by the release app.

The trusted caller supplies fixture-only connections and a MockTransport.
Serve on an IP loopback listener with proxy headers and access logs disabled.
No HTTP endpoint dispatches the worker or exposes quarantine objects.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from collections.abc import Callable
from contextlib import AbstractContextManager, contextmanager
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from stat import S_ISDIR
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import httpx
import psycopg
from fastapi import FastAPI, HTTPException, Query, Request
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
from bri.knowledge.query import answer_question

PREFIX = '/v1/sources/csv'
REVIEW_PREFIX = '/v1/knowledge/proposals/csv'

_INVALID = 'Invalid CSV intake request'
_APP, _INTAKE, _WORKER, _READER = 'bri_app', 'bri_csv_intake', 'bri_csv_worker', 'bri_csv_reader'
_ORIGIN = f'https://{EXPECTED_PROJECT_REF}.supabase.co'
Scope = Callable[[], AbstractContextManager[psycopg.Connection]]
_NODE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', re.ASCII)
_UUID = re.compile(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}', re.ASCII)
_PROPOSAL = re.compile(r'csv:' + _UUID.pattern)
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


def _private_request(request: Request, app: FastAPI) -> None:
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
    query = request.query_params.multi_items()
    if (query and not (request.method == 'GET' and request.url.path == '/v1/knowledge/search'
                       and len(query) == 1 and query[0][0] == 'q')) or any(
        h in {'tenant', 'tenant-id', 'actor', 'actor-id', 'principal', 'principal-id', 'role',
              'session-id', 'auth-user-id', 'issuer', 'cookie'}
        or (h.startswith('x-') and h != 'x-node-id')
        for h in request.headers
    ):
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


def create_staged_csv_intake_app(
    *, identity_scope: Scope, intake_scope: Scope, worker_scope: Scope, private_socket: Path,
    auth_transport: httpx.MockTransport, store: LocalCsvQuarantine, dbname: str = 'postgres', port: int = 5432,
    reader_scope: Scope | None = None,
) -> FastAPI:
    """Assemble with distinct disposable scopes and private storage.

    HTTP submits, checks status, lists pending proposals, and records decisions.
    A trusted in-process caller runs ``app.state.csv_worker.dispatch(job_id)``.
    The stage review queue returns the existing ``csv:<uuid>`` proposal ID;
    a review decision does not grant publication access. An optional fourth
    scope serves governed published reads only on this private listener.
    """
    socket = Path(private_socket).resolve(strict=True)
    scopes = (identity_scope, intake_scope, worker_scope) + ((reader_scope,) if reader_scope is not None else ())
    if (len({id(scope) for scope in scopes}) != len(scopes)
            or type(auth_transport) is not httpx.MockTransport):
        raise ValueError('Private disposable database and distinct fixture scopes required')
    identity_db = _restricted(identity_scope, socket, dbname, port, _APP)
    intake_db = _restricted(intake_scope, socket, dbname, port, _INTAKE)
    worker_db = _restricted(worker_scope, socket, dbname, port, _WORKER)
    reader_db = _restricted(reader_scope, socket, dbname, port, _READER) if reader_scope is not None else None

    class IdentityDatabase(Database):
        @contextmanager
        def _connect(self):
            with identity_db() as db, db.transaction():
                db.execute('SET TRANSACTION READ ONLY')
                _check_role(db, _APP)
                yield db

    registry = IdentityDatabase('', '')
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False)
    app.state.csv_worker = _Worker(CsvIntakeProcessor(store, _WorkerRepo(worker_db)))

    @app.middleware('http')
    async def private(request: Request, call_next):
        cid = uuid4()
        request.state.csv_correlation = cid
        try:
            _private_request(request, app)
            response = await call_next(request)
        except HTTPException as exc:
            response = JSONResponse({'detail': exc.detail}, status_code=exc.status_code)
        except psycopg.errors.InsufficientPrivilege:
            response = JSONResponse({'detail': 'CSV intake denied'}, status_code=403)
        except (psycopg.errors.UniqueViolation, psycopg.errors.ObjectNotInPrerequisiteState):
            response = JSONResponse({'detail': 'CSV intake conflict'}, status_code=409)
        except psycopg.errors.InvalidParameterValue:
            response = JSONResponse({'detail': _INVALID}, status_code=422)
        except Exception:  # Do not reflect SQL, storage, auth or parser diagnostics.
            response = JSONResponse({'detail': 'CSV intake unavailable'}, status_code=503)
        response.headers.update({'Cache-Control': 'no-store', 'X-Request-ID': str(cid)})
        return response

    def resolve(ident, action: str, node: str | None):
        principal = registry.resolve_authenticated_principal(ident.auth_user_id, ident.issuer, ident.auth_user_id)
        if principal is not None and not principal.platform_superadmin and len(principal.tenant_ids) == 1:
            tenant = next(iter(principal.tenant_ids))
            role = dict(principal.role_bindings).get(tenant)
            matching_grant = (is_authorized(principal, action, Resource(tenant, node)) if node is not None else
                              any(g.tenant_id == tenant and g.action == action and g.scope_id
                                  for g in principal.grants))
            if (role in ({'user', 'superuser'} if action == 'source:submit' else {'user', 'superuser', 'admin'})
                    and matching_grant and registry.auth_session_is_active(ident.auth_user_id, ident.session_id)):
                return _Authority(tenant, UUID(principal.subject_id), UUID(ident.session_id),
                                  ident.issuer, ident.auth_user_id, principal)
        raise HTTPException(403, 'Current authorized BRI session required')

    async def authorize(request: Request, action: str, node: str | None = None):
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

    def submit(authority, node, key, body, digest, cid):
        row = _command(intake_db, _INTAKE, _SUBMIT,
                       (*authority.args, node, key, digest, len(body), cid), authority=authority)
        if not row or not row[0]:
            raise HTTPException(403, 'CSV intake denied')
        job, state, object_key = row
        if state == 'creating':
            store.install(authority.tenant, str(object_key), body)
            state = _job_state(_command(intake_db, _INTAKE, _READY, (*authority.args, job, cid),
                                        authority=authority))
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
        from bri.api.app import (
            KnowledgeRecordResponse, KnowledgeSearchResponse, SourceReferenceResponse,
            _citation_response, _knowledge_item, _record_response, _source_response,
        )

        def read_published(authority: _Authority):
            rows = _command(reader_db, _READER, _PUBLISHED, (
                authority.tenant, authority.actor, UUID(authority.uid), authority.sid, authority.issuer,
            ), many=True, read_only=True)
            return tuple(_knowledge_item(row, governed_csv=True) for row in rows
                         if is_authorized(authority.principal, 'knowledge:read', Resource(row[1], row[2])))

        async def published(request):
            await _body(request, 0)
            authority = await authorize(request, 'knowledge:read')
            return authority.principal, await run_in_threadpool(read_published, authority)

        @app.get('/v1/knowledge', response_model=list[KnowledgeRecordResponse])
        async def list_published(request: Request):
            _, items = await published(request)
            return [_record_response(item) for item in items]

        @app.get('/v1/knowledge/search', response_model=KnowledgeSearchResponse)
        async def search_published(request: Request, q: str = Query(min_length=1, max_length=512)):
            principal, items = await published(request)
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

    return app
