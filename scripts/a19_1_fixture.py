"""Local synthetic A19.1 services; no finalized classified rows are seeded."""
from base64 import urlsafe_b64encode
from contextlib import contextmanager
from json import dumps
import socket
import sys
from uuid import UUID, uuid4

import a13_demo as harness
from a13_demo import ROOT, require, status
from a18_3_fixture import (ACCESS, ORIGINS as LEGACY_ORIGINS, PUBLISHER, SCOPE_LABELS, XLSX_READER,
                           _Lifecycle, _csv_bytes, _provision, _signed_identities, _xlsx_bytes)

BASE = '/v1/knowledge-metadata'
ORIGINS = LEGACY_ORIGINS | {'catalogue': 'http://127.0.0.1:8118',
                           'csv_seed': 'http://127.0.0.1:8119', 'xlsx_seed': 'http://127.0.0.1:8120'}
CLASS = 'fixture-service-guide'
ORIGINAL_LABEL = 'Service guide (fixture)'
RENAMED_LABEL = 'Service manual (fixture)'
MEDIA = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'


def metadata(title, primary=CLASS):
    return dict(version=1, primary_classification_id=primary, additional_classification_ids=[],
                title=title, description=None, effective_date=None, review_date=None, expiry_date=None)


def setup(args, scratch, stack, *, metadata_enabled=True, legacy_baseline=True):
    require(socket.if_nameindex() == [(1, 'lo')], 'Expected private loopback-only network')
    sys.path[:0] = [str(ROOT), str(ROOT / 'src'), str(ROOT / 'tests')]
    import httpx
    from bri.api.csv_intake import create_staged_csv_intake_app, create_staged_csv_reader_app
    from bri.api.csv_review_workspace import create_staged_csv_review_app
    from bri.api.knowledge_metadata import create_staged_metadata_catalogue_app
    from bri.api.unified_knowledge import create_staged_unified_knowledge_app
    from bri.api.xlsx_governance import create_staged_xlsx_governance_app
    from bri.api.xlsx_intake import create_staged_xlsx_intake_app
    from bri.ingestion.csv_intake import LocalCsvQuarantine
    from bri.ingestion.xlsx_intake import LocalXlsxQuarantine
    from test_csv_intake_postgres import ISSUER
    from test_knowledge_metadata_api import MetadataHttpTests
    from test_unified_knowledge_postgres import ROLE, UnifiedKnowledgePostgresTests
    from test_xlsx_governance_postgres import REVIEWER, XlsxGovernancePostgresTests

    class Fixture(UnifiedKnowledgePostgresTests):
        provision = XlsxGovernancePostgresTests.provision
        governance = XlsxGovernancePostgresTests.call
        install = MetadataHttpTests.install

    fixture = Fixture()
    stack.callback(fixture.doClassCleanups)
    fixture.setUpClass()
    scopes = {key: value[0] for key, value in SCOPE_LABELS.items()} | {'social': 'services:exact', 'root': 'root'}
    # A18.3 provisions fixed identifiers, then local fixture prerequisites add a
    # colon-bearing exact node; no application-side encoding is injected.
    fixed = {key: value[0] for key, value in SCOPE_LABELS.items()}
    fixture.tenant, fixture.foreign, fixture.identities = _provision(fixture, ISSUER, fixed)
    tenant, foreign, actors = fixture.tenant, fixture.foreign, fixture.identities
    identity = 'text,uuid,uuid,uuid,text'
    catalogue = 'bri_classification_catalogue'
    with fixture.connect('postgres') as db:
        db.execute(f'CREATE ROLE {catalogue} LOGIN NOINHERIT NOBYPASSRLS; GRANT USAGE ON SCHEMA bri TO {catalogue}')
        for name, suffix in {'list': ',text,text', 'seed': '', 'create': ',text,text,text,text', 'rename': ',text,text',
                             'describe': ',text,text', 'retire': ',text'}.items():
            routine = f'bri.classification_catalogue_{name}({identity}{suffix})'
            require(db.execute("SELECT has_function_privilege('bri_app',to_regprocedure(%s),'EXECUTE')", (routine,)).fetchone()
                    == (False,), 'Catalogue command must remain restricted')
            db.execute(f'GRANT EXECUTE ON FUNCTION {routine} TO {catalogue}')
    for role, names in {
        'bri_csv_intake': ('csv_submit_metadata_v1', 'csv_review_metadata_v1', 'csv_review_metadata_detail_v1'),
        'bri_xlsx_submitter': ('xlsx_submit_metadata_v1',),
        REVIEWER: ('xlsx_review_metadata_v1', 'xlsx_review_metadata_detail_v1'),
        'bri_csv_reader': ('csv_read_metadata_v1', 'csv_propose_metadata_correction_v1', 'csv_review_metadata_correction_v1'),
        XLSX_READER: ('xlsx_read_metadata_v1', 'xlsx_propose_metadata_correction_v1', 'xlsx_review_metadata_correction_v1'),
    }.items():
        for name in names:
            MetadataHttpTests.install(fixture, role, name)
    for fmt, role in (('csv', 'bri_csv_reader'), ('xlsx', XLSX_READER)):
        routine = f'bri.{fmt}_list_metadata_corrections_v1({identity},uuid,uuid,uuid,integer)'
        with fixture.connect('bri_app') as db:
            require(db.execute("SELECT has_function_privilege(to_regprocedure(%s),'EXECUTE')", (routine,)).fetchone()
                    == (False,), 'Correction list must remain restricted')
        with fixture.connect('postgres') as db:
            db.execute(f'GRANT EXECUTE ON FUNCTION {routine} TO {role}')
    with fixture.connect('postgres') as db:
        require(db.execute("SELECT current_setting('server_version_num'),inet_server_addr(),current_setting('listen_addresses')").fetchone()
                == ('160002', None, ''), 'Expected socket-only PostgreSQL 16.2')
        for t in (tenant, foreign):
            db.execute("INSERT INTO bri.org_nodes VALUES (%s,%s,'team','Exact fixture services','root')", (t, scopes['social']))
            db.execute('INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) '
                       'SELECT tenant_id,principal_id,role_id,%s FROM bri.auth_role_assignments '
                       'WHERE (tenant_id,scope_node_id)=(%s,%s)', (scopes['social'], t, fixed['social']))

        def member(name, permissions, node, t=tenant):
            p, u, _ = actors[name] = uuid4(), uuid4(), uuid4()
            db.execute("INSERT INTO bri.auth_principals VALUES (%s,'active')", (p,))
            db.execute("INSERT INTO bri.auth_identity_links(auth_user_id,principal_id,auth_issuer,auth_subject,"
                       "provider_type,provider_issuer,provider_subject) VALUES (%s,%s,%s,%s,'native',%s,%s)",
                       (u, p, ISSUER, str(u), ISSUER, str(u)))
            db.execute("INSERT INTO bri.auth_tenant_memberships(tenant_id,principal_id,membership_type,status) "
                       "VALUES (%s,%s,'user','active')", (t, p))
            for permission in permissions:
                db.execute('INSERT INTO bri.app_roles VALUES (%s,%s,%s) ON CONFLICT DO NOTHING', (t, permission, permission))
                db.execute('INSERT INTO bri.role_permissions VALUES (%s,%s,%s) ON CONFLICT DO NOTHING', (t, permission, permission))
                db.execute('INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) '
                           'VALUES (%s,%s,%s,%s)', (t, p, permission, node))

        member('manager', ['classification:catalogue:manage'], 'root')
        member('proposer', ['knowledge:read', 'knowledge:metadata:propose'], scopes['social'])
        for name in ('corrector', 'competing', 'revoked'):
            member(name, ['knowledge:read', 'knowledge:metadata:review'], scopes['social'])
        member('wrong_node', ['source:submit', 'knowledge:review', 'knowledge:read'], scopes['empty'])
        for name, (principal, subject, _) in actors.items():
            actor = actors[name] = principal, subject, uuid4()
            db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                       'VALUES (%s,%s,%s,clock_timestamp())', actor)

    headers, cookies, transport = _signed_identities(args, scratch, stack, actors, ISSUER)
    def scope(role):
        return lambda: fixture.connect(role)

    common = dict(identity_scope=scope('bri_app'), private_socket=fixture.sock, auth_transport=transport)
    mode = dict(common, enable_metadata=metadata_enabled)
    for name in ('csv-store', 'xlsx-store'):
        (scratch / name).mkdir(mode=0o700)
    csv_options = dict(intake_scope=scope('bri_csv_intake'), worker_scope=scope('bri_csv_worker'),
                       store=LocalCsvQuarantine(scratch / 'csv-store'))
    xlsx_options = dict(submitter_scope=scope('bri_xlsx_submitter'), worker_scope=scope('bri_xlsx_worker'),
                        store=LocalXlsxQuarantine(scratch / 'xlsx-store'))
    csv_stage = create_staged_csv_intake_app(**mode, **csv_options)
    xlsx_stage = create_staged_xlsx_intake_app(**mode, **xlsx_options)
    apps = {
        'csv_intake': csv_stage, 'xlsx_intake': xlsx_stage,
        'csv_review': create_staged_csv_review_app(**mode, review_scope=scope('bri_csv_intake')),
        'csv_reader': create_staged_csv_reader_app(**mode, reader_scope=scope('bri_csv_reader')),
        'xlsx_governance': create_staged_xlsx_governance_app(**mode, review_scope=scope(REVIEWER), reader_scope=scope(XLSX_READER)),
        'unified': create_staged_unified_knowledge_app(**common, reader_scope=scope(ROLE)),
        'catalogue': create_staged_metadata_catalogue_app(**common, catalogue_scope=scope(catalogue)),
    }
    if not metadata_enabled:
        # This transport prepares classified pending inputs only. No browser
        # bridge targets these listeners; the browser sees the OFF assemblies.
        apps['csv_seed'] = create_staged_csv_intake_app(**common, **csv_options, enable_metadata=True)
        apps['xlsx_seed'] = create_staged_xlsx_intake_app(**common, **xlsx_options, enable_metadata=True)
    for name, app in apps.items():
        stack.enter_context(harness.reader_server(app, port=int(ORIGINS[name].rsplit(':', 1)[1])))
    client = stack.enter_context(httpx.Client(trust_env=False, timeout=20))
    legacy = _Lifecycle(fixture, client, headers, actors, fixed, {})
    # Establish independent unchanged workflows through genuine legacy ingestion.
    baseline = {
        'xlsx': legacy.xlsx('legacy workbook', 'social', 'Legacy fixture visits', xlsx_stage),
        'csv': legacy.csv('legacy CSV', 'social', 'Legacy fixture visits for referrals', csv_stage, note=harness.ANSWER),
        'pending': legacy.csv('legacy pending CSV', 'information', 'Legacy fixture pending', csv_stage, pending=True),
    } if legacy_baseline else {}
    return dict(fixture=fixture, client=client, headers=headers, cookies=cookies, scopes=scopes, baseline=baseline,
                actors=actors, csv_stage=csv_stage, xlsx_stage=xlsx_stage)


def pending(data, fmt, marker, *, metadata_value=None, service=None):
    """Create a real native pending proposal through signed fixture-side HTTP."""
    from bri.api.csv_intake import PREFIX as CSV
    from bri.api.xlsx_intake import PREFIX as XLSX
    from bri.ingestion.csv_intake import ProcessOutcome


    require(fmt in ('csv', 'xlsx'), 'Unexpected fixture format')
    route = (CSV if fmt == 'csv' else XLSX) if metadata_value is None else f'{BASE}/{fmt}/uploads'
    raw = _csv_bytes(marker, 'Synthetic review fixture') if fmt == 'csv' else _xlsx_bytes(marker)
    hdr = {'Content-Type': 'text/csv' if fmt == 'csv' else MEDIA, 'X-Node-ID': data['scopes']['social'],
           'Idempotency-Key': str(uuid4())}
    if metadata_value is not None:
        hdr['X-BRI-Metadata'] = urlsafe_b64encode(dumps(metadata_value).encode()).decode().rstrip('=')
    ready = request(data, service or f'{fmt}_intake', route, 'submitter', 202, method='POST', headers=hdr, content=raw)
    assert isinstance(ready, dict)
    job = UUID(ready['id'])
    require(ready['state'] == 'ready', f'{fmt} fixture original not ready')
    if fmt == 'csv':
        require(data['csv_stage'].state.csv_worker.dispatch(job) is ProcessOutcome.COMPLETED, 'CSV fixture worker failed')
    else:
        require(data['xlsx_stage'].state.xlsx_worker.dispatch(job, uuid4()) == 'completed', 'XLSX fixture worker failed')
    return job


def pending_state(data, fmt, job, *, classified):
    """Read back fixture persistence independently of the browser and bridge."""
    require(fmt in ('csv', 'xlsx'), 'Unexpected fixture format')
    fixture = data['fixture']
    with fixture.connect('postgres') as db:
        rows = db.execute(f'SELECT state FROM bri.{fmt}_jobs WHERE (tenant_id,job_id)=(%s,%s)',
                          (fixture.tenant, job)).fetchall()
        require(rows == [('proposed',)], f'{fmt} denial changed the native job')
        require(db.execute('SELECT count(*) FROM bri.knowledge_metadata_initial WHERE (tenant_id,format,job_id)=(%s,%s,%s)',
                           (fixture.tenant, fmt, job)).fetchone() == (int(classified),), 'Wrong classification binding')
        require(db.execute('SELECT count(*) FROM bri.knowledge_metadata_initial_decisions WHERE (tenant_id,format,job_id)=(%s,%s,%s)',
                           (fixture.tenant, fmt, job)).fetchone() == (0,), 'Unexpected committed metadata decision')
        if fmt == 'xlsx':
            count = db.execute('SELECT count(*) FROM bri.xlsx_review_decisions WHERE (tenant_id,job_id)=(%s,%s)',
                               (fixture.tenant, job)).fetchone()
        else:
            count = db.execute("SELECT count(*) FROM bri.csv_audit_events WHERE (tenant_id,job_id)=(%s,%s) "
                               "AND event IN ('approved','rejected')", (fixture.tenant, job)).fetchone()
        require(count == (0,), 'Denial left committed native decision state')


def classified_native_guard(data, fmt, job):
    """Verify the exact PG guard behind the deliberately opaque HTTP denial."""
    from psycopg.errors import InsufficientPrivilege
    from test_csv_intake_postgres import ISSUER

    fixture = data['fixture']
    actor, subject, session = data['actors']['reviewer']
    role = 'bri_csv_intake' if fmt == 'csv' else 'bri_xlsx_reviewer'
    with fixture.connect(role) as db:
        try:
            with db.transaction():
                db.execute("SELECT set_config('bri.tenant_id',%s,true),set_config('bri.auth_user_id',%s,true)",
                           (fixture.tenant, str(subject)))
                if fmt == 'csv':
                    db.execute('SELECT bri.csv_review_decide(%s,%s,%s,%s,%s,%s,%s)',
                               (fixture.tenant, actor, session, ISSUER, job, 'approved', uuid4()))
                else:
                    db.execute('SELECT bri.xlsx_review_decide(%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                               (fixture.tenant, actor, subject, session, ISSUER, job, 'approve', uuid4(), uuid4()))
                raise RuntimeError('Classified native approval did not reach the protected guard')
        except InsufficientPrivilege as exc:
            require(exc.sqlstate == '42501' and exc.diag.message_primary == 'Metadata validation required' and
                    'km_initial_approval_guard' in (exc.diag.context or ''), 'Wrong classified native approval guard')


@contextmanager
def unavailable_metadata_detail(data, fmt):
    """Independently fail the actual metadata read, keeping native detail up."""
    require(fmt in ('csv', 'xlsx'), 'Unexpected fixture format')
    role = 'bri_csv_intake' if fmt == 'csv' else 'bri_xlsx_reviewer'
    signature = 'text,uuid,uuid,uuid,text,uuid' + (',integer' if fmt == 'csv' else '')
    routine = f'bri.{fmt}_review_metadata_detail_v1({signature})'
    fixture = data['fixture']

    def permitted(want):
        with fixture.connect(role) as db:
            require(db.execute('SELECT has_function_privilege(to_regprocedure(%s),\'EXECUTE\')',
                               (routine,)).fetchone() == (want,), 'Unexpected metadata-read dependency privilege')

    permitted(True)
    with fixture.connect('postgres') as db:
        db.execute(f'REVOKE EXECUTE ON FUNCTION {routine} FROM {role}')
    try:
        permitted(False)
        yield
    finally:
        with fixture.connect('postgres') as db:
            db.execute(f'GRANT EXECUTE ON FUNCTION {routine} TO {role}')
        permitted(True)


def request(data, service, route, who, code, *, method='GET', **kwargs):
    headers = kwargs.pop('headers', {})
    if who:
        headers = data['headers'][who] | headers
    response = status(data['client'].request(method, ORIGINS[service] + route, headers=headers, **kwargs),
                      code, f'{service} {method} {route} ({who or "unsigned"})')
    require('no-store' in response.headers.get('cache-control', ''), 'Private fixture receipt was cacheable')
    return response.json() if response.content else None


def xlsx_publish(data, record, job):
    result = data['fixture'].governance(PUBLISHER, 'xlsx_publication_change', record, job, 'publish', uuid4(), identity='publisher')
    require((result['state'], result['revision']) == ('published', 1), 'Separate governed publication failed')


def xlsx_gate(data, gate, record, job, who, allow=True):
    args = (record, job) if gate == 'version' else (record,)
    result = data['fixture'].governance(ACCESS, f'xlsx_{gate}_access_change', *args, data['actors'][who][0],
                                       allow, uuid4(), identity='access')
    require(result is allow, f'Governed XLSX {gate} gate did not commit')
