"""Synthetic A18.3 governed lifecycle; called inside A13's private demo harness."""
import csv as csv_writer
import socket
import subprocess
import sys
from hashlib import sha256
from io import BytesIO, StringIO
from uuid import UUID, uuid4

import a13_demo as harness
from a13_demo import ROOT, protocol, require, status

ORGANISATION = 'Alder Reach Public Services (fictional)'
MIXED_QUERY = 'Visit coordination guidance'
SCOPE_LABELS = {
    'social': ('social-services', 'Social Services'),
    'information': ('information-management', 'Information Management'),
    'hr': ('human-resources', 'HR'),
    'hidden': ('restricted-service', 'Restricted Service'),
    'empty': ('empty-service', 'Community Liaison (empty)'),
}
ORIGINS = {
    'unified': 'http://127.0.0.1:8018',
    'csv_reader': harness.API,
    'xlsx_governance': 'http://127.0.0.1:8117',
    'xlsx_intake': 'http://127.0.0.1:8116',
    'csv_intake': 'http://127.0.0.1:8112',
    'csv_review': 'http://127.0.0.1:8114',
}
PUBLISHER = 'bri_xlsx_publication_maintainer'
ACCESS = 'bri_xlsx_access_maintainer'
XLSX_READER = 'bri_xlsx_reader'


def _provision(fixture, issuer, scopes):
    from test_csv_intake_postgres import READER
    from test_csv_review_workspace_postgres import DECIDE, DETAIL, QUEUE
    from test_privileged_approvals_pg import seed_approval_tenant
    from test_xlsx_intake_postgres import SUBMITTER, WORKER
    from scripts.db.disposable.catalog import XLSX_GOVERNANCE_ROUTINES

    tenant, local_admins = seed_approval_tenant(fixture.connect)
    foreign, foreign_admins = seed_approval_tenant(fixture.connect)
    actors = {}
    submit = 'source:submit'
    review = 'knowledge:review'
    read = 'knowledge:read'
    loaded = ('social', 'information', 'hr', 'hidden')
    local = ('social', 'information', 'hr', 'empty')
    with fixture.connect('postgres') as db:
        db.execute(f'GRANT EXECUTE ON FUNCTION {", ".join(READER)} TO bri_csv_reader')
        db.execute(f'GRANT EXECUTE ON FUNCTION {QUEUE}, {DETAIL}, {DECIDE} TO bri_csv_intake')
        for role, routines in (('bri_xlsx_submitter', SUBMITTER), ('bri_xlsx_worker', WORKER)):
            db.execute(f'CREATE ROLE {role} LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS '
                       'NOCREATEROLE NOCREATEDB NOREPLICATION')
            db.execute(f'GRANT USAGE ON SCHEMA bri TO {role}; '
                       f'GRANT EXECUTE ON FUNCTION {", ".join(routines)} TO {role}')
        for t, admins, label in ((tenant, local_admins, ORGANISATION),
                                 (foreign, foreign_admins, 'Mere Point Public Services (fictional)')):
            db.execute('UPDATE bri.tenants SET display_name=%s,sector=%s WHERE tenant_id=%s',
                       (label, 'public service', t))
            for key, (node, display) in SCOPE_LABELS.items():
                if t == tenant or key == 'social':
                    db.execute("INSERT INTO bri.org_nodes VALUES (%s,%s,'team',%s,'root')", (t, node, display))
            db.execute('INSERT INTO bri.xlsx_worker_creators VALUES (%s,%s)', (t, admins[1][0]))
            db.execute('INSERT INTO bri.csv_worker_creators VALUES (%s,%s)', (t, admins[1][0]))

        def member(name, t, grants):
            p, u, _ = actor = (uuid4(), uuid4(), uuid4())
            actors[name] = actor
            db.execute("INSERT INTO bri.auth_principals VALUES (%s,'active')", (p,))
            db.execute("INSERT INTO bri.auth_identity_links(auth_user_id,principal_id,auth_issuer,auth_subject,"
                       "provider_type,provider_issuer,provider_subject) VALUES (%s,%s,%s,%s,'native',%s,%s)",
                       (u, p, issuer, str(u), issuer, str(u)))
            db.execute("INSERT INTO bri.auth_tenant_memberships(tenant_id,principal_id,membership_type,status) "
                       "VALUES (%s,%s,'user','active')", (t, p))
            for permission, keys in grants:
                db.execute('INSERT INTO bri.app_roles VALUES (%s,%s,%s) ON CONFLICT DO NOTHING',
                           (t, permission, permission))
                db.execute('INSERT INTO bri.role_permissions VALUES (%s,%s,%s) ON CONFLICT DO NOTHING',
                           (t, permission, permission))
                for key in keys:
                    db.execute('INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) '
                               'VALUES (%s,%s,%s,%s)', (t, p, permission, scopes[key]))
            db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                       'VALUES (%s,%s,%s,clock_timestamp())', actor)

        # Intentionally grant review to the uploader so the denial exercises
        # separation of duties rather than the missing-permission check.
        member('submitter', tenant, [(submit, loaded), (review, loaded)])
        member('reviewer', tenant, [(review, loaded)])
        member('publisher', tenant, [('knowledge:publish', loaded)])
        member('access', tenant, [('knowledge:access_manage', loaded)])
        member('reader', tenant, [(read, local), ('organisation:read', ('hidden',))])
        member('hidden_reader', tenant, [(read, ('hidden',))])
        member('unauthorized', tenant, [])
        member('foreign_submitter', foreign, [(submit, ('social',))])
        member('foreign_reviewer', foreign, [(review, ('social',))])
        member('foreign_reader', foreign, [(read, ('social',))])
    for role, routines in XLSX_GOVERNANCE_ROUTINES.items():
        fixture.provision(role, routines)
    return tenant, foreign, actors


def _signed_identities(args, scratch, stack, actors, issuer):
    import httpx

    log = stack.enter_context((scratch / 'fixture-worker.log').open('wb'))
    worker = harness.launch(stack, [args.node, str(ROOT / 'scripts/a13-browser.mjs')],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log)
    assert worker.stdout is not None and worker.stdin is not None
    stack.callback(worker.stdout.close)
    stack.callback(worker.stdin.close)
    headers, cookies, allowlist = {}, {}, {}
    for name, (_, user, session) in actors.items():
        signed = protocol(worker, step='sign', issuer=issuer, httpOnly=True,
                          identities=[(str(user), str(session))])
        token, = signed['tokens']
        auth = f'Bearer {token}'
        headers[name], cookies[name] = {'Authorization': auth}, signed['cookie']
        allowlist[auth] = str(user)

    def provider(request):
        if request.method == 'GET' and str(request.url) == f'{issuer}/user':
            if user := allowlist.get(request.headers.get('Authorization')):
                return httpx.Response(200, json={'id': user, 'factors': [{'factor_type': 'totp', 'status': 'verified'}]})
        return httpx.Response(401, json={'message': 'invalid fixture identity'})

    return headers, cookies, httpx.MockTransport(provider)


def _listen(stack, app, name):
    stack.enter_context(harness.reader_server(app, port=int(ORIGINS[name].rsplit(':', 1)[1])))


def _xlsx_bytes(marker):
    from openpyxl import Workbook

    with BytesIO() as buffer:
        workbook = Workbook()
        try:
            sheet = workbook.active
            assert sheet is not None
            sheet.title = 'Service guidance'
            sheet.append(('Policy', 'Evidence'))
            sheet.append(('Fictional internal policy', marker))
            workbook.save(buffer)
            return buffer.getvalue()
        finally:
            workbook.close()


def _csv_bytes(marker, note):
    with StringIO(newline='') as buffer:
        output = csv_writer.writer(buffer)
        output.writerow(('Policy', 'Evidence'))
        output.writerow(('Fictional internal policy', f'{note}\r\n{marker}'))
        return buffer.getvalue().encode()


def _csv_allow(fixture, tenant, ref):
    # A13's accepted CSV overlay is tenant-bound legacy policy metadata, not
    # finalized knowledge. Unlike XLSX it has no maintenance routine/HTTP API.
    with fixture.connect('bri_migrator') as db:
        db.execute("SELECT set_config('bri.tenant_id',%s,true)", (tenant,))
        db.execute('INSERT INTO bri.knowledge_record_access VALUES (%s,%s,true)', (tenant, ref))
        db.execute('INSERT INTO bri.knowledge_version_access VALUES (%s,%s,%s,true)', (tenant, ref, ref))


class _Lifecycle:
    def __init__(self, fixture, client, headers, actors, scopes, checks):
        self.fixture, self.client, self.headers = fixture, client, headers
        self.actors, self.scopes, self.checks = actors, scopes, checks

    def request(self, method, origin, path, actor, expected, label, *, headers=None, **kwargs):
        result = status(self.client.request(method, ORIGINS[origin] + path,
                        headers={**self.headers[actor], **(headers or {})}, **kwargs), expected, label)
        self.checks[label] = result.status_code
        return result.json()

    def search(self, actor, scope, query, expected, label):
        from bri.api.unified_knowledge import SEARCH

        return self.request('POST', 'unified', SEARCH, actor, expected, label,
                            json={'scope_node_id': self.scopes[scope], 'query': query})

    def evidence(self, record, actor, expected, label):
        origin = 'unified' if record['format'] == 'csv' else 'xlsx_governance'
        return self.request('GET', origin, record['evidence_path'], actor, expected, label)

    def xlsx(self, name, scope, marker, stage, *, reader='reader', record_only=False):
        from bri.api.xlsx_governance import PUBLISHED_V2_PREFIX, REVIEW_PREFIX
        from bri.api.xlsx_intake import PREFIX

        raw = _xlsx_bytes(marker)
        uploaded = self.request('POST', 'xlsx_intake', PREFIX, 'submitter', 202, f'{name}: XLSX submit',
                                headers={'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                                         'X-Node-ID': self.scopes[scope], 'Idempotency-Key': str(uuid4())}, content=raw)
        job = UUID(uploaded['id'])
        require(uploaded['state'] == 'ready', f'{name}: original not ready')
        require(stage.state.xlsx_worker.dispatch(job, uuid4()) == 'completed', f'{name}: XLSX worker failed')
        self.checks[f'{name}: XLSX extract'] = 'completed'
        receipt = self.request('GET', 'xlsx_intake', f'{PREFIX}/{job}', 'submitter', 200, f'{name}: proposed')
        require(receipt == {'id': str(job), 'state': 'proposed'}, f'{name}: XLSX extraction not proposed')
        proposal = f'{REVIEW_PREFIX}/xlsx:{job}'

        def decide(actor, expected, label):
            return self.request('POST', 'xlsx_governance', proposal + '/decision', actor, expected,
                                f'{name}: {label}', headers={'Idempotency-Key': str(uuid4())}, json={'decision': 'approve'})

        # The uploader's exact-node review grant reaches the reviewer/author
        # separation guard; it is not a missing-permission denial.
        decide('submitter', 404, 'uploader self-approval denied')
        review = decide('reviewer', 200, 'independent XLSX approval')
        require(review == {'id': f'xlsx:{job}', 'decision': 'approve'}, f'{name}: wrong XLSX review receipt')
        with self.fixture.connect('postgres') as db:
            original, canonical = db.execute('SELECT original_sha256,canonical_sha256 FROM bri.xlsx_source_versions '
                                             'WHERE (tenant_id,job_id)=(%s,%s)', (self.fixture.tenant, job)).fetchone()
            record, actor = db.execute('SELECT k.record_id,d.actor_id FROM bri.xlsx_validated_knowledge k '
                                       'JOIN bri.xlsx_review_decisions d USING (tenant_id,job_id) '
                                       'WHERE (k.tenant_id,k.job_id)=(%s,%s)', (self.fixture.tenant, job)).fetchone()
        require(actor == self.actors['reviewer'][0] and original == sha256(raw).hexdigest(),
                f'{name}: wrong XLSX review actor or original digest')
        data = dict(format='xlsx', record_id=str(record), version_id=str(job), scope=self.scopes[scope],
                    query=marker, marker=marker, evidence_path=f'{PUBLISHED_V2_PREFIX}/{record}/evidence/{job}',
                    original_sha256=original, extracted_sha256=canonical)
        self.evidence(data, reader, 404, f'{name}: approved but unpublished denied')
        call = self.fixture.governance
        require(call(PUBLISHER, 'xlsx_publication_change', record, job, 'publish', uuid4(), identity='reviewer') is None,
                f'{name}: reviewer published')
        self.checks[f'{name}: reviewer publication denied'] = True
        published = call(PUBLISHER, 'xlsx_publication_change', record, job, 'publish', uuid4(), identity='publisher')
        require((published['state'], published['revision']) == ('published', 1), f'{name}: XLSX publication not committed')
        self.checks[f'{name}: protected publication'] = published['state']
        self.evidence(data, reader, 404, f'{name}: publication alone denied')
        target = self.actors[reader][0]
        require(call(ACCESS, 'xlsx_record_access_change', record, target, True, uuid4(), identity='access') is True,
                f'{name}: record grant failed')
        self.evidence(data, reader, 404, f'{name}: record-only denied')
        rows = self.search(reader, scope, marker, 200, f'{name}: record-only search')
        require(not rows['results'], f'{name}: record-only evidence leaked into search')
        if not record_only:
            require(call(ACCESS, 'xlsx_version_access_change', record, job, target, True, uuid4(), identity='access') is True,
                    f'{name}: exact-version grant failed')
            result = self.evidence(data, reader, 200, f'{name}: both gates open')
            require(result['original_sha256'] == original and result['canonical_sha256'] == canonical and
                    {'row': 2, 'column': 2, 'value': ['text', marker]} in result['cells'],
                    f'{name}: wrong XLSX worksheet evidence')
        for actor in ('reviewer', 'publisher'):
            self.evidence(data, actor, 404, f'{name}: {actor} cannot read')
            self.search(actor, scope, marker, 403, f'{name}: {actor} cannot search')
        return data

    def csv(self, name, scope, marker, stage, *, foreign=False, pending=False, note='Administrative note only.'):
        from bri.api.csv_intake import PREFIX, REVIEW_PREFIX
        from bri.api.unified_knowledge import CSV_EVIDENCE
        from bri.ingestion.csv_intake import ProcessOutcome, extract_bounded_csv

        raw = _csv_bytes(marker, note)
        prefix = 'foreign_' if foreign else ''
        tenant = self.fixture.foreign if foreign else self.fixture.tenant
        uploader, reviewer, reader = (prefix + name for name in ('submitter', 'reviewer', 'reader'))
        uploaded = self.request('POST', 'csv_intake', PREFIX, uploader, 202, f'{name}: CSV submit',
                                headers={'Content-Type': 'text/csv', 'X-Node-ID': self.scopes[scope],
                                         'Idempotency-Key': str(uuid4())}, content=raw)
        job = UUID(uploaded['id'])
        require(stage.state.csv_worker.dispatch(job) is ProcessOutcome.COMPLETED, f'{name}: CSV worker failed')
        self.checks[f'{name}: CSV extract'] = 'completed'
        ref = f'csv:{job}'
        proposal = f'{REVIEW_PREFIX}/{ref}'
        url = proposal + '/decision'
        if not foreign:
            self.request('POST', 'csv_intake', url, uploader, 403, f'{name}: uploader self-approval denied',
                         json={'decision': 'approved'})
        original, extracted = sha256(raw).hexdigest(), extract_bounded_csv(raw).extracted_sha256
        path = CSV_EVIDENCE.format(record_id=job, version_id=job)
        data = dict(format='csv', record_id=str(job), version_id=str(job), scope=self.scopes[scope], query=marker,
                    marker=marker, evidence_path=path, original_sha256=original, extracted_sha256=extracted,
                    legacy_ref=ref)
        detail = self.request('GET', 'csv_review', proposal, reviewer, 200, f'{name}: CSV pending review detail')
        require(detail['state'] == 'proposed' and marker in detail['evidence'], f'{name}: wrong CSV review evidence')
        if pending:
            self.evidence(data, reader, 404, f'{name}: pending CSV not published')
            return data
        review = self.request('POST', 'csv_review', url, reviewer, 200, f'{name}: independent CSV approval',
                              json={'decision': 'approved'})
        require(review == {'id': ref, 'decision': 'approved'}, f'{name}: wrong CSV review receipt')
        detail = self.request('GET', 'csv_review', proposal, reviewer, 200, f'{name}: CSV approved review detail')
        require(detail['state'] == 'approved' and detail['history'][-1]['event'] == 'approved',
                f'{name}: CSV review decision not visible')
        self.evidence(data, reader, 404, f'{name}: CSV without overlay denied')
        _csv_allow(self.fixture, tenant, ref)
        result = self.evidence(data, reader, 200, f'{name}: CSV overlay opens evidence')
        require(result['original_sha256'] == original and result['content_sha256'] == extracted,
                f'{name}: wrong CSV evidence digest')
        return data


def setup_fixture(args, scratch, stack, *, wrap_unified=None):
    """Start a disposable fixture and verify its lifecycle before returning browser inputs."""
    require(socket.if_nameindex() == [(1, 'lo')], 'The A18.3 fixture requires a loopback-only network namespace')
    for path in (ROOT / 'tests', ROOT / 'src', ROOT):
        if str(path) not in sys.path:
            sys.path.insert(0, str(path))
    import httpx
    from bri.api import csv_intake
    from bri.api.csv_review_workspace import create_staged_csv_review_app
    from bri.api.unified_knowledge import SEARCH_SCOPES, create_staged_unified_knowledge_app
    from bri.api.xlsx_governance import create_staged_xlsx_governance_app
    from bri.api.xlsx_intake import create_staged_xlsx_intake_app
    from bri.ingestion.csv_intake import LocalCsvQuarantine
    from bri.ingestion.xlsx_intake import LocalXlsxQuarantine
    from test_csv_intake_postgres import ISSUER
    from test_unified_knowledge_postgres import ROLE, UnifiedKnowledgePostgresTests
    from test_xlsx_governance_postgres import REVIEWER, XlsxGovernancePostgresTests

    class Fixture(UnifiedKnowledgePostgresTests):
        provision = XlsxGovernancePostgresTests.provision
        governance = XlsxGovernancePostgresTests.call

    fixture = Fixture()
    stack.callback(fixture.doClassCleanups)
    fixture.setUpClass()
    with fixture.connect('postgres') as db:
        require(db.execute("SELECT current_setting('server_version_num'),inet_server_addr(),"
                           "current_setting('listen_addresses')").fetchone() == ('160002', None, ''),
                'Expected private socket-only PostgreSQL 16.2')
    scopes = {name: node for name, (node, _) in SCOPE_LABELS.items()}
    fixture.tenant, fixture.foreign, fixture.identities = _provision(fixture, ISSUER, scopes)
    actors = fixture.identities
    headers, cookies, transport = _signed_identities(args, scratch, stack, actors, ISSUER)

    def scope(role):
        return lambda: fixture.connect(role)

    common = dict(identity_scope=scope('bri_app'), private_socket=fixture.sock, auth_transport=transport)
    for name in ('csv-store', 'xlsx-store'):
        (scratch / name).mkdir(mode=0o700)
    csv_stage = csv_intake.create_staged_csv_intake_app(**common, intake_scope=scope('bri_csv_intake'),
                                                       worker_scope=scope('bri_csv_worker'),
                                                       store=LocalCsvQuarantine(scratch / 'csv-store'))
    xlsx_stage = create_staged_xlsx_intake_app(**common, submitter_scope=scope('bri_xlsx_submitter'),
                                              worker_scope=scope('bri_xlsx_worker'),
                                              store=LocalXlsxQuarantine(scratch / 'xlsx-store'))
    governance = create_staged_xlsx_governance_app(**common, review_scope=scope(REVIEWER),
                                                   reader_scope=scope(XLSX_READER))
    unified = create_staged_unified_knowledge_app(**common, reader_scope=scope(ROLE))
    csv_reader = csv_intake.create_staged_csv_reader_app(**common, reader_scope=scope('bri_csv_reader'))
    csv_review = create_staged_csv_review_app(**common, review_scope=scope('bri_csv_intake'))
    for name, app in (('csv_intake', csv_stage), ('xlsx_intake', xlsx_stage), ('xlsx_governance', governance),
                      ('csv_reader', csv_reader), ('csv_review', csv_review),
                      ('unified', wrap_unified(unified) if wrap_unified else unified)):
        _listen(stack, app, name)
    client = stack.enter_context(httpx.Client(trust_env=False, timeout=20))
    checks = {}
    flow = _Lifecycle(fixture, client, headers, actors, scopes, checks)
    records = {
        'social': flow.xlsx('social', 'social', MIXED_QUERY, xlsx_stage),
        'social_csv': flow.csv('social_csv', 'social', f'{MIXED_QUERY} for referrals', csv_stage),
        'information': flow.csv('information', 'information', 'Archive transfer procedures', csv_stage, note=harness.ANSWER),
        'pending_csv': flow.csv('pending_csv', 'information', 'Draft public records triage', csv_stage, pending=True),
        'hr': flow.xlsx('hr', 'hr', 'Induction planning guidance', xlsx_stage),
        'hidden': flow.xlsx('hidden', 'hidden', 'Restricted scheduling guidance', xlsx_stage, reader='hidden_reader'),
        'record_only': flow.xlsx('record_only', 'information', 'Record only access sentinel', xlsx_stage, record_only=True),
        'foreign': flow.csv('foreign', 'social', 'Foreign tenant access sentinel', csv_stage, foreign=True),
    }
    for key in ('social', 'social_csv', 'information', 'hr', 'hidden', 'foreign'):
        if key == 'social':
            continue  # The exact workbook marker is intentionally also a CSV substring.
        record = records[key]
        actor = {'hidden': 'hidden_reader', 'foreign': 'foreign_reader'}.get(key, 'reader')
        scope_key = 'social' if key in ('foreign', 'social_csv') else key
        hits = flow.search(actor, scope_key, record['query'], 200, f'{key}: exact search')['results']
        require(len(hits) == 1 and hits[0]['record_id'] == record['record_id'] and
                hits[0]['source_version_id'] == record['version_id'] and hits[0]['evidence_url'] == record['evidence_path'] and
                hits[0]['format'] == record['format'] and hits[0]['original_sha256'] == record['original_sha256'] and
                hits[0]['canonical_sha256' if record['format'] == 'xlsx' else 'content_sha256'] == record['extracted_sha256'],
                f'{key}: wrong protected search lineage')
    mixed = flow.search('reader', 'social', MIXED_QUERY, 200, 'mixed exact-node search')['results']
    require([(hit['format'], hit['record_id'], hit['match']) for hit in mixed] == [
                ('xlsx', records['social']['record_id'], 'exact'), ('csv', records['social_csv']['record_id'], 'substring')],
            'Mixed search must return the two authorized Social Services sources only')
    flow.evidence(records['hidden'], 'reader', 404, 'hidden: primary evidence denied')
    flow.search('reader', 'hidden', records['hidden']['query'], 403, 'hidden: primary search denied')
    flow.evidence(records['foreign'], 'reader', 404, 'foreign: primary evidence denied')
    flow.evidence(records['social'], 'foreign_reader', 404, 'social: foreign evidence denied')
    for scope_key, query, label in (('empty', records['social']['query'], 'allowed empty'),
                                    ('social', records['foreign']['query'], 'foreign excluded'),
                                    ('hr', records['information']['query'], 'sibling excluded')):
        require(not flow.search('reader', scope_key, query, 200, label)['results'], f'{label}: unexpected results')
    discovered = flow.request('GET', 'unified', SEARCH_SCOPES, 'reader', 200, 'primary scopes')['scopes']
    require({(row['scope_node_id'], row['display_label']) for row in discovered} ==
            {SCOPE_LABELS[name] for name in ('social', 'information', 'hr', 'empty')},
            'Expected only the three departments and allowed-empty scope')
    question = dict(text=harness.QUESTION, answer=harness.ANSWER, record_id=records['information']['legacy_ref'])
    answer = flow.request('GET', 'csv_reader', '/v1/knowledge/search', 'reader', 200, 'A13 CSV question',
                          params={'q': question['text']})
    require(answer['status'] == 'supported' and answer['answer'] == question['answer'] and
            [row['record_id'] for row in answer['citations']] == [question['record_id']], 'Wrong A13 answer or citation')
    from a15_consumer import read_inventory

    report_status, inventory = read_inventory(bearer=headers['reader']['Authorization'][7:], scope_node_id=scopes['social'])
    require(report_status == 200 and inventory['result']['status'] == 'complete' and inventory['result']['count'] == 1 and
            [row['record_id'] for row in inventory['result']['evidence']] == [records['social_csv']['legacy_ref']],
            'A15 must report the CSV, not the adjacent XLSX')
    checks['A15 CSV-only inventory'] = report_status
    harness.report('PASS governed XLSX and CSV lifecycle, exact lineage, scope isolation and denial controls')
    return dict(fixture=fixture, tenant=fixture.tenant, foreign_tenant=fixture.foreign, organisation=ORGANISATION,
                scopes=scopes, actors=actors, headers=headers, cookies=cookies, client=client,
                origins=ORIGINS.copy(), records=records, checks=checks,
                mixed_scope=scopes['social'], mixed_query=MIXED_QUERY,
                mixed={'query': MIXED_QUERY, 'records': ('social_csv', 'social')}, question=question,
                legacy_question=harness.QUESTION, legacy_answer=harness.ANSWER)
