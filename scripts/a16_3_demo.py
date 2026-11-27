#!/usr/bin/env python3
"""Run the signed A16.3 Chromium demo in a disposable loopback-only namespace."""
from base64 import b64encode
import os
import subprocess
import sys
from hashlib import sha256
from urllib.parse import quote
from uuid import UUID, uuid4

import a13_demo as harness
from a13_demo import ROOT, UI, protocol, report, require, status


def run(args, scratch, stack):
    sys.path[:0] = [str(ROOT), str(ROOT / 'src'), str(ROOT / 'tests')]
    import httpx
    from openpyxl import Workbook
    from bri.api import csv_intake as csv
    from bri.api.xlsx_governance import REVIEW_PREFIX, create_staged_xlsx_governance_app
    from bri.api.xlsx_intake import create_staged_xlsx_intake_app
    from bri.ingestion.csv_intake import LocalCsvQuarantine, ProcessOutcome
    from bri.ingestion.xlsx_intake import LocalXlsxQuarantine
    from test_csv_intake_api import StagedCsvPostgres
    from test_csv_intake_postgres import INTAKE, READER, WORKER
    from test_csv_reporting_postgres import ROUTINE
    from test_xlsx_intake_postgres import ISSUER, XlsxIntakePostgresTests
    from test_xlsx_governance_postgres import REVIEW, REVIEWER, XlsxGovernancePostgresTests

    class Fixture(XlsxIntakePostgresTests):
        provision = XlsxGovernancePostgresTests.provision
        grant_authority = XlsxGovernancePostgresTests.grant_authority
        governance = XlsxGovernancePostgresTests.call

    port = harness.start_chromium(args, scratch, stack)
    fixture = Fixture()
    stack.callback(fixture.doClassCleanups)
    fixture.setUpClass()
    fixture.setUp()
    fixture.identities = {'submitter': fixture.identity}
    tenant = fixture.tenant
    with fixture.connect('postgres') as db:
        require(db.execute("SELECT current_setting('server_version_num'),inet_server_addr(),"
                           "current_setting('listen_addresses')").fetchone() == ('160002', None, ''),
                'Expected socket-only PostgreSQL 16.2')
        for name in ('reviewer', 'publisher', 'access', 'reader', 'unauthorized'):
            p, u, s = (uuid4() for _ in range(3))
            fixture.identities[name] = p, u, s
            db.execute("INSERT INTO bri.auth_principals VALUES (%s,'active')", (p,))
            db.execute("INSERT INTO bri.auth_identity_links(auth_user_id,principal_id,auth_issuer,auth_subject,"
                       "provider_type,provider_issuer,provider_subject) VALUES (%s,%s,%s,%s,'native',%s,%s)",
                       (u, p, ISSUER, str(u), ISSUER, str(u)))
            db.execute("INSERT INTO bri.auth_tenant_memberships(tenant_id,principal_id,membership_type,status) "
                       "VALUES (%s,%s,'user','active')", (tenant, p))
            db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                       'VALUES (%s,%s,%s,clock_timestamp())', (p, u, s))
        for role, routines in (('bri_csv_intake', INTAKE), ('bri_csv_worker', WORKER),
                               ('bri_csv_reader', (*READER, ROUTINE))):
            db.execute(f'CREATE ROLE {role} LOGIN NOINHERIT; GRANT USAGE ON SCHEMA bri TO {role}')
            db.execute(f'GRANT EXECUTE ON FUNCTION {", ".join(routines)} TO {role}')
        db.execute('ALTER ROLE bri_csv_reader SET temp_file_limit = 16384')
        db.execute('INSERT INTO bri.csv_worker_creators VALUES (%s,%s)', (tenant, fixture.creator))
    for name, permission in (('reviewer', 'knowledge:review'), ('publisher', 'knowledge:publish'),
                             ('access', 'knowledge:access_manage'), ('reader', 'knowledge:read')):
        fixture.grant_authority(name, permission)
    publisher, access, reader = 'bri_xlsx_publication_maintainer', 'bri_xlsx_access_maintainer', 'bri_xlsx_reader'
    fixture.provision(REVIEWER, REVIEW)
    fixture.provision(publisher, {'xlsx_publication_change': 'uuid,uuid,text,uuid'})
    fixture.provision(access, {'xlsx_record_access_change': 'uuid,uuid,boolean,uuid',
                               'xlsx_version_access_change': 'uuid,uuid,uuid,boolean,uuid'})
    fixture.provision(reader, {'xlsx_published_detail': 'uuid', 'xlsx_published_evidence': 'uuid,uuid'})

    log = stack.enter_context((scratch / 'fixture-worker.log').open('wb'))

    def pipe(name):
        proc = harness.launch(stack, [args.node, str(ROOT / 'scripts' / name)],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log)
        stack.callback(proc.stdout.close)
        stack.callback(proc.stdin.close)
        return proc

    signer, browser = pipe('a13-browser.mjs'), pipe('a16_3-browser.mjs')
    tokens, cookies, allowlist = {}, {}, {}
    for name, (_, user, sid) in fixture.identities.items():
        signed = protocol(signer, step='sign', issuer=ISSUER, httpOnly=True, identities=[(str(user), str(sid))])
        token, = signed['tokens']
        tokens[name] = {'Authorization': f'Bearer {token}'}
        cookies[name] = signed['cookie']
        allowlist[f'Bearer {token}'] = str(user)
    require(len(set(allowlist.values())) == 6, 'Expected six distinct synthetic identities')

    def provider(req):
        if req.method == 'GET' and str(req.url) == f'{ISSUER}/user':
            if uid := allowlist.get(req.headers.get('Authorization')):
                return httpx.Response(200, json={'id': uid, 'factors': [{'factor_type': 'totp', 'status': 'verified'}]})
        return httpx.Response(401, json={'message': 'invalid fixture identity'})

    def scope(role):
        return lambda: fixture.connect(role)

    common = dict(identity_scope=scope('bri_app'), private_socket=fixture.sock,
                  auth_transport=httpx.MockTransport(provider))
    for name in ('csv-store', 'xlsx-store'):
        (scratch / name).mkdir(mode=0o700)
    csv_stage = csv.create_staged_csv_intake_app(**common, intake_scope=scope('bri_csv_intake'),
                                                 worker_scope=scope('bri_csv_worker'),
                                                 store=LocalCsvQuarantine(scratch / 'csv-store'))
    xlsx_stage = create_staged_xlsx_intake_app(**common, submitter_scope=scope('bri_xlsx_submitter'),
                                               worker_scope=scope('bri_xlsx_worker'),
                                               store=LocalXlsxQuarantine(scratch / 'xlsx-store'))
    gov = create_staged_xlsx_governance_app(**common, review_scope=scope(REVIEWER), reader_scope=scope(reader))
    stack.enter_context(harness.reader_server(xlsx_stage, port=8116))
    stack.enter_context(harness.reader_server(gov, port=8117))
    stack.enter_context(harness.reader_server(csv.create_staged_csv_reader_app(**common, reader_scope=scope('bri_csv_reader'))))
    client = stack.enter_context(httpx.Client(trust_env=False, timeout=90))
    with StagedCsvPostgres.stage_client(csv_stage) as http:
        raw = f'Policy,Evidence\r\nRecords,"Administrative note.\r\n{harness.ANSWER}"\r\n'.encode()
        uploaded = status(http.post(csv.PREFIX, headers={**tokens['submitter'], 'Content-Type': 'text/csv',
                               'X-Node-ID': 'team', 'Idempotency-Key': str(uuid4())}, content=raw), 202, 'CSV seed')
        csv_job = UUID(uploaded.json()['id'])
        require(csv_stage.state.csv_worker.dispatch(csv_job) is ProcessOutcome.COMPLETED, 'CSV dispatch failed')
        ref = f'csv:{csv_job}'
        status(http.post(f'{csv.REVIEW_PREFIX}/{ref}/decision', headers=tokens['reviewer'],
                         json={'decision': 'approved'}), 200, 'CSV seed approve')
    with fixture.connect('bri_migrator') as db:
        db.execute("SELECT set_config('bri.tenant_id',%s,true)", (tenant,))
        db.execute('INSERT INTO bri.knowledge_record_access VALUES (%s,%s,true)', (tenant, ref))
        db.execute('INSERT INTO bri.knowledge_version_access VALUES (%s,%s,%s,true)', (tenant, ref, ref))

    def legacy_reads():
        paths = ('/v1/knowledge', '/v1/knowledge/search', f'/v1/knowledge/{ref}', f'/v1/sources/{ref}',
                 '/v1/reports/published-knowledge-inventory')
        params = ({}, {'q': harness.QUESTION}, {}, {}, {'scope_node_id': 'team'})
        return [status(client.get(harness.API + path, params=query, headers=tokens['reader']),
                       200, 'A13/A15 signed read').json() for path, query in zip(paths, params, strict=True)]

    before = legacy_reads()
    require([row['record_id'] for row in before[0]] == [ref] and before[1]['answer'] == harness.ANSWER
            and [row['record_id'] for row in before[4]['result']['evidence']] == [ref], 'Wrong legacy baseline')

    web = harness.next_copy(scratch)
    log = stack.enter_context((scratch / 'next.log').open('wb'))
    server = harness.launch(stack, [args.node, 'local-workspace/server.mjs'], cwd=web,
                            env=harness.swc_environment(scratch, args.swc_archive), stdout=log, stderr=log)

    def ready():
        try:
            return client.get(f'{UI}/api/bri-local/v1/knowledge/proposals/xlsx', timeout=1).status_code == 401
        except httpx.TransportError:
            return False

    harness.until(ready, 'unsigned XLSX bridge 401', process=server, seconds=90)
    for path in ('/xlsx', '/xlsx/review', f'/xlsx/review/xlsx%3A{uuid4()}',
                 f'/xlsx/knowledge/{uuid4()}', f'/xlsx/knowledge/{uuid4()}/evidence/{uuid4()}'):
        status(client.get(UI + path), 200, 'compile public Next shell')

    def step(name, *, identity=None, **data):
        if identity:
            data['cookie'] = cookies[identity]
        try:
            return protocol(browser, step=name, **data)
        except RuntimeError as exc:
            raise RuntimeError(f'Chromium {name}: {exc}') from None

    file = scratch / 'synthetic.xlsx'
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = 'Synthetic'
    for row in (('Policy', 'Evidence'), ('Records', harness.CONFLICT), ('<demo-literal>café</demo-literal>', '=1+1')):
        sheet.append(row)
    sheet['B3'].data_type = 's'
    workbook.save(file)
    workbook.close()
    payload = file.read_bytes()
    jobs = []
    for index in range(2):
        extra = {'port': port, 'identity': 'submitter'} if index == 0 else {}
        job = UUID(step('upload', file=b64encode(payload).decode('ascii'), state='ready', **extra)['job'])
        jobs.append(job)
        require(xlsx_stage.state.xlsx_worker.dispatch(job, uuid4()) == 'completed', 'XLSX dispatch failed')
        step('status', job=str(job), state='proposed')
    with fixture.connect('postgres') as db:
        require(db.execute('SELECT job_id,original_sha256 FROM bri.xlsx_source_versions WHERE tenant_id=%s ORDER BY job_id',
                           (tenant,)).fetchall() == [(job, sha256(payload).hexdigest()) for job in sorted(jobs)],
                'Worker lineage does not match Chromium uploads')
    report('PASS Chromium signed uploads and ready/proposed status; real worker dispatch and original digests')

    approved, stale = jobs
    step('review-denied', identity='unauthorized', job=str(approved))
    step('approve', identity='reviewer', job=str(approved), jobs=[str(job) for job in sorted(jobs)])
    step('stale-open', job=str(stale))
    status(client.post(f'http://127.0.0.1:8117{REVIEW_PREFIX}/xlsx:{stale}/decision',
                       headers={**tokens['reviewer'], 'Idempotency-Key': str(uuid4())},
                       json={'decision': 'reject'}), 200, 'competing signed rejection')
    step('stale-submit', job=str(stale))
    with fixture.connect('postgres') as db:
        require(set(db.execute('SELECT job_id,actor_id,decision FROM bri.xlsx_review_decisions WHERE tenant_id=%s',
                               (tenant,)).fetchall()) == {(approved, fixture.identities['reviewer'][0], 'approve'),
                                                         (stale, fixture.identities['reviewer'][0], 'reject')},
                'Expected exactly two committed review decisions')
        record, = db.execute('SELECT record_id FROM bri.xlsx_validated_knowledge WHERE (tenant_id,job_id)=(%s,%s)',
                             (tenant, approved)).fetchone()
    report('PASS Chromium unauthorized review, exact pending evidence, approval/history, stale 409 and fresh rejected history without resubmit')

    ids = dict(record=str(record), job=str(approved))
    step('closed', identity='reader', **ids)
    require(fixture.governance(publisher, 'xlsx_publication_change', record, approved, 'publish', uuid4(),
                               identity='reviewer') is None, 'Reviewer must not publish')
    event = fixture.governance(publisher, 'xlsx_publication_change', record, approved, 'publish', uuid4(),
                               identity='publisher')
    require(event['state'] == 'published' and event['revision'] == 1, 'Publish did not commit')
    step('closed', **ids)
    target = fixture.identities['reader'][0]
    require(fixture.governance(access, 'xlsx_record_access_change', record, target, True, uuid4(),
                               identity='access') is True, 'Record allow failed')
    step('closed', **ids)
    require(fixture.governance(access, 'xlsx_version_access_change', record, approved, target, True, uuid4(),
                               identity='access') is True, 'Version allow failed')
    step('open', **ids)
    require(legacy_reads() == before, 'Published XLSX changed A13/A15 responses on the same database')
    step('switch-denied', identity='unauthorized', **ids)
    step('open', identity='reader', **ids)
    require(fixture.governance(access, 'xlsx_version_access_change', record, approved, target, False, uuid4(),
                               identity='access') is False, 'Version revocation failed')
    step('revoked', **ids)
    report('PASS Chromium approval-only, publish-only, record-only denials; both gates open exact workbook; identity switch and live version revocation clear evidence')
    report('PASS same-DB signed A13 list/search/record/source and A15 v1 inventory unchanged after XLSX publication and both allows')


if __name__ == '__main__':
    sys.exit(harness.main(run, entry=os.path.abspath(__file__), name='a16-3', browser_required=True,
                          description=__doc__))
