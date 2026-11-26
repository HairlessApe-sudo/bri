#!/usr/bin/env python3
"""Run the signed A14 review demo in a loopback-only Linux namespace."""
import json
import subprocess
import sys
from hashlib import sha256
from urllib.parse import quote
from uuid import UUID, uuid4

import a13_demo as harness
from a13_demo import ROOT, UI, BRIDGE, protocol, report, require, status

REVIEW_ORIGIN = 'http://127.0.0.1:8114'
CSV = b'Kind,Literal\r\nFormula,=1+1\r\nMarkup,"<a14-literal>caf\xc3\xa9</a14-literal>\r\nstill literal"\r\n'
EVIDENCE = json.dumps({'headers': ['Kind', 'Literal'], 'rows': [
    ['Formula', '=1+1'], ['Markup', '<a14-literal>café</a14-literal>\r\nstill literal'],
]}, ensure_ascii=False, separators=(',', ':'))


def reader_identity(fixture):
    # Reuse the creator principal only after intake. Give its fresh session
    # read authority, not review authority; leave the actual reviewer unchanged.
    principal, user, _ = fixture.actors[1]
    reader = principal, user, uuid4()
    tenant = fixture.tenant
    with fixture.connect('postgres') as db:
        db.execute("UPDATE bri.auth_role_assignments SET status='revoked' "
                   "WHERE (tenant_id,principal_id,role_id)=(%s,%s,'csv')", (tenant, principal))
        db.execute("INSERT INTO bri.app_roles VALUES (%s,'demo-reader','Demo published reader')", (tenant,))
        db.execute("INSERT INTO bri.role_permissions VALUES (%s,'demo-reader','knowledge:read')", (tenant,))
        db.execute("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) "
                   "VALUES (%s,%s,'demo-reader','team')", (tenant, principal))
        db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                   'VALUES (%s,%s,%s,clock_timestamp())', reader)
    return reader


def seed(stage, uploader):
    from bri.api.csv_intake import PREFIX
    from bri.ingestion.csv_intake import ProcessOutcome
    from test_csv_intake_api import StagedCsvPostgres

    refs = []
    with StagedCsvPostgres.stage_client(stage) as client:
        for raw, outcome in ((CSV, ProcessOutcome.COMPLETED), (b'Kind,Literal\r\nPlain,second\r\n', ProcessOutcome.COMPLETED),
                             (b'duplicate,duplicate\r\n1,2\r\n', ProcessOutcome.FAILED)):
            result = status(client.post(PREFIX, content=raw, headers={**uploader, 'Content-Type': 'text/csv',
                            'X-Node-ID': 'team', 'Idempotency-Key': str(uuid4())}), 202, 'A12 fixture intake')
            job = UUID(result.json()['id'])
            require(stage.state.csv_worker.dispatch(job) is outcome, 'Unexpected A12 fixture worker outcome')
            refs.append(f'csv:{job}')
    return refs


def verify_persistence(fixture, refs, reader, issuer):
    approved, rejected, failed = refs
    with fixture.connect('bri_migrator') as db:
        db.execute('SET TRANSACTION READ ONLY')
        db.execute("SELECT set_config('bri.tenant_id',%s,true)", (fixture.tenant,))
        decisions = db.execute('SELECT proposal_id,decision,csv_governed FROM bri.validation_decisions '
                               'WHERE tenant_id=%s AND proposal_id=ANY(%s)', (fixture.tenant, refs)).fetchall()
        require(sorted(decisions) == sorted([(approved, 'approved', True), (rejected, 'rejected', True)]),
                'Expected exactly one governed decision per proposal and none for failed intake')
        validated = db.execute('SELECT proposal_id FROM bri.validated_knowledge WHERE tenant_id=%s '
                               'AND proposal_id=ANY(%s)', (fixture.tenant, refs)).fetchall()
        require(validated == [(approved,)], 'Unexpected committed validation rows')
        for table in ('knowledge_record_access', 'knowledge_version_access'):
            rows = db.execute(f'SELECT count(*) FROM bri.{table} WHERE tenant_id=%s AND source_id=ANY(%s)',
                              (fixture.tenant, refs)).fetchone()
            require(rows == (0,), f'Unexpected access rows in {table}')
    with fixture.connect('bri_csv_reader') as db:
        db.execute('SET TRANSACTION READ ONLY')
        require(db.execute('SELECT proposal_id FROM bri.csv_read_published(%s,%s,%s,%s,%s)',
                           (fixture.tenant, *reader, issuer)).fetchall() == [],
                'Restricted published SQL returned a demo proposal')


def run(args, scratch, stack):
    sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'tests')]
    import httpx
    from bri.api.csv_intake import create_staged_csv_intake_app, create_staged_csv_reader_app
    from bri.api.csv_review_workspace import create_staged_csv_review_app
    from bri.ingestion.csv_intake import LocalCsvQuarantine
    from test_authentication import ISSUER
    from test_csv_review_workspace_api import BASE, ReviewWorkspacePostgresTests

    port = harness.start_chromium(args, scratch, stack)
    fixture = ReviewWorkspacePostgresTests()
    stack.callback(fixture.doClassCleanups)
    fixture.setUpClass()
    fixture.setUp()
    with fixture.connect('postgres') as db:
        require(db.execute("SELECT current_setting('server_version_num'),inet_server_addr(),"
                           "current_setting('listen_addresses')").fetchone() == ('160002', None, ''),
                'Expected private Unix-socket-only PostgreSQL 16.2')
    report('PASS PostgreSQL 16.2, Unix socket only; A14 migrations and ACL fixture')

    worker = harness.launch(stack, [args.node, str(ROOT / 'scripts/a13-browser.mjs')],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    assert worker.stdout is not None and worker.stdin is not None
    stack.callback(worker.stdout.close)
    stack.callback(worker.stdin.close)
    identities = {}

    def sign(identity):
        _, user, session = identity
        token, = protocol(worker, step='sign', issuer=ISSUER, identities=[(str(user), str(session))])['tokens']
        bearer = f'Bearer {token}'
        identities[bearer] = str(user)
        return {'Authorization': bearer}

    def provider(request):
        # A13's provider recognizes exactly the RSA tokens issued over the pipe.
        # The API unit test's provider helper expects HS256, not these tokens.
        if request.method == 'GET' and str(request.url) == f'{ISSUER}/user':
            if user := identities.get(request.headers.get('Authorization')):
                return httpx.Response(200, json={'id': user, 'factors': [{'factor_type': 'totp', 'status': 'verified'}]})
        return httpx.Response(401, json={'message': 'invalid fixture identity'})

    def browser(step, **data):
        try:
            require(protocol(worker, step=f'a14-{step}', **data).get('ok'), 'Missing browser acknowledgement')
        except RuntimeError as exc:
            raise RuntimeError(f'Chromium {step}: {exc}') from None

    common = dict(identity_scope=lambda: fixture.connect('bri_app'), private_socket=fixture.sock,
                  auth_transport=httpx.MockTransport(provider))
    quarantine = scratch / 'quarantine'
    quarantine.mkdir(mode=0o700)
    stage = create_staged_csv_intake_app(**common, intake_scope=lambda: fixture.connect('bri_csv_intake'),
                                        worker_scope=lambda: fixture.connect('bri_csv_worker'),
                                        store=LocalCsvQuarantine(quarantine))
    refs = seed(stage, sign(fixture.actors[2]))
    approved, stale, failed = refs
    reviewer = fixture.actors[0]
    reader = reader_identity(fixture)
    reader_headers = sign(reader)
    review_app = create_staged_csv_review_app(**common, review_scope=lambda: fixture.connect('bri_csv_intake'))
    stack.enter_context(harness.reader_server(review_app, port=8114))
    # An adjacent reader-only listener is an independent read-authority control.
    reader_app = create_staged_csv_reader_app(**common, reader_scope=lambda: fixture.connect('bri_csv_reader'))
    stack.enter_context(harness.reader_server(reader_app))
    client = stack.enter_context(httpx.Client(trust_env=False, timeout=30))
    status(client.get(f'{REVIEW_ORIGIN}/v1/knowledge'), 404, 'review listener has no published endpoint')
    status(client.post(f'{REVIEW_ORIGIN}/v1/sources/csv'), 404, 'review listener has no intake endpoint')
    status(client.post('http://127.0.0.1:9013/auth/v1/token?grant_type=password'), 404, 'fixture has no HTTP mint')

    web = harness.next_copy(scratch)
    log = stack.enter_context((scratch / 'next.log').open('wb'))
    server = harness.launch(stack, [args.node, 'local-workspace/server.mjs'], cwd=web,
                            env=harness.swc_environment(scratch, args.swc_archive), stdout=log, stderr=log)

    def ready():
        try:
            return client.get(f'{UI}{BRIDGE}{BASE.removeprefix("/v1")}', timeout=1).status_code == 401
        except httpx.TransportError:
            return False

    harness.until(ready, 'Next review bridge (unsigned must return 401)', process=server, seconds=90)
    # Cold Next compilation can exceed the short CDP command timeout on WSL.
    # Warm only the public page shells, not any signed or browser-result reads.
    for path in ('/review', f'/review/{quote(approved, safe="")}'):
        status(client.get(f'{UI}{path}', timeout=90), 200, 'Next shell compile')
    browser('denied', port=port, ref=approved)
    report('PASS unsigned bridge 401; signed published reader denied review in Chromium; no evidence or controls')
    reviewer_headers = sign(reviewer)
    browser('approve', port=port, approved=approved, stale=stale, evidence=EVIDENCE,
            original=sha256(CSV).hexdigest(), extracted=sha256(EVIDENCE.encode()).hexdigest())
    report('PASS Chromium pending queue, exact version/digests/lines, inert evidence, explicit approval 200 and fresh approved history')

    # Chromium is parked on a *live proposed detail*, not a fabricated response.
    # A separate real HTTP client commits a rejection before Chromium confirms.
    browser('prepare-stale', ref=stale)
    result = status(client.post(f'{REVIEW_ORIGIN}{BASE}/{stale}/decision', headers=reviewer_headers,
                               json={'decision': 'rejected'}), 200, 'competing real Uvicorn decision')
    require(result.json() == {'id': stale, 'decision': 'rejected'}, 'Unexpected committed rejection acknowledgement')
    browser('stale', ref=stale)
    browser('terminal', approved=approved, stale=stale, failed=failed)
    report('PASS Chromium stale POST 409, explicit refresh to rejected history, empty pending queue and terminal status filters')

    published_url = f'{harness.API}/v1/knowledge'
    require(status(client.get(published_url, headers=reader_headers), 200, 'signed published reader').json() == [],
            'Published reader returned a demo record')
    status(client.get(published_url, headers=reviewer_headers), 403, 'reviewer lacks published read grant')
    verify_persistence(fixture, refs, reader, ISSUER)
    require(protocol(worker, step='stats')['jwksReads'] > 0, 'No fixture JWKS reads observed')
    report('PASS committed decisions and validation; zero record/version access rows; restricted SQL and signed read API return no records')


if __name__ == '__main__':
    sys.exit(harness.main(run, entry=__file__, name='a14', browser_required=True, description=__doc__))
