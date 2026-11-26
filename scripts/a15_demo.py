#!/usr/bin/env python3
"""Compare the signed A15 API consumer with the isolated local workspace."""
import os
import subprocess
import sys
from contextlib import ExitStack
from urllib.parse import quote

import a13_demo as harness
from a13_demo import ROOT, UI, BRIDGE, require, report, status, protocol
from a15_consumer import PATH, read_inventory


def run(args, scratch, stack):
    sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'tests')]
    import httpx
    from bri.api.csv_intake import create_staged_csv_reader_app
    from test_authentication import ISSUER
    from test_csv_intake_api import StagedCsvPostgres
    from test_csv_intake_postgres import READER
    from test_csv_reporting_postgres import CsvReportingPostgresTests

    port = None if args.http_only else harness.start_chromium(args, scratch, stack)
    class DemoFixture(CsvReportingPostgresTests):
        stage_client = staticmethod(StagedCsvPostgres.stage_client)

    fixture = DemoFixture()
    stack.callback(fixture.doClassCleanups)
    fixture.setUpClass()
    fixture.setUp_intake()
    with fixture.connect('postgres') as db:
        require(db.execute("SELECT current_setting('server_version_num'), inet_server_addr(), "
                           "current_setting('listen_addresses')").fetchone() == ('160002', None, ''),
                'Expected disposable Unix-socket-only PostgreSQL 16.2')
        db.execute(f'GRANT EXECUTE ON FUNCTION {", ".join(READER)} TO bri_csv_reader')

    worker_log = stack.enter_context((scratch / 'fixture-worker.log').open('wb'))
    worker = harness.launch(stack, [args.node, str(ROOT / 'scripts/a13-browser.mjs')],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=worker_log)
    assert worker.stdout is not None and worker.stdin is not None
    stack.callback(worker.stdout.close)
    stack.callback(worker.stdin.close)
    tokens, allowlist = {}, {}

    def sign(*actors, cookie=False):
        signed = protocol(worker, step='sign', issuer=ISSUER, httpOnly=cookie,
                          identities=[(str(uid), str(sid)) for _, uid, sid in actors])
        for actor, token in zip(actors, signed['tokens'], strict=True):
            tokens[actor] = token
            allowlist[f'Bearer {token}'] = str(actor[1])
        return signed.get('cookie')

    def provider(request):
        if request.method == 'GET' and str(request.url) == f'{ISSUER}/user':
            if uid := allowlist.get(request.headers.get('Authorization')):
                return httpx.Response(200, json={'id': uid, 'factors': [{'factor_type': 'totp', 'status': 'verified'}]})
        return httpx.Response(401, json={'message': 'invalid fixture identity'})

    def bearer(actor):
        return {'Authorization': f'Bearer {tokens[actor]}'}

    transport = httpx.MockTransport(provider)
    def identity_scope():
        return fixture.connect('bri_app')

    sign(*(actors[i] for actors in (fixture.actors, fixture.foreign_actors) for i in (0, 2)))
    local, other, foreign = harness.publish(fixture, transport, scratch / 'quarantine', bearer,
                                           {'identity_scope': identity_scope})
    reader, root_reader, foreign_reader = StagedCsvPostgres.seed_readers(fixture)
    root_cookie = sign(root_reader, cookie=True)
    cookie = sign(reader, foreign_reader, cookie=True)
    app = create_staged_csv_reader_app(identity_scope=identity_scope, reader_scope=lambda: fixture.connect('bri_csv_reader'),
                                       private_socket=fixture.sock, auth_transport=transport)
    reader_listener = stack.enter_context(ExitStack())
    reader_listener.enter_context(harness.reader_server(app))
    client = stack.enter_context(httpx.Client(trust_env=False, timeout=90))
    bridge = f'{UI}{BRIDGE}{PATH.removeprefix("/v1")}'
    cookie_header = {'Cookie': cookie}

    def direct(actor, node='team'):
        return read_inventory(bearer=tokens[actor], scope_node_id=node)

    def parity(node, code, *, actor=reader, headers=cookie_header):
        direct_code, expected = direct(actor, node)
        require(direct_code == code, 'Unexpected signed direct reporting status')
        response = status(client.get(bridge, params={'scope_node_id': node}, headers=headers), code,
                          'signed local bridge')
        require('no-store' in response.headers.get('cache-control', ''), 'Report must not be cached')
        if code != 403:
            require(response.json() == expected, 'Signed API consumer and bridge disagree')
        else:
            require(response.json() == {'detail': 'Local workspace read unavailable.'}, 'Non-generic bridge denial')
        return expected

    def envelope(node, state, **extra):
        return {'result': {'metric_id': 'published_knowledge_inventory', 'metric_version': 1,
                           'scope_node_id': node, 'status': state, **extra}}

    def evidence(*records):
        return [dict(record_id=r['ref'], source_version_id=r['ref'], original_sha256=r['digest'],
                     content_sha256=r['extracted'], first_line=1, last_line=3)
                for r in sorted(records, key=lambda r: r['ref'])]

    web = harness.next_copy(scratch)
    log = stack.enter_context((scratch / 'next.log').open('wb'))
    next_server = harness.launch(stack, [args.node, 'local-workspace/server.mjs'], cwd=web,
                                 env=harness.swc_environment(scratch, args.swc_archive), stdout=log, stderr=log)

    def ready():
        try:
            return client.get(bridge, params={'scope_node_id': 'team'}, timeout=1).status_code == 401
        except httpx.TransportError:
            return False

    harness.until(ready, 'unsigned bridge (401)', process=next_server, seconds=90)
    for path in ('/reports', f'/sources/{quote(local["ref"], safe="")}'):
        status(client.get(f'{UI}{path}'), 200, 'Next shell compile')
    require(parity('team', 200) == envelope('team', 'complete', count=2, evidence=evidence(local, other)),
            'Signed consumer did not return exact ordered evidence')
    require(parity('root', 200, actor=root_reader, headers={'Cookie': root_cookie})
            == envelope('root', 'complete', count=0, evidence=[]),
            'Exact parent node must not count child records')
    require(direct(foreign_reader) == (200, envelope('team', 'complete', count=1, evidence=evidence(foreign))),
            'Foreign tenant saw non-tenant records')
    require(parity('root', 403) == parity('unknown-node', 403), 'Denied and missing nodes must be indistinguishable')
    report('PASS signed API and bridge parity, exact and empty node, foreign isolation, generic denial')

    browser = None
    if port is not None:
        browser = harness.launch(stack, [args.node, str(ROOT / 'scripts/a15-browser.mjs')],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=worker_log)
        assert browser.stdout is not None and browser.stdin is not None
        stack.callback(browser.stdout.close)
        stack.callback(browser.stdin.close)
        protocol(browser, step='complete', port=port, cookie=cookie, rootCookie=root_cookie,
                 evidence=evidence(local, other), ref=local['ref'])
        report('PASS Chromium exact count, authorized empty, signed evidence rows and existing source follow-through')

    with fixture.connect('postgres') as db:
        db.execute('ALTER ROLE bri_csv_reader SET temp_file_limit = -1')
    try:
        require(parity('team', 503) == envelope('team', 'unavailable'), 'Unavailable must not expose count or evidence')
        if browser:
            protocol(browser, step='unavailable')
    finally:
        with fixture.connect('postgres') as db:
            db.execute('ALTER ROLE bri_csv_reader RESET temp_file_limit')

    if browser:
        protocol(browser, step='restored', evidence=evidence(local, other))
    with fixture.connect('postgres') as db:
        require(db.execute('UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() '
                           'WHERE session_id=%s AND revoked_at IS NULL', (reader[2],)).rowcount == 1,
                'Expected one committed native session revocation')
    parity('team', 403)
    if browser:
        protocol(browser, step='denied')
    report('PASS unavailable without partial data; live native-session revocation denies fresh evaluation')
    reader_listener.close()
    dependency = status(client.get(bridge, params={'scope_node_id': 'team'}, headers=cookie_header), 503,
                        'stopped reader dependency')
    require(dependency.json() == {'detail': 'Local workspace read unavailable.'}, 'Dependency failure leaked details')
    if browser:
        protocol(browser, step='dependency')
    report('PASS stopped reader is a dependency failure, not a metric result')


if __name__ == '__main__':
    sys.exit(harness.main(run, entry=os.path.abspath(__file__), name='a15', description=__doc__))
