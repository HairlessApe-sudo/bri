#!/usr/bin/env python3
"""Isolated A13 signed-fixture demo. Run from the repository's Python venv."""
import argparse
import asyncio
import json
import os
import re
import select
import shutil
import signal
import socket
import subprocess
import sys
import tarfile
import threading
import time
from contextlib import ExitStack, contextmanager
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import quote
from uuid import UUID, uuid4

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / 'web'
QUESTION = 'How many years must employee files be retained?'
ANSWER = 'Employee files must be retained for seven years.'
CONFLICT = 'Employee files must be retained for ten years.'
UNRELATED = 'What is the swimming pool capacity?'
FOREIGN_ANSWER = 'Employee files must be retained for twelve years.'
UI = 'http://127.0.0.2:3013'
API = 'http://127.0.0.1:8013'
BRIDGE = '/api/bri-local/v1'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def status(response, expected, label):
    require(response.status_code == expected, f'{label}: expected HTTP {expected}, got {response.status_code}')
    return response


def report(text):
    print(text, flush=True)


def stop(process):
    # Child process groups include Next workers/Chromium renderers. The private PID
    # namespace additionally reaps any crash handler that started a new session.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(5)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(5)


def launch(stack, argv, *, stdout, stderr, stdin=subprocess.DEVNULL, cwd=None, env=None):
    process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=stdin, stdout=stdout, stderr=stderr,
                               start_new_session=True)
    stack.callback(stop, process)
    return process


def until(check, label, *, process=None, seconds=60):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError(f'{label}: process exited {process.returncode}')
        value = check()
        if value:
            return value
        time.sleep(0.1)
    raise RuntimeError(f'Timed out: {label}')


@contextmanager
def reader_server(app, *, port=8013):
    import uvicorn

    with socket.socket() as listener:
        listener.bind(('127.0.0.1', port))
        config = uvicorn.Config(app, proxy_headers=False, access_log=False, log_level='error',
                                timeout_graceful_shutdown=5)
        server = uvicorn.Server(config)
        thread = threading.Thread(target=server.run, kwargs={'sockets': [listener]}, daemon=True)
        thread.start()
        try:
            until(lambda: server.started or (not thread.is_alive() and 'failed'), 'Uvicorn startup', seconds=10)
            require(server.started, 'Uvicorn failed to start')
            yield
        finally:
            server.should_exit = True
            thread.join(10)
            require(not thread.is_alive(), 'Uvicorn did not terminate')


def protocol(worker, **message):
    worker.stdin.write(json.dumps(message).encode() + b'\n')
    worker.stdin.flush()
    require(select.select([worker.stdout], [], [], 240)[0], 'Node fixture worker timed out')
    line = worker.stdout.readline()
    require(line, 'Node fixture worker exited before acknowledging the step')
    try:
        reply = json.loads(line)
    except ValueError:
        raise RuntimeError('Fixture worker protocol error') from None
    require('error' not in reply, str(reply.get('error', '')))
    return reply


def chrome_port(profile):
    marker = profile / 'DevToolsActivePort'
    if marker.is_file():
        parts = marker.read_text().splitlines()
        if len(parts) >= 2 and parts[0].isdigit():
            return int(parts[0])
    return None


def start_chromium(args, scratch, stack):
    profile = scratch / 'browser'
    log = stack.enter_context((scratch / 'chromium.log').open('wb'))
    chrome = launch(stack, [args.chromium, '--headless=new', '--no-sandbox', '--disable-dev-shm-usage',
                            '--no-first-run', '--disable-background-networking', '--disable-breakpad',
                            '--no-proxy-server', '--remote-debugging-address=127.0.0.1',
                            '--remote-debugging-port=0', f'--user-data-dir={profile}', 'about:blank'],
                    stdout=log, stderr=log)
    return until(lambda: chrome_port(profile), 'Chromium DevTools startup', process=chrome, seconds=20)


def next_copy(scratch):
    # Compile the exact local workspace and shared components without reading any
    # repo dotenv file or writing generated Next files into another agent's worktree.
    web = scratch / 'web'
    web.mkdir()
    (web / 'node_modules').symlink_to(WEB / 'node_modules', target_is_directory=True)
    for name in ('package.json', 'package-lock.json', 'tsconfig.json'):
        shutil.copy2(WEB / name, web / name)
    shutil.copytree(WEB / 'src', web / 'src', ignore=shutil.ignore_patterns('.env*'))
    shutil.copytree(WEB / 'local-workspace', web / 'local-workspace',
                    ignore=shutil.ignore_patterns('.next', 'node_modules', '*.tsbuildinfo', '.env*'))
    return web


def swc_environment(scratch, archive):
    env = dict(os.environ, NODE_ENV='development', NEXT_TELEMETRY_DISABLED='1', npm_config_offline='true')
    if archive:
        version = json.loads((WEB / 'node_modules/next/package.json').read_text())['version']
        name = 'next-swc.linux-x64-gnu.node'
        require(archive.name == f'swc-linux-x64-gnu-{version}.tgz', 'SWC tarball must match the installed Next version')
        target = scratch / 'swc'
        target.mkdir()
        with tarfile.open(archive, 'r:gz') as tar:
            src = tar.extractfile(f'package/{name}')
            if src is None:
                raise RuntimeError('Cached SWC archive does not contain a Linux binding')
            with src, (target / name).open('wb') as out:
                shutil.copyfileobj(src, out)
        env['NEXT_TEST_NATIVE_DIR'] = str(target)
    return env


def publish(fixture, transport, root, bearer, scopes):
    from bri.api.csv_intake import PREFIX, REVIEW_PREFIX, create_staged_csv_intake_app
    from bri.ingestion.csv_intake import LocalCsvQuarantine, ProcessOutcome, extract_bounded_csv

    root.mkdir(mode=0o700)
    stage = create_staged_csv_intake_app(**scopes, private_socket=fixture.sock, auth_transport=transport,
                                        intake_scope=lambda: fixture.connect('bri_csv_intake'),
                                        worker_scope=lambda: fixture.connect('bri_csv_worker'),
                                        store=LocalCsvQuarantine(root))
    published = []
    with fixture.stage_client(stage) as intake:
        for tenant, actors, answer in ((fixture.tenant, fixture.actors, ANSWER),
                                       (fixture.tenant, fixture.actors, CONFLICT),
                                       (fixture.foreign, fixture.foreign_actors, FOREIGN_ANSWER)):
            original = f'Policy,Evidence\r\nRecords,"Administrative note.\r\n{answer}"\r\n'.encode()
            job = UUID(status(intake.post(PREFIX, headers={**bearer(actors[2]), 'Content-Type': 'text/csv',
                              'X-Node-ID': 'team', 'Idempotency-Key': str(uuid4())}, content=original),
                              202, 'governed intake').json()['id'])
            require(stage.state.csv_worker.dispatch(job) is ProcessOutcome.COMPLETED, 'CSV worker did not complete')
            ref = f'csv:{job}'
            status(intake.post(f'{REVIEW_PREFIX}/{ref}/decision', headers=bearer(actors[0]),
                               json={'decision': 'approved'}), 200, 'governed review')
            with fixture.connect('bri_migrator') as db:
                db.execute("SELECT set_config('bri.tenant_id',%s,true)", (tenant,))
                db.execute('INSERT INTO bri.knowledge_record_access VALUES (%s,%s,true)', (tenant, ref))
                db.execute('INSERT INTO bri.knowledge_version_access VALUES (%s,%s,%s,true)', (tenant, ref, ref))
            published.append(dict(ref=ref, digest=sha256(original).hexdigest(),
                                  extracted=extract_bounded_csv(original).extracted_sha256))
    return published


def run(args, scratch, stack):
    sys.path[:0] = [str(ROOT / 'src'), str(ROOT / 'tests')]
    import httpx
    from bri.api.csv_intake import create_staged_csv_reader_app
    from test_csv_intake_api import StagedCsvPostgres
    from test_authentication import ISSUER

    port = None if args.http_only else start_chromium(args, scratch, stack)

    fixture = StagedCsvPostgres()
    stack.callback(fixture.doClassCleanups)
    fixture.setUpClass()
    fixture.setUp()
    with fixture.connect('postgres') as db:
        require(db.execute("SELECT current_setting('server_version_num'), inet_server_addr(), "
                           "current_setting('listen_addresses')").fetchone() == ('160002', None, ''),
                'Expected disposable Unix-socket-only PostgreSQL 16.2')
    report('PASS PostgreSQL 16.2 private socket; migrations and two restricted fixture tenants ready')
    worker_log = stack.enter_context((scratch / 'fixture-worker.log').open('wb'))
    worker = launch(stack, [args.node, str(ROOT / 'scripts/a13-browser.mjs')], stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, stderr=worker_log)
    assert worker.stdout is not None and worker.stdin is not None
    stack.callback(worker.stdout.close)
    stack.callback(worker.stdin.close)
    auth, allowlist = {}, {}

    def sign_actors(actors, *, cookie=False):
        issued = protocol(worker, step='sign', issuer=ISSUER, httpOnly=cookie and args.http_only,
                          identities=[(str(uid), str(sid)) for _, uid, sid in actors])
        for actor, token in zip(actors, issued['tokens'], strict=True):
            auth[actor] = f'Bearer {token}'
            allowlist[auth[actor]] = str(actor[1])
        return issued.get('cookie', '')

    def bearer(actor):
        return {'Authorization': auth[actor]}

    def verify(request):
        if request.method == 'GET' and str(request.url) == f'{ISSUER}/user':
            if uid := allowlist.get(request.headers.get('Authorization')):
                return httpx.Response(200, json={'id': uid, 'factors': [{'factor_type': 'totp', 'status': 'verified'}]})
        return httpx.Response(401, json={'message': 'invalid fixture identity'})

    transport = httpx.MockTransport(verify)
    def identity_scope():
        return fixture.connect('bri_app')

    sign_actors([team[i] for team in (fixture.actors, fixture.foreign_actors) for i in (0, 2)])
    local, conflict, foreign = publish(fixture, transport, scratch / 'quarantine', bearer,
                                       {'identity_scope': identity_scope})
    # These grant writes invalidate older sessions (including the root reviewer).
    # Finish publishing before seeding the fresh, dedicated reader sessions.
    reader, _, foreign_reader = fixture.seed_readers()
    cookie = sign_actors([reader, foreign_reader], cookie=True)
    headers = {'Cookie': cookie} if args.http_only else {}
    app = create_staged_csv_reader_app(identity_scope=identity_scope, reader_scope=lambda: fixture.connect('bri_csv_reader'),
                                       private_socket=fixture.sock, auth_transport=transport)
    hold_source, source_arrived = threading.Event(), threading.Event()

    async def gated_reader(scope, receive, send):
        # Delay only the actual fresh source revalidation, never fabricate a
        # response. Release to the normal app before the bridge's 8s deadline.
        if hold_source.is_set() and scope['type'] == 'http' and scope['path'] == f"/v1/sources/{local['ref']}":
            source_arrived.set()
            async with asyncio.timeout(6):
                while hold_source.is_set():
                    await asyncio.sleep(0.02)
        await app(scope, receive, send)

    stack.enter_context(reader_server(gated_reader))
    client = stack.enter_context(httpx.Client(trust_env=False, timeout=60))
    search_path = '/knowledge/search'

    def direct_search(actor, wanted_status, wanted_answer=None):
        response = status(client.get(f'{API}/v1{search_path}', params={'q': QUESTION}, headers=bearer(actor)),
                          wanted_status, 'Uvicorn search')
        if wanted_answer:
            data = response.json()
            wanted_ref = local['ref'] if actor == reader else foreign['ref']
            require(data['status'] == 'supported' and data['answer'] == wanted_answer
                    and [row['record_id'] for row in data['citations']] == [wanted_ref], 'Wrong direct evidence')

    direct_search(foreign_reader, 200, FOREIGN_ANSWER)
    status(client.get(f"{API}/v1/sources/{foreign['ref']}", headers=bearer(reader)), 404, 'cross-tenant source')
    report('PASS staged intake/worker/review published three records across two tenants; Uvicorn :8013 enforces tenant-specific evidence')
    web = next_copy(scratch)
    log = stack.enter_context((scratch / 'next.log').open('wb'))
    next_server = launch(stack, [args.node, 'local-workspace/server.mjs'], cwd=web,
                         env=swc_environment(scratch, args.swc_archive), stdout=log, stderr=log)

    def next_ready():
        try:
            response = client.get(f'{UI}{BRIDGE}/knowledge', timeout=1)
        except httpx.TransportError:
            return False
        return response.status_code == 401

    status(client.post('http://127.0.0.1:9013/auth/v1/token?grant_type=password'), 404, 'no HTTP token mint')
    until(next_ready, 'Next loopback bridge readiness (unsigned read must return 401)', process=next_server, seconds=90)
    report('PASS Next 127.0.0.2:3013 rejects missing cookie; JWKS 127.0.0.1:9013 has no network mint route')
    try:
        client.get(f'http://127.0.0.1:3013{BRIDGE}/knowledge', timeout=1)
    except httpx.ConnectError:
        pass
    else:
        raise RuntimeError('The workspace must not listen at the reader/signer host')
    if args.http_only:
        status(client.get(f'{UI}/knowledge'), 200, 'Next knowledge page')
        for q, state, expected_refs in ((UNRELATED, 'insufficient', set()),
                                        (QUESTION, 'conflicting', {local['ref'], conflict['ref']})):
            data = status(client.get(f'{UI}{BRIDGE}{search_path}', params={'q': q}, headers=headers),
                          200, f'signed SSR {state} search').json()
            require(data['status'] == state and data['answer'] is None and
                    {citation['record_id'] for citation in data['citations']} == expected_refs, f'Wrong {state} evidence')
        report('PASS HTTP-only: signed bridge distinguishes insufficient and conflicting results')
    else:
        require(protocol(worker, step='alternatives', port=port, question=QUESTION, unrelated=UNRELATED).get('ok'),
                'Browser answer alternatives or cookie-scope proof missing')
        report('PASS Chromium rendered insufficient/conflicting states; fixture cookie reached only the workspace bridge')
    with fixture.connect('bri_migrator') as db:
        db.execute("SELECT set_config('bri.tenant_id',%s,true)", (fixture.tenant,))
        require(db.execute('UPDATE bri.knowledge_version_access SET readable=false '
                           'WHERE tenant_id=%s AND source_id=%s AND source_version_id=%s',
                           (fixture.tenant, conflict['ref'], conflict['ref'])).rowcount == 1, 'Conflict version gate missing')
    direct_search(reader, 200, ANSWER)
    source_path = f"/sources/{quote(local['ref'], safe='')}"
    if args.http_only:
        status(client.get(f'{UI}/knowledge'), 200, 'Next knowledge page')
        query = status(client.get(f'{UI}{BRIDGE}{search_path}', params={'q': QUESTION}, headers=headers),
                       200, 'signed SSR search').json()
        require(query['answer'] == ANSWER and len(query['citations']) == 1 and query['citations'][0]['record_id'] == local['ref'],
                'Wrong signed bridge answer/citation')
        status(client.get(f'{UI}{source_path}'), 200, 'Next source page')
        source = status(client.get(f'{UI}{BRIDGE}{source_path}', headers=headers), 200, 'signed SSR source').json()
        require(source['original_sha256'] == local['digest'] and source['content_sha256'] == local['extracted']
                and (source['csv_first_line'], source['csv_last_line']) == (1, 3), 'Wrong signed bridge provenance')
        report('PASS HTTP-only: Next pages and signed bridge search/source return 200 with expected answer/citation/provenance')
    else:
        require(protocol(worker, step='before', port=port, question=QUESTION, answer=ANSWER,
                         foreignAnswer=FOREIGN_ANSWER, **local).get('ok'), 'Browser positive proof missing')
        report('PASS Chromium submitted search (200), rendered answer/citation, and followed source link (200) to CSV provenance')

    with fixture.connect('postgres') as db:
        changed = db.execute('UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() '
                             'WHERE session_id=%s AND revoked_at IS NULL', (reader[2],)).rowcount
        require(changed == 1, 'Did not revoke exactly one active native session')
    with fixture.connect('postgres') as db:
        require(db.execute('SELECT revoked_at IS NOT NULL FROM bri.auth_sessions WHERE session_id=%s',
                           (reader[2],)).fetchone() == (True,), 'Committed revocation not visible')
    direct_search(reader, 403)
    direct_search(foreign_reader, 200, FOREIGN_ANSWER)
    report('PASS native session revocation committed and read back; Uvicorn rejects that bearer, foreign reader unaffected')
    if args.http_only:
        for path, params in ((search_path, {'q': QUESTION}), (source_path, None), ('/knowledge', None)):
            denial = status(client.get(f'{UI}{BRIDGE}{path}', params=params, headers=headers), 403, f'fresh signed read {path}')
            require(ANSWER not in denial.text and local['ref'] not in denial.text and local['digest'] not in denial.text,
                    'Denied response leaked evidence')
        report('PASS HTTP-only: same SSR cookie now returns 403 for fresh search, list and source reads')
    else:
        require(protocol(worker, step='after').get('ok'), 'Browser revocation proof missing')
        report('PASS Chromium refresh lost answer, citation and source link (403)')
        hold_source.set()
        try:
            back = protocol(worker, step='back')
            require(back.get('ok') and source_arrived.wait(2), 'Source back navigation did not revalidate through Uvicorn')
            require(protocol(worker, step='back-pending').get('ok'), 'Pending source proof missing')
        finally:
            hold_source.clear()
        require(protocol(worker, step='back-result').get('ok'), 'Browser historical source denial missing')
        mode = 'BFCache restoration' if back['bfcache'] else 'cold history navigation (not BFCache)'
        report(f'PASS Chromium back ({mode}) hid parked provenance during delayed real revalidation and after 403')
    require(protocol(worker, step='stats')['jwksReads'] > 0, 'No JWKS reads observed')


def main(run_demo=run, *, entry=__file__, name='a13', browser_required=False, description=__doc__):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument('--pg-bin', required=True, type=Path, help='offline PostgreSQL 16.2 binary directory')
    parser.add_argument('--swc-archive', type=Path, help='cached matching Linux x64 GNU SWC tarball (WSL override)')
    parser.add_argument('--chromium', default=str(Path.home() / '.hermes/tools/chromium-1248/chrome-linux64/chrome'))
    parser.add_argument('--node', default=shutil.which('node') or 'node', help='Linux Node 26 executable')
    if not browser_required:
        parser.add_argument('--http-only', action='store_true', help='diagnose real HTTP/DB flow without browser (not a Chromium pass)')
    else:
        parser.set_defaults(http_only=False)
    args = parser.parse_args()
    require(not sys.flags.optimize, 'Do not disable Python fixture assertions')
    # The outer invocation resolves authorized local paths before entering the
    # network+PID namespace. Everything after re-exec has a narrow environment.
    if os.getpid() != 1:
        require(os.getuid() != 0, 'Run as a non-root user')
        require(not any(key.startswith('PG') for key in os.environ), 'Unset inherited PG* options')
        tmp = Path(os.environ.get('TMPDIR') or '/tmp').resolve(strict=True)
        env = {key: os.environ[key] for key in ('PATH', 'LD_LIBRARY_PATH') if key in os.environ}
        env.update(TMPDIR=str(tmp), BRI_TEST_PG_BIN=str(args.pg_bin.resolve(strict=True)), LC_ALL='C.UTF-8')
        argv = [sys.executable, '-B', entry, '--pg-bin', env['BRI_TEST_PG_BIN'],
                '--node', str(Path(args.node).resolve(strict=True)), '--chromium', str(Path(args.chromium).resolve())]
        if args.swc_archive:
            argv += ['--swc-archive', str(args.swc_archive.resolve(strict=True))]
        if args.http_only:
            argv += ['--http-only']
        os.execvpe('unshare', ['unshare', '--map-current-user', '--keep-caps', '-npf', '--kill-child',
                               'sh', '-ec', 'ip link set lo up; exec setpriv --bounding-set=-all '
                               '--inh-caps=-all --ambient-caps=-all -- "$@"', f'{name}-demo', *argv], env)
    require(socket.if_nameindex() == [(1, 'lo')], 'The demo requires a loopback-only network namespace')
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    signal.signal(signal.SIGINT, lambda *_: sys.exit(130))
    os.umask(0o077)
    with TemporaryDirectory(prefix=f'{name}-') as temp:
        scratch = Path(temp)
        os.environ.update(HOME=temp, XDG_CONFIG_HOME=temp, XDG_CACHE_HOME=temp)
        try:
            with ExitStack() as stack:
                run_demo(args, scratch, stack)
        except Exception as exc:
            def safe(text):
                return re.sub(r'[\w.%-]{70,}', '[redacted]', str(text))

            print(f'FAIL {type(exc).__name__}: {safe(exc)}', file=sys.stderr)
            # Logs are disposable and never contain the private signing protocol.
            for name in ('chromium.log', 'next.log', 'fixture-worker.log'):
                path = scratch / name
                if path.is_file() and path.stat().st_size:
                    lines = path.read_text(errors='replace').splitlines()[-24:]
                    print(f'{name}:\n' + '\n'.join(safe(line) for line in lines), file=sys.stderr)
            return 1
    report('PASS all fixture processes stopped and temporary state removed')
    return 0


if __name__ == '__main__':
    sys.exit(main())
