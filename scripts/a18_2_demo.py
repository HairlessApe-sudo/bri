#!/usr/bin/env python3
"""Run the signed A18.2 Knowledge Interface matrix in isolated Chromium."""
import asyncio
import json
import os
import re
import subprocess
import sys
import threading
from contextlib import contextmanager
from hashlib import sha256
from uuid import uuid4

import a13_demo as harness
from a13_demo import ROOT, UI, protocol, report, require, status
from a15_consumer import read_inventory

BRIDGE = '/api/bri-local/unified'
SEARCH = '/v1/knowledge/search'
SCOPES = SEARCH + '/scopes'
PAGE = '/knowledge/search'
LITERAL = '<demo-literal>café</demo-literal>'
OLD_QUERY = 'AM5 only in the old session'

# Node's built-in WebSocket keeps the browser runner dependency-free; the same
# A13 private signer and A15 consumer are reused below. The A16.3 recipe's
# restricted, separate governance listener is also used here.
CDP = r'''
import { once } from 'node:events';
import { createInterface } from 'node:readline';
const pending = new Map(), traffic = new Map();
let socket, seq = 0, clock = 0, origin;
const runtimeFailures = Object.create(null);
function note(kind) { runtimeFailures[kind] = (runtimeFailures[kind] ?? 0) + 1; }
async function command(method, params) {
  const id = ++seq;
  const {promise, resolve} = Promise.withResolvers();
  const timeout = setTimeout(() => resolve({error:true}), 10000);
  pending.set(id, resolve);
  try {
    socket.send(JSON.stringify({id, method, params}));
    const reply = await promise;
    if (reply.error) throw Error('CDP command failed: ' + method);
    return reply.result;
  } finally { clearTimeout(timeout); pending.delete(id); }
}
async function run(m) {
  if (m.step === 'attach') {
    origin = m.origin;
    const remote = `127.0.0.1:${m.port}`;
    const res = await fetch(`http://${remote}/json/list`, {redirect:'error',signal:AbortSignal.timeout(5000)});
    const url = new URL((await res.json()).find(p => p.type === 'page').webSocketDebuggerUrl);
    if (url.origin !== `ws://${remote}`) throw Error('Unexpected Chromium debugger origin');
    socket = new WebSocket(url);
    await once(socket,'open',{signal:AbortSignal.timeout(5000)});
    socket.addEventListener('message', ({data}) => {
      const message = JSON.parse(data);
      if (message.id) pending.get(message.id)?.(message);
      const p = message.params;
      if (message.method === 'Runtime.exceptionThrown') {
        const name = p.exceptionDetails?.exception?.className;
        note(['ReferenceError','TypeError','SyntaxError','Error'].includes(name) ? name : 'OtherException');
      }
      if (message.method === 'Network.webSocketFrameError') note('WebSocketError');
      if (message.method === 'Network.webSocketHandshakeResponseReceived') note(`WebSocket${p.response.status}`);
      if (message.method === 'Network.requestWillBeSent') {
        const url = new URL(p.request.url);
        if (url.origin === origin) traffic.set(p.requestId, {ix:++clock, method:p.request.method,
          path:url.pathname, cursor:url.searchParams.get('cursor'), input:p.request.postData, type:p.type});
      }
      const item = traffic.get(p?.requestId);
      if (!item) return;
      if (message.method === 'Network.responseReceived') {
        item.status = p.response.status;
        item.noStore = /(?:^|,\s*)no-store(?:\s*,|$)/i.test(Object.entries(p.response.headers)
          .find(([k]) => k.toLowerCase() === 'cache-control')?.[1] ?? '');
      }
      if (message.method === 'Network.loadingFinished') item.finished = true;
      if (message.method === 'Network.loadingFailed') item.failed = true;
    });
    await command('Network.enable',{maxTotalBufferSize:8388608, maxResourceBufferSize:2097152, maxPostDataSize:4096});
    await command('Network.setCacheDisabled',{cacheDisabled:true});
    await command('Page.enable',{});
    await command('Runtime.enable',{});
  } else if (m.step === 'cookie') {
    const prefix = '/api/bri-local';
    await command('Network.clearBrowserCookies',{});
    const cookies = m.cookie.split('; ').map(pair => {
      const at = pair.indexOf('=');
      if (at <= 0) throw Error('Malformed fixture cookie');
      return {name:pair.slice(0,at),value:pair.slice(at+1),url:`${origin}${prefix}/`,
        path:prefix,httpOnly:true,sameSite:'Lax'};
    });
    await command('Network.setCookies',{cookies});
    const scoped = (await command('Network.getCookies',{urls:[`${origin}${prefix}/unified`]})).cookies;
    const outside = (await command('Network.getCookies',{urls:[`${origin}/knowledge/search`]})).cookies;
    if (scoped.length !== cookies.length || outside.length ||
        !scoped.every(c=>c.httpOnly && c.path===prefix && c.domain===new URL(origin).hostname))
      throw Error('Fixture cookie scope mismatch');
  } else if (m.step === 'eval') {
    const out = await command('Runtime.evaluate',{expression:m.expr,returnByValue:true,awaitPromise:true});
    if (out.exceptionDetails) throw Error('Chromium evaluation failed');
    return {value:out.result.value};
  } else if (m.step === 'page') {
    const result = await command('Page.navigate',{url:origin+m.path});
    if (result.errorText) throw Error('Chromium navigation failed');
  } else if (m.step === 'mark') return {value:clock};
  else if (m.step === 'count') {
    return {value:[...traffic.values()].filter(i=>i.ix>m.mark && i.path===m.path && i.method===m.method).length};
  }
  else if (m.step === 'diagnose') {
    const counts = {};
    for (const item of traffic.values()) {
      if (item.ix <= m.mark) continue;
      const category = item.path === m.path ? 'expected-route' : item.type ?? 'other';
      const key = `${category}/${item.status ?? '-'}/${item.failed ? 'failed' : item.finished ? 'done' : 'pending'}`;
      counts[key] = (counts[key] ?? 0) + 1;
    }
    return {value:{counts,runtimeFailures}};
  }
  else if (m.step === 'receipt') {
    for (const [id,item] of traffic) {
      if (item.ix <= m.mark || item.path !== m.path || item.method !== m.method || item.cursor !== m.cursor) continue;
      const unexpected = item.status !== undefined && item.status !== m.code;
      const ready = m.retired ? item.finished || item.failed : m.body ? item.finished : item.status !== undefined;
      if (!unexpected && !ready) continue;
      const body = m.body && item.finished && !unexpected && (await command('Network.getResponseBody',{requestId:id}));
      return {value:{...item, body:body ? JSON.parse(body.body) : undefined}};
    }
    return {value:null};
  } else throw Error('Unknown Chromium step');
  return {};
}
try {
  for await (const line of createInterface({input:process.stdin})) {
    const reply = await run(JSON.parse(line));
    process.stdout.write(JSON.stringify({ok:true,...reply})+'\n');
  }
} catch (e) {
  // Only fixed diagnostics may leave the private pipe; never echo CDP data.
  const message = /^(?:CDP command failed: [A-Za-z.]+|Unexpected Chromium debugger origin|Malformed fixture cookie|Fixture cookie scope mismatch|Chromium evaluation failed|Chromium navigation failed|Unknown Chromium step)$/.test(e.message)
    ? e.message : 'Chromium runner failed';
  process.stdout.write(JSON.stringify({error:message})+'\n');
  process.exitCode = 1;
} finally { socket?.close(); }
'''


def worker(args, stack, log, *, script=None):
    arg = [str(ROOT / 'scripts' / script)] if script else ['--input-type=module', '-e', CDP]
    child = harness.launch(stack, [args.node, *arg], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log)
    assert child.stdout is not None and child.stdin is not None
    stack.callback(child.stdout.close)
    stack.callback(child.stdin.close)
    return child


def quoted(value):
    return json.dumps(value, ensure_ascii=True)


def wire_query(value):
    return re.sub(r'[A-Z]', lambda letter: letter[0].lower(), re.sub(r'[ \t\r\n\f\v]+', ' ', value).strip(' '))


class Chromium:
    def __init__(self, child, port):
        self.child = child
        self.run('attach', port=port, origin=UI)

    def run(self, step, **kwargs):
        return protocol(self.child, step=step, **kwargs).get('value')

    def dom(self, expression):
        return self.run('eval', expr=expression)

    def expect(self, expression, label):
        harness.until(lambda: self.dom(expression), f'Chromium {label}', seconds=25)

    def mark(self):
        return self.run('mark')

    def no_search(self, mark):
        self.paint()
        require(self.run('count', mark=mark, path=BRIDGE + SEARCH, method='POST') == 0,
                'Scope revalidation dispatched an automatic search')

    def paint(self):
        self.dom('new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(()=>resolve(true))))')

    def receipt(self, mark, path, code, *, method='GET', cursor=None, body=True, retired=False):
        def find():
            return self.run('receipt', mark=mark, path=path, method=method, cursor=cursor, body=body,
                            retired=retired, code=code)
        try:
            receipt = harness.until(find, f'Chromium {method} {path} terminal request', seconds=40)
        except RuntimeError as exc:
            raise RuntimeError(f'{exc}; {self.run("diagnose", mark=mark, path=path)}') from None
        if retired and receipt.get('failed') and 'status' not in receipt:
            return receipt
        require(receipt.get('status') == code and (not path.startswith('/api/') or receipt.get('noStore')),
                f'Chromium {method} {path}: expected no-store HTTP {code}, got {receipt.get("status")}')
        if body and not retired:
            require(receipt.get('finished'), 'Expected completed Chromium response')
        return receipt

    def page(self, path):
        self.run('page', path=path)

    def cookie(self, cookie):
        self.run('cookie', cookie=cookie)

    @staticmethod
    def control(label):
        return ('[...document.querySelectorAll("label")].find(e=>e.textContent.trim()===' + quoted(label) + ')?.control')

    def change(self, label, value):
        control = self.control(label)
        self.expect(f'({control}) && !({control}).disabled', label)
        self.dom(f'''(() => {{const el={control};
          const proto=el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
          Object.getOwnPropertyDescriptor(proto,'value').set.call(el,{quoted(value)});
          el.dispatchEvent(new Event('input',{{bubbles:true}}));
          el.dispatchEvent(new Event('change',{{bubbles:true}}));
        }})()''')
        require(self.dom(f'({control}).value') == value, f'Chromium {label} value not selected')

    def click(self, label, card=None):
        container = 'document' if card is None else f'document.querySelectorAll("#knowledge-results [data-format]")[{card}]'
        self.expect(f'''(() => {{const b=[...({container}?.querySelectorAll('button') ?? [])]
          .find(e=>e.textContent.trim()==={quoted(label)});
          if (!b || b.disabled || !Object.keys(b).some(k=>k.startsWith('__reactProps$'))) return false;
          b.click(); return true;
        }})()''', f'click {label}')

    def state(self, area, value):
        self.expect(f'document.querySelector("#knowledge-{area}")?.dataset.state==={quoted(value)}', f'{area} {value}')

    def scopes(self, expected):
        control = self.control('Organisational scope')
        self.expect(f'''JSON.stringify([...(({control})?.options ?? [])].filter(o=>o.value)
          .map(o=>[o.value,o.textContent.trim()]))===JSON.stringify({quoted(expected)})''', 'exact selectable scopes')

    def cleared(self, *secrets, selection=False):
        control = self.control('Organisational scope')
        wanted = f'!({control})?.value && ' if selection else ''
        self.expect(f'''{wanted}!document.querySelector('#knowledge-results [data-format]') &&
          ![...document.querySelectorAll('#knowledge-evidence button')].some(b=>!b.disabled) &&
          !{quoted(secrets)}.some(s=>document.querySelector('main')?.textContent.includes(s))''', 'visible selection/results/evidence cleared')

    def revalidated_view(self, state, *old_markers, selected='', options=()):
        self.state('scopes', state)
        self.state('search-state', 'initial')
        self.state('evidence', 'initial')
        view = self.dom('''((oldMarkers) => {
          const root=document.querySelector('.unified-workspace');
          const scope=root.querySelector('#unified-scope'), query=root.querySelector('#unified-query');
          return {queryEmpty:query.value==='', oldMarkupAbsent:!oldMarkers.some(s=>root.outerHTML.includes(s) ||
            root.textContent.includes(s) || query.value.includes(s)), selected:scope.value,
            options:[...scope.options].filter(o=>o.value).map(o=>[o.value,o.textContent.trim()]),
            findingsAbsent:!root.querySelector('#knowledge-results,#knowledge-evidence .content-panel,details,.provenance-grid'),
            evidenceEmpty:root.querySelector('#knowledge-evidence').textContent.trim()==='',
            searchDisabled:root.querySelector('button[type="submit"]').disabled,
            inputsDisabled:[query.disabled,scope.disabled]};
        })(%s)''' % quoted(old_markers))
        require(view['queryEmpty'], 'Prior signed identity query remains in the input during revalidation')
        require(view['oldMarkupAbsent'], 'Prior signed workspace marker remains in the DOM')
        require(view['selected'] == selected and view['options'] == list(options),
                'Revalidation exposed a stale selection or scope option')
        require(view['findingsAbsent'] and view['evidenceEmpty'], 'Revalidation exposed results, evidence, errors or details')
        require(view['searchDisabled'] and view['inputsDisabled'] == [state != 'complete'] * 2,
                'Protected search controls do not match the verified scope state')

    def query(self, text):
        self.change('Search query', text)
        mark = self.mark()
        self.click('Search')
        return mark

    def results(self, mark, scope, query, expected, *, code=200, state=None):
        receipt = self.receipt(mark, BRIDGE + SEARCH, code, method='POST', body=code != 403)
        require(json.loads(receipt['input']) == {'scope_node_id': scope, 'query': wire_query(query)},
                'Search did not send the exact scope and normalized literal query')
        self.state('search-state', state or ('complete' if expected else 'empty'))
        if code == 200:
            hits = receipt['body']['results']
            require([(h['format'], h['record_id'], h['match']) for h in hits] == expected,
                    'Wrong exact ordered record identity, format or match in signed browser receipt')
            # Per-card format and public match excerpt are checked in actual DOM order,
            # independent of the response projection's private provenance fields.
            view = [[h['format'], h['excerpt'], h['source_id'],
                     'Exact match' if h['match'] == 'exact' else 'Substring match'] for h in hits]
            self.expect(f'''(() => {{const cards=[...document.querySelectorAll('ol#knowledge-results [data-format]')];
                const want={quoted(view)};
                return cards.length===want.length && cards.every((c,i)=>c.dataset.format===want[i][0] &&
                  want[i].slice(1).every(v=>c.textContent.includes(v)));}})()''', 'ordered result cards and excerpts')
            return hits
        if 'body' in receipt:
            require('results' not in receipt['body'], 'Failure contained partial results')
        self.cleared()
        return []

    def evidence(self, mark, path, code=200, cursor=None):
        answer = self.receipt(mark, BRIDGE + path, code, cursor=cursor, body=code == 200).get('body')
        self.state('evidence', 'complete' if code == 200 else 'denied')
        return answer

    def provenance(self, index, expected):
        selector = f'#knowledge-results [data-format]:nth-child({index + 1}) details'
        self.expect(f'''(() => {{const s=document.querySelector({quoted(selector + ' summary')});
          if (!s || s.textContent.trim()!=='Technical provenance') return false;
          if (!s.parentElement.open) s.click(); return s.parentElement.open;}})()''', 'expand technical provenance')
        self.expect(f'''(() => {{const d=document.querySelector({quoted(selector + '[open]')});
          if (!d) return false;
          const pairs=Object.fromEntries([...d.querySelectorAll('dl div')]
            .map(x=>[x.querySelector('dt').textContent,x.querySelector('dd').textContent]));
          return Object.entries({quoted(expected)}).every(([k,v])=>pairs[k]===v);}})()''', 'exact visible provenance')

    def worksheet(self, section, cells):
        self.expect(f'''(() => {{const s=document.querySelector({quoted(section)});
          if (!s) return false;
          const cells=[...s.querySelectorAll('dl div')].map(d=>[d.querySelector('dt')?.textContent,d.querySelector('dd')?.textContent]);
          return JSON.stringify(cells)===JSON.stringify({quoted(cells)});}})()''', 'exact ordered worksheet coordinates, types and values')


class Latch:
    def __init__(self):
        self.arrived = threading.Event()
        self.release = threading.Event()
        self.finished = threading.Event()
        self.status = None


class Gate:
    """Hold a *computed real* response at ASGI send, not a mocked endpoint."""
    def __init__(self, app):
        self.app = app
        self.latches = {}
        self.lock = threading.Lock()

    @contextmanager
    def hold(self, path):
        latch = Latch()
        with self.lock:
            require(path not in self.latches, 'A response is already armed for this path')
            self.latches[path] = latch
        try:
            yield latch
        finally:
            with self.lock:
                if self.latches.get(path) is latch:
                    del self.latches[path]
            latch.release.set()

    async def __call__(self, scope, receive, send):
        latch = None
        if scope['type'] == 'http':
            with self.lock:
                latch = self.latches.pop(scope['path'], None)
        if latch is None:
            return await self.app(scope, receive, send)

        async def held(message):
            if message['type'] == 'http.response.start':
                latch.status = message['status']
                latch.arrived.set()
                async with asyncio.timeout(15):
                    while not latch.release.is_set():
                        await asyncio.sleep(.01)
            await send(message)

        try:
            await self.app(scope, receive, held)
        finally:
            latch.finished.set()


def run(args, scratch, stack):
    sys.path[:0] = [str(ROOT), str(ROOT / 'src'), str(ROOT / 'tests')]
    import httpx
    from bri.api.csv_intake import create_staged_csv_reader_app
    from bri.api.unified_knowledge import create_staged_unified_knowledge_app
    from bri.api.xlsx_governance import PUBLISHED_PREFIX, create_staged_xlsx_governance_app
    from test_csv_intake_postgres import ISSUER, ORIGINAL, READER
    from test_unified_knowledge_postgres import ROLE, SCOPES as SCOPE_SQL, UnifiedKnowledgePostgresTests

    port = harness.start_chromium(args, scratch, stack)
    fixture = UnifiedKnowledgePostgresTests()
    stack.callback(fixture.doClassCleanups)
    fixture.setUpClass()
    fixture.setUp()
    tenant = fixture.tenant
    with fixture.connect('postgres') as db:
        require(db.execute("SELECT current_setting('server_version_num'),inet_server_addr(),"
                           "current_setting('listen_addresses')").fetchone() == ('160002', None, ''),
                'Expected private socket-only PostgreSQL 16.2')
        db.execute(f'GRANT EXECUTE ON FUNCTION {", ".join(READER)} TO bri_csv_reader')
        db.execute('CREATE ROLE bri_xlsx_reader LOGIN NOINHERIT; CREATE ROLE bri_xlsx_reviewer LOGIN NOINHERIT')
        db.execute('GRANT USAGE ON SCHEMA bri TO bri_xlsx_reader,bri_xlsx_reviewer')
        db.execute('GRANT EXECUTE ON FUNCTION bri.xlsx_published_detail(text,uuid,uuid,uuid,text,uuid), '
                   'bri.xlsx_published_evidence(text,uuid,uuid,uuid,text,uuid,uuid) TO bri_xlsx_reader')
        db.execute("INSERT INTO bri.org_nodes VALUES (%s,'empty-team','team','Empty team','root'),"
                   "(%s,'hidden-team','team','Hidden team','root')", (tenant, tenant))
        db.execute("INSERT INTO bri.app_roles VALUES (%s,'demo-org','Organisation only')", (tenant,))
        db.execute("INSERT INTO bri.role_permissions VALUES (%s,'demo-org','organisation:read')", (tenant,))
        db.execute("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) "
                   "VALUES (%s,%s,'csv','empty-team'),(%s,%s,'demo-org','hidden-team')",
                   (tenant, fixture.actors[0][0], tenant, fixture.actors[0][0]))

    def fresh(identity):
        actor = (*identity[:2], uuid4())
        with fixture.connect('postgres') as db:
            db.execute('INSERT INTO bri.auth_sessions(principal_id,auth_user_id,session_id,started_at) '
                       'VALUES (%s,%s,%s,clock_timestamp())', actor)
        return actor

    fixture.actors[0] = reader = fresh(fixture.actors[0])
    def new_member(authorized):
        p, u = uuid4(), uuid4()
        with fixture.connect('postgres') as db:
            db.execute("INSERT INTO bri.auth_principals VALUES (%s,'active')", (p,))
            db.execute("INSERT INTO bri.auth_identity_links(auth_user_id,principal_id,auth_issuer,auth_subject,"
                       "provider_type,provider_issuer,provider_subject) VALUES (%s,%s,%s,%s,'native',%s,%s)",
                       (u, p, ISSUER, str(u), ISSUER, str(u)))
            db.execute("INSERT INTO bri.auth_tenant_memberships(tenant_id,principal_id,membership_type,status) "
                       "VALUES (%s,%s,'user','active')", (tenant, p))
            if authorized:
                db.execute("INSERT INTO bri.org_nodes VALUES (%s,'b-team','team','Replacement team','root')", (tenant,))
                db.execute("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) "
                           "VALUES (%s,%s,'csv','b-team')", (tenant, p))
        return fresh((p, u))

    empty_actor = new_member(False)
    replacement = new_member(True)

    multiline, extracted = fixture.publish_csv()
    exact, _ = fixture.publish_csv(b'Label\nhead')
    hidden_csv, _ = fixture.publish_csv(b'Label\nhead', allow=False)
    literal, literal_data = fixture.publish_csv(f'Label\n{LITERAL} {OLD_QUERY}'.encode())

    log = stack.enter_context((scratch / 'fixture-worker.log').open('wb'))
    signer = worker(args, stack, log, script='a13-browser.mjs')
    browser = Chromium(worker(args, stack, log), port)
    allowlist = {}

    def sign(actor):
        signed = protocol(signer, step='sign', issuer=ISSUER, httpOnly=True,
                          identities=[(str(actor[1]), str(actor[2]))])
        token, = signed['tokens']
        allowlist[f'Bearer {token}'] = str(actor[1])
        return token, signed['cookie']

    token, cookie = sign(reader)
    _, empty_cookie = sign(empty_actor)
    _, replacement_cookie = sign(replacement)
    require(replacement_cookie != cookie, 'Replacement must use a different signed browser cookie')

    def provider(request):
        if request.method == 'GET' and str(request.url) == f'{ISSUER}/user':
            if user := allowlist.get(request.headers.get('Authorization')):
                return httpx.Response(200, json={'id': user, 'factors': [{'factor_type': 'totp', 'status': 'verified'}]})
        return httpx.Response(401, json={'message': 'invalid fixture identity'})

    def scope(role):
        return lambda: fixture.connect(role)

    identity_scope = scope('bri_app')
    transport = httpx.MockTransport(provider)
    gated = Gate(create_staged_unified_knowledge_app(reader_scope=scope(ROLE), identity_scope=identity_scope,
                                                     private_socket=fixture.sock, auth_transport=transport))
    stack.enter_context(harness.reader_server(gated, port=8018))
    csv_reader = create_staged_csv_reader_app(reader_scope=scope('bri_csv_reader'), identity_scope=identity_scope,
                                              private_socket=fixture.sock, auth_transport=transport)
    stack.enter_context(harness.reader_server(csv_reader))
    governance = create_staged_xlsx_governance_app(reader_scope=scope('bri_xlsx_reader'),
                                                   review_scope=scope('bri_xlsx_reviewer'), identity_scope=identity_scope,
                                                   private_socket=fixture.sock, auth_transport=transport)
    stack.enter_context(harness.reader_server(governance, port=8117))
    client = stack.enter_context(httpx.Client(trust_env=False, timeout=12))
    headers = {'Authorization': f'Bearer {token}'}

    def legacy():
        ref = f'csv:{exact}'
        paths = ['/v1/knowledge', '/v1/knowledge/search', f'/v1/knowledge/{ref}', f'/v1/sources/{ref}']
        a13 = [status(client.get(harness.API + path, headers=headers, params={'q': 'head'} if i == 1 else None),
                      200, 'A13 compatibility').json() for i, path in enumerate(paths)]
        code, a15 = read_inventory(bearer=token, scope_node_id='team')
        require(code == 200 and a15['result']['count'] == 3, 'Expected exact A15 positive CSV baseline')
        require({r['record_id'] for r in a13[0]} == {e['record_id'] for e in a15['result']['evidence']},
                'A13 and A15 fixture inventory differed')
        return a13, a15

    before = legacy()
    xlsx = fixture.seed_xlsx(2)
    hidden_xlsx, = fixture.seed_xlsx(allowed=False)
    record, version = xlsx[0]
    xlsx_path = f'/v2/knowledge/xlsx/{record}/evidence/{version}'
    legacy_xlsx_path = f'{PUBLISHED_PREFIX}/{record}/evidence/{version}'
    csv_path = f'/v1/knowledge/csv/{multiline}/versions/{multiline}/evidence'
    original, canonical = fixture.xlsx_original_digest, fixture.xlsx_fixture_digest
    gov_url = 'http://127.0.0.1:8117'
    sheet_v1 = status(client.get(gov_url + legacy_xlsx_path, headers=headers), 200, 'A16 v1 baseline').json()
    require(sheet_v1['source_version_id'] == str(version) and
            {'row': 2, 'column': 1, 'value': ['text', 'head']} in sheet_v1['cells'], 'Wrong A16 v1 baseline')
    report('Preflight: Chromium CDP, signed A13/A15 and A16 v1 baselines, restricted listeners, private PostgreSQL 16.2')

    web = harness.next_copy(scratch)
    next_log = stack.enter_context((scratch / 'next.log').open('wb'))
    server = harness.launch(stack, [args.node, 'local-workspace/server.mjs'], cwd=web,
                            env=harness.swc_environment(scratch, args.swc_archive), stdout=next_log, stderr=next_log)

    def ready():
        try:
            return client.get(UI + harness.BRIDGE + '/knowledge', timeout=1).status_code == 401
        except httpx.TransportError:
            return False

    harness.until(ready, 'Next unsigned legacy bridge 401', process=server, seconds=90)
    browser.cookie(cookie)
    mark = browser.mark()
    browser.page(PAGE)
    browser.receipt(mark, PAGE, 200, body=False)
    browser.expect('[...document.querySelectorAll("h1")].some(e=>e.textContent.trim()==="Knowledge Interface")', 'Knowledge Interface heading')
    first_discovery = browser.receipt(mark, BRIDGE + SCOPES, 200)['body']
    browser.state('scopes', 'complete')
    browser.state('search-state', 'initial')
    scopes = [['empty-team', 'Empty team — empty-team'], ['team', 'Team — team']]
    require(first_discovery == {'version': 1, 'status': 'complete', 'scopes': [
        {'scope_node_id': 'empty-team', 'display_label': 'Empty team'},
        {'scope_node_id': 'team', 'display_label': 'Team'},
    ]}, 'Discovery did not return exactly the two authorized nodes')
    browser.scopes(scopes)
    browser.cleared(selection=True)
    status(client.get(UI + BRIDGE + SCOPES), 401, 'unsigned unified discovery bridge')

    def select(node):
        browser.change('Organisational scope', node)

    def search(query, expected, node='team', **kwargs):
        return browser.results(browser.query(query), node, query, expected, **kwargs)

    def view(index, path, code=200):
        mark = browser.mark()
        browser.click('View evidence', index)
        return browser.evidence(mark, path, code)

    def refresh(code, state, signed_cookie=None):
        if signed_cookie:
            browser.cookie(signed_cookie)
        mark = browser.mark()
        browser.click('Refresh scopes')
        answer = browser.receipt(mark, BRIDGE + SCOPES, code, body=code == 200).get('body')
        browser.state('scopes', state)
        return answer

    select('empty-team')
    search('head', [], node='empty-team')
    select('team')
    csv_hits = [('csv', str(exact), 'exact'), ('csv', str(multiline), 'substring')]
    xlsx_hits = [('xlsx', str(row), 'exact') for row, _ in xlsx]
    mixed = [csv_hits[0], *xlsx_hits, csv_hits[1]]
    results = search(' HeAD ', mixed)
    require(search('head', mixed) == results and all(str(i) not in json.dumps(results)
            for i in (hidden_csv, *hidden_xlsx)), 'Normalization or hidden exclusion changed the receipt')
    search('no synthetic match', [])
    search('café', [('csv', str(literal), 'substring')])
    browser.expect(f'document.querySelector("#knowledge-results").textContent.includes({quoted(LITERAL)}) && '
                   '!document.querySelector("demo-literal")', 'synthetic markup rendered as literal text')
    report('PASS discovery, inaccessible nodes absent, eligible empty node, mixed exact-first ranked results, hidden exclusion, zero and inert markup')

    bar = [('csv', str(multiline), 'substring')]
    hits = search('bar', bar)
    require(hits[0]['evidence'] == {'first_line': 3, 'last_line': 5}, 'Wrong multiline matched coordinates')
    csv = view(0, csv_path)
    require(csv == {'record_id': str(multiline), 'source_version_id': str(multiline), 'first_line': 1,
                    'last_line': 6, 'original_sha256': ORIGINAL, 'content_sha256': extracted.extracted_sha256},
            'Wrong exact CSV evidence receipt')
    browser.expect(r'/3\s*[–—-]\s*5/.test(document.querySelector("#knowledge-results").textContent) && '
                   r'/1\s*[–—-]\s*6/.test(document.querySelector("#knowledge-evidence").textContent)',
                   'matched and full CSV physical line ranges')
    browser.provenance(0, {'Record ID': str(multiline), 'Exact source version ID': str(multiline),
                           'Original SHA-256': ORIGINAL, 'Content SHA-256': extracted.extracted_sha256})
    select('empty-team')
    browser.state('search-state', 'initial')
    browser.cleared(str(multiline), extracted.extracted_sha256)
    select('team')
    search('head', mixed)
    xlsx_v2 = view(1, xlsx_path)
    require(xlsx_v2 == sheet_v1 | {'version': 2, 'source_id': str(version), 'original_sha256': original,
                                    'canonical_sha256': canonical, 'extractor_version': 1,
                                    'canonicalization_version': 1}, 'A16 v2 sheet and provenance mismatch')
    worksheet = [['A1 · text', 'Not exact'], ['B1 · text', 'Label'], ['A2 · text', 'head'], ['B2 · text', '%'],
                 ['A3 · number', '7e0'], ['B3 · boolean', 'true'], ['A4 · date', '2026-11-27'],
                 ['B4 · time', '17:22:33'], ['A5 · datetime', '2026-12-01T10:41:02'], ['B5 · blank', ''],
                 ['A6 · blank', ''], ['B6 · boolean', 'false']]
    browser.expect('''(() => { const t=document.querySelector('#knowledge-evidence').textContent;
      return ['Synthetic','A1:B6','Matched worksheet cell: A2'].every(x=>t.includes(x)); })()''', 'matched XLSX worksheet')
    browser.worksheet('#knowledge-evidence [aria-label="Worksheet evidence"]', worksheet)
    browser.provenance(1, {'Record ID': str(record), 'Exact source version ID': str(version),
                           'Original SHA-256': original, 'Canonical SHA-256': canonical,
                           'Extractor version': '1', 'Canonicalization version': '1', 'Worksheet ID': '1'})
    report('PASS CSV multiline match and full evidence bounds, separate XLSX v2 worksheet, exact-version provenance, and scope-change clearing')

    # Hold a successful response after permission/database evaluation. Change the
    # scope and obtain a different result before releasing the genuine old body.
    with gated.hold(SEARCH) as held_search:
        stale = browser.query('head')
        require(held_search.arrived.wait(3) and held_search.status == 200, 'Expected successful old result withheld by ASGI')
        browser.state('search-state', 'loading')
        select('empty-team')
        search('head', [], node='empty-team')
    require(held_search.finished.wait(3), 'Withheld real response did not terminate')
    old = browser.receipt(stale, BRIDGE + SEARCH, 200, method='POST', retired=True)
    require(json.loads(old['input']) == {'scope_node_id': 'team', 'query': 'head'}, 'Wrong request was delayed')
    if old.get('finished'):
        require(len(old['body']['results']) == len(mixed), 'Delayed upstream response was not the original result')
    browser.paint()
    browser.state('search-state', 'empty')
    browser.cleared(str(record), str(multiline), canonical)

    # Swapping the cookie without discovery cannot reuse the old opaque context.
    select('team')
    search('bar', bar)
    view(0, csv_path)
    browser.cookie(empty_cookie)
    view(0, csv_path, 403)
    browser.cleared(str(multiline), extracted.extracted_sha256, selection=True)
    refresh(200, 'complete', cookie)

    select('team')
    literal_hit = [('csv', str(literal), 'substring')]
    literal_path = f'/v1/knowledge/csv/{literal}/versions/{literal}/evidence'
    old_findings = (OLD_QUERY, wire_query(OLD_QUERY), str(literal), literal_data.extracted_sha256)
    old_workspace = (*old_findings, 'Empty team — empty-team', 'Team — team')

    search(OLD_QUERY, literal_hit)
    view(0, literal_path)
    browser.provenance(0, {'Content SHA-256': literal_data.extracted_sha256})
    with gated.hold(SCOPES) as same_cookie:
        mark = browser.mark()
        browser.click('Refresh scopes')
        require(same_cookie.arrived.wait(3) and same_cookie.status == 200, 'Expected a held same-cookie discovery')
        browser.revalidated_view('loading', *old_workspace)
        browser.no_search(mark)
    require(same_cookie.finished.wait(3), 'Same-cookie discovery did not terminate')
    browser.receipt(mark, BRIDGE + SCOPES, 200)
    browser.revalidated_view('complete', *old_findings, selected='team', options=scopes)
    browser.no_search(mark)
    report('PASS same-cookie revalidation clears the pending workspace and restores only the exact eligible selection')

    # Keep A's genuine successful search and B's genuine discovery behind independent latches.
    with gated.hold(SEARCH) as old_search, gated.hold(SCOPES) as new_scopes:
        stale = browser.query(OLD_QUERY)
        require(old_search.arrived.wait(3) and old_search.status == 200, 'Expected a held signed search from A')
        browser.state('search-state', 'loading')
        browser.cookie(replacement_cookie)
        mark = browser.mark()
        browser.click('Refresh scopes')
        require(new_scopes.arrived.wait(3) and new_scopes.status == 200, 'Expected a held successful discovery from B')
        browser.revalidated_view('loading', *old_workspace)
        old_search.release.set()
        require(old_search.finished.wait(3), 'Held search from A did not terminate')
        old = browser.receipt(stale, BRIDGE + SEARCH, 200, method='POST', retired=True)
        require(json.loads(old['input']) == {'scope_node_id': 'team', 'query': wire_query(OLD_QUERY)},
                'Wrong signed search was held during replacement')
        if old.get('finished'):
            require([(h['format'], h['record_id'], h['match']) for h in old['body']['results']] == literal_hit,
                    'Delayed signed response from A was not the original result')
        browser.no_search(mark)
        require(not new_scopes.finished.is_set(), 'Discovery from B terminated before the held-search assertion')
        browser.revalidated_view('loading', *old_workspace)
    require(new_scopes.finished.wait(3), 'Held discovery from B did not terminate')
    require(browser.receipt(mark, BRIDGE + SCOPES, 200)['body'] == {'version': 1, 'status': 'complete', 'scopes': [
        {'scope_node_id': 'b-team', 'display_label': 'Replacement team'},
    ]}, 'Replacement did not discover only its separately authorized scope')
    browser.revalidated_view('complete', *old_workspace, options=[['b-team', 'Replacement team — b-team']])
    browser.no_search(mark)
    report('PASS replacement redacts A while B is pending; released A cannot republish; only B scopes return without automatic search')

    require(refresh(200, 'empty', empty_cookie) == {'version': 1, 'status': 'complete', 'scopes': []},
            'Identity without knowledge grants had scopes or the wrong receipt')
    browser.revalidated_view('empty', *old_workspace, 'Replacement team — b-team')
    refresh(200, 'complete', cookie)
    browser.scopes(scopes)
    report('PASS delayed success suppressed after scope change; same-page identity switch clears scope, result and evidence; empty discovery')

    select('team')
    search(OLD_QUERY, literal_hit)
    view(0, literal_path)
    browser.provenance(0, {'Content SHA-256': literal_data.extracted_sha256})
    with fixture.connect('bri_migrator') as db:
        db.execute(f'REVOKE EXECUTE ON FUNCTION {SCOPE_SQL} FROM {ROLE}')
    try:
        browser.cookie(replacement_cookie)
        with gated.hold(SCOPES) as failed_scopes:
            mark = browser.mark()
            browser.click('Refresh scopes')
            require(failed_scopes.arrived.wait(3) and failed_scopes.status == 503, 'Expected a held failed replacement discovery')
            browser.revalidated_view('loading', *old_workspace)
            browser.no_search(mark)
        require(failed_scopes.finished.wait(3), 'Failed replacement discovery did not terminate')
        browser.receipt(mark, BRIDGE + SCOPES, 503, body=False)
        browser.revalidated_view('unavailable', *old_workspace, 'Replacement team — b-team')
        browser.no_search(mark)
        unavailable = status(client.get(UI + BRIDGE + SCOPES, headers={'Cookie': replacement_cookie}),
                             503, 'discovery failure envelope')
        require('scopes' not in unavailable.json(), 'Discovery failure disclosed partial scopes')
    finally:
        with fixture.connect('bri_migrator') as db:
            db.execute(f'GRANT EXECUTE ON FUNCTION {SCOPE_SQL} TO {ROLE}')
    refresh(200, 'complete', cookie)
    browser.revalidated_view('complete', *old_findings, options=scopes)
    report('PASS failed replacement discovery redacts pending and unavailable views; explicit refresh recovers without stale selection')

    def csv_allow(gate, allowed):
        for job in (exact, multiline, literal):
            with fixture.connect('bri_migrator') as db:
                db.execute("SELECT set_config('bri.tenant_id',%s,true)", (tenant,))
                require(db.execute(f'UPDATE bri.knowledge_{gate}_access SET readable=%s '
                                   'WHERE (tenant_id,source_id)=(%s,%s)',
                                   (allowed, tenant, f'csv:{job}')).rowcount == 1, 'Missing fixture CSV access row')

    def xlsx_allow(gate, allowed):
        with fixture.connect('postgres') as db:
            for r, v in xlsx:
                keys = (tenant, r, reader[0]) if gate == 'record' else (tenant, r, v, reader[0])
                if allowed:
                    db.execute(f'INSERT INTO bri.xlsx_{gate}_access VALUES ({",".join(["%s"] * len(keys))})', keys)
                else:
                    where = ('tenant_id,record_id,principal_id' if gate == 'record'
                             else 'tenant_id,record_id,job_id,principal_id')
                    require(db.execute(f'DELETE FROM bri.xlsx_{gate}_access WHERE '
                                       f'({where})=({",".join(["%s"] * len(keys))})', keys).rowcount == 1,
                            'Missing fixture XLSX access row')

    select('team')
    for gate in ('record', 'version'):
        search('bar', bar)
        view(0, csv_path)
        csv_allow(gate, False)
        view(0, csv_path, 404)
        browser.cleared(str(multiline), extracted.extracted_sha256, selection=True)
        refresh(200, 'complete')
        select('team')
        search('head', xlsx_hits)
        csv_allow(gate, True)
        search('head', mixed)
        view(1, xlsx_path)
        xlsx_allow(gate, False)
        view(1, xlsx_path, 404)
        browser.cleared(str(version), canonical, selection=True)
        refresh(200, 'complete')
        select('team')
        search('head', csv_hits)
        xlsx_allow(gate, True)
    require(legacy() == before, 'A13/A15 changed after unified reads or XLSX publication')
    require(status(client.get(gov_url + legacy_xlsx_path, headers=headers), 200, 'A16 v1 parity').json() == sheet_v1,
            'A16 v1 changed after unified v2 reads')
    mark = browser.mark()
    browser.page(f'/xlsx/knowledge/{record}/evidence/{version}')
    browser.receipt(mark, harness.BRIDGE + legacy_xlsx_path.removeprefix('/v1'), 200)
    browser.worksheet('[aria-label="Worksheet evidence"]', worksheet)
    report('PASS independent record and version revocation of both formats; CSV-only and XLSX-only; A13/A15 receipts and A16 v1 unchanged')

    mark = browser.mark()
    browser.page(PAGE)
    browser.receipt(mark, BRIDGE + SCOPES, 200)
    browser.state('scopes', 'complete')
    select('team')

    # The search stress fixture has repeated headers and is not a valid
    # worksheet receipt. Seed a valid canonical 51-row sheet for pagination.
    dense, dense_version = uuid4(), uuid4()
    job_actor, job_subject, job_session = fixture.actors[2]
    sheet_range = 'A1:A51'
    canonical_page = json.dumps({'rows': [[['text', 'Column']]] + [[['text', 'not the search term']]] * 50,
        'version': 1, 'worksheet': {'identity': '1', 'range': sheet_range, 'title': 'Paged synthetic'}},
        separators=(',', ':'), sort_keys=True)
    from bri.ingestion.xlsx_strict import _canonical_metadata
    _canonical_metadata(canonical_page.encode())
    page_digest = sha256(canonical_page.encode()).hexdigest()
    creator = fixture.actors[1][0]
    with fixture.connect('postgres') as db:
        db.execute('''INSERT INTO bri.xlsx_jobs(tenant_id,job_id,scope_node_id,actor_id,creator_id,auth_user_id,
            session_id,issuer,request_key,original_sha256,byte_count,state,attempt)
            VALUES (%s,%s,'team',%s,%s,%s,%s,%s,%s,%s,100,'proposed',1)''',
            (tenant,dense_version,job_actor,creator,job_subject,job_session,ISSUER,uuid4(),original))
        db.execute("INSERT INTO bri.xlsx_sources VALUES (%s,%s,'team',%s)", (tenant,dense_version,creator))
        db.execute("INSERT INTO bri.xlsx_source_versions VALUES (%s,%s,%s,%s,'1','Paged synthetic',%s)",
                   (tenant,dense_version,original,page_digest,sheet_range))
        db.execute('INSERT INTO bri.xlsx_extractions VALUES (%s,%s,%s,%s,1,1)',
                   (tenant,dense_version,canonical_page,page_digest))
        db.execute('INSERT INTO bri.xlsx_pending_proposals(tenant_id,job_id) VALUES (%s,%s)', (tenant,dense_version))
        db.execute("INSERT INTO bri.xlsx_review_decisions(tenant_id,job_id,actor_id,request_id,decision) VALUES (%s,%s,%s,%s,'approve')",
                   (tenant,dense_version,reader[0],uuid4()))
        db.execute('INSERT INTO bri.xlsx_validated_knowledge(tenant_id,record_id,job_id) VALUES (%s,%s,%s)',
                   (tenant,dense,dense_version))
        db.execute("INSERT INTO bri.xlsx_publication_events(tenant_id,record_id,job_id,revision,action,actor_id) VALUES (%s,%s,%s,1,'publish',%s)",
                   (tenant,dense,dense_version,reader[0]))
        db.execute('INSERT INTO bri.xlsx_record_access VALUES (%s,%s,%s)', (tenant,dense,reader[0]))
        db.execute('INSERT INTO bri.xlsx_version_access VALUES (%s,%s,%s,%s)', (tenant,dense,dense_version,reader[0]))
    dense_path = f'/v2/knowledge/xlsx/{dense}/evidence/{dense_version}'
    search('not the search term', [('xlsx', str(dense), 'exact')])
    first = view(0, dense_path)
    cursor = first['next_cursor']
    require(cursor and first['cells'][0]['row'] == 1, 'Expected genuine paginated first worksheet page')
    mark = browser.mark()
    browser.click('Next evidence page')
    second = browser.evidence(mark, dense_path, cursor=cursor)
    require(second['cells'][0]['row'] > 1 and second['source_version_id'] == str(dense_version),
            'Second evidence page did not advance within the same version')
    browser.expect(f'document.querySelector("#knowledge-evidence").textContent.includes({quoted("A" + str(second["cells"][0]["row"]))})',
                   'second page coordinates rendered')

    # Fixture overflow is a real protected SQL failure; do not stub the response.
    overflow = fixture.seed_xlsx(999)
    search('head', [], code=503, state='unavailable')
    with fixture.connect('postgres') as db:
        require(db.execute('DELETE FROM bri.xlsx_version_access WHERE tenant_id=%s AND principal_id=%s '
                           'AND record_id=ANY(%s)', (tenant, reader[0], [r for r, _ in overflow])).rowcount == 999,
                'Expected to exclude exactly the synthetic overflow batch')
    search('head', mixed)
    view(1, xlsx_path)
    report('PASS signed XLSX v2 cursor follow-through and protected search overflow without partial cards')

    # Keep the previously selected team in the same page while revoking exactly
    # that node. This write can invalidate the old session; fresh identity uses
    # the same actor and preserves the separate, eligible empty-team grant.
    with fixture.connect('postgres') as db:
        require(db.execute("UPDATE bri.auth_role_assignments SET status='revoked' WHERE "
                           "(tenant_id,principal_id,role_id,scope_node_id)=(%s,%s,'csv','team')",
                           (tenant, reader[0])).rowcount == 1, 'Expected one exact team grant revoked')
    new_reader = fresh(reader)
    new_token, new_cookie = sign(new_reader)
    denial = status(client.post('http://127.0.0.1:8018' + SEARCH, json={'scope_node_id': 'team', 'query': 'head'},
                                headers={'Authorization': f'Bearer {new_token}'}), 403, 'revoked exact node positive control')
    require('results' not in denial.json(), 'Revoked scope leaked results')
    refresh(200, 'complete', new_cookie)
    browser.scopes([scopes[0]])
    browser.cleared(str(record), str(multiline), str(dense), selection=True)
    select('empty-team')
    search('head', [], node='empty-team')
    with fixture.connect('postgres') as db:
        require(db.execute('UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() '
                           'WHERE session_id=%s AND revoked_at IS NULL', (new_reader[2],)).rowcount == 1,
                'Expected a committed native-session revocation')
    search('head', [], node='empty-team', code=403, state='denied')
    refresh(403, 'denied')
    browser.scopes([])
    browser.cleared(selection=True)
    report('PASS exact node revocation, refresh removes selection/results, unaffected empty node, and live signed session revocation')
    require(protocol(signer, step='stats')['jwksReads'] > 0, 'No signed JWKS verification was observed')
    report('PASS A18.2 signed Chromium demonstration complete')


if __name__ == '__main__':
    sys.exit(harness.main(run, entry=os.path.abspath(__file__), name='a18-2', browser_required=True,
                          description=__doc__))
