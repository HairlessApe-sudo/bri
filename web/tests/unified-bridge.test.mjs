import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import http from 'node:http';
import { syncBuiltinESMExports } from 'node:module';
import { EventEmitter, once } from 'node:events';
import { Readable } from 'node:stream';
import test from 'node:test';
import { composeLocalWorkspace, LOCAL_AUTH_OPTIONS } from '../local-workspace/bridge.mjs';
import { parseScopes, parseSearch } from '../local-workspace/unified-contract.mjs';

const ui = 'http://127.0.0.2:3013';
const prefix = '/api/bri-local/unified';
const contextHeader = 'x-bri-unified-context';
const searchPath = '/v1/knowledge/search';
const scopesPath = `${searchPath}/scopes`;
const record = '5607a17a-61be-4c19-a912-bbfe61d070e3';
const version = 'e50d72bc-5fa2-4891-b69b-c68225911a57';
const csvPath = `/v1/knowledge/csv/${record}/versions/${record}/evidence`;
const xlsxPath = `/v2/knowledge/xlsx/${record}/evidence/${version}`;
const unavailable = { version: 1, status: 'unavailable' };
const scopes = { version: 1, status: 'complete', scopes: [{ scope_node_id: 'fixture.node', display_label: 'Synthetic scope' }] };
const search = { version: 1, status: 'complete', results: [] };
const query = '{"scope_node_id":"fixture.node","query":"Café   policy"}';

class Reply extends EventEmitter {
  headers = {};
  setHeader(name, value) { this.headers[name] = value; }
  writeHead(status, headers) { Object.assign(this.headers, headers); this.status = status; return this; }
  end(body) { this.emit('reply', { status: this.status ?? 200, headers: this.headers, body }); }
}

function cookieFor(token, now) {
  const data = { access_token: token, refresh_token: 'synthetic-refresh', expires_at: now + 600, user: { id: record } };
  return `${LOCAL_AUTH_OPTIONS.cookieName}=base64-${Buffer.from(JSON.stringify(data)).toString('base64url')}`;
}

function signedFixture(t, kid) {
  const old = process.env.NODE_ENV;
  process.env.NODE_ENV = 'development';
  t.after(() => { if (old === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = old; });
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const header = { alg: 'RS256', typ: 'JWT', kid };
  const now = Math.floor(Date.now() / 1000);
  const jwt = (sub = record, key = privateKey) => {
    const claims = { iss: LOCAL_AUTH_OPTIONS.issuer, aud: 'authenticated', sub, session_id: version,
      aal: 'aal2', iat: now, exp: now + 600 };
    const input = [header, claims].map((value) => Buffer.from(JSON.stringify(value)).toString('base64url')).join('.');
    return `${input}.${sign('RSA-SHA256', Buffer.from(input), key).toString('base64url')}`;
  };
  const token = jwt();
  const cookie = cookieFor(token, now);
  const jwks = { keys: [{ ...publicKey.export({ format: 'jwk' }), ...header, use: 'sig' }] };
  return { jwt, token, cookie, now, jwks };
}

test('unified bridge with signed fixture and mocked loopback transport', async (t) => {
  const { jwt, token, cookie, now, jwks } = signedFixture(t, 'unified-bridge-fixture');
  let signerCalls = 0;

  const reads = [];
  const digest = 'e'.repeat(64);
  const csv = { record_id: record, source_version_id: record, first_line: 1, last_line: 2,
    original_sha256: digest, content_sha256: digest };
  const xlsx = { version: 2, record_id: record, source_version_id: version, source_id: version, node_id: 'fixture.node',
    original_sha256: digest, canonical_sha256: digest, extractor_version: 1, canonicalization_version: 1,
    sheet_id: '1', sheet_title: 'Synthetic', cell_range: 'A1', cells: [{ row: 1, column: 1, value: ['text', 'Fixture'] }], next_cursor: null };
  let override;
  const transport = t.mock.method(http, 'request', (destination, options, callback) => {
    const url = new URL(destination);
    const outgoing = new EventEmitter();
    outgoing.destroy = () => {};
    outgoing.end = (payload) => {
      let response;
      let status = 200;
      let type = 'application/json';
      if (url.origin === LOCAL_AUTH_OPTIONS.origin) {
        signerCalls++;
        assert.equal(url.pathname, '/auth/v1/.well-known/jwks.json');
        response = JSON.stringify(jwks);
      } else {
        assert.equal(url.hostname, '127.0.0.1');
        reads.push({ port: Number(url.port), path: url.pathname + url.search,
          method: options.method, headers: options.headers, body: payload?.toString() });
        const body = { [scopesPath]: scopes, [searchPath]: search, [csvPath]: csv, [xlsxPath]: xlsx }[url.pathname];
        response = override?.body ?? JSON.stringify(body);
        status = override?.status ?? status;
        type = override?.type ?? type;
      }
      const upstream = Readable.from([Buffer.from(response)]);
      upstream.statusCode = status;
      upstream.headers = { 'content-type': type, 'cache-control': 'public', location: '/no-redirect',
        'set-cookie': 'upstream=private', [contextHeader]: 'untrusted' };
      callback(upstream);
    };
    return outgoing;
  });
  syncBuiltinESMExports();
  t.after(() => { transport.mock.restore(); syncBuiltinESMExports(); });
  const pages = [];
  const handler = composeLocalWorkspace((req, res) => { pages.push(req.url); res.end('Next page'); });
  async function call(path, headers = {}, method = 'GET', payload) {
    const req = Readable.from(payload === undefined ? [] : [Buffer.from(payload)]);
    req.url = path;
    req.method = method;
    const singles = { host: new URL(ui).host, ...headers };
    req.headersDistinct = Object.fromEntries(Object.entries(singles).map(([key, value]) => [key, [value].flat()]));
    req.rawHeaders = Object.entries(req.headersDistinct).flatMap(([key, values]) => values.flatMap((value) => [key, value]));
    req.headers = Object.fromEntries(Object.entries(req.headersDistinct).map(([key, values]) => [key, values.join(', ')]));
    req.socket = { localAddress: '127.0.0.2', localPort: 3013, remoteAddress: '127.0.0.1' };
    const res = new Reply();
    const result = once(res, 'reply');
    await handler(req, res);
    return (await result)[0];
  }

  let context;
  await t.test('discovery binds an opaque context to a freshly verified cookie', async () => {
    const result = await call(prefix + scopesPath, { cookie, 'x-unrelated': 'strip me', 'user-agent': 'Chromium fixture' });
    assert.equal(result.status, 200);
    assert.deepEqual(JSON.parse(result.body), scopes);
    assert.equal(result.headers['cache-control'], 'private, no-store');
    assert.match(result.headers[contextHeader], /^[0-9a-f]{64}$/);
    context = result.headers[contextHeader];
    assert.equal(result.headers.location, undefined);
    assert.equal(result.headers['set-cookie'], undefined);
    const sent = reads.at(-1);
    assert.equal(sent.port, 8018);
    assert.equal(sent.path, scopesPath);
    assert.equal(sent.method, 'GET');
    assert.equal(sent.headers.authorization, ['Bearer', token].join(' '));
    for (const name of ['cookie', 'x-unrelated', contextHeader]) assert.equal(sent.headers[name], undefined);
    assert.equal(signerCalls, 1);
  });

  const protectedHeaders = () => ({ cookie, [contextHeader]: context });
  const post = (body = query, headers = {}) => call(prefix + searchPath, {
    ...protectedHeaders(), origin: ui, 'content-type': 'application/json',
    'content-length': String(Buffer.byteLength(body)), ...headers,
  }, 'POST', body);

  await t.test('only the intended page is dispatched into Next', async () => {
    assert.equal((await call('/knowledge/search')).body, 'Next page');
    assert.equal((await call('/knowledge/search', {}, 'HEAD')).status, 200);
    for (const path of ['/knowledge/%73earch', '/knowledge/search/', '/knowledge/search/other',
      '/knowledge/search?query=do-not-log']) assert.equal((await call(path)).status, 404, path);
    assert.equal((await call('/knowledge/search', {}, 'POST')).status, 405);
    assert.deepEqual(pages, ['/knowledge/search', '/knowledge/search']);
  });

  await t.test('search and both exact-version evidence operations are pinned to their correct readers', async () => {
    const cursor = 'a'.repeat(64);
    for (const [run, port, path, body, method] of [
      [post, 8018, searchPath, search, 'POST'],
      [() => call(prefix + csvPath, protectedHeaders()), 8018, csvPath, csv, 'GET'],
      [() => call(`${prefix}${xlsxPath}?cursor=${cursor}`, protectedHeaders()), 8117, `${xlsxPath}?cursor=${cursor}`, xlsx, 'GET'],
    ]) {
      const result = await run();
      assert.equal(result.status, 200);
      assert.deepEqual(JSON.parse(result.body), body);
      assert.equal(result.headers['cache-control'], 'private, no-store');
      for (const name of [contextHeader, 'location', 'set-cookie']) assert.equal(result.headers[name], undefined);
      const sent = reads.at(-1);
      assert.deepEqual([sent.port, sent.path, sent.method], [port, path, method]);
      const expectedHeaders = { authorization: ['Bearer', token].join(' '), accept: 'application/json' };
      if (method === 'POST') {
        assert.deepEqual(JSON.parse(sent.body), JSON.parse(query));
        Object.assign(expectedHeaders, { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(sent.body)) });
      }
      assert.deepEqual(sent.headers, expectedHeaders);
    }
  });

  await t.test('XLSX continuation preserves the opaque cursor without admitting a v1 or wrong-version receipt', async () => {
    const cursor = 'f'.repeat(64);
    try {
      override = { body: JSON.stringify({ ...xlsx, cell_range: 'A1:A2', next_cursor: cursor }) };
      const first = await call(prefix + xlsxPath, protectedHeaders());
      assert.equal(first.status, 200);
      assert.equal(JSON.parse(first.body).next_cursor, cursor);
      override.body = JSON.stringify({ ...xlsx, cell_range: 'A1:A2', cells: [{ row: 2, column: 1, value: null }] });
      const second = await call(`${prefix}${xlsxPath}?cursor=${cursor}`, protectedHeaders());
      assert.equal(second.status, 200);
      assert.equal(JSON.parse(second.body).next_cursor, null);
      assert.equal(reads.at(-1).path, `${xlsxPath}?cursor=${cursor}`);
      const { version: _contract, ...notV2 } = xlsx;
      for (const invalid of [notV2, { ...xlsx, source_version_id: record }]) {
        override.body = JSON.stringify(invalid);
        assert.equal((await call(prefix + xlsxPath, protectedHeaders())).status, 502);
      }
    } finally { override = undefined; }
  });

  await t.test('a previous identity context cannot initiate another protected read', async () => {
    const before = reads.length;
    const changed = cookieFor(jwt(version), now);
    const forged = cookieFor(jwt(record, generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey), now);
    assert.equal((await call(prefix + scopesPath)).status, 401);
    assert.equal((await call(prefix + scopesPath, { cookie: forged })).status, 401);
    for (const path of [csvPath, xlsxPath]) {
      const absent = await call(prefix + path, { cookie });
      const stale = await call(prefix + path, { cookie: changed, [contextHeader]: context });
      const validLooking = await call(prefix + path, { cookie, [contextHeader]: '0'.repeat(64) });
      assert.equal(stale.status, 403);
      assert.equal(absent.status, 403);
      assert.equal(stale.headers[contextHeader], undefined);
      assert.equal(stale.body, validLooking.body);
      assert.equal((await call(prefix + path, { [contextHeader]: context })).status, 401);
      assert.equal((await call(prefix + path, { cookie: forged, [contextHeader]: context })).status, 401);
    }
    assert.equal((await post(query, { cookie: changed })).status, 403);
    assert.equal((await post(query, { [contextHeader]: [context, context] })).status, 403);
    assert.equal(reads.length, before);
    const fresh = (await call(prefix + scopesPath, { cookie: changed })).headers[contextHeader];
    assert.match(fresh, /^[0-9a-f]{64}$/);
    assert.notEqual(fresh, context);
    assert.equal((await post(query, { cookie: changed, [contextHeader]: fresh })).status, 200);
    assert.equal((await call(prefix + scopesPath, { cookie })).headers[contextHeader], context);
  });

  await t.test('aliases, invalid methods, claims, and malformed request framing never reach a reader', async () => {
    const before = reads.length;
    const h = protectedHeaders();
    for (const [path, headers, method, status] of [
      [prefix, {}, 'GET', 404],
      [prefix + '/v1/knowledge', {}, 'GET', 404],
      [prefix + scopesPath + '/', {}, 'GET', 404],
      [prefix + scopesPath.replace('/scopes', '/%73copes'), {}, 'GET', 404],
      [prefix.replace('/unified', '/%75nified') + scopesPath, {}, 'GET', 404],
      [prefix + '/v1/knowledge/../knowledge/search/scopes', {}, 'GET', 404],
      [prefix + csvPath.replace(record, record.toUpperCase()), h, 'GET', 404],
      [prefix + xlsxPath.replace(version, '00000000-0000-0000-0000-000000000000'), h, 'GET', 404],
      [prefix + xlsxPath.replace('/v2/', '/v1/'), h, 'GET', 404],
      [prefix + searchPath, h, 'GET', 405],
      [prefix + scopesPath, {}, 'HEAD', 405],
      [prefix + csvPath, h, 'POST', 405],
      [prefix + scopesPath + '?', {}, 'GET', 400],
      [prefix + csvPath + '?cursor=' + '0'.repeat(64), h, 'GET', 400],
      [prefix + xlsxPath + '?limit=1', h, 'GET', 400],
      [prefix + xlsxPath + '?cursor=bad', h, 'GET', 400],
      [prefix + xlsxPath + '?cursor=' + 'A'.repeat(64), h, 'GET', 400],
      [prefix + xlsxPath + '?%63ursor=' + 'a'.repeat(64), h, 'GET', 400],
      [prefix + xlsxPath + '?cursor=' + 'a'.repeat(64) + '&cursor=' + 'a'.repeat(64), h, 'GET', 400],
      [prefix + scopesPath, { origin: 'http://other.invalid' }, 'GET', 403],
      [prefix + scopesPath, { origin: [ui, ui] }, 'GET', 403],
      [prefix + scopesPath, { host: 'localhost:3013' }, 'GET', 403],
      [prefix + scopesPath, { 'x-forwarded-for': '127.0.0.1' }, 'GET', 403],
      [prefix + scopesPath, { 'x-forwarded_for': '127.0.0.1' }, 'GET', 400],
      [prefix + scopesPath, { authorization: 'browser-claimed' }, 'GET', 400],
      [prefix + scopesPath, { x_scope_node_id: 'browser-claimed' }, 'GET', 400],
      [prefix + scopesPath, { 'x-bri-membership': 'browser-claimed' }, 'GET', 400],
      [prefix + scopesPath, { 'x-auth-token': 'browser-claimed' }, 'GET', 400],
      [prefix + scopesPath, { [contextHeader]: context }, 'GET', 400],
      [prefix + csvPath, { ...h, 'content-length': '1' }, 'GET', 400],
      [prefix + csvPath, { ...h, 'content-type': 'application/json' }, 'GET', 400],
      [prefix + csvPath, { ...h, 'transfer-encoding': 'chunked' }, 'GET', 400],
    ]) assert.equal((await call(path, { cookie, ...headers }, method)).status, status, `${method} ${path}`);
    assert.equal((await call(prefix + searchPath, h, 'POST', query)).status, 403);
    assert.equal((await post(query, { 'content-type': 'text/plain' })).status, 415);
    assert.equal((await post(query, { 'content-type': ['application/json', 'application/json'] })).status, 415);
    assert.equal((await post(query, { 'transfer-encoding': 'chunked' })).status, 400);
    assert.equal((await post(query, { 'content-length': '02' })).status, 400);
    assert.equal((await post(query, { 'content-length': '99999999999999999999999999' })).status, 413);
    assert.equal((await post(' '.repeat(4096) + query)).status, 413);
    for (const invalid of ['[]', '{"scope_node_id":"site","query":"q","tenant":"spoof"}',
      '{"scope_node_id":"site","query":"q","qu\\u0065ry":"q"}', '{"scope_node_id":"bad node","query":"q"}',
      '{"scope_node_id":"site","query":"\\ud800"}', '{"scope_node_id":"site","query":"\\u0000"}',
      '{"scope_node_id":"site","query":"   "}', JSON.stringify({ scope_node_id: 'site', query: 'é'.repeat(129) })]) {
      assert.equal((await post(invalid)).status, 400);
    }
    assert.equal(reads.length, before);
    assert.equal((await post(query, { 'content-type': 'application/json; charset=utf-8' })).status, 200);
    assert.equal((await post(query + ' '.repeat(4096 - Buffer.byteLength(query)))).status, 200);
  });

  await t.test('redirects, invalid receipts and response overflow fail closed without upstream diagnostics', async () => {
    const before = reads.length;
    try {
      for (const [bad, code] of [
        [{ status: 302, body: 'private diagnostic' }, 502],
        [{ status: 403, body: 'private diagnostic' }, 403],
        [{ status: 503, body: 'private diagnostic' }, 503],
        [{ type: 'text/html', body: 'private diagnostic' }, 502],
        [{ body: '{' }, 502],
        [{ body: JSON.stringify({ ...scopes, unexpected: 'private diagnostic' }) }, 502],
        [{ body: JSON.stringify(scopes).padEnd(131073) }, 503],
      ]) {
        override = bad;
        const result = await call(prefix + scopesPath, { cookie });
        assert.equal(result.status, code);
        assert.equal(result.headers['cache-control'], code === 503 ? 'private, no-store' : 'no-store');
        if (code === 503) assert.deepEqual(JSON.parse(result.body), unavailable);
        for (const name of ['location', 'set-cookie', contextHeader]) assert.equal(result.headers[name], undefined);
        assert.doesNotMatch(result.body, /private diagnostic/);
      }
      assert.equal(reads.length, before + 7);
      override = { body: JSON.stringify(scopes).padEnd(131072) };
      assert.equal((await call(prefix + scopesPath, { cookie })).status, 200);
      override = { body: JSON.stringify(xlsx).padEnd(524288) };
      assert.equal((await call(prefix + xlsxPath, protectedHeaders())).status, 200);
      override.body += ' ';
      assert.equal((await call(prefix + xlsxPath, protectedHeaders())).status, 503);
    } finally { override = undefined; }
  });
});

async function listen(t, origin, handler) {
  const { hostname, port } = new URL(origin);
  const server = http.createServer(handler);
  server.listen(Number(port), hostname);
  await once(server, 'listening');
  t.after(() => new Promise((resolve) => {
    server.close(resolve);
    server.closeAllConnections();
  }));
}

function callSocket(path, headers, payload) {
  return new Promise((resolve, reject) => {
    const req = http.request(ui, {
      path: prefix + path, method: payload === undefined ? 'GET' : 'POST', headers,
      agent: false, signal: AbortSignal.timeout(10000),
    }, (res) => {
      let body = '';
      res.setEncoding('utf8').on('data', (chunk) => { body += chunk; });
      res.on('error', reject).once('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('error', reject).end(payload);
  });
}

// These listeners share pinned local ports with local-workspace.test.mjs.
// Run with BRI_UNIFIED_SOCKET_TEST=1 and --test-concurrency=1 to exercise both files.
test('unified unavailable envelopes across the real loopback bridge', {
  skip: process.env.BRI_UNIFIED_SOCKET_TEST !== '1' && 'requires exclusive local fixture ports',
}, async (t) => {
  const { jwt, token, cookie, now, jwks } = signedFixture(t, 'unified-bridge-socket-fixture');
  await listen(t, LOCAL_AUTH_OPTIONS.origin, (req, res) => {
    if (req.method !== 'GET' || req.url !== '/auth/v1/.well-known/jwks.json') return res.writeHead(404).end();
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(jwks));
  });
  const reads = [];
  let scenario = 'exact limit';
  await listen(t, 'http://127.0.0.1:8018', (req, res) => {
    let payload = '';
    req.setEncoding('utf8').on('data', (chunk) => { payload += chunk; });
    req.on('end', () => {
      reads.push({ path: req.url, method: req.method, bearer: req.headers.authorization === `Bearer ${token}`, payload });
      if (scenario === 'transport failure') return req.socket.destroy();
      const value = req.url === scopesPath ? scopes : search;
      const status = scenario === 'upstream 503' ? 503 : scenario === 'upstream 403' ? 403 : 200;
      res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'public',
        'set-cookie': 'private=upstream', location: '/private-diagnostic', [contextHeader]: 'untrusted' });
      if (status !== 200) return res.end(JSON.stringify({ ...value, detail: 'private diagnostic' }));
      // No Content-Length: use the real streaming byte counter, with a valid JSON prefix.
      res.write(JSON.stringify(value).padEnd(131072));
      return res.end(scenario === 'one byte over limit' ? ' ' : undefined);
    });
  });
  await listen(t, ui, composeLocalWorkspace((_req, res) => res.writeHead(404).end()));

  const discover = (headers = { cookie }) => callSocket(scopesPath, headers);
  const discovery = await discover();
  assert.equal(discovery.status, 200);
  assert.deepEqual(parseScopes(JSON.parse(discovery.body)), scopes);
  const context = discovery.headers[contextHeader];
  assert.match(context, /^[0-9a-f]{64}$/);
  const post = (overrides) => callSocket(searchPath, {
    cookie, [contextHeader]: context, origin: ui, 'content-type': 'application/json',
    'content-length': String(Buffer.byteLength(query)), ...overrides,
  }, query);
  const searched = await post();
  assert.equal(searched.status, 200);
  assert.deepEqual(parseSearch(JSON.parse(searched.body)), search);

  function checkDenial(result, status, detail = 'Local workspace read unavailable.') {
    assert.equal(result.status, status);
    assert.equal(result.headers['cache-control'], 'no-store');
    assert.equal(result.headers[contextHeader], undefined);
    assert.deepEqual(JSON.parse(result.body), { detail });
  }
  await t.test('session and context denials do not become dependency errors', async () => {
    const before = reads.length;
    const missingSession = 'A current signed fixture session is required.';
    checkDenial(await discover({}), 401, missingSession);
    checkDenial(await post({ cookie: '' }), 401, missingSession);
    checkDenial(await post({ cookie: cookieFor(jwt(version), now) }), 403);
    assert.equal(reads.length, before);
  });

  for (const [path, run, parse, method, payload] of [
    [scopesPath, discover, parseScopes, 'GET', ''], [searchPath, post, parseSearch, 'POST', query],
  ]) {
    for (const failure of ['upstream 503', 'transport failure', 'one byte over limit']) {
      await t.test(`${method} ${path}: ${failure} returns only the versioned unavailable envelope`, async () => {
        scenario = failure;
        const before = reads.length;
        const result = await run();
        assert.deepEqual(reads.slice(before), [{ path, method, bearer: true, payload }]);
        assert.equal(result.status, 503);
        assert.deepEqual(JSON.parse(result.body), unavailable);
        assert.deepEqual(parse(JSON.parse(result.body)), unavailable);
        assert.equal(result.headers['cache-control'], 'private, no-store');
        assert.equal(result.headers['content-type'], 'application/json; charset=utf-8');
        for (const name of ['location', 'set-cookie', contextHeader]) assert.equal(result.headers[name], undefined);
      });
    }
    await t.test(`${method} ${path}: upstream authorization denial remains 403`, async () => {
      scenario = 'upstream 403';
      const before = reads.length;
      checkDenial(await run(), 403);
      assert.deepEqual(reads.slice(before), [{ path, method, bearer: true, payload }]);
    });
  }
});
