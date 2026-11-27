import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { generateKeyPairSync, sign } from 'node:crypto';
import { createServerClient, serializeCookieHeader } from '@supabase/ssr';
import test from 'node:test';

const ui = 'http://127.0.0.2:3013';
const api = 'http://127.0.0.1:8013';
const auth = 'http://127.0.0.1:9013';
const prefix = '/api/bri-local/v1';
const id = 'csv:01234567-89ab-4def-8123-456789abcdef';
const uid = '34567890-1234-4234-8234-123456789abc';
const sid = '45678901-2345-4234-8234-012345678abc';
const cookieName = 'sb-bri-local-auth-token';
const issuer = 'https://bwqdyibvuecgthtatrtv.supabase.co/auth/v1'; // Claim only, never a network destination.

async function listen(t, origin, handler) {
  const server = createServer(handler);
  const url = new URL(origin);
  await new Promise((resolve, reject) => server.once('error', reject).listen(+url.port, url.hostname, resolve));
  t.after(() => { server.closeAllConnections(); return new Promise((resolve) => server.close(resolve)); });
}

function get(path, headers = {}, method = 'GET', localAddress = '127.0.0.1', payload) {
  return new Promise((resolve, reject) => {
    const req = request(ui, { path, headers, method, localAddress }, (res) => {
      let body = '';
      res.setEncoding('utf8').on('data', (chunk) => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('error', reject).end(payload);
  });
}

function jwt(key, header, claims) {
  const encode = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
  const input = `${encode(header)}.${encode(claims)}`;
  return `${input}.${sign('RSA-SHA256', Buffer.from(input), key).toString('base64url')}`;
}

test('private HTTP bridge uses a verified SSR cookie and preserves backend decisions', async (t) => {
  const old = process.env.NODE_ENV;
  process.env.NODE_ENV = 'development';
  t.after(() => { if (old === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = old; });
  const { composeLocalWorkspace, LOCAL_AUTH_OPTIONS } = await import('../local-workspace/bridge.mjs');
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const { privateKey: wrongKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const header = { alg: 'RS256', typ: 'JWT', kid: 'bri-local-test' };
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: issuer, aud: 'authenticated', role: 'authenticated', sub: uid, session_id: sid,
    aal: 'aal2', iat: now, exp: now + 600, amr: [{ method: 'totp', timestamp: now }],
  };
  const token = jwt(privateKey, header, claims);
  let signinToken = token;
  let providerReads = 0;
  await listen(t, auth, (req, res) => {
    providerReads++;
    res.setHeader('content-type', 'application/json');
    if (req.url === '/auth/v1/.well-known/jwks.json') return res.end(JSON.stringify({ keys: [{ ...publicKey.export({ format: 'jwk' }), ...header, use: 'sig' }] }));
    if (req.url === '/auth/v1/token?grant_type=password' && req.method === 'POST') {
      req.resume();
      return res.end(JSON.stringify({ access_token: signinToken, refresh_token: 'fixture-refresh', token_type: 'bearer', expires_in: 600, user: { id: uid, aud: 'authenticated' } }));
    }
    res.statusCode = 404;
    res.end('{}');
  });
  const makeCookie = async (accessToken) => {
    signinToken = accessToken;
    const cookies = [];
    const client = createServerClient(auth, LOCAL_AUTH_OPTIONS.key, {
      cookieOptions: { name: cookieName, path: LOCAL_AUTH_OPTIONS.cookiePath, httpOnly: true, sameSite: 'lax' },
      cookies: { getAll: () => [], setAll: (batch) => cookies.push(...batch) },
    });
    const { error } = await client.auth.signInWithPassword({ email: 'local@example.test', password: 'fixture-only' });
    assert.equal(error, null);
    const activeCookies = cookies.filter(({ value }) => value);
    assert.ok(activeCookies.length);
    for (const { options } of activeCookies) {
      assert.equal(options.path, '/api/bri-local');
      assert.equal(options.httpOnly, true);
      assert.equal(options.sameSite, 'lax');
      assert.equal(options.domain, undefined);
    }
    return activeCookies.map(({ name, value }) => serializeCookieHeader(name, value).split(';')[0]).join('; ');
  };
  const cookie = await makeCookie(token);
  const forgedCookie = await makeCookie(jwt(wrongKey, header, claims));
  const wrongIssuer = await makeCookie(jwt(privateKey, header, { ...claims, iss: 'http://other.invalid/auth/v1' }));
  const reads = [];
  let decision = 200;
  let responseBody;
  await listen(t, api, (req, res) => {
    reads.push({ path: req.url, method: req.method, headers: req.headers });
    res.writeHead(decision, { 'content-type': 'application/json', 'cache-control': 'public, max-age=3600', 'set-cookie': 'upstream=private', location: 'http://127.0.0.1:8013/should-not-follow' });
    if (responseBody !== undefined) {
      // Stream without Content-Length to exercise the actual byte counter.
      res.write(responseBody);
      return res.end();
    }
    res.end(JSON.stringify({ detail: decision === 200 ? 'fixture evidence' : 'internal diagnostic' }));
  });
  await listen(t, ui, composeLocalWorkspace((_req, res) => { res.statusCode = 404; res.end(); }));
  const before = providerReads;
  const unavailable = await get(`${prefix}/knowledge`);
  assert.equal(unavailable.status, 401);
  for (const [path, headers, method, status] of [
    [`${prefix}/knowledge`, { host: 'localhost:3013' }, 'GET', 403],
    [`${prefix}/knowledge`, { host: '127.0.0.1:3013' }, 'GET', 403],
    [`${prefix}/knowledge`, { origin: 'http://127.0.0.1:3013' }, 'GET', 403],
    [`${prefix}/knowledge`, { 'x-forwarded-for': '127.0.0.1' }, 'GET', 403],
    [`${prefix}/knowledge`, { authorization: `Bearer ${token}` }, 'GET', 400],
    [`${prefix}/knowledge`, { 'x-bri-role': 'admin' }, 'GET', 400],
    [`${prefix}/knowledge`, {}, 'HEAD', 405],
    [`${prefix}/knowledge`, {}, 'POST', 405],
    [`${prefix}/knowledge/`, {}, 'GET', 404],
    [`${prefix}/%6bnowledge`, {}, 'GET', 404],
    ['/api/bri%2Dlocal/v1/knowledge', {}, 'GET', 404],
    [`${prefix}/sources/csv`, {}, 'GET', 404],

    [`${prefix}/knowledge/${id}`, {}, 'GET', 404],
    [`${prefix}/knowledge/${encodeURIComponent(id).replace('%3A', '%3a')}`, {}, 'GET', 404],
    [`${prefix}/knowledge?tenant=other`, {}, 'GET', 400],
    [`${prefix}/knowledge/search?q=a&q=b`, {}, 'GET', 400],
    [`${prefix}/knowledge/search?q=%C0`, {}, 'GET', 400],
    [`${prefix}/knowledge/search?q=%20`, {}, 'GET', 400],
  ]) {
    const result = await get(path, { cookie, ...headers }, method);
    assert.equal(result.status, status, `${method} ${path}`);
  }
  assert.equal(providerReads, before);
  assert.equal(reads.length, 0);
  for (const bad of [forgedCookie, wrongIssuer]) assert.equal((await get(`${prefix}/knowledge`, { cookie: bad })).status, 401);
  assert.equal(reads.length, 0);
  for (const [path, forwarded] of [
    ['/knowledge', '/knowledge'], ['/knowledge/search?q=exact+evidence', '/knowledge/search?q=exact+evidence'],
    [`/knowledge/${encodeURIComponent(id)}`, `/knowledge/${id}`], [`/sources/${encodeURIComponent(id)}`, `/sources/${id}`],
  ]) {
    const result = await get(`${prefix}${path}`, { cookie, origin: ui, 'user-agent': 'synthetic-browser' });
    assert.equal(result.status, 200);
    assert.equal(result.headers['cache-control'], 'no-store');
    assert.equal(result.headers.location, undefined);
    assert.equal(result.headers['set-cookie'], undefined);
    assert.match(result.body, /fixture evidence/);
    const seen = reads.at(-1);
    assert.equal(seen.path, `/v1${forwarded}`);
    assert.equal(seen.method, 'GET');
    assert.deepEqual(seen.headers, { authorization: `Bearer ${token}`, accept: 'application/json', host: '127.0.0.1:8013', connection: seen.headers.connection });
  }
  for (const [status, rendered] of [[302, 502], [401, 401], [403, 403], [404, 404], [503, 503]]) {
    decision = status;
    const calls = reads.length;
    const result = await get(`${prefix}/knowledge`, { cookie });
    assert.equal(result.status, rendered);
    assert.equal(result.headers.location, undefined);
    assert.doesNotMatch(result.body, /internal diagnostic|fixture evidence/);
    assert.equal(reads.length, calls + 1);
  }
  decision = 200;
  assert.equal((await get(`${prefix}/knowledge`, { cookie }, 'GET', '127.0.0.2')).status, 200);

  await t.test('review uses only the pinned listener, exact routes and canonical signed decisions', async () => {
    const base = '/v1/knowledge/proposals/csv';
    const queue = `/api/bri-local${base}`;
    const detail = `${queue}/${encodeURIComponent(id)}`;
    const action = `${detail}/decision`;
    const summary = { id, node_id: 'team', state: 'proposed', created_at: '2026-11-01T00:00:00+00:00' };
    const seen = [];
    let status = 200;
    let body;
    await listen(t, 'http://127.0.0.1:8114', async (req, res) => {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      seen.push({ path: req.url, method: req.method, headers: req.headers, body: Buffer.concat(chunks).toString() });
      res.writeHead(status, { 'content-type': 'application/json', location: '/redirect', 'set-cookie': 'not-forwarded=1' });
      res.end(JSON.stringify(body));
    });
    const before = reads.length;
    body = { items: [summary], next_cursor: null };
    const cursor = '5607a17a-61be-4c19-a912-bbfe61d070e3';
    const queued = await get(`${queue}?limit=1&status=proposed&after=${cursor}`, { cookie });
    assert.equal(queued.status, 200);
    assert.deepEqual(JSON.parse(queued.body), body);
    assert.equal(seen.at(-1).path, `${base}?status=proposed&after=${cursor}&limit=1`);
    assert.equal(queued.headers['cache-control'], 'no-store');
    assert.equal(queued.headers['set-cookie'], undefined);
    body = { ...summary, state: 'failed', provenance: null, evidence: null, next_evidence_offset: null, history: [] };
    assert.equal((await get(`${detail}?offset=0`, { cookie })).status, 200);
    assert.equal(seen.at(-1).path, `${base}/${id}?offset=0`);
    const post = (payload, headers = {}) => get(action, {
      cookie, origin: ui, 'content-type': 'application/json', 'content-length': Buffer.byteLength(payload), ...headers,
    }, 'POST', '127.0.0.1', payload);
    body = { id, decision: 'approved' };
    assert.deepEqual(JSON.parse((await post(' { "decision" : "approv\\u0065d" } ', { 'x-random': 'not-forwarded' })).body), body);
    const sent = seen.at(-1);
    assert.equal(sent.path, `${base}/${id}/decision`);
    assert.equal(sent.method, 'POST');
    assert.equal(sent.body, '{"decision":"approved"}');
    assert.deepEqual(sent.headers, { authorization: ['Bearer', token].join(' '), accept: 'application/json',
      'content-type': 'application/json', 'content-length': String(Buffer.byteLength(sent.body)), host: '127.0.0.1:8114', connection: sent.headers.connection });
    const calls = seen.length;
    for (const [path, code] of [[`${queue}?limit=51`, 400], [`${queue}?status=ready`, 400],
      [`${queue}?after=csv%3A${cursor}`, 400], [`${queue}?limit=1&limit=2`, 400], [`${queue}?`, 400],
      [`${detail}?offset=-1`, 400], [`${detail}?offset=999999999`, 400], [`${detail}?offset=01`, 400],
      [detail.replace('%3A', '%253A'), 404], [detail.replace('%3A', '%3a'), 404], [`${detail}/`, 404], [action, 405]]) {
      assert.equal((await get(path, { cookie })).status, code, path);
    }
    const valid = '{"decision":"approved"}';
    assert.equal((await get(action, { cookie, 'content-type': 'application/json', 'content-length': valid.length }, 'POST', '127.0.0.1', valid)).status, 403);
    assert.equal((await post(valid, { origin: 'http://127.0.0.1:3013' })).status, 403);
    assert.equal((await post(valid, { 'content-type': 'application/json; charset=utf-8' })).status, 415);
    assert.equal((await post(valid, { cookie: forgedCookie })).status, 401);
    assert.equal((await get(queue)).status, 401);
    for (const invalid of ['{"decision":"approve"}', '{"decision":"approved","decision":"rejected"}',
      '{"decision":"approved","reason":null}', 'null', '["approved"]']) assert.equal((await post(invalid)).status, 400);
    assert.equal((await post(' '.repeat(512) + valid)).status, 413);
    const stalled = await new Promise((resolve, reject) => {
      const req = request(ui, { path: action, method: 'POST', signal: AbortSignal.timeout(5000), headers: {
        cookie, origin: ui, 'content-type': 'application/json', 'content-length': valid.length,
      } }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
      req.on('error', reject).write('{'); // Deliberately leave a small, validly framed body incomplete.
    });
    assert.equal(stalled, 408);
    assert.equal(seen.length, calls);
    assert.equal(reads.length, before);
    status = 409;
    body = { detail: 'private diagnostic' };
    const stale = await post(valid);
    assert.equal(stale.status, 409);
    assert.doesNotMatch(stale.body, /private diagnostic/);
    status = 302;
    assert.equal((await post(valid)).status, 502);
    assert.equal(seen.at(-1).path, `${base}/${id}/decision`);
    status = 200;
    body = { id, decision: 'rejected' };
    assert.equal((await post(valid)).status, 502);
    body = [{ id, text: 'legacy private evidence' }];
    const unknown = await get(queue, { cookie });
    assert.equal(unknown.status, 502);
    assert.doesNotMatch(unknown.body, /private evidence/);
  });

  await t.test('XLSX intake forwards only signed fixed-origin binary submission and matching receipts', async () => {
    const seen = [];
    const job = '5607a17a-61be-4c19-a912-bbfe61d070e3';
    const base = '/v1/intake/xlsx';
    const media = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
    const workbook = Buffer.from([0x50, 0x4b, 0x00, 0xff]);
    let extra = {};
    await listen(t, 'http://127.0.0.1:8116', async (req, res) => {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      seen.push({ path: req.url, headers: req.headers, body: Buffer.concat(chunks) });
      res.writeHead(req.method === 'POST' ? 202 : 200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ id: job, state: 'ready', ...extra }));
    });
    const headers = { cookie, origin: ui, 'content-type': media, 'content-length': workbook.length,
      'x-node-id': 'fixture.node:1', 'idempotency-key': job, 'x-random': 'strip' };
    const post = (overrides = {}) => get(`/api/bri-local${base}`, { ...headers, ...overrides }, 'POST', '127.0.0.1', workbook);
    for (const [overrides, code] of [[{ origin: undefined }, 403], [{ cookie: forgedCookie }, 401],
      [{ 'x-tenant-id': 'spoof' }, 400], [{ 'x-dev-identity': 'spoof' }, 400], [{ 'x_scope_id': 'spoof' }, 400],
      [{ 'content-type': 'text/csv' }, 415],
      [{ 'x-node-id': 'bad node' }, 400], [{ 'idempotency-key': 'invalid' }, 400],
      [{ 'content-length': 5000001 }, 413]]) {
      const supplied = { ...headers, ...overrides };
      for (const key of Object.keys(supplied)) if (supplied[key] === undefined) delete supplied[key];
      assert.equal((await get(`/api/bri-local${base}`, supplied, 'POST', '127.0.0.1', workbook)).status, code);
    }
    assert.equal(seen.length, 0);
    const accepted = await post();
    assert.equal(accepted.status, 202);
    assert.equal(accepted.headers['cache-control'], 'no-store');
    assert.deepEqual(JSON.parse(accepted.body), { id: job, state: 'ready' });
    assert.deepEqual(seen[0].body, workbook);
    assert.equal(seen[0].headers['x-node-id'], headers['x-node-id']);
    assert.equal(seen[0].headers['idempotency-key'], job);
    assert.ok(seen[0].headers.authorization?.endsWith(token));
    for (const suppressed of ['cookie', 'x-random', 'origin']) assert.equal(seen[0].headers[suppressed], undefined);
    const statusPath = `/api/bri-local${base}/${job}`;
    assert.equal((await get(`${statusPath}?`, { cookie })).status, 400);
    assert.equal((await get(statusPath, { cookie, 'x-node-id': 'spoof' })).status, 400);
    assert.equal((await get(statusPath, { cookie })).status, 200);
    assert.deepEqual(seen.map((item) => item.path), [base, `${base}/${job}`]);
    extra = { id, private_key: 'never expose' };
    const wrong = await get(statusPath, { cookie });
    assert.equal(wrong.status, 502);
    assert.doesNotMatch(wrong.body, /never expose/);
  });

  await t.test('XLSX governance queue is signed, bounded, and never forwards maintenance targets', async () => {
    const seen = [];
    const base = '/v1/knowledge/proposals/xlsx';
    const queue = `/api/bri-local${base}`;
    const cursor = 'c'.repeat(64);
    const id = 'xlsx:5607a17a-61be-4c19-a912-bbfe61d070e3';
    let body = { items: [{ id, node_id: 'fixture-node', state: 'proposed' }], next_cursor: cursor };
    await listen(t, 'http://127.0.0.1:8117', (req, res) => {
      seen.push({ path: req.url, headers: req.headers });
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(typeof body === 'string' ? body : JSON.stringify(body));
    });
    for (const [path, headers, method, code] of [[queue, {}, 'GET', 401],
      [queue, { cookie: forgedCookie }, 'GET', 401], [`${queue}?limit=21`, { cookie }, 'GET', 400],
      [`${queue}?cursor=${cursor}&cursor=${cursor}`, { cookie }, 'GET', 400], [`${queue}?tenant=fake`, { cookie }, 'GET', 400],
      [`${queue}/publish`, { cookie }, 'POST', 404], [`${queue}/`, { cookie }, 'GET', 404]]) {
      assert.equal((await get(path, headers, method)).status, code, path);
    }
    assert.equal(seen.length, 0);
    const input = `${queue}?limit=20&cursor=${cursor}`;
    const result = await get(input, { cookie, 'x-random': 'strip' });
    assert.equal(result.status, 200);
    assert.deepEqual(JSON.parse(result.body), body);
    assert.ok(seen[0].headers.authorization?.endsWith(token));
    assert.equal(seen[0].headers.cookie, undefined);
    assert.equal(seen[0].headers['x-random'], undefined);
    assert.equal(seen[0].path, `${base}?limit=20&cursor=${cursor}`);
    body = { items: Array(21).fill({ id, node_id: 'fixture-node', state: 'proposed' }), next_cursor: null };
    assert.equal((await get(queue, { cookie })).status, 502);
    body = JSON.stringify({ items: [], next_cursor: null });
    body += ' '.repeat(512 * 1024 - Buffer.byteLength(body));
    assert.equal((await get(queue, { cookie })).status, 200);
    body += ' ';
    assert.ok((await get(queue, { cookie })).status >= 500);
    const detail = `${queue}/${encodeURIComponent(id)}`;
    const action = `${detail}/decision`;
    body = { id, node_id: 'fixture-node', state: 'proposed', sheet_id: '1', sheet_title: 'Policy', cell_range: 'A1',
      cells: [{ row: 1, column: 1, value: ['text', 'synthetic'] }], next_cursor: null };
    assert.equal((await get(detail, { cookie })).status, 200);
    assert.equal(seen.at(-1).path, `${base}/${id}`);
    assert.equal((await get(detail.replace('%3A', ':'), { cookie })).status, 404);
    const post = (payload, headers = {}) => get(action, { cookie, origin: ui, 'content-type': 'application/json',
      'content-length': Buffer.byteLength(payload), 'idempotency-key': id.slice(5), ...headers }, 'POST', '127.0.0.1', payload);
    const valid = '{"decision":"approve"}';
    const before = seen.length;
    assert.equal((await post('{"decision":"approve","decision":"reject"}')).status, 400);
    assert.equal((await post(valid, { 'idempotency-key': 'invalid' })).status, 400);
    assert.equal((await post(valid, { cookie: forgedCookie })).status, 401);
    assert.equal(seen.length, before);
    body = { id, decision: 'approve' };
    assert.deepEqual(JSON.parse((await post(valid)).body), body);
    assert.equal(seen.at(-1).path, `${base}/${id}/decision`);
    assert.equal(seen.at(-1).headers['idempotency-key'], id.slice(5));
    body = { id, decision: 'reject' };
    assert.equal((await post(valid)).status, 502);
    const version = 'e50d72bc-5fa2-4891-b69b-c68225911a57';
    const published = `/v1/knowledge/xlsx/${id.slice(5)}`;
    const evidence = `${published}/evidence/${version}`;
    const record = { record_id: id.slice(5), source_version_id: version, node_id: 'fixture-node' };
    body = record;
    const detailRead = await get(`/api/bri-local${published}`, { cookie });
    assert.equal(detailRead.status, 200);
    assert.deepEqual(JSON.parse(detailRead.body), record);
    assert.equal(seen.at(-1).path, published);
    assert.equal((await get(`/api/bri-local${published}?cursor=${cursor}`, { cookie })).status, 400);
    body = { ...record, sheet_id: '1', sheet_title: 'Policy', cell_range: 'A1',
      cells: [{ row: 1, column: 1, value: ['text', 'synthetic'] }], next_cursor: null };
    const evidenceRead = await get(`/api/bri-local${evidence}?cursor=${cursor}`, { cookie });
    assert.equal(evidenceRead.status, 200);
    assert.deepEqual(JSON.parse(evidenceRead.body), body);
    assert.equal(seen.at(-1).path, `${evidence}?cursor=${cursor}`);
    body = { ...body, source_version_id: id.slice(5) };
    const mismatch = await get(`/api/bri-local${evidence}`, { cookie });
    assert.equal(mismatch.status, 502);
    assert.doesNotMatch(mismatch.body, /synthetic/);
  });

  await t.test('only knowledge detail accommodates an escaped 20 MB extraction', async () => {
    const project = (cell) => JSON.stringify({ headers: ['Test'], rows: [[cell]] });
    const padding = 20_000_000 - Buffer.byteLength(project('é'));
    const extracted = project('\\'.repeat(Math.floor(padding / 2)) + 'é' + 'x'.repeat(padding % 2));
    assert.equal(Buffer.byteLength(extracted), 20_000_000);
    responseBody = JSON.stringify({ content: extracted });
    assert.ok(Buffer.byteLength(responseBody) > 39_000_000);
    const knowledge = `${prefix}/knowledge/${encodeURIComponent(id)}`;
    assert.equal((await get(knowledge, { cookie })).body, responseBody);
    for (const route of [`${prefix}/knowledge`, `${prefix}/knowledge/search?q=one`, `${prefix}/sources/${encodeURIComponent(id)}`]) {
      assert.equal((await get(route, { cookie })).status, 503);
    }
  });
  await t.test('bridge accepts the byte cap exactly and rejects one byte more', async () => {
    const cappedBody = (size) => `"é${'a'.repeat(size - 4)}"`;
    for (const [route, limit] of [
      [`${prefix}/knowledge/${encodeURIComponent(id)}`, 48_000_000],
      [`${prefix}/knowledge`, 16 * 1024 * 1024],
    ]) {
      responseBody = cappedBody(limit);
      assert.equal(Buffer.byteLength(responseBody), limit);
      assert.equal((await get(route, { cookie })).status, 200);
      responseBody = cappedBody(limit + 1);
      const oversized = await get(route, { cookie });
      assert.equal(oversized.status, 503);
      assert.equal(oversized.body, '{"detail":"Local workspace read unavailable."}');
    }
  });
  process.env.NODE_ENV = 'production';
  assert.throws(() => composeLocalWorkspace(() => {}), /development/);
});
