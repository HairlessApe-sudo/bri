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

function get(path, headers = {}, method = 'GET', localAddress = '127.0.0.1') {
  return new Promise((resolve, reject) => {
    const req = request(ui, { path, headers, method, localAddress }, (res) => {
      let body = '';
      res.setEncoding('utf8').on('data', (chunk) => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    });
    req.on('error', reject).end();
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
    [`${prefix}/knowledge/proposals/csv`, {}, 'GET', 404],
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
