import assert from 'node:assert/strict';
import test from 'node:test';
import { Readable } from 'node:stream';

const root = '/v1/knowledge-administration';
const id = '5607a17a-61be-4c19-a912-bbfe61d070e3';
const origin = 'http://127.0.0.2:3013';
const contextHeader = 'x-bri-administration-context';
const metadata = { version: 1, title: 'Synthetic', description: null, effective_date: null, review_date: null,
  expiry_date: null, primary_classification_id: 'policy', additional_classification_ids: [] };

async function bridge() {
  const mod = await import('../local-workspace/administration-bridge.mjs').catch((error) => {
    if (error.code !== 'ERR_MODULE_NOT_FOUND') throw error;
    return {};
  });
  assert.equal(typeof mod.administrationTarget, 'function');
  return mod;
}

test('administration routing is exact, staged and does not intercept accepted metadata or XLSX status', async () => {
  const { administrationTarget: route } = await bridge();
  assert.equal(route(`${root}/csv/uploads`, 'POST', undefined, false), 404);
  assert.deepEqual(route(`${root}/csv/uploads`, 'POST', undefined, true), {
    kind: 'upload', format: 'csv', origin: 'http://127.0.0.1:8112', path: `${root}/csv/uploads`,
  });
  assert.equal(route(`${root}/xlsx/uploads`, 'POST', undefined, true).origin, 'http://127.0.0.1:8116');
  assert.equal(route(`${root}/csv/uploads`, 'GET', undefined, true), 405);
  assert.equal(route(`${root}/csv/uploads`, 'POST', '', true), 400);
  for (const path of [`${root}/csv/upload%73`, `${root}/csv/uploads/`, `${root}/csv/jobs`, `${root}/xlsx/worker/${id}`]) {
    assert.equal(route(path, 'POST', undefined, true), 404);
  }
  assert.equal(route(`/v1/intake/xlsx/${id}`, 'GET', undefined, false), null);
  assert.equal(route(`${root}/xlsx/status/${id}`, 'GET', undefined, true).path, `/v1/intake/xlsx/${id}`);
  assert.equal(route(`${root}/selection/xlsx/synthetic`, 'GET', undefined, true).path, '/v1/knowledge-metadata/catalogue/selection/xlsx_submit/synthetic');
  assert.equal(route('/v1/knowledge-metadata/xlsx/uploads', 'POST', undefined, true), null);
  assert.equal(route(`/v1/sources/csv/${id}`, 'GET', undefined, true).path, `/v1/sources/csv/${id}`);
  assert.equal(route(`/v1/sources/csv/${id}`, 'GET', undefined, false), 404);
  assert.equal(route(`/v1/sources/csv/${id.toUpperCase()}`, 'GET', undefined, true), 404);
});

function exchange(payload, status, contentType = 'application/json') {
  const calls = [];
  return { calls, deps: { origin, browserAuthority: () => false,
    verifiedBearer: async () => { calls.push('auth'); return 'signed'; },
    loopbackRequest: async (...args) => { calls.push(args); return {
      status, contentType, body: Buffer.isBuffer(payload) ? payload : Buffer.from(JSON.stringify(payload)),
    }; },
  } };
}
async function forward(mod, target, upstream, headers = {}, bytes = Buffer.alloc(0), duplicates = {}) {
  if (target.kind !== 'session' && !Object.hasOwn(headers, contextHeader)) {
    const setup = await forward(mod, { kind: 'session' }, exchange({}, 200));
    headers = { ...headers, [contextHeader]: setup.headers[contextHeader] };
  }
  const req = Object.assign(Readable.from(bytes.length ? [bytes] : []), {
    headers, headersDistinct: { ...Object.fromEntries(Object.entries(headers).map(([key, val]) => [key, [val]])), ...duplicates },
  });
  const res = { setHeader() {}, writeHead(code, headers) { Object.assign(this, { code, headers }); return this; }, end(data) { this.data = data; } };
  await mod.forwardAdministration(req, res, target, upstream.deps);
  return res;
}

test('classified CSV forwarding uses the explicit media, unchanged bytes and only signed authority', async () => {
  const mod = await bridge();
  const target = mod.administrationTarget(`${root}/csv/uploads`, 'POST', undefined, true);
  const bytes = Buffer.from('col\nvalue\n');
  const headers = { origin, cookie: 'fixture', 'content-type': 'text/csv', 'content-length': String(bytes.length), 'x-node-id': 'synthetic.node',
    'idempotency-key': id, 'x-bri-metadata': Buffer.from(JSON.stringify(metadata)).toString('base64url') };
  const upstream = exchange({ id, state: 'ready' }, 202);
  for (const [patch, expected] of [[{ 'x-worker-id': id }, 400], [{ 'x-tenant-id': id }, 400], [{ origin: 'http://127.0.0.3:3013' }, 403],
    [{ 'content-type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' }, 415],
    [{ 'content-length': '5000001' }, 413], [{ 'x-bri-metadata': Buffer.from(JSON.stringify({ ...metadata, tenant: id })).toString('base64url') }, 422]]) {
    assert.equal((await forward(mod, target, upstream, { ...headers, ...patch }, bytes)).code, expected);
  }
  assert.equal((await forward(mod, target, upstream, headers, bytes, { 'x-node-id': ['a', 'b'] })).code, 422);
  assert.deepEqual(upstream.calls, []);
  const response = await forward(mod, target, upstream, headers, bytes);
  assert.equal(response.code, 202);
  assert.equal(response.headers['cache-control'], 'private, no-store');
  assert.deepEqual(JSON.parse(response.data), { id, state: 'ready' });
  assert.deepEqual(upstream.calls[1], [target.origin, target.path, {
    accept: 'application/json', authorization: 'Bearer signed', 'content-type': headers['content-type'],
    'content-length': headers['content-length'], 'x-node-id': headers['x-node-id'],
    'idempotency-key': id, 'x-bri-metadata': headers['x-bri-metadata'],
  }, 1024, bytes]);
});

test('bridge rejection of an unverifiable native 202 is an uncertain browser upload', async () => {
  const mod = await bridge();
  const { prepareSubmission, uploadSubmission } = await import('../local-workspace/administration-client.mjs');
  const target = mod.administrationTarget(`${root}/csv/uploads`, 'POST', undefined, true);
  const upstream = exchange({ id, state: 'ready', extra: true }, 202);
  const session = await forward(mod, { kind: 'session' }, exchange({}, 200));
  const context = session.headers[contextHeader];
  const file = new File(['col\nvalue\n'], 'synthetic.csv');
  const command = prepareSubmission('csv', file, 'synthetic.node', id, metadata, context);
  const transport = async (path, options) => {
    assert.equal(path, `/api/bri-local${target.path}`);
    assert.equal(options.body, file);
    const body = Buffer.from(await options.body.arrayBuffer());
    const reply = await forward(mod, target, upstream, { origin, 'content-length': String(body.length), ...options.headers }, body);
    assert.equal(reply.code, 502);
    return new Response(reply.data, { status: reply.code, headers: reply.headers });
  };
  await assert.rejects(uploadSubmission(transport, context, command, new AbortController().signal), { status: 502, outcome: 'uncertain' });
  assert.equal(upstream.calls[1][3], 1024);
});

test('native status binds the exact UUID and format state and never passes upstream errors', async () => {
  const mod = await bridge();
  const target = mod.administrationTarget(`/v1/sources/csv/${id}`, 'GET', undefined, true);
  assert.equal((await forward(mod, target, exchange({ id, state: 'approved' }, 200))).code, 200);
  for (const payload of [{ id, state: 'unverified' }, { id, state: 'ready', record_count: 1 },
    { id: id.replace(/3$/, '4'), state: 'ready' }, Buffer.alloc(1025), Buffer.from(`{"id":"${id}","state":"failed","state":"ready"}`)]) {
    assert.equal((await forward(mod, target, exchange(payload, 200))).code, 502);
  }
  const denied = await forward(mod, target, exchange({ secret: id }, 403));
  assert.equal(denied.code, 403);
  assert.doesNotMatch(denied.data, new RegExp(id));
  assert.equal(denied.headers['cache-control'], 'private, no-store');
});

test('catalogue visibility validates existing catalogue and discloses only authorization', async () => {
  const mod = await bridge();
  const target = mod.administrationTarget(`${root}/catalogue-visibility`, 'GET', undefined, true);
  const rows = [{ category_id: 'category', category_label: 'Category', classification_id: 'restricted', label: 'Sensitive', description: null, retired: false }];
  const upstream = exchange(rows, 200);
  assert.deepEqual(JSON.parse((await forward(mod, target, upstream)).data), { visible: true });
  assert.equal(upstream.calls[1][0], 'http://127.0.0.1:8118');
  assert.equal(upstream.calls[1][1], '/v1/knowledge-metadata/catalogue/admin');
  assert.equal((await forward(mod, target, exchange([...rows, ...rows], 200))).code, 502);
  assert.equal((await forward(mod, target, exchange(rows, 403))).code, 403);
});

test('a context bound to a replaced signed session cannot reach any protected upstream', async () => {
  const mod = await bridge();
  const session = await forward(mod, { kind: 'session' }, exchange({}, 200));
  const target = mod.administrationTarget(`${root}/catalogue-visibility`, 'GET', undefined, true);
  const upstream = exchange([], 200);
  upstream.deps.verifiedBearer = async () => 'different-signed-session';
  const response = await forward(mod, target, upstream, { [contextHeader]: session.headers[contextHeader] });
  assert.equal(response.code, 401);
  assert.deepEqual(upstream.calls, []);
});
