import assert from 'node:assert/strict';
import test from 'node:test';
import { buildBackendRequest, BackendRequestError } from '../src/lib/backend-proxy.mjs';


const resource = '/v1/reports/published-knowledge-inventory';
const path = `/api/bri-local${resource}`;
const node = 'team';
const ref = 'csv:01234567-89ab-4def-8123-456789abcdef';
const row = { record_id: ref, source_version_id: ref, original_sha256: 'a'.repeat(64),
  content_sha256: 'b'.repeat(64), first_line: 1, last_line: 3 };
const meta = { metric_id: 'published_knowledge_inventory', metric_version: 1, scope_node_id: node };
const complete = { result: { ...meta, status: 'complete', count: 1, evidence: [row] } };
const empty = { result: { ...meta, status: 'complete', count: 0, evidence: [] } };
const unavailable = { result: { ...meta, status: 'unavailable' } };
const contract = () => import('../local-workspace/reporting.mjs');

test('only exact, bounded complete or unavailable envelopes are accepted', async () => {
  const { parseReport } = await contract();
  assert.deepEqual(parseReport(200, complete, node), complete);
  assert.deepEqual(parseReport(200, empty, node), empty);
  assert.deepEqual(parseReport(503, unavailable, node), unavailable);
  for (const [status, value, scope = node] of [
    [200, unavailable], [503, complete], [200, complete, 'other'],
    [503, { result: { ...unavailable.result, count: 0 } }],
    [200, { result: { ...complete.result, count: 2 } }],
    [200, { result: { ...complete.result, count: 2, evidence: [row, row] } }],
    ...[{ record_id: '//elsewhere' }, { source_version_id: 'different' }, { first_line: 4 },
      { content_sha256: 'x'.repeat(64) }, { content: 'private' }].map((patch) =>
      [200, { result: { ...complete.result, evidence: [{ ...row, ...patch }] } }]),
  ]) assert.equal(parseReport(status, value, scope), null);
});

test('fresh evaluations erase old evidence synchronously and ignore late response bodies', async () => {
  const { createReportEvaluation } = await contract();
  const states = [];
  let releaseBody;
  let calls = 0;
  const evaluation = createReportEvaluation((state) => states.push(state), async (url, options) => {
    assert.equal(url, `${path}?scope_node_id=team`);
    assert.equal(options.cache, 'no-store');
    if (++calls === 1) return new Response(JSON.stringify(complete));
    if (calls === 2) return { status: 200, json: () => new Promise((resolve) => { releaseBody = resolve; }) };
    return new Response(JSON.stringify(complete), { status: 403 });
  });
  await evaluation.run(node);
  assert.deepEqual(states.at(-1), { status: 'complete', result: complete.result });
  const delayed = evaluation.run(node);
  assert.deepEqual(states.at(-1), { status: 'loading' });
  await Promise.resolve();
  await evaluation.run(node);
  assert.deepEqual(states.at(-1), { status: 'denied' });
  releaseBody(complete);
  await delayed;
  assert.deepEqual(states.at(-1), { status: 'denied' });
});

test('empty, unavailable, denial and dependency failures never publish result data', async () => {
  const { createReportEvaluation } = await contract();
  for (const [code, body, status] of [[200, empty, 'empty'], [503, unavailable, 'unavailable'],
    [503, {}, 'dependency'], [200, {}, 'dependency'], [401, complete, 'denied'], [404, complete, 'denied'],
    [500, complete, 'dependency'], [0, {}, 'dependency']]) {
    let state;
    const evaluation = createReportEvaluation((next) => { state = next; }, async () => {
      if (!code) throw new Error('network');
      return new Response(JSON.stringify(body), { status: code });
    });
    await evaluation.run(node);
    assert.deepEqual(state, { status });
  }
});

test('retiring an evaluation before dispatch leaves no in-flight HTTP read', async () => {
  const { createReportEvaluation } = await contract();
  let calls = 0;
  const evaluation = createReportEvaluation(() => evaluation.cancel(), async () => {
    calls++;
    return new Response();
  });
  await evaluation.run(node);
  assert.equal(calls, 0);
});

test('release proxy does not expose the reporting resource', () => {
  const query = new URLSearchParams({ scope_node_id: node });
  for (const config of [
    { BRI_API_ORIGIN: 'http://127.0.0.1:8000', BRI_UI_DEV_IDENTITY: 'test-reader' },
    { BRI_API_ORIGIN: 'https://example.test', BRI_UI_AUTH_MODE: 'supabase' },
  ]) {
    assert.throws(() => buildBackendRequest(resource, query, config),
      (error) => error instanceof BackendRequestError && error.status === 404);
  }
});

test('local reporting bridge requires a signed session and an exact read-only route', async (t) => {
  const old = process.env.NODE_ENV;
  process.env.NODE_ENV = 'development';
  t.after(() => { if (old === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = old; });
  const { composeLocalWorkspace } = await import('../local-workspace/bridge.mjs');
  const dispatch = composeLocalWorkspace((_req, res) => res.writeHead(200).end('local UI'));
  async function get(url, method = 'GET', headers = {}) {
    const host = '127.0.0.2:3013';
    let code;
    await dispatch({ url, method, headers: { host, ...headers }, rawHeaders: ['Host', host],
      socket: { localAddress: '127.0.0.2', localPort: 3013, remoteAddress: '127.0.0.1' } }, {
      setHeader() {}, writeHead(status) { code = status; return this; }, end() {},
    });
    return code;
  }
  assert.equal(await get('/reports'), 200);
  assert.equal(await get('/reports', 'POST'), 405);
  assert.equal(await get(`${path}?scope_node_id=team`), 401);
  assert.equal(await get(`${path}?scope_node_id=team`, 'GET', { 'x-node-id': 'other' }), 400);
  assert.equal(await get(`${path}?scope_node_id=team`, 'GET', { scope_node_id: 'other' }), 400);
  assert.equal(await get(`${path}?scope_node_id=team`, 'POST'), 405);
  assert.equal(await get('/api/bri-local/v1/reports'), 404);
  assert.equal(await get(`${path}/?scope_node_id=team`), 404);
  for (const query of ['', '?', '?scope_node_id=', '?scope_node_id=%20', '?scope_node_id=%00',
    '?scope_node_id=%20team', '?scope_node_id=%C0', '?scope%5fnode_id=team',
    '?scope_node_id=team%0a', '?scope_node_id=team&scope_node_id=other', '?scope_node_id=team&tenant_id=other']) {
    assert.equal(await get(`${path}${query}`), 400, query);
  }
});
