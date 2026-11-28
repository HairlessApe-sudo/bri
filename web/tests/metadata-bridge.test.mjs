import assert from 'node:assert/strict';
import test from 'node:test';
import { Readable } from 'node:stream';

const base = '/v1/knowledge-metadata';
const id = '5607a17a-61be-4c19-a912-bbfe61d070e3';
const version = '5607a17a-61be-4c19-a912-bbfe61d070e4';
const record = `${base}/xlsx/records/${id}/versions/${version}`;

test('metadata bridge allows only exact method, format, IDs, operation and query', async () => {
  const mod = await import('../local-workspace/metadata-bridge.mjs').catch(() => ({}));
  assert.equal(typeof mod.metadataTarget, 'function');
  const { metadataTarget: target } = mod;
  assert.equal(target(`${base}/csv/uploads`, 'POST'), 404);
  assert.equal(target(`${base}/xlsx/upload%73`, 'POST'), 404);
  assert.equal(target(`${record}/`, 'GET'), 404);
  assert.equal(target(record.replace(id, id.toUpperCase()), 'GET'), 404);
  assert.equal(target(record, 'POST'), 405);
  assert.equal(target(record, 'GET', ''), 400);
  assert.equal(target(`${record}/corrections`, 'GET', `after=${id}&after=${version}`), 400);
  assert.equal(target(`${base}/catalogue/selection/xlsx_correction/team`, 'GET'), 404);
  assert.equal(target(`${record}/corrections`, 'GET', `after=${id}`).path, `${record}/corrections?after=${id}`);
  assert.equal(target(`${base}/xlsx/uploads`, 'POST').origin, 'http://127.0.0.1:8116');
});

test('metadata bridge rejects alternate authority and unexpected success data', async () => {
  const mod = await import('../local-workspace/metadata-bridge.mjs').catch(() => ({}));
  assert.equal(typeof mod.forwardMetadata, 'function');
  const target = mod.metadataTarget(record, 'GET');
  const invocations = [];
  let payload = { record_id: id, source_version_id: version, metadata: null };
  const options = {
    origin: 'http://127.0.0.2:3013', browserAuthority: () => false,
    verifiedBearer: async () => { invocations.push('auth'); return 'fixture'; },
    loopbackRequest: async (...args) => {
      invocations.push(args);
      return { status: 200, contentType: 'application/json', body: Buffer.from(JSON.stringify(payload)) };
    },
  };
  async function request(headers) {
    const req = Object.assign(Readable.from([]), { headers, headersDistinct: Object.fromEntries(Object.entries(headers).map(([key, val]) => [key, [val]])) });
    const res = { writeHead(status, headers) { this.status = status; this.headers = headers; return this; },
      end(body) { this.body = body; }, setHeader() {} };
    await mod.forwardMetadata(req, res, target, options);
    return res;
  }
  assert.equal((await request({ scope_node_id: 'spoof' })).status, 400);
  assert.deepEqual(invocations, []);
  const response = await request({ cookie: 'fixture' });
  assert.equal(response.status, 200);
  assert.equal(response.headers['cache-control'], 'private, no-store');
  assert.deepEqual(JSON.parse(response.body), payload);
  assert.deepEqual(invocations[1].slice(0, 3), ['http://127.0.0.1:8117', record,
    { accept: 'application/json', authorization: 'Bearer fixture' }]);
  payload = { ...payload, actor_id: id };
  assert.equal((await request({})).status, 502);
  payload = { record_id: version, source_version_id: version, metadata: null };
  assert.equal((await request({})).status, 502);
});

test('correction proposal binds the exact version and revision, not the server ID to the request key', async () => {
  const { forwardMetadata, metadataTarget } = await import('../local-workspace/metadata-bridge.mjs');
  const target = metadataTarget(`${record}/corrections`, 'POST');
  const requestId = '5607a17a-61be-4c19-a912-bbfe61d070e5';
  const proposalId = '5607a17a-61be-4c19-a912-bbfe61d070e6';
  const expectedRevision = '9007199254740993';
  const origin = 'http://127.0.0.2:3013';
  const bytes = Buffer.from(JSON.stringify({ request_id: requestId, expected_revision: expectedRevision,
    metadata: { version: 1, primary_classification_id: 'policy', additional_classification_ids: [], title: 'Example',
      description: null, effective_date: null, review_date: null, expiry_date: null } }));
  let receipt = { record_id: id, source_version_id: version, proposal_id: proposalId, expected_revision: expectedRevision };
  let dispatched = 0;
  async function send(originHeader) {
    const headers = { origin: originHeader, 'content-type': 'application/json', 'content-length': `${bytes.length}` };
    const req = Object.assign(Readable.from([bytes]), { headers, headersDistinct: Object.fromEntries(Object.entries(headers).map(([key, val]) => [key, [val]])) });
    const res = { writeHead(status) { this.status = status; return this; }, end(body) { this.body = body; }, setHeader() {} };
    await forwardMetadata(req, res, target, {
      origin, browserAuthority: () => false, verifiedBearer: async () => 'fixture',
      loopbackRequest: async (_origin, _path, _headers, _limit, body) => {
        dispatched++;
        assert.deepEqual(body, bytes);
        return { status: 200, contentType: 'application/json', body: Buffer.from(JSON.stringify(receipt)) };
      },
    });
    return res;
  }
  assert.equal((await send('http://127.0.0.3:3013')).status, 403);
  assert.equal(dispatched, 0);
  const confirmed = await send(origin);
  assert.equal(confirmed.status, 200);
  assert.deepEqual(JSON.parse(confirmed.body), receipt);
  receipt = { ...receipt, expected_revision: '9007199254740992' };
  assert.equal((await send(origin)).status, 502);
  receipt = { ...receipt, expected_revision: expectedRevision, proposal_id: 'unsafe' };
  assert.equal((await send(origin)).status, 502);
});
