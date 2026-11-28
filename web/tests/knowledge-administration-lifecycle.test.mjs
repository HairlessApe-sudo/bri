import assert from 'node:assert/strict';
import test from 'node:test';

const format = 'csv';
const id = '5607a17a-61be-4c19-a912-bbfe61d070e3';
const context = '1'.repeat(64);
const meta = { version: 1, title: 'Synthetic', description: null, effective_date: null, review_date: null, expiry_date: null,
  primary_classification_id: 'policy', additional_classification_ids: [] };
const deferred = () => { let resolve; const promise = new Promise((done) => { resolve = done; }); return { promise, resolve }; };
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });

async function modules() {
  const result = await import('../local-workspace/administration-client.mjs').catch((err) => {
    if (err.code !== 'ERR_MODULE_NOT_FOUND') throw err;
    return {};
  });
  assert.equal(typeof result.createAdministrationLifecycle, 'function');
  return result;
}

test('retiring or replacing a lane cancels that lane, not unrelated reads, and only current work can publish', async () => {
  const { createAdministrationLifecycle } = await modules();
  const lifecycle = createAdministrationLifecycle();
  const status = lifecycle.begin('status');
  const selection = lifecycle.begin('selection');
  const upload = lifecycle.begin('upload');
  const replacement = lifecycle.begin('status');
  assert.equal(status.signal.aborted, true);
  assert.ok(selection.current());
  assert.ok(upload.current());
  assert.ok(replacement.current());
  lifecycle.cancel('selection', 'upload');
  assert.ok(replacement.current());
  assert.ok(!selection.current() && !upload.current());
  lifecycle.clear();
  assert.equal(replacement.signal.aborted, true);
  assert.equal(replacement.current(), false);
});

test('changed scope cannot publish even when a mock transport ignores abort and the body arrives later', async () => {
  const { createAdministrationLifecycle, readJob } = await modules();
  const lifecycle = createAdministrationLifecycle();
  const body = deferred();
  const request = lifecycle.begin('status');
  const read = readJob(async () => ({ status: 200, headers: new Headers({ 'content-type': 'application/json' }),
    body: { getReader: () => ({ read: () => body.promise, cancel: async () => {}, releaseLock() {} }) } }),
  context, format, id, request.signal);
  await Promise.resolve();
  lifecycle.clear();
  body.resolve({ done: false, value: new TextEncoder().encode(JSON.stringify({ id, state: 'proposed' })) });
  await assert.rejects(read, { name: 'AbortError' });
});

test('explicit format and exact UUID drive native status; mismatch, unsafe and malformed receipts reject', async () => {
  const { readJob } = await modules();
  const signal = new AbortController().signal;
  let requested;
  const okay = async (path, options) => { requested = { path, options }; return json({ id, state: 'approved' }); };
  assert.deepEqual(await readJob(okay, context, format, id, signal), { id, state: 'approved' });
  assert.equal(requested.path, `/api/bri-local/v1/sources/csv/${id}`);
  assert.equal(requested.options.headers['x-bri-administration-context'], context);
  assert.equal(requested.options.cache, 'no-store');
  await assert.rejects(readJob(okay, context, 'xlsx', id, signal), { status: 502 });
  await assert.rejects(readJob(okay, context, 'csv', `csv:${id}`, signal), { status: 422 });
  await assert.rejects(readJob(async () => json({ id, state: 'ready', count: 1 }), context, format, id, signal), { status: 502 });
});

test('explicit retry uses the same immutable file, format and idempotency key without trying another parser', async () => {
  const { prepareSubmission, uploadSubmission } = await modules();
  const file = new File(['col\nvalue\n'], 'synthetic.csv');
  const original = { ...meta, additional_classification_ids: ['secondary'] };
  const command = prepareSubmission('csv', file, 'synthetic', id, original, context);
  original.title = 'Changed';
  original.additional_classification_ids.push('unrelated');
  assert.ok(Object.isFrozen(command));
  assert.deepEqual(JSON.parse(Buffer.from(command.metadata, 'base64url')), { ...meta, additional_classification_ids: ['secondary'] });
  const requests = [];
  const transport = async (...args) => { requests.push(args); return requests.length === 1 ? json({}, 503) : json({ id, state: 'ready' }, 202); };
  await assert.rejects(uploadSubmission(transport, context, command, new AbortController().signal), { status: 503 });
  assert.deepEqual(await uploadSubmission(transport, context, command, new AbortController().signal), { id, state: 'ready' });
  for (const [path, options] of requests) {
    assert.equal(path, '/api/bri-local/v1/knowledge-administration/csv/uploads');
    assert.equal(options.body, file);
    assert.equal(options.headers['idempotency-key'], id);
    assert.equal(options.headers['content-type'], 'text/csv');
    assert.equal(options.headers['x-node-id'], 'synthetic');
    assert.equal(options.headers['x-bri-metadata'], command.metadata);
    assert.equal(options.headers['x-bri-administration-context'], context);
  }
  assert.throws(() => prepareSubmission('xlsx', file, 'synthetic', id, meta, context), { status: 422 });
});

test('bound command cannot be dispatched with another signed context', async () => {
  const { prepareSubmission, uploadSubmission } = await modules();
  const command = prepareSubmission('csv', new File(['col\nvalue\n'], 'synthetic.csv'), 'synthetic', id, meta, context);
  let posts = 0;
  await assert.rejects(uploadSubmission(async () => { posts++; }, '2'.repeat(64), command, new AbortController().signal),
    { status: 401, outcome: 'retired' });
  assert.equal(posts, 0);
});

test('only intact exact denials are conclusive; broken or unexpected upload replies are uncertain', async () => {
  const { prepareSubmission, uploadSubmission } = await modules();
  const command = prepareSubmission('xlsx', new File(['synthetic'], 'synthetic.xlsx'), 'synthetic', id, meta, context);
  const run = (transport) => uploadSubmission(transport, context, command, new AbortController().signal);
  for (const status of [400, 413, 415, 422]) {
    await assert.rejects(run(async () => json({ detail: 'Invalid governed metadata request.' }, status)), { status, outcome: 'rejected' });
  }
  // The bridge flattens fingerprint conflicts and all native uniqueness
  // errors to the same 409 (including failure to append a readiness event).
  await assert.rejects(run(async () => json({ detail: 'Governed metadata conflict. Refresh before starting a new operation.' }, 409)),
    { status: 409, outcome: 'uncertain' });
  await assert.rejects(run(async () => json({ detail: 'Governed metadata operation denied.' }, 403)), { status: 403, outcome: 'retired' });
  for (const status of [408, 418, 429, 500, 501, 502, 503, 504, 599]) {
    await assert.rejects(run(async () => json({}, status)), { status, outcome: 'uncertain' });
  }
  for (const response of [json({}, 403), json({ detail: 'Invalid governed metadata request.', extra: true }, 422),
    json({ id, state: 'approved' }, 202), json({ id, state: 'ready', extra: true }, 202), json({ id, state: 'ready' }),
    new Response('{"id":"', { status: 202, headers: { 'content-type': 'application/json' } }),
    new Response(JSON.stringify({ id, state: 'ready' }), { status: 202 }),
    new Response(new ReadableStream({ start(controller) { controller.error(new Error('interrupted')); } }),
      { status: 422, headers: { 'content-type': 'application/json' } })]) {
    await assert.rejects(run(async () => response), { status: 502, outcome: 'uncertain' });
  }
  await assert.rejects(run(async () => { throw new TypeError('network'); }), { status: 503, outcome: 'uncertain' });
});

test('retirement suppresses the original receipt even when its body arrives late', async () => {
  const { createAdministrationLifecycle, prepareSubmission, uploadSubmission } = await modules();
  const command = prepareSubmission('csv', new File(['col\nvalue\n'], 'synthetic.csv'), 'synthetic', id, meta, context);
  const lifecycle = createAdministrationLifecycle();
  const request = lifecycle.begin('upload');
  const body = deferred();
  const started = deferred();
  const upload = uploadSubmission(async () => ({ status: 202, headers: new Headers({ 'content-type': 'application/json' }),
    body: { getReader: () => ({ read: () => { started.resolve(); return body.promise; }, cancel: async () => {}, releaseLock() {} }) } }),
  context, command, request.signal);
  await started.promise;
  lifecycle.clear();
  body.resolve({ done: false, value: new TextEncoder().encode(JSON.stringify({ id, state: 'ready' })) });
  await assert.rejects(upload, { name: 'AbortError' });
  assert.equal(request.current(), false);
});
