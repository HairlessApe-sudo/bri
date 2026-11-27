import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import ts from 'typescript';

const id = '5607a17a-61be-4c19-a912-bbfe61d070e3';
const reply = (value, status) => Response.json(value, { status });

registerHooks({
  load(url, context, next) {
    if (!/\.tsx?$/.test(url)) return next(url, context);
    return { format: 'module', shortCircuit: true, source: ts.transpileModule(readFileSync(new URL(url), 'utf8'), {
      compilerOptions: { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
    }).outputText };
  },
});

test('local XLSX landing offers a workbook upload and separate status check without privileged operations', async () => {
  const { IntakeForms } = await import('../local-workspace/app/xlsx/intake-forms.tsx');
  const html = renderToStaticMarkup(createElement(IntakeForms, { onUpload() {}, onStatus() {} }));
  assert.match(html, /type="file"[^>]+accept="\.xlsx"/);
  assert.match(html, /Upload workbook/);
  assert.match(html, /Check job status/);
  assert.match(html, /Node ID/);
  assert.doesNotMatch(html, /publish|withdraw|grant|tenant/i);
});

test('XLSX submission sends the original workbook once and status is a separate authorized read', async () => {
  const client = await import('../local-workspace/app/xlsx/client.mjs');
  const calls = [];
  const file = new File(['fixture'], 'policy.xlsx');
  const signal = new AbortController().signal;
  const transport = async (path, options) => {
    calls.push({ path, options });
    return reply({ id, state: options.method === 'POST' ? 'ready' : 'proposed' }, options.method === 'POST' ? 202 : 200);
  };
  assert.deepEqual(await client.uploadWorkbook(transport, file, 'team', id, signal), { id, state: 'ready' });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].path, '/api/bri-local/v1/intake/xlsx');
  assert.equal(calls[0].options.body, file);
  assert.equal(calls[0].options.headers['x-node-id'], 'team');
  assert.equal(calls[0].options.headers['idempotency-key'], id);
  assert.equal(calls[0].options.signal, signal);
  assert.deepEqual(await client.readJob(transport, id, signal), { id, state: 'proposed' });
  assert.equal(calls[1].path, `/api/bri-local/v1/intake/xlsx/${id}`);
  assert.equal(calls[1].options.cache, 'no-store');
  assert.equal(calls[1].options.redirect, 'error');
  assert.equal(calls[1].options.credentials, 'same-origin');
});

test('invalid submission and status input never reach transport', async () => {
  const client = await import('../local-workspace/app/xlsx/client.mjs');
  const transport = () => assert.fail('unexpected transport');
  await assert.rejects(client.uploadWorkbook(transport, new File(['x'], 'policy.csv'), 'team', id));
  await assert.rejects(client.uploadWorkbook(transport, new File([], 'policy.xlsx'), 'team', id));
  await assert.rejects(client.uploadWorkbook(transport, new File(['x'], 'policy.xlsx'), 'bad node', id));
  await assert.rejects(client.readJob(transport, '../jobs'));
});

test('uncertain XLSX submission does not retry and withdrawn status is not returned as data', async () => {
  const client = await import('../local-workspace/app/xlsx/client.mjs');
  let calls = 0;
  const fail = async () => { calls++; throw new Error('connection lost'); };
  await assert.rejects(client.uploadWorkbook(fail, new File(['x'], 'policy.xlsx'), 'team', id));
  assert.equal(calls, 1);
  await assert.rejects(client.readJob(async () => reply({ id, state: 'ready' }, 404), id), { status: 404 });
});

const proposal = `xlsx:${id}`;
const sheet = { id: proposal, node_id: 'team', state: 'proposed', sheet_id: '1', sheet_title: '<img src=x>',
  cell_range: 'A1:B26', cells: [{ row: 1, column: 1, value: ['text', '=HYPERLINK("https://bad.invalid") <img>'] }],
  next_cursor: 'a'.repeat(64) };

test('XLSX worksheet evidence remains inert text at its exact coordinate', async () => {
  const { parseXlsxProposal } = await import('../local-workspace/xlsx-governance.mjs');
  const { WorksheetView } = await import('../local-workspace/app/xlsx/worksheet.tsx');
  const html = renderToStaticMarkup(createElement(WorksheetView, { data: parseXlsxProposal(sheet, proposal) }));
  assert.match(html, /&lt;img src=x&gt;/);
  assert.match(html, /A1/);
  assert.match(html, /=HYPERLINK\(&quot;https:\/\/bad\.invalid&quot;\) &lt;img&gt;/);
  assert.doesNotMatch(html, /<script>|<img|href=|<iframe/);
});

test('worksheet shows one table row per physical row even for partial column windows', async () => {
  const { parseXlsxProposal } = await import('../local-workspace/xlsx-governance.mjs');
  const { WorksheetView } = await import('../local-workspace/app/xlsx/worksheet.tsx');
  const data = parseXlsxProposal({ ...sheet, cells: [sheet.cells[0], { row: 1, column: 2, value: ['boolean', false] },
    { row: 2, column: 1, value: null }] }, proposal);
  const html = renderToStaticMarkup(createElement(WorksheetView, { data }));
  assert.equal([...html.matchAll(/<tr>/g)].length, 3); // Header + two physical rows.
  for (const marker of ['A1', 'B1', 'A2', 'false', 'blank']) assert.ok(html.includes(marker));
});

test('XLSX review detail binds the literal proposal and rejects invalid worksheet pages', async () => {
  const { parseXlsxProposal, isXlsxPagePath } = await import('../local-workspace/xlsx-governance.mjs');
  const cells = Array.from({ length: 51 }, (_, index) => ({ row: index + 1, column: 1, value: null }));
  for (const incompatible of [{ ...sheet, id: `csv:${id}` }, { ...sheet, cells, cell_range: 'A1:A51' },
    { ...sheet, cells: [sheet.cells[0], sheet.cells[0]] }, { ...sheet, cells: [{ ...sheet.cells[0], column: 3 }] },
    { ...sheet, cells: [{ ...sheet.cells[0], value: ['formula', '=SUM()'] }] }, { ...sheet, storage_key: 'opaque' }]) {
    assert.throws(() => parseXlsxProposal(incompatible, proposal));
  }
  assert.equal(isXlsxPagePath(`/xlsx/review/${encodeURIComponent(proposal)}`), true);
  assert.equal(isXlsxPagePath(`/xlsx/review/${proposal}`), false);
  assert.equal(isXlsxPagePath(`/xlsx/review/${encodeURIComponent(encodeURIComponent(proposal))}`), false);
  assert.equal(isXlsxPagePath(`/xlsx/knowledge/${id}`), true);
  assert.equal(isXlsxPagePath(`/xlsx/knowledge/${id}/evidence/${id}`), true);
  assert.equal(isXlsxPagePath(`/xlsx/knowledge/${id}/evidence/${id}/grant`), false);
});

test('XLSX decision requires confirmation and a stale snapshot cannot write again', async () => {
  const { decisionAttempt } = await import('../local-workspace/app/xlsx/client.mjs');
  const posts = [];
  const transport = async (path, options) => { posts.push({ path, options }); return reply({}, 409); };
  const signal = new AbortController().signal;
  const attempt = decisionAttempt(transport, proposal, 'proposed', signal, () => id);
  assert.equal(await attempt.confirm('approve'), null);
  attempt.choose('approve');
  assert.equal(await attempt.confirm('reject'), null);
  assert.equal(posts.length, 0);
  await assert.rejects(attempt.confirm('approve'), { status: 409 });
  attempt.choose('approve');
  assert.equal(await attempt.confirm('approve'), null);
  assert.equal(posts.length, 1);
  assert.match(posts[0].path, /xlsx%3A.+\/decision$/);
  assert.equal(posts[0].options.headers['idempotency-key'], id);
  assert.deepEqual(JSON.parse(posts[0].options.body), { decision: 'approve' });
});

test('stale XLSX review recovery offers only an explicit refresh', async () => {
  const { ReviewRecovery } = await import('../local-workspace/app/xlsx/review/recovery.tsx');
  const html = renderToStaticMarkup(createElement(ReviewRecovery, { status: 409, refresh() {} }));
  assert.match(html, /proposal changed/);
  assert.match(html, /Refresh proposal/);
  assert.doesNotMatch(html, /Approve|Reject|Confirm|Worksheet evidence/);
});

test('a retired XLSX decision snapshot cannot publish its delayed acknowledgement', async () => {
  const { decisionAttempt } = await import('../local-workspace/app/xlsx/client.mjs');
  const lifetime = new AbortController();
  let finish;
  const transport = async () => new Promise((resolve) => { finish = resolve; });
  const attempt = decisionAttempt(transport, proposal, 'proposed', lifetime.signal, () => id);
  attempt.choose('reject');
  const pending = attempt.confirm('reject');
  lifetime.abort();
  finish(reply({ id: proposal, decision: 'reject' }, 200));
  assert.equal(await pending, null);
});

test('XLSX published detail and evidence are separately authorized and exact-version bound', async () => {
  const { readPublishedRecord, readPublishedEvidence } = await import('../local-workspace/app/xlsx/client.mjs');
  const version = 'e50d72bc-5fa2-4891-b69b-c68225911a57';
  const summary = { record_id: id, source_version_id: version, node_id: 'team' };
  const evidenced = { ...summary, sheet_id: '1', sheet_title: 'Policy', cell_range: 'A1',
    cells: [{ row: 1, column: 1, value: ['text', 'authorized'] }], next_cursor: null };
  const log = [];
  const allowed = (body) => async (path, options) => { log.push([path, options]); return reply(body, 200); };
  assert.deepEqual(await readPublishedRecord(allowed(summary), id), summary);
  assert.deepEqual(await readPublishedEvidence(allowed(evidenced), id, version), evidenced);
  assert.deepEqual(log.map(([path]) => path), [`/api/bri-local/v1/knowledge/xlsx/${id}`, `/api/bri-local/v1/knowledge/xlsx/${id}/evidence/${version}`]);
  assert.ok(log.every(([, options]) => options.cache === 'no-store' && options.credentials === 'same-origin'));
  await assert.rejects(readPublishedEvidence(allowed({ ...evidenced, source_version_id: id }), id, version));
  await assert.rejects(readPublishedEvidence(async () => reply(evidenced, 404), id, version), { status: 404 });
});

test('protected XLSX read clears its snapshot before revalidation and ignores a retired receipt', async () => {
  const { authorizedRead } = await import('../local-workspace/app/xlsx/client.mjs');
  const states = [];
  const first = authorizedRead(async () => 'previous authorized evidence', (state) => states.push(state));
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(states.at(-1), { data: 'previous authorized evidence' });
  first();
  let finish;
  const late = authorizedRead(() => new Promise((resolve) => { finish = resolve; }), (state) => states.push(state));
  assert.equal(states.at(-1), null);
  late();
  const cancel = authorizedRead(async () => { throw Object.assign(new Error('Internal error'), { status: 404 }); }, (state) => states.push(state));
  finish('formerly visible evidence');
  await new Promise((resolve) => setImmediate(resolve));
  cancel();
  assert.deepEqual(states, [null, { data: 'previous authorized evidence' }, null, null, { error: 404 }]);
});

test('release bridge does not expose any local XLSX surface', async () => {
  const { buildBackendRequest, BackendRequestError } = await import('../src/lib/backend-proxy.mjs');
  const release = { BRI_API_ORIGIN: 'https://example.test', BRI_UI_AUTH_MODE: 'supabase' };
  const staged = { BRI_API_ORIGIN: 'http://127.0.0.1:8000', BRI_UI_DEV_IDENTITY: 'fixture-reader' };
  for (const config of [release, staged]) for (const [method, path] of [
    ['POST', '/v1/intake/xlsx'], ['GET', `/v1/intake/xlsx/${id}`], ['GET', '/v1/knowledge/proposals/xlsx'],
    ['GET', `/v1/knowledge/proposals/xlsx/${encodeURIComponent(proposal)}`],
    ['POST', `/v1/knowledge/proposals/xlsx/${encodeURIComponent(proposal)}/decision`],
    ['GET', `/v1/knowledge/xlsx/${id}`], ['GET', `/v1/knowledge/xlsx/${id}/evidence/${id}`],
  ]) assert.throws(() => buildBackendRequest(path, new URLSearchParams(), config, { method }),
    (error) => error instanceof BackendRequestError && error.status === 404);
});
