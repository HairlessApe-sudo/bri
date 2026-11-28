import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import ts from 'typescript';
import * as client from '../local-workspace/app/classification/client.mjs';

registerHooks({
  load(url, context, next) {
    if (!url.endsWith('.tsx')) return next(url, context);
    return { format: 'module', shortCircuit: true, source: ts.transpileModule(readFileSync(new URL(url), 'utf8'), {
      compilerOptions: { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
    }).outputText };
  },
});

const metadata = {
  version: 1, title: 'First title', description: null, primary_classification_id: 'policy',
  additional_classification_ids: ['technical', 'financial'], effective_date: '2024-02-29', review_date: null, expiry_date: null,
};

test('metadata input canonicalizes additional classes without altering title or dates', () => {
  assert.deepEqual(client.metadataInput(metadata), { ...metadata, additional_classification_ids: ['financial', 'technical'] });
});

test('classified submission is raw XLSX with an exact authorized node and UTF-8 metadata header', async () => {
  const file = new File(['synthetic'], 'fixture.xlsx');
  const signal = new AbortController().signal;
  const receipt = await client.uploadClassifiedWorkbook(async (url, init) => {
    assert.equal(url, '/api/bri-local/v1/knowledge-metadata/xlsx/uploads');
    assert.equal(init.method, 'POST');
    assert.equal(init.body, file);
    assert.equal(init.cache, 'no-store');
    assert.equal(init.mode, 'same-origin');
    assert.equal(init.signal, signal);
    assert.equal(init.headers['x-node-id'], 'synthetic:node');
    assert.deepEqual(JSON.parse(Buffer.from(init.headers['x-bri-metadata'], 'base64url').toString('utf8')),
      { ...metadata, title: 'Évidence', additional_classification_ids: ['financial', 'technical'] });
    return Response.json({ id: record, state: 'ready' }, { status: 202 });
  }, file, 'synthetic:node', record, { ...metadata, title: 'Évidence' }, signal);
  assert.deepEqual(receipt, { id: record, state: 'ready' });
});

const record = '398da094-fba0-45f6-ac61-e319e15bd585';
const version = '26a5541e-19d0-4091-8c04-f961b0210939';
const row = { category_id: 'governance', category_label: 'Governance', classification_id: 'policy', label: '<Policy>', description: null, retired: true };

test('selection rejects retired and duplicate options; main catalogue preserves retired labels as text', async () => {
  const signal = new AbortController().signal;
  const transport = async () => Response.json([row]);
  await assert.rejects(client.readSelection(transport, 'xlsx_submit', 'scope', signal));
  assert.deepEqual(await client.readAdminCatalogue(transport, signal), [row]);
  const active = { ...row, retired: false };
  assert.deepEqual(await client.readSelection(async () => Response.json([active]), 'xlsx_submit', 'scope', signal), [active]);
  await assert.rejects(client.readSelection(async () => Response.json([active, active]), 'xlsx_submit', 'scope', signal));
});

test('selection uses the exact literal source node and never dispatches encoded aliases', async () => {
  const signal = new AbortController().signal;
  await client.readSelection(async (url) => {
    assert.equal(url, '/api/bri-local/v1/knowledge-metadata/catalogue/selection/xlsx_submit/node:exact');
    return Response.json([]);
  }, 'xlsx_submit', 'node:exact', signal);
  await assert.rejects(client.readSelection(assert.fail, 'xlsx_submit', 'node%3Aexact', signal), { status: 422 });
  await assert.rejects(client.readSelection(assert.fail, 'metadata_propose', 'node:exact', signal));
});

test('exact-version receipts distinguish unclassified from denial and reject switched targets or leaked fields', async () => {
  const signal = new AbortController().signal;
  const body = { record_id: record, source_version_id: version, metadata: null };
  const run = (value, status = 200) => client.readValidatedMetadata(async (url) => {
    assert.equal(url, `/api/bri-local/v1/knowledge-metadata/csv/records/${record}/versions/${version}`);
    return Response.json(value, { status });
  }, 'csv', `csv:${record}`, `csv:${version}`, signal);
  assert.deepEqual(await run(body), body);
  await assert.rejects(run(body, 403), { status: 403 });
  await assert.rejects(run({ ...body, source_version_id: record }));
  await assert.rejects(run({ ...body, proposed_metadata: metadata }));
});

test('correction proposal uses the exact opaque CAS revision without rounding or silent retry', async () => {
  const signal = new AbortController().signal;
  const revision = '9007199254740993';
  let calls = 0;
  const transport = async (url, init) => {
    assert.equal(url, `/api/bri-local/v1/knowledge-metadata/xlsx/records/${record}/versions/${version}/corrections`);
    calls++;
    assert.equal(JSON.parse(init.body).expected_revision, revision);
    return new Response(null, { status: 409 });
  };
  await assert.rejects(client.proposeCorrection(transport, 'xlsx', record, version, revision, record, metadata, signal), { status: 409 });
  assert.equal(calls, 1);
  await assert.rejects(client.proposeCorrection(transport, 'xlsx', record, version, '092', record, metadata, signal));
  assert.equal(calls, 1);
});

test('correction proposal accepts a distinct server-issued UUID and binds the exact target and revision', async () => {
  const signal = new AbortController().signal;
  const key = '105389df-2f63-45c1-ac7c-ee76996fd462';
  const proposal = '1e890d7e-6189-4fcf-86c4-079482aac140';
  const body = { record_id: record, source_version_id: version, expected_revision: '1', proposal_id: proposal };
  for (const fmt of ['csv', 'xlsx']) {
    const run = (response) => client.proposeCorrection(async (_url, init) => {
      assert.equal(JSON.parse(init.body).request_id, key);
      return Response.json(response);
    }, fmt, record, version, '1', key, metadata, signal);
    assert.deepEqual(await run(body), body);
    await assert.rejects(run({ ...body, proposal_id: 'not-a-uuid' }));
    await assert.rejects(run({ ...body, expected_revision: '2' }));
    await assert.rejects(run({ ...body, source_version_id: record }));
  }
});

test('initial review binds proposed metadata to the existing native proposal and sends an atomic correction only on approval', async () => {
  const signal = new AbortController().signal;
  const base = `/api/bri-local/v1/knowledge-metadata/csv/review/${record}`;
  const original = { job_id: record, node_id: 'node', proposed_metadata: metadata };
  const read = (value) => client.readInitialMetadata(async (url) => {
    assert.equal(url, base);
    return Response.json(value);
  }, 'csv', `csv:${record}`, signal);
  assert.equal((await read(original)).proposed_metadata.title, 'First title');
  assert.equal((await read({ ...original, proposed_metadata: null })).proposed_metadata, null);
  await assert.rejects(read({ ...original, job_id: version }));
  const transport = async (url, init) => {
    assert.equal(url, `${base}/decision`);
    assert.deepEqual(JSON.parse(init.body), { action: 'approve', request_id: version, metadata: {
      ...metadata, title: 'Corrected', additional_classification_ids: ['financial', 'technical'],
    } });
    return Response.json({ job_id: record, decision: 'approve', metadata_revision: '1' });
  };
  await client.decideInitialMetadata(transport, 'csv', `csv:${record}`, 'approve', version, { ...metadata, title: 'Corrected' }, signal);
  await assert.rejects(client.decideInitialMetadata(assert.fail, 'csv', `csv:${record}`, 'reject', version, metadata, signal));
});

test('aborted classification request ignores a late response body', async () => {
  const controller = new AbortController();
  const transport = async () => ({ status: 200, async json() { controller.abort(); return []; } });
  await assert.rejects(client.readAdminCatalogue(transport, controller.signal), { name: 'AbortError' });
});

test('correction inspection rejects another or looping page and validates bounded pending metadata', async () => {
  const signal = new AbortController().signal;
  const valid = { proposal_id: version, expected_revision: '0', proposed_metadata: metadata };
  const after = '105389df-2f63-45c1-ac7c-ee76996fd462';
  const path = `/api/bri-local/v1/knowledge-metadata/xlsx/records/${record}/versions/${version}/corrections?after=${after}`;
  const read = (value) => client.readCorrections(async (url) => {
    assert.equal(url, path);
    return Response.json(value);
  }, 'xlsx', record, version, after, signal);
  assert.equal((await read({ items: [valid], next_after: null })).items[0].expected_revision, '0');
  await assert.rejects(read({ items: [valid], next_after: record }));
  await assert.rejects(read({ items: [valid, valid], next_after: null }));
});

test('retired associations display as escaped historical text and cannot appear in selection controls', async () => {
  const { MetadataFields, MetadataValues } = await import('../local-workspace/app/classification/fields.tsx');
  const title = '<script>not executable</script>';
  const proposal = { ...metadata, title };
  const description = renderToStaticMarkup(createElement(MetadataValues, { metadata: proposal, classes: [row] }));
  assert.match(description, /&lt;script&gt;not executable&lt;\/script&gt;/);
  assert.match(description, /&lt;Policy&gt;.*<code>policy<\/code> \(retired\)/);
  const active = { ...row, classification_id: 'technical', label: 'Technical', retired: false };
  const form = renderToStaticMarkup(createElement(MetadataFields, { options: [row, active], initial: proposal }));
  assert.match(form, /<option value="technical"/);
  assert.doesNotMatch(form, /<option value="policy"/);
  assert.doesNotMatch(form, /<script>/);
});

test('approval of a correction accepts only the next exact revision and never sends authority or replacement metadata', async () => {
  const signal = new AbortController().signal;
  const proposal = { proposal_id: version, expected_revision: '9007199254740993', proposed_metadata: metadata };
  const response = (revision) => async (url, options) => {
    assert.equal(url, `/api/bri-local/v1/knowledge-metadata/xlsx/records/${record}/versions/${version}/corrections/${version}/decision`);
    assert.deepEqual(JSON.parse(options.body), { action: 'approve', request_id: record });
    return Response.json({ record_id: record, source_version_id: version, proposal_id: version, decision: 'approve', metadata_revision: revision });
  };
  const decide = (revision) => client.decideCorrection(response(revision), 'xlsx', record, version, proposal, 'approve', record, signal);
  await assert.rejects(decide('9007199254740993'));
  await assert.rejects(decide(9007199254740994));
  assert.equal((await decide('9007199254740994')).metadata_revision, '9007199254740994');
});

test('metadata input rejects extra properties, invalid calendar dates, duplicate classes and excess UTF-8 bytes', () => {
  for (const patch of [{ node: 'scope' }, { expiry_date: '2023-02-29' }, { additional_classification_ids: ['policy'] },
    { additional_classification_ids: ['technical', 'technical'] }, { title: '😀'.repeat(41) }, { title: '   ' }]) {
    assert.throws(() => client.metadataInput({ ...metadata, ...patch }));
  }
});
