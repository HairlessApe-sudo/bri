import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import ts from 'typescript';
import { composeLocalWorkspace } from '../local-workspace/bridge.mjs';

// Render the actual pages and controls, substituting state at the async read seam.
const workspace = new URL('../local-workspace/', import.meta.url);
const fixtureKey = Symbol.for('bri.test.local-review-mode');
const fixture = globalThis[fixtureKey] = {};
const state = `const fixture = globalThis[Symbol.for('bri.test.local-review-mode')];`;
const mocks = {
  'next/headers': `${state} export async function headers() { return new Headers(fixture.headers); }`,
  'next/navigation': `${state} export function useParams() { return fixture.params; }`,
  'server-only': '',
  'bri:test/csv-read': `${state}
    export { PageHeading, StateMessage } from '${new URL('../src/components/data-state.tsx', import.meta.url)}';
    export function useRemote(_path, _key, decode) { return fixture.native === null ? { error: Object.assign(new Error(), { status: 403 }) } : { data: decode(fixture.native) }; }`,
  'bri:test/xlsx-read': `${state}
    export { XlsxError, PageButtons } from '${new URL('app/xlsx/read.tsx', workspace)}';
    export function useXlsxRead(_path, decode) { return fixture.native === null ? {error: 403} : {data: decode(fixture.native)}; }
    export function useAuthorizedRead() { return fixture.discovery[fixture.reads++]; }`,
};
registerHooks({
  resolve(specifier, context, next) {
    if (specifier === '@/components/data-state') specifier = 'bri:test/csv-read';
    else if (context.parentURL?.startsWith(workspace.href) && ['../xlsx/read', '../../read'].includes(specifier)) specifier = 'bri:test/xlsx-read';
    if (Object.hasOwn(mocks, specifier)) return { url: specifier, shortCircuit: true };
    if (specifier.startsWith('@/')) specifier = new URL(`../src/${specifier.slice(2)}`, import.meta.url).href;
    if ((specifier.startsWith('.') || specifier.startsWith('file:')) && !/\.[cm]?[jt]sx?$/.test(specifier)) {
      for (const extension of ['.ts', '.tsx']) {
        try { return next(`${specifier}${extension}`, context); }
        catch (error) { if (error.code !== 'ERR_MODULE_NOT_FOUND') throw error; }
      }
    }
    return next(specifier, context);
  },
  load(url, context, next) {
    if (Object.hasOwn(mocks, url)) return { format: 'module', shortCircuit: true, source: mocks[url] };
    if (!/\.tsx?$/.test(url)) return next(url, context);
    return { format: 'module', shortCircuit: true, source: ts.transpileModule(readFileSync(new URL(url), 'utf8'), {
      compilerOptions: { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
    }).outputText };
  },
});

async function route(path) {
  const Page = (await import(new URL(`${path}/page.tsx`, workspace))).default;
  const url = new URL(`${path}/layout.tsx`, workspace);
  // The held export has no detail layouts. Render its page under its original identity layout.
  const Layout = existsSync(url) ? (await import(url)).default : ({ children }) => children;
  return async () => renderToStaticMarkup(await Layout({ children: createElement(Page) }));
}
const csv = await route('app/review/[proposalId]');
const xlsx = await route('app/xlsx/review/[id]');
const uuid = '01234567-89ab-4def-8123-456789abcdef';
const node_id = 'team';
const created_at = '2026-11-01T00:00:00.001+00:00';
const id = `csv:${uuid}`;
const native = {
  csv: { id, state: 'proposed', node_id, created_at,
    provenance: { source_id: id, source_version_id: id, source_version: '1', extraction_id: id,
      original_sha256: 'a'.repeat(64), content_sha256: 'b'.repeat(64), csv_first_line: 1, csv_last_line: 1 },
    evidence: 'fixture', next_evidence_offset: null, history: [{ event: 'proposed', occurred_at: created_at, reason: null }] },
  xlsx: { id: `xlsx:${uuid}`, state: 'proposed', node_id, sheet_id: '1', sheet_title: 'Evidence', cell_range: 'A1',
    cells: [{ row: 1, column: 1, value: ['text', 'fixture'] }], next_cursor: null },
};
const modeKey = 'BRI_LOCAL_METADATA_ENABLED';
const origin = '127.0.0.2:3013';
const controls = /Approve…|Reject…|Approve as proposed|Correct and approve/;

function request(format, forgedMode) {
  const segment = encodeURIComponent(native[format].id);
  fixture.params = format === 'csv' ? { proposalId: segment } : { id: segment };
  const headers = { host: origin, 'x-bri-local-review-mode': forgedMode };
  return { method: 'GET', url: `${format === 'csv' ? '' : '/xlsx'}/review/${segment}`, headers,
    rawHeaders: ['Host', origin, 'X-BRI-Local-Review-Mode', forgedMode],
    socket: { localAddress: '127.0.0.2', localPort: 3013, remoteAddress: '127.0.0.1' } };
}

function compose(mode) {
  const original = process.env[modeKey];
  const nodeEnv = process.env.NODE_ENV;
  try {
    process.env.NODE_ENV = 'development';
    if (mode === undefined) delete process.env[modeKey];
    else process.env[modeKey] = mode;
    return composeLocalWorkspace(async (req, res) => {
      fixture.headers = req.headers;
      res.html = await (req.url.startsWith('/xlsx') ? xlsx : csv)();
    });
  } finally {
    if (original === undefined) delete process.env[modeKey];
    else process.env[modeKey] = original;
    if (nodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = nodeEnv;
  }
}

async function render(handler, format, { forgedMode, discovery = [], proposal = native[format] }) {
  Object.assign(fixture, { reads: 0, discovery, native: proposal });
  const res = { setHeader() {} };
  const original = process.env.NODE_ENV;
  try {
    process.env.NODE_ENV = 'development';
    await handler(request(format, forgedMode), res);
  } finally {
    if (original === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = original;
  }
  return res.html;
}

for (const format of ['csv', 'xlsx']) {
  test(`${format} startup with no metadata opt-in renders native pending controls without discovery`, async () => {
    const html = await render(compose(undefined), format, { forgedMode: 'enabled', discovery: [{ error: 404 }] });
    assert.match(html, /Approve…/);
    assert.match(html, /Reject…/);
    assert.equal(fixture.reads, 0);
  });

  test(`${format} startup with explicit metadata off still gates native controls on authorized pending detail`, async () => {
    const handler = compose('0');
    assert.match(await render(handler, format, { forgedMode: 'enabled' }), /Approve…/);
    for (const proposal of [null, { ...native[format], state: 'approved' }]) {
      assert.doesNotMatch(await render(handler, format, { forgedMode: 'enabled', proposal }), controls);
      assert.equal(fixture.reads, 0);
    }
  });

  test(`${format} startup with metadata enabled never falls back on unsuccessful discovery`, async () => {
    const handler = compose('1');
    for (const error of [401, 403, 404, 502, 503]) {
      assert.doesNotMatch(await render(handler, format, { forgedMode: 'disabled', discovery: [{ error }] }), controls);
      assert.equal(fixture.reads, 1);
    }
  });

  test(`${format} startup with metadata enabled distinguishes classified from explicitly unclassified`, async () => {
    const handler = compose('1');
    const data = { job_id: uuid, node_id, proposed_metadata: null };
    assert.match(await render(handler, format, { forgedMode: 'disabled', discovery: [{ data }] }), /Approve…/);
    const proposed_metadata = { version: 1, title: 'Classified fixture', description: null, primary_classification_id: 'policy',
      additional_classification_ids: [], effective_date: null, review_date: null, expiry_date: null };
    const html = await render(handler, format, { forgedMode: 'disabled', discovery: [{ data: { ...data, proposed_metadata } }, { data: [] }] });
    assert.match(html, /Classified fixture/);
    assert.match(html, /Approve as proposed/);
    assert.doesNotMatch(html, />Approve…<|XLSX review decision/);
  });
}

test('invalid local metadata startup configuration fails closed', () => {
  for (const invalid of ['', 'true', '01', ' 0']) assert.throws(() => compose(invalid), /BRI_LOCAL_METADATA_ENABLED/);
});
