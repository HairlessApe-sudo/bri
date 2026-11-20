import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import ts from 'typescript';
import { getRouteMatcher } from 'next/dist/shared/lib/router/utils/route-matcher.js';
import { getRouteRegex } from 'next/dist/shared/lib/router/utils/route-regex.js';
import { prepareProxyRequest } from '../src/lib/backend-proxy.mjs';

registerHooks({
  resolve(specifier, context, next) {
    if (!context.parentURL?.endsWith('/page.tsx')) return next(specifier, context);
    if (specifier === 'next/link' || specifier === 'next/navigation' || specifier === '@/components/data-state') {
      return { url: `data:text/javascript,export default () => null; export const useParams = () => globalThis.publishedRecordParams; export const useRemote = globalThis.capturePublishedRecordRequest; export const PageHeading = () => null; export const StateMessage = () => null;`, shortCircuit: true };
    }
    if (specifier === '@/components/knowledge-detail-view' || specifier === '@/components/sources-detail-view') {
      return { url: 'data:text/javascript,export const KnowledgeDetailView = () => null; export const SourceDetailView = () => null;', shortCircuit: true };
    }
    if (specifier === '@/components/source-provenance') {
      return next(new URL('../src/components/source-provenance.tsx', import.meta.url).href, context);
    }
    return next(specifier, context);
  },
  load(url, context, next) {
    if (!url.endsWith('/source-provenance.tsx') && !url.endsWith('/page.tsx')) return next(url, context);
    const { outputText } = ts.transpileModule(readFileSync(new URL(url), 'utf8'), {
      compilerOptions: { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
    });
    return { format: 'module', source: outputText, shortCircuit: true };
  },
});

const { SourceProvenance } = await import('../src/components/source-provenance.tsx');
const render = (source, showLegacyDigest = false) => renderToStaticMarkup(createElement(SourceProvenance, { source, showLegacyDigest }));
const legacy = { content_sha256: 'a'.repeat(64) };
const csv = { ...legacy, original_sha256: 'b'.repeat(64), csv_first_line: 2, csv_last_line: 5 };

test('published record pages send canonical encoded IDs through the proxy', async (t) => {
  const recordId = 'csv:01234567-89ab-4def-8123-456789abcdef';
  const matchProxy = getRouteMatcher(getRouteRegex('/api/bri/[...path]'));
  const matchPage = (section) => getRouteMatcher(getRouteRegex(`/${section}/[recordId]`));
  const env = { BRI_UI_AUTH_MODE: 'supabase', BRI_API_ORIGIN: 'https://api.example.test' };
  const capture = t.mock.fn(() => ({ data: null, loading: true }));
  globalThis.capturePublishedRecordRequest = capture;
  t.after(() => {
    delete globalThis.capturePublishedRecordRequest;
    delete globalThis.publishedRecordParams;
  });

  for (const section of ['knowledge', 'sources']) {
    const encodedId = 'csv%3A01234567-89ab-4def-8123-456789abcdef';
    globalThis.publishedRecordParams = matchPage(section)(`/${section}/${encodedId}`);
    assert.deepEqual({ ...globalThis.publishedRecordParams }, { recordId });
    const { default: Page } = section === 'knowledge'
      ? await import('../src/app/(workspace)/knowledge/%5BrecordId%5D/page.tsx')
      : await import('../src/app/(workspace)/sources/%5BrecordId%5D/page.tsx');
    Page();
    const [url] = capture.mock.calls.at(-1).arguments;
    assert.equal(url, `/api/bri/v1/${section}/${encodedId}`);
    const { path } = matchProxy(url);
    const result = await prepareProxyRequest(new Request(`https://ui.example.test${url}`), `/${path.join('/')}`, env, async () => 'fixture-session');
    assert.equal(result.url, `${env.BRI_API_ORIGIN}/v1/${section}/${recordId}`);
  }
});

test('published CSV provenance distinguishes the digests and labels inclusive physical lines', () => {
  const html = render({ ...csv, object_key: 'private-object-key', storage_path: '/quarantine/private.csv' });
  assert.match(html, new RegExp(`Original CSV bytes SHA-256</dt><dd[^>]*>${csv.original_sha256}`));
  assert.match(html, new RegExp(`Extracted content SHA-256</dt><dd[^>]*>${csv.content_sha256}`));
  assert.match(html, /Physical CSV lines \(inclusive\)<\/dt><dd[^>]*>2–5<\/dd>/);
  assert.match(render({ ...csv, csv_last_line: 2 }), /<dd>2<\/dd>/);
  assert.doesNotMatch(html, /private-object-key|quarantine|href=|<button|<form/);
});

test('legacy and null fields do not add CSV provenance', () => {
  for (const source of [legacy, { ...legacy, original_sha256: null, csv_first_line: null, csv_last_line: null }]) {
    assert.equal(render(source), '');
    const html = render(source, true);
    assert.match(html, new RegExp(`Content SHA-256</dt><dd[^>]*>${legacy.content_sha256}`));
    assert.doesNotMatch(html, /CSV|Extracted content/);
  }
});

test('only a well-formed original digest and complete valid line ranges are displayed', () => {
  assert.equal(render({ ...legacy, original_sha256: '/quarantine/private.csv' }), '');
  assert.match(render({ ...legacy, original_sha256: csv.original_sha256 }), /Original CSV bytes/);
  assert.match(render({ ...legacy, csv_first_line: 2, csv_last_line: 5 }), /Physical CSV lines/);
  for (const range of [
    { csv_first_line: 2 }, { csv_last_line: 5 }, { csv_first_line: 0, csv_last_line: 2 },
    { csv_first_line: 5, csv_last_line: 2 }, { csv_first_line: 2.5, csv_last_line: 5 },
    { csv_first_line: '2', csv_last_line: 5 },
  ]) {
    assert.doesNotMatch(render({ ...legacy, original_sha256: csv.original_sha256, ...range }), /Physical CSV lines/);
  }
});
