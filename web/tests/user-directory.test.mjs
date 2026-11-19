import test from 'node:test';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import { readFileSync } from 'node:fs';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import ts from 'typescript';

// Render the actual TSX without requiring a Next server or a provider session.
registerHooks({
  resolve(specifier, context, next) {
    if (specifier === 'next/server') return next('next/server.js', context);
    if (specifier === '@/lib/supabase/server') {
      return { url: 'data:text/javascript,export const createSupabaseServerClient = () => globalThis.directoryTestSession()', shortCircuit: true };
    }
    if (specifier.startsWith('@/')) {
      const path = specifier.slice(2);
      for (const extension of ['', '.ts', '.tsx']) {
        try { return next(new URL(`../src/${path}${extension}`, import.meta.url).href, context); }
        catch (error) { if (error.code !== 'ERR_MODULE_NOT_FOUND') throw error; }
      }
    }
    return next(specifier, context);
  },
  load(url, context, next) {
    if (!/\.tsx?$/.test(url)) return next(url, context);
    const { outputText } = ts.transpileModule(readFileSync(new URL(url), 'utf8'), {
      compilerOptions: { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.ESNext },
    });
    return { format: 'module', source: outputText, shortCircuit: true };
  },
});

const api = await import('../src/lib/user-directory.mjs');
const { fetchApi } = await import('../src/lib/api.ts');
const route = await import('../src/app/api/bri/%5B...path%5D/route.ts');
const { DirectoryList, DirectoryDetail } = await import('../src/components/user-directory-view.tsx');
const id = '00000000-0000-4000-8000-000000000001';
const user = { id, display_name: null, status: 'pending', role: 'superuser', mfa_status: 'unknown' };
const listPath = '/api/bri/v1/users';
const render = (Component, props) => renderToStaticMarkup(createElement(Component, props));

test('directory list search and pagination produce only same-origin GET endpoints', () => {
  assert.equal(api.directoryListPath('', 0), listPath);
  assert.equal(api.directoryListPath('  A&B? #+  ', 25), `${listPath}?q=A%26B%3F+%23%2B&offset=25`);
  assert.equal(api.directoryListPath('', 50), `${listPath}?offset=50`);
  assert.equal(api.directoryDetailPath(id), `${listPath}/${id}`);
  assert.throws(() => api.directoryDetailPath(`${id}?tenant_id=x`), /Invalid user ID/);
});

test('directory list shows safe fields and opens detail for the selected UUID', () => {
  let selected;
  const props = { data: { items: [user], has_more: true }, offset: 0, onSelect: (id) => { selected = id; } };
  const html = render(DirectoryList, props);
  assert.match(html, /Unnamed user/);
  assert.match(html, /Pending/);
  assert.match(html, /Superuser/);
  assert.match(html, /Unknown/);
  assert.match(html, /<button[^>]+disabled[^>]*>Previous/);
  assert.match(html, /<button(?![^>]*disabled)[^>]*>Next/);
  function findButton(element, text) {
    if (!element || typeof element !== 'object') return;
    if (element.type === 'button' && element.props.children === text) return element;
    if (Array.isArray(element)) return element.map((child) => findButton(child, text)).find(Boolean);
    return findButton(element.props?.children, text);
  }
  findButton(DirectoryList(props), 'Unnamed user').props.onClick();
  assert.equal(selected, id);
});

test('directory pagination follows has_more, with a way back from an empty later page', () => {
  const props = { data: { items: [], has_more: false }, offset: 25 };
  const html = render(DirectoryList, props);
  assert.match(html, /No users found/);
  assert.match(html, /Page 2/);
  assert.match(html, /<button(?![^>]*disabled)[^>]*>Previous/);
  assert.match(html, /<button[^>]+disabled[^>]*>Next/);
  const limitHtml = render(DirectoryList, { ...props, offset: 10000, data: { items: [user], has_more: true } });
  assert.match(limitHtml, /<button[^>]+disabled[^>]*>Next/);
  assert.match(limitHtml, /Refine your search/);
});

test('directory detail renders the detail response rather than relying on the list record', () => {
  const html = render(DirectoryDetail, { data: { ...user, display_name: 'Detail fixture', status: 'active', role: 'user', mfa_status: 'verified' } });
  for (const value of ['Detail fixture', 'Active', 'User', 'Verified', id, 'Back to directory']) assert.ok(html.includes(value));
});

test('directory distinguishes loading, authentication, denied, missing user, and failure without reflecting error text', () => {
  assert.match(render(DirectoryList, { loading: true, offset: 0 }), /role="status"[^]*Loading/);
  for (const [status, message] of [[401, 'Verified session required'], [403, 'Access denied'], [404, 'User not found'], [503, 'Could not load the directory']]) {
    const html = render(DirectoryDetail, { error: Object.assign(new Error('sensitive failure text'), { status }) });
    assert.ok(html.includes(message));
    assert.match(html, /role="alert"/);
    assert.doesNotMatch(html, /sensitive failure text/);
  }
});

test('Next dev request logging omits directory search and detail URLs', async () => {
  const config = (await import('../next.config.ts')).default;
  const rules = config.logging?.incomingRequests?.ignore ?? [];
  for (const url of [`${listPath}?q=private`, `${listPath}/${id}`, `/users?q=private`, `/api/bri/v1/%75sers/${id}`]) {
    assert.ok(rules.some((rule) => rule.test(url)), `Missing logging exclusion for a directory URL`);
  }
});

test('directory client and Next handler read list and detail through the same-origin boundary', async (t) => {
  const previousMode = process.env.BRI_UI_AUTH_MODE;
  const previousOrigin = process.env.BRI_API_ORIGIN;
  process.env.BRI_UI_AUTH_MODE = 'supabase';
  process.env.BRI_API_ORIGIN = 'https://api.example.test';
  globalThis.directoryTestSession = async () => ({ auth: {
    getSession: async () => ({ data: { session: { access_token: 'fixture-server-token' } }, error: null }),
    getClaims: async () => ({ data: { claims: { sub: id, aal: 'aal2' } }, error: null }),
  } });
  t.after(() => {
    for (const [key, value] of [['BRI_UI_AUTH_MODE', previousMode], ['BRI_API_ORIGIN', previousOrigin]]) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    delete globalThis.directoryTestSession;
  });
  const seen = [];
  let failureStatus;
  t.mock.method(globalThis, 'fetch', async (input, init) => {
    if (input.startsWith('/')) {
      assert.equal(init.headers.authorization, undefined);
      const url = new URL(input, 'https://ui.example.test');
      const result = await route.GET(new Request(url, init), { params: Promise.resolve({ path: url.pathname.split('/').slice(3) }) });
      assert.match(result.headers.get('cache-control'), /no-store/);
      return result;
    }
    seen.push(input);
    assert.equal(init.method, 'GET');
    assert.deepEqual(init.headers, { authorization: 'Bearer fixture-server-token' });
    assert.equal(init.redirect, 'manual');
    assert.equal(init.cache, 'no-store');
    if (failureStatus) return Response.json({ detail: 'sensitive upstream text' }, { status: failureStatus });
    const detail = input.endsWith(`/${id}`);
    return Response.json(detail ? { ...user, display_name: 'Detail fixture' } : { items: [user], has_more: true });
  });
  const page = await fetchApi(api.directoryListPath('A&B', 25));
  const detail = await fetchApi(api.directoryDetailPath(page.items[0].id));
  assert.deepEqual(page, { items: [user], has_more: true });
  assert.deepEqual(detail, { ...user, display_name: 'Detail fixture' });
  assert.deepEqual(seen, [`https://api.example.test/v1/users?q=A%26B&offset=25`, `https://api.example.test/v1/users/${id}`]);
  for (failureStatus of [401, 403, 404, 503]) {
    const url = `https://ui.example.test${listPath}/${id}`;
    const result = await route.GET(new Request(url), { params: Promise.resolve({ path: ['v1', 'users', id] }) });
    assert.equal(result.status, failureStatus);
    assert.doesNotMatch(await result.text(), /sensitive upstream text/);
  }
});
