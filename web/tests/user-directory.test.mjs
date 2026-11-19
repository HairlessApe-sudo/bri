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
      compilerOptions: { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
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

test('only a successful directory list shows the disabled Create User entry', () => {
  const props = { offset: 0, data: { items: [], has_more: false } };
  const html = render(DirectoryList, props);
  assert.match(html, /<fieldset disabled[^>]*>/);
  assert.match(html, /Display name/);
  assert.match(html, /Email/);
  assert.match(html, /<button[^>]+type="button"[^>]*>Create user/);
  assert.match(html, /A safe invitation and account setup flow is not available/);
  assert.doesNotMatch(html, /<form|type="password"|name="(?:role|tenant_id)"/);
  for (const state of [{ data: null }, { loading: true }, { error: Object.assign(new Error(), { status: 403 }) }]) {
    assert.doesNotMatch(render(DirectoryList, { ...props, ...state }), /Create user/);
  }
});

test('Create User validates locally and sends only the normalized provisioning contract', async () => {
  const { CreateUserForm, createProvisioningFlow } = await import('../src/components/create-user-form.tsx');
  const calls = [];
  let view;
  const transport = async (path, init) => {
    calls.push([path, init.method, JSON.parse(init.body), init.headers]);
    return Response.json({ id, status: 'pending_setup' });
  };
  const html = render(CreateUserForm, { transport });
  assert.deepEqual([...html.matchAll(/<input[^>]*name="([^"]+)"/g)].map((m) => m[1]), ['display_name', 'email']);
  assert.match(html, /<button[^>]+type="submit"[^>]*>Create user/);
  assert.doesNotMatch(html, /Check status|Last confirmed status/);
  const flow = createProvisioningFlow(transport, (next) => { view = next; });
  await flow.submit('  ', 'fixture@example.test');
  assert.match(view.error, /display name/i);
  await flow.submit('a'.repeat(129), 'fixture@example.test');
  assert.match(view.error, /display name/i);
  for (const invalidEmail of ['a@', 'a<bad>@example.test', 'a@tést.invalid']) {
    await flow.submit('Fixture', invalidEmail);
    assert.match(view.error, /email/i);
  }
  assert.deepEqual(calls, []);
  await flow.submit('  Fixture Name  ', '  Fixture@example.test  ');
  assert.equal(calls.length, 1);
  const requestId = calls[0][2].request_id;
  assert.match(requestId, /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/);
  assert.deepEqual(calls[0], ['/v1/users/provisioning', 'POST', { request_id: requestId, display_name: 'Fixture Name', email: 'Fixture@example.test' }, { 'Content-Type': 'application/json' }]);
  assert.deepEqual(view.receipt, { id, status: 'pending_setup' });
  assert.equal(view.error, undefined);
});

test('an unacknowledged Create User request is retried explicitly with the original body and ID', async () => {
  const { createProvisioningFlow } = await import('../src/components/create-user-form.tsx');
  const calls = [];
  let rejectPost;
  let view;
  const flow = createProvisioningFlow((path, init) => {
    calls.push([path, init.method, init.body]);
    return calls.length === 1 ? new Promise((_, reject) => { rejectPost = reject; })
      : Promise.resolve(Response.json({ id, status: 'inviting' }));
  }, (next) => { view = next; });
  const first = flow.submit('Fixture', 'fixture@example.test');
  await flow.submit('Duplicate click', 'other@example.test');
  await flow.checkStatus();
  assert.equal(calls.length, 1);
  rejectPost(new Error('private upstream message'));
  await first;
  assert.equal(calls.length, 1);
  assert.equal(view.receipt, undefined);
  assert.match(view.error, /Could not confirm the request/);
  assert.doesNotMatch(view.error, /private upstream message/);
  await flow.submit('Changed name', 'changed@example.test');
  assert.deepEqual(calls, [calls[0], calls[0]]);
  assert.equal(view.receipt.status, 'inviting');
  await flow.submit('Fixture', 'fixture@example.test');
  assert.equal(calls.length, 2);
});

test('manual status checks use the submitted request key and validate the distinct returned user ID', async () => {
  const { createProvisioningFlow, provisioningStatusCopy } = await import('../src/components/create-user-form.tsx');
  const statuses = {
    pending_setup: /not active/, inviting: /not been confirmed/, invitation_sent: /not active/,
    invitation_retryable: /retryable/, invitation_unresolved: /outcome unknown/, active: /^Active/,
  };
  assert.deepEqual(Object.keys(provisioningStatusCopy), Object.keys(statuses));
  const replies = Object.keys(statuses).map((status) => Response.json({ id, status }));
  replies.push(
    Response.json({ id, status: 'ACTIVE' }),
    Response.json({ id, status: 'active', email: 'hidden@example.test' }),
    Response.json({ id: '00000000-0000-4000-8000-000000000099', status: 'pending_setup' }),
    Response.json({ id: `${id}/extra`, status: 'active' }),
    Response.json({ detail: 'hidden@example.test' }, { status: 403 }),
  );
  const calls = [];
  let view;
  const flow = createProvisioningFlow(async (path, init) => { calls.push([path, init]); return replies.shift(); }, (next) => { view = next; });
  await flow.submit('Fixture', 'fixture@example.test');
  assert.equal(calls.length, 1); // No automatic GET.
  for (const [status, wording] of Object.entries(statuses)) {
    assert.equal(view.receipt.status, status);
    assert.match(provisioningStatusCopy[status], wording);
    if (status !== 'active') await flow.checkStatus();
  }
  while (replies.length) {
    await flow.checkStatus();
    assert.deepEqual(view.receipt, { id, status: 'active' });
    assert.match(view.error, /Could not check the current status/);
    assert.doesNotMatch(view.error, /hidden@example.test/);
  }
  const { request_id: requestKey } = JSON.parse(calls[0][1].body);
  assert.notEqual(requestKey, id);
  assert.deepEqual(calls.slice(1), Array.from({ length: 10 }, () => [`/v1/users/provisioning/${requestKey}`, { method: 'GET' }]));
});

test('directory detail renders the detail response rather than relying on the list record', () => {
  const html = render(DirectoryDetail, { data: { ...user, display_name: 'Detail fixture', status: 'active', role: 'user', mfa_status: 'verified' } });
  for (const value of ['Detail fixture', 'Active', 'User', 'Verified', id, 'Back to directory']) assert.ok(html.includes(value));
  assert.match(html, /Lifecycle changes are disabled in this release/);
  assert.doesNotMatch(html, /<form|<input|<select|>Suspend<|>Reactivate<|>Edit display name</);
});

test('directory distinguishes loading, authentication, denied, missing user, and failure without reflecting error text', () => {
  assert.match(render(DirectoryList, { loading: true, offset: 0 }), /role="status"[^]*Loading/);
  for (const [status, message] of [[401, 'Verified session required'], [403, 'Access denied'], [404, 'User not found'], [503, 'Could not load the directory']]) {
    const html = render(DirectoryDetail, { error: Object.assign(new Error('sensitive failure text'), { status }) });
    assert.ok(html.includes(message));
    assert.match(html, /role="alert"/);
    assert.doesNotMatch(html, /sensitive failure text|Lifecycle changes are disabled/);
  }
});

const lifecyclePath = `/v1/users/${id}/lifecycle`;
const lifecycle = { id, display_name: 'Committed name', status: 'active', role: 'user', version: 3,
  can_edit: true, can_suspend: true, can_reactivate: false };

test('staged lifecycle sends only the edit contract and renders nothing optimistic', async () => {
  const { createLifecycleFlow } = await import('../src/lib/user-lifecycle.ts');
  const calls = [];
  let finishPatch;
  let view;
  const flow = createLifecycleFlow(id, async (path, init) => {
    calls.push([path, init]);
    if (init.method === 'GET') return Response.json(lifecycle);
    return new Promise((resolve) => { finishPatch = resolve; });
  }, (next) => { view = next; });
  assert.deepEqual(calls, []);
  await flow.refresh();
  assert.deepEqual(calls, [[lifecyclePath, { method: 'GET' }]]);
  assert.deepEqual(view.account, lifecycle);
  flow.select('edit');
  for (const name of [' ', 'a'.repeat(129), 'bad\u0000name']) await flow.submit('edit', name, false);
  assert.equal(calls.length, 1);
  const pending = flow.submit('edit', '  Requested name  ', false);
  await flow.submit('edit', 'Another name', false);
  await flow.refresh();
  assert.equal(calls.length, 2);
  assert.equal(view.phase, 'saving');
  assert.deepEqual(view.account, lifecycle);
  assert.deepEqual(calls[1], [lifecyclePath, { method: 'PATCH', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ action: 'edit', expected_version: 3, display_name: 'Requested name' }) }]);
  const committed = { ...lifecycle, display_name: 'Server name', version: 2, can_suspend: false };
  finishPatch(Response.json(committed));
  await pending;
  assert.deepEqual(view.account, committed);
  assert.equal(view.action, null);
  flow.select('suspend');
  assert.equal(view.action, null);
  assert.equal(calls.length, 2);
});

test('staged suspend and reactivate require an action-specific reason and explicit confirmation', async () => {
  const { createLifecycleFlow } = await import('../src/lib/user-lifecycle.ts');
  const suspended = { ...lifecycle, role: 'superuser', status: 'suspended', version: 4, can_edit: false, can_suspend: false, can_reactivate: true };
  const bodies = [];
  let view;
  const flow = createLifecycleFlow(id, async (_, init) => {
    if (init.method === 'GET') return Response.json({ ...lifecycle, role: 'superuser' });
    bodies.push(JSON.parse(init.body));
    return Response.json(bodies.length === 1 ? suspended : { ...lifecycle, role: 'superuser', version: 5 });
  }, (next) => { view = next; });
  await flow.refresh();
  flow.select('reactivate');
  await flow.submit('reactivate', 'review_complete', true);
  flow.select('suspend');
  await flow.submit('suspend', '', true);
  await flow.submit('suspend', 'access_restored', true);
  await flow.submit('suspend', 'policy_violation', false);
  assert.deepEqual(bodies, []);
  assert.match(view.error, /confirm/i);
  flow.select(null);
  await flow.submit('suspend', 'access_review', true);
  assert.deepEqual(bodies, []);
  flow.select('suspend');
  await flow.submit('suspend', 'access_review', true);
  assert.deepEqual(view.account, suspended);
  flow.select('reactivate');
  await flow.submit('reactivate', 'temporary_leave', true);
  await flow.submit('reactivate', 'review_complete', false);
  assert.equal(bodies.length, 1);
  await flow.submit('reactivate', 'access_restored', true);
  assert.deepEqual(bodies, [
    { action: 'suspend', expected_version: 3, reason: 'access_review' },
    { action: 'reactivate', expected_version: 4, reason: 'access_restored' },
  ]);
  assert.equal(view.account.status, 'active');
});

test('stale lifecycle changes cannot be replayed; explicit refresh and a new action are required', async () => {
  const { createLifecycleFlow } = await import('../src/lib/user-lifecycle.ts');
  const refreshed = { ...lifecycle, display_name: 'Concurrent name', version: 8 };
  const calls = [];
  let view;
  const flow = createLifecycleFlow(id, async (_, init) => {
    calls.push([init.method, init.body && JSON.parse(init.body)]);
    if (calls.length === 1) return Response.json(lifecycle);
    if (calls.length === 2) return Response.json({ detail: 'private conflict detail' }, { status: 409 });
    if (calls.length === 3) return Response.json(refreshed);
    return Response.json({ ...refreshed, status: 'suspended', version: 9, can_suspend: false, can_reactivate: true });
  }, (next) => { view = next; });
  await flow.refresh();
  flow.select('suspend');
  await flow.submit('suspend', 'policy_violation', true);
  assert.equal(view.phase, 'refresh-required');
  assert.equal(view.action, null);
  assert.deepEqual(view.account, lifecycle);
  assert.match(view.error, /changed.*refresh/i);
  assert.doesNotMatch(view.error, /private/);
  flow.select('suspend');
  await flow.submit('suspend', 'policy_violation', true);
  assert.equal(calls.length, 2);
  await flow.refresh();
  assert.deepEqual(view.account, refreshed);
  await flow.submit('suspend', 'policy_violation', true);
  assert.equal(calls.length, 3);
  flow.select('suspend');
  await flow.submit('suspend', 'policy_violation', true);
  assert.deepEqual(calls.map(([method]) => method), ['GET', 'PATCH', 'GET', 'PATCH']);
  assert.equal(calls[3][1].expected_version, 8);
});

test('malformed lifecycle responses never enable actions or replace the last confirmed account', async () => {
  const { createLifecycleFlow } = await import('../src/lib/user-lifecycle.ts');
  assert.throws(() => createLifecycleFlow(`${id}?tenant_id=other`, () => assert.fail(), () => assert.fail()), /Invalid user ID/);
  for (const value of [null, 'invalid', { ...lifecycle, id: '00000000-0000-4000-8000-000000000099' },
    { ...lifecycle, display_name: 1 }, { ...lifecycle, role: 'admin' }, { ...lifecycle, status: 'unknown' },
    { ...lifecycle, version: -1 }, { ...lifecycle, version: 3.5 }, { ...lifecycle, version: '4' },
    { ...lifecycle, version: Number.MAX_SAFE_INTEGER + 1 }, { ...lifecycle, can_reactivate: 'false' },
    { ...lifecycle, can_suspend: undefined }, { ...lifecycle, email: 'private@example.test' }]) {
    let view;
    const flow = createLifecycleFlow(id, async () => Response.json(value), (next) => { view = next; });
    await flow.refresh();
    assert.equal(view.phase, 'refresh-required');
    assert.equal(view.account, null);
    assert.doesNotMatch(view.error, /private/);
  }
  for (const failedPatch of [() => Response.json({ ...lifecycle, status: 'suspended' }),
    () => new Response('private invalid JSON'), () => { throw new Error('private network error'); }]) {
    let view;
    const methods = [];
    const flow = createLifecycleFlow(id, async (_, init) => {
      methods.push(init.method);
      return init.method === 'GET' ? Response.json(lifecycle) : failedPatch();
    }, (next) => { view = next; });
    await flow.refresh();
    flow.select('suspend');
    await flow.submit('suspend', 'temporary_leave', true);
    assert.equal(view.phase, 'refresh-required');
    assert.deepEqual(view.account, lifecycle);
    assert.match(view.error, /could not confirm/i);
    assert.doesNotMatch(view.error, /private/);
    assert.deepEqual(methods, ['GET', 'PATCH']);
  }
});

test('the staged detail panel shows only permitted buttons, the selected form, and committed status', async () => {
  const { LifecyclePanel, StagedDirectoryDetail } = await import('../src/components/user-lifecycle.tsx');
  const props = { view: { phase: 'ready', account: lifecycle, action: null } };
  const html = render(LifecyclePanel, props);
  assert.match(html, /<dt>Status<\/dt><dd>Active<\/dd>/);
  assert.match(html, />Edit display name<\/button>/);
  assert.match(html, />Suspend<\/button>/);
  assert.doesNotMatch(html, />Reactivate<\/button>|<form/);
  const edit = render(LifecyclePanel, { view: { ...props.view, action: 'edit' } });
  assert.match(edit, /name="display_name"/);
  assert.doesNotMatch(edit, /name="(?:reason|confirm|role|tenant_id|version|email)"/);
  for (const [action, reasons] of [['suspend', ['policy_violation', 'access_review', 'temporary_leave']],
    ['reactivate', ['review_complete', 'access_restored']]]) {
    const account = action === 'suspend' ? lifecycle : { ...lifecycle, status: 'suspended', can_edit: false, can_suspend: false, can_reactivate: true };
    const form = render(LifecyclePanel, { view: { ...props.view, account, action } });
    assert.match(form, /<select[^>]*name="reason"[^>]*required/);
    assert.match(form, /<input[^>]*type="checkbox"[^>]*required/);
    assert.deepEqual([...form.matchAll(/<option value="([^"]+)"/g)].map((match) => match[1]), reasons);
    assert.doesNotMatch(form, /name="display_name"/);
  }
  const stale = render(LifecyclePanel, { view: { phase: 'refresh-required', account: lifecycle, action: null, error: 'Refresh first' } });
  assert.match(stale, /Last confirmed account details/);
  assert.match(stale, /role="alert">Refresh first/);
  assert.match(stale, />Refresh lifecycle<\/button>/);
  assert.doesNotMatch(stale, />Edit display name<|>Suspend<|>Reactivate<|<form/);
  const denied = render(LifecyclePanel, { view: { ...props.view, account: { ...lifecycle, can_edit: false, can_suspend: false } } });
  assert.match(denied, /No lifecycle changes are permitted/);
  assert.doesNotMatch(denied, />Edit display name<|>Suspend<|>Reactivate</);
  const staged = render(StagedDirectoryDetail, { data: user, transport: () => assert.fail('No server-render transport') });
  assert.match(staged, /User details[^]*Loading lifecycle/);
  assert.doesNotMatch(staged, /<dt>Status<\/dt>|Lifecycle changes are disabled/);
});

test('Next dev request logging omits directory search and detail URLs', async () => {
  const config = (await import('../next.config.ts')).default;
  const rules = config.logging?.incomingRequests?.ignore ?? [];
  for (const url of [`${listPath}?q=private`, `${listPath}/${id}`, `/users?q=private`, `/api/bri/v1/%75sers/${id}`]) {
    assert.ok(rules.some((rule) => rule.test(url)), `Missing logging exclusion for a directory URL`);
  }
});

test('the release Next handler denies lifecycle GET without reaching a session or upstream and exports no PATCH', async (t) => {
  const previousMode = process.env.BRI_UI_AUTH_MODE;
  const previousNodeEnv = process.env.NODE_ENV;
  process.env.NODE_ENV = 'test';
  t.after(() => {
    if (previousMode === undefined) delete process.env.BRI_UI_AUTH_MODE; else process.env.BRI_UI_AUTH_MODE = previousMode;
    if (previousNodeEnv === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = previousNodeEnv;
  });
  const fetch = t.mock.method(globalThis, 'fetch', () => { throw new Error('Unexpected upstream'); });
  assert.equal(route.PATCH, undefined);
  for (const mode of ['supabase', 'synthetic']) {
    process.env.BRI_UI_AUTH_MODE = mode;
    const result = await route.GET(new Request(`https://ui.example.test/api/bri${lifecyclePath}`), {
      params: Promise.resolve({ path: ['v1', 'users', id, 'lifecycle'] }),
    });
    assert.equal(result.status, 404);
    assert.equal(result.headers.get('cache-control'), 'no-store');
  }
  assert.equal(fetch.mock.callCount(), 0);
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
