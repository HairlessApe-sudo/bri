import test from 'node:test';
import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import { readFileSync } from 'node:fs';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import ts from 'typescript';

const imports = new Set();
registerHooks({
  resolve(specifier, context, next) {
    if (specifier.startsWith('@/')) {
      for (const extension of ['', '.ts', '.tsx']) {
        try { return next(new URL(`../src/${specifier.slice(2)}${extension}`, import.meta.url).href, context); }
        catch (error) { if (error.code !== 'ERR_MODULE_NOT_FOUND') throw error; }
      }
    }
    return next(specifier, context);
  },
  load(url, context, next) {
    imports.add(url);
    if (!/\.tsx?$/.test(url)) return next(url, context);
    const { outputText } = ts.transpileModule(readFileSync(new URL(url), 'utf8'), {
      compilerOptions: { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
    });
    return { format: 'module', source: outputText, shortCircuit: true };
  },
});

const { UserDirectory, DirectoryDetailContent } = await import('../src/components/user-directory.tsx');
const { DirectoryList } = await import('../src/components/user-directory-view.tsx');
const releaseImports = [...imports];
const directory = await import('../src/lib/user-directory.mjs');
const id = '00000000-0000-4000-8000-000000000001';
const user = { id, display_name: 'Fixture', status: 'pending', role: 'superuser', mfa_status: 'unknown' };
const render = (Component, props) => renderToStaticMarkup(createElement(Component, props));
const listProps = (row) => ({ offset: 0, data: { items: [row], has_more: false }, onViewGrants() {} });

function findButton(element, label) {
  if (!element || typeof element !== 'object') return;
  if (element.type === 'button' && element.props.children === label) return element;
  if (Array.isArray(element)) return element.map((child) => findButton(child, label)).find(Boolean);
  return findButton(element.props?.children, label);
}

test('filter changes keep the submitted search and restart bounded pagination', () => {
  const initial = { query: '', offset: 0, filters: {} };
  const reduce = directory.updateDirectoryList;
  const searched = reduce(initial, { type: 'search', query: ' A&B ' });
  const next = reduce(searched, { type: 'page', offset: 25 });
  const filtered = reduce(next, { type: 'filter', key: 'status', value: 'pending' });
  assert.equal(directory.directoryListPath(filtered.query, filtered.offset, filtered.filters), '/api/bri/v1/users?q=A%26B&status=pending');
  const changed = reduce(reduce(filtered, { type: 'page', offset: 10000 }), { type: 'filter', key: 'mfa_status', value: 'unknown' });
  assert.equal(directory.directoryListPath(changed.query, changed.offset, changed.filters), '/api/bri/v1/users?q=A%26B&status=pending&mfa_status=unknown');
  const cleared = reduce(changed, { type: 'filter', key: 'status', value: '' });
  assert.equal(directory.directoryListPath(cleared.query, cleared.offset, cleared.filters), '/api/bri/v1/users?q=A%26B&mfa_status=unknown');
  for (const offset of [-25, 1.5, 10025]) assert.equal(reduce(cleared, { type: 'page', offset }), cleared);
  assert.equal(reduce(cleared, { type: 'filter', key: 'role', value: 'admin' }), cleared);
  assert.equal(reduce(cleared, { type: 'filter', key: 'tenant_id', value: 'secret' }), cleared);
  assert.deepEqual(reduce(reduce(cleared, { type: 'page', offset: 25 }), { type: 'search', query: 'Other' }),
    { query: 'Other', offset: 0, filters: { mfa_status: 'unknown' } });
});

test('overview renders the three labeled allowlisted filters only when enabled', () => {
  const html = render(UserDirectory, { enabled: true });
  for (const [label, values] of Object.entries({ Status: ['pending', 'active', 'suspended', 'deactivated'],
    Role: ['user', 'superuser'], MFA: ['verified', 'unknown'] })) {
    const options = html.match(new RegExp(`<label>${label}<select[^>]*>(.*?)</select></label>`))?.[1];
    assert.deepEqual([...options?.matchAll(/<option value="([^"]*)"/g) ?? []].map((x) => x[1]), ['', ...values]);
  }
  assert.doesNotMatch(render(UserDirectory, { enabled: false }), /<select/);
});

test('overview only offers View grants for a literal server true, without rendering grant fields', () => {
  for (const can_view_grants of [false, undefined, null, 1, 'true']) {
    assert.doesNotMatch(render(DirectoryList, listProps({ ...user, can_view_grants })), /View grants/);
  }
  const row = { ...user, can_view_grants: true, assigned: [{ scope_name: 'PRIVATE-GRANT' }] };
  let selected;
  const props = { ...listProps(row), onViewGrants: (id) => { selected = id; } };
  assert.match(render(DirectoryList, props), />View grants<\/button>/);
  assert.doesNotMatch(render(DirectoryList, props), /PRIVATE-GRANT|Assigned grants|Effective grants/);
  findButton(DirectoryList(props), 'View grants').props.onClick();
  assert.equal(selected, id);
});

test('the grants shortcut targets the grants panel only in the verified matching detail', () => {
  const props = { accountId: id, data: user, onBack() {}, focusGrants: true };
  assert.match(render(DirectoryDetailContent, props), /tabindex="-1"[^>]*><section aria-label="Account grants"/);
  for (const state of [{ loading: true }, { error: new Error() }, { data: null }, { data: { ...user, id: 'other' } }]) {
    assert.doesNotMatch(render(DirectoryDetailContent, { ...props, ...state }), /tabindex="-1"|Account grants/);
  }
});

test('setup indicator is derived solely from pending directory status', () => {
  for (const status of ['pending', 'active', 'suspended', 'deactivated']) {
    const html = render(DirectoryList, listProps({ ...user, status, provider_setup_status: 'PRIVATE-SETUP', setup_pending: status !== 'pending' }));
    assert.equal(html.includes('Account setup pending'), status === 'pending');
    assert.doesNotMatch(html, /PRIVATE-SETUP/);
  }
});

test('the release overview module graph does not import staged controls', () => {
  assert.ok(releaseImports.some((url) => url.endsWith('/components/user-directory.tsx')));
  assert.ok(!releaseImports.some((url) => /(?:staged-directory-overview|privileged-approvals|user-lifecycle|user-delegation|create-user-form|user-deactivation)\.[tj]sx?$/.test(url)));
});

const staged = () => import('../src/components/staged-directory-overview.tsx');
const queueRow = { approval_id: id, target_id: id, target_name: 'PRIVATE-TARGET', requester_label: 'Restricted requester',
  reason: 'LOST_FACTOR', requested_at: '2026-11-19T10:00:00Z', expires_at: '2026-11-19T11:00:00Z', state: 'PENDING',
  reconciliation: 'NONE', can_decide: true };

test('staged queue gate accepts a valid read, discards contents, and requires explicit opt-in', async () => {
  const { createOverviewQueueGate, OverviewQueueEntry } = await staged();
  const calls = [];
  const gate = createOverviewQueueGate(async (path, init) => {
    calls.push([path, init]);
    return Response.json({ items: [queueRow], next_cursor: 'PRIVATE-CURSOR' });
  });
  const markup = () => render(OverviewQueueEntry, { gate, phase: gate.getSnapshot() });
  assert.doesNotMatch(markup(), /Open MFA reset queue/);
  gate.open();
  assert.deepEqual(calls, []);
  assert.equal(gate.getSnapshot(), 'idle');
  await gate.check();
  assert.equal(gate.getSnapshot(), 'authorized');
  assert.match(markup(), /Open MFA reset queue/);
  assert.doesNotMatch(markup(), /PRIVATE-|Load approval queue|Approve|Reject|1 request/);
  assert.deepEqual(calls, [['/v1/privileged-approvals/queue?limit=25', { method: 'GET', cache: 'no-store', redirect: 'manual', signal: calls[0][1].signal }]]);
  findButton(OverviewQueueEntry({ gate, phase: gate.getSnapshot() }), 'Open MFA reset queue').props.onClick();
  assert.equal(gate.getSnapshot(), 'open');
  assert.equal(calls.length, 1);
});

test('staged queue gate fails closed on denial, redirect, transport failure or invalid success', async () => {
  const { createOverviewQueueGate } = await staged();
  for (const reply of [() => Response.json({ items: [], next_cursor: null }, { status: 403 }),
    () => Response.redirect('https://uncontacted.example.test/'), () => new Response('not-json'),
    () => Response.json({ items: [{ ...queueRow, can_decide: 'true' }], next_cursor: null }),
    () => Response.json({ items: [], next_cursor: '' }), () => new Response(null, { status: 204 }),
    () => { throw new Error('PRIVATE-TRANSPORT'); }]) {
    const gate = createOverviewQueueGate(async () => reply());
    await gate.check();
    gate.open();
    assert.equal(gate.getSnapshot(), 'unavailable');
  }
});

test('staged queue gate discards aborted replies and revokes the shortcut when leaving overview', async () => {
  const { createOverviewQueueGate } = await staged();
  const late = Promise.withResolvers();
  let signal;
  const first = createOverviewQueueGate((_, init) => { signal = init.signal; return late.promise; });
  const pending = first.check();
  first.leaveOverview();
  assert.equal(signal.aborted, true);
  const second = createOverviewQueueGate(async () => Response.json({ items: [], next_cursor: null }));
  late.resolve(Response.json({ items: [queueRow], next_cursor: null }));
  await pending;
  assert.equal(first.getSnapshot(), 'idle');
  assert.equal(second.getSnapshot(), 'idle');
  await second.check();
  second.leaveOverview();
  second.open();
  assert.equal(second.getSnapshot(), 'idle');
});
