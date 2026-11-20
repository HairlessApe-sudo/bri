import assert from 'node:assert/strict';
import { registerHooks } from 'node:module';
import test from 'node:test';

registerHooks({
  resolve(specifier, context, next) {
    if (specifier.startsWith('@/')) {
      const path = specifier.slice(2);
      return next(new URL(`../src/${path}${path.endsWith('.mjs') ? '' : '.ts'}`, import.meta.url).href, context);
    }
    return next(specifier, context);
  },
});

const { createLifecycleFlow } = await import('../src/lib/user-lifecycle.ts');
const delegation = await import('../src/lib/user-delegation.ts');
const { createDelegationFlow } = delegation;
const firstId = '00000000-0000-4000-8000-000000000001';
const secondId = '00000000-0000-4000-8000-000000000002';
const firstNodes = [{ id: 'north', label: 'North' }, { id: 'south', label: 'South' }];
const permission = 'knowledge:read';
const account = (id, version, status = 'active') => ({ id, version, status, display_name: 'Test user', role: 'user',
  can_edit: true, can_suspend: status === 'active', can_reactivate: status === 'suspended' });
const cases = [
  { name: 'lifecycle', create: (id, _nodes, transport) => createLifecycleFlow(id, transport),
    action: 'suspend', submit: (flow, confirmed = true) => flow.submit('suspend', 'access_review', confirmed),
    choose() {}, state: (view) => view.account, result: account,
    saved: (id, version) => account(id, version, 'suspended') },
  { name: 'delegation', create: createDelegationFlow,
    action: 'grant', submit: (flow, confirmed = true) => flow.submit('grant', confirmed),
    choose: (flow) => flow.choose('north', permission), state: (view) => view.state,
    result: (_id, version) => ({ version: `opaque:${version}`, granted: false }),
    saved: (_id, version) => ({ version: `opaque:${version}`, granted: true }) },
];

for (const spec of cases) {
  function transportFor(version, calls) {
    return async (path, init) => {
      calls.push({ path, ...init });
      const id = path.split('/')[3];
      return Response.json(init.method === 'GET' ? spec.result(id, version) : spec.saved(id, version + 1));
    };
  }
  async function review(flow) {
    spec.choose(flow);
    await flow.refresh();
    flow.select(spec.action);
    assert.equal(flow.getSnapshot().action, spec.action);
  }
  const changes = ['target', 'transport', ...(spec.name === 'delegation' ? ['catalog'] : [])];
  for (const change of changes) {
    test(`${spec.name}: replacing the ${change} invalidates the old confirmation`, async () => {
      const calls = [];
      const firstTransport = transportFor(1, calls);
      const first = spec.create(firstId, firstNodes, firstTransport);
      const unbind = first.bind();
      await review(first);
      const id = change === 'target' ? secondId : firstId;
      const transport = change === 'transport' ? transportFor(4, calls) : firstTransport;
      const nodes = change === 'catalog' ? [{ id: 'north', label: 'Renamed north' }] : firstNodes;
      unbind();
      // The one transport retained on a target change handles both URLs.
      const replacement = spec.create(id, nodes, transport);
      const close = replacement.bind();
      await spec.submit(first);
      await first.refresh();
      spec.choose(replacement);
      assert.equal(replacement.getSnapshot().phase, 'idle');
      await spec.submit(replacement);
      assert.deepEqual(calls.map(({ method }) => method), ['GET']);
      // The response must match the URL even when transport identity is retained.
      await replacement.refresh();
      await spec.submit(replacement);
      assert.equal(replacement.getSnapshot().action, null);
      assert.equal(calls.at(-1).path.split('/')[3], id);
      assert.deepEqual(calls.map(({ method }) => method), ['GET', 'GET']);
      replacement.select(spec.action);
      await spec.submit(replacement, false);
      assert.equal(calls.length, 2);
      await spec.submit(replacement);
      assert.deepEqual(calls.map(({ method }) => method), ['GET', 'GET', 'PATCH']);
      assert.equal(calls.at(-1).path.split('/')[3], id);
      close();
    });
  }

  test(`${spec.name}: retiring during the saving notification prevents dispatch`, async () => {
    const calls = [];
    const flow = spec.create(firstId, firstNodes, transportFor(1, calls));
    const close = flow.bind();
    await review(flow);
    const unsubscribe = flow.subscribe(() => {
      if (flow.getSnapshot().phase === 'saving') close();
    });
    await spec.submit(flow);
    unsubscribe();
    assert.deepEqual(calls.map(({ method }) => method), ['GET']);
  });

  for (const stale of ['load', 'success body', ...(spec.name === 'delegation' ? ['failure body'] : [])]) {
    test(`${spec.name}: ignores a late ${stale} even when transport does not honor abort`, async () => {
      const calls = [];
      let complete;
      const reply = new Promise((resolve) => { complete = resolve; });
      const first = spec.create(firstId, firstNodes, async (path, init) => {
        calls.push({ path, ...init });
        if (stale === 'load' && calls.length === 1) return reply;
        if (init.method === 'GET') return Response.json(spec.result(firstId, 1));
        return { ok: stale === 'success body', status: stale === 'success body' ? 200 : 403, json: () => reply };
      });
      const close = first.bind();
      let pending;
      if (stale === 'load') {
        spec.choose(first);
        pending = first.refresh();
      } else {
        await review(first);
        pending = spec.submit(first);
        await Promise.resolve();
        assert.deepEqual(spec.state(first.getSnapshot()), spec.result(firstId, 1));
      }
      const signal = calls.at(-1).signal;
      assert.equal(signal.aborted, false);
      close();
      assert.equal(signal.aborted, true);
      // Rebind the same store as an effect replay would. Its new read must work.
      const end = first.bind();
      await review(first);
      const before = first.getSnapshot();
      const replacement = spec.create(secondId, firstNodes, transportFor(7, []));
      const endReplacement = replacement.bind();
      await review(replacement);
      complete(stale === 'load' ? Response.json(spec.result(firstId, 1)) : spec.saved(firstId, 2));
      await pending;
      assert.equal(first.getSnapshot(), before);
      assert.equal(replacement.getSnapshot().action, spec.action);
      assert.deepEqual(spec.state(replacement.getSnapshot()), spec.result(secondId, 7));
      end();
      endReplacement();
    });
  }
}

test('delegation catalog has a stable content key and an immutable snapshot', () => {
  const { delegationCatalogKey, readDelegationCatalog } = delegation;
  const input = firstNodes.map((node) => ({ ...node }));
  const key = delegationCatalogKey(input);
  const catalog = readDelegationCatalog(key);
  assert.equal(delegationCatalogKey(input.map((node) => ({ ...node })).reverse()), key);
  assert.ok(Object.isFrozen(catalog) && catalog.every(Object.isFrozen));
  input[0].label = 'Renamed';
  assert.notEqual(delegationCatalogKey(input), key);
  assert.deepEqual(catalog, firstNodes);
  input[0].label = 'North';
  input[0].id = 'new north';
  assert.notEqual(delegationCatalogKey(input), key);
  input.pop();
  assert.notEqual(delegationCatalogKey(input), key);
});
