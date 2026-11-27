import test from 'node:test';
import assert from 'node:assert/strict';
import { createUnifiedLifecycle } from '../local-workspace/unified-lifecycle.mjs';

test('an earlier request cannot publish after a newer request commits, even if it ignores abort', async () => {
  const lifecycle = createUnifiedLifecycle();
  let finish;
  const old = lifecycle.begin();
  const publications = [];
  const delayed = new Promise((resolve) => { finish = resolve; }).then((value) => {
    if (old.current()) publications.push(value);
  });
  const next = lifecycle.begin();
  assert.equal(old.signal.aborted, true);
  if (next.current()) publications.push('current');
  finish('old');
  await delayed;
  assert.deepEqual(publications, ['current']);
});

test('starting revalidation retires protected work and withdraws access before clearing the view', async () => {
  const lifecycle = createUnifiedLifecycle();
  assert.equal(lifecycle.beginRevalidation(() => {}).authorize('A', ['team']), '');
  assert.equal(lifecycle.select('team'), true);
  const old = lifecycle.begin();
  let finish;
  const delayed = new Promise((resolve) => { finish = resolve; }).then(() => old.current());
  let cleared = false;
  const pending = lifecycle.beginRevalidation(() => {
    assert.equal(old.signal.aborted, true);
    assert.equal(lifecycle.access(), null);
    cleared = true;
  });
  assert.equal(cleared, true);
  assert.equal(lifecycle.select('team'), false);
  finish();
  assert.equal(await delayed, false);
  assert.equal(pending.current(), true);
  assert.equal(lifecycle.access(), null);
  assert.equal(pending.authorize('B', ['team', 'b-only']), '');
  assert.equal(lifecycle.access(), 'B');
});

test('same binding restores only the previously selected exact eligible scope', () => {
  const lifecycle = createUnifiedLifecycle();
  lifecycle.beginRevalidation(() => {}).authorize('A', ['team', 'other']);
  lifecycle.select('team');
  const superseded = lifecycle.beginRevalidation(() => {});
  const latest = lifecycle.beginRevalidation(() => {});
  assert.equal(superseded.authorize('B', ['team']), null);
  assert.equal(lifecycle.access(), null);
  assert.equal(latest.authorize('A', ['other', 'team']), 'team');
  assert.equal(lifecycle.beginRevalidation(() => {}).authorize('A', ['other']), '');
});

test('discarding a failed discovery never recovers its retained selection on retry', () => {
  const lifecycle = createUnifiedLifecycle();
  lifecycle.beginRevalidation(() => {}).authorize('A', ['team']);
  lifecycle.select('team');
  const failed = lifecycle.beginRevalidation(() => {});
  lifecycle.resetAccess();
  assert.equal(lifecycle.access(), null);
  assert.equal(failed.authorize('A', ['team']), null);
  assert.equal(lifecycle.beginRevalidation(() => {}).authorize('A', ['team']), '');
});

test('scope, query, identity, failure, and page retirement share the same invalidation boundary', () => {
  const lifecycle = createUnifiedLifecycle();
  for (const transition of ['scope', 'query', 'identity', 'failure', 'pagehide']) {
    const inFlight = lifecycle.begin();
    lifecycle.clear();
    assert.equal(inFlight.signal.aborted, true, transition);
    assert.equal(inFlight.current(), false, transition);
  }
});
