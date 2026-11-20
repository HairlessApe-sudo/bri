import assert from 'node:assert/strict';
import test from 'node:test';
import { visibleRemote } from '../src/lib/remote-state.mjs';

const transitionEvent = (type, persisted) => Object.assign(new Event(type), { persisted });

test('parking hides the current snapshot synchronously and only persisted pageshow can restart reads', async () => {
  const { observeEvidencePage } = await import('../local-workspace/app/evidence-page.mjs');
  const window = new EventTarget();
  const document = Object.assign(new EventTarget(), { visibilityState: 'visible' });
  const path = '/api/bri-local/v1/knowledge';
  const evidence = { path, refreshKey: 0, data: ['previously delivered evidence'], error: null, loading: false };
  let state = { parked: false, refreshKey: 0 };
  const changes = [];
  const observer = observeEvidencePage(window, document, (value) => { state = value; changes.push(value); });
  const visible = () => visibleRemote(evidence, state.parked ? null : path, state.refreshKey);
  assert.ok(visible().data);
  window.dispatchEvent(transitionEvent('pageshow', false));
  assert.equal(changes.length, 0);

  window.dispatchEvent(transitionEvent('pagehide', true));
  assert.equal(state.parked, true);
  assert.deepEqual(visible(), { data: null, error: null, loading: false });
  window.dispatchEvent(new Event('focus'));
  document.dispatchEvent(new Event('visibilitychange'));
  observer.refresh();
  window.dispatchEvent(transitionEvent('pageshow', false));
  assert.equal(changes.length, 1);
  assert.equal(visible().loading, false);

  window.dispatchEvent(transitionEvent('pageshow', true));
  assert.equal(state.parked, false);
  assert.ok(state.refreshKey > evidence.refreshKey);
  assert.deepEqual(visible(), { data: null, error: null, loading: true });
  assert.equal(changes.length, 2);
  window.dispatchEvent(new Event('focus'));
  assert.equal(changes.length, 3);
  document.visibilityState = 'hidden';
  document.dispatchEvent(new Event('visibilitychange'));
  assert.equal(changes.length, 3);

  observer.dispose();
  window.dispatchEvent(transitionEvent('pagehide', true));
  window.dispatchEvent(new Event('focus'));
  document.visibilityState = 'visible';
  document.dispatchEvent(new Event('visibilitychange'));
  assert.equal(changes.length, 3);
});