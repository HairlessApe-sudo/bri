import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks } from 'node:module';
import test from 'node:test';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import ts from 'typescript';
import { parseDetail, parseQueue, proposalFromSegment } from '../local-workspace/review-contract.mjs';

const id = 'csv:01234567-89ab-4def-8123-456789abcdef';
const created_at = '2026-11-01T00:00:00.001+00:00';
const summary = { id, state: 'proposed', node_id: 'team', created_at };
const literal = '<img src=x onerror=alert(1)> https://example.invalid';
const provenance = { source_id: id, source_version_id: id, source_version: '1', extraction_id: id,
  original_sha256: 'a'.repeat(64), content_sha256: 'b'.repeat(64), csv_first_line: 1, csv_last_line: 3 };
const proposal = { ...summary, provenance, evidence: literal, next_evidence_offset: null,
  history: [{ event: 'proposed', occurred_at: created_at, reason: null }] };
const failed = { ...summary, state: 'failed', provenance: null, evidence: null, next_evidence_offset: null,
  history: [{ event: 'failed', occurred_at: created_at, reason: 'invalid_csv' }] };

registerHooks({
  resolve(specifier, context, next) {
    if (!specifier.startsWith('@/')) return next(specifier, context);
    for (const ext of ['', '.ts', '.tsx']) {
      try { return next(new URL(`../src/${specifier.slice(2)}${ext}`, import.meta.url).href, context); }
      catch (error) { if (error.code !== 'ERR_MODULE_NOT_FOUND') throw error; }
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

const { ReviewConfirmation, ReviewDetailView, ReviewError, ReviewQueueView } = await import('../local-workspace/app/review/views.tsx');
const render = (view, props) => renderToStaticMarkup(createElement(view, props));

test('review links use exactly one canonical encoding and cursors are bare last-row UUIDs', () => {
  const segment = encodeURIComponent(id);
  assert.equal(proposalFromSegment(segment), id);
  for (const input of [id, encodeURIComponent(segment), segment.replace('%3A', '%3a'), `${segment}/`, '%']) {
    assert.equal(proposalFromSegment(input), null);
  }
  const page = { items: [summary], next_cursor: id.slice(4) };
  assert.match(render(ReviewQueueView, { data: parseQueue(page, 'proposed', null, 1) }), new RegExp(`href="/review/${segment}`));
  assert.throws(() => parseQueue(page, 'proposed', page.next_cursor, 1));
  assert.throws(() => parseQueue({ ...page, next_cursor: id }, 'proposed', null, 1));
  assert.throws(() => parseQueue(page, 'approved', null, 1));
});

function parseScopeLabel(node_id) {
  return {
    queue: parseQueue({ items: [{ ...summary, node_id }], next_cursor: null }),
    detail: parseDetail({ ...proposal, node_id }, id),
  };
}

test('review scope labels preserve schema-native Unicode and render only as text', () => {
  const node_id = ' 東京 🧪 <scope> https://scope.invalid ';
  const { queue, detail } = parseScopeLabel(node_id);
  assert.equal(queue.items[0].node_id, node_id);
  assert.equal(detail.node_id, node_id);
  const queueHtml = render(ReviewQueueView, { data: queue });
  assert.deepEqual([...queueHtml.matchAll(/href="([^"]+)"/g)].map((match) => match[1]), [`/review/${encodeURIComponent(id)}`]);
  for (const html of [queueHtml, render(ReviewDetailView, { data: detail, offset: 0 })]) {
    assert.ok(html.includes(' 東京 🧪 &lt;scope&gt; https://scope.invalid '));
    assert.doesNotMatch(html, /<scope>|href="https:\/\/scope\.invalid/);
  }
});

test('review scope labels accept up to 256 code points, including SQL-projected ellipsis', () => {
  for (const node_id of ['🧪'.repeat(256), `${'🧪'.repeat(255)}…`]) {
    const { queue, detail } = parseScopeLabel(node_id);
    assert.equal(queue.items[0].node_id, node_id);
    assert.equal(detail.node_id, node_id);
  }
  for (const node_id of ['🧪'.repeat(257), 'x'.repeat(257), null]) {
    assert.throws(() => parseQueue({ items: [{ ...summary, node_id }], next_cursor: null }));
    assert.throws(() => parseDetail({ ...proposal, node_id }, id));
  }
});

test('blank review scope labels receive a display fallback without changing the parsed text', () => {
  for (const node_id of ['', ' \t\n']) {
    const { queue, detail } = parseScopeLabel(node_id);
    assert.equal(queue.items[0].node_id, node_id);
    assert.equal(detail.node_id, node_id);
    assert.match(render(ReviewQueueView, { data: queue }), /Blank node label/);
    assert.match(render(ReviewDetailView, { data: detail, offset: 0 }), /Blank node label/);
  }
});

test('review projection binds lineage and accepts only bounded exact offsets and processing codes', () => {
  const evidence = '🧪'.repeat(4096);
  const second = { ...proposal, evidence, next_evidence_offset: 8192 };
  assert.equal(parseDetail(second, id, 4096).next_evidence_offset, 8192);
  assert.throws(() => parseDetail(second, id));
  assert.throws(() => parseDetail({ ...second, evidence: `${evidence}x` }, id, 4096));
  for (const variant of [{ ...proposal, object_key: 'internal' }, { ...proposal, provenance: null },
    { ...failed, evidence: 'unexpected' }, { ...failed, history: [{ ...failed.history[0], reason: 'private error' }] },
    { ...proposal, history: [{ ...proposal.history[0], reason: 'authority_lost' }] },
    { ...proposal, history: [{ ...proposal.history[0], event: 'version_access' }] }]) {
    assert.throws(() => parseDetail(variant, id));
  }
});

test('review evidence is escaped and terminal states cannot render decision controls', () => {
  const decisions = createElement(ReviewConfirmation, { choice: null, choose() {}, submit() {} });
  const draw = (data) => render(ReviewDetailView, { data: parseDetail(data, id), offset: 0, actions: decisions });
  const proposed = draw(proposal);
  assert.match(proposed, /&lt;img src=x onerror=alert\(1\)&gt; https:\/\/example.invalid/);
  assert.doesNotMatch(proposed, /<img|href="https:/);
  assert.match(proposed, /Approval does not publish this record or authorize/);
  assert.match(proposed, /Approve…/);
  assert.doesNotMatch(proposed, /Confirm approval/);
  for (const item of [{ ...proposal, state: 'approved' }, { ...proposal, state: 'rejected' }, failed]) {
    assert.doesNotMatch(draw(item), /Approve…|Reject…|Confirm approval|Review decision/);
  }
  assert.match(draw(failed), /invalid_csv/);
  assert.match(draw(failed), /No extracted evidence/);
});

test('confirmation controls stage a choice before submitting and expose no reason input', () => {
  const chosen = [];
  const posted = [];
  const props = { choose: (value) => chosen.push(value), submit: (value) => posted.push(value) };
  function button(node, label) {
    if (!node || typeof node !== 'object') return;
    if (node.type === 'button' && node.props.children === label) return node;
    if (Array.isArray(node)) return node.map((child) => button(child, label)).find(Boolean);
    return button(node.props?.children, label);
  }
  button(ReviewConfirmation({ ...props, choice: null }), 'Reject…').props.onClick();
  assert.deepEqual(chosen, ['rejected']);
  assert.deepEqual(posted, []);
  const confirm = ReviewConfirmation({ ...props, choice: 'rejected' });
  button(confirm, 'Cancel').props.onClick();
  button(confirm, 'Confirm rejection').props.onClick();
  assert.deepEqual(chosen, ['rejected', null]);
  assert.deepEqual(posted, ['rejected']);
  assert.doesNotMatch(render(ReviewConfirmation, { ...props, choice: 'rejected' }), /<textarea|<input|MFA/);
});

test('review errors distinguish denied identity and not found without leaking a diagnostic', () => {
  for (const [status, label] of [[401, 'Identity required'], [403, 'Access denied'], [404, 'Proposal not found']]) {
    const html = render(ReviewError, { error: Object.assign(new Error('private diagnostic'), { status }) });
    assert.match(html, new RegExp(label));
    assert.doesNotMatch(html, /private diagnostic|Approve|Reject/);
  }
});
