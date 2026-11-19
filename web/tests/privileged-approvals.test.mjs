import test from 'node:test';
import assert from 'node:assert/strict';

const prefix = '/v1/privileged-approvals';
const target = '00000000-0000-4000-8000-000000000001';
const correlation = '00000000-0000-4000-8000-000000000002';

test('request waits for eligibility, explicit submit and step-up, then retries an ambiguous POST with the same UUID', async () => {
  const { createApprovalRequestFlow } = await import('../src/lib/privileged-approvals.ts');
  const challenge = Promise.withResolvers();
  const posts = [];
  let reads = 0;
  let challenges = 0;
  const flow = createApprovalRequestFlow(target, async (path, init) => {
    if (init.method === 'GET') {
      assert.equal(path, `${prefix}/eligibility/${target}`);
      reads++;
      return Response.json({ eligible: reads !== 1 });
    }
    assert.equal(path, prefix);
    assert.equal(init.method, 'POST');
    const body = JSON.parse(init.body);
    posts.push(body);
    assert.deepEqual(Object.keys(body).sort(), ['reason', 'request_id', 'target']);
    assert.equal(body.target, target);
    assert.equal(body.reason, 'LOST_FACTOR');
    assert.match(body.request_id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    if (posts.length === 1) throw new Error('private transport detail');
    return Response.json({ approval_id: body.request_id, state: 'PENDING', correlation_id: correlation });
  }, async (action) => { assert.equal(action, 'request'); challenges++; await challenge.promise; });

  await flow.submit();
  await flow.reload();
  flow.chooseReason('LOST_FACTOR');
  await flow.submit();
  assert.equal(challenges, 0);
  await flow.reload();
  flow.chooseReason('unapproved');
  await flow.submit();
  assert.equal(challenges, 0);
  flow.chooseReason('LOST_FACTOR');
  assert.equal(posts.length, 0);
  const first = flow.submit();
  await flow.submit();
  assert.equal(challenges, 1);
  assert.equal(posts.length, 0);
  challenge.resolve();
  await first;
  assert.equal(flow.getSnapshot().phase, 'reload');
  assert.doesNotMatch(flow.getSnapshot().error, /private/);
  await flow.submit();
  await flow.reload();
  assert.equal(posts.length, 1);
  flow.chooseReason('REPLACED_DEVICE');
  await flow.submit();
  assert.equal(challenges, 2);
  assert.deepEqual(posts, [posts[0], posts[0]]);
  assert.equal(flow.getSnapshot().receipt.state, 'PENDING');
});

const row = { approval_id: correlation, target_id: target, target_name: 'Directory label', requester_label: 'Restricted requester',
  reason: 'LOST_FACTOR', requested_at: '2026-11-19T10:00:00Z', expires_at: '2026-11-19T11:00:00Z',
  state: 'PENDING', reconciliation: 'NONE', can_decide: true };

test('queue follows opaque cursors and only accepts explicit decisions for server-authorized pending rows', async () => {
  const { createApprovalQueueFlow } = await import('../src/lib/privileged-approvals.ts');
  const decision = Promise.withResolvers();
  const cursor = 'opaque+/?=&';
  const calls = [];
  const flow = createApprovalQueueFlow(async (path, init) => {
    calls.push([path, init.method]);
    if (init.method === 'POST') {
      assert.equal(path, `${prefix}/${correlation}/decision`);
      assert.deepEqual(JSON.parse(init.body), { decision: 'APPROVE' });
      return decision.promise;
    }
    const url = new URL(path, 'https://fixture.test');
    assert.equal(url.pathname, `${prefix}/queue`);
    assert.equal(url.searchParams.get('limit'), '25');
    if (calls.length === 1) {
      assert.equal(url.searchParams.has('cursor'), false);
      return Response.json({ items: [{ ...row, can_decide: false, requester_id: 'hidden' }], next_cursor: cursor });
    }
    assert.equal(url.searchParams.get('cursor'), cursor);
    return Response.json({ items: [row], next_cursor: null });
  }, async (action) => { assert.equal(action, 'decision'); });
  await flow.reload();
  assert.deepEqual(flow.getSnapshot().page.items, [{ ...row, can_decide: false }]);
  await flow.decide(correlation, 'REJECT');
  assert.equal(calls.length, 1);
  await flow.next();
  await flow.decide(target, 'APPROVE');
  await flow.decide(correlation, 'EXECUTE');
  assert.equal(calls.length, 2);
  const pending = flow.decide(correlation, 'APPROVE');
  await flow.decide(correlation, 'REJECT');
  assert.equal(flow.getSnapshot().page.items[0].state, 'PENDING');
  decision.resolve(Response.json({ approval_id: correlation, state: 'APPROVED', correlation_id: target }));
  await pending;
  assert.equal(flow.getSnapshot().phase, 'reload');
  assert.equal(flow.getSnapshot().receipt.state, 'APPROVED');
  assert.equal(flow.getSnapshot().page, undefined);
  assert.equal(calls.length, 3);
  await flow.reload();
  assert.equal(calls.length, 4);
});

test('replacing a staged context aborts late reads and prevents a delayed step-up from posting', async () => {
  const { createApprovalRequestFlow, createApprovalQueueFlow } = await import('../src/lib/privileged-approvals.ts');
  const late = Promise.withResolvers();
  const step = Promise.withResolvers();
  const unused = () => assert.fail('Unexpected call');
  const original = createApprovalRequestFlow(target, async (path, init) => {
    assert.equal(init.method, 'GET');
    return Response.json({ eligible: true });
  }, () => step.promise);
  await original.reload();
  original.chooseReason('COMPROMISED_FACTOR');
  const submit = original.submit();
  original.cancelPending();
  const replacement = createApprovalRequestFlow(correlation, unused, unused);
  step.resolve();
  await submit;
  assert.equal(replacement.getSnapshot().phase, 'idle');
  const oldQueue = createApprovalQueueFlow(() => late.promise, unused);
  const reading = oldQueue.reload();
  oldQueue.cancelPending();
  const newQueue = createApprovalQueueFlow(async () => Response.json({ items: [], next_cursor: null }), unused);
  await newQueue.reload();
  late.resolve(Response.json({ items: [row], next_cursor: null }));
  await reading;
  assert.equal(oldQueue.getSnapshot().page, undefined);
  assert.deepEqual(newQueue.getSnapshot().page.items, []);
});

test('a rejected challenge makes no request, and server denial after step-up never confirms a request', async () => {
  const { createApprovalRequestFlow } = await import('../src/lib/privileged-approvals.ts');
  let challengeDenied = true;
  let posts = 0;
  const flow = createApprovalRequestFlow(target, async (_, init) => {
    if (init.method === 'GET') return Response.json({ eligible: true });
    posts++;
    return Response.json({ detail: 'private server denial' }, { status: 403 });
  }, async () => { if (challengeDenied) throw new Error('private challenge error'); });
  await flow.reload();
  flow.chooseReason('REPLACED_DEVICE');
  await flow.submit();
  assert.equal(posts, 0);
  assert.match(flow.getSnapshot().error, /Step-up could not be completed/);
  challengeDenied = false;
  await flow.reload();
  await flow.submit();
  assert.equal(posts, 1);
  assert.equal(flow.getSnapshot().phase, 'reload');
  assert.equal(flow.getSnapshot().receipt, undefined);
  assert.equal(flow.getSnapshot().retry, false);
  assert.doesNotMatch(flow.getSnapshot().error, /private/);
});

test('queue rejects malformed projections and does not accept a mismatched decision receipt', async () => {
  const { createApprovalQueueFlow } = await import('../src/lib/privileged-approvals.ts');
  let supplied = { ...row, requester_label: 'private requester' };
  const flow = createApprovalQueueFlow(async (_, init) => init.method === 'GET'
    ? Response.json({ items: [supplied], next_cursor: null })
    : Response.json({ approval_id: target, state: 'REJECTED', correlation_id: correlation }), async () => {});
  await flow.reload();
  assert.equal(flow.getSnapshot().page, undefined);
  assert.doesNotMatch(flow.getSnapshot().error, /private/);
  supplied = row;
  await flow.reload();
  await flow.decide(correlation, 'REJECT');
  assert.equal(flow.getSnapshot().phase, 'reload');
  assert.equal(flow.getSnapshot().page, undefined);
  assert.equal(flow.getSnapshot().receipt, undefined);
  assert.match(flow.getSnapshot().error, /could not be confirmed/);
});
