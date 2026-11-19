import test from 'node:test';
import assert from 'node:assert/strict';
import { BackendRequestError, prepareProxyRequest } from '../src/lib/backend-proxy.mjs';

const env = { BRI_UI_AUTH_MODE: 'supabase', BRI_API_ORIGIN: 'https://api.example.test' };
const id = 'abcdefab-0000-4000-8000-000000000001';
const path = `/v1/users/${id}/grants`;
const request = (suffix = path, init) => new Request(`https://ui.example.test/api/bri${suffix}`, init);
const status = (code) => (error) => error instanceof BackendRequestError && error.status === code;
const unused = () => assert.fail('Session lookup must not run');

test('grants GET forwards only the verified directory bearer to the exact upstream path', async () => {
  const target = await prepareProxyRequest(request(), path, env, async (verified) => {
    assert.equal(verified, true);
    return 'fixture-token';
  });
  assert.equal(target.url, `${env.BRI_API_ORIGIN}${path}`);
  assert.equal(target.directory, true);
  assert.deepEqual([...target.headers], [['authorization', 'Bearer fixture-token']]);
  await assert.rejects(prepareProxyRequest(request(), path, env, async () => undefined), status(401));
});

test('grants denies synthetic access, non-GET methods and path aliases before session lookup', async () => {
  await assert.rejects(prepareProxyRequest(request(), path, { BRI_UI_AUTH_MODE: 'synthetic' }, unused), status(404));
  for (const method of ['POST', 'DELETE', 'HEAD', 'OPTIONS', 'PUT', 'PATCH']) {
    await assert.rejects(prepareProxyRequest(request(path, { method }), path, env, unused), status(404));
  }
  for (const [raw, decoded] of [
    [path.replace('/grants', '/%67rants'), path], [path.replace('/grants', '%2Fgrants'), path],
    [path.replace('/grants', '/%2567rants'), path.replace('/grants', '/%67rants')],
    [path.replace('abcdefab', '%61bcdefab'), path], [path.replace('/users', '/%75sers'), path],
    [`${path}/`, path], [`${path}/extra`, `${path}/extra`],
    ['/v1/users/invalid/grants', '/v1/users/invalid/grants'],
  ]) {
    await assert.rejects(prepareProxyRequest(request(raw), decoded, env, unused), status(404));
  }
});

test('grants denies all queries and client authority headers before session lookup', async () => {
  for (const query of ['?', '?&&', '?q=x', '?limit=1', '?scope_id=hidden', '?tenant_id=other', '?%71=x']) {
    await assert.rejects(prepareProxyRequest(request(`${path}${query}`), path, env, unused), status(400));
  }
  for (const name of ['authorization', 'x-dev-identity', 'x-tenant-id', 'x-bri-tenant-context', 'x-role', 'x-bri-role']) {
    await assert.rejects(prepareProxyRequest(request(path, { headers: { [name]: 'fixture' } }), path, env, unused), status(400));
  }
});