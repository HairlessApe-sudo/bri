import test from 'node:test';
import assert from 'node:assert/strict';
import * as proxy from '../src/lib/backend-proxy.mjs';

const env = { BRI_UI_AUTH_MODE: 'supabase', BRI_API_ORIGIN: 'https://api.example.test' };
const base = 'https://ui.example.test/api/bri';
const id = '00000000-0000-4000-8000-000000000001';
const session = 'fixture-server-token';
const request = (suffix = '', options) => new Request(`${base}/v1/users${suffix}`, options);
const status = (code) => (error) => error instanceof proxy.BackendRequestError && error.status === code;

function unused() { assert.fail('Session lookup must not run'); }

const list = '/v1/users';

test('directory forwards only the verified server session to the fixed list and UUID detail paths', async () => {
  for (const [path, suffix, query] of [[list, '', ''], [list, '?q=A%26B+%2B&limit=100&offset=0', '?q=A%26B+%2B&limit=100&offset=0'], [`${list}/${id}`, `/${id}`, '']]) {
    const target = await proxy.prepareProxyRequest(request(suffix), path, env, async (directory) => {
      assert.equal(directory, true);
      return session;
    });
    assert.equal(target.url, `${env.BRI_API_ORIGIN}${path}${query}`);
    assert.deepEqual([...target.headers], [['authorization', `Bearer ${session}`]]);
  }
});

test('directory is disabled in synthetic mode without looking up a session', async () => {
  await assert.rejects(proxy.prepareProxyRequest(request(), list, { BRI_UI_DEV_IDENTITY: 'fixture' }, unused), status(404));
});

test('directory rejects unapproved methods and non-UUID detail paths before session lookup', async () => {
  for (const method of ['POST', 'DELETE', 'PUT', 'PATCH', 'HEAD']) {
    await assert.rejects(proxy.prepareProxyRequest(request('', { method }), list, env, unused), status(404));
  }
  for (const suffix of ['/me', `/${id}/roles`, `/${id}%2Fextra`, `/${id}\n`]) {
    await assert.rejects(proxy.prepareProxyRequest(request(), `${list}${suffix}`, env, unused), status(404));
  }
});

test('provisioning POST and status GET are not forwarded in hosted or synthetic mode', async () => {
  for (const mode of [env, { BRI_UI_AUTH_MODE: 'synthetic', BRI_UI_DEV_IDENTITY: 'fixture' }]) {
    const post = request('/provisioning', { method: 'POST', body: JSON.stringify({ request_id: id, display_name: 'Fixture', email: 'fixture@example.test' }) });
    await assert.rejects(proxy.prepareProxyRequest(post, `${list}/provisioning`, mode, unused), status(404));
    await assert.rejects(proxy.prepareProxyRequest(request(`/provisioning/${id}`), `${list}/provisioning/${id}`, mode, unused), status(404));
  }
});

test('directory permits only unique list parameters and accepts no detail query parameters', async () => {
  for (const query of ['q=x&q=y', 'offset=0&offset=1', 'limit=25&limit=50', 'role=admin', 'tenant_id=other', 'limit=0', 'limit=101', 'limit=1.5', 'limit=0001', 'offset=-1', 'offset=1e2', 'offset=10001', 'q=%00', `q=${'a'.repeat(129)}`]) {
    await assert.rejects(proxy.prepareProxyRequest(request(`?${query}`), list, env, unused), status(400));
  }
  await assert.rejects(proxy.prepareProxyRequest(request(`/${id}?q=example`), `${list}/${id}`, env, unused), status(400));
});

test('directory rejects client authority headers and requires a server session', async () => {
  for (const name of ['authorization', 'x-dev-identity', 'x-tenant-id', 'x-bri-tenant-context', 'x-role', 'x-bri-role']) {
    await assert.rejects(proxy.prepareProxyRequest(request('', { headers: { [name]: 'fixture-client-value' } }), list, env, unused), status(400));
  }
  await assert.rejects(proxy.prepareProxyRequest(request(), list, env, async () => undefined), status(401));
});

test('the directory obtains the bearer only after verifying claims for that exact token at AAL2', async () => {
  for (const [claims, verificationError, expected] of [
    [{ sub: id, aal: 'aal2' }, null, session],
    [{ sub: id, aal: 'aal1' }, null, undefined],
    [{ aal: 'aal2' }, null, undefined],
    [null, new Error('verification failed'), undefined],
  ]) {
    const auth = {
      getSession: async () => ({ data: { session: { access_token: session } }, error: null }),
      getClaims: async (token) => {
        assert.equal(token, session);
        return { data: { claims }, error: verificationError };
      },
    };
    assert.equal(await proxy.readProxySessionToken(auth, true), expected);
  }
  assert.equal(await proxy.readProxySessionToken({
    getSession: async () => ({ data: { session: null }, error: null }), getClaims: unused,
  }, true), undefined);
});
