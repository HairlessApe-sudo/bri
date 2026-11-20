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
const historySuffix = `/${id}/history`;
const history = `${list}${historySuffix}`;

test('history rejects every unsupported query before session lookup', async () => {
  for (const query of ['q=x', 'offset=0', 'limit=0', 'limit=101', 'limit=1.5', 'limit=1e1', 'limit=0001', 'limit=',
    'limit=1%0A', 'limit=1&limit=2', 'limit=1&%6cimit=2', 'cursor=', 'cursor=invalid', `cursor=${id}%0A`,
    'cursor=ABCDEFAB-0000-0000-0000-000000000001', `cursor=${id}&cursor=${id}`]) {
    await assert.rejects(proxy.prepareProxyRequest(request(`${historySuffix}?${query}`), history, env, unused), status(400));
  }
});

test('history is exact, GET-only, and denied in synthetic mode before session lookup', async () => {
  await assert.rejects(proxy.prepareProxyRequest(request(historySuffix), history, { BRI_UI_AUTH_MODE: 'synthetic' }, unused), status(404));
  for (const method of ['POST', 'DELETE', 'PUT', 'PATCH', 'HEAD', 'OPTIONS']) {
    await assert.rejects(proxy.prepareProxyRequest(request(historySuffix, { method }), history, env, unused), status(404));
  }
  for (const [suffix, path] of [
    [`/${id}/%68istory`, history], [`/${id}%2Fhistory`, history], [`/${id}/%2568istory`, `${list}/${id}/%68istory`],
    [`/${id}/history/`, history], [`/${id}/history/extra`, `${history}/extra`], ['/invalid/history', `${list}/invalid/history`],
  ]) {
    await assert.rejects(proxy.prepareProxyRequest(request(suffix), path, env, unused), status(404));
  }
});

test('history forwards optional bounds and enforces the directory session boundary', async () => {
  for (const query of ['', '?limit=1', '?limit=025', `?cursor=${id}`, `?limit=100&cursor=${id}`]) {
    const target = await proxy.prepareProxyRequest(request(`${historySuffix}${query}`), history, env, async (verified) => {
      assert.equal(verified, true);
      return session;
    });
    assert.equal(target.url, `${env.BRI_API_ORIGIN}${history}${query}`);
    assert.deepEqual([...target.headers], [['authorization', `Bearer ${session}`]]);
  }
  await assert.rejects(proxy.prepareProxyRequest(request(historySuffix), history, env, async () => undefined), status(401));
  for (const name of ['authorization', 'x-dev-identity', 'x-tenant-id', 'x-bri-tenant-context', 'x-role', 'x-bri-role']) {
    await assert.rejects(proxy.prepareProxyRequest(request(historySuffix, { headers: { [name]: 'fixture' } }), history, env, unused), status(400));
  }
});

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

test('lifecycle GET and PATCH are blocked before session lookup in hosted and synthetic mode', async () => {
  const suffix = `/${id}/lifecycle`;
  for (const mode of [env, { BRI_UI_AUTH_MODE: 'synthetic', BRI_UI_DEV_IDENTITY: 'fixture' }]) {
    for (const method of ['GET', 'PATCH']) {
      await assert.rejects(proxy.prepareProxyRequest(request(suffix, { method }), `${list}${suffix}`, mode, unused), status(404));
    }
  }
});

test('delegation GET and PATCH, including encoded paths, are denied before session lookup', async () => {
  for (const mode of [env, { BRI_UI_AUTH_MODE: 'synthetic', BRI_UI_DEV_IDENTITY: 'fixture' }]) {
    for (const suffix of [`/${id}/delegation`, `/${id}/%64elegation`, `/${id}%2Fdelegation`, `/${id}/%2564elegation`]) {
      const path = `${list}${suffix}`;
      for (const target of new Set([path, decodeURIComponent(path)])) {
        await assert.rejects(proxy.prepareProxyRequest(request(`${suffix}?node=fixture&permission=knowledge%3Aread`), target, mode, unused), status(404));
        await assert.rejects(proxy.prepareProxyRequest(request(suffix, { method: 'PATCH', body: '{}' }), target, mode, unused), status(404));
      }
    }
  }
});

test('deactivation GET and PATCH are denied before session lookup, including encoded paths', async () => {
  for (const mode of [env, { BRI_UI_AUTH_MODE: 'synthetic', BRI_UI_DEV_IDENTITY: 'fixture' }]) {
    for (const suffix of [`/${id}/deactivation`, `/${id}/%64eactivation`, `/${id}%2Fdeactivation`, `/${id}/%2564eactivation`]) {
      for (const target of new Set([`${list}${suffix}`, decodeURIComponent(`${list}${suffix}`)])) {
        await assert.rejects(proxy.prepareProxyRequest(request(suffix), target, mode, unused), status(404));
        const patch = request(suffix, { method: 'PATCH', body: '{"expected_version":"7","reason":"account_closed"}' });
        await assert.rejects(proxy.prepareProxyRequest(patch, target, mode, unused), status(404));
      }
    }
  }
});

test('directory permits only unique list parameters and accepts no detail query parameters', async () => {
  for (const query of ['q=x&q=y', 'offset=0&offset=1', 'limit=25&limit=50', 'role=admin', 'tenant_id=other', 'limit=0', 'limit=101', 'limit=1.5', 'limit=0001', 'offset=-1', 'offset=1e2', 'offset=10001', 'q=%00', `q=${'a'.repeat(129)}`]) {
    await assert.rejects(proxy.prepareProxyRequest(request(`?${query}`), list, env, unused), status(400));
  }
  await assert.rejects(proxy.prepareProxyRequest(request(`/${id}?q=example`), `${list}/${id}`, env, unused), status(400));
});

test('overview forwards only the documented exact list filters with bounded search pagination', async () => {
  for (const [key, values] of Object.entries({ status: ['pending', 'active', 'suspended', 'deactivated'],
    role: ['user', 'superuser'], mfa_status: ['verified', 'unknown'] })) {
    for (const value of values) {
      const query = `?q=Alice+%26+Bob&limit=25&offset=10000&${key}=${value}`;
      const target = await proxy.prepareProxyRequest(request(query), list, env, async (directory) => {
        assert.equal(directory, true);
        return session;
      });
      assert.equal(target.url, `${env.BRI_API_ORIGIN}${list}${query}`);
      for (const suffix of [`/${id}`, historySuffix, `/${id}/grants`]) {
        await assert.rejects(proxy.prepareProxyRequest(request(`${suffix}?${key}=${value}`), `${list}${suffix}`, env, unused), status(400));
      }
    }
    for (const query of [`${key}=`, `${key}=ADMIN`, `${key}=constructor`, `${key}=${values[0]}%0A`,
      `${key}=${values[0]}&%${key.charCodeAt(0).toString(16)}${key.slice(1)}=${values[0]}`]) {
      await assert.rejects(proxy.prepareProxyRequest(request(`?${query}`), list, env, unused), status(400));
    }
  }
});

test('overview rejects decoded list aliases before session lookup', async () => {
  for (const path of ['/api/bri/v1/%75sers', '/api/bri/v1/users/', '/api/bri/%76%31/users']) {
    for (const search of ['', '?status=pending', '?status=invalid']) {
      await assert.rejects(proxy.prepareProxyRequest(new Request(`https://ui.example.test${path}${search}`), list, env, unused), status(404));
    }
  }
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
