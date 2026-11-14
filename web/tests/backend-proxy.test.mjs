import test from 'node:test';
import assert from 'node:assert/strict';
import { errorMessageForStatus } from '../src/lib/client-errors.mjs';
import { BackendRequestError, assertNoSpoofedIdentityHeaders, assertSameOriginMutation, buildBackendRequest, resolveUiAuthMode } from '../src/lib/backend-proxy.mjs';

test('maps access denied, identity, missing record, and server failures to explicit states', () => {
  assert.match(errorMessageForStatus(403), /Access denied/);
  assert.match(errorMessageForStatus(401), /identity was not accepted/);
  assert.match(errorMessageForStatus(404), /not available/);
  assert.match(errorMessageForStatus(503), /API is unavailable/);
});

const config = {
  BRI_API_ORIGIN: 'http://127.0.0.1:8000',
  BRI_UI_DEV_IDENTITY: 'user-noordlicht-reader',
};

test('forwards only approved read routes with the server-configured identity', () => {
  const result = buildBackendRequest('/v1/knowledge/search', new URLSearchParams('q=retention'), config);
  assert.equal(result.url, 'http://127.0.0.1:8000/v1/knowledge/search?q=retention');
  assert.deepEqual([...result.headers.entries()], [['x-dev-identity', 'user-noordlicht-reader']]);
});

test('rejects mutation and unapproved backend routes as not found', () => {
  const isHiddenRoute = (error) => error instanceof BackendRequestError && error.status === 404;
  assert.throws(() => buildBackendRequest('/v1/knowledge/proposals', new URLSearchParams(), config), isHiddenRoute);
  assert.throws(() => buildBackendRequest('/admin', new URLSearchParams(), config), isHiddenRoute);
});

test('rejects unsupported and duplicated query parameters as bad requests', () => {
  const isBadRequest = (error) => error instanceof BackendRequestError && error.status === 400;
  assert.throws(() => buildBackendRequest('/v1/knowledge', new URLSearchParams('tenant_id=other'), config), isBadRequest);
  assert.throws(() => buildBackendRequest('/v1/knowledge/search', new URLSearchParams('q=first&q=second'), config), isBadRequest);
});

test('requires a loopback backend and a configured server identity', () => {
  assert.throws(() => buildBackendRequest('/v1/knowledge', new URLSearchParams(), { ...config, BRI_API_ORIGIN: 'https://example.com' }), /loopback HTTP/);
  assert.throws(() => buildBackendRequest('/v1/knowledge', new URLSearchParams(), { ...config, BRI_UI_DEV_IDENTITY: '' }), /identity must be configured/);
});

test('hosted Supabase mode forwards only the server session bearer to an HTTPS API', () => {
  const hosted = {
    BRI_UI_AUTH_MODE: 'supabase',
    BRI_API_ORIGIN: 'https://api.example.test',
  };
  const result = buildBackendRequest(
    '/v1/knowledge/search',
    new URLSearchParams('q=retention'),
    hosted,
    { method: 'GET', accessToken: 'server-session-token' },
  );
  assert.equal(result.url, 'https://api.example.test/v1/knowledge/search?q=retention');
  assert.deepEqual([...result.headers.entries()], [['authorization', 'Bearer server-session-token']]);
});

test('hosted Supabase mode allows only bodyless session start and revoke methods', () => {
  const hosted = { BRI_UI_AUTH_MODE: 'supabase', BRI_API_ORIGIN: 'https://api.example.test' };
  for (const method of ['POST', 'DELETE']) {
    const result = buildBackendRequest('/v1/auth/session', new URLSearchParams(), hosted, {
      method,
      accessToken: 'server-session-token',
    });
    assert.equal(result.url, 'https://api.example.test/v1/auth/session');
    assert.deepEqual([...result.headers.entries()], [['authorization', 'Bearer server-session-token']]);
  }
});

test('hosted mode denies missing sessions, synthetic writes, unapproved methods, and spoof paths', () => {
  const hosted = { BRI_UI_AUTH_MODE: 'supabase', BRI_API_ORIGIN: 'https://api.example.test' };
  const local = { ...config };
  assert.throws(
    () => buildBackendRequest('/v1/knowledge', new URLSearchParams(), hosted, { method: 'GET' }),
    (error) => error instanceof BackendRequestError && error.status === 401,
  );
  assert.throws(() => buildBackendRequest('/v1/knowledge', new URLSearchParams(), hosted, {
    method: 'POST', accessToken: 'server-session-token',
  }), (error) => error instanceof BackendRequestError && error.status === 404);
  assert.throws(() => buildBackendRequest('/v1/auth/session', new URLSearchParams(), local, {
    method: 'POST',
  }), (error) => error instanceof BackendRequestError && error.status === 404);
  assert.throws(() => buildBackendRequest('/v1/auth/session', new URLSearchParams('tenant_id=x'), hosted, {
    method: 'POST', accessToken: 'server-session-token',
  }), (error) => error instanceof BackendRequestError && error.status === 400);
});

test('hosted mode requires a fixed HTTPS origin and rejects malformed session tokens', () => {
  const hosted = { BRI_UI_AUTH_MODE: 'supabase', BRI_API_ORIGIN: 'http://api.example.test' };
  assert.throws(() => buildBackendRequest('/v1/knowledge', new URLSearchParams(), hosted, {
    method: 'GET', accessToken: 'server-session-token',
  }), /HTTPS/);
  assert.throws(() => buildBackendRequest('/v1/knowledge', new URLSearchParams(), {
    BRI_UI_AUTH_MODE: 'supabase', BRI_API_ORIGIN: 'https://api.example.test',
  }, { method: 'GET', accessToken: 'bad token' }),
    (error) => error instanceof BackendRequestError && error.status === 401,
  );
});

test('requires an exact same-origin header for state-changing proxy requests', () => {
  assert.doesNotThrow(() => assertSameOriginMutation('https://ui.example.test/api/bri/session', 'https://ui.example.test'));
  for (const origin of [undefined, 'https://attacker.example', 'null']) {
    assert.throws(
      () => assertSameOriginMutation('https://ui.example.test/api/bri/session', origin),
      (error) => error instanceof BackendRequestError && error.status === 403,
    );
  }
});

test('rejects repeated search parameters instead of changing query interpretation', () => {
  assert.throws(() => buildBackendRequest('/v1/knowledge/search', new URLSearchParams('q=first&q=second'), config), /Duplicate query parameter/);
});

test('requires hosted production to explicitly use Supabase Auth', () => {
  assert.equal(resolveUiAuthMode({ NODE_ENV: 'development' }), 'synthetic');
  assert.equal(resolveUiAuthMode({ NODE_ENV: 'production', BRI_UI_AUTH_MODE: 'supabase' }), 'supabase');
  assert.throws(() => resolveUiAuthMode({ NODE_ENV: 'production' }), /must explicitly use Supabase/);
  assert.throws(() => resolveUiAuthMode({ NODE_ENV: 'production', BRI_UI_AUTH_MODE: 'synthetic' }), /must explicitly use Supabase/);
});

test('rejects caller-supplied identity and tenant headers but never uses caller Authorization', () => {
  assert.doesNotThrow(() => assertNoSpoofedIdentityHeaders(new Headers({ authorization: 'Bearer untrusted' })));
  for (const name of ['x-dev-identity', 'x-tenant-id', 'x-bri-tenant-context']) {
    assert.throws(
      () => assertNoSpoofedIdentityHeaders(new Headers({ [name]: 'attacker-value' })),
      (error) => error instanceof BackendRequestError && error.status === 400,
    );
  }
});
