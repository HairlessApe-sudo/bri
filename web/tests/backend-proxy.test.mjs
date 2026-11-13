import test from 'node:test';
import assert from 'node:assert/strict';
import { errorMessageForStatus } from '../src/lib/client-errors.mjs';
import { BackendRequestError, buildBackendRequest } from '../src/lib/backend-proxy.mjs';

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

test('rejects repeated search parameters instead of changing query interpretation', () => {
  assert.throws(() => buildBackendRequest('/v1/knowledge/search', new URLSearchParams('q=first&q=second'), config), /Duplicate query parameter/);
});
