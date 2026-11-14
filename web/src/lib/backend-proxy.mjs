export class BackendRequestError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'BackendRequestError';
    this.status = status;
  }
}

const READ_ROUTES = [
  /^\/health$/,
  /^\/live$/,
  /^\/ready$/,
  /^\/v1\/me\/tenants$/,
  /^\/v1\/organizations\/structure$/,
  /^\/v1\/organizations\/nodes\/[A-Za-z0-9._~-]+$/,
  /^\/v1\/knowledge$/,
  /^\/v1\/knowledge\/search$/,
  /^\/v1\/knowledge\/(?!proposals$)[A-Za-z0-9._~-]+$/,
  /^\/v1\/sources\/[A-Za-z0-9._~-]+$/,
];

function backendOrigin(env, mode) {
  const fallback = mode === 'synthetic' ? 'http://127.0.0.1:8000' : '';
  const origin = env.BRI_API_ORIGIN || fallback;
  let base;
  try {
    base = new URL(origin);
  } catch {
    throw new Error(mode === 'synthetic' ? 'Backend origin must be loopback HTTP' : 'Backend origin must be a fixed HTTPS origin');
  }
  const hasExtraParts = base.username || base.password || base.pathname !== '/' || base.search || base.hash;
  if (hasExtraParts || base.hostname.endsWith('.')) {
    throw new Error(mode === 'synthetic' ? 'Backend origin must be loopback HTTP' : 'Backend origin must be a fixed HTTPS origin');
  }
  if (mode === 'synthetic' && (base.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(base.hostname))) {
    throw new Error('Backend origin must be loopback HTTP');
  }
  if (mode === 'supabase' && (base.protocol !== 'https:' || !base.hostname)) {
    throw new Error('Backend origin must be a fixed HTTPS origin');
  }
  return base;
}

export function resolveUiAuthMode(env = process.env) {
  const mode = env.BRI_UI_AUTH_MODE;
  if (!mode) {
    if (env.NODE_ENV === 'production') {
      throw new Error('BRI_UI_AUTH_MODE must explicitly use Supabase Auth in production');
    }
    return 'synthetic';
  }
  if (!['synthetic', 'supabase'].includes(mode)) {
    throw new Error('UI authentication mode must be synthetic or supabase');
  }
  if (env.NODE_ENV === 'production' && mode !== 'supabase') {
    throw new Error('BRI_UI_AUTH_MODE must explicitly use Supabase Auth in production');
  }
  return mode;
}

export function buildBackendRequest(path, searchParams, env = process.env, options = {}) {
  const method = String(options.method || 'GET').toUpperCase();
  const normalized = `/${String(path).replace(/^\/+|\/+$/g, '')}`;
  const isRead = method === 'GET' && READ_ROUTES.some((route) => route.test(normalized));
  const isSessionAction = normalized === '/v1/auth/session' && ['POST', 'DELETE'].includes(method);
  if (!isRead && !isSessionAction) throw new BackendRequestError('Not found', 404);

  const mode = resolveUiAuthMode(env);
  if (mode === 'synthetic' && !isRead) throw new BackendRequestError('Not found', 404);
  if (mode === 'supabase' && method !== 'GET' && method !== 'POST' && method !== 'DELETE') {
    throw new BackendRequestError('Not found', 404);
  }

  const params = new URLSearchParams();
  for (const [key, value] of searchParams.entries()) {
    if (normalized !== '/v1/knowledge/search' || key !== 'q') {
      throw new BackendRequestError('Unsupported query parameter', 400);
    }
    if (params.has(key)) throw new BackendRequestError('Duplicate query parameter', 400);
    params.append(key, value);
  }
  if (normalized === '/v1/knowledge/search' && !params.has('q')) {
    throw new BackendRequestError('Search query is required', 400);
  }
  if (isSessionAction && params.size) throw new BackendRequestError('Session routes do not accept query parameters', 400);

  const base = backendOrigin(env, mode);
  const target = new URL(normalized, base);
  target.search = params.toString();

  if (mode === 'synthetic') {
    const identity = env.BRI_UI_DEV_IDENTITY;
    if (typeof identity !== 'string' || !/^[A-Za-z0-9._-]{1,120}$/.test(identity)) {
      throw new Error('A valid server-side development identity must be configured');
    }
    return { url: target.toString(), headers: new Map([['x-dev-identity', identity]]) };
  }

  const accessToken = options.accessToken;
  if (!normalized.startsWith('/health') && (!accessToken || typeof accessToken !== 'string' || accessToken.length > 16_384 || !/^[A-Za-z0-9._-]+$/.test(accessToken))) {
    throw new BackendRequestError('Authentication required', 401);
  }
  const headers = new Map();
  if (accessToken) headers.set('authorization', `Bearer ${accessToken}`);
  return { url: target.toString(), headers };
}

export function assertNoSpoofedIdentityHeaders(headers) {
  for (const name of ['x-dev-identity', 'x-tenant-id', 'x-bri-tenant-context']) {
    if (headers.has(name)) {
      throw new BackendRequestError('Client identity and tenant headers are not accepted', 400);
    }
  }
}

export function assertSameOriginMutation(requestUrl, originHeader) {
  let requestOrigin;
  try {
    requestOrigin = new URL(requestUrl).origin;
  } catch {
    throw new BackendRequestError('Invalid request origin', 403);
  }
  if (typeof originHeader !== 'string' || originHeader !== requestOrigin) {
    throw new BackendRequestError('Cross-origin request denied', 403);
  }
}
