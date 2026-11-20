import { DIRECTORY_FILTERS, DIRECTORY_MAX_OFFSET, DIRECTORY_MAX_QUERY, isDirectoryUserId, isHistoryCursor } from './user-directory.mjs';

// Include encoded aliases in the development log and auth-refresh exclusions.
export const backendProxyPrefix = /^\/(?:a|%61)(?:p|%70)(?:i|%69)(?:\/|%2f)(?:b|%62)(?:r|%72)(?:i|%69)(?:[/?]|%2f|$)/i;

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
  /^\/v1\/sources\/(?!(?:csv|csv-intake)$)[A-Za-z0-9._~-]+$/,
];

const PUBLISHED_CSV = /^(\/v1\/(?:knowledge|sources)\/)(csv:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/;
const LEGACY_CSV_SOURCE = /^\/v1\/sources\/(?:csv|csv-intake)$/;
const DIRECTORY_LIST = '/v1/users';

function isCanonicalCsvRead(path, pathname) {
  const published = PUBLISHED_CSV.exec(path);
  if (published) {
    return pathname === undefined || pathname === `/api/bri${published[1]}${encodeURIComponent(published[2])}`;
  }
  // On the normal backend these exact GETs read provenance for legacy IDs.
  // Do not point the proxy at staged intake or share these paths with a future GET collection.
  return LEGACY_CSV_SOURCE.test(path) && (pathname === undefined || pathname === `/api/bri${path}`);
}

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

function validateBackendTarget(path, searchParams, mode, method, pathname = undefined) {
  const normalized = `/${String(path).replace(/^\/+|\/+$/g, '')}`;
  const directory = normalized === DIRECTORY_LIST || normalized.startsWith(`${DIRECTORY_LIST}/`);
  const userPath = normalized.slice(DIRECTORY_LIST.length + 1);
  const history = directory && userPath.endsWith('/history') && isDirectoryUserId(userPath.slice(0, -'/history'.length));
  const grants = directory && userPath.endsWith('/grants') && isDirectoryUserId(userPath.slice(0, -'/grants'.length));
  // Catch-all params are decoded; the original URL must also match the literal path.
  const isDirectoryRead = directory && mode === 'supabase' && path === normalized
    && (pathname === undefined || pathname === `/api/bri${path}`)
    && (normalized === DIRECTORY_LIST || isDirectoryUserId(userPath) || history || grants);
  const isRead = method === 'GET'
    && (isDirectoryRead || isCanonicalCsvRead(path, pathname) || READ_ROUTES.some((route) => route.test(normalized)));
  const isSessionAction = normalized === '/v1/auth/session' && ['POST', 'DELETE'].includes(method);
  const isRecovery = normalized === '/v1/auth/recovery/invalidate' && method === 'POST';
  if (!isRead && !isSessionAction && !isRecovery) throw new BackendRequestError('Not found', 404);

  if (mode === 'synthetic' && !isRead) throw new BackendRequestError('Not found', 404);
  if (mode === 'supabase' && method !== 'GET' && method !== 'POST' && method !== 'DELETE') {
    throw new BackendRequestError('Not found', 404);
  }

  const params = new URLSearchParams();
  for (const [key, value] of searchParams.entries()) {
    const filter = normalized === DIRECTORY_LIST && Object.hasOwn(DIRECTORY_FILTERS, key) ? DIRECTORY_FILTERS[key] : null;
    const allowed = normalized === DIRECTORY_LIST ? filter !== null || ['q', 'limit', 'offset'].includes(key)
      : history ? ['limit', 'cursor'].includes(key) : normalized === '/v1/knowledge/search' && key === 'q';
    if (!allowed) {
      throw new BackendRequestError('Unsupported query parameter', 400);
    }
    if (params.has(key)) throw new BackendRequestError('Duplicate query parameter', 400);
    if (history && key === 'cursor' && !isHistoryCursor(value)) {
      throw new BackendRequestError('Invalid history pagination parameter', 400);
    }
    if (filter) {
      if (!filter.includes(value)) throw new BackendRequestError('Invalid directory filter', 400);
    } else if (normalized === DIRECTORY_LIST || (history && key === 'limit')) {
      if (key === 'q') {
        if ([...value].length > DIRECTORY_MAX_QUERY || value.includes('\0')) {
          throw new BackendRequestError('Invalid directory query', 400);
        }
      } else {
        const [min, max] = key === 'limit' ? [1, 100] : [0, DIRECTORY_MAX_OFFSET];
        if (!value || /[^0-9]/.test(value) || value.length > String(max).length || Number(value) < min || Number(value) > max) {
          throw new BackendRequestError('Invalid pagination parameter', 400);
        }
      }
    }
    params.append(key, value);
  }
  if (normalized === '/v1/knowledge/search' && !params.has('q')) {
    throw new BackendRequestError('Search query is required', 400);
  }
  if (isSessionAction && params.size) throw new BackendRequestError('Session routes do not accept query parameters', 400);

  return { normalized, params, directory, history, grants };
}

function makeBackendRequest({ normalized, params }, env, mode, accessToken) {
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

  if (!normalized.startsWith('/health') && (!accessToken || typeof accessToken !== 'string' || accessToken.length > 16_384 || !/^[A-Za-z0-9._-]+$/.test(accessToken))) {
    throw new BackendRequestError('Authentication required', 401);
  }
  const headers = new Map();
  if (accessToken) headers.set('authorization', `Bearer ${accessToken}`);
  return { url: target.toString(), headers };
}

export function buildBackendRequest(path, searchParams, env = process.env, options = {}) {
  const mode = resolveUiAuthMode(env);
  const method = String(options.method || 'GET').toUpperCase();
  return makeBackendRequest(validateBackendTarget(path, searchParams, mode, method), env, mode, options.accessToken);
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

export async function prepareProxyRequest(request, path, env, readSessionToken) {
  const method = request.method.toUpperCase();
  const mode = resolveUiAuthMode(env);
  const { pathname, searchParams, href } = new URL(request.url);
  const target = validateBackendTarget(path, searchParams, mode, method, pathname);
  // URLSearchParams does not expose empty query strings or separators alone.
  if (target.grants && href.split('#', 1)[0].includes('?')) throw new BackendRequestError('Unsupported query parameter', 400);
  let accessToken;
  if (mode === 'supabase') {
    assertNoSpoofedIdentityHeaders(request.headers);
    if (target.directory && ['authorization', 'x-role', 'x-bri-role'].some((name) => request.headers.has(name))) {
      throw new BackendRequestError('Client authorization headers are not accepted', 400);
    }
    if (method === 'POST' || method === 'DELETE') {
      assertSameOriginMutation(request.url, request.headers.get('origin'));
      if (request.body !== null) throw new BackendRequestError('Session routes do not accept a body', 400);
    }
    accessToken = await readSessionToken(target.directory);
    if (!accessToken) throw new BackendRequestError('Authentication required', 401);
  }
  return {...makeBackendRequest(target, env, mode, accessToken), accessToken, directory: target.directory, grants: target.grants};
}

export async function readProxySessionToken(auth, directory) {
  const { data: { session }, error } = await auth.getSession();
  const token = error ? undefined : session?.access_token;
  if (!token || !directory) return token;
  // Verify the exact cookie-derived token being sent; the API authorizes the resource.
  const { data, error: claimsError } = await auth.getClaims(token);
  if (!claimsError && data?.claims?.sub && data.claims.aal === 'aal2') return token;
}
