export class BackendRequestError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'BackendRequestError';
    this.status = status;
  }
}

const READ_ROUTES = [
  /^\/health$/,
  /^\/v1\/organizations\/structure$/,
  /^\/v1\/organizations\/nodes\/[A-Za-z0-9._~-]+$/,
  /^\/v1\/knowledge$/,
  /^\/v1\/knowledge\/search$/,
  /^\/v1\/knowledge\/(?!proposals$)[A-Za-z0-9._~-]+$/,
  /^\/v1\/sources\/[A-Za-z0-9._~-]+$/,
];

export function buildBackendRequest(path, searchParams, env = process.env) {
  const normalized = `/${String(path).replace(/^\/+|\/+$/g, '')}`;
  if (!READ_ROUTES.some((route) => route.test(normalized))) {
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

  const origin = env.BRI_API_ORIGIN || 'http://127.0.0.1:8000';
  let base;
  try {
    base = new URL(origin);
  } catch {
    throw new Error('Backend origin must be loopback HTTP');
  }
  if (base.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(base.hostname) || base.username || base.password || base.pathname !== '/' || base.search || base.hash) {
    throw new Error('Backend origin must be loopback HTTP');
  }

  const identity = env.BRI_UI_DEV_IDENTITY;
  if (typeof identity !== 'string' || !/^[A-Za-z0-9._-]{1,120}$/.test(identity)) {
    throw new Error('A valid server-side development identity must be configured');
  }

  const target = new URL(normalized, base);
  target.search = params.toString();
  return {
    url: target.toString(),
    headers: new Map([['x-dev-identity', identity]]),
  };
}
