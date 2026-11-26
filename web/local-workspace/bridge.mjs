import { request as httpRequest } from 'node:http';
import { isIPv4 } from 'node:net';
import { createServerClient, parseCookieHeader } from '@supabase/ssr';
import { reviewPagePath } from './review-contract.mjs';
import { reviewTarget, forwardReview } from './review-bridge.mjs';

export const LOCAL_HOST = '127.0.0.2';
export const LOCAL_PORT = 3013;
const PREFIX = '/api/bri-local';
export const LOCAL_AUTH_OPTIONS = Object.freeze({
  origin: 'http://127.0.0.1:9013',
  // This matches the existing synthetic registry mapping. It is a claim, never a URL to fetch.
  issuer: 'https://bwqdyibvuecgthtatrtv.supabase.co/auth/v1',
  key: 'bri-local-synthetic-fixture',
  cookieName: 'sb-bri-local-auth-token',
  cookiePath: PREFIX,
});
const BACKEND = 'http://127.0.0.1:8013';
const HOST = `${LOCAL_HOST}:${LOCAL_PORT}`;
const UUID = '(?!00000000-0000-0000-0000-000000000000)[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}';
const uuid = new RegExp(`^${UUID}$`);
const record = new RegExp(`^/(knowledge|sources)/csv%3A(${UUID})$`);
const MAX_RESPONSE = 16 * 1024 * 1024;
// A12 allows 20,000,000 UTF-8 bytes of compact JSON. Nesting it as a JSON string
// can double the size (quotes and backslashes), plus the response metadata.
const MAX_KNOWLEDGE_DETAIL_RESPONSE = 48_000_000;
const responseHeaders = {
  'cache-control': 'no-store',
  'content-type': 'application/json; charset=utf-8',
  'x-content-type-options': 'nosniff',
};

function send(res, status, body) {
  res.writeHead(status, responseHeaders).end(body);
}
const unavailable = 'Local workspace read unavailable.';
const deny = (res, status, detail = unavailable) => send(res, status, JSON.stringify({ detail }));

export function isPrivateWorkspaceRequest(req) {
  let hosts = 0;
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    if (req.rawHeaders[i].toLowerCase() === 'host') hosts++;
  }
  const peer = req.socket.remoteAddress;
  return process.env.NODE_ENV === 'development'
    && req.socket.localAddress === LOCAL_HOST && req.socket.localPort === LOCAL_PORT
    && typeof peer === 'string' && isIPv4(peer) && peer.startsWith('127.')
    && hosts === 1 && req.headers.host === HOST
    && (req.headers.origin === undefined || req.headers.origin === `http://${HOST}`)
    && !Object.keys(req.headers).some((name) => /^(forwarded|via|x-real-ip|proxy-.*|x-forwarded-.*)$/.test(name));
}

function browserAuthority(req) {
  return Object.keys(req.headers).some((name) => /^(authorization|x-node-id|(?:(?:x-)?bri-|x-)?(?:tenant|role|actor|principal|identity|issuer|auth-user|session)(?:-.*)?)$/.test(name));
}

// A direct numeric-loopback socket: no environment proxy/dispatcher, DNS, redirects or shared cache.
function loopbackRequest(origin, path, headers, maxResponse = MAX_RESPONSE, body) {
  return new Promise((resolve, reject) => {
    const outgoing = httpRequest(`${origin}${path}`, {
      method: body === undefined ? 'GET' : 'POST', headers, agent: false, signal: AbortSignal.timeout(8000),
    }, (upstream) => {
      const chunks = [];
      let size = 0;
      upstream.on('error', reject);
      upstream.on('data', (chunk) => {
        size += chunk.length;
        if (size > maxResponse) {
          const error = new Error('Local response exceeds limit');
          reject(error);
          outgoing.destroy(error);
        }
        else chunks.push(chunk);
      });
      upstream.on('end', () => resolve({
        status: upstream.statusCode, contentType: upstream.headers['content-type'], body: Buffer.concat(chunks),
      }));
    });
    outgoing.on('error', reject).end(body);
  });
}

function backendPath(path, rawQuery) {
  const version = `${PREFIX}/v1`;
  if (!path.startsWith(`${version}/`)) return null;
  const resource = path.slice(version.length);
  if (resource === '/knowledge/search') {
    // Exactly one literal q, no encoded aliases, malformed UTF-8 or raw separators.
    if (!rawQuery?.startsWith('q=') || rawQuery.includes('&')) return false;
    let q;
    try { q = decodeURIComponent(rawQuery.slice(2).replaceAll('+', ' ')); } catch { return false; }
    if (!q.trim() || Array.from(q).length > 512 || /[\x00-\x1f\x7f]/.test(q)) return false;
    return `/v1${resource}?${new URLSearchParams({ q })}`;
  }
  const ref = record.exec(resource);
  if (resource !== '/knowledge' && !ref) return null;
  if (rawQuery !== undefined) return false;
  return ref ? `/v1/${ref[1]}/csv:${ref[2]}` : '/v1/knowledge';
}

async function verifiedBearer(req) {
  const cookies = parseCookieHeader(req.headers.cookie ?? '').filter(({ name }) => (
    name === LOCAL_AUTH_OPTIONS.cookieName || new RegExp(`^${LOCAL_AUTH_OPTIONS.cookieName}\\.\\d+$`).test(name)
  ));
  if (!cookies.length) return;
  const { auth } = createServerClient(LOCAL_AUTH_OPTIONS.origin, LOCAL_AUTH_OPTIONS.key, {
    cookieOptions: { name: LOCAL_AUTH_OPTIONS.cookieName, path: LOCAL_AUTH_OPTIONS.cookiePath, httpOnly: true, sameSite: 'lax' },
    cookies: { getAll: () => cookies, setAll: () => {} },
    global: {
      fetch: async (input, init) => {
        // This reader neither refreshes a session nor delegates JWT verification to a user endpoint.
        const jwksPath = '/auth/v1/.well-known/jwks.json';
        if (String(input) !== `${LOCAL_AUTH_OPTIONS.origin}${jwksPath}` || init?.method !== 'GET') {
          return Response.json({ msg: 'Verification requires a current signed fixture' }, { status: 401 });
        }
        const upstream = await loopbackRequest(LOCAL_AUTH_OPTIONS.origin, jwksPath, { accept: 'application/json' });
        if (upstream.status !== 200) return Response.json({ msg: 'Fixture signer unavailable' }, { status: 503 });
        return new Response(upstream.body, { headers: { 'content-type': 'application/json' } });
      },
    },
  });
  const { data: { session }, error } = await auth.getSession();
  const token = error ? null : session?.access_token;
  if (typeof token !== 'string' || token.length > 16384 || !/^[\w-]+\.[\w-]+\.[\w-]+$/.test(token)) return;
  const { data, error: verificationError } = await auth.getClaims(token);
  const claims = data?.claims;
  if (!verificationError && claims?.iss === LOCAL_AUTH_OPTIONS.issuer && claims.aud === 'authenticated'
    && claims.aal === 'aal2' && typeof claims.sub === 'string' && uuid.test(claims.sub)
    && typeof claims.session_id === 'string' && uuid.test(claims.session_id)) return token;
}

export function composeLocalWorkspace(nextHandler) {
  if (process.env.NODE_ENV !== 'development') throw new Error('Local workspace requires development mode');
  return async (req, res) => {
    if (!isPrivateWorkspaceRequest(req)) return deny(res, 403);
    const target = req.url ?? '';
    if (!target.startsWith('/') || /[\\#\x00-\x20\x7f]/.test(target)) return deny(res, 404);
    const separator = target.indexOf('?');
    const path = separator === -1 ? target : target.slice(0, separator);
    const query = separator === -1 ? undefined : target.slice(separator + 1);
    if (path !== PREFIX && !path.startsWith(`${PREFIX}/`)) {
      // Only the separate Next UI and its assets are dispatched to Next. No release routes, even by alias.
      if (path === '/review' || reviewPagePath.test(path)) {
        if (req.method !== 'GET' && req.method !== 'HEAD') return deny(res, 405);
        res.setHeader('cache-control', 'no-store');
        return nextHandler(req, res);
      }
      if (path === '/' || path === '/knowledge' || record.test(path) || path.startsWith('/_next/static/')) {
        return nextHandler(req, res);
      }
      return deny(res, 404);
    }
    const review = reviewTarget(path.slice(PREFIX.length), req.method, query);
    if (typeof review === 'number') return deny(res, review);
    if (review) return forwardReview(req, res, review, {
      browserAuthority, origin: `http://${HOST}`, verifiedBearer, loopbackRequest, send, deny,
    });
    if (req.method !== 'GET') return deny(res, 405);
    const upstreamPath = backendPath(path, query);
    if (upstreamPath === null) return deny(res, 404);
    if (!upstreamPath || browserAuthority(req) || req.headers['transfer-encoding'] || (req.headers['content-length'] && req.headers['content-length'] !== '0')) {
      return deny(res, 400);
    }
    try {
      const token = await verifiedBearer(req);
      if (!token) return deny(res, 401, 'A current signed fixture session is required.');
      // backendPath has already validated the exact route and record UUID.
      const limit = upstreamPath.startsWith('/v1/knowledge/csv:') ? MAX_KNOWLEDGE_DETAIL_RESPONSE : MAX_RESPONSE;
      const upstream = await loopbackRequest(BACKEND, upstreamPath, { authorization: `Bearer ${token}`, accept: 'application/json' }, limit);
      if (upstream.status !== 200) return deny(res, upstream.status >= 400 && upstream.status <= 599 ? upstream.status : 502);
      if (!/^application\/json(?:\s*;|$)/i.test(upstream.contentType ?? '')) return deny(res, 502);
      return send(res, 200, upstream.body);
    } catch {
      return deny(res, 503);
    }
  };
}
