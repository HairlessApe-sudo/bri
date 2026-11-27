import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { isScopeId, normalizeQuery, parseScopes, parseSearch } from './unified-contract.mjs';
import { isCursor, parsePublishedEvidence, shape } from './xlsx-governance.mjs';
import { xlsxUuid } from './xlsx-intake.mjs';

const PREFIX = '/unified';
const CONTEXT = 'x-bri-unified-context';
const SEARCH = '/v1/knowledge/search';
const DISCOVERY = `${SEARCH}/scopes`;
const KNOWLEDGE = 'http://127.0.0.1:8018';
const GOVERNANCE = 'http://127.0.0.1:8117'; // Existing local XLSX governance listener.
const MAX_REQUEST = 4096;
const MAX_RECEIPT = 131072;
const MAX_XLSX_RECEIPT = 524288;
const processKey = randomBytes(32);
const framing = ['transfer-encoding', 'expect', 'content-encoding', 'content-disposition', 'content-range', 'range', 'trailer'];
const readerTypes = new Set(['application/json', 'application/json; charset=utf-8']);
const successHeaders = {
  'cache-control': 'private, no-store', 'content-type': 'application/json; charset=utf-8', 'x-content-type-options': 'nosniff',
};
const sendUnavailable = (res) => res.writeHead(503, successHeaders).end('{"version":1,"status":"unavailable"}');

export function unifiedTarget(path, method, query) {
  if (path !== PREFIX && !path.startsWith(`${PREFIX}/`)) return null;
  const resource = path.slice(PREFIX.length);
  const [lead, api, knowledge, format, record, link, version, evidence, ...extra] = resource.split('/');
  const exactVersion = lead === '' && knowledge === 'knowledge' && record && version
    && xlsxUuid.test(record) && xlsxUuid.test(version);
  const csv = exactVersion && api === 'v1' && format === 'csv' && link === 'versions' && evidence === 'evidence' && !extra.length;
  const xlsx = exactVersion && api === 'v2' && format === 'xlsx' && link === 'evidence' && evidence === undefined;
  const search = resource === SEARCH;
  const discovery = resource === DISCOVERY;
  if (!csv && !xlsx && !search && !discovery) return 404;
  if (method !== (search ? 'POST' : 'GET')) return 405;
  if (query !== undefined && (!xlsx || !query.startsWith('cursor=') || !isCursor(query.slice(7)))) return 400;
  return { search, discovery, xlsx, record, version,
    origin: xlsx ? GOVERNANCE : KNOWLEDGE, limit: xlsx ? MAX_XLSX_RECEIPT : MAX_RECEIPT,
    path: query === undefined ? resource : `${resource}?${query}` };
}

function browserClaims(req) {
  return Object.keys(req.headers).some((name) => {
    // Standard browser metadata is not an authority claim and is never forwarded.
    if (name === 'user-agent') return false;
    const canonical = name.replaceAll('_', '-');
    return /^(?:forwarded|via|x-real-ip|proxy-.*|x-forwarded-.*)$/.test(canonical)
      || /^(?:x-)?(?:(?:bri-)?(?:auth|authorization|authentication|dev-identity|sub|subject|sid|node|scope|user|tenant|role|actor|principal|identity|issuer|session|permission|membership)s?(?:-.*)?|idempotency-key)$/.test(canonical)
      || (canonical === CONTEXT && name !== CONTEXT);
  });
}

function single(req, name) {
  const values = req.headersDistinct[name];
  return values?.length === 1 ? values[0] : undefined;
}

function readExact(req, length) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    const timer = setTimeout(() => finish(408), 5000);
    const broken = () => finish(400);
    const end = () => finish(size === length ? 0 : 400);
    const read = (chunk) => {
      size += chunk.length;
      if (size > length) return finish(413);
      chunks.push(chunk);
    };
    function finish(status) {
      clearTimeout(timer);
      req.off('data', read).off('error', broken).off('aborted', broken).off('end', end);
      if (status) { req.pause(); reject(status); }
      else resolve(Buffer.concat(chunks, size));
    }
    req.on('data', read).once('error', broken).once('aborted', broken).once('end', end);
  });
}

// Exactly two JSON string members. Decode keys individually so escaped duplicate
// keys cannot be hidden by JSON.parse's last-member-wins behavior.
const string = String.raw`"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*"`;
const whitespace = String.raw`[ \t\r\n]*`;
const member = `(${string})${whitespace}:${whitespace}(${string})`;
const searchObject = new RegExp(`^${whitespace}\\{${whitespace}${member}${whitespace},${whitespace}${member}${whitespace}\\}${whitespace}$`);
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function searchBody(bytes) {
  const match = searchObject.exec(utf8.decode(bytes));
  if (!match) throw new Error('Invalid search body');
  const [first, a, second, b] = match.slice(1).map((part) => JSON.parse(part));
  const data = { [first]: a, [second]: b };
  if (!shape(data, ['scope_node_id', 'query']) || !isScopeId(data.scope_node_id)) throw new Error('Invalid search body');
  normalizeQuery(data.query); // Validate the normalized byte budget without changing the literal forwarded query.
  return JSON.stringify({ scope_node_id: data.scope_node_id, query: data.query });
}

function receipt(upstream, target) {
  const value = JSON.parse(utf8.decode(upstream.body));
  if (target.discovery || target.search) {
    const parsed = target.discovery ? parseScopes(value) : parseSearch(value);
    if (parsed.status !== 'complete') throw new Error('Invalid success status');
    return parsed;
  }
  const { record, version } = target;
  if (!target.xlsx) {
    if (!shape(value, ['record_id', 'source_version_id', 'first_line', 'last_line', 'original_sha256', 'content_sha256'])
      || value.record_id !== record || value.source_version_id !== version || record !== version
      || ![value.first_line, value.last_line].every(Number.isInteger)
      || value.first_line < 1 || value.first_line > value.last_line || value.last_line > 2147483647
      || !isCursor(value.original_sha256) || !isCursor(value.content_sha256)) throw new Error('Invalid CSV receipt');
    return value;
  }
  if (!value || typeof value !== 'object') throw new Error('Invalid worksheet receipt');
  const { version: contract, source_id, original_sha256, canonical_sha256,
    extractor_version, canonicalization_version, ...worksheet } = value;
  if (contract !== 2 || source_id !== version || !isCursor(original_sha256) || !isCursor(canonical_sha256)
    || extractor_version !== 1 || canonicalization_version !== 1 || !isScopeId(worksheet.node_id)) {
    throw new Error('Invalid worksheet receipt');
  }
  return { ...parsePublishedEvidence(worksheet, record, version), version: contract, source_id, original_sha256,
    canonical_sha256, extractor_version, canonicalization_version };
}

export async function forwardUnified(req, res, target, { browserAuthority, origin, verifiedBearer, loopbackRequest, deny }) {
  if (target.search) res.setHeader('connection', 'close');
  if (browserAuthority(req) || browserClaims(req) || framing.some((name) => req.headers[name] !== undefined)) return deny(res, 400);
  const length = single(req, 'content-length');
  const headers = { accept: 'application/json' };
  let body;
  if (target.search) {
    if (single(req, 'origin') !== origin) return deny(res, 403);
    if (!readerTypes.has(single(req, 'content-type'))) return deny(res, 415);
    if (!/^[1-9][0-9]*$/.test(length ?? '')) return deny(res, 400);
    if (Number(length) > MAX_REQUEST) return deny(res, 413);
    try { body = searchBody(await readExact(req, Number(length))); }
    catch (error) { return deny(res, typeof error === 'number' ? error : 400); }
    Object.assign(headers, { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(body)) });
  } else if (req.headers['content-type'] !== undefined || (req.headers['content-length'] !== undefined && length !== '0')
    || (target.discovery && req.headers[CONTEXT] !== undefined)) return deny(res, 400);

  try {
    const token = await verifiedBearer(req);
    if (res.destroyed) return;
    if (!token) return deny(res, 401, 'A current signed fixture session is required.');
    // The opaque binding is not accepted as authority. Every operation first
    // verifies the cookie and independently rechecks authorization at its reader.
    const fingerprint = createHmac('sha256', processKey).update(token).digest();
    if (!target.discovery) {
      const context = single(req, CONTEXT);
      if (!isCursor(context) || !timingSafeEqual(Buffer.from(context, 'hex'), fingerprint)) return deny(res, 403);
    }
    headers.authorization = ['Bearer', token].join(' ');
    const versionedUnavailable = target.discovery || target.search;
    let upstream;
    try {
      upstream = await loopbackRequest(target.origin, target.path, headers, target.limit, body);
    } catch {
      // Transport errors and the streaming byte cap can reject before a receipt is available.
      return versionedUnavailable ? sendUnavailable(res) : deny(res, 503);
    }
    if (upstream.status === 503 && versionedUnavailable) return sendUnavailable(res);
    if (upstream.status !== 200) return deny(res, upstream.status >= 400 && upstream.status <= 599 ? upstream.status : 502);
    if (!/^application\/json(?:\s*;|$)/i.test(upstream.contentType ?? '')) return deny(res, 502);
    let encoded;
    try { encoded = JSON.stringify(receipt(upstream, target)); } catch { return deny(res, 502); }
    if (Buffer.byteLength(encoded) > target.limit) return deny(res, 502);
    res.writeHead(200, target.discovery ? { ...successHeaders, [CONTEXT]: fingerprint.toString('hex') } : successHeaders).end(encoded);
  } catch {
    return deny(res, 503);
  }
}
