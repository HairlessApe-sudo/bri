import { intakePath, maxWorkbookBytes, parseIntakeReceipt, xlsxMedia, xlsxNode, xlsxUuid } from './xlsx-intake.mjs';
import { isCursor, isXlsxId, parsePublishedEvidence, parsePublishedRecord, parseXlsxDecision, parseXlsxProposal,
  parseXlsxQueue, queueLimit, xlsxPublishedPath, xlsxReviewPath } from './xlsx-governance.mjs';

const INTAKE = 'http://127.0.0.1:8116';
const GOVERNANCE = 'http://127.0.0.1:8117';
export const maxXlsxResponse = 512 * 1024;

export function governanceTarget(path, method, query) {
  if (path === xlsxPublishedPath || path.startsWith(`${xlsxPublishedPath}/`)) return publishedTarget(path, method, query);
  let id;
  let mutation = false;
  if (path !== xlsxReviewPath) {
    if (!path.startsWith(`${xlsxReviewPath}/`)) return null;
    const part = path.slice(xlsxReviewPath.length + 1);
    mutation = part.endsWith('/decision');
    const segment = mutation ? part.slice(0, -9) : part;
    id = segment.replace(/^xlsx%3A/, 'xlsx:');
    if (!isXlsxId(id) || encodeURIComponent(id) !== segment) return 404;
  }
  if (method !== (mutation ? 'POST' : 'GET')) return 405;
  const params = new Map();
  if (query !== undefined) for (const part of query.split('&')) {
    const [key, value, extra] = part.split('=');
    if (mutation || !value || extra !== undefined || params.has(key)
      || !(key === 'cursor' ? isCursor(value) : !id && key === 'limit' && /^(?:[1-9]|1[0-9]|20)$/.test(value))) return 400;
    params.set(key, value);
  }
  return { mutation, path: xlsxReviewPath + (id ? `/${id}` : '') + (mutation ? '/decision' : '')
      + (params.size ? `?${new URLSearchParams(params)}` : ''),
    decode: (value, decision) => mutation ? parseXlsxDecision(value, id, decision) : id ? parseXlsxProposal(value, id)
      : parseXlsxQueue(value, Number(params.get('limit') ?? queueLimit)) };
}

function publishedTarget(path, method, query) {
  const segments = path.slice(xlsxPublishedPath.length + 1).split('/');
  const [record, literal, version] = segments;
  if (!xlsxUuid.test(record) || (segments.length !== 1
    && (segments.length !== 3 || literal !== 'evidence' || !xlsxUuid.test(version)))) return 404;
  if (method !== 'GET') return 405;
  if (query !== undefined && (!version || !query.startsWith('cursor=') || !isCursor(query.slice(7)))) return 400;
  return { mutation: false, path: path + (query ? `?${query}` : ''), decode: version
    ? (value) => parsePublishedEvidence(value, record, version) : (value) => parsePublishedRecord(value, record) };
}

export async function forwardGovernance(req, res, target, { browserAuthority, origin, verifiedBearer, loopbackRequest, send, deny }) {
  if (target.mutation) res.setHeader('connection', 'close');
  if (browserAuthority(req) || xlsxAuthoritySpoof(req) || rejectAlternateFraming(req)) return deny(res, 400);
  const length = single(req, 'content-length');
  const headers = { accept: 'application/json' };
  let body;
  let decision;
  if (target.mutation) {
    if (req.headers.origin !== origin) return deny(res, 403);
    if (single(req, 'content-type') !== 'application/json') return deny(res, 415);
    const key = single(req, 'idempotency-key');
    if (!key || !xlsxUuid.test(key) || !/^[1-9][0-9]*$/.test(length ?? '')) return deny(res, 400);
    if (Number(length) > 1024) return deny(res, 413);
    try {
      const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(await readExact(req, Number(length)));
      const match = /^[\x20\t\r\n]*\{[\x20\t\r\n]*"decision"[\x20\t\r\n]*:[\x20\t\r\n]*"(approve|reject)"[\x20\t\r\n]*\}[\x20\t\r\n]*$/.exec(text);
      if (!match) return deny(res, 400);
      decision = match[1];
      body = JSON.stringify({ decision });
      Object.assign(headers, { 'content-type': 'application/json', 'content-length': String(Buffer.byteLength(body)), 'idempotency-key': key });
    } catch (error) { return deny(res, typeof error === 'number' ? error : 400); }
  } else if ((length !== undefined && length !== '0') || ['content-type', 'idempotency-key'].some((name) => req.headers[name] !== undefined)) {
    return deny(res, 400);
  }
  try {
    const token = await verifiedBearer(req);
    if (res.destroyed) return;
    if (!token) return deny(res, 401, 'A current signed fixture session is required.');
    headers.authorization = ['Bearer', token].join(' ');
    const upstream = await loopbackRequest(GOVERNANCE, target.path, headers, maxXlsxResponse, body);
    return xlsxResponse(upstream, 200, (value) => target.decode(value, decision), res, send, deny, [400, 401, 403, 404, 409, 422, 503]);
  } catch { return deny(res, 503); }
}

export function intakeTarget(path, method, query) {
  const id = path.startsWith(`${intakePath}/`) && path.slice(intakePath.length + 1);
  const upload = path === intakePath;
  if (!upload && (!id || !xlsxUuid.test(id))) return null;
  if (method !== (upload ? 'POST' : 'GET')) return 405;
  if (query !== undefined) return 400;
  return { path, upload, id: id || undefined };
}

function readExact(req, length) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    const timer = setTimeout(() => finish(408), 5000);
    const bad = () => finish(400);
    const data = (chunk) => {
      size += chunk.length;
      if (size > length) return finish(413);
      chunks.push(chunk);
    };
    const end = () => finish(size === length ? null : 400);
    function finish(status) {
      clearTimeout(timer);
      req.off('data', data).off('error', bad).off('aborted', bad).off('end', end);
      if (status) { req.pause(); reject(status); }
      else resolve(Buffer.concat(chunks, size));
    }
    req.on('data', data).once('error', bad).once('aborted', bad).once('end', end);
  });
}

function single(req, name) {
  const values = req.headersDistinct[name];
  return values?.length === 1 ? values[0] : undefined;
}

function rejectAlternateFraming(req) {
  return ['transfer-encoding', 'expect', 'content-encoding', 'content-disposition', 'content-range', 'range', 'trailer']
    .some((name) => req.headers[name] !== undefined);
}

function xlsxAuthoritySpoof(req) {
  return Object.keys(req.headers).some((name) => {
    const canonical = name.replaceAll('_', '-');
    return /^(?:x-)?(?:dev-identity|sub|sid|node-id|scope-(?:node-)?id|user-id|permissions)$/.test(canonical)
      && name !== 'x-node-id';
  });
}

async function xlsxResponse(upstream, expected, decode, res, send, deny, known) {
  if (upstream.status !== expected) return deny(res, known.includes(upstream.status) ? upstream.status : 502);
  if (!/^application\/json(?:\s*;|$)/i.test(upstream.contentType ?? '')) return deny(res, 502);
  let body;
  try { body = JSON.stringify(decode(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(upstream.body)))); }
  catch { return deny(res, 502); }
  return Buffer.byteLength(body) <= maxXlsxResponse ? send(res, expected, body) : deny(res, 502);
}

export async function forwardIntake(req, res, target, { browserAuthority, origin, verifiedBearer, loopbackRequest, send, deny }) {
  const { upload, path, id } = target;
  if (upload) res.setHeader('connection', 'close');
  if (browserAuthority(req, upload) || xlsxAuthoritySpoof(req) || rejectAlternateFraming(req)) return deny(res, 400);
  const length = single(req, 'content-length');
  const headers = { accept: 'application/json' };
  if (upload) {
    if (req.headers.origin !== origin) return deny(res, 403);
    if (single(req, 'content-type') !== xlsxMedia) return deny(res, 415);
    const node = single(req, 'x-node-id');
    const key = single(req, 'idempotency-key');
    if (!node || !xlsxNode.test(node) || !key || !xlsxUuid.test(key) || !/^[1-9][0-9]*$/.test(length ?? '')) return deny(res, 400);
    if (Number(length) > maxWorkbookBytes) return deny(res, 413);
    Object.assign(headers, { 'content-type': xlsxMedia, 'content-length': length, 'x-node-id': node, 'idempotency-key': key });
  } else if ((length !== undefined && length !== '0') || ['content-type', 'idempotency-key'].some((name) => req.headers[name] !== undefined)) {
    return deny(res, 400);
  }
  try {
    // Start reading immediately; the body is bounded and never forwarded without verification.
    const body = upload ? await readExact(req, Number(length)) : undefined;
    const token = await verifiedBearer(req);
    if (res.destroyed) return;
    if (!token) return deny(res, 401, 'A current signed fixture session is required.');
    headers.authorization = ['Bearer', token].join(' ');
    const upstream = await loopbackRequest(INTAKE, path, headers, maxXlsxResponse, body);
    return xlsxResponse(upstream, upload ? 202 : 200, (value) => parseIntakeReceipt(value, id), res, send, deny,
      [400, 401, 403, 404, 409, 413, 415, 422, 503]);
  } catch (error) {
    return deny(res, typeof error === 'number' ? error : 503);
  }
}
