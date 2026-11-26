import { reviewResource, encodedProposal, uuid, isReviewState, isDecision,
  maxReviewOffset, reviewDefaultLimit, parseQueue, parseDetail, parseDecision } from './review-contract.mjs';

const REVIEW_BACKEND = 'http://127.0.0.1:8114';
const base = `/v1${reviewResource}`;
const record = new RegExp(`^${base}/${encodedProposal}(/decision)?$`);
const MAX_RESPONSE = 512 * 1024;
const MAX_DECISION_BYTES = 512;
const DECISION_TIMEOUT_MS = 1500;

export function reviewTarget(path, method, query) {
  const match = record.exec(path);
  if (path !== base && !match) return null;
  const id = match && `csv:${match[1]}`;
  const mutation = Boolean(match?.[2]);
  if (method !== (mutation ? 'POST' : 'GET')) return 405;
  const validators = mutation ? {} : id ? { offset: (value) => decimal(value, 0, maxReviewOffset) } : {
    status: isReviewState, after: (value) => uuid.test(value), limit: (value) => decimal(value, 1, 50),
  };
  const params = new Map();
  if (query !== undefined) {
    for (const pair of query.split('&')) {
      const [key, value, extra] = pair.split('=');
      if (!Object.hasOwn(validators, key) || value === undefined || extra !== undefined || params.has(key)
        || !validators[key](value)) return 400;
      params.set(key, value);
    }
  }
  const search = new URLSearchParams(Object.keys(validators).filter((key) => params.has(key)).map((key) => [key, params.get(key)]));
  return {
    path: `${base}${id ? `/${id}` : ''}${mutation ? '/decision' : ''}${search.size ? `?${search}` : ''}`,
    mutation,
    decode: (value, decision) => mutation ? parseDecision(value, id, decision) : id
      ? parseDetail(value, id, Number(params.get('offset') ?? 0))
      : parseQueue(value, params.get('status') ?? 'proposed', params.get('after') ?? null, Number(params.get('limit') ?? reviewDefaultLimit)),
  };
}

function decimal(value, min, max) {
  return /^(?:0|[1-9][0-9]*)$/.test(value) && value.length <= String(max).length && Number(value) >= min && Number(value) <= max;
}

function readDecision(req, length) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    const timer = setTimeout(() => finish(408), DECISION_TIMEOUT_MS);
    const data = (chunk) => {
      size += chunk.length;
      if (size > MAX_DECISION_BYTES || size > length) return finish(413);
      chunks.push(chunk);
    };
    const error = () => finish(400);
    const end = () => {
      if (size !== length) return finish(400);
      try {
        const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(Buffer.concat(chunks));
        // Admit exactly one string member, then let JSON.parse validate its escapes.
        if (!/^[ \t\r\n]*\{[ \t\r\n]*"(?:[^"\\\x00-\x1f]|\\.)*"[ \t\r\n]*:[ \t\r\n]*"(?:[^"\\\x00-\x1f]|\\.)*"[ \t\r\n]*\}[ \t\r\n]*$/.test(text)) return finish(400);
        const value = JSON.parse(text);
        if (!Object.hasOwn(value, 'decision') || !isDecision(value.decision)) return finish(400);
        return finish(null, value.decision);
      } catch { return finish(400); }
    };
    function finish(status, decision) {
      clearTimeout(timer);
      req.off('data', data).off('end', end).off('aborted', error).off('error', error);
      if (status) { req.pause(); reject(status); } else resolve(decision);
    }
    req.on('data', data).once('end', end).once('aborted', error).once('error', error);
  });
}

export async function forwardReview(req, res, target, { browserAuthority, origin, verifiedBearer, loopbackRequest, send, deny }) {
  if (target.mutation) res.setHeader('connection', 'close');
  if (browserAuthority(req) || req.headers['transfer-encoding'] || req.headers.expect) return deny(res, 400);
  const length = req.headers['content-length'];
  let decision;
  if (target.mutation) {
    if (req.headers.origin !== origin) return deny(res, 403);
    const mediaTypes = req.headersDistinct['content-type'];
    if (mediaTypes?.length !== 1 || mediaTypes[0] !== 'application/json' || req.headers['content-encoding'] !== undefined) return deny(res, 415);
    if (typeof length !== 'string' || !/^[1-9][0-9]*$/.test(length)) return deny(res, 400);
    if (Number(length) > MAX_DECISION_BYTES) return deny(res, 413);
    try { decision = await readDecision(req, Number(length)); } catch (status) { return deny(res, status); }
  } else if (length && length !== '0') return deny(res, 400);

  try {
    const token = await verifiedBearer(req);
    if (res.destroyed) return;
    if (!token) return deny(res, 401, 'A current signed fixture session is required.');
    const headers = { authorization: ['Bearer', token].join(' '), accept: 'application/json' };
    const body = decision === undefined ? undefined : JSON.stringify({ decision });
    if (body !== undefined) {
      headers['content-type'] = 'application/json';
      headers['content-length'] = String(Buffer.byteLength(body));
    }
    const upstream = await loopbackRequest(REVIEW_BACKEND, target.path, headers, MAX_RESPONSE, body);
    if (upstream.status !== 200) {
      const known = [401, 403, 404, 503, ...(target.mutation ? [409] : [])];
      return deny(res, known.includes(upstream.status) ? upstream.status : 502);
    }
    if (!/^application\/json(?:\s*;|$)/i.test(upstream.contentType ?? '')) return deny(res, 502);
    let decoded;
    try { decoded = target.decode(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(upstream.body)), decision); }
    catch { return deny(res, 502); }
    return send(res, 200, JSON.stringify(decoded));
  } catch { return deny(res, 503); }
}
