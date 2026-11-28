import { maxWorkbookBytes, xlsxMedia } from './xlsx-intake.mjs';

const base = '/v1/knowledge-metadata';
const uuidPattern = '(?!00000000-0000-0000-0000-000000000000)[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}';
const uuid = new RegExp(`^${uuidPattern}$`);
const nodePattern = '[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}';
const node = new RegExp(`^${nodePattern}$`);
const classification = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
const revision = (value, zero = false) => typeof value === 'string'
  && (zero ? /^(?:0|[1-9][0-9]{0,18})$/ : /^[1-9][0-9]{0,18}$/).test(value)
  && (value.length < 19 || value <= '9223372036854775807');
const format = '(csv|xlsx)';
const exactVersion = `${format}/records/(${uuidPattern})/versions/(${uuidPattern})`;
const routes = [
  ['uploads', 8116, 'upload', 'POST', '/xlsx/uploads'],
  ['review', [8114, 8117], 'pending', 'GET', `/${format}/review/(${uuidPattern})`],
  ['review', [8114, 8117], 'initial', 'POST', `/${format}/review/(${uuidPattern})/decision`],
  ['reads', [8013, 8117], 'read', 'GET', `/${exactVersion}`],
  ['reads', [8013, 8117], 'list', 'GET', `/${exactVersion}/corrections`],
  ['reads', [8013, 8117], 'propose', 'POST', `/${exactVersion}/corrections`],
  ['reads', [8013, 8117], 'correction', 'POST', `/${exactVersion}/corrections/(${uuidPattern})/decision`],
  ['catalogue', 8118, 'admin', 'GET', '/catalogue/admin'],
  ['catalogue', 8118, 'selection', 'GET', `/catalogue/selection/(csv_submit|xlsx_submit|csv_review|xlsx_review)/${nodePattern}`],
  ['catalogue', 8118, 'maintenance', 'POST', '/catalogue/admin/(seed|create|rename|describe|retire)'],
].map(([, port, kind, method, pattern]) => [port, kind, method, new RegExp(`^${base}${pattern}$`)]);
const limit = 512 * 1024;
const jsonLimit = 8192;
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
const statuses = new Set([400, 401, 403, 404, 408, 409, 413, 415, 422, 503]);
const errors = { 401: 'A current signed fixture session is required.', 403: 'Governed metadata operation denied.',
  404: 'Governed metadata target not found.', 409: 'Governed metadata conflict. Refresh before starting a new operation.' };

export function metadataTarget(path, method, query) {
  if (path !== base && !path.startsWith(`${base}/`)) return null;
  let wrongMethod = false;
  for (const [ports, kind, allowed, pattern] of routes) {
    const match = pattern.exec(path);
    if (!match) continue;
    if (allowed !== method) { wrongMethod = true; continue; }
    const after = query === undefined ? undefined : /^after=(.+)$/.exec(query)?.[1];
    if (query !== undefined && (kind !== 'list' || !isId(after))) return 400;
    const [fmt, record, version, proposal] = match.slice(1);
    const port = Array.isArray(ports) ? ports[fmt === 'csv' ? 0 : 1] : ports;
    return { kind, method, origin: `http://127.0.0.1:${port}`, path: query === undefined ? path : `${path}?${query}`,
      record, version, proposal, after, operation: fmt };
  }
  return wrongMethod ? 405 : 404;
}

function exact(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}
const isId = (value) => typeof value === 'string' && uuid.test(value);
const isNode = (value) => typeof value === 'string' && node.test(value);
const isClass = (value) => typeof value === 'string' && classification.test(value);
const text = (value, max, empty = false) => typeof value === 'string' && value.isWellFormed()
  && (empty || /[^ ]/.test(value)) && !value.includes('\0') && Buffer.byteLength(value) <= max;
const date = (value) => value === null || (typeof value === 'string' && /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(value)
  && !value.startsWith('0000') && Number.isFinite(Date.parse(value)) && new Date(value).toISOString().slice(0, 10) === value);
const fields = ['title', 'description', 'effective_date', 'review_date', 'expiry_date'];
const details = (value) => text(value.title, 160) && (value.description === null || text(value.description, 2048))
  && fields.slice(2).every((key) => date(value[key]));
const allClasses = (primary, additional, sorted = true) => isClass(primary) && Array.isArray(additional)
  && additional.length <= 8 && new Set(additional).size === additional.length
  && additional.every((item, i) => isClass(item) && item !== primary && (!sorted || i === 0 || additional[i - 1] < item));
const proposed = (value, sorted = true) => exact(value, ['version', 'primary_classification_id', 'additional_classification_ids', ...fields])
  && value.version === 1 && details(value) && allClasses(value.primary_classification_id, value.additional_classification_ids, sorted);
const label = (value) => exact(value, ['classification_id', 'label', 'retired'])
  && isClass(value.classification_id) && text(value.label, 160) && typeof value.retired === 'boolean';
const authoritative = (value) => exact(value, ['revision', 'responsible_node_id', 'primary_classification', 'additional_classifications', ...fields])
  && revision(value.revision) && isNode(value.responsible_node_id) && details(value) && label(value.primary_classification)
  && Array.isArray(value.additional_classifications) && value.additional_classifications.length <= 8
  && value.additional_classifications.every(label) && allClasses(value.primary_classification.classification_id,
    value.additional_classifications.map((item) => item.classification_id));

function validReply(value, target, body) {
  const { kind, record, version, proposal, after } = target;
  const versioned = (keys) => exact(value, ['record_id', 'source_version_id', ...keys])
    && value.record_id === record && value.source_version_id === version;
  if (kind === 'upload') return exact(value, ['id', 'state']) && isId(value.id)
    && ['ready', 'processing', 'proposed', 'failed'].includes(value.state);
  if (kind === 'pending') return exact(value, ['job_id', 'node_id', 'proposed_metadata']) && value.job_id === record
    && isNode(value.node_id) && (value.proposed_metadata === null || proposed(value.proposed_metadata));
  if (kind === 'initial') return exact(value, ['job_id', 'decision', 'metadata_revision']) && value.job_id === record
    && ['approve', 'reject'].includes(body?.action) && value.decision === body.action
    && (body.action === 'reject' ? value.metadata_revision === null
      : (value.metadata_revision === '1' || (!Object.hasOwn(body, 'metadata') && value.metadata_revision === null)));
  if (kind === 'read') return versioned(['metadata']) && (value.metadata === null || authoritative(value.metadata));
  if (kind === 'list') {
    if (!exact(value, ['items', 'next_after']) || !Array.isArray(value.items) || value.items.length > 10) return false;
    let previous = after;
    for (const item of value.items) {
      if (!exact(item, ['proposal_id', 'expected_revision', 'proposed_metadata']) || !isId(item.proposal_id)
        || (previous !== undefined && previous >= item.proposal_id) || !revision(item.expected_revision, true)
        || !proposed(item.proposed_metadata)) return false;
      previous = item.proposal_id;
    }
    return value.next_after === null || (value.items.length === 10 && value.next_after === previous);
  }
  if (kind === 'propose') return versioned(['proposal_id', 'expected_revision']) && isId(value.proposal_id)
    && revision(value.expected_revision, true)
    && value.expected_revision === body?.expected_revision;
  if (kind === 'correction') return versioned(['proposal_id', 'decision', 'metadata_revision']) && value.proposal_id === proposal
    && ['approve', 'reject'].includes(body?.action) && value.decision === body.action
    && (body.action === 'approve' ? revision(value.metadata_revision) : value.metadata_revision === null);
  if (kind === 'admin' || kind === 'selection') return Array.isArray(value) && value.every((entry) => (
    exact(entry, ['category_id', 'category_label', 'classification_id', 'label', 'description', 'retired'])
    && isClass(entry.category_id) && isClass(entry.classification_id) && text(entry.category_label, 160)
    && text(entry.label, 160) && (entry.description === null || text(entry.description, 2048, true))
    && typeof entry.retired === 'boolean' && (kind === 'admin' || entry.retired === false)
  )) && new Set(value.map((entry) => entry.classification_id)).size === value.length;
  return false;
}

const adminFields = { seed: [], create: ['category_id', 'classification_id', 'label', 'description'],
  rename: ['classification_id', 'label'], describe: ['classification_id', 'description'], retire: ['classification_id'] };

function validCommand(value, { kind, operation }) {
  if (kind === 'maintenance') {
    const keys = adminFields[operation];
    return exact(value, keys) && keys.every((key) => key.endsWith('_id') ? isClass(value[key])
      : key === 'label' ? text(value[key], 160) : value[key] === null || text(value[key], 2048, true));
  }
  if (kind === 'propose') return exact(value, ['request_id', 'expected_revision', 'metadata'])
    && isId(value.request_id) && revision(value.expected_revision, true) && proposed(value.metadata, false);
  const replacement = kind === 'initial' && value && Object.hasOwn(value, 'metadata');
  return exact(value, replacement ? ['action', 'request_id', 'metadata'] : ['action', 'request_id'])
    && ['approve', 'reject'].includes(value.action) && isId(value.request_id)
    && (!replacement || (value.action === 'approve' && proposed(value.metadata, false)));
}

export const validAdminCatalogue = (value) => validReply(value, { kind: 'admin' });
export const validSelectionCatalogue = (value) => validReply(value, { kind: 'selection' });
export const validProposedMetadata = (value) => proposed(value, false);

export function single(req, name) {
  const fields = req.headersDistinct[name];
  return fields?.length === 1 ? fields[0] : undefined;
}

export function readExact(req, length) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    const timer = setTimeout(() => finish(408), 5000);
    const failed = () => finish(400);
    const data = (chunk) => {
      size += chunk.length;
      if (size > length) return finish(413);
      chunks.push(chunk);
    };
    const end = () => finish(size === length ? 0 : 400);
    function finish(status) {
      clearTimeout(timer);
      req.off('data', data).off('error', failed).off('aborted', failed).off('end', end);
      if (status) { req.pause(); reject(status); }
      else resolve(Buffer.concat(chunks, size));
    }
    req.on('data', data).once('error', failed).once('aborted', failed).once('end', end);
  });
}

function send(res, status, body) {
  const headers = { 'cache-control': 'private, no-store', 'x-content-type-options': 'nosniff' };
  if (body !== undefined) headers['content-type'] = 'application/json; charset=utf-8';
  res.writeHead(status, headers).end(body);
}

export function denyMetadata(res, status) {
  return send(res, status, JSON.stringify({ detail: errors[status] ?? (status >= 500
    ? 'Governed metadata unavailable.' : 'Invalid governed metadata request.') }));
}

export async function forwardMetadata(req, res, target, { browserAuthority, origin, verifiedBearer, loopbackRequest }) {
  const { kind, method, path } = target;
  const upload = kind === 'upload';
  const mutation = method === 'POST';
  if (mutation) res.setHeader('connection', 'close');
  if (browserAuthority(req, upload) || Object.keys(req.headers).some((name) => (
    name.includes('_') || /^(?:x-)?(?:dev-identity|sub|sid|node-id|scope-(?:node-)?id|user-id|permissions|bri-metadata)$/.test(name)
      && !(upload && (name === 'x-bri-metadata' || name === 'x-node-id'))
  )) || ['transfer-encoding', 'expect', 'content-encoding', 'content-disposition', 'content-range', 'range', 'trailer']
    .some((name) => Object.hasOwn(req.headers, name))) return denyMetadata(res, 400);
  const length = single(req, 'content-length');
  const upstreamHeaders = { accept: 'application/json' };
  if (mutation) {
    if (single(req, 'origin') !== origin) return denyMetadata(res, 403);
    if (!/^[1-9][0-9]{0,7}$/.test(length ?? '')) return denyMetadata(res, 400);
    if (Number(length) > (upload ? maxWorkbookBytes : jsonLimit)) return denyMetadata(res, 413);
    const media = single(req, 'content-type');
    if (media !== (upload ? xlsxMedia : 'application/json')) return denyMetadata(res, 415);
    Object.assign(upstreamHeaders, { 'content-type': media, 'content-length': length });
    if (upload) {
      const nodeId = single(req, 'x-node-id');
      const key = single(req, 'idempotency-key');
      const meta = single(req, 'x-bri-metadata');
      if (!isNode(nodeId) || !isId(key) || typeof meta !== 'string' || !/^[\w-]{1,10923}$/.test(meta)) return denyMetadata(res, 422);
      const decoded = Buffer.from(meta, 'base64url');
      if (decoded.length > jsonLimit || decoded.toString('base64url') !== meta) return denyMetadata(res, 422);
      try {
        if (!proposed(JSON.parse(utf8.decode(decoded)), false)) return denyMetadata(res, 422);
      } catch { return denyMetadata(res, 422); }
      Object.assign(upstreamHeaders, { 'x-node-id': nodeId, 'idempotency-key': key, 'x-bri-metadata': meta });
    } else if (Object.hasOwn(req.headers, 'idempotency-key')) return denyMetadata(res, 400);
  } else if ((Object.hasOwn(req.headers, 'content-length') && length !== '0')
    || ['content-type', 'idempotency-key'].some((name) => Object.hasOwn(req.headers, name))) return denyMetadata(res, 400);

  try {
    const token = await verifiedBearer(req);
    if (res.destroyed) return;
    if (!token) return denyMetadata(res, 401);
    upstreamHeaders.authorization = ['Bearer', token].join(' ');
    let body, input;
    if (mutation) {
      try {
        body = await readExact(req, Number(length));
        if (!upload) {
          input = JSON.parse(utf8.decode(body)); // Preserve raw bytes: Python detects duplicate keys.
          if (!validCommand(input, target)) return denyMetadata(res, 422);
        }
      } catch (error) {
        return denyMetadata(res, typeof error === 'number' ? error : 422);
      }
    }
    const upstream = await loopbackRequest(target.origin, path, upstreamHeaders, limit, body);
    const expected = upload ? 202 : kind === 'maintenance' ? 204 : 200;
    if (upstream.status !== expected) return denyMetadata(res, statuses.has(upstream.status) ? upstream.status : 502);
    if (expected === 204) return upstream.body.length === 0 ? send(res, 204) : denyMetadata(res, 502);
    if (!/^application\/json(?:\s*;|$)/i.test(upstream.contentType ?? '') || upstream.body.length > limit) return denyMetadata(res, 502);
    try {
      const value = JSON.parse(utf8.decode(upstream.body));
      if (!validReply(value, target, input)) return denyMetadata(res, 502);
      const serialized = JSON.stringify(value);
      return Buffer.byteLength(serialized) <= limit ? send(res, expected, serialized) : denyMetadata(res, 502);
    } catch {
      return denyMetadata(res, 502);
    }
  } catch {
    return denyMetadata(res, 503);
  }
}
