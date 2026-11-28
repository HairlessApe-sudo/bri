import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { denyMetadata, readExact, single, validAdminCatalogue, validProposedMetadata, validSelectionCatalogue } from './metadata-bridge.mjs';
import { administrationBase, administrationContextHeader, administrationSessionPath, catalogVisibilityPath, csvStatusBase,
  decodeExactJson, isAdministrationContext, isJobId, mediaFor,
  metadataLimit, parseAdministrationReceipt, receiptLimit, uploadLimit } from './administration-contract.mjs';
import { xlsxNode } from './xlsx-intake.mjs';

const intakeOrigin = { csv: 'http://127.0.0.1:8112', xlsx: 'http://127.0.0.1:8116' };
const catalogueLimit = 512 * 1024;
const upstreamStatuses = new Set([400, 401, 403, 404, 408, 409, 413, 415, 422, 503]);
const processKey = randomBytes(32);
const responseHeaders = { 'cache-control': 'private, no-store', 'content-type': 'application/json; charset=utf-8',
  'x-content-type-options': 'nosniff' };

export function administrationTarget(path, method, query, enabled) {
  const csvStatus = path === csvStatusBase || path.startsWith(`${csvStatusBase}/`);
  if (!csvStatus && path !== administrationBase && !path.startsWith(`${administrationBase}/`)) return null;
  if (!enabled) return 404;
  let target;
  if (csvStatus) {
    const id = path.slice(csvStatusBase.length + 1);
    if (!isJobId(id)) return 404;
    target = { kind: 'status', format: 'csv', id, origin: intakeOrigin.csv, path };
  } else if (path === administrationSessionPath) {
    target = { kind: 'session' };
  } else if (path === catalogVisibilityPath) {
    target = { kind: 'visibility', origin: 'http://127.0.0.1:8118', path: '/v1/knowledge-metadata/catalogue/admin' };
  } else if (path.startsWith(`${administrationBase}/xlsx/status/`)) {
    const id = path.slice(`${administrationBase}/xlsx/status/`.length);
    if (!isJobId(id)) return 404;
    target = { kind: 'status', format: 'xlsx', id, origin: intakeOrigin.xlsx, path: `/v1/intake/xlsx/${id}` };
  } else if (path.startsWith(`${administrationBase}/selection/`)) {
    const match = /^\/v1\/knowledge-administration\/selection\/(csv|xlsx)\/([A-Za-z0-9][A-Za-z0-9_.:-]{0,127})$/.exec(path);
    if (!match) return 404;
    target = { kind: 'selection', origin: 'http://127.0.0.1:8118', path: `/v1/knowledge-metadata/catalogue/selection/${match[1]}_submit/${match[2]}` };
  } else {
    const format = /^\/v1\/knowledge-administration\/(csv|xlsx)\/uploads$/.exec(path)?.[1];
    if (!format) return 404;
    target = { kind: 'upload', format, origin: intakeOrigin[format], path };
  }
  if (method !== (target.kind === 'upload' ? 'POST' : 'GET')) return 405;
  return query === undefined ? target : 400;
}

export async function forwardAdministration(req, res, target, { browserAuthority, origin, verifiedBearer, loopbackRequest }) {
  const upload = target.kind === 'upload';
  if (upload) res.setHeader('connection', 'close');
  if (browserAuthority(req, upload) || Object.keys(req.headers).some((name) => name.includes('_')
    || /^(?:x-)?(?:(?:bri-)?(?:worker|tenant|actor|role|principal|identity|issuer|session)(?:-.*)?|authorization|dev-identity|sub|sid|node-id|scope-(?:node-)?id|user-id|permissions|bri-metadata)$/.test(name)
      && !(upload && (name === 'x-node-id' || name === 'x-bri-metadata')))
    || ['transfer-encoding', 'expect', 'content-encoding', 'content-disposition', 'content-range', 'range', 'trailer']
      .some((name) => Object.hasOwn(req.headers, name))) return denyMetadata(res, 400);
  const length = single(req, 'content-length');
  const headers = { accept: 'application/json' };
  if (upload) {
    if (single(req, 'origin') !== origin) return denyMetadata(res, 403);
    if (!/^[1-9][0-9]{0,7}$/.test(length ?? '')) return denyMetadata(res, 400);
    if (Number(length) > uploadLimit) return denyMetadata(res, 413);
    const media = single(req, 'content-type');
    if (media !== mediaFor(target.format)) return denyMetadata(res, 415);
    const node = single(req, 'x-node-id');
    const key = single(req, 'idempotency-key');
    const envelope = single(req, 'x-bri-metadata');
    if (!node || !xlsxNode.test(node) || !isJobId(key) || !/^[\w-]{1,10923}$/.test(envelope ?? '')) return denyMetadata(res, 422);
    try {
      const metadata = Buffer.from(envelope, 'base64url');
      if (metadata.length > metadataLimit || metadata.toString('base64url') !== envelope
        || !validProposedMetadata(decodeExactJson(metadata))) return denyMetadata(res, 422);
    } catch { return denyMetadata(res, 422); }
    Object.assign(headers, { 'content-type': media, 'content-length': length, 'x-node-id': node,
      'idempotency-key': key, 'x-bri-metadata': envelope });
  } else if ((Object.hasOwn(req.headers, 'content-length') && length !== '0')
    || ['content-type', 'idempotency-key'].some((name) => Object.hasOwn(req.headers, name))) return denyMetadata(res, 400);
  const context = single(req, administrationContextHeader);
  if (target.kind === 'session' && Object.hasOwn(req.headers, administrationContextHeader)) return denyMetadata(res, 400);

  try {
    const token = await verifiedBearer(req);
    if (res.destroyed) return;
    if (!token) return denyMetadata(res, 401);
    const fingerprint = createHmac('sha256', processKey).update(token).digest();
    // This binding cannot supply authority. A fresh signed cookie and the native operation still authorize each request.
    if (target.kind === 'session') return res.writeHead(200, { ...responseHeaders,
      [administrationContextHeader]: fingerprint.toString('hex') }).end('{"current":true}');
    if (!isAdministrationContext(context) || !timingSafeEqual(Buffer.from(context, 'hex'), fingerprint)) return denyMetadata(res, 401);
    headers.authorization = ['Bearer', token].join(' ');
    const body = upload ? await readExact(req, Number(length)) : undefined;
    if (res.destroyed) return;
    const visibility = target.kind === 'visibility';
    const selection = target.kind === 'selection';
    const limit = visibility || selection ? catalogueLimit : receiptLimit;
    const upstream = await loopbackRequest(target.origin, target.path, headers, limit, body);
    const expected = upload ? 202 : 200;
    if (upstream.status !== expected) return denyMetadata(res, upstreamStatuses.has(upstream.status) ? upstream.status : 502);
    if (!/^application\/json(?:\s*;|$)/i.test(upstream.contentType ?? '') || upstream.body.length > limit) return denyMetadata(res, 502);
    let reply;
    try {
      const value = decodeExactJson(upstream.body);
      if (visibility) {
        if (!validAdminCatalogue(value)) return denyMetadata(res, 502);
        reply = { visible: true };
      } else if (selection) {
        if (!validSelectionCatalogue(value)) return denyMetadata(res, 502);
        reply = value;
      } else reply = parseAdministrationReceipt(target.format, value, target.id);
    } catch { return denyMetadata(res, 502); }
    res.writeHead(expected, responseHeaders).end(JSON.stringify(reply));
  } catch (error) {
    return denyMetadata(res, typeof error === 'number' ? error : error?.code === 'LOCAL_RESPONSE_LIMIT' ? 502 : 503);
  }
}
