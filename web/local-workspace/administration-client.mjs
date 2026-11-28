import { catalogue, metadataInput } from './app/classification/client.mjs';
import { xlsxNode } from './xlsx-intake.mjs';
import { administrationBase, administrationContextHeader, administrationSessionPath, catalogVisibilityPath,
  decodeExactJson, isAdministrationContext, isFormat, isJobId, mediaFor, metadataLimit,
  parseAdministrationReceipt, receiptLimit, statusPath, uploadLimit } from './administration-contract.mjs';

const api = '/api/bri-local';
const failure = (status) => Object.assign(new Error('Knowledge Administration request not confirmed'), { status });
const encoder = new TextEncoder();

export function createAdministrationLifecycle() {
  /** @type {Map<string, AbortController>} */
  const lanes = new Map();
  const cancel = (...names) => {
    for (const name of names) {
      const previous = lanes.get(name);
      lanes.delete(name);
      previous?.abort();
    }
  };
  return {
    cancel,
    clear() { cancel(...lanes.keys()); },
    begin(name) {
      cancel(name);
      const controller = new AbortController();
      lanes.set(name, controller);
      return { signal: controller.signal, current: () => lanes.get(name) === controller && !controller.signal.aborted };
    },
  };
}

async function readBounded(response, signal, limit) {
  if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') ?? '') || !response.body) throw failure(502);
  const reader = response.body.getReader();
  const bytes = new Uint8Array(limit);
  let length = 0;
  let consumed = false;
  try {
    for (;;) {
      signal.throwIfAborted();
      const chunk = await reader.read();
      signal.throwIfAborted();
      if (chunk.done) { consumed = true; break; }
      if (!(chunk.value instanceof Uint8Array) || length + chunk.value.length > limit) throw failure(502);
      bytes.set(chunk.value, length);
      length += chunk.value.length;
    }
    return decodeExactJson(bytes.subarray(0, length));
  } catch {
    signal.throwIfAborted();
    throw failure(502);
  } finally {
    if (!consumed) void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

// Only intact, known bridge denials classify a dispatched upload. An HTTP
// status alone does not establish what happened. 403 can also be returned
// after reservation if authority is lost before the native ready operation.
// 409 is not definitive: the bridge also uses it for native uniqueness
// errors, including a possible readiness-audit failure after reservation.
const uploadDenials = new Map([
  [400, 'Invalid governed metadata request.'], [413, 'Invalid governed metadata request.'],
  [415, 'Invalid governed metadata request.'], [422, 'Invalid governed metadata request.'],
  [401, 'A current signed fixture session is required.'], [403, 'Governed metadata operation denied.'],
  [404, 'Governed metadata target not found.'],
]);
const uploadFailure = (status, outcome) => Object.assign(failure(status), { outcome });

async function request(transport, path, signal, context, expected = 200, init = {}, limit = receiptLimit, upload = false) {
  signal.throwIfAborted();
  if (context !== undefined && !isAdministrationContext(context)) throw failure(401);
  let response;
  try {
    response = await transport(`${api}${path}`, { ...init, mode: 'same-origin', credentials: 'same-origin', cache: 'no-store',
      redirect: 'error', signal, headers: { ...init.headers, ...(context === undefined ? {} : { [administrationContextHeader]: context }) } });
  } catch {
    signal.throwIfAborted();
    throw failure(503);
  }
  signal.throwIfAborted();
  if (response.status !== expected) {
    const status = response.status >= 400 && response.status <= 599 ? response.status : 502;
    const detail = upload ? uploadDenials.get(status) : undefined;
    if (detail !== undefined) {
      const value = await readBounded(response, signal, limit);
      signal.throwIfAborted();
      if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== 1
        || !Object.hasOwn(value, 'detail') || value.detail !== detail) throw failure(502);
      throw uploadFailure(status, [401, 403, 404].includes(status) ? 'retired' : 'rejected');
    }
    void response.body?.cancel().catch(() => {});
    throw failure(status);
  }
  const value = await readBounded(response, signal, limit);
  signal.throwIfAborted();
  return { value, headers: response.headers };
}

function exactTrue(value, field) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.hasOwn(value, field) && value[field] === true && Object.keys(value).length === 1;
}

export async function readSessionContext(transport, signal) {
  const { value, headers } = await request(transport, administrationSessionPath, signal, undefined);
  const context = headers.get(administrationContextHeader);
  if (!isAdministrationContext(context) || !exactTrue(value, 'current')) throw failure(502);
  return context;
}

export async function readCatalogueVisibility(transport, context, signal) {
  const { value } = await request(transport, catalogVisibilityPath, signal, context);
  if (!exactTrue(value, 'visible')) throw failure(502);
  return true;
}

export async function readSubmissionSelection(transport, context, format, node, signal) {
  if (!isFormat(format) || !isNode(node)) throw failure(422);
  const { value } = await request(transport, `${administrationBase}/selection/${format}/${node}`, signal, context, 200, {}, 512 * 1024);
  return catalogue(value, false);
}

export async function readJob(transport, context, format, id, signal) {
  if (!isFormat(format) || !isJobId(id)) throw failure(422);
  const { value } = await request(transport, statusPath(format, id), signal, context);
  try { return parseAdministrationReceipt(format, value, id); } catch { throw failure(502); }
}

const isNode = (node) => typeof node === 'string' && !/[\n\r]/.test(node) && xlsxNode.test(node);
export function validFile(format, file) {
  return isFormat(format) && file instanceof File && file.name.toLowerCase().endsWith(`.${format}`)
    && file.size > 0 && file.size <= uploadLimit;
}

export function prepareSubmission(format, file, node, key, input, context) {
  if (!isAdministrationContext(context)) throw failure(401);
  if (!validFile(format, file) || !isNode(node) || !isJobId(key)) throw failure(422);
  const bytes = encoder.encode(JSON.stringify(metadataInput(input)));
  if (bytes.length > metadataLimit) throw failure(422);
  const metadata = btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
  return Object.freeze({ context, format, file, node, key, metadata });
}

export async function uploadSubmission(transport, context, command, signal) {
  signal.throwIfAborted();
  if (!isAdministrationContext(context) || command.context !== context) throw uploadFailure(401, 'retired');
  const { format, file, key, metadata, node } = command;
  try {
    const { value } = await request(transport, `${administrationBase}/${format}/uploads`, signal, context, 202, {
      method: 'POST', body: file,
      headers: { 'content-type': mediaFor(format), 'x-node-id': node, 'idempotency-key': key, 'x-bri-metadata': metadata },
    }, receiptLimit, true);
    return parseAdministrationReceipt(format, value);
  } catch (error) {
    signal.throwIfAborted();
    if (error?.outcome) throw error;
    throw uploadFailure(error?.status ?? 502, 'uncertain');
  }
}
