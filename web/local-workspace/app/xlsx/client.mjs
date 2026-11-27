import { intakePath, maxWorkbookBytes, parseIntakeReceipt, xlsxMedia, xlsxNode, xlsxUuid } from '../../xlsx-intake.mjs';
import { invalid, isCursor, isDecision, isXlsxId, parsePublishedEvidence, parsePublishedRecord, parseXlsxDecision, xlsxPublishedPath, xlsxReviewPath } from '../../xlsx-governance.mjs';

export async function readPublishedRecord(transport, id, signal) {
  if (!xlsxUuid.test(id)) invalid();
  return parsePublishedRecord(await localJson(transport, `${xlsxPublishedPath}/${id}`, { signal }, 200), id);
}

export async function readPublishedEvidence(transport, id, version, cursor, signal) {
  if (!xlsxUuid.test(id) || !xlsxUuid.test(version) || (cursor != null && !isCursor(cursor))) invalid();
  const path = `${xlsxPublishedPath}/${id}/evidence/${version}${cursor ? `?cursor=${cursor}` : ''}`;
  return parsePublishedEvidence(await localJson(transport, path, { signal }, 200), id, version);
}

/** @template T
 * @param {(signal: AbortSignal) => Promise<T>} load
 * @param {(state: {data?: T, error?: number} | null) => void} publish
 */
export function authorizedRead(load, publish) {
  const controller = new AbortController();
  publish(null);
  load(controller.signal).then((data) => {
    if (!controller.signal.aborted) publish({ data });
  }).catch((error) => {
    if (!controller.signal.aborted) publish({ error: error?.status ?? 502 });
  });
  return () => controller.abort();
}

export async function localJson(transport, path, options, expected) {
  const result = await transport(`/api/bri-local${path}`, {
    credentials: 'same-origin', cache: 'no-store', redirect: 'error', ...options,
  });
  if (result.status !== expected) throw Object.assign(new Error('XLSX request unavailable'), { status: result.status });
  return result.json();
}

export async function uploadWorkbook(transport, file, node, key, signal) {
  if (!file || !/\.xlsx$/i.test(file.name) || file.size < 1 || file.size > maxWorkbookBytes
    || !xlsxNode.test(node) || !xlsxUuid.test(key)) throw new Error('Choose a nonempty XLSX workbook and enter a valid node ID.');
  const value = await localJson(transport, intakePath, {
    method: 'POST', signal, body: file,
    headers: { 'content-type': xlsxMedia, 'x-node-id': node, 'idempotency-key': key },
  }, 202);
  return parseIntakeReceipt(value);
}

export async function readJob(transport, id, signal) {
  if (!xlsxUuid.test(id)) throw new Error('Enter the XLSX job ID.');
  return parseIntakeReceipt(await localJson(transport, `${intakePath}/${id}`, { signal }, 200), id);
}

export function decisionAttempt(transport, id, state, signal, randomId) {
  let choice = null;
  let submitted = false;
  return {
    choose(next) {
      if (!submitted && !signal.aborted && state === 'proposed') choice = isDecision(next) ? next : null;
    },
    async confirm(decision) {
      if (!isXlsxId(id) || !isDecision(decision) || choice !== decision || submitted || signal.aborted || state !== 'proposed') return null;
      submitted = true;
      choice = null;
      const key = randomId();
      if (!xlsxUuid.test(key)) throw new Error('Invalid idempotency key');
      if (signal.aborted) return null;
      const value = await localJson(transport, `${xlsxReviewPath}/${encodeURIComponent(id)}/decision`, {
        method: 'POST', signal, headers: { 'content-type': 'application/json', 'idempotency-key': key },
        body: JSON.stringify({ decision }),
      }, 200);
      return signal.aborted ? null : parseXlsxDecision(value, id, decision);
    },
  };
}
