import { isProposalId } from './review-contract.mjs';

export const reportPath = '/v1/reports/published-knowledge-inventory';
export const reportMaxBytes = 512 * 1024;
const parameter = 'scope_node_id=';
const metricKeys = ['metric_id', 'metric_version', 'scope_node_id', 'status'];
const rowKeys = ['record_id', 'source_version_id', 'original_sha256', 'content_sha256', 'first_line', 'last_line'];

/** @param {unknown} value @returns {value is string} */
export function validScope(value) {
  return typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(value);
}

/** @param {string | undefined} query */
export function reportScope(query) {
  if (!query?.startsWith(parameter) || query.length > parameter.length + 128 * 3 || query.includes('&')) return null;
  try {
    const node = decodeURIComponent(query.slice(parameter.length).replaceAll('+', ' '));
    return validScope(node) ? node : null;
  } catch { return null; }
}

/** @param {string} node */
export const reportTarget = (node) => `${reportPath}?${parameter}${encodeURIComponent(node)}`;

const shape = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const digest = (value) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const line = (value) => Number.isInteger(value) && value >= 1 && value <= 2147483647;

/** @typedef {{ record_id: string, source_version_id: string, original_sha256: string, content_sha256: string, first_line: number, last_line: number }} Evidence */
/** @typedef {{ metric_id: 'published_knowledge_inventory', metric_version: 1, scope_node_id: string }} Metric */
/** @typedef {Metric & { status: 'complete', count: number, evidence: Evidence[] }} Complete */
/** @param {number} status @param {any} body @param {string} node
 * @returns {{ result: Complete | (Metric & { status: 'unavailable' }) } | null} */
export function parseReport(status, body, node) {
  if (status !== 200 && status !== 503 || !shape(body, ['result'])) return null;
  const data = body.result;
  const expected = status === 200 ? 'complete' : 'unavailable';
  if (!shape(data, status === 200 ? [...metricKeys, 'count', 'evidence'] : metricKeys)
    || data.metric_id !== 'published_knowledge_inventory' || data.metric_version !== 1
    || data.scope_node_id !== node || data.status !== expected) return null;
  if (status === 200) {
    const { count, evidence } = data;
    if (!Array.isArray(evidence) || count !== evidence.length || count > 1000) return null;
    const seen = new Set();
    for (const row of evidence) {
      if (!shape(row, rowKeys) || !isProposalId(row.record_id) || row.source_version_id !== row.record_id
        || seen.has(row.record_id) || !digest(row.original_sha256) || !digest(row.content_sha256)
        || !line(row.first_line) || !line(row.last_line) || row.first_line > row.last_line) return null;
      seen.add(row.record_id);
    }
  }
  return body;
}

/** @typedef {{ status: 'idle' | 'invalid' | 'loading' | 'empty' | 'unavailable' | 'denied' | 'dependency' } | { status: 'complete', result: Complete }} ReportState */
/** @param {(state: ReportState) => void} publish @param {typeof fetch} transport */
export function createReportEvaluation(publish, transport) {
  /** @type {AbortController | undefined} */
  let active;
  function cancel() {
    const retired = active;
    active = undefined;
    retired?.abort();
  }
  return {
    cancel,
    /** @param {string} node */
    async run(node) {
      cancel();
      if (!validScope(node)) return publish({ status: 'invalid' });
      const request = new AbortController();
      active = request;
      /** @param {ReportState} state */
      const finish = (state) => { if (active === request) publish(state); };
      publish({ status: 'loading' });
      if (active !== request) return;
      try {
        const response = await transport(`/api/bri-local${reportTarget(node)}`, {
          signal: request.signal, cache: 'no-store', credentials: 'same-origin', redirect: 'error',
        });
        if (active !== request) return;
        if ([401, 403, 404].includes(response.status)) return finish({ status: 'denied' });
        if (response.status !== 200 && response.status !== 503) return finish({ status: 'dependency' });
        const data = parseReport(response.status, await response.json(), node)?.result;
        if (!data) return finish({ status: 'dependency' });
        if (data.status === 'unavailable') return finish({ status: 'unavailable' });
        return finish(data.count ? { status: 'complete', result: data } : { status: 'empty' });
      } catch {
        finish({ status: 'dependency' });
      } finally {
        if (active === request) active = undefined;
      }
    },
  };
}
