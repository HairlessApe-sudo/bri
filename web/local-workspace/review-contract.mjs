// Shared by the isolated bridge and the local UI. Nothing in the release app imports this.
export const reviewResource = '/knowledge/proposals/csv';
export const maxReviewOffset = 20_000_000; // A12 maximum extracted bytes (also bounds character offsets).
export const reviewDefaultLimit = 50;
const evidencePageSize = 4096;
const maxHistory = 32;
export const reviewStates = /** @type {const} */ (['proposed', 'approved', 'rejected', 'failed']);
const events = /** @type {const} */ (['submitted', 'ready', 'claimed', 'lease_expired', 'retry', 'failed', 'proposed', 'approved', 'rejected']);
const reasons = /** @type {const} */ (['invalid_csv', 'object_missing', 'digest_mismatch', 'storage_error', 'processing_error', 'lease_expired', 'authority_lost']);
export const uuid = /^(?!00000000-0000-0000-0000-000000000000)[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
export const encodedProposal = `csv%3A(${uuid.source.slice(1, -1)})`;
export const reviewPagePath = new RegExp(`^/review/${encodedProposal}$`);

const fail = () => { throw new Error('Could not read the local review response.'); };
function shape(value, names) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== names.length
    || !names.every((name) => Object.hasOwn(value, name))) fail();
  return value;
}
/** @template {string} T @param {unknown} value @param {readonly T[]} options @returns {value is T} */
function known(value, options) { return options.some((option) => value === option); }
/** @param {unknown} value @returns {value is typeof reviewStates[number]} */
export function isReviewState(value) { return known(value, reviewStates); }
/** @param {unknown} value @returns {value is 'approved' | 'rejected'} */
export function isDecision(value) { return value === 'approved' || value === 'rejected'; }
/** @param {unknown} value @returns {value is string} */
export function isProposalId(value) { return typeof value === 'string' && value.startsWith('csv:') && uuid.test(value.slice(4)); }
/** @param {unknown} segment */
export function proposalFromSegment(segment) {
  if (typeof segment !== 'string' || !reviewPagePath.test(`/review/${segment}`)) return null;
  return decodeURIComponent(segment);
}
const instant = (value) => typeof value === 'string'
  && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})$/.test(value)
  && Number.isFinite(Date.parse(value));
const integer = (value, min, max) => Number.isSafeInteger(value) && value >= min && value <= max;
const digest = (value) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const summaryKeys = ['id', 'state', 'node_id', 'created_at'];
const maxScopeLabelCodePoints = 256; // SQL projects node_id as display text, not a route identifier.
function summary({ id, state, node_id, created_at }) {
  if (!isProposalId(id) || !isReviewState(state) || typeof node_id !== 'string'
    || Array.from(node_id).length > maxScopeLabelCodePoints || !instant(created_at)) return fail();
  return { id, state, node_id: /** @type {string} */ (node_id), created_at: /** @type {string} */ (created_at) };
}

/** @param {unknown} value @param {typeof reviewStates[number]} status @param {string | null} after */
export function parseQueue(value, status = 'proposed', after = null, limit = reviewDefaultLimit) {
  const { items, next_cursor } = shape(value, ['items', 'next_cursor']);
  if (!Array.isArray(items) || items.length > limit || (next_cursor !== null
    && (typeof next_cursor !== 'string' || !uuid.test(next_cursor) || next_cursor === after || !items.length))) return fail();
  const rows = items.map((item) => summary(shape(item, summaryKeys)));
  const ids = new Set(rows.map(({ id }) => id));
  if (ids.size !== rows.length || (after && ids.has(`csv:${after}`)) || rows.some((row) => row.state !== status)) return fail();
  if (next_cursor !== null && (rows.length !== limit || rows.at(-1)?.id !== `csv:${next_cursor}`)) return fail();
  return { items: rows, next_cursor: /** @type {string | null} */ (next_cursor) };
}

/**
 * @typedef {{source_id: string, source_version_id: string, source_version: string, extraction_id: string,
 * original_sha256: string, content_sha256: string, csv_first_line: number, csv_last_line: number}} Provenance
 */
/** @param {unknown} value @returns {Provenance | null} */
function provenanceValue(value) {
  if (value === null) return null;
  const keys = ['source_id', 'source_version_id', 'source_version', 'extraction_id', 'original_sha256', 'content_sha256', 'csv_first_line', 'csv_last_line'];
  const { source_id, source_version_id, source_version, extraction_id, original_sha256, content_sha256, csv_first_line, csv_last_line } = shape(value, keys);
  if (![source_id, source_version_id, extraction_id].every(isProposalId)
    || typeof source_version !== 'string' || !/^[A-Za-z0-9._-]{1,128}$/.test(source_version)
    || !digest(original_sha256) || !digest(content_sha256)
    || !integer(csv_first_line, 1, 5_000_000) || !integer(csv_last_line, csv_first_line, 5_000_000)) return fail();
  return { source_id, source_version_id, source_version, extraction_id, original_sha256, content_sha256, csv_first_line, csv_last_line };
}

/** @param {unknown} value @param {string} id */
export function parseDetail(value, id, offset = 0) {
  const data = shape(value, [...summaryKeys, 'provenance', 'evidence', 'next_evidence_offset', 'history']);
  const item = summary(data);
  const { evidence, next_evidence_offset, history } = data;
  const provenance = provenanceValue(data.provenance);
  if (item.id !== id || (evidence !== null && (typeof evidence !== 'string' || Array.from(evidence).length > evidencePageSize))
    || (next_evidence_offset !== null && (typeof evidence !== 'string' || Array.from(evidence).length !== evidencePageSize
      || next_evidence_offset !== offset + evidencePageSize || !integer(next_evidence_offset, 0, maxReviewOffset)))
    || (item.state === 'failed' ? provenance !== null || evidence !== null : provenance === null || evidence === null)
    || (provenance && [provenance.source_id, provenance.source_version_id, provenance.extraction_id].some((ref) => ref !== id))
    || !Array.isArray(history) || history.length > maxHistory) return fail();
  const timeline = history.map((entry) => {
    const { event, occurred_at, reason } = shape(entry, ['event', 'occurred_at', 'reason']);
    if (!known(event, events) || !instant(occurred_at)
      || (reason !== null && (!known(reason, reasons) || !['failed', 'retry', 'lease_expired'].includes(event)))) return fail();
    return { event, occurred_at: /** @type {string} */ (occurred_at), reason: /** @type {typeof reasons[number] | null} */ (reason) };
  });
  return { ...item, provenance, evidence: /** @type {string | null} */ (evidence),
    next_evidence_offset: /** @type {number | null} */ (next_evidence_offset), history: timeline };
}

/** @param {unknown} value @param {string} id @param {'approved' | 'rejected'} expected */
export function parseDecision(value, id, expected) {
  const { id: resultId, decision } = shape(value, ['id', 'decision']);
  if (!isProposalId(resultId) || resultId !== id || !isDecision(decision) || decision !== expected) return fail();
  return { id: resultId, decision };
}
