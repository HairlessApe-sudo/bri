import { maxWorkbookBytes, parseIntakeReceipt, xlsxMedia, xlsxNode, xlsxUuid } from '../../xlsx-intake.mjs';

export const classificationId = (value) => typeof value === 'string' && /^[a-z0-9][a-z0-9_.-]{0,63}$/.test(value);
const encoder = new TextEncoder();
const invalid = () => { throw Object.assign(new Error('Invalid metadata or response'), { status: 502 }); };
const exact = (value, keys) => {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== keys.length
      || !keys.every((key) => Object.hasOwn(value, key))) invalid();
  return value;
};
const boundedText = (value, max) => typeof value === 'string' && value.isWellFormed() && !value.includes('\0') && encoder.encode(value).length <= max;
const text = (value, max) => boundedText(value, max) && !!value.trim();
const nullableText = (value, max) => value === null || text(value, max);
const date = (value) => {
  if (value === null) return true;
  if (typeof value !== 'string' || !/^(?!0000)\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const parsed = new Date(`${value}T00:00:00Z`);
  return Number.isFinite(+parsed) && parsed.toISOString().slice(0, 10) === value;
};
const fields = ['title', 'description', 'effective_date', 'review_date', 'expiry_date'];
function validateFields(value) {
  if (!text(value.title, 160) || !nullableText(value.description, 2048)
      || ![value.effective_date, value.review_date, value.expiry_date].every(date)) invalid();
}
/** @typedef {{version: 1, primary_classification_id: string, additional_classification_ids: string[], title: string,
 * description: string | null, effective_date: string | null, review_date: string | null, expiry_date: string | null}} MetadataInput */
/** @param {unknown} value @returns {MetadataInput} */
export function metadataInput(value) {
  const row = exact(value, [...fields, 'version', 'primary_classification_id', 'additional_classification_ids']);
  const { version, primary_classification_id: primary, additional_classification_ids: other } = row;
  validateFields(row);
  if (version !== 1 || !classificationId(primary) || !Array.isArray(other) || other.length > 8
      || !other.every(classificationId) || other.includes(primary) || new Set(other).size !== other.length) invalid();
  return { ...row, additional_classification_ids: [...other].sort() };
}

const root = '/api/bri-local/v1/knowledge-metadata';
const httpError = (status) => Object.assign(new Error('Classification request not confirmed'), { status });
async function request(transport, path, signal, status = 200, options = {}) {
  signal.throwIfAborted();
  const response = await transport(`${root}${path}`, {
    mode: 'same-origin', credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal, ...options,
  });
  signal.throwIfAborted();
  if (response.status !== status) throw httpError(response.status);
  if (status === 204) return;
  const value = await response.json();
  signal.throwIfAborted();
  return value;
}
const jsonLimit = 8192;
const post = (value) => {
  const body = JSON.stringify(value);
  if (encoder.encode(body).length > jsonLimit) throw httpError(422);
  return { method: 'POST', headers: { 'content-type': 'application/json' }, body };
};
const requireUuid = (value) => {
  if (typeof value !== 'string' || !xlsxUuid.test(value)) throw httpError(422);
  return value;
};
const requireNode = (value) => {
  if (typeof value !== 'string' || !xlsxNode.test(value)) throw httpError(422);
  return value;
};
function formatId(format, id) {
  if (!['csv', 'xlsx'].includes(format)) invalid();
  return requireUuid(typeof id === 'string' && id.startsWith(`${format}:`) ? id.slice(format.length + 1) : id);
}
function recordPath(format, record, version) {
  return `/${format}/records/${formatId(format, record)}/versions/${formatId(format, version)}`;
}
const isRevision = (value, allowZero = false) => typeof value === 'string'
  && ((allowZero && value === '0') || (/^[1-9][0-9]{0,18}$/.test(value) && (value.length < 19 || value <= '9223372036854775807')));

/** @typedef {{classification_id: string, label: string, retired: boolean}} HistoricalClass */
/** @typedef {{revision: string, responsible_node_id: string, title: string, description: string | null, effective_date: string | null,
 * review_date: string | null, expiry_date: string | null, primary_classification: HistoricalClass, additional_classifications: HistoricalClass[]}} ValidatedMetadata */
/** @returns {HistoricalClass} */
function historicalClass(value) {
  const row = exact(value, ['classification_id', 'label', 'retired']);
  if (!classificationId(row.classification_id) || !text(row.label, 160) || typeof row.retired !== 'boolean') invalid();
  return row;
}
/** @returns {ValidatedMetadata | null} */
function validatedMetadata(value) {
  if (value === null) return null;
  const row = exact(value, [...fields, 'revision', 'responsible_node_id', 'primary_classification', 'additional_classifications']);
  validateFields(row);
  if (!isRevision(row.revision) || typeof row.responsible_node_id !== 'string' || !xlsxNode.test(row.responsible_node_id)
      || !Array.isArray(row.additional_classifications) || row.additional_classifications.length > 8) invalid();
  const primary = historicalClass(row.primary_classification);
  const additional = row.additional_classifications.map(historicalClass);
  if (new Set([primary, ...additional].map((item) => item.classification_id)).size !== additional.length + 1) invalid();
  return row;
}
/** @typedef {{category_id: string, category_label: string, classification_id: string, label: string, description: string | null}} CatalogueEntry */
/** @param {unknown} value @param {boolean} admin @returns {(CatalogueEntry & {retired?: boolean})[]} */
function catalogue(value, admin) {
  if (!Array.isArray(value)) return invalid();
  const ids = new Set();
  const rows = value.map((entry) => {
    const row = exact(entry, ['category_id', 'category_label', 'classification_id', 'label', 'description', 'retired']);
    if (!classificationId(row.category_id) || !classificationId(row.classification_id) || !text(row.category_label, 160)
        || !text(row.label, 160) || (row.description !== null && !boundedText(row.description, 2048)) || ids.has(row.classification_id)
        || typeof row.retired !== 'boolean' || (!admin && row.retired)) invalid();
    ids.add(row.classification_id);
    return row;
  });
  return rows;
}
export async function readAdminCatalogue(transport, signal) {
  return catalogue(await request(transport, '/catalogue/admin', signal), true);
}
export async function writeCatalogue(transport, operation, values, signal) {
  const keys = { seed: [], create: ['category_id', 'classification_id', 'label', 'description'], rename: ['classification_id', 'label'],
    describe: ['classification_id', 'description'], retire: ['classification_id'] };
  if (!Object.hasOwn(keys, operation)) invalid();
  const command = exact(values, keys[operation]);
  if (('classification_id' in command && !classificationId(command.classification_id))
      || ('category_id' in command && !classificationId(command.category_id))
      || ('label' in command && !text(command.label, 160)) || ('description' in command && command.description !== null
        && !boundedText(command.description, 2048))) throw httpError(422);
  await request(transport, `/catalogue/admin/${operation}`, signal, 204, post(command));
}
export async function readSelection(transport, operation, target, signal) {
  if (!['xlsx_submit', 'csv_submit', 'xlsx_review', 'csv_review'].includes(operation)) invalid();
  return catalogue(await request(transport, `/catalogue/selection/${operation}/${requireNode(target)}`, signal), false);
}

export async function uploadClassifiedWorkbook(transport, file, node, key, input, signal) {
  if (!file || !/\.xlsx$/i.test(file.name) || file.size < 1 || file.size > maxWorkbookBytes) throw httpError(422);
  const bytes = encoder.encode(JSON.stringify(metadataInput(input)));
  if (bytes.length > jsonLimit) throw httpError(422);
  const header = btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
  return parseIntakeReceipt(await request(transport, '/xlsx/uploads', signal, 202, {
    method: 'POST', body: file,
    headers: { 'content-type': xlsxMedia, 'x-node-id': requireNode(node), 'idempotency-key': requireUuid(key), 'x-bri-metadata': header },
  }), undefined);
}

function targetReceipt(value, format, record, version, extraKeys, expectedProposal) {
  const row = exact(value, ['record_id', 'source_version_id', ...extraKeys]);
  if (row.record_id !== formatId(format, record) || row.source_version_id !== formatId(format, version)
      || (expectedProposal !== undefined && row.proposal_id !== expectedProposal)) invalid();
  return row;
}
/** @returns {Promise<{record_id: string, source_version_id: string, metadata: ValidatedMetadata | null}>} */
export async function readValidatedMetadata(transport, format, record, version, signal) {
  const row = targetReceipt(await request(transport, recordPath(format, record, version), signal), format, record, version, ['metadata']);
  return { ...row, metadata: validatedMetadata(row.metadata) };
}
/** @returns {Promise<{record_id: string, source_version_id: string, proposal_id: string, expected_revision: string}>} */
export async function proposeCorrection(transport, format, record, version, expected, key, input, signal) {
  if (!isRevision(expected, true)) invalid();
  const command = { request_id: requireUuid(key), expected_revision: expected, metadata: metadataInput(input) };
  const row = targetReceipt(await request(transport, `${recordPath(format, record, version)}/corrections`, signal, 200, post(command)),
    format, record, version, ['proposal_id', 'expected_revision']);
  if (row.expected_revision !== expected || typeof row.proposal_id !== 'string' || !xlsxUuid.test(row.proposal_id)) invalid();
  return row;
}

function initialPath(format, job) { return `/${format}/review/${formatId(format, job)}`; }
/** @returns {Promise<{job_id: string, node_id: string, proposed_metadata: MetadataInput | null}>} */
export async function readInitialMetadata(transport, format, job, signal) {
  const row = exact(await request(transport, initialPath(format, job), signal), ['job_id', 'node_id', 'proposed_metadata']);
  if (row.job_id !== formatId(format, job) || typeof row.node_id !== 'string' || !xlsxNode.test(row.node_id)) invalid();
  return { ...row, proposed_metadata: row.proposed_metadata === null ? null : metadataInput(row.proposed_metadata) };
}
const requireAction = (action) => { if (action !== 'approve' && action !== 'reject') invalid(); return action; };
export async function decideInitialMetadata(transport, format, job, action, key, replacement, signal) {
  const command = { action: requireAction(action), request_id: requireUuid(key) };
  if (replacement !== null) {
    if (action !== 'approve') invalid();
    command.metadata = metadataInput(replacement);
  }
  const row = exact(await request(transport, `${initialPath(format, job)}/decision`, signal, 200, post(command)),
    ['job_id', 'decision', 'metadata_revision']);
  if (row.job_id !== formatId(format, job) || row.decision !== action
      || (action === 'approve' ? row.metadata_revision !== '1' : row.metadata_revision !== null)) invalid();
  return row;
}

/** @typedef {{proposal_id: string, expected_revision: string, proposed_metadata: MetadataInput}} Correction */
/** @returns {Promise<{items: Correction[], next_after: string | null}>} */
export async function readCorrections(transport, format, record, version, after, signal) {
  const path = `${recordPath(format, record, version)}/corrections${after === null ? '' : `?after=${requireUuid(after)}`}`;
  const page = exact(await request(transport, path, signal), ['items', 'next_after']);
  if (!Array.isArray(page.items) || page.items.length > 10) invalid();
  let last = after;
  const items = page.items.map((value) => {
    const item = exact(value, ['proposal_id', 'expected_revision', 'proposed_metadata']);
    if (typeof item.proposal_id !== 'string' || !xlsxUuid.test(item.proposal_id) || (last !== null && last >= item.proposal_id)
        || !isRevision(item.expected_revision, true)) invalid();
    last = item.proposal_id;
    return { ...item, proposed_metadata: metadataInput(item.proposed_metadata) };
  });
  if (page.next_after !== null && (items.length !== 10 || page.next_after !== last)) invalid();
  return { items, next_after: page.next_after };
}
export async function decideCorrection(transport, format, record, version, correction, action, key, signal) {
  const id = requireUuid(correction.proposal_id);
  if (!isRevision(correction.expected_revision, true)) invalid();
  const path = `${recordPath(format, record, version)}/corrections/${id}/decision`;
  const row = targetReceipt(await request(transport, path, signal, 200, post({ action: requireAction(action), request_id: requireUuid(key) })),
    format, record, version, ['proposal_id', 'decision', 'metadata_revision'], id);
  if (row.decision !== action || (action === 'approve'
    ? !isRevision(row.metadata_revision) || BigInt(row.metadata_revision) !== BigInt(correction.expected_revision) + 1n
    : row.metadata_revision !== null)) invalid();
  return row;
}
