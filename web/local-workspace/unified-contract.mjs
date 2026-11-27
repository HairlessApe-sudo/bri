import { isCursor, parsePublishedEvidence, shape } from './xlsx-governance.mjs';
import { xlsxUuid } from './xlsx-intake.mjs';

const encoder = new TextEncoder();
const receiptLimit = 131072;
const invalid = () => { throw new Error('Invalid unified knowledge receipt'); };
const validString = (value) => typeof value === 'string' && !/[\uD800-\uDFFF]/u.test(value);
const byteLength = (value) => encoder.encode(value).length;
const bounded = (value, limit = receiptLimit) => {
  if (byteLength(JSON.stringify(value)) > limit) invalid();
  return value;
};

export const isScopeId = (value) => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(value);

export function normalizeQuery(value) {
  if (!validString(value) || /[\x00-\x08\x0E-\x1F\x7F]/.test(value)) {
    throw new Error('Invalid knowledge query');
  }
  // Do not use Unicode trim, lowercase, or normalization. Python and SQL fold ASCII only.
  const query = value.replace(/[ \t\n\r\f\v]+/g, ' ').replace(/^ | $/g, '')
    .replace(/[A-Z]/g, (letter) => letter.toLowerCase());
  if (!query || byteLength(query) > 256) throw new Error('Invalid knowledge query');
  return query;
}

function compareBytes(left, right) {
  for (let i = 0; i < Math.min(left.length, right.length); i++) {
    if (left[i] !== right[i]) return left[i] - right[i];
  }
  return left.length - right.length;
}

function checkEnvelope(value, key, limit) {
  if (shape(value, ['version', 'status']) && value.version === 1 && value.status === 'unavailable') return false;
  if (!shape(value, ['version', 'status', key]) || value.version !== 1 || value.status !== 'complete'
    || !Array.isArray(value[key]) || value[key].length > limit) invalid();
  return true;
}

export function parseScopes(value) {
  if (!checkEnvelope(value, 'scopes', 500)) return value;
  const seen = new Set();
  let previousLabel;
  let previousId;
  for (const entry of value.scopes) {
    if (!shape(entry, ['scope_node_id', 'display_label']) || !isScopeId(entry.scope_node_id)
      || !validString(entry.display_label) || seen.has(entry.scope_node_id)) invalid();
    const label = encoder.encode(entry.display_label);
    if (label.length > receiptLimit) invalid();
    // PostgreSQL COLLATE "C" orders UTF-8 bytes, not JavaScript UTF-16 code units.
    if (previousLabel !== undefined) {
      const order = compareBytes(previousLabel, label);
      if (order > 0 || (order === 0 && previousId >= entry.scope_node_id)) invalid();
    }
    previousLabel = label;
    previousId = entry.scope_node_id;
    seen.add(previousId);
  }
  return bounded(value);
}

const identityKeys = ['record_id', 'source_version_id', 'original_sha256'];
const hitKeys = [...identityKeys, 'format', 'source_id', 'match', 'excerpt', 'excerpt_truncated', 'evidence', 'evidence_url'];
const lineKeys = ['first_line', 'last_line'];
const sheetKeys = ['sheet_id', 'sheet_title'];
const xlsxProvenanceKeys = ['canonical_sha256', 'extractor_version', 'canonicalization_version'];
const isUuid = (value) => typeof value === 'string' && xlsxUuid.test(value);
const validLines = ({ first_line, last_line }) => Number.isInteger(first_line) && Number.isInteger(last_line)
  && first_line >= 1 && first_line <= last_line && last_line <= 2147483647;
const validSheet = ({ sheet_id, sheet_title }) => typeof sheet_id === 'string' && /^[1-9][0-9]{0,9}$/.test(sheet_id)
  && Number(sheet_id) <= 4294967295 && validString(sheet_title) && sheet_title.length > 0
  && !/[\x00-\x1f\[\]:*?/\\]/.test(sheet_title) && Array.from(sheet_title).length <= 31;

function cellPosition(value) {
  const match = typeof value === 'string' && /^([A-Z]{1,2})([1-9][0-9]{0,4})$/.exec(value);
  if (!match || Number(match[2]) > 10000 || (match[1].length === 2 && match[1] > 'BL')) invalid();
  const column = [...match[1]].reduce((n, letter) => n * 26 + letter.charCodeAt(0) - 64, 0);
  return { row: Number(match[2]), column };
}

function validatedHitPath(hit) {
  const kind = hit?.format;
  if (kind !== 'csv' && kind !== 'xlsx') invalid();
  const specific = kind === 'csv' ? ['content_sha256'] : xlsxProvenanceKeys;
  if (!shape(hit, [...hitKeys, ...specific]) || !isUuid(hit.record_id) || !isUuid(hit.source_version_id)
    || !isCursor(hit.original_sha256) || typeof hit.excerpt_truncated !== 'boolean'
    || (hit.match !== 'exact' && hit.match !== 'substring') || !validString(hit.excerpt)
    || !hit.excerpt || byteLength(hit.excerpt) > 2048) invalid();

  const { record_id: record, source_version_id: version, evidence } = hit;
  let path;
  if (kind === 'csv') {
    if (record !== version || hit.source_id !== `csv:${version}` || !isCursor(hit.content_sha256)
      || !shape(evidence, lineKeys) || !validLines(evidence)) invalid();
    path = `/v1/knowledge/csv/${record}/versions/${version}/evidence`;
  } else {
    if (hit.source_id !== version || !isCursor(hit.canonical_sha256)
      || hit.extractor_version !== 1 || hit.canonicalization_version !== 1
      || !shape(evidence, [...sheetKeys, 'cell']) || !validSheet(evidence)) invalid();
    cellPosition(evidence.cell);
    path = `/v2/knowledge/xlsx/${record}/evidence/${version}`;
  }
  if (hit.evidence_url !== path) invalid();
  return path;
}

export function parseSearch(value) {
  if (!checkEnvelope(value, 'results', 20)) return value;
  const seen = new Set();
  for (const hit of value.results) {
    validatedHitPath(hit);
    const key = `${hit.format}:${hit.record_id}`;
    if (seen.has(key)) invalid();
    seen.add(key);
  }
  return bounded(value);
}

/** Build an upstream route from validated identifiers, never from an arbitrary link.
 * @param {any} hit
 * @param {string} [cursor]
 */
export function evidencePath(hit, cursor = undefined) {
  const path = validatedHitPath(hit);
  if (cursor === undefined) return path;
  if (hit.format !== 'xlsx' || !isCursor(cursor)) invalid();
  return `${path}?cursor=${cursor}`;
}

const csvReceiptKeys = [...identityKeys, ...lineKeys, 'content_sha256'];
const v1PublishedKeys = ['record_id', 'source_version_id', 'node_id', ...sheetKeys, 'cell_range', 'cells', 'next_cursor'];
const v2PublishedKeys = ['version', 'source_id', 'original_sha256', ...xlsxProvenanceKeys];
const sameFields = (value, hit, keys) => keys.every((key) => value[key] === hit[key]);

/** Bind the independently authorized receipt to the selected search hit.
 * @param {any} value
 * @param {any} hit
 * @param {string} [scope]
 */
export function parseEvidence(value, hit, scope = undefined) {
  validatedHitPath(hit);
  if (hit.format === 'csv') {
    // The CSV receipt covers the source, not just the matched row's physical lines.
    if (!shape(value, csvReceiptKeys) || !sameFields(value, hit, [...identityKeys, 'content_sha256'])
      || !validLines(value) || value.first_line > hit.evidence.first_line || value.last_line < hit.evidence.last_line) invalid();
    return bounded(value);
  }

  if (!shape(value, [...v1PublishedKeys, ...v2PublishedKeys]) || value.version !== 2
    || !sameFields(value, hit, [...identityKeys, 'source_id', ...xlsxProvenanceKeys])
    || !isScopeId(value.node_id) || (scope !== undefined && value.node_id !== scope)
    || !sameFields(value, hit.evidence, sheetKeys)) invalid();

  // Only project v1 keys after v2 provenance and the exact receipt keys have passed.
  const v1 = Object.fromEntries(v1PublishedKeys.map((key) => [key, value[key]]));
  const worksheet = parsePublishedEvidence(v1, hit.record_id, hit.source_version_id);
  const position = cellPosition(hit.evidence.cell);
  const end = cellPosition(worksheet.cell_range.split(':').at(-1));
  if (position.row > end.row || position.column > end.column) invalid();
  for (const cell of worksheet.cells) {
    if (!cell || (typeof cell.value?.[1] === 'string' && !validString(cell.value[1]))) invalid();
    // The match can be on a different page, but a displayed matched cell cannot be blank.
    if (cell.row === position.row && cell.column === position.column && cell.value === null) invalid();
  }
  const v2 = Object.fromEntries(v2PublishedKeys.map((key) => [key, value[key]]));
  return bounded({ ...worksheet, ...v2 }, 524288);
}
