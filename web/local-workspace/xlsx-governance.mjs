import { xlsxUuid } from './xlsx-intake.mjs';

export const xlsxReviewPath = '/v1/knowledge/proposals/xlsx';
export const queueLimit = 20;
const encodedReviewId = 'xlsx%3A[0-9a-f-]{36}';
export function isXlsxPagePath(path) {
  if (path === '/xlsx' || path === '/xlsx/review' || path === '/xlsx/knowledge') return true;
  const [root, area, id, child, version, ...extra] = path.slice(1).split('/');
  if (root !== 'xlsx' || extra.length || !id) return false;
  if (area === 'review') return child === undefined && new RegExp(`^${encodedReviewId}$`).test(id) && xlsxUuid.test(id.slice(7));
  return area === 'knowledge' && xlsxUuid.test(id) && (child === undefined || (child === 'evidence' && xlsxUuid.test(version)));
}
export const isCursor = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
export const isXlsxId = (value) => typeof value === 'string' && value.startsWith('xlsx:') && xlsxUuid.test(value.slice(5));
export const invalid = () => { throw new Error('Invalid XLSX projection'); };
export const shape = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const states = ['proposed', 'approved', 'rejected'];

/** @returns {{items: {id: string, node_id: string, state: string}[], next_cursor: string | null}} */
export function parseXlsxQueue(value, limit = queueLimit) {
  if (!shape(value, ['items', 'next_cursor']) || !Array.isArray(value.items) || value.items.length > limit
    || (value.next_cursor !== null && (!value.items.length || !isCursor(value.next_cursor)))) invalid();
  const ids = new Set();
  const items = value.items.map(({ id, node_id, state, ...extra }) => {
    if (!isXlsxId(id) || ids.has(id) || typeof node_id !== 'string' || Object.keys(extra).length || !states.includes(state)) invalid();
    ids.add(id);
    return { id, node_id, state };
  });
  return { items, next_cursor: value.next_cursor };
}

const cellKinds = ['text', 'number', 'date', 'datetime', 'time'];
const worksheetKeys = ['sheet_id', 'sheet_title', 'cell_range', 'cells', 'next_cursor'];

/** @typedef {{row: number, column: number, value: [string, string | boolean] | null}} Cell */
/** @typedef {{sheet_id: string, sheet_title: string, cell_range: string, cells: Cell[], next_cursor: string | null}} Worksheet */

/** @returns {Worksheet} */
export function parseWorksheet(value) {
  const { sheet_id, sheet_title, cell_range, cells, next_cursor } = value;
  const range = typeof cell_range === 'string' && /^A1(?::([A-Z]{1,2})([1-9][0-9]{0,4}))?$/.exec(cell_range);
  if (typeof sheet_id !== 'string' || !/^[1-9][0-9]{0,9}$/.test(sheet_id) || Number(sheet_id) > 4294967295
    || typeof sheet_title !== 'string' || Array.from(sheet_title).length < 1 || Array.from(sheet_title).length > 31
    || !range || !Array.isArray(cells) || !cells.length || cells.length > 50 * 64
    || (next_cursor !== null && !isCursor(next_cursor))) invalid();
  const columns = [...(range[1] ?? 'A')].reduce((n, letter) => n * 26 + letter.charCodeAt(0) - 64, 0);
  const rows = Number(range[2] ?? '1');
  if (columns > 64 || rows > 10_000 || rows * columns > 100_000 || cell_range === 'A1:A1') invalid();
  let first = 0;
  let previous = -1;
  const projected = cells.map((cell) => {
    if (!shape(cell, ['row', 'column', 'value'])) invalid();
    const { row, column, value } = cell;
    if (!Number.isInteger(row) || row < 1 || row > rows || !Number.isInteger(column) || column < 1 || column > columns) invalid();
    if (value !== null && (!Array.isArray(value) || value.length !== 2 || (value[0] === 'boolean'
      ? typeof value[1] !== 'boolean' : !cellKinds.includes(value[0]) || typeof value[1] !== 'string' || new TextEncoder().encode(value[1]).length > 4096))) invalid();
    if (!first) first = row;
    const index = (row - 1) * columns + column - 1;
    if ((previous !== -1 && index !== previous + 1) || row - first >= 50) invalid();
    previous = index;
    return { row, column, value };
  });
  if ((previous === rows * columns - 1) !== (next_cursor === null)) invalid();
  return { sheet_id, sheet_title, cell_range, cells: projected, next_cursor };
}

export function parseXlsxProposal(value, expectedId) {
  if (!shape(value, ['id', 'node_id', 'state', ...worksheetKeys]) || !isXlsxId(value.id)
    || value.id !== expectedId || typeof value.node_id !== 'string' || !states.includes(value.state)) invalid();
  return { id: value.id, node_id: value.node_id, state: value.state, ...parseWorksheet(value) };
}

export const isDecision = (value) => value === 'approve' || value === 'reject';

export function parseXlsxDecision(value, id, decision) {
  if (!shape(value, ['id', 'decision']) || !isXlsxId(id) || value.id !== id || !isDecision(decision) || value.decision !== decision) invalid();
  return { id, decision };
}

export const xlsxPublishedPath = '/v1/knowledge/xlsx';
const recordFields = ['record_id', 'source_version_id', 'node_id'];

function publishedRecord(value, record, version) {
  const { record_id, source_version_id, node_id } = value;
  if (!xlsxUuid.test(record_id) || record_id !== record || !xlsxUuid.test(source_version_id)
    || (version !== undefined && source_version_id !== version) || typeof node_id !== 'string') invalid();
  return { record_id, source_version_id, node_id };
}

export function parsePublishedRecord(value, record) {
  if (!shape(value, recordFields)) invalid();
  return publishedRecord(value, record);
}

export function parsePublishedEvidence(value, record, version) {
  if (!shape(value, [...recordFields, ...worksheetKeys])) invalid();
  return { ...publishedRecord(value, record, version), ...parseWorksheet(value) };
}
