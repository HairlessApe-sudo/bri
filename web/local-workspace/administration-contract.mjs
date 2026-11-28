import { maxWorkbookBytes, xlsxMedia, xlsxUuid } from './xlsx-intake.mjs';

export const administrationBase = '/v1/knowledge-administration';
export const receiptLimit = 1024;
export const metadataLimit = 8192;
export const uploadLimit = maxWorkbookBytes; // Both native intake formats currently use this bound.
export const isJobId = (id) => typeof id === 'string' && !/[\r\n]/.test(id) && xlsxUuid.test(id);
export const isFormat = (format) => format === 'csv' || format === 'xlsx';
export const mediaFor = (format) => format === 'csv' ? 'text/csv' : format === 'xlsx' ? xlsxMedia : undefined;
export const catalogVisibilityPath = `${administrationBase}/catalogue-visibility`;
export const administrationSessionPath = `${administrationBase}/session`;
export const administrationContextHeader = 'x-bri-administration-context';
export const isAdministrationContext = (value) => typeof value === 'string' && value.length === 64 && /^[0-9a-f]+$/.test(value);
export const csvStatusBase = '/v1/sources/csv';

export function statusPath(format, id) {
  if (!isFormat(format) || !isJobId(id)) throw new Error('An exact native job identifier and format are required');
  return `${format === 'csv' ? csvStatusBase : `${administrationBase}/xlsx/status`}/${id}`;
}

const baseStates = ['ready', 'processing', 'proposed', 'failed'];
/** @param {'csv' | 'xlsx'} format @param {unknown} value @param {string} [expectedId] */
export function parseAdministrationReceipt(format, value, expectedId) {
  const states = [...baseStates, ...(expectedId === undefined ? [] : ['creating']), ...(format === 'csv' ? ['approved', 'rejected'] : [])];
  if (!isFormat(format) || !value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).length !== 2 || !Object.hasOwn(value, 'id') || !Object.hasOwn(value, 'state')
    || !isJobId(value.id) || (expectedId !== undefined && value.id !== expectedId) || !states.includes(value.state)) {
    throw new Error('Invalid native job receipt');
  }
  return { id: value.id, state: value.state };
}

// JSON.parse alone silently collapses duplicate keys, even when the names use different escapes.
export function decodeExactJson(bytes) {
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  const value = JSON.parse(text);
  const stack = [];
  const colon = /\s*:/y;
  for (const token of text.matchAll(/"(?:[^"\\]|\\.)*"|[{}\[\]]/gs)) {
    colon.lastIndex = token.index + token[0].length;
    if (token[0] === '{') stack.push(new Set());
    else if (token[0] === '[') stack.push(null);
    else if (token[0] === '}' || token[0] === ']') stack.pop();
    else if (stack.at(-1) && colon.test(text)) {
      const key = JSON.parse(token[0]);
      if (stack.at(-1).has(key)) throw new Error('Duplicate JSON key');
      stack.at(-1).add(key);
    }
  }
  return value;
}
