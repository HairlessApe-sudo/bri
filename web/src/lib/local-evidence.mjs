const csvId = /^csv:(?!00000000-0000-0000-0000-000000000000)[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const digest = /^[0-9a-f]{64}$/;

function malformed() { throw new Error('BRI did not return valid published evidence.'); }
function populated(value) { return typeof value === 'string' && Boolean(value.trim()); }
function physicalLine(value) { return Number.isSafeInteger(value) && value > 0; }

/** @returns {import('./api').SourceReference} */
export function parseLocalSource(source, recordId) {
  if (!source || !csvId.test(source.record_id) || (recordId !== undefined && source.record_id !== recordId)
    || !['title', 'source_id', 'source_version_id', 'source_version', 'extraction_id', 'extractor_name', 'extractor_version', 'source_location'].every((key) => populated(source[key]))
    || !digest.test(source.content_sha256) || !digest.test(source.original_sha256)
    || !physicalLine(source.csv_first_line) || !physicalLine(source.csv_last_line) || source.csv_last_line < source.csv_first_line) malformed();
  return source;
}

/** @returns {import('./api').KnowledgeRecord} */
export function parseLocalRecord(record, recordId) {
  parseLocalSource(record, recordId);
  if (!populated(record.scope_id) || record.validation_state !== 'approved' || typeof record.content !== 'string') malformed();
  return record;
}

/** @returns {import('./api').KnowledgeRecord[]} */
export function parseLocalRecords(records) {
  if (!Array.isArray(records)) malformed();
  return records.map((record) => parseLocalRecord(record, undefined));
}

/** @returns {import('./api').SearchResult} */
export function parseLocalSearch(result) {
  if (!Array.isArray(result?.citations)) malformed();
  const { answer, citations, status } = result;
  for (const citation of citations) {
    parseLocalSource(citation, undefined);
    if (!populated(citation.excerpt)) malformed();
  }
  if (status === 'supported' && populated(answer) && citations.some(({ excerpt }) => excerpt === answer)) return result;
  if (status === 'conflicting' && answer === null && new Set(citations.map(({ excerpt }) => excerpt)).size >= 2) return result;
  if (status === 'insufficient' && answer === null && citations.length === 0) return result;
  return malformed();
}
