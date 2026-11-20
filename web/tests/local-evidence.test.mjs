import assert from 'node:assert/strict';
import test from 'node:test';

const recordId = 'csv:01234567-89ab-4def-8123-456789abcdef';
const source = {
  record_id: recordId, title: 'Synthetic rules', source_id: 'synthetic-source',
  source_version_id: 'synthetic-version-id', source_version: '1', extraction_id: 'synthetic-extraction',
  source_location: 'csv:lines=2-3', extractor_name: 'governed-csv', extractor_version: '1',
  original_sha256: 'a'.repeat(64), content_sha256: 'b'.repeat(64), csv_first_line: 2, csv_last_line: 3,
};
const citation = { ...source, excerpt: 'Permit applications require Form B.' };

test('only A13 statuses can expose the exact returned evidence', async () => {
  const { parseLocalSearch, parseLocalSource } = await import('../src/lib/local-evidence.mjs');
  const supported = { status: 'supported', answer: citation.excerpt, citations: [citation] };
  const conflicting = { status: 'conflicting', answer: null, citations: [citation, { ...citation, excerpt: 'Permit applications require Form C.' }] };
  const insufficient = { status: 'insufficient', answer: null, citations: [] };
  for (const evidence of [supported, conflicting, insufficient]) assert.deepEqual(parseLocalSearch(evidence), evidence);
  for (const invalid of [
    { ...supported, answer: 'Submit Form D.' }, { ...supported, citations: [] },
    { ...supported, status: 'outdated' }, { ...conflicting, citations: [citation] },
    { ...conflicting, answer: citation.excerpt }, { ...insufficient, citations: [citation] },
    { ...supported, citations: [{ ...citation, csv_last_line: 1 }] },
    { ...supported, citations: [{ ...citation, source_version_id: null }] },
  ]) assert.throws(() => parseLocalSearch(invalid), /evidence/);
  assert.deepEqual(parseLocalSource(source, recordId), source);
  assert.throws(() => parseLocalSource(source, 'csv:12345678-89ab-4def-8123-456789abcdef'), /evidence/);
});

test('remote state does not expose evidence while a new request is pending or denied', async () => {
  const { visibleRemote, workspaceEvidenceDenial } = await import('../src/lib/remote-state.mjs');
  const evidence = { path: '/search?q=one', refreshKey: 1, data: citation, error: null, loading: false };
  const pending = { data: null, error: null, loading: true };
  assert.equal(visibleRemote(evidence, evidence.path, 1).data, citation);
  assert.deepEqual(visibleRemote(evidence, '/search?q=two', 1), pending);
  assert.deepEqual(visibleRemote(evidence, evidence.path, 2), pending);
  assert.equal(visibleRemote(evidence, null, 1).data, null);
  const denied = Object.assign(new Error('Access denied'), { status: 403 });
  assert.deepEqual(visibleRemote({ ...evidence, error: denied }, evidence.path, 1), { data: null, error: denied, loading: false });
  assert.equal(workspaceEvidenceDenial(null, denied), denied);
  assert.equal(workspaceEvidenceDenial(denied, null), denied);
  assert.equal(workspaceEvidenceDenial(null, new Error('Invalid search response')), null);
});
