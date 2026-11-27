import assert from 'node:assert/strict';
import { test } from 'node:test';
import * as contract from '../local-workspace/unified-contract.mjs';

const unavailable = { version: 1, status: 'unavailable' };
const scopes = (...entries) => ({ version: 1, status: 'complete', scopes: entries });
const scope = (scope_node_id, display_label) => ({ scope_node_id, display_label });

test('query normalization is limited to backend ASCII folding and whitespace', () => {
  assert.equal(contract.normalizeQuery(' \tA\n\r\f\vB Éẞ e\u0301 😀 '), 'a b Éẞ e\u0301 😀');
  assert.equal(contract.normalizeQuery(' '), ' ');
  assert.equal(contract.normalizeQuery('é'.repeat(128)), 'é'.repeat(128));
  assert.equal(contract.normalizeQuery('😀'.repeat(64)), '😀'.repeat(64));
  assert.equal(contract.normalizeQuery(' '.repeat(4096) + 'A'), 'a');
  for (const query of [null, 1, '', ' \t\v ', 'a\u0000', 'a\u0008', 'a\u007f', '\ud800', '\udc00',
    'é'.repeat(129), '😀'.repeat(64) + 'a']) assert.throws(() => contract.normalizeQuery(query));
});

test('scopes preserve blank labels and use UTF-8 byte order with the ID as tie-break', () => {
  const receipt = scopes(scope('z', ''), scope('a', 'é'), scope('b:._-1', 'é'), scope('x', '\ue000'), scope('w', '😀'));
  assert.deepEqual(contract.parseScopes(receipt), receipt);
  assert.deepEqual(contract.parseScopes(scopes()), scopes());
  assert.deepEqual(contract.parseScopes(unavailable), unavailable);
  assert.equal(contract.isScopeId('a' + '-'.repeat(127)), true);
  for (const id of [null, '-a', 'a\n', 'a%20', 'á', 'a'.repeat(129)]) assert.equal(contract.isScopeId(id), false);
  for (const invalid of [null, { ...unavailable, scopes: [] }, { ...scopes(), version: '1' },
    scopes(scope('x', '😀'), scope('w', '\ue000')), scopes(scope('b', 'é'), scope('a', 'é')),
    scopes(scope('a', 'a'), scope('a', 'b')), scopes(scope('a', '\ud800')), scopes(scope('a', null)),
    scopes(scope('a', ''), { ...scope('b', ''), tenant_id: 'private' }), scopes(...Array(501).fill(scope('a', '')))]) {
    assert.throws(() => contract.parseScopes(invalid));
  }
});

test('scope wire budget counts UTF-8 and JSON escapes', () => {
  const receipt = scopes(scope('team', ''));
  const budget = 131072 - Buffer.byteLength(JSON.stringify(receipt));
  receipt.scopes[0].display_label = '\u0002' + 'é'.repeat(Math.floor((budget - 6) / 2)) + 'x'.repeat(budget % 2);
  assert.equal(Buffer.byteLength(JSON.stringify(receipt)), 131072);
  assert.deepEqual(contract.parseScopes(receipt), receipt);
  receipt.scopes[0].display_label += 'x';
  assert.throws(() => contract.parseScopes(receipt));
});

const csvId = 'aabbccdd-2233-4455-6677-8899aabbccdd';
const xlsxId = 'aabbccdd-2233-4455-6677-8899aabbccde';
const xlsxVersion = 'aabbccdd-2233-4455-6677-8899aabbccdf';
const original_sha256 = 'a'.repeat(64);
const content_sha256 = 'b'.repeat(64);
const canonical_sha256 = 'c'.repeat(64);
const csv = { format: 'csv', record_id: csvId, source_id: `csv:${csvId}`, source_version_id: csvId,
  original_sha256, content_sha256, match: 'exact', excerpt: 'évidence', excerpt_truncated: false,
  evidence: { first_line: 3, last_line: 4 }, evidence_url: `/v1/knowledge/csv/${csvId}/versions/${csvId}/evidence` };
const xlsx = { format: 'xlsx', record_id: xlsxId, source_id: xlsxVersion, source_version_id: xlsxVersion,
  original_sha256, canonical_sha256, extractor_version: 1, canonicalization_version: 1, match: 'substring',
  excerpt: 'evidence', excerpt_truncated: true, evidence: { sheet_id: '4294967295', sheet_title: 'Synthetic', cell: 'B2' },
  evidence_url: `/v2/knowledge/xlsx/${xlsxId}/evidence/${xlsxVersion}` };
const search = (...results) => ({ version: 1, status: 'complete', results });

test('search returns native complete and unavailable shapes without losing format-specific fields', () => {
  assert.deepEqual(contract.parseSearch(search(csv, xlsx)), search(csv, xlsx));
  assert.deepEqual(contract.parseSearch(search()), search());
  assert.deepEqual(contract.parseSearch(unavailable), unavailable);
  assert.deepEqual(contract.parseSearch(search({ ...xlsx, evidence: { ...xlsx.evidence, cell: 'BL10000', sheet_title: '😀'.repeat(31) },
    excerpt: 'é'.repeat(1024) })).results[0].evidence.cell, 'BL10000');
  assert.deepEqual(contract.parseSearch(search({ ...csv, evidence: { first_line: 2147483647, last_line: 2147483647 } })).results[0].evidence,
    { first_line: 2147483647, last_line: 2147483647 });
});

test('search rejects an entire receipt when any hit, provenance, coordinate, or link is invalid', () => {
  const invalidCsv = [
    { ...csv, record_id: csvId.toUpperCase() }, { ...csv, record_id: csvId + '\n' },
    { ...csv, source_version_id: xlsxVersion }, { ...csv, source_id: csvId },
    { ...csv, evidence: { first_line: true, last_line: 4 } }, { ...csv, evidence: { first_line: 4, last_line: 3 } },
    { ...csv, evidence: { first_line: 1, last_line: 2147483648 } }, { ...csv, content_sha256: 'C'.repeat(64) },
  ];
  const invalidXlsx = [
    { ...xlsx, source_id: csvId }, { ...xlsx, original_sha256: original_sha256 + '\n' },
    { ...xlsx, record_id: '00000000-0000-0000-0000-000000000000' }, { ...xlsx, match: 'prefix' },
    { ...xlsx, excerpt: 'é'.repeat(1025) }, { ...xlsx, excerpt: '\ud800' }, { ...xlsx, excerpt: '' },
    { ...xlsx, excerpt_truncated: 1 }, { ...xlsx, canonical_sha256: 'G'.repeat(64) },
    { ...xlsx, extractor_version: true }, { ...xlsx, canonicalization_version: 2 },
    { ...xlsx, evidence_url: '/v1' + xlsx.evidence_url.slice(3) }, { ...xlsx, evidence_url: 'https://invalid.test' + xlsx.evidence_url },
    { ...xlsx, evidence_url: xlsx.evidence_url + '?cursor=' + '1'.repeat(64) },
    ...[{ sheet_id: '0' }, { sheet_id: 1 }, { sheet_id: '01' }, { sheet_id: '4294967296' }, { sheet_id: '1\n' },
      { sheet_title: 'a/b' }, { sheet_title: 'a\u001f' }, { sheet_title: '😀'.repeat(32) },
      { cell: 'BM1' }, { cell: 'AB10001' }, { cell: 'A01' }, { cell: 'a1' }, { cell: 'A1\n' }, { private: 'extra' }]
      .map((change) => ({ ...xlsx, evidence: { ...xlsx.evidence, ...change } })),
  ];
  for (const entry of [...invalidCsv, ...invalidXlsx, null, { ...xlsx, storage_key: 'private' }]) {
    assert.throws(() => contract.parseSearch(search(xlsx, entry)), /Invalid unified knowledge receipt/);
  }
  for (const invalid of [search(csv, csv), { ...unavailable, results: [] }, { ...search(), total: 0 },
    { ...search(csv), status: 'partial' }, search(...Array(21).fill(csv)), { ...search(), results: Array(1) }]) {
    assert.throws(() => contract.parseSearch(invalid));
  }
});

test('search wire budget covers JSON escapes across the complete page', () => {
  const receipt = search(...Array.from({ length: 20 }, (_, i) => {
    const id = `aabbccdd-2233-4455-6677-8899aabbcc${(i + 16).toString(16)}`;
    return { ...csv, record_id: id, source_version_id: id, source_id: `csv:${id}`,
      evidence_url: `/v1/knowledge/csv/${id}/versions/${id}/evidence` };
  }));
  let budget = 131072 - Buffer.byteLength(JSON.stringify(receipt));
  for (const hit of receipt.results) {
    const controls = Math.min(1900, Math.floor(budget / 6));
    hit.excerpt += '\u0002'.repeat(controls);
    budget -= 6 * controls;
  }
  receipt.results.at(-1).excerpt += 'x'.repeat(budget);
  assert.equal(Buffer.byteLength(JSON.stringify(receipt)), 131072);
  assert.deepEqual(contract.parseSearch(receipt), receipt);
  receipt.results.at(-1).excerpt += 'x';
  assert.throws(() => contract.parseSearch(receipt));
});

test('evidence paths are fixed and only XLSX accepts a canonical continuation', () => {
  const cursor = 'ab'.repeat(32);
  assert.equal(contract.evidencePath(csv), csv.evidence_url);
  assert.equal(contract.evidencePath(xlsx), xlsx.evidence_url);
  assert.equal(contract.evidencePath(xlsx, cursor), `${xlsx.evidence_url}?cursor=${cursor}`);
  for (const invalid of ['', null, cursor.toUpperCase(), cursor + '\n', cursor + '&scope=other']) {
    assert.throws(() => contract.evidencePath(xlsx, invalid));
  }
  assert.throws(() => contract.evidencePath(csv, cursor));
  assert.throws(() => contract.evidencePath({ ...xlsx, evidence_url: '//invalid.test/evidence' }));
  assert.throws(() => contract.evidencePath({ ...xlsx, record_id: '../xlsx' }));
});

const csvReceipt = { record_id: csvId, source_version_id: csvId, first_line: 1, last_line: 9,
  original_sha256, content_sha256 };
const cell = (row, column, value = null) => ({ row, column, value });
const next_cursor = 'f'.repeat(64);
const page = { version: 2, record_id: xlsxId, source_version_id: xlsxVersion, source_id: xlsxVersion, node_id: 'team',
  original_sha256, canonical_sha256, extractor_version: 1, canonicalization_version: 1, sheet_id: xlsx.evidence.sheet_id,
  sheet_title: xlsx.evidence.sheet_title, cell_range: 'A1:B3', cells: [cell(1, 1, ['text', 'First']), cell(1, 2, ['text', 'Second'])], next_cursor };

test('CSV evidence binds IDs and digests and contains the matching line span', () => {
  assert.deepEqual(contract.parseEvidence(csvReceipt, csv, 'team'), csvReceipt);
  for (const delta of [{ record_id: xlsxId }, { source_version_id: xlsxVersion }, { original_sha256: 'd'.repeat(64) },
    { content_sha256: 'e'.repeat(64) }, { first_line: 4 }, { last_line: 3 }, { first_line: 0 },
    { last_line: 2147483648 }, { last_line: true }, { source_id: csv.source_id }, { node_id: 'team' }]) {
    assert.throws(() => contract.parseEvidence({ ...csvReceipt, ...delta }, csv));
  }
  assert.throws(() => contract.parseEvidence(unavailable, csv));
  assert.throws(() => contract.parseEvidence(csvReceipt, xlsx));
});

test('XLSX v2 evidence retains native fields across pages before and after the hit', () => {
  assert.deepEqual(contract.parseEvidence(page, xlsx, 'team'), page);
  assert.deepEqual(contract.parseEvidence(page, xlsx), page);
  const later = { ...page, cells: [cell(2, 2, ['boolean', true]), cell(3, 1), cell(3, 2, ['number', '1e0'])], next_cursor: null };
  assert.deepEqual(contract.parseEvidence(later, xlsx, 'team'), later);
  const after = { ...later, cells: later.cells.slice(1) };
  assert.deepEqual(contract.parseEvidence(after, xlsx, 'team'), after);
  assert.throws(() => contract.parseEvidence(page, xlsx, 'other-team'));
  assert.throws(() => contract.parseEvidence(page, xlsx, null));
});

test('XLSX v2 evidence rejects incompatible provenance, worksheet, and page shapes', () => {
  const { source_id, version, ...v1 } = page;
  for (const invalid of [v1, unavailable, { ...page, storage_key: 'private' },
    ...[{ version: 1 }, { record_id: csvId }, { source_version_id: csvId }, { source_id: csvId }, { node_id: 'bad/id' },
      { canonical_sha256: 'd'.repeat(64) }, { original_sha256: 'f'.repeat(64) }, { extractor_version: 2 },
      { canonicalization_version: true }, { sheet_id: '1' }, { sheet_title: 'Other' }, { cell_range: 'A1:A3' },
      { cell_range: 'A1:B1' }, { cell_range: 'A1:B3\n' }, { cell_range: 'A1:BL10000' }, { next_cursor: 'g'.repeat(64) },
      { next_cursor: null }, { cells: [] }, { cells: [cell(1, 1), cell(2, 1)] }, { cells: [cell(1, 1), cell(1, 1)] },
      { cells: [cell(1, 3)] }, { cells: [cell(1, 1, ['text', 'é'.repeat(2049)])] },
      { cells: [cell(1, 1, ['text', '\ud800'])] }, { cells: [cell(1, 1, ['boolean', 'true'])] },
      { cells: [{ ...cell(1, 1), hidden: 'private' }] }, { cells: Array(1) }, { cells: [cell(2, 2)] },
      { cell_range: 'A1:B51', cells: Array.from({ length: 101 }, (_, i) => cell(1 + Math.floor(i / 2), 1 + i % 2)) }]
      .map((change) => ({ ...page, ...change }))]) {
    assert.throws(() => contract.parseEvidence(invalid, xlsx), /Invalid (unified knowledge receipt|XLSX projection)/);
  }
});

test('XLSX evidence applies the full 512 KiB serialized page budget', () => {
  const receipt = { ...page, cell_range: 'A1:D40', next_cursor: null, cells: Array.from({ length: 160 }, (_, i) =>
    cell(1 + Math.floor(i / 4), 1 + i % 4, ['text', 'x'])) };
  let budget = 524288 - Buffer.byteLength(JSON.stringify(receipt));
  for (const entry of receipt.cells) {
    const added = Math.min(4095, budget);
    entry.value[1] += 'é'.repeat(Math.floor(added / 2)) + 'x'.repeat(added % 2);
    budget -= added;
  }
  assert.equal(Buffer.byteLength(JSON.stringify(receipt)), 524288);
  assert.deepEqual(contract.parseEvidence(receipt, xlsx), receipt);
  receipt.cells.at(-1).value[1] += 'x';
  assert.throws(() => contract.parseEvidence(receipt, xlsx));
});
