'use client';

import { useCallback } from 'react';
import { useParams } from 'next/navigation';
import { xlsxUuid } from '../../../../xlsx-intake.mjs';
import { useEvidenceRefresh } from '../../../refresh';
import { readPublishedRecord } from '../../client.mjs';
import { useAuthorizedRead, XlsxError } from '../../read';

export default function XlsxPublishedRecordPage() {
  const { record } = useParams<{ record: string }>();
  const { parked, refreshKey, refresh } = useEvidenceRefresh();
  return parked ? null : <>
    <h1>Published XLSX detail</h1>
    <p><a href="/xlsx/knowledge">← Published XLSX records</a></p>
    <p><button type="button" onClick={refresh}>Refresh record</button></p>
    {xlsxUuid.test(record) ? <RecordSnapshot key={`${record}:${refreshKey}`} record={record} />
      : <XlsxError status={404} missing="XLSX record not found." />}
  </>;
}

function RecordSnapshot({ record }: { record: string }) {
  const load = useCallback((signal: AbortSignal) => readPublishedRecord(fetch, record, signal), [record]);
  const state = useAuthorizedRead(load);
  if (!state) return <p role="status">Loading XLSX record…</p>;
  if (!state.data) return <XlsxError status={state.error ?? 502} missing="XLSX record not found." />;
  const { record_id, source_version_id, node_id } = state.data;
  return <section className="content-panel">
    <h2>Authorized record</h2>
    <dl>
      <dt>Record ID</dt><dd><code>{record_id}</code></dd>
      <dt>Source version ID</dt><dd><code>{source_version_id}</code></dd>
      <dt>Node</dt><dd>{node_id}</dd>
    </dl>
    <p><a href={`/xlsx/knowledge/${record_id}/evidence/${source_version_id}`}>Open exact-version worksheet evidence</a></p>
  </section>;
}
