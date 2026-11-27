'use client';

import { useCallback, useState } from 'react';
import { useParams } from 'next/navigation';
import { xlsxUuid } from '../../../../../../xlsx-intake.mjs';
import { useEvidenceRefresh } from '../../../../../refresh';
import { readPublishedEvidence } from '../../../../client.mjs';
import { PageButtons, useAuthorizedRead, XlsxError } from '../../../../read';
import { WorksheetView } from '../../../../worksheet';

const missing = 'XLSX evidence not found.';

export default function XlsxPublishedEvidencePage() {
  const { record, version } = useParams<{ record: string; version: string }>();
  const { parked, refreshKey, refresh } = useEvidenceRefresh();
  if (parked) return null;
  if (!xlsxUuid.test(record) || !xlsxUuid.test(version)) return <XlsxError status={404} missing={missing} />;
  return <>
    <h1>Exact-version XLSX evidence</h1>
    <p><a href={`/xlsx/knowledge/${record}`}>← Published XLSX detail</a></p>
    <p><button type="button" onClick={refresh}>Refresh evidence</button></p>
    <Pages key={`${record}:${version}:${refreshKey}`} record={record} version={version} />
  </>;
}

function Pages({ record, version }: { record: string; version: string }) {
  const [cursor, visit] = useState<string | null>(null);
  return <Slice key={cursor ?? ''} record={record} version={version} cursor={cursor} visit={visit} />;
}

function Slice({ record, version, cursor, visit }: {
  record: string; version: string; cursor: string | null; visit: (next: string | null) => void;
}) {
  const load = useCallback((signal: AbortSignal) => readPublishedEvidence(fetch, record, version, cursor, signal), [record, version, cursor]);
  const state = useAuthorizedRead(load);
  if (!state) return <p role="status">Loading exact worksheet evidence…</p>;
  if (!state.data) return <XlsxError status={state.error ?? 502} missing={missing} />;
  return <>
    <p>Source version <code>{state.data.source_version_id}</code></p>
    <WorksheetView data={state.data} />
    <PageButtons cursor={cursor} next={state.data.next_cursor} visit={visit} noun="evidence" />
  </>;
}
