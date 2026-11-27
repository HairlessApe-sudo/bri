'use client';

import { useState } from 'react';
import { parseXlsxQueue, xlsxReviewPath } from '../../../xlsx-governance.mjs';
import { useEvidenceRefresh } from '../../refresh';
import { PageButtons, useXlsxRead, XlsxError } from '../read';

export default function XlsxQueuePage() {
  const { parked, refreshKey, refresh } = useEvidenceRefresh();
  return parked ? null : <>
    <h1>XLSX review queue</h1>
    <p><a href="/xlsx">← XLSX intake</a></p>
    <p><button type="button" onClick={refresh}>Refresh queue</button></p>
    <Pages key={refreshKey} />
  </>;
}

function Pages() {
  const [cursor, visit] = useState<string | null>(null);
  return <Queue key={cursor ?? ''} cursor={cursor} visit={visit} />;
}

function Queue({ cursor, visit }: { cursor: string | null; visit: (next: string | null) => void }) {
  const state = useXlsxRead(xlsxReviewPath + (cursor ? `?cursor=${cursor}` : ''), parseXlsxQueue);
  if (!state) return <p role="status">Loading XLSX review queue…</p>;
  if (!state.data) return <XlsxError status={state.error ?? 502} missing="XLSX review queue not found." />;
  const { items, next_cursor } = state.data;
  return <>
    {items.length ? <div className="table-wrap"><table aria-label="XLSX review queue">
      <thead><tr><th scope="col">Proposal</th><th scope="col">Node</th><th scope="col">Review state</th></tr></thead>
      <tbody>{items.map(({ id, node_id, state }) => <tr key={id}>
        <td><a href={`/xlsx/review/${encodeURIComponent(id)}`}>{id}</a></td><td>{node_id}</td><td>{state}</td>
      </tr>)}</tbody>
    </table></div> : <p>No XLSX proposals on this page.</p>}
    <PageButtons cursor={cursor} next={next_cursor} visit={visit} noun="queue" />
  </>;
}
