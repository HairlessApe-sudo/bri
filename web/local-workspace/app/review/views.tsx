'use client';

import type { ReactNode } from 'react';
import { StateMessage } from '@/components/data-state';
import { parseDetail, parseQueue, reviewStates } from '../../review-contract.mjs';

export type ReviewState = typeof reviewStates[number];
export type ReviewDecision = 'approved' | 'rejected';
export type Detail = ReturnType<typeof parseDetail>;
export type Queue = ReturnType<typeof parseQueue>;
export const labels: Record<ReviewState, string> = { proposed: 'Proposed', approved: 'Approved', rejected: 'Rejected', failed: 'Processing failed' };

function scopeLabel(value: string) {
  return value.trim() ? value : 'Blank node label';
}

export function ReviewError({ error }: { error: Error }) {
  const status = (error as Error & { status?: number }).status;
  if (status === 404) return <p className="state-message" role="alert">Proposal not found.</p>;
  const message = status === 401 ? 'A current signed fixture session is required.' : status === 403
    ? 'This session is not authorized to review here.' : 'Refresh to try loading the current review state.';
  return <StateMessage error={Object.assign(new Error(message), { status })} />;
}

export function ReviewQueueView({ data }: { data: Queue }) {
  if (!data.items.length) return <p className="state-message">No proposals on this page.</p>;
  return <div className="table-wrap"><table aria-label="CSV review queue">
    <thead><tr><th scope="col">Review ID</th><th scope="col">State</th><th scope="col">Node</th><th scope="col">Created</th></tr></thead>
    <tbody>{data.items.map((row) => <tr key={row.id}>
      <td><a className="knowledge-title mono breakable" href={`/review/${encodeURIComponent(row.id)}`}>{row.id}</a></td>
      <td>{labels[row.state]}</td><td>{scopeLabel(row.node_id)}</td><td><time dateTime={row.created_at}>{row.created_at}</time></td>
    </tr>)}</tbody>
  </table></div>;
}

export function ReviewDetailView({ data, offset, pagination, actions }: { data: Detail; offset: number; pagination: ReactNode; actions?: ReactNode }) {
  const p = data.provenance;
  return <>
    <section className="content-panel" aria-label="Proposal state">
      <h2>{labels[data.state]}</h2>
      <p><code className="breakable">{data.id}</code> · {scopeLabel(data.node_id)} · <time dateTime={data.created_at}>{data.created_at}</time></p>
      {data.state === 'failed' && <p>Processing failed. No proposal can be decided.</p>}
      {data.state === 'approved' && <p>This review is complete. Approval does not publish the record or authorize access.</p>}
      {data.state === 'rejected' && <p>This review is complete. No further decision is available.</p>}
    </section>
    {p && <section className="content-panel" aria-label="Provenance">
      <h2>Provenance</h2>
      <dl className="provenance-grid">{[
        ['Source ID', p.source_id], ['Source version ID', p.source_version_id], ['Source version', p.source_version],
        ['Extraction ID', p.extraction_id], ['Original SHA-256', p.original_sha256], ['Extracted SHA-256', p.content_sha256],
        ['CSV lines (inclusive)', `${p.csv_first_line}–${p.csv_last_line}`],
      ].map(([name, value]) => <div key={name}><dt>{name}</dt><dd className="mono breakable">{value}</dd></div>)}</dl>
    </section>}
    <section className="content-panel" aria-label="Extracted evidence">
      <h2>Extracted evidence</h2>
      {data.evidence === null ? <p>No extracted evidence is available.</p> : <>
        <p>Character offset: {offset}</p>
        {data.evidence ? <pre className="breakable" style={{ whiteSpace: 'pre-wrap' }}>{data.evidence}</pre> : <p>No text on this evidence page.</p>}
        {pagination}
      </>}
    </section>
    <section className="content-panel" aria-label="Review history">
      <h2>History</h2>
      {data.history.length ? <ol>{data.history.map(({ event, occurred_at, reason }, i) => <li key={`${occurred_at}-${i}`}>
        <strong>{event}</strong> · <time dateTime={occurred_at}>{occurred_at}</time>{reason && <> · <code>{reason}</code></>}
      </li>)}</ol> : <p>No history entries.</p>}
    </section>
    {data.state === 'proposed' && actions}
  </>;
}

export function ReviewConfirmation({ choice, choose, submit }: {
  choice: ReviewDecision | null; choose: (decision: ReviewDecision | null) => void; submit: (decision: ReviewDecision) => void;
}) {
  const confirm = choice === 'approved' ? 'Confirm approval' : 'Confirm rejection';
  return <section className="content-panel" aria-label="Review decision">
    <h2>Review decision</h2>
    <p><strong>Approval does not publish this record or authorize anyone to access it.</strong></p>
    {choice ? <fieldset>
      <legend>{confirm}</legend>
      <p>This records a final review decision for the proposal shown above.</p>
      <button type="button" onClick={() => submit(choice)}>{confirm}</button>{' '}
      <button type="button" onClick={() => choose(null)}>Cancel</button>
    </fieldset> : <>
      <button type="button" onClick={() => choose('approved')}>Approve…</button>{' '}
      <button type="button" onClick={() => choose('rejected')}>Reject…</button>
    </>}
  </section>;
}
