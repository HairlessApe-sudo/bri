'use client';

import { useCallback, useLayoutEffect, useRef, useState } from 'react';
import { useParams } from 'next/navigation';
import { isXlsxId, parseXlsxProposal, xlsxReviewPath } from '../../../../xlsx-governance.mjs';
import { InitialMetadataReview } from '../../../classification/initial-review';
import { useEvidenceRefresh } from '../../../refresh';
import { decisionAttempt } from '../../client.mjs';
import { PageButtons, useXlsxRead, XlsxError } from '../../read';
import { WorksheetView } from '../../worksheet';
import { ReviewRecovery } from '../recovery';

type Decision = 'approve' | 'reject';
type Proposal = ReturnType<typeof parseXlsxProposal>;
const missing = 'XLSX proposal not found.';

export default function XlsxProposalPage() {
  const segment = useParams<{ id: string }>().id;
  const id = segment.replace(/^xlsx%3A/, 'xlsx:');
  return <ProposalPage key={id} id={id} />;
}

function ProposalPage({ id }: { id: string }) {
  const { parked, refreshKey, refresh } = useEvidenceRefresh();
  // Focus/bfcache reads must not silently clear a failed decision's recovery gate.
  const [recovery, block] = useState<number | null>(null);
  return parked ? null : <>
    <h1>XLSX review detail</h1>
    <p><a href="/xlsx/review">← XLSX review queue</a></p>
    {recovery !== null ? <ReviewRecovery status={recovery} refresh={() => { block(null); refresh(); }} /> : <>
      <p><button type="button" onClick={refresh}>Refresh proposal</button></p>
      {isXlsxId(id) ? <Pages key={refreshKey} id={id} refresh={refresh} block={block} />
        : <XlsxError status={404} missing={missing} />}
    </>}
  </>;
}

type ReviewFlow = { refresh: () => void; block: (status: number) => void };

function Pages({ id, refresh, block }: { id: string } & ReviewFlow) {
  const [cursor, visit] = useState<string | null>(null);
  return <Slice key={cursor ?? ''} id={id} cursor={cursor} visit={visit} refresh={refresh} block={block} />;
}

type PageFlow = ReviewFlow & { cursor: string | null; visit: (next: string | null) => void };

function Slice({ id, cursor, visit, refresh, block }: { id: string } & PageFlow) {
  const decode = useCallback((value: unknown) => parseXlsxProposal(value, id), [id]);
  const state = useXlsxRead(`${xlsxReviewPath}/${encodeURIComponent(id)}${cursor ? `?cursor=${cursor}` : ''}`, decode);
  if (!state) return <p role="status">Loading XLSX proposal…</p>;
  if (!state.data) return <XlsxError status={state.error ?? 502} missing={missing} />;
  return <DecisionSnapshot data={state.data} refresh={refresh} cursor={cursor} visit={visit} block={block} />;
}

function DecisionSnapshot({ data, refresh, cursor, visit, block }: { data: Proposal } & PageFlow) {
  const attempt = useRef<ReturnType<typeof decisionAttempt> | null>(null);
  const [choice, setChoice] = useState<Decision | null>(null);
  const [pending, setPending] = useState(false);
  useLayoutEffect(() => {
    const controller = new AbortController();
    attempt.current = decisionAttempt(fetch, data.id, data.state, controller.signal, () => crypto.randomUUID());
    return () => { attempt.current = null; controller.abort(); };
  }, [data.id, data.state]);

  function choose(decision: Decision | null) {
    attempt.current?.choose(decision);
    setChoice(decision);
  }

  async function confirm(decision: Decision) {
    const active = attempt.current;
    if (!active || choice !== decision || pending) return;
    setChoice(null);
    setPending(true);
    try {
      const receipt = await active.confirm(decision);
      if (attempt.current === active && receipt) refresh();
    } catch (error) {
      if (attempt.current === active) block((error as { status?: number }).status ?? 502);
    }
  }

  if (pending) return <p role="status">Recording decision and checking current state…</p>;
  return <>
    <p><code>{data.id}</code> · {data.node_id} · {data.state}</p>
    <WorksheetView data={data} />
    <PageButtons cursor={cursor} next={data.next_cursor} visit={visit} noun="evidence" />
    {data.state === 'proposed' && <InitialMetadataReview format="xlsx" job={data.id} node={data.node_id} refresh={refresh} block={block}
      legacy={<section className="content-panel" aria-label="XLSX review decision">
      <h2>Review decision</h2>
      <p>Approval validates this proposal. It does not publish it or grant access.</p>
      {choice ? <fieldset><legend>Record the decision for this proposal?</legend>
        <button type="button" onClick={() => void confirm(choice)}>{choice === 'approve' ? 'Confirm approval' : 'Confirm rejection'}</button>{' '}
        <button type="button" onClick={() => choose(null)}>Cancel</button>
      </fieldset> : <>
        <button type="button" onClick={() => choose('approve')}>Approve…</button>{' '}
        <button type="button" onClick={() => choose('reject')}>Reject…</button>
      </>}
    </section>} />}
  </>;
}
