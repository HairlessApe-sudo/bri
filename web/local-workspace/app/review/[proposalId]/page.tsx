'use client';

import { useCallback, useLayoutEffect, useRef, useState } from 'react';
import { useParams } from 'next/navigation';
import { PageHeading, StateMessage, useRemote } from '@/components/data-state';
import { apiBase, useEvidenceRefresh } from '../../refresh';
import { parseDecision, parseDetail, proposalFromSegment, reviewResource } from '../../../review-contract.mjs';
import { ReviewConfirmation, ReviewDetailView, ReviewError, type Detail, type ReviewDecision } from '../views';

export default function ReviewProposalPage() {
  const id = proposalFromSegment(useParams<{ proposalId: string }>().proposalId);
  const { parked, refreshKey, refresh } = useEvidenceRefresh();
  if (parked) return null;
  return <>
    <PageHeading eyebrow="LOCAL FIXTURE WORKSPACE" title="CSV review detail" description="Inspect the extraction and its provenance before recording a decision." />
    <p className="back-link"><a href="/review">← Review queue</a></p>
    <p><button type="button" onClick={refresh}>Refresh proposal</button></p>
    {id ? <EvidencePages key={`${id}:${refreshKey}`} id={id} refresh={refresh} />
      : <p role="alert">Proposal not found.</p>}
  </>;
}

function EvidencePages({ id, refresh }: { id: string; refresh: () => void }) {
  const [offset, setOffset] = useState(0);
  return <EvidenceSlice key={offset} id={id} offset={offset} setOffset={setOffset} refresh={refresh} />;
}

function EvidenceSlice({ id, offset, setOffset, refresh }: {
  id: string; offset: number; setOffset: (offset: number) => void; refresh: () => void;
}) {
  const path = `${apiBase}${reviewResource}/${encodeURIComponent(id)}`;
  const decode = useCallback((value: unknown) => parseDetail(value, id, offset), [id, offset]);
  const { data, loading, error } = useRemote(`${path}?offset=${offset}`, 0, decode);
  if (error) return <ReviewError error={error} />;
  const next = data?.next_evidence_offset;
  return <StateMessage loading={loading}>{data && <DecisionSnapshot data={data} path={path} offset={offset} refresh={refresh} pagination={<p>
    {offset > 0 && <button type="button" onClick={() => setOffset(0)}>First evidence page</button>}{' '}
    {typeof next === 'number' && <button type="button" onClick={() => setOffset(next)}>Next evidence page</button>}
  </p>} />}</StateMessage>;
}

function DecisionSnapshot({ data, path, offset, refresh, pagination }: {
  data: Detail; path: string; offset: number; refresh: () => void; pagination: React.ReactNode;
}) {
  const [choice, choose] = useState<ReviewDecision | null>(null);
  const [result, setResult] = useState<number | null>(null);
  const lifetime = useRef<AbortController | null>(null);
  const submitted = useRef(false);
  useLayoutEffect(() => {
    const controller = new AbortController();
    lifetime.current = controller;
    return () => { lifetime.current = null; controller.abort(); };
  }, []);

  const submit = async (decision: ReviewDecision) => {
    const signal = lifetime.current?.signal;
    if (!signal || signal.aborted || submitted.current || data.state !== 'proposed' || choice !== decision) return;
    submitted.current = true;
    choose(null);
    setResult(0);
    try {
      const response = await fetch(`${path}/decision`, {
        method: 'POST', mode: 'same-origin', credentials: 'same-origin', redirect: 'error', cache: 'no-store', signal,
        headers: { 'content-type': 'application/json', accept: 'application/json' }, body: JSON.stringify({ decision }),
      });
      if (signal.aborted) return;
      if (response.status !== 200) { setResult(response.status); return; }
      parseDecision(await response.json(), data.id, decision);
      if (!signal.aborted) refresh(); // Never substitute the acknowledgement for a fresh authorized detail read.
    } catch {
      if (!signal.aborted) setResult(502);
    }
  };

  if (result === 0) return <p role="status">Recording decision and checking current state…</p>;
  if (result === 409) return <p role="alert">This proposal already changed. Refresh the proposal to see its current state.</p>;
  if (result === 401 || result === 403 || result === 404) return <ReviewError error={Object.assign(new Error(), { status: result })} />;
  if (result !== null) return <p role="alert">The decision could not be confirmed. Refresh the proposal before taking further action.</p>;
  return <ReviewDetailView data={data} offset={offset} pagination={pagination}
    actions={<ReviewConfirmation choice={choice} choose={choose} submit={submit} />} />;
}
