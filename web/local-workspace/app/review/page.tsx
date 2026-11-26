'use client';

import { useCallback, useState } from 'react';
import { PageHeading, StateMessage, useRemote } from '@/components/data-state';
import { apiBase, useEvidenceRefresh } from '../refresh';
import { isReviewState, parseQueue, reviewResource, reviewStates, reviewDefaultLimit } from '../../review-contract.mjs';
import { labels, ReviewError, ReviewQueueView, type ReviewState } from './views';

export default function ReviewPage() {
  const { parked, refreshKey, refresh } = useEvidenceRefresh();
  const [status, setStatus] = useState<ReviewState>('proposed');
  if (parked) return null;
  return <>
    <PageHeading eyebrow="LOCAL FIXTURE WORKSPACE" title="CSV review queue" description="Review authorized CSV proposals and see completed reviews or processing failures." />
    <section className="content-panel" aria-label="Review queue">
      <div className="panel-toolbar">
        <label>State{' '}<select value={status} onChange={(event) => {
          if (isReviewState(event.target.value)) setStatus(event.target.value);
        }}>{reviewStates.map((value) => <option key={value} value={value}>{labels[value]}</option>)}</select></label>
        <button type="button" onClick={refresh}>Refresh queue</button>
      </div>
      <QueuePages key={`${status}:${refreshKey}`} status={status} />
    </section>
  </>;
}

function QueuePages({ status }: { status: ReviewState }) {
  const [after, setAfter] = useState<string | null>(null);
  return <QueueSlice key={after ?? ''} after={after} status={status} setAfter={setAfter} />;
}

function QueueSlice({ status, after, setAfter }: { status: ReviewState; after: string | null; setAfter: (after: string | null) => void }) {
  const params = new URLSearchParams({ status, limit: String(reviewDefaultLimit) });
  if (after) params.set('after', after);
  const decode = useCallback((value: unknown) => parseQueue(value, status, after, reviewDefaultLimit), [status, after]);
  const { data, error, loading } = useRemote(`${apiBase}${reviewResource}?${params}`, 0, decode);
  if (error) return <ReviewError error={error} />;
  const next = data?.next_cursor;
  return <StateMessage loading={loading}>{data && <>
    <ReviewQueueView data={data} />
    {(after || next) && <p>
      {after && <button type="button" onClick={() => setAfter(null)}>First page</button>}{' '}
      {next && <button type="button" onClick={() => setAfter(next)}>Next page</button>}
    </p>}
  </>}</StateMessage>;
}
