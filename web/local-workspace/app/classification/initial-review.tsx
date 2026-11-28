'use client';

import { createContext, useCallback, useContext, useState, type FormEvent, type ReactNode } from 'react';
import { useAuthorizedRead } from '../xlsx/read';
import { decideInitialMetadata, readInitialMetadata, readSelection, type MetadataInput } from './client.mjs';
import { MetadataError, MetadataFields, MetadataValues, readMetadataForm, useAction } from './fields';

type ReviewContext = { format: 'csv' | 'xlsx'; job: string; node: string; refresh: () => void; block: (status: number) => void };
type InitialReviewContext = ReviewContext & { legacy: ReactNode };
const MetadataReviewRequired = createContext(true);

export function ReviewMetadataMode({ required, children }: { required: boolean; children: ReactNode }) {
  return <MetadataReviewRequired.Provider value={required}>{children}</MetadataReviewRequired.Provider>;
}

export function InitialMetadataReview(props: InitialReviewContext) {
  return useContext(MetadataReviewRequired) ? <DiscoverInitialMetadata {...props} /> : props.legacy;
}

function DiscoverInitialMetadata({ format, job, node, refresh, block, legacy }: InitialReviewContext) {
  const load = useCallback(async (signal: AbortSignal) => {
    const receipt = await readInitialMetadata(fetch, format, job, signal);
    if (receipt.node_id !== node) throw new Error('Unmatched proposal scope');
    return receipt;
  }, [format, job, node]);
  const state = useAuthorizedRead(load);
  if (!state) return <p role="status">Checking proposed classification…</p>;
  if (!state.data) return <MetadataError status={state.error ?? 502} />;
  return state.data.proposed_metadata ? <ClassifiedDecision format={format} job={job} node={node} refresh={refresh} block={block}
    proposed={state.data.proposed_metadata} /> : <>
    <section className="content-panel" aria-label="Proposed classification"><h2>Proposed classification</h2><p>No classification was submitted with this legacy proposal.</p></section>
    {legacy}
  </>;
}

function ClassifiedDecision({ format, job, node, refresh, block, proposed }: ReviewContext & { proposed: MetadataInput }) {
  const load = useCallback((signal: AbortSignal) => readSelection(fetch, `${format}_review`, node, signal), [format, node]);
  const active = useAuthorizedRead(load);
  const { action, run } = useAction<Awaited<ReturnType<typeof decideInitialMetadata>>>();
  const [choice, choose] = useState<'approve' | 'replace' | 'reject' | null>(null);
  const [invalid, setInvalid] = useState(false);
  const options = active?.data;
  const noLongerSelectable = options ? [proposed.primary_classification_id, ...proposed.additional_classification_ids]
    .filter((id) => !options.some((row) => row.classification_id === id)) : [];
  const approveOriginal = !!options && !noLongerSelectable.length;
  function confirm(decision: 'approve' | 'reject', replacement: MetadataInput | null) {
    if (decision === 'approve' && (replacement === null ? choice !== 'approve' || !approveOriginal : choice !== 'replace' || !options?.length)) return;
    if (decision === 'reject' && (choice !== 'reject' || replacement !== null)) return;
    void run(async (signal) => {
      try { return await decideInitialMetadata(fetch, format, job, decision, crypto.randomUUID(), replacement, signal); }
      catch (err) { if (!signal.aborted) block((err as { status?: number }).status ?? 502); throw err; }
    }, refresh);
  }
  function correct(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!options?.length) return;
    try { confirm('approve', readMetadataForm(event.currentTarget, options)); }
    catch { setInvalid(true); }
  }
  function cancel() { choose(null); setInvalid(false); }
  if (action && 'error' in action) return <MetadataError status={action.error} retry />;
  if (action) return <p role="status">Recording decision and checking current state…</p>;
  return <>
    <section className="content-panel" aria-label="Proposed classification">
      <h2>Proposed classification</h2>
      <p>The submitter’s metadata is shown here as proposed, not yet validated.</p>
      <MetadataValues metadata={proposed} classes={options} />
      {!active && <p role="status">Checking active classifications…</p>}
      {active && !options && <MetadataError status={active.error ?? 502} />}
      {noLongerSelectable.length > 0 && <p role="alert">No longer selectable: {noLongerSelectable.join(', ')}. To approve, select active classifications.</p>}
    </section>
    <section className="content-panel" aria-label="Review decision">
      <h2>Review decision</h2>
      <p>Approval validates the metadata with the evidence in one decision. It does not publish the record or grant access.</p>
      {!choice ? <>
        <button type="button" disabled={!approveOriginal} onClick={() => choose('approve')}>Approve as proposed…</button>{' '}
        <button type="button" disabled={!options?.length} onClick={() => choose('replace')}>Correct and approve…</button>{' '}
        <button type="button" onClick={() => choose('reject')}>Reject…</button>
      </> : choice === 'replace' && options?.length ? <form onSubmit={correct}>
        <MetadataFields initial={proposed} options={options} legend="Metadata to validate at approval" />
        {invalid && <p role="alert">Check the fields, text lengths and classification selections.</p>}
        <button type="submit">Confirm corrected approval</button>{' '}<button type="button" onClick={cancel}>Cancel</button>
      </form> : choice !== 'replace' && <fieldset>
        <legend>Record the decision for this proposal?</legend>
        <button type="button" onClick={() => confirm(choice, null)}>{choice === 'approve' ? 'Confirm approval' : 'Confirm rejection'}</button>{' '}
        <button type="button" onClick={cancel}>Cancel</button>
      </fieldset>}
    </section>
  </>;
}
