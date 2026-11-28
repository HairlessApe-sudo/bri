'use client';

import { useCallback, useState } from 'react';
import { PageButtons, useAuthorizedRead } from '../xlsx/read';
import { decideCorrection, readCorrections, readValidatedMetadata, type Correction } from './client.mjs';
import { MetadataError, MetadataValues, statusOf, useAction } from './fields';
import { ProposeCorrection } from './propose';

export type ExactTarget = { format: 'csv' | 'xlsx'; record: string; version: string };
type Scope = ExactTarget & { refresh: () => void };
type ReviewScope = Scope & { revision: string; block: (status: number) => void };

export function ExactMetadata({ format, record, version, refresh }: Scope) {
  const load = useCallback((signal: AbortSignal) => readValidatedMetadata(fetch, format, record, version, signal), [format, record, version]);
  const state = useAuthorizedRead(load);
  const [open, setOpen] = useState<'propose' | 'review' | null>(null);
  const [recovery, block] = useState<number | null>(null);
  return <section className="content-panel" aria-label="Validated metadata">
    <h2>Validated metadata</h2>
    {recovery !== null ? <><MetadataError status={recovery} retry />
      <button type="button" onClick={refresh}>Refresh exact-version metadata</button></>
      : !state ? <p role="status">Checking exact-version metadata…</p> : !state.data ? <MetadataError status={state.error ?? 502} /> : <>
      {state.data.metadata ? <MetadataValues metadata={state.data.metadata} /> : <p>This source version has no validated classification.</p>}
      <p>Metadata changes do not change the source evidence, publication, or access to this record.</p>
      {!open ? <p><button type="button" onClick={() => setOpen('propose')}>Propose a metadata correction…</button>{' '}
        <button type="button" onClick={() => setOpen('review')}>Inspect pending metadata corrections</button></p> : <>
        {open === 'propose' ? <ProposeCorrection format={format} record={record} version={version} metadata={state.data.metadata} block={block} />
          : <Corrections format={format} record={record} version={version} revision={state.data.metadata?.revision ?? '0'} refresh={refresh} block={block} />}
        <p><button type="button" onClick={() => setOpen(null)}>Close corrections</button></p>
      </>}
    </>}
  </section>;
}

function Corrections(props: ReviewScope) {
  const [after, visit] = useState<string | null>(null);
  return <CorrectionPage key={after ?? ''} {...props} after={after} visit={visit} />;
}

function CorrectionPage({ format, record, version, revision, after, visit, refresh, block }: ReviewScope & {
  after: string | null; visit: (after: string | null) => void;
}) {
  const load = useCallback((signal: AbortSignal) => readCorrections(fetch, format, record, version, after, signal), [format, record, version, after]);
  const page = useAuthorizedRead(load);
  const { action, run } = useAction<Awaited<ReturnType<typeof decideCorrection>>>();
  const [choice, choose] = useState<{ item: Correction; action: 'approve' | 'reject' } | null>(null);
  if (action && 'error' in action) return <MetadataError status={action.error} retry />;
  if (action) return <p role="status">Recording correction decision and checking current metadata…</p>;
  if (!page) return <p role="status">Checking access to pending corrections…</p>;
  if (!page.data) return <MetadataError status={page.error ?? 502} />;
  function confirm() {
    if (!choice || choice.item.expected_revision !== revision) return;
    void run(async (signal) => {
      try { return await decideCorrection(fetch, format, record, version, choice.item, choice.action, crypto.randomUUID(), signal); }
      catch (error) { if (!signal.aborted) block(statusOf(error)); throw error; }
    }, refresh);
  }
  return <div>
    <h3>Pending metadata corrections</h3>
    {!page.data.items.length && <p>No pending corrections are available to this session.</p>}
    {page.data.items.map((item) => <article key={item.proposal_id} className="content-panel" aria-label="Pending metadata correction">
      <p>Proposal <code className="breakable">{item.proposal_id}</code> · expected revision <code>{item.expected_revision}</code></p>
      <MetadataValues metadata={item.proposed_metadata} />
      {item.expected_revision !== revision && <p role="alert">The current revision does not match this proposal. Refresh before deciding.</p>}
      {choice?.item === item ? <fieldset>
        <legend>{choice.action === 'approve' ? 'Apply this correction to validated metadata?' : 'Reject this proposed correction?'}</legend>
        <button type="button" disabled={item.expected_revision !== revision} onClick={confirm}>{choice.action === 'approve' ? 'Confirm metadata correction approval' : 'Confirm metadata correction rejection'}</button>{' '}
        <button type="button" onClick={() => choose(null)}>Cancel</button>
      </fieldset> : !choice && <p>
        <button type="button" disabled={item.expected_revision !== revision} onClick={() => choose({ item, action: 'approve' })}>Approve metadata correction…</button>{' '}
        <button type="button" disabled={item.expected_revision !== revision} onClick={() => choose({ item, action: 'reject' })}>Reject metadata correction…</button>
      </p>}
    </article>)}
    {page.data.items.some((item) => item.expected_revision !== revision) &&
      <p><button type="button" onClick={refresh}>Refresh exact-version metadata</button></p>}
    {!choice && <PageButtons cursor={after} next={page.data.next_after} visit={visit} noun="correction" />}
  </div>;
}
