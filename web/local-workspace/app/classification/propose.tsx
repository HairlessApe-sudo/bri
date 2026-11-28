'use client';

import { useState, type FormEvent } from 'react';
import { metadataInput, proposeCorrection, type MetadataInput, type ValidatedMetadata } from './client.mjs';
import { MetadataError, MetadataValues, statusOf, useAction } from './fields';
import type { ExactTarget } from './exact';

export function ProposeCorrection({ format, record, version, metadata, block }: ExactTarget & {
  metadata: ValidatedMetadata | null; block: (status: number) => void;
}) {
  const revision = metadata?.revision ?? '0';
  const { action, run } = useAction<Awaited<ReturnType<typeof proposeCorrection>>>();
  const [draft, setDraft] = useState<MetadataInput | null>(null);
  const [invalid, setInvalid] = useState(false);
  const known = metadata ? [metadata.primary_classification, ...metadata.additional_classifications] : [];
  const retired = new Set(known.filter((row) => row.retired).map((row) => row.classification_id));
  const activePrimary = metadata?.primary_classification.retired === false ? metadata.primary_classification.classification_id : '';
  const activeAdditional = metadata?.additional_classifications.filter((row) => !row.retired).map((row) => row.classification_id) ?? [];

  function inspect(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const field = (key: string) => String(form.get(key) ?? '');
    try {
      const input = metadataInput({ version: 1, primary_classification_id: field('primary'),
        additional_classification_ids: field('additional') ? field('additional').split(',').map((item) => item.trim()) : [],
        title: field('title'), description: field('description') || null, effective_date: field('effective') || null,
        review_date: field('review') || null, expiry_date: field('expiry') || null });
      if ([input.primary_classification_id, ...input.additional_classification_ids].some((id) => retired.has(id))) throw new Error('Retired classification');
      setInvalid(false); setDraft(input);
    } catch { setInvalid(true); }
  }
  function confirm() {
    if (!draft) return;
    const input = draft;
    setDraft(null);
    void run(async (signal) => {
      try { return await proposeCorrection(fetch, format, record, version, revision, crypto.randomUUID(), input, signal); }
      catch (error) { if (!signal.aborted) block(statusOf(error)); throw error; }
    });
  }

  if (action && 'error' in action) return <MetadataError status={action.error} retry />;
  if (action && 'pending' in action) return <p role="status">Submitting the exact-version metadata correction…</p>;
  if (action && 'result' in action) return <p role="status">Correction proposed: <code>{action.result.proposal_id}</code>. Validated metadata is unchanged pending independent review.</p>;
  return <div>
    <h3>Propose a metadata correction</h3>
    <p>Expected metadata revision: <code>{revision}</code>. This operation requires separate permission for this exact source version and does not apply the proposed change.</p>
    <form onSubmit={inspect} hidden={draft !== null}>
      <fieldset>
        <legend>Proposed replacement metadata</legend>
        <p>Enter known active classification IDs. This form does not list the tenant catalogue; the server checks whether each ID is selectable for this correction.</p>
        <p><label>Primary classification ID <input name="primary" required pattern="[a-z0-9][a-z0-9_.\-]{0,63}" maxLength={64} defaultValue={activePrimary} autoComplete="off" /></label></p>
        <p><label>Additional classification IDs (optional, up to eight, separated by commas)<br />
          <input name="additional" maxLength={526} defaultValue={activeAdditional.join(', ')} autoComplete="off" /></label></p>
        <p><label>Title <input name="title" required maxLength={160} defaultValue={metadata?.title} autoComplete="off" /></label></p>
        <p><label>Description (optional)<br /><textarea name="description" maxLength={2048} defaultValue={metadata?.description ?? ''} autoComplete="off" /></label></p>
        <p><label>Effective date <input name="effective" type="date" defaultValue={metadata?.effective_date ?? ''} /></label>{' '}
          <label>Review date <input name="review" type="date" defaultValue={metadata?.review_date ?? ''} /></label>{' '}
          <label>Expiry date <input name="expiry" type="date" defaultValue={metadata?.expiry_date ?? ''} /></label></p>
        {invalid && <p role="alert">Check the fields, text lengths and active classification IDs.</p>}
        <button type="submit">Inspect correction before submitting</button>
      </fieldset>
    </form>
    {draft && <fieldset>
      <legend>Submit this proposal for independent review?</legend>
      <MetadataValues metadata={draft} classes={known} />
      <button type="button" onClick={confirm}>Confirm metadata correction proposal</button>{' '}
      <button type="button" onClick={() => setDraft(null)}>Edit proposal</button>
    </fieldset>}
  </div>;
}
