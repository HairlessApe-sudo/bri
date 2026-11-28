'use client';

import { useLayoutEffect, useRef, useState } from 'react';
import { metadataInput, type CatalogueEntry, type MetadataInput, type ValidatedMetadata } from './client.mjs';

export const statusOf = (error: unknown) => (error as { status?: number } | null)?.status ?? 502;

export function MetadataError({ status, retry = false }: { status: number; retry?: boolean }) {
  const message = status === 401 ? 'A current signed fixture session is required.'
    : status === 403 ? 'Access denied.'
    : status === 404 ? 'This target was not found or is not available to this session.'
    : status === 409 ? 'The state changed. Refresh to inspect the current state before trying again.'
    : status === 422 ? 'The request was not accepted. Check the inputs and refresh before trying again.'
    : retry ? 'The change could not be confirmed. Refresh before trying again.' : 'Classification information is unavailable.';
  return <p className="state-message" role="alert">{message}</p>;
}

export function useAction<T>() {
  const lifetime = useRef<AbortController | null>(null);
  const sent = useRef(false);
  const [action, setAction] = useState<{ pending: true } | { result: T } | { error: number } | null>(null);
  useLayoutEffect(() => {
    const controller = new AbortController();
    lifetime.current = controller;
    return () => { lifetime.current = null; controller.abort(); };
  }, []);
  async function run(load: (signal: AbortSignal) => Promise<T>, success?: (value: T) => void) {
    const signal = lifetime.current?.signal;
    if (sent.current || !signal || signal.aborted) return;
    sent.current = true;
    setAction({ pending: true });
    try {
      const result = await load(signal);
      if (!signal.aborted) { setAction({ result }); success?.(result); }
    } catch (error) {
      if (!signal.aborted) setAction({ error: statusOf(error) });
    }
  }
  return { action, run };
}

type Selectable = CatalogueEntry & { retired?: boolean };
const selectable = (row: Selectable) => row.retired !== true;

export function readMetadataForm(form: HTMLFormElement, options: Selectable[]) {
  const data = new FormData(form);
  const string = (name: string) => String(data.get(name) ?? '');
  const value = metadataInput({ version: 1, title: string('title'), description: string('description') || null,
    primary_classification_id: string('primary'), additional_classification_ids: data.getAll('additional').map(String).filter(Boolean),
    effective_date: string('effective') || null, review_date: string('review') || null, expiry_date: string('expiry') || null });
  if (![value.primary_classification_id, ...value.additional_classification_ids].every((id) => options.some((row) => selectable(row) && row.classification_id === id))) {
    throw new Error('Select an active classification.');
  }
  return value;
}

function classLabel(row: CatalogueEntry) { return `${row.category_label} · ${row.label} (${row.classification_id})`; }

export function MetadataFields({ options: available, initial, legend = 'Proposed metadata' }: {
  options: Selectable[]; initial?: MetadataInput; legend?: string;
}) {
  const options = available.filter(selectable);
  const active = new Set(options.map((row) => row.classification_id));
  const [primary, setPrimary] = useState(initial && active.has(initial.primary_classification_id) ? initial.primary_classification_id : '');
  const [extra, setExtra] = useState((initial?.additional_classification_ids ?? []).filter((id) => active.has(id)));
  return <fieldset>
    <legend>{legend}</legend>
    <p><label>Primary classification <select name="primary" required value={primary} onChange={(event) => {
      setPrimary(event.target.value); setExtra((current) => current.filter((id) => id !== event.target.value));
    }}>
      <option value="">Select an active classification</option>
      {options.map((row) => <option key={row.classification_id} value={row.classification_id}>{classLabel(row)}</option>)}
    </select></label></p>
    <p><label>Additional classifications (optional, up to eight)<br />
      <select name="additional" multiple size={Math.min(Math.max(options.length, 2), 6)} value={extra} onChange={(event) => {
        setExtra(Array.from(event.target.selectedOptions, (option) => option.value));
      }}>
        {options.map((row) => <option key={row.classification_id} value={row.classification_id} disabled={row.classification_id === primary}>{classLabel(row)}</option>)}
      </select></label></p>
    <p><label>Title <input name="title" required maxLength={160} defaultValue={initial?.title} autoComplete="off" /></label></p>
    <p><label>Description (optional)<br /><textarea name="description" maxLength={2048} defaultValue={initial?.description ?? ''} autoComplete="off" /></label></p>
    <p><label>Effective date <input name="effective" type="date" defaultValue={initial?.effective_date ?? ''} /></label>{' '}
      <label>Review date <input name="review" type="date" defaultValue={initial?.review_date ?? ''} /></label>{' '}
      <label>Expiry date <input name="expiry" type="date" defaultValue={initial?.expiry_date ?? ''} /></label></p>
    <p>Dates are descriptive only; they do not change publication, access, retention, or disposition.</p>
  </fieldset>;
}

type ClassText = { classification_id: string; label?: string; retired?: boolean };
export function MetadataValues({ metadata, classes }: {
  metadata: MetadataInput | ValidatedMetadata; classes?: ClassText[];
}) {
  const label = (id: string) => classes?.find((row) => row.classification_id === id) ?? { classification_id: id };
  const render = (row: ClassText) => <>{row.label && <>{row.label} · </>}<code>{row.classification_id}</code>{row.retired && ' (retired)'}</>;
  const primary = 'primary_classification' in metadata ? metadata.primary_classification : label(metadata.primary_classification_id);
  const additional = 'additional_classifications' in metadata ? metadata.additional_classifications : metadata.additional_classification_ids.map(label);
  return <dl className="provenance-grid">
    <div><dt>Title</dt><dd className="breakable">{metadata.title}</dd></div>
    <div><dt>Primary classification</dt><dd className="breakable">{render(primary)}</dd></div>
    <div><dt>Additional classifications</dt><dd>{additional.length ? <ul>{additional.map((row) => <li key={row.classification_id}>{render(row)}</li>)}</ul> : 'None'}</dd></div>
    <div><dt>Description</dt><dd className="breakable">{metadata.description ?? 'Not set'}</dd></div>
    <div><dt>Effective date</dt><dd>{metadata.effective_date ?? 'Not set'}</dd></div>
    <div><dt>Review date</dt><dd>{metadata.review_date ?? 'Not set'}</dd></div>
    <div><dt>Expiry date</dt><dd>{metadata.expiry_date ?? 'Not set'}</dd></div>
    {'revision' in metadata && <><div><dt>Metadata revision</dt><dd><code>{metadata.revision}</code></dd></div>
      <div><dt>Responsible node</dt><dd className="breakable"><code>{metadata.responsible_node_id}</code></dd></div></>}
  </dl>;
}
