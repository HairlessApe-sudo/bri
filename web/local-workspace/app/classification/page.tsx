'use client';

import type { FormEvent } from 'react';
import { useState } from 'react';
import { PageHeading } from '@/components/data-state';
import { useEvidenceRefresh } from '../refresh';
import { useAuthorizedRead } from '../xlsx/read';
import { readAdminCatalogue, writeCatalogue } from './client.mjs';
import { MetadataError, useAction } from './fields';

type Operation = 'seed' | 'create' | 'rename' | 'describe' | 'retire';
const labels: Record<Operation, string> = { seed: 'Provision starter catalogue', create: 'Create classification',
  rename: 'Rename classification', describe: 'Set classification description', retire: 'Retire classification' };
const load = (signal: AbortSignal) => readAdminCatalogue(fetch, signal);

export default function CataloguePage() {
  const { parked, refreshKey, refresh } = useEvidenceRefresh();
  return parked ? null : <>
    <PageHeading eyebrow="LOCAL FIXTURE WORKSPACE" title="Classification catalogue" description="Manage the tenant’s classification labels. This does not grant access to knowledge." />
    <p><button type="button" onClick={refresh}>Refresh catalogue</button></p>
    <CatalogueSnapshot key={refreshKey} refresh={refresh} />
  </>;
}

function CatalogueSnapshot({ refresh }: { refresh: () => void }) {
  const state = useAuthorizedRead(load);
  const { action, run } = useAction<void>();
  const [operation, choose] = useState<Operation | null>(null);
  if (action && 'error' in action) return <MetadataError status={action.error} retry />;
  if (action) return <p role="status">Checking the current catalogue…</p>;
  if (!state) return <p role="status">Loading classification catalogue…</p>;
  if (!state.data) return <MetadataError status={state.error ?? 502} />;
  const rows = state.data;
  const categories = [...new Map(rows.map((row) => [row.category_id, row.category_label]))];
  const active = rows.filter((row) => !row.retired);
  function submit(event: FormEvent<HTMLFormElement>, op: Operation) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    const id = String(form.get('classification') ?? '');
    const category_id = String(form.get('category') ?? '');
    const label = String(form.get('label') ?? '');
    const description = String(form.get('description') ?? '') || null;
    if (['rename', 'describe', 'retire'].includes(op) && !active.some((row) => row.classification_id === id)) return;
    if (op === 'create' && !categories.some(([value]) => value === category_id)) return;
    const payload = op === 'seed' ? {} : op === 'create' ? { category_id, classification_id: id, label, description }
      : op === 'rename' ? { classification_id: id, label } : op === 'describe' ? { classification_id: id, description } : { classification_id: id };
    void run((signal) => writeCatalogue(fetch, op, payload, signal), refresh);
  }
  return <>
    {rows.length ? <div className="table-wrap"><table aria-label="Tenant catalogue">
      <thead><tr><th scope="col">Category</th><th scope="col">Classification</th><th scope="col">Description</th><th scope="col">State</th></tr></thead>
      <tbody>{rows.map((row) => <tr key={row.classification_id}><td>{row.category_label}</td><td><strong>{row.label}</strong><br /><code className="breakable">{row.classification_id}</code></td>
        <td className="breakable">{row.description ?? '—'}</td><td>{row.retired ? 'Retired' : 'Active'}</td></tr>)}</tbody>
    </table></div> : <p>The catalogue is empty.</p>}
    <section className="content-panel" aria-label="Catalogue maintenance">
      <h2>Catalogue maintenance</h2>
      {!operation ? <p>{(Object.keys(labels) as Operation[]).filter((op) => op === 'seed'
        || (op === 'create' ? categories.length > 0 : active.length > 0)).map((op) => <span key={op}>
        <button type="button" onClick={() => choose(op)}>{labels[op]}…</button>{' '}</span>)}</p>
        : <form key={operation} onSubmit={(event) => submit(event, operation)}><fieldset>
          <legend>{labels[operation]}</legend>
          {operation === 'seed' && <p>This provisions the starter entries without undoing edits or retirement.</p>}
          {operation === 'create' && <>
            <p><label>Category <select name="category" required><option value="">Select a category</option>
              {categories.map(([id, label]) => <option key={id} value={id}>{label}</option>)}</select></label></p>
            <p><label>Stable classification ID <input name="classification" required pattern="[a-z0-9][a-z0-9_.\-]{0,63}" maxLength={64} autoComplete="off" /></label></p>
          </>}
          {['rename', 'describe', 'retire'].includes(operation) && <p><label>Classification <select name="classification" required>
            <option value="">Select a classification</option>{active.map((row) => <option key={row.classification_id} value={row.classification_id}>{row.label} ({row.classification_id})</option>)}
          </select></label></p>}
          {['create', 'rename'].includes(operation) && <p><label>Label <input name="label" required maxLength={160} autoComplete="off" /></label></p>}
          {['create', 'describe'].includes(operation) && <p><label>Description (blank clears it)<br /><textarea name="description" maxLength={2048} autoComplete="off" /></label></p>}
          {operation === 'retire' && <p>Retired classifications remain in history but cannot be selected for new metadata.</p>}
          <button type="submit">{labels[operation]}</button>{' '}<button type="button" onClick={() => choose(null)}>Cancel</button>
        </fieldset></form>}
    </section>
  </>;
}
