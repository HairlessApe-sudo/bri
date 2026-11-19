'use client';

import { useEffect, useState, type FormEvent } from 'react';
import { DirectoryAccountFields, DirectoryDetail } from '@/components/user-directory-view';
import type { DirectoryUser } from '@/lib/api';
import {
  createLifecycleFlow, initialLifecycleView, lifecycleActions, lifecycleReasons, permittedLifecycleActions,
  type LifecycleTransport, type LifecycleView,
} from '@/lib/user-lifecycle';

type Flow = ReturnType<typeof createLifecycleFlow>;

export function LifecyclePanel({ view, flow }: { view: LifecycleView; flow: Flow }) {
  const { account, action, phase, error } = view;
  const busy = phase === 'idle' || phase === 'loading' || phase === 'saving';
  const allowed = account && phase === 'ready' ? permittedLifecycleActions(account) : [];
  const selected = action && allowed.includes(action) ? action : null;
  const label = selected ? lifecycleActions[selected].label : '';

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!selected) return;
    const fields = new FormData(event.currentTarget);
    const value = String(fields.get(selected === 'edit' ? 'display_name' : 'reason') ?? '');
    void flow.submit(selected, value, fields.get('confirm') === 'yes');
  }

  return <section aria-label="Account lifecycle">
    <div aria-live="polite">
      {account && <>
        {phase !== 'ready' && <p>Last confirmed account details</p>}
        <dl className="provenance-grid"><DirectoryAccountFields user={account} /></dl>
      </>}
      {busy && <p role="status">{phase === 'saving' ? 'Waiting for the server to confirm the change…' : 'Loading lifecycle…'}</p>}
    </div>
    {error && <p className="auth-error" role="alert">{error}</p>}
    {!busy && <div className="directory-pagination">
      <button type="button" className="source-pill" onClick={() => void flow.refresh()}>Refresh lifecycle</button>
      {!selected && allowed.map((choice) => <button key={choice} type="button" className="source-pill" onClick={() => flow.select(choice)}>
        {lifecycleActions[choice].label}
      </button>)}
    </div>}
    {phase === 'ready' && !allowed.length && <p role="status">No lifecycle changes are permitted for this account.</p>}
    {selected && <form key={selected} className="auth-form directory-create" aria-label={label} method="post" onSubmit={submit}>
      {selected === 'edit' ? <label>Display name
        <input name="display_name" type="text" defaultValue={account?.display_name ?? ''} autoComplete="off" required />
      </label> : <>
        <label>Reason for this change
          <select name="reason" required defaultValue="">
            <option value="" disabled>Select a reason</option>
            {Object.entries(lifecycleReasons[selected]).map(([value, text]) => <option value={value} key={value}>{text}</option>)}
          </select>
        </label>
        <label className="lifecycle-confirm"><input type="checkbox" name="confirm" value="yes" required />
          I confirm that I want to {label.toLowerCase()} this account.
        </label>
      </>}
      <button className="auth-submit" type="submit">{selected === 'edit' ? 'Save display name' : `Confirm ${label.toLowerCase()}`}</button>
      <button className="source-pill" type="button" onClick={() => flow.select(null)}>Cancel</button>
    </form>}
  </section>;
}

function StagedLifecycle({ id, transport }: { id: string; transport: LifecycleTransport }) {
  const [view, show] = useState(initialLifecycleView);
  const [flow] = useState(() => createLifecycleFlow(id, transport, show));
  useEffect(() => { void flow.refresh(); }, [flow]);
  return <LifecyclePanel view={view} flow={flow} />;
}

// Local harness only. The release UserDirectory never imports or supplies this panel.
export function StagedDirectoryDetail({ data, onBack, transport }: {
  data: DirectoryUser; onBack: () => void; transport: LifecycleTransport;
}) {
  return <DirectoryDetail data={data} onBack={onBack}
    lifecycle={<StagedLifecycle key={data.id} id={data.id} transport={transport} />} />;
}
