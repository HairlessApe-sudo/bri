'use client';

import { useMemo, useSyncExternalStore, type FormEvent } from 'react';
import { DirectoryDetail } from '@/components/user-directory-view';
import type { DirectoryUser } from '@/lib/api';
import { createDeactivationFlow, deactivationReasons, type DeactivationTransport, type DeactivationView } from '@/lib/user-deactivation';

type Flow = ReturnType<typeof createDeactivationFlow>;
const statusLabels = { active: 'Active', suspended: 'Suspended', deactivated: 'Deactivated' };

export function DeactivationPanel({ id, view, flow }: { id: string; view: DeactivationView; flow: Flow }) {
  const { phase, state, reason, reviewing, error } = view;
  const busy = phase === 'loading' || phase === 'saving';
  const canDeactivate = phase === 'ready' && state && state.status !== 'deactivated';

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void flow.submit(new FormData(event.currentTarget).get('confirm') === 'yes');
  }

  return <section aria-label="Account deactivation">
    <h3>Account deactivation</h3>
    <p className="auth-error"><span><strong>Permanent in ordinary account management.</strong>{' '}
      Deactivation ends this account’s BRI access and cannot be reversed through ordinary account management.
      It is not suspension and is not deletion: identity and business records are retained.</span></p>
    <p>Deactivation requires a recent verified TOTP challenge.</p>
    <button type="button" className="source-pill" disabled={busy} onClick={() => void flow.reload()}>
      {phase === 'idle' ? 'Load deactivation state' : 'Reload deactivation state'}
    </button>
    <div aria-live="polite">
      {state && <p>{phase === 'ready' ? 'Deactivation state' : 'Last confirmed deactivation state'}: {statusLabels[state.status]}</p>}
      {busy && <p>{phase === 'loading' ? 'Loading deactivation state…' : 'Waiting for the server to confirm deactivation…'}</p>}
    </div>
    {error && <p className="auth-error" role="alert">{error}</p>}
    {canDeactivate && !reviewing && <div className="auth-form directory-create">
      <label>Deactivation reason
        <select name="reason" value={reason} required onChange={(event) => flow.chooseReason(event.currentTarget.value)}>
          <option value="">Select a reason</option>
          {Object.entries(deactivationReasons).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select>
      </label>
      <button type="button" className="source-pill" disabled={!reason} onClick={flow.review}>Review deactivation</button>
    </div>}
    {canDeactivate && reviewing && reason && <form className="auth-form directory-create" method="post" onSubmit={submit}>
      <p>Account <span className="mono breakable">{id}</span> · Reason: {deactivationReasons[reason]}</p>
      <label className="lifecycle-confirm">
        <input type="checkbox" name="confirm" value="yes" required />
        I confirm that I want to deactivate this account and understand that ordinary account management cannot reverse it.
      </label>
      <button type="submit" className="auth-submit">Confirm deactivation</button>
      <button type="button" className="source-pill" onClick={flow.cancelReview}>Cancel review</button>
    </form>}
  </section>;
}

// Local/test harness only. The release directory never imports this entry point.
export function StagedDeactivationDetail({ data, onBack, transport }: {
  data: DirectoryUser; onBack: () => void; transport: DeactivationTransport;
}) {
  const { id } = data;
  // A new target or transport starts empty. Late replies can only update their original store.
  const flow = useMemo(() => createDeactivationFlow(id, transport), [id, transport]);
  const view = useSyncExternalStore(flow.subscribe, flow.getSnapshot, flow.getSnapshot);
  const account = view.state ? { ...data, status: view.state.status } : data;
  return <DirectoryDetail data={account} onBack={onBack}
    deactivation={<DeactivationPanel id={id} view={view} flow={flow} />} />;
}
