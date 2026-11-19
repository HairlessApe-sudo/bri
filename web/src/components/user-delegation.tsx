'use client';

import { useState, type FormEvent } from 'react';
import { DirectoryDetail } from '@/components/user-directory-view';
import type { DirectoryUser } from '@/lib/api';
import { createDelegationFlow, delegationPermissions, initialDelegationView,
  type DelegationNode, type DelegationTransport, type DelegationView } from '@/lib/user-delegation';

type Flow = ReturnType<typeof createDelegationFlow>;

export function DelegationPanel({ view, nodes, flow }: {
  view: DelegationView; nodes: readonly DelegationNode[]; flow: Flow;
}) {
  const { node, permission, state, phase, action, error } = view;
  const busy = phase === 'loading' || phase === 'saving';
  const nextAction = phase === 'ready' && state ? (state.granted ? 'revoke' : 'grant') : null;

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (action && nextAction === action) {
      void flow.submit(action, new FormData(event.currentTarget).get('confirm') === 'yes');
    }
  }

  return <section aria-label="Permission delegation">
    <h3>Permission delegation</h3>
    <div className="auth-form directory-create">
      <label>Exact organisation node
        <select name="node" value={node} disabled={busy} onChange={(event) => flow.choose(event.target.value, permission)}>
          <option value="">Select a node</option>
          {nodes.map(({ id, label }) => <option value={id} key={id}>{label} ({id})</option>)}
        </select>
      </label>
      <label>Read permission
        <select name="permission" value={permission} disabled={busy} onChange={(event) => flow.choose(node, event.target.value)}>
          <option value="">Select a permission</option>
          {Object.entries(delegationPermissions).map(([value, label]) => <option value={value} key={value}>{label}</option>)}
        </select>
      </label>
      <button type="button" className="source-pill" disabled={busy || !node || !permission} onClick={() => void flow.refresh()}>
        {phase === 'idle' ? 'Load grant state' : 'Reload grant state'}
      </button>
    </div>
    <div aria-live="polite">
      {state && <p>{phase === 'ready' ? 'Grant state' : 'Last confirmed grant state'}: {state.granted ? 'Granted' : 'Not granted'}</p>}
      {busy && <p role="status">{phase === 'loading' ? 'Loading grant state…' : 'Waiting for the server to confirm the change…'}</p>}
    </div>
    {error && <p className="auth-error" role="alert">{error}</p>}
    {nextAction && !action && <button type="button" className="source-pill" onClick={() => flow.select(nextAction)}>
      {nextAction === 'grant' ? 'Grant' : 'Revoke'}
    </button>}
    {nextAction && action === nextAction && permission && <form key={action} className="auth-form directory-create" method="post" onSubmit={submit}>
      <label className="lifecycle-confirm">
        <input type="checkbox" name="confirm" value="yes" required />
        I confirm that I want to {action} {delegationPermissions[permission]} on node {node} for this user.
      </label>
      <button type="submit" className="auth-submit">Confirm {action}</button>
      <button type="button" className="source-pill" onClick={() => flow.select(null)}>Cancel</button>
    </form>}
  </section>;
}

function StagedDelegation({ id, nodes, transport }: { id: string; nodes: readonly DelegationNode[]; transport: DelegationTransport }) {
  const [view, show] = useState(initialDelegationView);
  const [flow] = useState(() => createDelegationFlow(id, nodes, transport, show));
  return <DelegationPanel view={view} nodes={nodes} flow={flow} />;
}

// Local/test harness only. The release directory never imports this entry point.
export function StagedDelegationDetail({ data, onBack, nodes, transport }: {
  data: DirectoryUser; onBack: () => void; nodes: readonly DelegationNode[]; transport: DelegationTransport;
}) {
  return <DirectoryDetail data={data} onBack={onBack}
    delegation={<StagedDelegation key={data.id} id={data.id} nodes={nodes} transport={transport} />} />;
}
