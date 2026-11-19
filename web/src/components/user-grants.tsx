'use client';

import { useEffect, useState } from 'react';
import { StateMessage } from '@/components/data-state';
import { accountClassLabels, accountStatusLabels, grantKey, permissionLabels, requestGrants, type AccountGrant, type GrantsState } from '@/lib/user-grants';

const failureLabels = {
  unauthenticated: 'Verified session required to view account grants.',
  denied: 'Access denied. You do not have permission to view account grants.',
  missing: 'Grants not found for this account.',
  error: 'Could not load account grants. Try again in a moment.',
};

function visibleScopeId(id: string) {
  // A nonempty identifier can consist entirely of whitespace.
  return id.trim() ? id : id.replace(/\s/g, (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`);
}

function GrantList({ title, rows, empty }: { title: string; rows: AccountGrant[]; empty: string }) {
  return <>
    <h4>{title}</h4>
    {rows.length ? <div className="table-wrap">
      <table aria-label={title}>
        <thead><tr><th scope="col">Scope</th><th scope="col">Scope ID</th><th scope="col">Permission</th></tr></thead>
        <tbody>{rows.map((grant) => <tr key={grantKey(grant)}>
          <td className="breakable">{grant.scope_name.trim() ? grant.scope_name : 'Unnamed scope'}</td>
          <td className="mono breakable">{visibleScopeId(grant.scope_id)}</td>
          <td>{permissionLabels[grant.permission]}</td>
        </tr>)}</tbody>
      </table>
    </div> : <p className="state-message" role="status">{empty}</p>}
  </>;
}

export function GrantsView({ state }: { state: GrantsState }) {
  if (state.phase === 'loading') return <StateMessage loading />;
  if (state.phase !== 'ready') {
    const denied = state.phase === 'unauthenticated' || state.phase === 'denied';
    return <p className={`state-message ${denied ? 'state-denied' : 'state-error'}`} role="alert">{failureLabels[state.phase]}</p>;
  }
  const { account_class, account_status, assigned, effective } = state.grants;
  const effectiveEmpty = account_status === 'active' ? 'No effective grants.'
    : `No effective grants while the account is ${account_status}.`;
  return <>
    <dl className="provenance-grid">
      <div><dt>Account class</dt><dd>{accountClassLabels[account_class]}</dd></div>
      <div><dt>Account status</dt><dd>{accountStatusLabels[account_status]}</dd></div>
    </dl>
    <p>Assigned grants are recorded for this account. Effective grants show which assigned permissions apply to the listed scopes under the account status shown here.</p>
    <p>This view does not determine whether the account can sign in or access any particular record or version.</p>
    <GrantList title="Assigned grants" rows={assigned} empty="No assigned grants." />
    <GrantList title="Effective grants" rows={effective} empty={effectiveEmpty} />
  </>;
}

function GrantsRequest({ accountId }: { accountId: string }) {
  const [state, setState] = useState<GrantsState>({ phase: 'loading' });
  useEffect(() => requestGrants(accountId, setState), [accountId]);
  return <GrantsView state={state} />;
}

export function UserGrants({ accountId }: { accountId: string }) {
  return <section aria-label="Account grants">
    <div className="panel-toolbar"><h3>Account grants</h3></div>
    <GrantsRequest key={accountId} accountId={accountId} />
  </section>;
}