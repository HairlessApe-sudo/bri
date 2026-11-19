import type { ReactNode } from 'react';
import { DisabledCreateUser } from '@/components/create-user-fields';
import { StateMessage } from '@/components/data-state';
import type { DirectoryUser, DirectoryUserPage } from '@/lib/api';
import { DIRECTORY_MAX_OFFSET, DIRECTORY_PAGE_SIZE } from '@/lib/user-directory.mjs';

type Remote<T> = { data?: T | null; error?: Error | null; loading?: boolean };
const statusLabels = { pending: 'Pending', active: 'Active', suspended: 'Suspended', deactivated: 'Deactivated' };
const roleLabels = { user: 'User', superuser: 'Superuser' };
const mfaLabels = { verified: 'Verified', unknown: 'Unknown' };
const userName = (user: Pick<DirectoryUser, 'display_name'>) => user.display_name?.trim() || 'Unnamed user';

function DirectoryError({ error, detail = false }: { error: Error; detail?: boolean }) {
  const { status } = error as Error & { status?: number };
  const denied = status === 401 || status === 403;
  const [title, description] = status === 401 ? ['Verified session required', 'Sign in again to access the user directory.']
    : status === 403 ? ['Access denied', 'Your account does not have permission to view the user directory.']
    : status === 404 && detail ? ['User not found', 'This user is not available in your directory.']
    : ['Could not load the directory', 'Try again in a moment.'];
  return <div className={`state-message ${denied ? 'state-denied' : 'state-error'}`} role="alert">
    <strong>{title}</strong><span>{description}</span>
  </div>;
}

export function DirectoryList({ data, error, loading, offset, onPage, onSelect }: Remote<DirectoryUserPage> & {
  offset: number; onPage: (offset: number) => void; onSelect: (id: string) => void;
}) {
  const atLimit = offset + DIRECTORY_PAGE_SIZE > DIRECTORY_MAX_OFFSET;
  return <>
    {error ? <DirectoryError error={error} /> : <StateMessage loading={loading}>
      {data && (data.items.length ? <div className="table-wrap">
        <table aria-label="Directory users">
          <thead><tr><th scope="col">Name</th><th scope="col">Status</th><th scope="col">Role</th><th scope="col">MFA</th></tr></thead>
          <tbody>{data.items.map((user) => <tr key={user.id}>
            <td><button className="directory-user breakable" type="button" onClick={() => onSelect(user.id)}>{userName(user)}</button></td>
            <td>{statusLabels[user.status]}</td><td>{roleLabels[user.role]}</td><td>{mfaLabels[user.mfa_status]}</td>
          </tr>)}</tbody>
        </table>
      </div> : <p className="state-message" role="status">No users found.</p>)}
    </StateMessage>}
    {(offset > 0 || data) && <nav aria-label="Directory pages" className="directory-pagination">
      <button className="source-pill" type="button" disabled={offset === 0 || loading} onClick={() => onPage(offset - DIRECTORY_PAGE_SIZE)}>Previous</button>
      <span aria-live="polite">Page {Math.floor(offset / DIRECTORY_PAGE_SIZE) + 1}</span>
      <button className="source-pill" type="button" disabled={loading || atLimit || !data?.has_more} onClick={() => onPage(offset + DIRECTORY_PAGE_SIZE)}>Next</button>
    </nav>}
    {atLimit && data?.has_more && <p className="state-message" role="status">Refine your search to see more users.</p>}
    {!loading && !error && data && <DisabledCreateUser />}
  </>;
}

export function DirectoryAccountFields({ user }: { user: Pick<DirectoryUser, 'display_name' | 'status' | 'role'> }) {
  return <>
    <div><dt>Display name</dt><dd className="breakable">{userName(user)}</dd></div>
    <div><dt>Status</dt><dd>{statusLabels[user.status]}</dd></div>
    <div><dt>Role</dt><dd>{roleLabels[user.role]}</dd></div>
  </>;
}

export function DirectoryDetail({ data, error, loading, onBack, lifecycle, delegation, deactivation, grants, history, children }: Remote<DirectoryUser> & {
  onBack: () => void; lifecycle?: ReactNode; delegation?: ReactNode; deactivation?: ReactNode; grants?: ReactNode; history?: ReactNode; children?: ReactNode;
}) {
  return <section className="content-panel" aria-label="User details">
    <div className="panel-toolbar"><h2>User details</h2><button className="source-pill directory-back" type="button" onClick={onBack}>Back to directory</button></div>
    {error ? <DirectoryError error={error} detail /> : <StateMessage loading={loading}>
      {data && <>
        <dl className="provenance-grid">
          {!lifecycle && <DirectoryAccountFields user={data} />}
          <div><dt>MFA</dt><dd>{mfaLabels[data.mfa_status]}</dd></div>
          <div className="hash-field"><dt>User ID</dt><dd className="mono breakable">{data.id}</dd></div>
        </dl>
        {lifecycle ?? <p className="auth-unavailable">Lifecycle changes are disabled in this release.{!delegation && !deactivation && !children && ' This detail is read-only.'}</p>}
        {delegation ?? <p className="auth-unavailable">Permission delegation is disabled in this release.</p>}
        {deactivation ?? <p className="auth-unavailable">Account deactivation is unavailable in this release.</p>}
        {grants}
        {history}
        {children}
      </>}
    </StateMessage>}
  </section>;
}
