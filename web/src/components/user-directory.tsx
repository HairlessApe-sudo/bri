'use client';

import { useReducer, useState, type FormEvent, type ReactNode } from 'react';
import { PageHeading, useRemote } from '@/components/data-state';
import { DirectoryDetail, DirectoryList, directoryFilterLabels } from '@/components/user-directory-view';
import { UserGrants } from '@/components/user-grants';
import { UserHistory } from '@/components/user-history';
import type { DirectoryUser, DirectoryUserPage } from '@/lib/api';
import { DIRECTORY_FILTERS, DIRECTORY_MAX_QUERY, directoryDetailPath, directoryListPath, isDirectoryUserId, updateDirectoryList } from '@/lib/user-directory.mjs';

function ListRequest({ path, offset, onPage, onSelect, onViewGrants, overviewActions }: {
  path: string; offset: number; onPage: (offset: number) => void; onSelect: (id: string) => void; onViewGrants: (id: string) => void;
  overviewActions?: ReactNode;
}) {
  const remote = useRemote<DirectoryUserPage>(path);
  return <>
    {remote.data && !remote.loading && !remote.error && overviewActions}
    <DirectoryList {...remote} offset={offset} onPage={onPage} onSelect={onSelect} onViewGrants={onViewGrants} />
  </>;
}

const focusGrantsPanel = (node: HTMLDivElement | null) => { node?.focus(); };

export function DirectoryDetailContent({ accountId, data, error, loading, onBack, focusGrants }: {
  accountId: string; data: DirectoryUser | null; error?: Error | null; loading?: boolean; onBack: () => void; focusGrants?: boolean;
}) {
  if (data && (!isDirectoryUserId(data.id) || data.id.toLowerCase() !== accountId.toLowerCase())) {
    return <DirectoryDetail error={new Error('Unexpected account response')} onBack={onBack} />;
  }
  const showPanels = data && !error && !loading;
  return <DirectoryDetail data={data} error={error} loading={loading} onBack={onBack}
    grants={showPanels ? (focusGrants
      ? <div tabIndex={-1} ref={focusGrantsPanel}><UserGrants accountId={accountId} /></div>
      : <UserGrants accountId={accountId} />) : null}
    history={showPanels ? <UserHistory key={accountId} accountId={accountId} /> : null} />;
}

function DetailRequest({ accountId, onBack, focusGrants }: { accountId: string; onBack: () => void; focusGrants: boolean }) {
  const remote = useRemote<DirectoryUser>(directoryDetailPath(accountId));
  return <DirectoryDetailContent {...remote} accountId={accountId} onBack={onBack} focusGrants={focusGrants} />;
}

const filterNames = { status: 'Status', role: 'Role', mfa_status: 'MFA' } as const;
const filterKeys = Object.keys(filterNames) as (keyof typeof filterNames)[];

export function UserDirectory({ enabled, overviewActions }: { enabled: boolean; overviewActions?: ReactNode }) {
  const [draft, setDraft] = useState('');
  const [{ query, offset, filters }, dispatch] = useReducer(updateDirectoryList, { query: '', offset: 0, filters: {} });
  const [searchKey, setSearchKey] = useState(0);
  const [selection, setSelection] = useState<{ id: string; focusGrants: boolean } | null>(null);
  const [invalidDetail, setInvalidDetail] = useState(false);
  const listPath = directoryListPath(query, offset, filters);

  function search(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    dispatch({ type: 'search', query: draft });
    setSearchKey((key) => key + 1);
  }
  function showDetail(id: string, focusGrants = false) {
    if (isDirectoryUserId(id)) setSelection({ id, focusGrants });
    else setInvalidDetail(true);
  }
  function back() {
    setSelection(null);
    setInvalidDetail(false);
  }

  return <>
    <PageHeading eyebrow="WORKSPACE / USERS" title="User directory" description="Search and inspect ordinary user accounts in your client organisation." />
    {!enabled ? <div className="state-message">The user directory is unavailable in synthetic development mode.</div>
      : selection ? <DetailRequest key={selection.id} accountId={selection.id} onBack={back} focusGrants={selection.focusGrants} />
      : invalidDetail ? <DirectoryDetail error={new Error('Invalid user ID')} onBack={back} />
      : <section className="content-panel" aria-label="Directory search">
        <form className="knowledge-search" role="search" onSubmit={search}>
          <label className="sr-only" htmlFor="directory-query">Search users</label>
          <input id="directory-query" type="search" value={draft} onChange={(event) => setDraft(event.target.value)} placeholder="Name or user ID" maxLength={DIRECTORY_MAX_QUERY} />
          <button type="submit">Search</button>
        </form>
        <div className="directory-pagination" role="group" aria-label="Directory filters">
          {filterKeys.map((key) => <label key={key}>{filterNames[key]}<select name={key} value={filters[key] ?? ''}
            onChange={(event) => dispatch({ type: 'filter', key, value: event.currentTarget.value })}>
            <option value="">Any</option>
            {DIRECTORY_FILTERS[key].map((value) => <option key={value} value={value}>{(directoryFilterLabels[key] as Record<string, string>)[value]}</option>)}
          </select></label>)}
        </div>
        <ListRequest key={`${searchKey}:${listPath}`} path={listPath} offset={offset} overviewActions={overviewActions}
          onPage={(offset) => dispatch({ type: 'page', offset })} onSelect={showDetail} onViewGrants={(id) => showDetail(id, true)} />
      </section>}
  </>;
}
