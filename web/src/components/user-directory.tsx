'use client';

import { useState, type FormEvent } from 'react';
import { PageHeading, useRemote } from '@/components/data-state';
import { DirectoryDetail, DirectoryList } from '@/components/user-directory-view';
import { UserHistory } from '@/components/user-history';
import type { DirectoryUser, DirectoryUserPage } from '@/lib/api';
import { DIRECTORY_MAX_QUERY, directoryDetailPath, directoryListPath, isDirectoryUserId } from '@/lib/user-directory.mjs';

function ListRequest({ path, offset, onPage, onSelect }: { path: string; offset: number; onPage: (offset: number) => void; onSelect: (id: string) => void }) {
  const remote = useRemote<DirectoryUserPage>(path);
  return <DirectoryList {...remote} offset={offset} onPage={onPage} onSelect={onSelect} />;
}

export function DirectoryDetailContent({ accountId, data, error, loading, onBack }: {
  accountId: string; data: DirectoryUser | null; error?: Error | null; loading?: boolean; onBack: () => void;
}) {
  if (data && (!isDirectoryUserId(data.id) || data.id.toLowerCase() !== accountId.toLowerCase())) {
    return <DirectoryDetail error={new Error('Unexpected account response')} onBack={onBack} />;
  }
  return <DirectoryDetail data={data} error={error} loading={loading} onBack={onBack}
    history={data && !error && !loading ? <UserHistory key={accountId} accountId={accountId} /> : null} />;
}

function DetailRequest({ accountId, onBack }: { accountId: string; onBack: () => void }) {
  const remote = useRemote<DirectoryUser>(directoryDetailPath(accountId));
  return <DirectoryDetailContent {...remote} accountId={accountId} onBack={onBack} />;
}

export function UserDirectory({ enabled }: { enabled: boolean }) {
  const [draft, setDraft] = useState('');
  const [query, setQuery] = useState('');
  const [offset, setOffset] = useState(0);
  const [searchKey, setSearchKey] = useState(0);
  const [accountId, setAccountId] = useState<string | null>(null);
  const [invalidDetail, setInvalidDetail] = useState(false);
  const listPath = directoryListPath(query, offset);

  function search(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setQuery(draft);
    setOffset(0);
    setSearchKey((key) => key + 1);
  }
  function showDetail(id: string) {
    if (isDirectoryUserId(id)) setAccountId(id);
    else setInvalidDetail(true);
  }
  function back() {
    setAccountId(null);
    setInvalidDetail(false);
  }

  return <>
    <PageHeading eyebrow="WORKSPACE / USERS" title="User directory" description="Search and inspect ordinary user accounts in your client organisation." />
    {!enabled ? <div className="state-message">The user directory is unavailable in synthetic development mode.</div>
      : accountId ? <DetailRequest key={accountId} accountId={accountId} onBack={back} />
      : invalidDetail ? <DirectoryDetail error={new Error('Invalid user ID')} onBack={back} />
      : <section className="content-panel" aria-label="Directory search">
        <form className="knowledge-search" role="search" onSubmit={search}>
          <label className="sr-only" htmlFor="directory-query">Search users</label>
          <input id="directory-query" type="search" value={draft} onChange={(event) => setDraft(event.target.value)} placeholder="Name or user ID" maxLength={DIRECTORY_MAX_QUERY} />
          <button type="submit">Search</button>
        </form>
        <ListRequest key={`${searchKey}:${offset}`} path={listPath} offset={offset} onPage={setOffset} onSelect={showDetail} />
      </section>}
  </>;
}
