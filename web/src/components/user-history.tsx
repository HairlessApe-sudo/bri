'use client';

import { useEffect, useState } from 'react';
import { StateMessage } from '@/components/data-state';
import { historyActionLabels, requestHistoryPage, type HistoryState } from '@/lib/user-history';

const failureLabels = {
  unauthenticated: 'Verified session required to view account history.',
  denied: 'Access denied. You do not have permission to view account history.',
  missing: 'History not found for this account.',
  error: 'Could not load account history. Try again in a moment.',
};
const dateFormat = new Intl.DateTimeFormat('en', { dateStyle: 'medium', timeStyle: 'medium', timeZone: 'UTC' });

function codeLabel(code: string | null) {
  const words = code?.replace(/[_-]+/g, ' ').trim();
  return words ? words[0].toUpperCase() + words.slice(1) : '—';
}

export function HistoryPageView({ state, cursor, onPage }: {
  state: HistoryState; cursor: string | null; onPage: (cursor: string | null) => void;
}) {
  const page = state.phase === 'ready' ? state.page : null;
  const next = page?.next_cursor;
  return <>
    {state.phase === 'loading' ? <StateMessage loading />
      : state.phase === 'ready' ? state.page.items.length ? <div className="table-wrap">
        <table aria-label="Account history events">
          <thead><tr><th scope="col">Date (UTC)</th><th scope="col">Action</th><th scope="col">Outcome</th><th scope="col">Reason</th><th scope="col">Actor</th></tr></thead>
          <tbody>{state.page.items.map((entry) => <tr key={entry.id}>
            <td><time dateTime={entry.occurred_at}>{dateFormat.format(new Date(entry.occurred_at))}</time></td>
            <td>{historyActionLabels[entry.action]}</td>
            <td className="breakable">{codeLabel(entry.outcome)}</td>
            <td className="breakable">{codeLabel(entry.reason_code)}</td>
            <td className="breakable">{entry.actorName}</td>
          </tr>)}</tbody>
        </table>
      </div> : <p className="state-message" role="status">No account history events on this page.</p>
      : <p className={`state-message ${state.phase === 'denied' || state.phase === 'unauthenticated' ? 'state-denied' : 'state-error'}`} role="alert">
        {failureLabels[state.phase]}
      </p>}
    {(cursor || (next && next !== cursor)) && <nav aria-label="Account history pages" className="directory-pagination">
      {cursor && <button className="source-pill" type="button" onClick={() => onPage(null)}>Newest events</button>}
      {next && next !== cursor && <button className="source-pill" type="button" onClick={() => onPage(next)}>Older events</button>}
    </nav>}
  </>;
}

function HistoryRequest({ accountId, cursor, onPage }: {
  accountId: string; cursor: string | null; onPage: (cursor: string | null) => void;
}) {
  const [state, setState] = useState<HistoryState>({ phase: 'loading' });
  useEffect(() => requestHistoryPage(accountId, cursor, setState), [accountId, cursor]);
  return <HistoryPageView state={state} cursor={cursor} onPage={onPage} />;
}

export function UserHistory({ accountId }: { accountId: string }) {
  const [cursor, setCursor] = useState<string | null>(null);
  return <section aria-label="Account history">
    <div className="panel-toolbar"><h3>Account history</h3></div>
    {/* A new page starts empty; do not carry rows across request scopes. */}
    <HistoryRequest key={`${accountId}:${cursor ?? ''}`} accountId={accountId} cursor={cursor} onPage={setCursor} />
  </section>;
}
