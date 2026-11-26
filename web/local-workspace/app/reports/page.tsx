'use client';

import { useLayoutEffect, useRef, useState } from 'react';
import { flushSync } from 'react-dom';
import { createReportEvaluation, type ReportState } from '../../reporting.mjs';

const messages = {
  idle: 'Enter the exact node ID you are authorized to evaluate.',
  invalid: 'Enter a valid exact node ID.',
  loading: 'Evaluating the authorized inventory…',
  empty: 'No readable published knowledge records at this node.',
  unavailable: 'The inventory could not be completed. No count or evidence is available.',
  denied: 'This session is not authorized to evaluate the inventory here.',
  dependency: 'The local reporting service could not be reached or returned an invalid response.',
};

export default function LocalReports() {
  const [scope, setScope] = useState('');
  const [state, setState] = useState<ReportState>({ status: 'idle' });
  const evaluation = useRef<ReturnType<typeof createReportEvaluation> | null>(null);
  useLayoutEffect(() => {
    const current = createReportEvaluation(setState, window.fetch.bind(window));
    evaluation.current = current;
    const hide = () => {
      current.cancel();
      flushSync(() => setState({ status: 'idle' }));
    };
    window.addEventListener('pagehide', hide);
    return () => {
      window.removeEventListener('pagehide', hide);
      evaluation.current = null;
      current.cancel();
    };
  }, []);

  return <section aria-labelledby="inventory-title">
    <h1 id="inventory-title">Published knowledge inventory</h1>
    <p>This counts only the governed CSV knowledge records your current session can read at one exact node. It is not an organization-wide total or a measure of completeness.</p>
    <form onSubmit={(event) => { event.preventDefault(); void evaluation.current?.run(scope); }}>
      <label htmlFor="inventory-scope">Exact node ID</label>{' '}
      <input id="inventory-scope" value={scope} maxLength={128} autoComplete="off" spellCheck={false}
        onChange={(event) => {
          evaluation.current?.cancel();
          setState({ status: 'idle' });
          setScope(event.target.value);
        }} />{' '}
      <button type="submit">Evaluate inventory</button>
    </form>
    <p role="status">{state.status === 'complete'
      ? `Readable published records: ${state.result.count}` : messages[state.status]}</p>
    {state.status === 'complete' && <section aria-label="Inventory evidence">
      <h2>Evidence references</h2>
      <ul>{state.result.evidence.map((row) => <li key={row.record_id}>
        <a href={`/knowledge/${encodeURIComponent(row.record_id)}`}>{row.record_id}</a>{' · '}
        <a href={`/sources/${encodeURIComponent(row.record_id)}`}>Inspect source provenance</a>
        <dl>
          <dt>Exact source version ID</dt><dd>{row.source_version_id}</dd>
          <dt>Original SHA-256</dt><dd><code>{row.original_sha256}</code></dd>
          <dt>Content SHA-256</dt><dd><code>{row.content_sha256}</code></dd>
          <dt>Physical CSV lines (inclusive)</dt><dd>{row.first_line}–{row.last_line}</dd>
        </dl>
      </li>)}</ul>
    </section>}
  </section>;
}
