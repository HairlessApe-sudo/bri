'use client';

import { useCallback, useLayoutEffect, useRef, useState } from 'react';
import { flushSync } from 'react-dom';
import { evidencePath, normalizeQuery, parseEvidence, parseScopes, parseSearch } from '../../../unified-contract.mjs';
import { createUnifiedLifecycle } from '../../../unified-lifecycle.mjs';
import { WorksheetView, type Worksheet } from '../../xlsx/worksheet';
import { EvidenceCorrection } from './evidence-correction';
import './unified.css';

const bridge = '/api/bri-local/unified';
const searchPath = '/v1/knowledge/search';
const bindingHeader = 'x-bri-unified-context';
type Scope = { scope_node_id: string; display_label: string };
type LineRange = { first_line: number; last_line: number };
type CommonHit = { record_id: string; source_version_id: string; source_id: string; original_sha256: string;
  excerpt: string; excerpt_truncated: boolean; match: 'exact' | 'substring'; evidence_url: string };
type Hit = CommonHit & ({ format: 'csv'; content_sha256: string; evidence: LineRange }
  | { format: 'xlsx'; canonical_sha256: string; extractor_version: number; canonicalization_version: number;
      evidence: { sheet_id: string; sheet_title: string; cell: string } });
type Receipt = LineRange | Worksheet;
type Status = 'initial' | 'loading' | 'complete' | 'empty' | 'unavailable' | 'denied' | 'invalid';
const denied = (status: number) => status === 401 || status === 403 || status === 404;

function physicalLines({ first_line, last_line }: LineRange) {
  return first_line === last_line ? `Physical CSV line ${first_line}` : `Physical CSV lines ${first_line}–${last_line} (inclusive)`;
}

export default function KnowledgeInterface() {
  const lifecycle = useRef(createUnifiedLifecycle());
  const [node, setNode] = useState('');
  const [query, setQuery] = useState('');
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [scopeStatus, setScopeStatus] = useState<Status>('initial');
  const [searchStatus, setSearchStatus] = useState<Status>('initial');
  const [results, setResults] = useState<Hit[]>([]);
  const [evidenceStatus, setEvidenceStatus] = useState<Status>('initial');
  const [evidence, setEvidence] = useState<{ hit: Hit; data: Receipt } | null>(null);

  const clearFindings = useCallback(() => {
    setResults([]);
    setEvidence(null);
    setSearchStatus('initial');
    setEvidenceStatus('initial');
  }, []);
  const clearView = useCallback(() => {
    setNode('');
    setScopes([]);
    setQuery('');
    clearFindings();
  }, [clearFindings]);

  const discover = useCallback(async (flush = false) => {
    const active = lifecycle.current;
    const request = active.beginRevalidation(() => {
      const redact = () => { clearView(); setScopeStatus('loading'); };
      // Event-driven rechecks must remove the old DOM before the fresh read.
      // The initial layout effect already commits its updates before paint.
      if (flush) flushSync(redact); else redact();
    });
    try {
      const response = await fetch(`${bridge}${searchPath}/scopes`, {
        cache: 'no-store', credentials: 'same-origin', redirect: 'error', signal: request.signal,
      });
      if (!request.current()) return;
      if (denied(response.status)) {
        active.resetAccess();
        setScopeStatus('denied');
        return;
      }
      if (response.status !== 200) throw new Error('Scope unavailable');
      const value = parseScopes(await response.json());
      if (!request.current()) return;
      const current = response.headers.get(bindingHeader);
      if (value.status !== 'complete' || !current || !/^[a-f0-9]{64}$/.test(current)) throw new Error('Invalid scope receipt');
      const available: Scope[] = value.scopes;
      const selected = request.authorize(current, available.map((item) => item.scope_node_id));
      if (selected === null) return;
      setNode(selected);
      setScopes(available);
      setScopeStatus(available.length ? 'complete' : 'empty');
    } catch {
      if (!request.current()) return;
      active.resetAccess();
      setScopeStatus('unavailable');
    }
  }, [clearView]);

  useLayoutEffect(() => {
    const active = lifecycle.current;
    const park = () => {
      active.resetAccess();
      flushSync(() => { clearView(); setScopeStatus('initial'); });
    };
    const recheck = () => { if (document.visibilityState === 'visible') void discover(true); };
    const visibility = () => { if (document.visibilityState === 'hidden') park(); else recheck(); };
    window.addEventListener('pagehide', park);
    window.addEventListener('pageshow', recheck);
    window.addEventListener('focus', recheck);
    document.addEventListener('visibilitychange', visibility);
    void discover();
    return () => {
      active.resetAccess();
      window.removeEventListener('pagehide', park);
      window.removeEventListener('pageshow', recheck);
      window.removeEventListener('focus', recheck);
      document.removeEventListener('visibilitychange', visibility);
    };
  }, [discover, clearView]);

  function failAuthorization() {
    lifecycle.current.resetAccess();
    clearView();
    setScopeStatus('denied');
  }

  async function runSearch() {
    const binding = lifecycle.current.access();
    if (scopeStatus !== 'complete' || !binding || !scopes.some((s) => s.scope_node_id === node)) return;
    const request = lifecycle.current.begin();
    clearFindings();
    try {
      const literal = normalizeQuery(query);
      if (!literal) throw new Error('Invalid query');
      setSearchStatus('loading');
      const reply = await fetch(`${bridge}${searchPath}`, {
        method: 'POST', cache: 'no-store', credentials: 'same-origin', redirect: 'error', signal: request.signal,
        headers: { 'content-type': 'application/json', [bindingHeader]: binding },
        body: JSON.stringify({ scope_node_id: node, query: literal }),
      });
      if (!request.current()) return;
      if (denied(reply.status)) { failAuthorization(); setSearchStatus('denied'); return; }
      if (reply.status !== 200 && reply.status !== 503) throw new Error('Search unavailable');
      const value = parseSearch(await reply.json());
      if (!request.current()) return;
      if (reply.status !== 200 || value.status !== 'complete') { setSearchStatus('unavailable'); return; }
      const hits: Hit[] = value.results;
      setResults(hits);
      setSearchStatus(hits.length ? 'complete' : 'empty');
    } catch {
      if (!request.current()) return;
      setSearchStatus('unavailable');
    }
  }

  async function viewEvidence(hit: Hit, cursor?: string) {
    const binding = lifecycle.current.access();
    if (!binding || !results.includes(hit)) return;
    const request = lifecycle.current.begin();
    setEvidence(null);
    setEvidenceStatus('loading');
    try {
      const path = evidencePath(hit, cursor);
      const reply = await fetch(`${bridge}${path}`, {
        cache: 'no-store', credentials: 'same-origin', redirect: 'error', signal: request.signal,
        headers: { [bindingHeader]: binding },
      });
      if (!request.current()) return;
      if (denied(reply.status)) { failAuthorization(); setEvidenceStatus('denied'); return; }
      if (reply.status !== 200) throw new Error('Evidence unavailable');
      const data: Receipt = parseEvidence(await reply.json(), hit, node);
      if (!request.current()) return;
      setEvidence({ hit, data });
      setEvidenceStatus('complete');
    } catch {
      if (!request.current()) return;
      clearFindings();
      setEvidenceStatus('unavailable');
    }
  }

  let valid = false;
  try { valid = Boolean(normalizeQuery(query)); } catch { /* Invalid input never dispatches. */ }
  const scopeMessage = { initial: 'Authorized scopes will be checked before searching.', loading: 'Checking authorized scopes…',
    empty: 'This session has no authorized search scopes.', unavailable: 'Authorized scopes could not be loaded. Refresh to try again.',
    denied: 'This session is not authorized for this operation. Refresh scopes before a new search.',
    complete: 'Choose one exact scope. Search does not include its parent or descendants.', invalid: '' };
  const searchMessage = { initial: 'No search has been performed.', loading: 'Searching this exact scope…',
    empty: 'No matching knowledge was found within the current authorized search scope.',
    unavailable: 'Search could not be completed. No results are available.', denied: 'This session is not authorized for this operation.',
    complete: 'Search results, in the order returned.', invalid: 'Enter a valid literal search query.' };
  const evidenceMessage = { initial: '', loading: 'Checking current authorization for this exact version…', complete: '', empty: '', invalid: '',
    denied: 'This session is not authorized for this operation. Run a fresh authorized search before opening evidence.',
    unavailable: 'Evidence could not be loaded. Run a fresh search to try again.' };

  return <section className="unified-workspace" aria-labelledby="unified-title">
    <header className="page-heading"><div><p className="eyebrow">GOVERNED RETRIEVAL · LOCAL SYNTHETIC WORKSPACE</p>
      <h1 id="unified-title">Knowledge Interface</h1><p className="lede">Search authorized CSV and XLSX knowledge in one exact organisational scope. Opening evidence checks current access again.</p></div></header>
    <form className="search-hero unified-form" onSubmit={(event) => { event.preventDefault(); if (valid) void runSearch(); }}>
      <div className="unified-scope-row"><label htmlFor="unified-scope">Organisational scope</label>
        <button type="button" disabled={scopeStatus === 'loading'} onClick={() => void discover(true)}>Refresh scopes</button></div>
      <select id="unified-scope" disabled={scopeStatus !== 'complete'} value={node}
        onChange={(event) => {
          if (!lifecycle.current.select(event.target.value)) return;
          lifecycle.current.clear(); clearFindings(); setNode(event.target.value);
        }}>
        <option value="">Select an authorized scope</option>
        {scopes.map(({ scope_node_id, display_label }) => <option key={scope_node_id} value={scope_node_id}>{display_label}{display_label ? ' — ' : ''}{scope_node_id}</option>)}
      </select>
      <p id="knowledge-scopes" data-state={scopeStatus} className="state-message" role="status">{scopeMessage[scopeStatus]}</p>
      <label htmlFor="unified-query">Search query</label>
      <div className="knowledge-search"><input id="unified-query" type="text" value={query} autoComplete="off" spellCheck={false}
        aria-describedby="unified-query-help" disabled={scopeStatus !== 'complete'}
        onChange={(event) => {
          if (!lifecycle.current.access()) return;
          lifecycle.current.clear(); clearFindings(); setQuery(event.target.value);
        }} />
        <button type="submit" disabled={!valid || !node || scopeStatus !== 'complete'}>Search</button></div>
      <p id="unified-query-help">Use literal text, up to 256 UTF-8 bytes after normalization.{query && !valid ? ' This query is not valid.' : ''}</p>
    </form>
    <p id="knowledge-search-state" data-state={searchStatus} className="state-message" role="status">{searchMessage[searchStatus]}</p>
    {searchStatus === 'complete' && <ol id="knowledge-results" className="unified-results citation-list" aria-label="Knowledge results">
      {results.map((hit) => <li className="citation-row" data-format={hit.format} key={`${hit.format}:${hit.record_id}`}>
        <div className="citation-title"><span className="verified-tag">{hit.format.toUpperCase()}</span>
          <span>{hit.match === 'exact' ? 'Exact match' : 'Substring match'}</span></div>
        <p className="breakable">Source <code>{hit.source_id}</code></p>
        <p className="citation-excerpt breakable">{hit.excerpt}</p>
        {hit.excerpt_truncated && <p className="result-meta">Excerpt clipped.</p>}
        <p className="breakable">{hit.format === 'csv' ? physicalLines(hit.evidence) : <>Worksheet {hit.evidence.sheet_title} · Cell {hit.evidence.cell}</>}</p>
        <button type="button" onClick={() => void viewEvidence(hit)}>View evidence</button>
        <details><summary>Technical provenance</summary><dl className="provenance-grid">
          <div><dt>Record ID</dt><dd className="breakable">{hit.record_id}</dd></div>
          <div><dt>Exact source version ID</dt><dd className="breakable">{hit.source_version_id}</dd></div>
          <div className="hash-field"><dt>Original SHA-256</dt><dd className="mono breakable">{hit.original_sha256}</dd></div>
          {hit.format === 'csv' ? <div className="hash-field"><dt>Content SHA-256</dt><dd className="mono breakable">{hit.content_sha256}</dd></div>
            : <><div className="hash-field"><dt>Canonical SHA-256</dt><dd className="mono breakable">{hit.canonical_sha256}</dd></div>
              <div><dt>Extractor version</dt><dd>{hit.extractor_version}</dd></div>
              <div><dt>Canonicalization version</dt><dd>{hit.canonicalization_version}</dd></div>
              <div><dt>Worksheet ID</dt><dd>{hit.evidence.sheet_id}</dd></div></>}
        </dl></details>
      </li>)}
    </ol>}
    <section id="knowledge-evidence" data-state={evidenceStatus} aria-label="Exact version evidence">
      {evidenceMessage[evidenceStatus] && <p className="state-message" role="status">{evidenceMessage[evidenceStatus]}</p>}
      {evidence && <div className="content-panel">
        <h2>Exact version evidence</h2><p className="breakable">Version <code>{evidence.hit.source_version_id}</code></p>
        {'cells' in evidence.data ? <><p>Matched worksheet cell: {evidence.hit.format === 'xlsx' ? evidence.hit.evidence.cell : ''}</p>
          <WorksheetView data={evidence.data} />
          {evidence.data.next_cursor && <button type="button" onClick={() => {
            if ('cells' in evidence.data && evidence.data.next_cursor) void viewEvidence(evidence.hit, evidence.data.next_cursor);
          }}>Next evidence page</button>}</>
          : <><p>{physicalLines(evidence.data)} in the exact source version.</p>
            {evidence.hit.format === 'csv' && <p>Matched location: {physicalLines(evidence.hit.evidence)}.</p>}
            <p className="lede">The CSV evidence receipt verifies the recorded line span and digests. It does not return the original file.</p></>}
        <EvidenceCorrection key={`${evidence.hit.format}:${evidence.hit.record_id}:${evidence.hit.source_version_id}`}
          format={evidence.hit.format} record={evidence.hit.record_id} version={evidence.hit.source_version_id}
          refresh={() => { void viewEvidence(evidence.hit); }} />
      </div>}
    </section>
  </section>;
}
