'use client';

import Link from 'next/link';
import { FormEvent, useState } from 'react';
import { PageHeading, StateMessage, useRemote } from '@/components/data-state';
import { SourceProvenance } from '@/components/source-provenance';
import { workspaceEvidenceDenial } from '@/lib/remote-state.mjs';
import type { Citation, KnowledgeRecord, SearchResult } from '@/lib/api';

function CitationRow({ citation, local }: { citation: Citation; local: boolean }) {
  const NavLink = local ? 'a' : Link;
  return <article className="citation-row">
    <div className="citation-title"><NavLink href={`/knowledge/${encodeURIComponent(citation.record_id)}`}>{citation.title}</NavLink><span className="verified-tag">Validated</span></div>
    <p className="citation-excerpt">“{citation.excerpt}”</p>
    <div className="citation-meta"><span>Version {citation.source_version}</span><span>{citation.source_location}</span><NavLink href={`/sources/${encodeURIComponent(citation.record_id)}`}>Source details →</NavLink></div>
    <SourceProvenance source={citation} />
  </article>;
}

type LocalEvidence = {
  parked: boolean;
  refreshKey: number;
  refresh: () => void;
  parseSearch: (value: unknown) => SearchResult;
  parseRecords: (value: unknown) => KnowledgeRecord[];
};

export function KnowledgeWorkspace({ apiBase, local }: { apiBase: string; local?: LocalEvidence }) {
  const NavLink = local ? 'a' : Link;
  const [draft, setDraft] = useState('');
  const [query, setQuery] = useState('');
  const [searchKey, setSearchKey] = useState(0);
  const parked = local?.parked ?? false;
  const records = useRemote<KnowledgeRecord[]>(parked ? null : `${apiBase}/knowledge`, local ? local.refreshKey + searchKey : 0, local?.parseRecords);
  const search = useRemote<SearchResult>(query && !parked ? `${apiBase}/knowledge/search?q=${encodeURIComponent(query)}` : null, (local?.refreshKey ?? 0) + searchKey, local?.parseSearch);
  const denial = local ? workspaceEvidenceDenial(records.error, search.error) : null;
  if (parked) return null;
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const value = draft.trim();
    if (!value) return;
    setQuery(value);
    setSearchKey((key) => key + 1);
  }

  return <>
    <PageHeading eyebrow="WORKSPACE / KNOWLEDGE" title="Validated knowledge" description="Search approved records and follow each answer back to its source and version." />
    <section className="search-hero">
      <div><span className="section-kicker">EVIDENCE-FIRST RETRIEVAL</span><h2>What do you need to know?</h2><p>{local ? 'Search only published fixture records available to the current session.' : 'Search uses validated knowledge available to the configured identity. Results include source citations.'}</p></div>
      <form className="knowledge-search" onSubmit={submit}><label className="sr-only" htmlFor="knowledge-query">Search validated knowledge</label><span aria-hidden="true">⌕</span><input id="knowledge-query" value={draft} onChange={(event) => setDraft(event.target.value)} placeholder="Try a phrase from an approved record…" maxLength={512} /><button type="submit" disabled={!draft.trim()}>Search <span>→</span></button></form>
      {local && <p><button type="button" onClick={local.refresh}>Refresh evidence</button></p>}
      {query && <div className="search-results" aria-live="polite"><div className="subsection-heading"><h3>Search results</h3><span>“{query}”</span></div>
        <StateMessage loading={!denial && (search.loading || Boolean(local && records.loading))}
          error={denial ?? search.error} empty={Boolean(!local && search.data && !search.data.citations.length)}>
          {search.data && <>
            {local && <p className="verified-tag">{search.data.status === 'supported' ? 'Supported' : search.data.status === 'conflicting' ? 'Conflicting evidence' : 'Insufficient evidence'}</p>}
            {search.data.answer && <p className="search-answer">{search.data.answer}</p>}
            {local && search.data.status === 'conflicting' && <p>No single answer is supported by the matching evidence.</p>}
            {local && search.data.status === 'insufficient' && <p>No answer can be supported by the available published evidence.</p>}
            {search.data.citations.length > 0 && <div className="citation-list">{search.data.citations.map((citation, index) =>
              <CitationRow key={`${citation.record_id}:${citation.source_version_id}:${index}`} citation={citation} local={Boolean(local)} />)}</div>}
          </>}
        </StateMessage>
      </div>}
    </section>
    <section className="content-panel knowledge-list-panel">
      <div className="panel-toolbar"><div><span className="section-kicker">APPROVED RECORDS</span><h2>Available knowledge</h2></div>{!denial && records.data && <span className="count-pill">{records.data.length} records</span>}</div>
      <StateMessage loading={!denial && records.loading} error={denial ?? records.error} empty={Boolean(records.data && !records.data.length)}>
        {records.data && <div className="knowledge-list">{records.data.map((record) => <article className="knowledge-item" key={record.record_id}>
          <div className="knowledge-item-main"><span className="record-marker" /><div><NavLink className="knowledge-title" href={`/knowledge/${encodeURIComponent(record.record_id)}`}>{record.title}</NavLink><p>{record.content.slice(0, 180)}{record.content.length > 180 ? '…' : ''}</p><div className="knowledge-item-meta"><span className="verified-tag">{record.validation_state}</span><span>Scope · {record.scope_id}</span></div></div></div>
          <NavLink className="source-pill" href={`/sources/${encodeURIComponent(record.record_id)}`}>Source · {record.source_version} <span>↗</span></NavLink>
        </article>)}</div>}
      </StateMessage>
    </section>
  </>;
}
