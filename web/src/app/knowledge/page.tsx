'use client';

import Link from 'next/link';
import { FormEvent, useState } from 'react';
import { PageHeading, StateMessage, useRemote } from '@/components/data-state';
import type { Citation, KnowledgeRecord, SearchResult } from '@/lib/api';

function CitationRow({ citation }: { citation: Citation }) {
  return <article className="citation-row">
    <div className="citation-title"><Link href={`/knowledge/${encodeURIComponent(citation.record_id)}`}>{citation.title}</Link><span className="verified-tag">Validated</span></div>
    <p className="citation-excerpt">“{citation.excerpt}”</p>
    <div className="citation-meta"><span>Version {citation.source_version}</span><span>{citation.source_location}</span><Link href={`/sources/${encodeURIComponent(citation.record_id)}`}>Source details →</Link></div>
  </article>;
}

export default function KnowledgePage() {
  const [draft, setDraft] = useState('');
  const [query, setQuery] = useState('');
  const [searchKey, setSearchKey] = useState(0);
  const records = useRemote<KnowledgeRecord[]>('/api/bri/v1/knowledge');
  const search = useRemote<SearchResult>(query ? `/api/bri/v1/knowledge/search?q=${encodeURIComponent(query)}` : null, searchKey);
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
      <div><span className="section-kicker">EVIDENCE-FIRST RETRIEVAL</span><h2>What do you need to know?</h2><p>Search uses validated knowledge available to the configured identity. Results include source citations.</p></div>
      <form className="knowledge-search" onSubmit={submit}><label className="sr-only" htmlFor="knowledge-query">Search validated knowledge</label><span aria-hidden="true">⌕</span><input id="knowledge-query" value={draft} onChange={(event) => setDraft(event.target.value)} placeholder="Try a phrase from an approved record…" maxLength={512} /><button type="submit" disabled={!draft.trim()}>Search <span>→</span></button></form>
      {query && <div className="search-results" aria-live="polite"><div className="subsection-heading"><h3>Search results</h3><span>“{query}”</span></div>
        <StateMessage loading={search.loading} error={search.error} empty={Boolean(search.data && !search.data.citations.length)}>
          {search.data && <>{search.data.answer && <p className="search-answer">{search.data.answer}</p>}{search.data.citations.length > 0 && <div className="citation-list">{search.data.citations.map((citation) => <CitationRow key={citation.record_id} citation={citation} />)}</div>}</>}
        </StateMessage>
      </div>}
    </section>
    <section className="content-panel knowledge-list-panel">
      <div className="panel-toolbar"><div><span className="section-kicker">APPROVED RECORDS</span><h2>Available knowledge</h2></div>{records.data && <span className="count-pill">{records.data.length} records</span>}</div>
      <StateMessage loading={records.loading} error={records.error} empty={Boolean(records.data && !records.data.length)}>
        {records.data && <div className="knowledge-list">{records.data.map((record) => <article className="knowledge-item" key={record.record_id}>
          <div className="knowledge-item-main"><span className="record-marker" /><div><Link className="knowledge-title" href={`/knowledge/${encodeURIComponent(record.record_id)}`}>{record.title}</Link><p>{record.content.slice(0, 180)}{record.content.length > 180 ? '…' : ''}</p><div className="knowledge-item-meta"><span className="verified-tag">{record.validation_state}</span><span>Scope · {record.scope_id}</span></div></div></div>
          <Link className="source-pill" href={`/sources/${encodeURIComponent(record.record_id)}`}>Source · {record.source_version} <span>↗</span></Link>
        </article>)}</div>}
      </StateMessage>
    </section>
  </>;
}
