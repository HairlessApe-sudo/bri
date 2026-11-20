import Link from 'next/link';
import { PageHeading, StateMessage, type Remote } from '@/components/data-state';
import { SourceProvenance } from '@/components/source-provenance';
import type { KnowledgeRecord } from '@/lib/api';

export function KnowledgeDetailView({ recordId, remote: { data, error, loading }, local = false }: { recordId: string; remote: Remote<KnowledgeRecord>; local?: boolean }) {
  const NavLink = local ? 'a' : Link;
  return <>
    <div className="back-link"><NavLink href="/knowledge">← All knowledge</NavLink></div>
    <StateMessage loading={loading} error={error}>
      {data && <>
        <PageHeading eyebrow="VALIDATED KNOWLEDGE / RECORD" title={data.title} description={local ? 'Approved content available to the current fixture session.' : 'Approved content available within the configured development identity’s authorised scope.'} />
        <article className="content-panel record-detail">
          <div className="detail-topline"><span className="verified-tag">{data.validation_state}</span><span>Scope · {data.scope_id}</span></div>
          <div className="record-content">{data.content}</div>
          <SourceProvenance source={data} />
          <div className="detail-footer"><span>Record {data.record_id}</span><NavLink className="primary-link" href={`/sources/${encodeURIComponent(data.record_id)}`}>Inspect source provenance <span>→</span></NavLink></div>
        </article>
      </>}
    </StateMessage>
  </>;
}
