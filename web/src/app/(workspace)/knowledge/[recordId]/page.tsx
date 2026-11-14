'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { PageHeading, StateMessage, useRemote } from '@/components/data-state';
import type { KnowledgeRecord } from '@/lib/api';

export default function KnowledgeDetailPage() {
  const params = useParams<{ recordId: string }>();
  const recordId = params.recordId;
  const { data, error, loading } = useRemote<KnowledgeRecord>(`/api/bri/v1/knowledge/${encodeURIComponent(recordId)}`);
  return <>
    <div className="back-link"><Link href="/knowledge">← All knowledge</Link></div>
    <StateMessage loading={loading} error={error}>
      {data && <>
        <PageHeading eyebrow="VALIDATED KNOWLEDGE / RECORD" title={data.title} description="Approved content available within the configured development identity’s authorised scope." />
        <article className="content-panel record-detail">
          <div className="detail-topline"><span className="verified-tag">{data.validation_state}</span><span>Scope · {data.scope_id}</span></div>
          <div className="record-content">{data.content}</div>
          <div className="detail-footer"><span>Record {data.record_id}</span><Link className="primary-link" href={`/sources/${encodeURIComponent(data.record_id)}`}>Inspect source provenance <span>→</span></Link></div>
        </article>
      </>}
    </StateMessage>
  </>;
}
