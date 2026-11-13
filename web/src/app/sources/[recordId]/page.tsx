'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { PageHeading, StateMessage, useRemote } from '@/components/data-state';
import type { SourceReference } from '@/lib/api';

export default function SourceDetailPage() {
  const params = useParams<{ recordId: string }>();
  const recordId = params.recordId;
  const { data, error, loading } = useRemote<SourceReference>(`/api/bri/v1/sources/${encodeURIComponent(recordId)}`);
  return <>
    <div className="back-link"><Link href={`/knowledge/${encodeURIComponent(recordId)}`}>← Knowledge record</Link></div>
    <StateMessage loading={loading} error={error}>
      {data && <>
        <PageHeading eyebrow="SOURCE / PROVENANCE" title={data.title} description="Provenance returned by the API for this approved knowledge record." />
        <section className="content-panel source-detail">
          <div className="source-heading"><span className="section-kicker">SOURCE OBJECT</span><h2>{data.source_id}</h2><span className="verified-tag">Version {data.source_version}</span></div>
          <dl className="provenance-grid">
            <div><dt>Source version ID</dt><dd>{data.source_version_id}</dd></div>
            <div><dt>Extraction ID</dt><dd>{data.extraction_id}</dd></div>
            <div><dt>Extractor</dt><dd>{data.extractor_name} · {data.extractor_version}</dd></div>
            <div><dt>Source location</dt><dd className="breakable">{data.source_location}</dd></div>
            <div className="hash-field"><dt>Content SHA-256</dt><dd className="mono breakable">{data.content_sha256}</dd></div>
          </dl>
          <div className="detail-footer"><span>Reference for record {data.record_id}</span><Link className="primary-link" href={`/knowledge/${encodeURIComponent(recordId)}`}>Return to record <span>→</span></Link></div>
        </section>
      </>}
    </StateMessage>
  </>;
}
