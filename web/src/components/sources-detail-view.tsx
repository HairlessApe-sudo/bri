import Link from 'next/link';
import { PageHeading, StateMessage, type Remote } from '@/components/data-state';
import { SourceProvenance } from '@/components/source-provenance';
import type { SourceReference } from '@/lib/api';

export function SourceDetailView({ recordId, remote: { data, error, loading }, local = false }: { recordId: string; remote: Remote<SourceReference>; local?: boolean }) {
  const NavLink = local ? 'a' : Link;
  return <>
    <div className="back-link"><NavLink href={`/knowledge/${encodeURIComponent(recordId)}`}>← Knowledge record</NavLink></div>
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
          </dl>
          <SourceProvenance source={data} showLegacyDigest />
          <div className="detail-footer"><span>Reference for record {data.record_id}</span><NavLink className="primary-link" href={`/knowledge/${encodeURIComponent(recordId)}`}>Return to record <span>→</span></NavLink></div>
        </section>
      </>}
    </StateMessage>
  </>;
}
