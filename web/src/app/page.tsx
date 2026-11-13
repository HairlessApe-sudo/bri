'use client';

import Link from 'next/link';
import { useRemote, PageHeading, StateMessage } from '@/components/data-state';
import type { KnowledgeRecord, OrganizationStructure } from '@/lib/api';

type Health = { status: string; database: string };

export default function Dashboard() {
  const health = useRemote<Health>('/api/bri/health');
  const organization = useRemote<OrganizationStructure>('/api/bri/v1/organizations/structure');
  const knowledge = useRemote<KnowledgeRecord[]>('/api/bri/v1/knowledge');

  return <>
    <PageHeading eyebrow="WORKSPACE / OVERVIEW" title="Organisation intelligence" description="A governed view of organisational information and validated knowledge." />
    <section className="dashboard-intro">
      <div><span className="section-kicker">YOUR WORKSPACE</span><h2>Knowledge, with its context intact.</h2><p>Explore the organisation and inspect validated records with their original source references.</p></div>
      <div className="live-indicator"><span className={health.data?.status === 'ok' ? 'pulse-dot is-live' : 'pulse-dot'} />
        <div><strong>{health.loading ? 'Connecting to API' : health.error ? 'API unavailable' : 'Connected to API'}</strong><small>{health.loading ? 'Checking backend readiness…' : health.error ? health.error.message : 'FastAPI · PostgreSQL-backed knowledge'}</small></div>
      </div>
    </section>
    <section className="overview-grid" aria-label="Available information">
      <article className="overview-panel">
        <div className="panel-head"><div><span className="section-kicker">01 / STRUCTURE</span><h3>Organisation</h3></div><Link className="text-link" href="/organization">Browse <span>→</span></Link></div>
        <StateMessage loading={organization.loading} error={organization.error} empty={Boolean(organization.data && !organization.data.nodes.length)}>
          {organization.data && <><p className="panel-copy">Visible organisation nodes and relationships for the configured identity.</p><div className="quantity-row"><strong>{organization.data.nodes.length.toLocaleString()}</strong><span>authorised nodes</span><span className="quantity-divider" /><strong>{organization.data.relationships.length.toLocaleString()}</strong><span>relationships</span></div>
            <div className="preview-list">{organization.data.nodes.slice(0, 4).map((node) => <div className="preview-line" key={node.node_id}><span className="node-marker" />{node.display_name}<span className="preview-type">{node.node_type.replaceAll('_', ' ')}</span></div>)}</div></>}
        </StateMessage>
      </article>
      <article className="overview-panel">
        <div className="panel-head"><div><span className="section-kicker">02 / KNOWLEDGE</span><h3>Validated records</h3></div><Link className="text-link" href="/knowledge">Explore <span>→</span></Link></div>
        <StateMessage loading={knowledge.loading} error={knowledge.error} empty={Boolean(knowledge.data && !knowledge.data.length)}>
          {knowledge.data && <><p className="panel-copy">Approved knowledge visible within the configured identity’s exact scopes.</p><div className="quantity-row"><strong>{knowledge.data.length.toLocaleString()}</strong><span>accessible records</span></div>
            <div className="preview-list">{knowledge.data.slice(0, 4).map((record) => <Link className="preview-line record-preview" key={record.record_id} href={`/knowledge/${encodeURIComponent(record.record_id)}`}><span className="record-marker" />{record.title}<span className="preview-type">{record.source_version}</span></Link>)}</div></>}
        </StateMessage>
      </article>
    </section>
    <section className="principle-strip"><span className="principle-mark">↳</span><div><strong>Evidence stays connected.</strong><p>Every record links to its source version, extraction, hash and source location.</p></div><Link href="/knowledge">View knowledge <span>→</span></Link></section>
  </>;
}
