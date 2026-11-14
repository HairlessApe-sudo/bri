'use client';

import { useMemo, useState } from 'react';
import { PageHeading, StateMessage, useRemote } from '@/components/data-state';
import type { OrganizationStructure } from '@/lib/api';

export default function OrganizationPage() {
  const { data, error, loading } = useRemote<OrganizationStructure>('/api/bri/v1/organizations/structure');
  const [filter, setFilter] = useState('');
  const nodes = data?.nodes ?? [];
  const visibleNodes = useMemo(() => {
    const term = filter.trim().toLocaleLowerCase();
    if (!term) return nodes;
    return nodes.filter((node) => `${node.display_name} ${node.node_type} ${node.node_id}`.toLocaleLowerCase().includes(term));
  }, [filter, nodes]);
  const visibleIds = new Set(visibleNodes.map((node) => node.node_id));
  const children = new Map<string, typeof visibleNodes>();
  for (const node of visibleNodes) {
    const parent = node.parent_node_id && visibleIds.has(node.parent_node_id) ? node.parent_node_id : '';
    children.set(parent, [...(children.get(parent) ?? []), node]);
  }
  const renderTree = (parent: string, depth = 0, ancestry = new Set<string>()): React.ReactNode => (children.get(parent) ?? []).map((node) => {
    const loop = ancestry.has(node.node_id);
    const nextAncestry = new Set(ancestry).add(node.node_id);
    return <div key={node.node_id}>
      <div className="org-row" style={{ '--depth': Math.min(depth, 8) } as React.CSSProperties}>
        <span className={`org-symbol type-${node.node_type.replace(/[^a-z0-9]/gi, '-')}`} />
        <span className="org-name">{node.display_name}</span><span className="org-type">{node.node_type.replaceAll('_', ' ')}</span>
      </div>
      {!loop && renderTree(node.node_id, depth + 1, nextAncestry)}
    </div>;
  });

  return <>
    <PageHeading eyebrow="WORKSPACE / ORGANISATION" title="Organisation structure" description="Browse the nodes this development identity is authorised to see. Parent grants do not imply access to descendants." />
    <section className="content-panel">
      <div className="panel-toolbar"><div><span className="section-kicker">AUTHORISED STRUCTURE</span><h2>Organisational nodes</h2></div><label className="search-field compact"><span className="sr-only">Filter visible organisation</span><span aria-hidden="true">⌕</span><input value={filter} onChange={(event) => setFilter(event.target.value)} placeholder="Filter visible nodes" /></label></div>
      <StateMessage loading={loading} error={error} empty={Boolean(data && !data.nodes.length)}>
        {data && <><div className="result-meta">Showing {visibleNodes.length} of {nodes.length} authorised nodes</div>
          {visibleNodes.length ? <div className="org-tree" role="tree" aria-label="Authorised organisational structure">{renderTree('')}</div> : <p className="inline-empty">No visible nodes match this filter.</p>}
          <div className="relationship-section"><div className="subsection-heading"><h3>Relationships</h3><span>{data.relationships.length} returned by API</span></div>
            {data.relationships.length ? <div className="table-wrap"><table><thead><tr><th>From</th><th>Relationship</th><th>To</th><th>Access grant</th></tr></thead><tbody>{data.relationships.map((relation) => <tr key={relation.relationship_id}><td>{nodes.find((n) => n.node_id === relation.from_node_id)?.display_name ?? relation.from_node_id}</td><td>{relation.relationship_type.replaceAll('_', ' ')}</td><td>{nodes.find((n) => n.node_id === relation.to_node_id)?.display_name ?? relation.to_node_id}</td><td>{relation.grants_access ? 'Granted' : 'No grant'}</td></tr>)}</tbody></table></div> : <p className="inline-empty">No authorised relationships were returned.</p>}
          </div>
        </>}
      </StateMessage>
    </section>
  </>;
}
