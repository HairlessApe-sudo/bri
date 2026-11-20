'use client';

import { useParams } from 'next/navigation';
import { useRemote } from '@/components/data-state';
import { KnowledgeDetailView } from '@/components/knowledge-detail-view';
import type { KnowledgeRecord } from '@/lib/api';

export default function KnowledgeDetailPage() {
  const params = useParams<{ recordId: string }>();
  const recordId = params.recordId;
  const remote = useRemote<KnowledgeRecord>(`/api/bri/v1/knowledge/${encodeURIComponent(recordId)}`);
  return <KnowledgeDetailView recordId={recordId} remote={remote} />;
}
