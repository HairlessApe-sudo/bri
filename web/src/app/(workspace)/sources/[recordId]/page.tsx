'use client';

import { useParams } from 'next/navigation';
import { useRemote } from '@/components/data-state';
import { SourceDetailView } from '@/components/sources-detail-view';
import type { SourceReference } from '@/lib/api';

export default function SourceDetailPage() {
  const params = useParams<{ recordId: string }>();
  const recordId = params.recordId;
  const remote = useRemote<SourceReference>(`/api/bri/v1/sources/${encodeURIComponent(recordId)}`);
  return <SourceDetailView recordId={recordId} remote={remote} />;
}
