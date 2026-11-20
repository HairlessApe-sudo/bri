'use client';

import { useCallback } from 'react';
import { useParams } from 'next/navigation';
import { useRemote } from '@/components/data-state';
import { KnowledgeDetailView } from '@/components/knowledge-detail-view';
import { parseLocalRecord } from '@/lib/local-evidence.mjs';
import type { KnowledgeRecord } from '@/lib/api';
import { apiBase, useEvidenceRefresh } from '../../refresh';

export default function LocalKnowledgeDetail() {
  // App Router stores URI-encoded segments; the evidence decoder expects the raw ID.
  const recordId = decodeURIComponent(useParams<{ recordId: string }>().recordId);
  const { parked, refreshKey, refresh } = useEvidenceRefresh();
  const decode = useCallback((value: unknown) => parseLocalRecord(value, recordId), [recordId]);
  const remote = useRemote<KnowledgeRecord>(parked ? null : `${apiBase}/knowledge/${encodeURIComponent(recordId)}`, refreshKey, decode);
  if (parked) return null;
  return <><p><button type="button" onClick={refresh}>Refresh evidence</button></p><KnowledgeDetailView recordId={recordId} remote={remote} local /></>;
}
