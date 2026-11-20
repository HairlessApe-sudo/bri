'use client';

import { useCallback } from 'react';
import { useParams } from 'next/navigation';
import { useRemote } from '@/components/data-state';
import { SourceDetailView } from '@/components/sources-detail-view';
import { parseLocalSource } from '@/lib/local-evidence.mjs';
import type { SourceReference } from '@/lib/api';
import { apiBase, useEvidenceRefresh } from '../../refresh';

export default function LocalSourceDetail() {
  // App Router stores URI-encoded segments; the evidence decoder expects the raw ID.
  const recordId = decodeURIComponent(useParams<{ recordId: string }>().recordId);
  const { parked, refreshKey, refresh } = useEvidenceRefresh();
  const decode = useCallback((value: unknown) => parseLocalSource(value, recordId), [recordId]);
  const remote = useRemote<SourceReference>(parked ? null : `${apiBase}/sources/${encodeURIComponent(recordId)}`, refreshKey, decode);
  if (parked) return null;
  return <><p><button type="button" onClick={refresh}>Refresh evidence</button></p><SourceDetailView recordId={recordId} remote={remote} local /></>;
}
