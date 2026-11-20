'use client';

import { KnowledgeWorkspace } from '@/components/knowledge-workspace';
import { parseLocalRecords, parseLocalSearch } from '@/lib/local-evidence.mjs';
import { apiBase, useEvidenceRefresh } from '../refresh';

export default function LocalKnowledge() {
  const refresh = useEvidenceRefresh();
  return <KnowledgeWorkspace apiBase={apiBase} local={{ ...refresh, parseRecords: parseLocalRecords, parseSearch: parseLocalSearch }} />;
}
