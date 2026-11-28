'use client';

import { createContext, useContext, useState, type ReactNode } from 'react';
import { ExactMetadata, type ExactTarget } from '../../classification/exact';

const CorrectionsEnabled = createContext(false);

export function EvidenceCorrectionMode({ enabled, children }: { enabled: boolean; children: ReactNode }) {
  return <CorrectionsEnabled.Provider value={enabled}>{children}</CorrectionsEnabled.Provider>;
}

export function EvidenceCorrection({ format, record, version, refresh }: ExactTarget & { refresh: () => void }) {
  const enabled = useContext(CorrectionsEnabled);
  const [open, setOpen] = useState(false);
  if (!enabled) return null;
  return open ? <><ExactMetadata format={format} record={record} version={version} refresh={refresh} />
    <button type="button" onClick={() => setOpen(false)}>Close exact-version metadata</button></>
    : <button type="button" onClick={() => setOpen(true)}>Open exact-version metadata and corrections</button>;
}
