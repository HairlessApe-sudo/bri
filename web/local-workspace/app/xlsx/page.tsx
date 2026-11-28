'use client';

import { useLayoutEffect, useRef, useState } from 'react';
import { useEvidenceRefresh } from '../refresh';
import { IntakeForms } from './intake-forms';
import { ClassifiedIntake } from './classified-intake';
import { readJob, uploadWorkbook } from './client.mjs';

export default function XlsxIntakePage() {
  const { parked, refreshKey } = useEvidenceRefresh();
  return parked ? null : <Intake refreshKey={refreshKey} />;
}

function Intake({ refreshKey }: { refreshKey: number }) {
  return <>
    <h1>XLSX intake</h1>
    <p>Upload a local synthetic workbook, or check the status of a previous submission.</p>
    <ul><li><a href="/xlsx/review">XLSX review queue</a></li>
      <li><a href="/xlsx/knowledge">Published XLSX records</a></li></ul>
    <ClassifiedIntake refreshKey={refreshKey} />
    <LegacyIntake key={refreshKey} />
  </>;
}

function LegacyIntake() {
  const lifetime = useRef<AbortController | null>(null);
  const busy = useRef(false);
  const [pending, setPending] = useState(false);
  const [receipt, setReceipt] = useState<Awaited<ReturnType<typeof readJob>> | null>(null);
  const [error, setError] = useState('');
  useLayoutEffect(() => {
    lifetime.current = new AbortController();
    return () => { lifetime.current?.abort(); lifetime.current = null; };
  }, []);

  async function run(load: (signal: AbortSignal) => ReturnType<typeof readJob>, upload = false) {
    const signal = lifetime.current?.signal;
    if (busy.current || !signal || signal.aborted) return;
    busy.current = true;
    setPending(true); setReceipt(null); setError('');
    try {
      const next = await load(signal);
      if (!signal.aborted) setReceipt(next);
    } catch (err) {
      if (!signal.aborted) {
        const status = (err as { status?: number }).status;
        setError(status === 401 ? 'A current signed fixture session is required.' : status === 403 ? 'Access denied.'
          : status === 404 ? 'XLSX job not found.' : upload ? 'Upload was not confirmed. No automatic retry was sent.' : 'Could not check job status.');
      }
    } finally {
      if (!signal.aborted) { busy.current = false; setPending(false); }
    }
  }

  return <>
    <IntakeForms disabled={pending} onUpload={(file, node) => void run(
      (signal) => uploadWorkbook(fetch, file, node, crypto.randomUUID(), signal), true,
    )} onStatus={(id) => void run((signal) => readJob(fetch, id, signal))} />
    {pending && <p role="status">Checking XLSX intake…</p>}
    {receipt && <p role="status">Job <code>{receipt.id}</code> · {receipt.state}</p>}
    {error && <p role="alert">{error}</p>}
  </>;
}
