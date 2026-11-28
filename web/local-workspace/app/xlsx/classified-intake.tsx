'use client';

import { useCallback, useState, type FormEvent } from 'react';
import { xlsxNode } from '../../xlsx-intake.mjs';
import { readSelection, uploadClassifiedWorkbook } from '../classification/client.mjs';
import { MetadataError, MetadataFields, readMetadataForm, useAction } from '../classification/fields';
import { useAuthorizedRead } from './read';

export function ClassifiedIntake({ refreshKey }: { refreshKey: number }) {
  const [node, editNode] = useState('');
  const [scope, setScope] = useState<{ node: string; refreshKey: number } | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const active = scope?.refreshKey === refreshKey && scope.node === node;
  return <section className="content-panel" aria-label="Classified XLSX submission">
    <h2>Submit a classified workbook</h2>
    <p>Choose a synthetic XLSX workbook, then load classifications available for its exact source node.</p>
    <p><label>Classified workbook <input type="file" accept=".xlsx" onChange={(event) => {
      setFile(event.target.files?.item(0) ?? null); setScope(null);
    }} /></label></p>
    <form onSubmit={(event) => { event.preventDefault(); if (file && xlsxNode.test(node)) { setScope({ node, refreshKey }); } }}>
      <p><label>Classified source node ID <input value={node} onChange={(event) => { editNode(event.target.value); setScope(null); }}
        required pattern="[A-Za-z0-9][A-Za-z0-9_.:\-]{0,127}" maxLength={128} autoComplete="off" /></label>{' '}
        <button type="submit" disabled={!file || Boolean(active)}>Load submission classifications</button></p>
    </form>
    {file && active && <Submission key={`${refreshKey}:${node}`} file={file} node={node} />}
  </section>;
}

function Submission({ file, node }: { file: File; node: string }) {
  const load = useCallback((signal: AbortSignal) => readSelection(fetch, 'xlsx_submit', node, signal), [node]);
  const selection = useAuthorizedRead(load);
  const { action, run } = useAction<Awaited<ReturnType<typeof uploadClassifiedWorkbook>>>();
  const [invalid, setInvalid] = useState(false);
  if (action && 'pending' in action) return <p role="status">Submitting classified workbook…</p>;
  if (action && 'error' in action) return <MetadataError status={action.error} retry />;
  if (action && 'result' in action) return <p role="status">Job <code>{action.result.id}</code> · {action.result.state}</p>;
  if (!selection) return <p role="status">Checking available classifications…</p>;
  if (!selection.data) return <MetadataError status={selection.error ?? 502} />;
  if (!selection.data.length) return <p>No active classifications are available for this submission.</p>;
  const options = selection.data;
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    try {
      const input = readMetadataForm(event.currentTarget, options);
      setInvalid(false);
      void run((signal) => uploadClassifiedWorkbook(fetch, file, node, crypto.randomUUID(), input, signal));
    } catch { setInvalid(true); }
  }
  return <form onSubmit={submit}>
    <MetadataFields options={options} />
    {invalid && <p role="alert">Check the fields, text lengths and classification selections.</p>}
    <button type="submit">Upload classified workbook</button>
  </form>;
}
