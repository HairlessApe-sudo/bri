'use client';

import { useCallback, useLayoutEffect, useRef, useState, type FormEvent } from 'react';
import { flushSync } from 'react-dom';
import { createAdministrationLifecycle, prepareSubmission, readCatalogueVisibility, readJob, readSessionContext,
  readSubmissionSelection, uploadSubmission } from '../../../administration-client.mjs';
import { isJobId } from '../../../administration-contract.mjs';
import { xlsxNode } from '../../../xlsx-intake.mjs';
import { MetadataError, MetadataFields, readMetadataForm, statusOf } from '../../classification/fields';

const nodePattern = '[A-Za-z0-9][A-Za-z0-9_.:\\-]{0,127}';
const jobPattern = '[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}';
type Format = 'csv' | 'xlsx';
type Selection = Awaited<ReturnType<typeof readSubmissionSelection>>;
type Receipt = Awaited<ReturnType<typeof readJob>>;
type Command = ReturnType<typeof prepareSubmission>;
type SignedContext = { context: string; signal: AbortSignal; generation: number };
type Scope = SignedContext & { lifecycle: ReturnType<typeof createAdministrationLifecycle>; retire: (status: number, uncertain?: boolean) => void };
const sensitiveFailure = (status: number) => [401, 403, 404, 502].includes(status);

type Submission = { phase: 'draft' } | { phase: 'uploading' }
  | { phase: 'confirmed'; receipt: Receipt; format: Format }
  | { phase: 'rejected' }
  | { phase: 'uncertain'; command: Command; confirmingAbandon: boolean };
const draft: Submission = { phase: 'draft' };
const recoveryLocked = (state: Submission) => state.phase === 'uploading' || state.phase === 'uncertain';

export function AdministrationWorkspace() {
  const lifecycle = useRef(createAdministrationLifecycle()).current;
  const current = useRef<SignedContext | null>(null);
  const generation = useRef(0);
  const [context, publish] = useState<SignedContext | null>(null);
  const [error, setError] = useState<number | null>(null);
  const [retiredUpload, showRetiredUpload] = useState(false);
  const [catalogueRefresh, refreshCatalogue] = useState(0);
  const retire = useCallback((status: number | null = null, uncertain = false) => {
    lifecycle.clear();
    current.current = null;
    publish(null);
    setError(status);
    showRetiredUpload(uncertain);
  }, [lifecycle]);

  const verify = useCallback(async (open: boolean) => {
    if (!open && !current.current) return;
    const request = lifecycle.begin('session');
    try {
      const next = await readSessionContext(fetch, request.signal);
      if (!request.current()) return;
      if (current.current && current.current.context !== next) return retire(401);
      current.current ??= { context: next, signal: lifecycle.begin('context').signal, generation: ++generation.current };
      publish(current.current);
      setError(null);
      if (!open) refreshCatalogue((value) => value + 1);
    } catch (error) {
      if (request.current()) retire(statusOf(error));
    }
  }, [lifecycle, retire]);

  useLayoutEffect(() => {
    const onFocus = () => void verify(false);
    const onVisible = () => { if (document.visibilityState === 'visible') onFocus(); };
    const onHide = () => flushSync(() => retire());
    const onShow = (event: PageTransitionEvent) => { if (event.persisted) void verify(true); };
    window.addEventListener('focus', onFocus);
    window.addEventListener('pagehide', onHide);
    window.addEventListener('pageshow', onShow);
    document.addEventListener('visibilitychange', onVisible);
    void verify(true);
    return () => {
      lifecycle.clear();
      current.current = null;
      window.removeEventListener('focus', onFocus);
      window.removeEventListener('pagehide', onHide);
      window.removeEventListener('pageshow', onShow);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, [lifecycle, retire, verify]);

  const scope = context && { ...context, lifecycle, retire };
  return <>
    <p><button type="button" aria-describedby="administration-context-clear"
      onClick={() => { retire(); void verify(true); }}>Clear workspace context</button></p>
    <p id="administration-context-clear">Clearing workspace context discards any browser recovery state. It does not cancel a submission that may already exist.</p>
    {!scope ? error ? <>
      <MetadataError status={error} />
      {retiredUpload && <p role="status">Recovery ended because access could not be confirmed. A previous submission may already exist.</p>}
    </> : <p role="status">Checking the current signed fixture session…</p>
      : <div key={scope.generation}>
        <CatalogueVisibility {...scope} refresh={catalogueRefresh} />
        <SubmitKnowledge {...scope} />
        <MySubmissions {...scope} />
      </div>}
  </>;
}

function CatalogueVisibility({ context, lifecycle, retire, refresh }: Scope & { refresh: number }) {
  const [verified, show] = useState<number | null>(null);
  const check = useCallback(async () => {
    const request = lifecycle.begin('catalogue');
    show(null);
    try {
      const value = await readCatalogueVisibility(fetch, context, request.signal);
      if (request.current() && value) show(refresh);
    } catch (error) {
      const status = statusOf(error);
      // Catalogue authority is independent of submit authority. A signed-session
      // mismatch is reported separately (401) by the bridge.
      if (request.current() && [401, 502].includes(status)) retire(status);
    }
  }, [context, lifecycle, retire, refresh]);
  useLayoutEffect(() => { void check(); return () => lifecycle.cancel('catalogue'); }, [check, lifecycle]);
  return <p><button type="button" onClick={() => void check()}>Check catalogue access</button>{' '}
    {verified === refresh && <a href="/classification">Classification catalogue</a>}</p>;
}

function FormatChoice({ label, format, edit, disabled = false }: {
  label: string; format: Format | ''; edit: (format: Format | '') => void; disabled?: boolean;
}) {
  return <label>{label} <select required value={format} disabled={disabled} onChange={(event) => edit(event.target.value as Format | '')}>
    <option value="">Choose a format</option><option value="csv">CSV</option><option value="xlsx">XLSX</option>
  </select></label>;
}

function SubmitKnowledge({ context, signal, lifecycle, retire }: Scope) {
  const [format, setFormat] = useState<Format | ''>('');
  const [node, setNode] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [selection, setSelection] = useState<Selection | null>(null);
  const [message, setMessage] = useState<number | null>(null);
  const [checking, setChecking] = useState(false);
  const [submission, renderSubmission] = useState<Submission>(draft);
  // Event guards must see transitions immediately, before React commits disabled controls.
  const currentSubmission = useRef<Submission>(draft);
  function transition(next: Submission) {
    currentSubmission.current = next;
    renderSubmission(next);
  }
  useLayoutEffect(() => () => {
    currentSubmission.current = draft;
    lifecycle.cancel('selection', 'upload');
  }, [lifecycle, signal]);

  const fileInput = useRef<HTMLInputElement>(null);
  const clearFile = () => { setFile(null); if (fileInput.current) fileInput.current.value = ''; };
  function editScope() {
    if (signal.aborted || recoveryLocked(currentSubmission.current)) return false;
    lifecycle.cancel('selection');
    setSelection(null);
    setMessage(null);
    setChecking(false);
    transition(draft);
    return true;
  }
  async function load() {
    if (signal.aborted || recoveryLocked(currentSubmission.current)) return;
    if (!format || !xlsxNode.test(node)) { setMessage(422); return; }
    const request = lifecycle.begin('selection');
    transition(draft);
    setMessage(null); setSelection(null); setChecking(true);
    try {
      const options = await readSubmissionSelection(fetch, context, format, node, request.signal);
      if (request.current()) setSelection(options);
    } catch (error) {
      if (!request.current()) return;
      const status = statusOf(error);
      if (sensitiveFailure(status)) retire(status);
      else { clearFile(); setMessage(status); }
    } finally { if (request.current()) setChecking(false); }
  }
  async function send(command: Command, recovering: boolean) {
    if (signal.aborted) return;
    transition({ phase: 'uploading' });
    lifecycle.cancel('selection');
    const request = lifecycle.begin('upload');
    setChecking(false); setMessage(null); setSelection(null); clearFile();
    try {
      const receipt = await uploadSubmission(fetch, context, command, request.signal);
      if (request.current()) transition({ phase: 'confirmed', receipt, format: command.format });
    } catch (error) {
      if (!request.current()) return;
      const status = statusOf(error);
      const outcome = (error as { outcome?: string } | null)?.outcome;
      if (outcome === 'retired') retire(status, true);
      // A denial of this retry cannot prove the original request did not commit.
      else if (outcome === 'rejected' && !recovering) transition({ phase: 'rejected' });
      else transition({ phase: 'uncertain', command, confirmingAbandon: false });
    }
  }
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (signal.aborted || !selection || !format || !file || recoveryLocked(currentSubmission.current)) return;
    try {
      const metadata = readMetadataForm(event.currentTarget, selection);
      void send(prepareSubmission(format, file, node, crypto.randomUUID(), metadata, context), false);
    } catch { setMessage(422); }
  }
  function retry() {
    const current = currentSubmission.current;
    if (current.phase === 'uncertain' && !current.confirmingAbandon) void send(current.command, true);
  }
  function confirmAbandon(show: boolean) {
    const current = currentSubmission.current;
    if (!signal.aborted && current.phase === 'uncertain') transition({ ...current, confirmingAbandon: show });
  }
  function abandon() {
    const current = currentSubmission.current;
    if (signal.aborted || current.phase !== 'uncertain' || !current.confirmingAbandon) return;
    transition(draft);
    setFormat(''); setNode('');
  }

  const frozen = recoveryLocked(submission);
  return <section className="content-panel" aria-labelledby="classified-submit-title">
    <h2 id="classified-submit-title">Submit classified knowledge</h2>
    <p>Choose one format and an exact source node. Use a synthetic file, up to 5 MB.</p>
    <form onSubmit={submit}>
      <p><FormatChoice label="Submission format" format={format} disabled={frozen} edit={(next) => {
        if (editScope()) { clearFile(); setFormat(next); }
      }} /></p>
      <p><label>Source node ID <input value={node} required pattern={nodePattern} maxLength={128} autoComplete="off" disabled={frozen}
        onChange={(event) => { if (editScope()) { if (selection || checking) clearFile(); setNode(event.target.value); } }} /></label></p>
      <p><label>Submission file <input ref={fileInput} type="file" required disabled={!format || frozen} accept={format ? `.${format}` : undefined}
        onChange={(event) => {
          if (signal.aborted || recoveryLocked(currentSubmission.current)) return;
          if (file || currentSubmission.current.phase !== 'draft') editScope();
          setFile(event.target.files?.item(0) ?? null);
        }} /></label></p>
      <button type="button" onClick={() => void load()} disabled={!format || frozen || checking}>Load submission classifications</button>
      {selection && (selection.length === 0 ? <p>No active classifications are available for this submission.</p> : <>
        <MetadataFields options={selection} />
        <button type="submit" disabled={!file || frozen}>Submit classified file</button>
      </>)}
    </form>
    {checking && <p role="status">Checking submission classifications…</p>}
    {submission.phase === 'uploading' && <p role="status">Submitting classified file…</p>}
    {message && <MetadataError status={message} />}
    {submission.phase === 'rejected' && <p role="alert">Submission rejected. No submission was created by this attempt. Check the file and inputs before starting another submission.</p>}
    {submission.phase === 'uncertain' && <>
      <p role="alert">Submission outcome unknown. The original submission may already exist.</p>
      {submission.confirmingAbandon ? <div role="group" aria-label="Confirm abandonment of submission recovery">
        <p role="alert">The original submission may already exist. Abandoning recovery does not cancel it. Starting a new submission could create a duplicate.</p>
        <button type="button" onClick={() => confirmAbandon(false)}>Keep recovering</button>{' '}
        <button type="button" onClick={abandon}>Abandon recovery and allow a new submission</button>
      </div> : <p>
        <button type="button" onClick={retry}>Retry the same submission</button>{' '}
        <button type="button" onClick={() => confirmAbandon(true)}>Abandon recovery…</button>
      </p>}
    </>}

    {submission.phase === 'confirmed' && <div role="status" aria-label="Submission acknowledgement">
      <p>Submission acknowledgement · {submission.format.toUpperCase()} job <code>{submission.receipt.id}</code> · <strong>{submission.receipt.state}</strong></p>
      <p>This is not approval or publication. Check current status separately in My Submissions.</p>
    </div>}
  </section>;
}

function MySubmissions({ context, lifecycle, retire }: Scope) {
  const [format, setFormat] = useState<Format | ''>('');
  const [id, setId] = useState('');
  const [status, setStatus] = useState<Receipt | null>(null);
  const [message, setMessage] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  function edit() { lifecycle.cancel('status'); setStatus(null); setMessage(null); setBusy(false); }
  async function check(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    edit();
    if (!format || !isJobId(id)) { setMessage(422); return; }
    const request = lifecycle.begin('status');
    setBusy(true);
    try {
      const result = await readJob(fetch, context, format, id, request.signal);
      if (request.current()) setStatus(result);
    } catch (error) {
      if (!request.current()) return;
      const code = statusOf(error);
      if (sensitiveFailure(code)) retire(code);
      else { setId(''); setMessage(code); }
    } finally { if (request.current()) setBusy(false); }
  }
  return <section className="content-panel" aria-labelledby="my-submissions-title">
    <h2 id="my-submissions-title">My Submissions</h2>
    <p>Enter the exact job UUID and choose its format. Check again to refresh; this does not list any jobs.</p>
    <form onSubmit={(event) => void check(event)}>
      <p><FormatChoice label="Job format" format={format} edit={(next) => { edit(); setId(''); setFormat(next); }} /></p>
      <p><label>Job ID <input value={id} required pattern={jobPattern} maxLength={36} autoComplete="off" spellCheck={false}
        onChange={(event) => { edit(); setId(event.target.value); }} /></label></p>
      <button type="submit">Check job status</button>
    </form>
    {busy && <p role="status">Checking exact job status…</p>}
    {message && <MetadataError status={message} />}
    {status && <div role="status" aria-label="Current job status">
      <p>{format.toUpperCase()} job <code>{status.id}</code> · <strong>{status.state}</strong></p>
      <p>Job status does not establish current publication or access.</p>
    </div>}
  </section>;
}
