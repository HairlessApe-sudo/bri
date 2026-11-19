'use client';

import { useLayoutEffect, useMemo, useSyncExternalStore, type FormEvent } from 'react';
import { DirectoryDetail } from '@/components/user-directory-view';
import type { DirectoryUser } from '@/lib/api';
import {
  approvalReasons, approvalStates, createApprovalQueueFlow, createApprovalRequestFlow, reconciliationLabels,
  type ApprovalQueueView, type ApprovalRequestView, type ApprovalStepUp, type ApprovalTransport,
} from '@/lib/privileged-approvals';
import { isDirectoryUserId } from '@/lib/user-directory.mjs';

type RequestFlow = ReturnType<typeof createApprovalRequestFlow>;
type QueueFlow = ReturnType<typeof createApprovalQueueFlow>;
type StagedDependencies = { transport: ApprovalTransport; stepUp: ApprovalStepUp };

function ApprovalReceipt({ receipt }: { receipt: NonNullable<ApprovalRequestView['receipt']> }) {
  return <p role="status">Server-confirmed status: {approvalStates[receipt.state]}.{' '}
    Approval ID: <span className="mono breakable">{receipt.approval_id}</span>.{' '}
    Correlation ID: <span className="mono breakable">{receipt.correlation_id}</span>.</p>;
}

export function ApprovalRequestPanel({ view, flow }: { view: ApprovalRequestView; flow: RequestFlow }) {
  const { phase, eligible, reason, retry, error, receipt } = view;
  const busy = phase === 'loading' || phase === 'saving';
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void flow.submit();
  }
  return <section aria-label="MFA reset request">
    <h3>MFA reset request</h3>
    <p>Submitting requires a recent verified TOTP challenge. A request does not remove a factor or restore access.</p>
    {!receipt && <button type="button" className="source-pill" disabled={busy} onClick={() => void flow.reload()}>
      {phase === 'idle' ? 'Check MFA reset eligibility' : 'Reload MFA reset eligibility'}
    </button>}
    {phase === 'loading' && <p role="status">Checking eligibility…</p>}
    {phase === 'saving' && <p role="status">Waiting for step-up and server confirmation…</p>}
    {phase === 'ready' && !eligible && <p role="status">An MFA reset request is not available for this account.</p>}
    {error && <p className="auth-error" role="alert">{error}</p>}
    {receipt && <ApprovalReceipt receipt={receipt} />}
    {phase === 'ready' && eligible && <form className="auth-form directory-create" method="post" onSubmit={submit}>
      {retry && <p>The previous outcome was not confirmed. Retrying uses the same request ID and reason.</p>}
      <label>MFA reset reason
        <select name="reason" value={reason} required disabled={retry} onChange={(event) => flow.chooseReason(event.currentTarget.value)}>
          <option value="">Select a reason</option>
          {Object.entries(approvalReasons).map(([code, label]) => <option key={code} value={code}>{label}</option>)}
        </select>
      </label>
      <button type="submit" className="auth-submit" disabled={!reason}>{retry ? 'Retry same MFA reset request' : 'Submit MFA reset request'}</button>
    </form>}
  </section>;
}

function StagedRequest({ id, transport, stepUp }: StagedDependencies & { id: string }) {
  const flow = useMemo(() => createApprovalRequestFlow(id, transport, stepUp), [id, transport, stepUp]);
  useLayoutEffect(() => flow.cancelPending, [flow]);
  const view = useSyncExternalStore(flow.subscribe, flow.getSnapshot, flow.getSnapshot);
  return <ApprovalRequestPanel view={view} flow={flow} />;
}

// Isolated harness composition. No release route imports either staged entry point.
export function StagedApprovalDetail({ data, onBack, transport, stepUp }: StagedDependencies & {
  data: DirectoryUser; onBack: () => void;
}) {
  const showRequest = data.status === 'active' && data.role === 'user' && isDirectoryUserId(data.id);
  return <DirectoryDetail data={data} onBack={onBack}>
    {showRequest && <StagedRequest id={data.id} transport={transport} stepUp={stepUp} />}
  </DirectoryDetail>;
}

export function ApprovalQueuePanel({ view, flow }: { view: ApprovalQueueView; flow: QueueFlow }) {
  const { phase, page, pageNumber, error, receipt } = view;
  const busy = phase === 'loading' || phase === 'saving';
  return <section className="content-panel" aria-label="MFA reset approval queue">
    <h2>MFA reset approval queue</h2>
    <p>Approval is separate from execution. Confirmed factor removal does not confirm re-enrollment or restored access.</p>
    <p>Decisions require a recent verified TOTP challenge.</p>
    <button type="button" className="source-pill" disabled={busy} onClick={() => void flow.reload()}>
      {phase === 'idle' ? 'Load approval queue' : 'Reload approval queue'}
    </button>
    {phase === 'loading' && <p role="status">Loading approvals…</p>}
    {phase === 'saving' && <p role="status">Waiting for step-up and server confirmation…</p>}
    {error && <p className="auth-error" role="alert">{error}</p>}
    {receipt && <><ApprovalReceipt receipt={receipt} /><p>Reload the queue to see the latest state.</p></>}
    {page?.items.length === 0 && <p role="status">No approval requests on this page.</p>}
    {page && page.items.length > 0 && <ul className="directory-list">
      {page.items.map((row) => <li key={row.approval_id}>
        <h3>{row.target_name || 'Unnamed user'}</h3>
        <dl className="provenance-grid">
          <div><dt>Target ID</dt><dd className="mono breakable">{row.target_id}</dd></div>
          <div><dt>Approval ID</dt><dd className="mono breakable">{row.approval_id}</dd></div>
          <div><dt>Requester</dt><dd>{row.requester_label}</dd></div>
          <div><dt>Reason</dt><dd>{approvalReasons[row.reason]}</dd></div>
          <div><dt>Requested</dt><dd><time dateTime={row.requested_at}>{row.requested_at}</time></dd></div>
          <div><dt>Expires</dt><dd><time dateTime={row.expires_at}>{row.expires_at}</time></dd></div>
          <div><dt>Status</dt><dd>{approvalStates[row.state]}</dd></div>
          <div><dt>Reconciliation</dt><dd>{reconciliationLabels[row.reconciliation]}</dd></div>
        </dl>
        {row.state === 'PENDING' && row.can_decide && <div>
          <button type="button" className="source-pill" disabled={phase !== 'ready'} aria-label={`Approve request ${row.approval_id}`} onClick={() => void flow.decide(row.approval_id, 'APPROVE')}>Approve</button>{' '}
          <button type="button" className="source-pill" disabled={phase !== 'ready'} aria-label={`Reject request ${row.approval_id}`} onClick={() => void flow.decide(row.approval_id, 'REJECT')}>Reject</button>
        </div>}
      </li>)}
    </ul>}
    {(page || pageNumber > 1) && <nav aria-label="Approval queue pages">
      <button type="button" className="source-pill" disabled={busy || pageNumber === 1} onClick={() => void flow.previous()}>Previous</button>{' '}
      <span>Page {pageNumber}</span>{' '}
      <button type="button" className="source-pill" disabled={phase !== 'ready' || !page?.next_cursor} onClick={() => void flow.next()}>Next</button>
    </nav>}
  </section>;
}

export function StagedApprovalQueue({ transport, stepUp }: StagedDependencies) {
  const flow = useMemo(() => createApprovalQueueFlow(transport, stepUp), [transport, stepUp]);
  useLayoutEffect(() => flow.cancelPending, [flow]);
  const view = useSyncExternalStore(flow.subscribe, flow.getSnapshot, flow.getSnapshot);
  return <ApprovalQueuePanel view={view} flow={flow} />;
}
