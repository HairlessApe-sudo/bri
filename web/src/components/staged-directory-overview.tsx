'use client';

import { useLayoutEffect, useMemo, useSyncExternalStore } from 'react';
import { StagedApprovalQueue } from '@/components/privileged-approvals';
import { UserDirectory } from '@/components/user-directory';
import { checkApprovalQueueAccess, type ApprovalStepUp, type ApprovalTransport } from '@/lib/privileged-approvals';

type Phase = 'idle' | 'checking' | 'unavailable' | 'authorized' | 'open';

export function createOverviewQueueGate(transport: ApprovalTransport) {
  let phase: Phase = 'idle';
  let pending: AbortController | undefined;
  const listeners = new Set<() => void>();
  const getSnapshot = () => phase;
  function subscribe(listener: () => void) {
    listeners.add(listener);
    return () => { listeners.delete(listener); };
  }
  function setPhase(next: Phase) {
    if (next === phase) return;
    phase = next;
    for (const listener of listeners) listener();
  }
  async function check() {
    if (phase !== 'idle' && phase !== 'unavailable') return;
    const controller = new AbortController();
    pending = controller;
    setPhase('checking');
    const allowed = await checkApprovalQueueAccess(transport, controller.signal);
    if (controller.signal.aborted || pending !== controller) return;
    pending = undefined;
    setPhase(allowed ? 'authorized' : 'unavailable');
  }
  function open() { if (phase === 'authorized') setPhase('open'); }
  function leaveOverview() {
    pending?.abort();
    pending = undefined;
    if (phase !== 'open') setPhase('idle');
  }
  function closeQueue() { if (phase === 'open') setPhase('idle'); }
  return { getSnapshot, subscribe, check, open, leaveOverview, closeQueue };
}

type Gate = ReturnType<typeof createOverviewQueueGate>;

export function OverviewQueueEntry({ gate, phase }: { gate: Gate; phase: Phase }) {
  if (phase === 'open') return null;
  return <div aria-label="MFA reset queue access">
    {phase === 'authorized'
      ? <button className="source-pill" type="button" onClick={gate.open}>Open MFA reset queue</button>
      : <button className="source-pill" type="button" disabled={phase === 'checking'} onClick={() => void gate.check()}>Check MFA reset queue access</button>}
    {phase === 'unavailable' && <p role="status">MFA reset queue access could not be verified.</p>}
  </div>;
}

function OverviewQueueAction({ gate, phase }: { gate: Gate; phase: Phase }) {
  useLayoutEffect(() => gate.leaveOverview, [gate]);
  return <OverviewQueueEntry gate={gate} phase={phase} />;
}

// Staged harness only. scopeKey identifies the current verified viewer/session/scope
// and must change when that context changes, even if the injected functions do not.
export function StagedDirectoryOverview({ scopeKey, transport, stepUp }: {
  scopeKey: string; transport: ApprovalTransport; stepUp: ApprovalStepUp;
}) {
  const gate = useMemo(() => createOverviewQueueGate(transport), [scopeKey, transport, stepUp]);
  const phase = useSyncExternalStore(gate.subscribe, gate.getSnapshot, gate.getSnapshot);
  if (phase === 'open') return <>
    <button className="source-pill" type="button" onClick={gate.closeQueue}>Back to directory</button>
    <StagedApprovalQueue transport={transport} stepUp={stepUp} />
  </>;
  return <UserDirectory key={scopeKey} enabled overviewActions={<OverviewQueueAction gate={gate} phase={phase} />} />;
}
