import { isDirectoryUserId } from './user-directory.mjs';

const prefix = '/v1/privileged-approvals';
export const approvalReasons = {
  LOST_FACTOR: 'Lost factor',
  REPLACED_DEVICE: 'Replaced device',
  COMPROMISED_FACTOR: 'Compromised factor',
} as const;
export const approvalStates = {
  PENDING: 'Awaiting approval',
  APPROVED: 'Approved — execution not confirmed',
  EXECUTING: 'Execution in progress',
  COMPLETED: 'MFA factor removal confirmed',
  REJECTED: 'Rejected',
  EXPIRED: 'Expired',
  FAILED: 'Execution failed',
} as const;

type Reason = keyof typeof approvalReasons;
type State = keyof typeof approvalStates;
type Receipt = { approval_id: string; state: State; correlation_id: string };
export type ApprovalTransport = (path: string, init: RequestInit) => Promise<Response>;
// Prepares the staged session only. Each POST must independently verify fresh TOTP
// on the server; do not supply browser timestamps, authority fields or proof in the body.
export type ApprovalStepUp = (action: 'request' | 'decision', signal: AbortSignal) => Promise<void>;
type Phase = 'idle' | 'loading' | 'ready' | 'saving' | 'reload' | 'confirmed';
type View = { phase: Phase; receipt?: Receipt; error?: string };

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function known<T extends object>(values: T, value: unknown): value is Extract<keyof T, string> {
  return typeof value === 'string' && Object.hasOwn(values, value);
}
function receipt(value: unknown, id: string): Receipt {
  if (!record(value) || typeof value.approval_id !== 'string' || value.approval_id.toLowerCase() !== id.toLowerCase() ||
    !known(approvalStates, value.state) || typeof value.correlation_id !== 'string' || !isDirectoryUserId(value.correlation_id)) {
    throw new Error('Invalid approval receipt');
  }
  return { approval_id: value.approval_id, state: value.state, correlation_id: value.correlation_id };
}

class ApprovalHttpError extends Error {
  readonly status: number;
  constructor(status: number) {
    super('Approval operation denied or unavailable');
    this.status = status;
  }
}

async function readJson(transport: ApprovalTransport, signal: AbortSignal, path: string, body?: object): Promise<unknown> {
  const response = await transport(path, {
    method: body ? 'POST' : 'GET', cache: 'no-store', signal,
    ...(body && { headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
  });
  if (!response.ok) throw new ApprovalHttpError(response.status);
  return response.json();
}

function safeError(error: unknown, fallback: string) {
  if (error instanceof ApprovalHttpError) {
    if (error.status === 401 || error.status === 403) return 'A verified session and approval access are required. For changes, verify your authenticator and reload.';
    if (error.status === 404) return 'Approval information is unavailable. Reload to check again.';
    if (error.status === 409 || error.status === 412) return 'The approval operation conflicts with server state. Reload to check again.';
  }
  return fallback;
}

// One store per staged context. Cancellation also prevents a late step-up from sending a POST.
function store<T extends View>(initial: T, transport: ApprovalTransport, stepUp: ApprovalStepUp) {
  if (typeof transport !== 'function' || typeof stepUp !== 'function') throw new Error('Staged approval dependencies are required');
  let view = initial;
  let operation: AbortController | undefined;
  const listeners = new Set<() => void>();
  const getSnapshot = () => view;
  function subscribe(listener: () => void) {
    listeners.add(listener);
    return () => { listeners.delete(listener); };
  }
  function update(next: Partial<T>) {
    view = { ...view, ...next };
    for (const listener of listeners) listener();
  }
  function begin(next: Partial<T>) {
    if (operation) return;
    const controller = new AbortController();
    operation = controller;
    update(next);
    return controller.signal;
  }
  function finish(signal: AbortSignal, next: Partial<T>) {
    if (signal.aborted) return;
    operation = undefined;
    update(next);
  }
  function cancelPending() { operation?.abort(); }
  return { getSnapshot, subscribe, update, begin, finish, cancelPending };
}

export type ApprovalRequestView = View & { eligible: boolean; reason: Reason | ''; retry: boolean };

export function createApprovalRequestFlow(target: string, transport: ApprovalTransport, stepUp: ApprovalStepUp) {
  if (!isDirectoryUserId(target)) throw new Error('Invalid user ID');
  const { getSnapshot, subscribe, begin, finish, update, cancelPending } = store<ApprovalRequestView>(
    { phase: 'idle', eligible: false, reason: '', retry: false }, transport, stepUp,
  );
  let ambiguous: { reason: Reason; request_id: string } | undefined;

  async function reload() {
    if (getSnapshot().phase === 'confirmed') return;
    const signal = begin({ phase: 'loading', eligible: false, error: undefined });
    if (!signal) return;
    try {
      const result = await readJson(transport, signal, `${prefix}/eligibility/${target}`);
      if (!record(result) || typeof result.eligible !== 'boolean') throw new Error('Invalid eligibility');
      finish(signal, { phase: 'ready', eligible: result.eligible });
    } catch (error) {
      finish(signal, { phase: 'reload', error: safeError(error, 'Could not check eligibility. Reload to try again.') });
    }
  }

  function chooseReason(reason: string) {
    const view = getSnapshot();
    if (view.phase !== 'ready' || !view.eligible || ambiguous || (reason !== '' && !known(approvalReasons, reason))) return;
    update({ reason });
  }

  async function submit() {
    const { phase, eligible, reason } = getSnapshot();
    if (phase !== 'ready' || !eligible || !reason) return;
    const signal = begin({ phase: 'saving', error: undefined });
    if (!signal) return;
    let submitted: typeof ambiguous;
    try {
      await stepUp('request', signal);
      if (signal.aborted) return;
      submitted = ambiguous ?? { reason, request_id: crypto.randomUUID() };
      const reply = await readJson(transport, signal, prefix, { target, ...submitted });
      if (signal.aborted) return;
      const confirmed = receipt(reply, submitted.request_id);
      ambiguous = undefined;
      finish(signal, { phase: 'confirmed', retry: false, receipt: confirmed });
    } catch (error) {
      if (signal.aborted) return;
      if (submitted && !(error instanceof ApprovalHttpError && [400, 401, 403, 404, 409, 412, 422].includes(error.status))) {
        ambiguous = submitted;
      }
      finish(signal, { phase: 'reload', eligible: false, retry: !!ambiguous,
        error: !submitted ? 'Step-up could not be completed. Reload eligibility before trying again.'
          : safeError(error, 'The request outcome could not be confirmed. Reload eligibility before explicitly retrying.') });
    }
  }

  return { getSnapshot, subscribe, reload, chooseReason, submit, cancelPending };
}

export const reconciliationLabels = {
  NONE: 'No reconciliation reported',
  PENDING: 'Reconciliation pending',
  UNRESOLVED: 'Reconciliation unresolved',
  SAFE_HANDOFF: 'Safe handoff recorded',
  VERIFIED_ABSENT: 'Factor absence verified',
} as const;
type Decision = 'APPROVE' | 'REJECT';
type QueueRow = {
  approval_id: string; target_id: string; target_name: string | null;
  requester_label: 'Restricted requester'; reason: Reason; requested_at: string; expires_at: string;
  state: State; reconciliation: keyof typeof reconciliationLabels; can_decide: boolean;
};
type QueuePage = { items: QueueRow[]; next_cursor: string | null };
export type ApprovalQueueView = View & { page?: QueuePage; pageNumber: number };
const pageLimit = 25;

function timestamp(value: unknown): value is string {
  return typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/.test(value) && Number.isFinite(Date.parse(value));
}

function queuePage(value: unknown): QueuePage {
  if (!record(value) || !Array.isArray(value.items) || value.items.length > pageLimit ||
    (value.next_cursor !== null && (typeof value.next_cursor !== 'string' || !value.next_cursor))) {
    throw new Error('Invalid approval page');
  }
  const seen = new Set<string>();
  const items = value.items.map((row: unknown): QueueRow => {
    if (!record(row) || typeof row.approval_id !== 'string' || !isDirectoryUserId(row.approval_id) ||
      typeof row.target_id !== 'string' || !isDirectoryUserId(row.target_id) ||
      (row.target_name !== null && typeof row.target_name !== 'string') || row.requester_label !== 'Restricted requester' ||
      !known(approvalReasons, row.reason) || !known(approvalStates, row.state) || !known(reconciliationLabels, row.reconciliation) ||
      !timestamp(row.requested_at) || !timestamp(row.expires_at) || typeof row.can_decide !== 'boolean' || seen.has(row.approval_id.toLowerCase())) {
      throw new Error('Invalid approval row');
    }
    seen.add(row.approval_id.toLowerCase());
    const { approval_id, target_id, target_name, requester_label, reason, requested_at, expires_at, state, reconciliation, can_decide } = row;
    return { approval_id, target_id, target_name, requester_label, reason, requested_at, expires_at, state, reconciliation, can_decide };
  });
  return { items, next_cursor: value.next_cursor };
}

export function createApprovalQueueFlow(transport: ApprovalTransport, stepUp: ApprovalStepUp) {
  const { getSnapshot, subscribe, begin, finish, cancelPending } = store<ApprovalQueueView>(
    { phase: 'idle', pageNumber: 1 }, transport, stepUp,
  );
  let cursors: (string | null)[] = [null];

  async function load(nextCursors: (string | null)[]) {
    const signal = begin({ phase: 'loading', page: undefined, receipt: undefined, error: undefined });
    if (!signal) return;
    cursors = nextCursors;
    const query = new URLSearchParams({ limit: String(pageLimit) });
    const cursor = cursors.at(-1);
    if (cursor != null) query.set('cursor', cursor);
    try {
      const page = queuePage(await readJson(transport, signal, `${prefix}/queue?${query}`));
      if (page.next_cursor !== null && cursors.includes(page.next_cursor)) throw new Error('Invalid cursor');
      finish(signal, { phase: 'ready', page, pageNumber: cursors.length });
    } catch (error) {
      finish(signal, { phase: 'reload', pageNumber: cursors.length, error: safeError(error, 'Could not load the approval queue. Reload to try again.') });
    }
  }

  function reload() { return load(cursors); }
  function first() { return load([null]); }
  async function next() {
    const { phase, page } = getSnapshot();
    if (phase === 'ready' && page?.next_cursor) await load([...cursors, page.next_cursor]);
  }
  async function previous() {
    if (cursors.length > 1) await load(cursors.slice(0, -1));
  }

  async function decide(id: string, decision: Decision) {
    const { phase, page } = getSnapshot();
    if (phase !== 'ready' || (decision !== 'APPROVE' && decision !== 'REJECT') ||
      !page?.items.some((row) => row.approval_id === id && row.state === 'PENDING' && row.can_decide)) return;
    const signal = begin({ phase: 'saving', error: undefined });
    if (!signal) return;
    let posting = false;
    try {
      await stepUp('decision', signal);
      if (signal.aborted) return;
      posting = true;
      const result = await readJson(transport, signal, `${prefix}/${id}/decision`, { decision });
      finish(signal, { phase: 'reload', page: undefined, receipt: receipt(result, id) });
    } catch (error) {
      finish(signal, { phase: 'reload', page: undefined, error: posting
        ? safeError(error, 'The decision outcome could not be confirmed. Reload the queue before taking another action.')
        : 'Step-up could not be completed. Reload the queue before taking another action.' });
    }
  }

  return { getSnapshot, subscribe, reload, first, next, previous, decide, cancelPending };
}
