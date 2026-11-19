import { isDirectoryUserId } from '@/lib/user-directory.mjs';

export const deactivationReasons = {
  account_closed: 'Account closed',
  access_review: 'Access review',
  policy_violation: 'Policy violation',
} as const;
type Reason = keyof typeof deactivationReasons;
type AccountState = { version: string; status: 'active' | 'suspended' | 'deactivated' };
export type DeactivationTransport = (path: string, init: RequestInit) => Promise<Response>;
export type DeactivationView = {
  phase: 'idle' | 'loading' | 'ready' | 'saving' | 'refresh-required';
  state: AccountState | null;
  reason: Reason | '';
  reviewing: boolean;
  error?: string;
};

function isVersion(value: unknown): value is string {
  // Match the API's bigint envelope without parsing or changing the token.
  return typeof value === 'string' && /^(?:0|[1-9][0-9]{0,18})$/.test(value)
    && (value.length < 19 || value <= '9223372036854775807');
}

function isAccountState(value: unknown): value is AccountState {
  return !!value && typeof value === 'object' && Object.keys(value).length === 2 &&
    'version' in value && isVersion(value.version) &&
    'status' in value && (value.status === 'active' || value.status === 'suspended' || value.status === 'deactivated');
}

async function failureMessage(response: Response, saving: boolean) {
  if (saving && (response.status === 409 || response.status === 412)) {
    return 'The account state changed. Reload it before reviewing deactivation again.';
  }
  if (response.status === 401) return 'A verified session is required to access account deactivation.';
  if (response.status === 403) {
    const body = await response.json().catch(() => null);
    if (body?.detail === 'Recent verified TOTP required' || body?.detail === 'A recent verified TOTP challenge is required' ||
      body?.detail === 'Verified TOTP event required') {
      return 'A recent verified TOTP challenge is required. Verify your authenticator, then reload the account state.';
    }
    return 'Access to this deactivation request was denied.';
  }
  if (response.status === 404) return 'Deactivation state is not available for this account.';
}

// One staged flow per account and transport. Only the server decides authority.
export function createDeactivationFlow(id: string, transport: DeactivationTransport) {
  if (!isDirectoryUserId(id)) throw new Error('Invalid user ID');
  if (typeof transport !== 'function') throw new Error('A staged deactivation transport is required');
  const path = `/v1/users/${id}/deactivation`;
  let view: DeactivationView = { phase: 'idle', state: null, reason: '', reviewing: false };
  const listeners = new Set<() => void>();
  const getSnapshot = () => view;
  function subscribe(listener: () => void) {
    listeners.add(listener);
    return () => { listeners.delete(listener); };
  }
  function update(next: Partial<DeactivationView>) {
    view = { ...view, ...next };
    for (const listener of listeners) listener();
  }
  const busy = () => view.phase === 'loading' || view.phase === 'saving';
  const canDeactivate = () => view.phase === 'ready' && view.state !== null && view.state.status !== 'deactivated';

  async function request(init: RequestInit, expectedVersion?: string) {
    const saving = expectedVersion !== undefined;
    update({ phase: saving ? 'saving' : 'loading', reason: '', reviewing: false, error: undefined });
    let error = saving ? 'Could not confirm deactivation. Reload the account state before trying again.'
      : 'Could not load the account state. Reload it to try again.';
    let status: number | undefined;
    try {
      const response = await transport(path, init);
      status = response.status;
      if (!response.ok) {
        error = await failureMessage(response, saving) ?? error;
        throw new Error('Deactivation request failed');
      }
      const state: unknown = await response.json();
      if (!isAccountState(state) || (saving && (state.status !== 'deactivated' || state.version === expectedVersion))) {
        throw new Error('Invalid deactivation response');
      }
      update({ phase: 'ready', state });
    } catch {
      const unavailable = status === 401 || status === 403 || status === 404;
      update({ phase: 'refresh-required', state: unavailable ? null : view.state, error });
    }
  }

  async function reload() {
    if (!busy()) await request({ method: 'GET' });
  }
  function chooseReason(reason: string) {
    if (!canDeactivate() || (reason !== '' && !Object.hasOwn(deactivationReasons, reason))) return;
    update({ reason: reason as DeactivationView['reason'], reviewing: false, error: undefined });
  }
  function review() {
    if (canDeactivate() && view.reason) update({ reviewing: true, error: undefined });
  }
  function cancelReview() {
    if (canDeactivate()) update({ reviewing: false, error: undefined });
  }
  async function submit(confirmed: boolean) {
    const { state, reason, reviewing } = view;
    if (!canDeactivate() || !state || !reason || !reviewing) return;
    if (confirmed !== true) {
      update({ error: 'Confirm this deactivation before submitting.' });
      return;
    }
    await request({ method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ expected_version: state.version, reason }) }, state.version);
  }

  return { getSnapshot, subscribe, reload, chooseReason, review, cancelReview, submit };
}
