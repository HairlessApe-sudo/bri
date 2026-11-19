import { isDirectoryUserId } from '@/lib/user-directory.mjs';

export const delegationPermissions = {
  'organisation:read': 'Organisation read',
  'knowledge:read': 'Knowledge read',
} as const;
type Permission = keyof typeof delegationPermissions;
type Action = 'grant' | 'revoke';
type GrantState = { version: string; granted: boolean };
export type DelegationNode = { id: string; label: string };
export type DelegationTransport = (path: string, init: RequestInit) => Promise<Response>;
export type DelegationView = {
  node: string;
  permission: Permission | '';
  phase: 'idle' | 'loading' | 'ready' | 'saving' | 'refresh-required';
  state: GrantState | null;
  action: Action | null;
  error?: string;
};
export const initialDelegationView: DelegationView = { node: '', permission: '', phase: 'idle', state: null, action: null };

function isGrantState(value: unknown): value is GrantState {
  return !!value && typeof value === 'object' && Object.keys(value).length === 2 &&
    'version' in value && typeof value.version === 'string' &&
    'granted' in value && typeof value.granted === 'boolean';
}

async function failureMessage(response: Response, saving: boolean) {
  if (saving && (response.status === 409 || response.status === 412)) {
    return 'The grant state changed. Reload it before choosing an action again.';
  }
  if (response.status === 401) return 'A verified session is required to access permission delegation.';
  if (response.status === 403) {
    const body = await response.json().catch(() => null);
    if (body?.detail === 'Recent verified TOTP required' || body?.detail === 'A recent verified TOTP challenge is required') {
      return 'A fresh TOTP challenge is required. Verify your authenticator, then reload the grant state.';
    }
    return 'Access to this delegation request was denied.';
  }
  if (response.status === 404) return 'Delegation state is not available for this user and selection.';
}

// Staged only. The injected transport, not the browser, determines authority.
export function createDelegationFlow(id: string, nodes: readonly DelegationNode[], transport: DelegationTransport, show: (view: DelegationView) => void) {
  if (!isDirectoryUserId(id)) throw new Error('Invalid user ID');
  if (typeof transport !== 'function') throw new Error('A staged delegation transport is required');
  const path = `/v1/users/${id}/delegation`;
  const nodeIds = new Set(nodes.map((node) => node.id));
  let view = initialDelegationView;
  const busy = () => view.phase === 'loading' || view.phase === 'saving';
  function update(next: Partial<DelegationView>) {
    view = { ...view, ...next };
    show(view);
  }

  function choose(node: string, permission: string) {
    if (busy() || (node !== '' && !nodeIds.has(node)) || (permission !== '' && !Object.hasOwn(delegationPermissions, permission))) return;
    if (node === view.node && permission === view.permission) return;
    update({ ...initialDelegationView, node, permission: permission as DelegationView['permission'], error: undefined });
  }

  async function request(target: string, init: RequestInit, change?: { action: Action; version: string }) {
    update({ phase: change ? 'saving' : 'loading', action: null, error: undefined });
    let error = change ? 'Could not confirm the change. Reload the grant state before trying again.'
      : 'Could not load the grant state. Reload it to try again.';
    let status: number | undefined;
    try {
      const response = await transport(target, init);
      status = response.status;
      if (!response.ok) {
        error = await failureMessage(response, !!change) ?? error;
        throw new Error('Delegation request failed');
      }
      const result: unknown = await response.json();
      if (!isGrantState(result) || (change && (result.version === change.version || result.granted !== (change.action === 'grant')))) {
        throw new Error('Invalid delegation response');
      }
      update({ phase: 'ready', state: result });
    } catch {
      const unavailable = status === 401 || status === 403 || status === 404;
      update({ phase: 'refresh-required', state: unavailable ? null : view.state, error });
    }
  }

  async function refresh() {
    if (busy() || !view.node || !view.permission) return;
    const params = new URLSearchParams({ node: view.node, permission: view.permission });
    await request(`${path}?${params}`, { method: 'GET' });
  }

  function select(action: Action | null) {
    if (view.phase !== 'ready' || !view.state || (action !== null && action !== (view.state.granted ? 'revoke' : 'grant'))) return;
    update({ action, error: undefined });
  }

  async function submit(action: Action, confirmed: boolean) {
    const { node, permission, state } = view;
    if (view.phase !== 'ready' || !state || action !== view.action || action !== (state.granted ? 'revoke' : 'grant')) return;
    if (confirmed !== true) {
      update({ error: 'Confirm this delegation change before submitting.' });
      return;
    }
    await request(path, { method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ node, permission, action, expected_version: state.version }) }, { action, version: state.version });
  }

  return { choose, refresh, select, submit };
}
