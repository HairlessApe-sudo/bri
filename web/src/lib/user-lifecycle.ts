import type { DirectoryUser } from '@/lib/api';
import { isDirectoryUserId } from '@/lib/user-directory.mjs';

export type LifecycleTransport = (path: string, options: RequestInit) => Promise<Response>;
export const lifecycleActions = {
  edit: { label: 'Edit display name', permission: 'can_edit' },
  suspend: { label: 'Suspend', permission: 'can_suspend' },
  reactivate: { label: 'Reactivate', permission: 'can_reactivate' },
} as const;
export const lifecycleReasons = {
  suspend: { policy_violation: 'Policy violation', access_review: 'Access review', temporary_leave: 'Temporary leave' },
  reactivate: { review_complete: 'Review complete', access_restored: 'Access restored' },
} as const;

export type LifecycleAction = keyof typeof lifecycleActions;
type LifecycleAccount = Pick<DirectoryUser, 'id' | 'display_name' | 'status' | 'role'> & {
  version: number; can_edit: boolean; can_suspend: boolean; can_reactivate: boolean;
};
export type LifecycleView = {
  phase: 'idle' | 'loading' | 'ready' | 'saving' | 'refresh-required';
  account: LifecycleAccount | null;
  action: LifecycleAction | null;
  error?: string;
};
export const initialLifecycleView: LifecycleView = { phase: 'idle', account: null, action: null };

export function permittedLifecycleActions(account: LifecycleAccount): LifecycleAction[] {
  return (Object.keys(lifecycleActions) as LifecycleAction[]).filter((action) => account[lifecycleActions[action].permission]);
}

function isAccount(result: unknown, id: string): result is LifecycleAccount {
  return !!result && typeof result === 'object' && Object.keys(result).length === 8 &&
    'id' in result && typeof result.id === 'string' && isDirectoryUserId(result.id) && result.id.toLowerCase() === id.toLowerCase() &&
    'display_name' in result && (result.display_name === null || typeof result.display_name === 'string') &&
    'status' in result && (result.status === 'pending' || result.status === 'active' || result.status === 'suspended' || result.status === 'deactivated') &&
    'role' in result && (result.role === 'user' || result.role === 'superuser') &&
    'version' in result && typeof result.version === 'number' && Number.isSafeInteger(result.version) && result.version >= 0 &&
    'can_edit' in result && typeof result.can_edit === 'boolean' &&
    'can_suspend' in result && typeof result.can_suspend === 'boolean' &&
    'can_reactivate' in result && typeof result.can_reactivate === 'boolean';
}

// Staged only: there is no network fallback or release proxy for this contract.
export function createLifecycleFlow(id: string, transport: LifecycleTransport, show: (view: LifecycleView) => void) {
  if (!isDirectoryUserId(id)) throw new Error('Invalid user ID');
  const path = `/v1/users/${id}/lifecycle`;
  let view = initialLifecycleView;
  function update(next: Partial<LifecycleView>) {
    view = { ...view, ...next };
    show(view);
  }

  async function request(init: RequestInit, expectedVersion?: number) {
    const saving = expectedVersion !== undefined;
    let status: number | undefined;
    update({ phase: saving ? 'saving' : 'loading', action: null, error: undefined });
    try {
      const response = await transport(path, init);
      status = response.status;
      if (!response.ok) throw new Error('Lifecycle request unavailable');
      const result: unknown = await response.json();
      if (!isAccount(result, id) || result.version === expectedVersion) throw new Error('Invalid lifecycle response');
      update({ account: result, phase: 'ready' });
    } catch {
      let error = saving ? 'Could not confirm the change. Refresh lifecycle before another attempt.'
        : 'Could not load lifecycle details. Refresh lifecycle to try again.';
      if (saving && (status === 409 || status === 412)) error = 'The account changed. Refresh lifecycle before choosing an action again.';
      const unavailable = status === 401 || status === 403 || status === 404;
      if (status === 401) error = 'A verified session is required to access lifecycle details.';
      if (status === 403) error = 'Access to this lifecycle request was denied.';
      if (status === 404) error = 'Lifecycle details are not available for this user.';
      update({ phase: 'refresh-required', account: unavailable ? null : view.account, error });
    }
  }

  async function refresh() {
    if (view.phase === 'loading' || view.phase === 'saving') return;
    await request({ method: 'GET' });
  }

  function select(action: LifecycleAction | null) {
    if (view.phase !== 'ready' || !view.account || (action !== null && !permittedLifecycleActions(view.account).includes(action))) return;
    update({ action, error: undefined });
  }

  async function submit(action: LifecycleAction, value: string, confirmed: boolean) {
    const { account } = view;
    if (view.phase !== 'ready' || !account || view.action !== action || !permittedLifecycleActions(account).includes(action)) return;
    let fields: { display_name: string } | { reason: string };
    if (action === 'edit') {
      const name = value.trim();
      if (!name || [...name].length > 128 || /\p{Cc}/u.test(value)) {
        update({ error: 'Enter a display name between 1 and 128 characters without control characters.' });
        return;
      }
      fields = { display_name: name };
    } else {
      if (!Object.hasOwn(lifecycleReasons[action], value)) {
        update({ error: 'Select a reason for this change.' });
        return;
      }
      if (confirmed !== true) {
        update({ error: 'Confirm this change before submitting it.' });
        return;
      }
      fields = { reason: value };
    }
    await request({ method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action, expected_version: account.version, ...fields }) }, account.version);
  }

  return { refresh, select, submit };
}
