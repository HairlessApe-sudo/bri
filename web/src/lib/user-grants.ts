import { fetchApi } from '@/lib/api';
import { directoryDetailPath } from '@/lib/user-directory.mjs';

export const permissionLabels = { 'organisation:read': 'Organisation read', 'knowledge:read': 'Knowledge read' } as const;
export const accountClassLabels = { user: 'User', superuser: 'Superuser' } as const;
export const accountStatusLabels = { active: 'Active', pending: 'Pending', suspended: 'Suspended', deactivated: 'Deactivated' } as const;

export type AccountGrant = { scope_id: string; scope_name: string; permission: keyof typeof permissionLabels };
type Grants = {
  account_class: keyof typeof accountClassLabels;
  account_status: keyof typeof accountStatusLabels;
  assigned: AccountGrant[];
  effective: AccountGrant[];
};
export type GrantsState = { phase: 'ready'; grants: Grants }
  | { phase: 'loading' | 'unauthenticated' | 'denied' | 'missing' | 'error' };

function invalidGrants(): never {
  throw new Error('Invalid grants response');
}

function hasFields(value: unknown, fields: string[]): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    && Object.keys(value).length === fields.length && fields.every((field) => Object.hasOwn(value, field));
}

function isLabel<T extends object>(labels: T, value: unknown): value is keyof T {
  return typeof value === 'string' && Object.hasOwn(labels, value);
}

export function grantKey(grant: AccountGrant) {
  return JSON.stringify([grant.scope_id, grant.permission]);
}

function parseGrantList(value: unknown, scopeNames: Map<string, string>) {
  if (!Array.isArray(value)) invalidGrants();
  const rows = new Map<string, AccountGrant>();
  for (const entry of value as unknown[]) {
    if (!hasFields(entry, ['scope_id', 'scope_name', 'permission'])) invalidGrants();
    const { scope_id, scope_name, permission } = entry;
    if (typeof scope_id !== 'string' || !scope_id || scope_id.includes('\0')
      || typeof scope_name !== 'string' || scope_name.includes('\0')
      || !isLabel(permissionLabels, permission)) invalidGrants();
    const name = scopeNames.get(scope_id);
    if (name !== undefined && name !== scope_name) invalidGrants();
    scopeNames.set(scope_id, scope_name);
    const row = { scope_id, scope_name, permission };
    const key = grantKey(row);
    if (rows.has(key)) invalidGrants();
    rows.set(key, row);
  }
  return rows;
}

export function parseGrants(value: unknown): Grants {
  if (!hasFields(value, ['account_class', 'account_status', 'assigned', 'effective'])) invalidGrants();
  const { account_class, account_status } = value;
  if (!isLabel(accountClassLabels, account_class) || !isLabel(accountStatusLabels, account_status)) invalidGrants();
  const scopeNames = new Map<string, string>();
  const assigned = parseGrantList(value.assigned, scopeNames);
  const effective = parseGrantList(value.effective, scopeNames);
  if (account_status !== 'active' && effective.size) invalidGrants();
  for (const key of effective.keys()) if (!assigned.has(key)) invalidGrants();
  return { account_class, account_status, assigned: [...assigned.values()], effective: [...effective.values()] };
}

export function requestGrants(accountId: string, publish: (state: GrantsState) => void) {
  const controller = new AbortController();
  async function load(): Promise<GrantsState> {
    try {
      const grants = parseGrants(await fetchApi<unknown>(`${directoryDetailPath(accountId)}/grants`, controller.signal));
      return { phase: 'ready', grants };
    } catch (error) {
      const status = (error as { status?: number } | null)?.status;
      return { phase: status === 401 ? 'unauthenticated' : status === 403 ? 'denied' : status === 404 ? 'missing' : 'error' };
    }
  }
  void load().then((state) => {
    if (!controller.signal.aborted) publish(state);
  });
  return () => controller.abort();
}