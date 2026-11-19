import { fetchApi } from '@/lib/api';
import { directoryDetailPath, isDirectoryUserId, isHistoryCursor } from '@/lib/user-directory.mjs';

const PAGE_SIZE = 25;
export const historyActionLabels = {
  provisioned: 'Provisioning requested',
  activated: 'Account activated',
  display_name_changed: 'Display name changed',
  suspended: 'Account suspended',
  reactivated: 'Account reactivated',
  permission_granted: 'Permission granted',
  permission_revoked: 'Permission revoked',
  deactivated: 'Account deactivated',
} as const;

type HistoryItem = {
  id: string;
  occurred_at: string;
  action: keyof typeof historyActionLabels;
  outcome: string;
  reason_code: string | null;
  actorName: string;
};
type HistoryPage = { items: HistoryItem[]; next_cursor: string | null };
export type HistoryState = { phase: 'ready'; page: HistoryPage }
  | { phase: 'loading' | 'unauthenticated' | 'denied' | 'missing' | 'error' };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function invalidHistory(): never {
  throw new Error('Invalid history response');
}

function isAction(value: unknown): value is HistoryItem['action'] {
  return typeof value === 'string' && Object.hasOwn(historyActionLabels, value);
}

export function parseHistoryPage(value: unknown): HistoryPage {
  if (!isRecord(value) || !Array.isArray(value.items) || value.items.length > PAGE_SIZE) invalidHistory();
  const next = value.next_cursor;
  if (next !== null && !(typeof next === 'string' && isHistoryCursor(next))) invalidHistory();
  const items = value.items.map((entry: unknown): HistoryItem => {
    if (!isRecord(entry)) invalidHistory();
    const { id, occurred_at, action, outcome, reason_code, actor } = entry;
    if (typeof id !== 'string' || !isDirectoryUserId(id)
      || typeof occurred_at !== 'string' || !/^\d{4}-\d{2}-\d{2}T/.test(occurred_at) || !Number.isFinite(Date.parse(occurred_at))
      || !isAction(action) || typeof outcome !== 'string' || (reason_code !== null && typeof reason_code !== 'string')
      || !isRecord(actor) || (actor.id !== null && !isDirectoryUserId(actor.id))
      || (actor.display_name !== null && typeof actor.display_name !== 'string')) invalidHistory();
    const actorName = actor.id === null ? 'Restricted actor' : actor.display_name?.trim() || 'Unnamed actor';
    return { id, occurred_at, action, outcome, reason_code, actorName };
  });
  return { items, next_cursor: next };
}

export function requestHistoryPage(accountId: string, cursor: string | null, publish: (state: HistoryState) => void) {
  const controller = new AbortController();
  async function load(): Promise<HistoryState> {
    try {
      const path = `${directoryDetailPath(accountId)}/history`;
      const params = new URLSearchParams({ limit: String(PAGE_SIZE) });
      if (cursor !== null) {
        if (!isHistoryCursor(cursor)) return { phase: 'error' };
        params.set('cursor', cursor);
      }
      const page = parseHistoryPage(await fetchApi<unknown>(`${path}?${params}`, controller.signal));
      return { phase: 'ready', page };
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
