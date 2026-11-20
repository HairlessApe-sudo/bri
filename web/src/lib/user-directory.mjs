const root = '/api/bri/v1/users';
export const DIRECTORY_PAGE_SIZE = 25;
export const DIRECTORY_MAX_OFFSET = 10_000;
export const DIRECTORY_MAX_QUERY = 128;
export const DIRECTORY_FILTERS = Object.freeze({
  status: Object.freeze(['pending', 'active', 'suspended', 'deactivated']),
  role: Object.freeze(['user', 'superuser']),
  mfa_status: Object.freeze(['verified', 'unknown']),
});

export function isDirectoryUserId(id) {
  return typeof id === 'string' && id.length === 36 && /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(id);
}

export function isHistoryCursor(cursor) {
  return isDirectoryUserId(cursor) && cursor === cursor.toLowerCase();
}

/** @typedef {Partial<Record<keyof typeof DIRECTORY_FILTERS, string>>} DirectoryFilters */
/** @typedef {{ query: string, offset: number, filters: DirectoryFilters }} DirectoryListState */
/** @param {DirectoryListState} state
 * @param {{ type: 'search', query: string } | { type: 'page', offset: number } | { type: 'filter', key: keyof typeof DIRECTORY_FILTERS, value: string }} action
 * @returns {DirectoryListState}
 */
export function updateDirectoryList(state, action) {
  if (action.type === 'search') return { ...state, query: action.query, offset: 0 };
  if (action.type === 'page') {
    const { offset } = action;
    return Number.isInteger(offset) && offset >= 0 && offset <= DIRECTORY_MAX_OFFSET ? { ...state, offset } : state;
  }
  const { key, value } = action;
  if (!Object.hasOwn(DIRECTORY_FILTERS, key) || (value && !DIRECTORY_FILTERS[key].includes(value))) return state;
  const filters = { ...state.filters };
  if (value) filters[key] = value;
  else delete filters[key];
  return { ...state, filters, offset: 0 };
}

/** @param {string} query @param {number} offset @param {DirectoryFilters} filters */
export function directoryListPath(query, offset, filters = {}) {
  const params = new URLSearchParams();
  if (query.trim()) params.set('q', query.trim());
  if (offset) params.set('offset', String(offset));
  for (const key of /** @type {(keyof typeof DIRECTORY_FILTERS)[]} */ (Object.keys(DIRECTORY_FILTERS))) {
    const value = filters[key];
    if (value && DIRECTORY_FILTERS[key].includes(value)) params.set(key, value);
  }
  return params.size ? `${root}?${params}` : root;
}

export function directoryDetailPath(id) {
  if (!isDirectoryUserId(id)) throw new Error('Invalid user ID');
  return `${root}/${id}`;
}
