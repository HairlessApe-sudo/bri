const root = '/api/bri/v1/users';
export const DIRECTORY_PAGE_SIZE = 25;
export const DIRECTORY_MAX_OFFSET = 10_000;
export const DIRECTORY_MAX_QUERY = 128;

export function isDirectoryUserId(id) {
  return typeof id === 'string' && id.length === 36 && /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(id);
}

export function directoryListPath(query, offset) {
  const params = new URLSearchParams();
  if (query.trim()) params.set('q', query.trim());
  if (offset) params.set('offset', String(offset));
  return params.size ? `${root}?${params}` : root;
}

export function directoryDetailPath(id) {
  if (!isDirectoryUserId(id)) throw new Error('Invalid user ID');
  return `${root}/${id}`;
}
