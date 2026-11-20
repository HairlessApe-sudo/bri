/** @template T @typedef {{ data: T | null, error: Error | null, loading: boolean }} Remote */
/**
 * Hide the preceding snapshot at render time, before effects can abort or replace it.
 * @template T
 * @param {Remote<T> & {path: string, refreshKey: number} | null} snapshot
 * @param {string | null} path
 * @param {number} refreshKey
 * @returns {Remote<T>}
 */
export function visibleRemote(snapshot, path, refreshKey) {
  if (!path || snapshot?.path !== path || snapshot.refreshKey !== refreshKey) {
    return { data: null, error: null, loading: Boolean(path) };
  }
  return {
    data: snapshot.loading || snapshot.error ? null : snapshot.data,
    error: snapshot.error,
    loading: snapshot.loading,
  };
}

/** @param {...(Error | null)} errors */
export function workspaceEvidenceDenial(...errors) {
  return errors.find((error) => {
    const status = /** @type {(Error & {status?: number}) | null} */ (error)?.status;
    return status === 401 || status === 403;
  }) ?? null;
}
