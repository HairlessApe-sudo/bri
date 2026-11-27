'use client';

import { useCallback, useLayoutEffect, useState } from 'react';
import { authorizedRead, localJson } from './client.mjs';

export function useAuthorizedRead<T>(load: (signal: AbortSignal) => Promise<T>) {
  const [state, setState] = useState<{ data?: T; error?: number } | null>(null);
  useLayoutEffect(() => authorizedRead(load, setState), [load]);
  return state;
}

export function useXlsxRead<T>(path: string, decode: (value: unknown) => T) {
  return useAuthorizedRead(useCallback(async (signal: AbortSignal) => decode(await localJson(fetch, path, { signal }, 200)), [path, decode]));
}

export function XlsxError({ status, missing }: { status: number; missing: string }) {
  const message = status === 401 ? 'A current signed fixture session is required.' : status === 403 ? 'Access denied.'
    : status === 404 ? missing : status === 400 ? 'This page is no longer available. Refresh to start again.' : 'XLSX information is unavailable.';
  return <p role="alert" className="state-message">{message}</p>;
}

export function PageButtons({ cursor, next, visit, noun }: {
  cursor: string | null; next: string | null; visit: (next: string | null) => void; noun: string;
}) {
  return <p>
    {cursor && <button type="button" onClick={() => visit(null)}>First {noun} page</button>}{' '}
    {next && <button type="button" onClick={() => visit(next)}>Next {noun} page</button>}
  </p>;
}
