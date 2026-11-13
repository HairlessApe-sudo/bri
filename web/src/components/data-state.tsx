'use client';

import { useCallback, useEffect, useState } from 'react';
import { fetchApi } from '@/lib/api';

type Remote<T> = { data: T | null; error: Error | null; loading: boolean };
export function useRemote<T>(path: string | null, refreshKey = 0): Remote<T> {
  const [state, setState] = useState<Remote<T>>({ data: null, error: null, loading: Boolean(path) });
  const reload = useCallback(() => {
    if (!path) {
      setState({ data: null, error: null, loading: false });
      return;
    }
    const controller = new AbortController();
    setState((old) => ({ ...old, loading: true, error: null }));
    fetchApi<T>(path, controller.signal)
      .then((data) => setState({ data, error: null, loading: false }))
      .catch((error: Error) => {
        if (error.name !== 'AbortError') setState({ data: null, error, loading: false });
      });
    return () => controller.abort();
  }, [path]);
  useEffect(() => reload(), [reload, refreshKey]);
  return state;
}

export function StateMessage({ loading, error, empty, children }: {
  loading?: boolean; error?: Error | null; empty?: boolean; children?: React.ReactNode;
}) {
  if (loading) return <div className="state-message" role="status"><span className="spinner" />Loading from BRI…</div>;
  if (error) {
    const status = (error as Error & { status?: number }).status;
    return <div className={`state-message ${status === 403 || status === 401 ? 'state-denied' : 'state-error'}`} role="alert">
      <strong>{status === 403 ? 'Access denied' : status === 401 ? 'Identity required' : 'Could not load this information'}</strong>
      <span>{error.message}</span>
    </div>;
  }
  if (empty) return <div className="state-message">No information is available for this identity and scope.</div>;
  return children;
}

export function PageHeading({ eyebrow, title, description }: { eyebrow: string; title: string; description: string }) {
  return <div className="page-heading"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p className="lede">{description}</p></div></div>;
}
