'use client';

import { useCallback, useLayoutEffect, useRef, useState } from 'react';
import { flushSync } from 'react-dom';
import { observeEvidencePage } from './evidence-page.mjs';

export const apiBase = '/api/bri-local/v1';

export function useEvidenceRefresh() {
  const [state, setState] = useState({ parked: false, refreshKey: 0 });
  const observer = useRef<ReturnType<typeof observeEvidencePage> | null>(null);
  const refresh = useCallback(() => observer.current?.refresh(), []);
  useLayoutEffect(() => {
    const active = observeEvidencePage(window, document, (next) => {
      // Commit the hidden UI and abort its reads before the browser parks it.
      if (next.parked) flushSync(() => setState(next));
      else setState(next);
    });
    observer.current = active;
    return () => {
      observer.current = null;
      active.dispose();
    };
  }, []);
  return { ...state, refresh };
}
