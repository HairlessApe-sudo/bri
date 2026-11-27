// Single generation for scope, search and evidence work. Retire before abort
// so synchronous abort subscribers cannot publish from the discarded task.
export function createUnifiedLifecycle() {
  /** @type {AbortController | null} */
  let owner = null;
  /** @type {{ binding: string, selected: string } | null} */
  let verified = null;
  /** @type {typeof verified} */
  let candidate = null;
  const clear = () => {
    const retired = owner;
    owner = null;
    retired?.abort();
  };
  const begin = () => {
    clear();
    const active = new AbortController();
    owner = active;
    return { signal: active.signal, current: () => owner === active };
  };
  return {
    clear,
    begin,
    access: () => verified?.binding ?? null,
    /** @param {string} selected */
    select(selected) {
      if (!verified) return false;
      verified.selected = selected;
      return true;
    },
    resetAccess() {
      verified = candidate = null;
      clear();
    },
    /** @param {() => void} clearView */
    beginRevalidation(clearView) {
      // Keep only the last verified binding and selection privately across
      // overlapping refreshes. Neither authorizes a request while pending.
      candidate = verified ?? candidate;
      verified = null;
      const request = begin();
      clearView();
      return { ...request,
        /** @param {string} binding @param {string[]} eligible */
        authorize(binding, eligible) {
          if (!request.current() || verified) return null;
          const selected = candidate?.binding === binding && eligible.includes(candidate.selected) ? candidate.selected : '';
          candidate = null;
          verified = { binding, selected };
          return selected;
        },
      };
    },
  };
}
