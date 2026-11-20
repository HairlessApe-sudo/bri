// A staged view belongs to one committed UI context. Non-React callers can
// still use the original callback interface without binding a UI lifetime.
export function createUserAdminStore<View>(initial: View, show?: (view: View) => void) {
  let view = initial;
  // undefined: standalone callback, null: no committed UI context.
  let context: AbortController | null | undefined = show ? undefined : null;
  const listeners = new Set<() => void>();

  const getSnapshot = () => view;
  function subscribe(listener: () => void) {
    listeners.add(listener);
    return () => { listeners.delete(listener); };
  }
  function update(next: Partial<View>) {
    if (context === null) return;
    view = { ...view, ...next };
    show?.(view);
    for (const listener of listeners) listener();
  }
  function begin(next: Partial<View>) {
    if (context === null) return null;
    const signal = context?.signal;
    update(next);
    return signal;
  }
  function bind() {
    const controller = new AbortController();
    context = controller;
    return () => {
      if (context === controller) {
        context = null;
        // Effect replay can reuse this store, but never its previous review.
        view = initial;
      }
      controller.abort();
    };
  }

  return { getSnapshot, subscribe, update, begin, bind };
}
