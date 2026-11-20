/**
 * @param {Window} page
 * @param {Document} tab
 * @param {(state: {parked: boolean, refreshKey: number}) => void} publish
 */
export function observeEvidencePage(page, tab, publish) {
  let parked = false;
  let refreshKey = 0;
  const refresh = () => {
    if (!parked) publish({ parked, refreshKey: ++refreshKey });
  };
  const leaving = () => {
    if (parked) return;
    parked = true;
    publish({ parked, refreshKey });
  };
  const restored = (/** @type {PageTransitionEvent} */ event) => {
    if (!event.persisted || !parked) return;
    parked = false;
    refresh();
  };
  const visibility = () => { if (tab.visibilityState === 'visible') refresh(); };
  page.addEventListener('pagehide', leaving);
  page.addEventListener('pageshow', restored);
  page.addEventListener('focus', refresh);
  tab.addEventListener('visibilitychange', visibility);
  return {
    refresh,
    dispose() {
      page.removeEventListener('pagehide', leaving);
      page.removeEventListener('pageshow', restored);
      page.removeEventListener('focus', refresh);
      tab.removeEventListener('visibilitychange', visibility);
    },
  };
}
