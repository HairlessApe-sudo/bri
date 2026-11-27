export function ReviewRecovery({ status, refresh }: { status: number; refresh: () => void }) {
  const reason = status === 401 ? 'A current signed fixture session is required.' : status === 403 ? 'Access denied.'
    : status === 404 ? 'XLSX proposal not found.' : status === 409 ? 'The proposal changed.'
      : 'Decision was not confirmed. No automatic retry was sent.';
  return <section aria-label="Review recovery">
    <p role="alert">{reason} Refresh the proposal before taking another action.</p>
    <button type="button" onClick={refresh}>Refresh proposal</button>
  </section>;
}
