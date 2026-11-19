// Equality check only, never a credential. The proxy computes its copy from
// the SSR cookie bearer only after the API has committed the user's cutoff.
export async function recoveryBinding(token) {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
  return Array.from(new Uint8Array(hash), byte => byte.toString(16).padStart(2, '0')).join('');
}

// Non-secret development identity; must match the API's EXPECTED_PROJECT_REF.
const DEVELOPMENT_PROVIDER = 'https://bwqdyibvuecgthtatrtv.supabase.co';

// Contract exercised only by in-process tests. There is intentionally no
// hosted implementation, network fallback, environment switch or UI caller.
// A future provider-mediated binding needs independent authorization.
export async function changeRecoveryPassword(input, testContract) {
  const {providerUrl, publishableKey} = input;
  if ((providerUrl !== DEVELOPMENT_PROVIDER && providerUrl !== DEVELOPMENT_PROVIDER + '/') ||
      !publishableKey || typeof testContract?.reserve !== 'function') {
    return {outcome: 'blocked', signedOut: false};
  }
  const {auth, subject, password} = input;
  let outcome = 'blocked';
  try {
    const {data, error} = await auth.getSession();
    const token = data?.session?.access_token;
    if (error || !token || !subject || data.session.user.id !== subject) throw new Error();
    const binding = await recoveryBinding(token);
    const {barrier, submitProviderChange} = await testContract.reserve('/api/bri/v1/auth/recovery/invalidate', {
      method: 'POST', mode: 'same-origin', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
    });
    if (barrier.status === 204 && barrier.headers.get('x-bri-recovery-binding') === binding &&
        typeof submitProviderChange === 'function') {
      outcome = 'unconfirmed';
      const response = await submitProviderChange(DEVELOPMENT_PROVIDER + '/auth/v1/user', {
        method: 'PUT', credentials: 'omit', redirect: 'error', cache: 'no-store', referrerPolicy: 'no-referrer',
        headers: { authorization: `Bearer ${token}`, apikey: publishableKey, 'content-type': 'application/json' },
        body: JSON.stringify({password}), signal: AbortSignal.timeout(15000),
      });
      if (response.status === 200 && (await response.json())?.id === subject) outcome = 'provider-acknowledged';
    }
  } catch {
    // Keep the last confirmed phase. Transport errors do not prove rollback.
  }
  let signedOut = false;
  try {
    const {error} = await auth.signOut({scope: 'local'});
    signedOut = !error;
  } catch { /* Never retry a password write to repair local sign-out. */ }
  return {outcome, signedOut};
}
