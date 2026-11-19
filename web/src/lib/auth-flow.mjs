export function resolveMfaRoute({ currentLevel, nextLevel, hasVerifiedTotp }) {
  if (currentLevel === 'aal2' && nextLevel === 'aal2' && hasVerifiedTotp === true) return '/';
  if (hasVerifiedTotp === true) return '/auth/mfa/challenge';
  return '/auth/mfa/enroll';
}

export async function completeBriAuth({ currentLevel, nextLevel, hasVerifiedTotp, startSession }) {
  const destination = resolveMfaRoute({ currentLevel, nextLevel, hasVerifiedTotp });
  if (destination === '/') await startSession();
  return destination;
}

export function buildRecoveryCallbackUrl(env) {
  const isProduction = env.NODE_ENV === 'production';
  const configured = env.BRI_WEB_ORIGIN || (isProduction ? '' : 'http://127.0.0.1:3000');
  if (!configured) throw new Error('BRI_WEB_ORIGIN must be configured for password recovery.');

  let origin;
  try {
    origin = new URL(configured);
  } catch {
    throw new Error('BRI_WEB_ORIGIN must be a valid origin.');
  }
  const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(origin.hostname);
  if (
    origin.username
    || origin.password
    || origin.pathname !== '/'
    || origin.search
    || origin.hash
    || origin.hostname.endsWith('.')
    || (isProduction && origin.protocol !== 'https:')
    || (!isProduction && origin.protocol !== 'https:' && !(origin.protocol === 'http:' && loopback))
  ) {
    throw new Error('BRI_WEB_ORIGIN must be a safe HTTPS origin (or loopback HTTP in development).');
  }

  const callback = new URL('/auth/callback', origin);
  callback.searchParams.set('next', '/auth/update-password');
  return callback.toString();
}

// UX gate using server-verified claims and server time. The API repeats the
// freshness check at mutation time; rendering this form is not authorization.
export function recoveryState(claims, verifiedTotp, now = Date.now() / 1000) {
  if (!claims?.sub || typeof claims.sub !== 'string' || claims.role !== 'authenticated' || claims.is_anonymous === true) return 'invalid';
  if (verifiedTotp !== true) return 'support';
  if (!Array.isArray(claims.amr) || !claims.amr.every(event => typeof event?.method === 'string')) return 'challenge';
  const events = claims.amr.filter(({method}) => method === 'totp' || method === 'mfa/totp');
  const time = events.length === 1 ? events[0].timestamp : null;
  return claims.aal === 'aal2' && Number.isSafeInteger(time) && time > 0 && time <= now && now - time <= 900
    ? 'ready' : 'challenge';
}

// The verification result has no caller-supplied return URL. Recovery never
// falls through to enrollment or to the workspace session-start path.
export async function verifyTotpChallenge(mfa, code, recovery = false) {
  const {data, error} = await mfa.listFactors();
  if (error) throw new Error('Authenticator status could not be verified.');
  const factor = data?.totp?.find(item => item.status === 'verified');
  if (!factor) {
    if (recovery) throw new Error('Recovery requires your registered authenticator. Contact BRI support.');
    return '/auth/mfa/enroll';
  }
  const challenge = await mfa.challenge({factorId: factor.id});
  if (challenge.error || !challenge.data?.id) throw new Error('Authenticator challenge could not be started.');
  const verified = await mfa.verify({factorId: factor.id, challengeId: challenge.data.id, code: code.trim()});
  if (verified.error) throw new Error('That code was not accepted. Check the code and try again.');
  return recovery ? '/auth/update-password' : null;
}
