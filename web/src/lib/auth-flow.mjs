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
