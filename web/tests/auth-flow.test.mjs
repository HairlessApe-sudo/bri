import test from 'node:test';
import assert from 'node:assert/strict';
import { buildRecoveryCallbackUrl, completeBriAuth, resolveMfaRoute } from '../src/lib/auth-flow.mjs';

test('routes an AAL1 session with an enrolled TOTP factor to a challenge', () => {
  assert.equal(resolveMfaRoute({ currentLevel: 'aal1', nextLevel: 'aal2', hasVerifiedTotp: true }), '/auth/mfa/challenge');
});

test('routes a session without a verified TOTP factor to enrollment', () => {
  assert.equal(resolveMfaRoute({ currentLevel: 'aal1', nextLevel: 'aal1', hasVerifiedTotp: false }), '/auth/mfa/enroll');
});

test('builds only a fixed password-recovery callback on the configured app origin', () => {
  assert.equal(
    buildRecoveryCallbackUrl({ BRI_WEB_ORIGIN: 'https://bri.example.test', NODE_ENV: 'production' }),
    'https://bri.example.test/auth/callback?next=%2Fauth%2Fupdate-password',
  );
  assert.equal(
    buildRecoveryCallbackUrl({ NODE_ENV: 'development' }),
    'http://127.0.0.1:3000/auth/callback?next=%2Fauth%2Fupdate-password',
  );
});

test('rejects unsafe or missing hosted password-recovery origins', () => {
  for (const env of [
    { NODE_ENV: 'production' },
    { BRI_WEB_ORIGIN: 'http://bri.example.test', NODE_ENV: 'production' },
    { BRI_WEB_ORIGIN: 'https://bri.example.test/other', NODE_ENV: 'production' },
    { BRI_WEB_ORIGIN: 'https://user:pass@bri.example.test', NODE_ENV: 'production' },
  ]) assert.throws(() => buildRecoveryCallbackUrl(env));
});

test('starts the BRI session only after current AAL2 and verified TOTP are established', async () => {
  let starts = 0;
  const startSession = async () => { starts += 1; };
  const challenge = await completeBriAuth({
    currentLevel: 'aal1', nextLevel: 'aal2', hasVerifiedTotp: true, startSession,
  });
  assert.equal(challenge, '/auth/mfa/challenge');
  assert.equal(starts, 0);

  const admitted = await completeBriAuth({
    currentLevel: 'aal2', nextLevel: 'aal2', hasVerifiedTotp: true, startSession,
  });
  assert.equal(admitted, '/');
  assert.equal(starts, 1);
});
test('admits only a current AAL2 session into the workspace', () => {
  assert.equal(resolveMfaRoute({ currentLevel: 'aal2', nextLevel: 'aal2', hasVerifiedTotp: true }), '/');
  assert.equal(resolveMfaRoute({ currentLevel: 'aal2', nextLevel: 'aal1', hasVerifiedTotp: false }), '/auth/mfa/enroll');
});
