import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { recoveryState, verifyTotpChallenge } from '../src/lib/auth-flow.mjs';
import * as recovery from '../src/lib/password-recovery.mjs';
import * as proxy from '../src/lib/backend-proxy.mjs';
import { buildBackendRequest } from '../src/lib/backend-proxy.mjs';

const path = '/v1/auth/recovery/invalidate';
const hosted = { BRI_UI_AUTH_MODE: 'supabase', BRI_API_ORIGIN: 'https://api.example.test' };
const build = (method, params = '', env = hosted, token = 'cookie-token') =>
  buildBackendRequest(path, new URLSearchParams(params), env, { method, accessToken: token });

test('only a hosted bodyless self-recovery POST may reach the fixed API endpoint', () => {
  const request = build('POST');
  assert.equal(request.url, hosted.BRI_API_ORIGIN + path);
  assert.deepEqual([...request.headers], [['authorization', 'Bearer cookie-token']]);
  for (const method of ['GET', 'PATCH', 'PUT', 'DELETE']) assert.throws(() => build(method), {status:404});
  assert.throws(() => build('POST', '', { BRI_UI_AUTH_MODE: 'synthetic' }), {status:404});
  assert.throws(() => build('POST', '', hosted, ''), {status:401});
  for (const query of ['tenant_id=t', 'subject=u', 'session_id=s', 'aal=aal2']) {
    assert.throws(() => build('POST', query), {status:400});
  }
});

const now = 10_000;
const claims = { sub: 'user', role: 'authenticated', aal: 'aal2', amr: [{method:'totp', timestamp:now}] };
test('only recent verified TOTP permits the form; other verified sessions get an in-place challenge', () => {
  const state = (c, factor = true) => recoveryState(c, factor, now);
  assert.equal(state(claims), 'ready');
  for (const c of [{...claims, aal:'aal1'}, {...claims, amr:[]},
    {...claims, iat:now, amr:[{method:'totp', timestamp:now-901}]},
    {...claims, amr:[{method:'totp', timestamp:now+1}]}, {...claims, amr:[...claims.amr, ...claims.amr]}]) {
    assert.equal(state(c), 'challenge');
  }
  assert.equal(state(claims, false), 'support');
  assert.equal(state(null), 'invalid');
  assert.equal(state({...claims, is_anonymous:true}), 'invalid');
});


test('recovery UI accepts one structured TOTP alias, never string, duplicate or other MFA evidence', () => {
  const canonical = {method:'mfa/totp', timestamp:now - 900};
  const state = (amr, time = now) => recoveryState({...claims, iat:now, amr}, true, time);
  assert.equal(state([canonical]), 'ready');
  assert.equal(state([canonical], now + 0.01), 'challenge');
  for (const amr of [['totp'], ['mfa/totp'], [canonical, 'totp'], [canonical, ...claims.amr],
    [{method:'mfa/totp'}], [{method:'mfa/phone', timestamp:now}], [{method:'recovery', timestamp:now}]]) {
    assert.equal(state(amr), 'challenge');
  }
});

const snapshot = { access_token:'original-token', user:{id:'user'} };
const providerUrl = 'https://bwqdyibvuecgthtatrtv.supabase.co';

test('rejects every non-pinned provider before credential access, sign-out or transport', async () => {
  for (const wrong of ['https://other.supabase.co', `${providerUrl}.example.test`, `${providerUrl}:8443`,
    `${providerUrl}/auth`, `${providerUrl}/old/..`, `${providerUrl}?q=1`, `${providerUrl}#x`,
    'https://user@bwqdyibvuecgthtatrtv.supabase.co', providerUrl.replace('https:', 'http:')]) {
    const calls = [];
    const auth = { getSession() { calls.push('session'); }, signOut() { calls.push('cleanup'); } };
    const send = () => { calls.push('network'); throw Error('unexpected transport'); };
    const result = await recovery.changeRecoveryPassword({auth, subject:'user', password:'synthetic',
      providerUrl:wrong, publishableKey:'test-key', send}, {reserve:send});
    assert.deepEqual(calls, [], wrong);
    assert.equal(result.outcome, 'blocked');
  }
});
async function attempt({ barrier = 204, match = true, provider = 200, cleanup = true, session = snapshot } = {}) {
  const calls = [];
  const auth = {
    getSession: async () => ({data:{session}}),
    signOut: async options => { calls.push(['signOut', options]); return {error: cleanup ? null : Error('private')}; },
  };
  const send = async (url, options) => {
    if (url === '/api/bri' + path) {
      calls.push(['barrier']);
      assert.equal(options.method, 'POST');
      assert.equal(options.credentials, 'same-origin');
      assert.equal(options.redirect, 'error');
      assert.equal(options.body, undefined);
      assert.equal(options.headers, undefined);
      if (!barrier) throw Error('network');
      return new Response(null, { status: barrier, headers: {
        'x-bri-recovery-binding': match ? await recovery.recoveryBinding(snapshot.access_token) : 'different-session',
      } });
    }
    assert.equal(url, providerUrl + '/auth/v1/user');
    assert.equal(options.method, 'PUT');
    assert.equal(options.headers.authorization, 'Bearer ' + snapshot.access_token);
    assert.equal(options.redirect, 'error');
    assert.deepEqual(JSON.parse(options.body), {password:'test-only'});
    calls.push(['provider']);
    if (!provider) throw Error('network');
    return Response.json({id:'user'}, {status:provider});
  };
  // Only this fixture supplies the operation-bound provider transport. No
  // browser-provided operation ID or completion flag is part of the contract.
  const contract = {
    reserve: async (url, options) => ({barrier: await send(url, options), submitProviderChange: send}),
  };
  const result = await recovery.changeRecoveryPassword({auth, subject:'user', password:'test-only', providerUrl, publishableKey:'test-key', send}, contract);
  return {result, calls:calls.map(c => c[0])};
}

// Architectural guard: the shipped client must not import the test contract
// or collect a new password, even if its hosting environment is configured.
test('the client has no operable password recovery entry point', async () => {
  const source = await readFile(new URL('../src/components/auth-forms.tsx', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /changeRecoveryPassword|resetPasswordForEmail|auth\.updateUser|autoComplete="new-password"/);
  for (const page of ['recover', 'update-password']) {
    const route = await readFile(new URL(`../src/app/auth/${page}/page.tsx`, import.meta.url), 'utf8');
    assert.match(route, /RecoveryUnavailablePage/);
    assert.doesNotMatch(route, /createSupabaseServerClient|TotpChallengeForm|RecoveryRequestForm|UpdatePasswordForm/);
  }
  const notice = await readFile(new URL('../src/components/auth-frame.tsx', import.meta.url), 'utf8');
  assert.match(notice, /Password recovery is unavailable/);
  assert.match(notice, /Contact authorized BRI support/);
});

test('without an in-process contract even the pinned project does no work', async () => {
  const calls = [];
  const auth = { getSession() { calls.push('session'); }, signOut() { calls.push('signOut'); } };
  const result = await recovery.changeRecoveryPassword({auth, subject:'user', providerUrl, publishableKey:'test-key',
    send: () => calls.push('network'), confirmed:true, operation_id:'browser-value'});
  assert.deepEqual(calls, []);
  assert.deepEqual(result, {outcome:'blocked', signedOut:false});
});

test('only provider acknowledgement follows a reserved, bound test write; never BRI confirmation', async () => {
  assert.deepEqual(await attempt(), {result:{outcome:'provider-acknowledged', signedOut:true}, calls:['barrier','provider','signOut']});
});
test('an ambiguous or denied cutoff never permits a password write', async () => {
  for (const barrier of [0, 200, 202, 302, 401, 403, 500]) {
    assert.deepEqual(await attempt({barrier}), {result:{outcome:'blocked', signedOut:true}, calls:['barrier','signOut']});
  }
});
test('a changed browser or SSR identity cannot select the password target', async () => {
  assert.deepEqual((await attempt({match:false})).calls, ['barrier','signOut']);
  assert.deepEqual((await attempt({session:{...snapshot,user:{id:'other'}}})).calls, ['signOut']);
});
test('after a cutoff, failed/ambiguous provider operations never resume or retry the session', async () => {
  for (const provider of [0, 400, 500]) {
    assert.deepEqual(await attempt({provider}), {result:{outcome:'unconfirmed',signedOut:true}, calls:['barrier','provider','signOut']});
  }
});
test('cleanup failure does not erase the password outcome or claim sign-out', async () => {
  assert.deepEqual((await attempt({cleanup:false})).result, {outcome:'provider-acknowledged',signedOut:false});
  assert.deepEqual((await attempt({cleanup:false, provider:0})).result, {outcome:'unconfirmed',signedOut:false});
});


test('the recovery proxy checks CSRF and rejects bodies and identity headers before reading SSR cookies', async () => {
  const origin = 'https://ui.example.test';
  const url = origin + '/api/bri' + path;
  const prepare = (headers, body, sessionToken) => proxy.prepareProxyRequest(
    new Request(url, {method: 'POST', headers, body}), path, hosted, async () => sessionToken,
  );
  for (const badOrigin of [null, 'null', 'https://other.example.test']) {
    await assert.rejects(prepare(badOrigin ? {origin:badOrigin} : {}), {status:403});
  }
  await assert.rejects(prepare({origin}, JSON.stringify({subject:'other'})), {status:400});
  for (const name of ['x-tenant-id', 'x-dev-identity', 'x-bri-tenant-context']) {
    await assert.rejects(prepare({origin, [name]:'other'}), {status:400});
  }
  const headers = {origin, authorization:'Bearer browser-token', 'x-bri-recovery-binding':'spoof'};
  await assert.rejects(prepare(headers), {status:401});
  const request = await prepare(headers, undefined, 'cookie-token');
  assert.deepEqual([...request.headers], [['authorization', 'Bearer cookie-token']]);
});


test('recovery verifies the existing factor, then returns only to the fixed password form', async () => {
  const calls = [];
  const mfa = {
    listFactors: async () => ({ data: {totp:[{id:'pending',status:'unverified'}, {id:'existing',status:'verified'}]} }),
    challenge: async ({factorId}) => { calls.push(factorId); return {data:{id:'challenge'}}; },
    verify: async ({factorId, challengeId, code}) => { calls.push([factorId,challengeId,code]); return {}; },
  };
  const complete = overrides => verifyTotpChallenge({...mfa,...overrides}, '123456', true);
  assert.equal(await complete({}), '/auth/update-password');
  assert.deepEqual(calls, ['existing', ['existing','challenge','123456']]);
  await assert.rejects(complete({ listFactors: async () => ({data:{totp:[]}}) }));
  await assert.rejects(complete({ verify: async () => ({error:Error('secret')}) }), /not accepted/);
});
