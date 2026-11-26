// Private stdio worker for a13_demo.py. Never run as a public auth service.
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID, sign, verify } from 'node:crypto';
import { createServer } from 'node:http';
import { createRequire } from 'node:module';
import { createInterface } from 'node:readline';
import { setTimeout as delay } from 'node:timers/promises';
import { LOCAL_AUTH_OPTIONS as auth, LOCAL_HOST, LOCAL_PORT } from '../web/local-workspace/bridge.mjs';

const { createServerClient, serializeCookieHeader } = createRequire(new URL('../web/package.json', import.meta.url))('@supabase/ssr');
assert(!process.stdin.isTTY && !process.stdout.isTTY, 'Run via the private demo harness');
assert(LOCAL_HOST === '127.0.0.2' && LOCAL_PORT === 3013 && auth.cookiePath === '/api/bri-local', 'Workspace host/cookie isolation is required');
const ui = `http://${LOCAL_HOST}:${LOCAL_PORT}`;
const bridge = `${ui}/api/bri-local/v1`;
const jwksPath = '/auth/v1/.well-known/jwks.json';
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const header = { alg: 'RS256', typ: 'JWT', kid: randomUUID() };
const jwks = JSON.stringify({ keys: [{ ...publicKey.export({ format: 'jwk' }), ...header, use: 'sig' }] });
const encode = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
let jwksReads = 0;
const provider = createServer((req, res) => {
  if (req.method !== 'GET' || req.url !== jwksPath) return res.writeHead(404, { 'content-type': 'application/json' }).end('{}');
  jwksReads++;
  res.writeHead(200, { 'content-type': 'application/json' }).end(jwks);
});

async function issue(issuer, sub, session_id) {
  assert.equal(issuer, auth.issuer);
  const now = Math.floor(Date.now() / 1000);
  const lifetime = 600;
  const claims = { iss: issuer, sub, session_id, aud: 'authenticated', role: 'authenticated', aal: 'aal2',
    amr: ['password', 'totp'].map((method) => ({ method, timestamp: now })), iat: now, exp: now + lifetime };
  const input = `${encode(header)}.${encode(claims)}`;
  const signature = sign('RSA-SHA256', Buffer.from(input), privateKey);
  assert(verify('RSA-SHA256', Buffer.from(input), publicKey, signature), 'Fixture signature self-check failed');
  const token = `${input}.${signature.toString('base64url')}`;
  const cookies = [];
  const harnessOnly = async (url, init) => {
    // This exchange is injected into the trusted adapter only. Port 9013 has no mint route.
    if (String(url) !== `${auth.origin}/auth/v1/token?grant_type=password` || init?.method !== 'POST') {
      return Response.json({}, { status: 404 });
    }
    return Response.json({ access_token: token, refresh_token: randomUUID(), token_type: 'bearer',
      expires_in: lifetime, user: { id: sub, aud: 'authenticated' } });
  };
  const client = createServerClient(auth.origin, auth.key, {
    cookieOptions: { name: auth.cookieName, path: auth.cookiePath, httpOnly: true, sameSite: 'lax' },
    cookies: { getAll: () => [], setAll: (batch) => cookies.push(...batch) }, global: { fetch: harnessOnly },
  });
  const { error } = await client.auth.signInWithPassword({ email: 'local@example.test', password: 'synthetic-fixture' });
  assert(!error, 'SSR session cookie exchange failed');
  const set = cookies.filter(({ value }) => value).map(({ name, value, options }) => {
    assert(options.httpOnly && options.sameSite === 'lax' && options.path === auth.cookiePath && !options.domain, 'Unexpected SSR cookie attributes');
    return { name, value: serializeCookieHeader(name, value).split(';')[0].slice(name.length + 1) };
  });
  assert(set.length > 0, 'SSR generated no session cookies');
  return { token, set };
}

async function until(check, label, ms = 45_000) {
  const deadline = Date.now() + ms;
  do {
    const value = await check();
    if (value) return value;
    await delay(100);
  } while (Date.now() < deadline);
  throw new Error(`Timed out: ${label}`);
}

async function browser(port, cookies, { countPosts = false } = {}) {
  assert(Number.isInteger(port) && port > 0 && port < 65536, 'Invalid DevTools port');
  const debuggerOrigin = `http://127.0.0.1:${port}`;
  const [tab] = (await (await fetch(`${debuggerOrigin}/json/list`, { signal: AbortSignal.timeout(5000) })).json())
    .filter(({ type }) => type === 'page');
  const endpoint = new URL(tab.webSocketDebuggerUrl);
  assert.equal(endpoint.origin, `ws://127.0.0.1:${port}`);
  const ws = new WebSocket(endpoint);
  await new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('CDP connection timed out')), 5000);
    ws.addEventListener('open', () => { clearTimeout(timeout); resolve(); }, { once: true });
    ws.addEventListener('error', () => { clearTimeout(timeout); reject(new Error('CDP connection failed')); }, { once: true });
  });
  let seq = 0;
  const pending = new Map();
  const responses = [];
  const posts = new Map();
  const reads = new Map();
  const requestCookies = new Map();
  const browserErrors = {};
  const countError = (key) => { browserErrors[key] = (browserErrors[key] ?? 0) + 1; };
  // Classify locally; CDP text, URLs, and console arguments must not leave this worker.
  function errorKind(text) {
    if (/WebSocket/i.test(text)) return 'websocket';
    if (/responded with a status of 404\b/i.test(text)) return '404';
    if (/hydration|hydrating|server rendered HTML/i.test(text)) return 'hydration';
    if (/ChunkLoadError|Loading chunk|dynamically imported module/i.test(text)) return 'chunk-load';
    if (/Unexpected token|SyntaxError/i.test(text)) return 'syntax';
    if (/Cannot read properties|is not a function|TypeError/i.test(text)) return 'type';
    if (/ReferenceError/i.test(text)) return 'reference';
    if (/Content Security Policy/i.test(text)) return 'csp';
    if (/mime type/i.test(text)) return 'mime';
    return 'other';
  }
  ws.addEventListener('message', ({ data }) => {
    const msg = JSON.parse(data);
    if (msg.id) pending.get(msg.id)?.(msg);
    if (countPosts && msg.method === 'Network.requestWillBeSent') {
      const { url, method } = msg.params.request;
      if (method === 'POST') posts.set(url, (posts.get(url) ?? 0) + 1);
      if (method === 'GET') {
        const path = url.split('?')[0];
        reads.set(path, (reads.get(path) ?? 0) + 1);
      }
    }
    if (msg.method === 'Network.responseReceived') {
      const { response, type } = msg.params;
      responses.push({ id: msg.params.requestId, url: response.url, status: response.status, type,
        cached: response.fromDiskCache || response.fromServiceWorker || response.fromPrefetchCache });
    }
    if (msg.method === 'Network.requestWillBeSentExtraInfo') {
      const { requestId, headers } = msg.params;
      const value = Object.entries(headers).find(([name]) => name.toLowerCase() === 'cookie')?.[1] ?? '';
      requestCookies.set(requestId, value.split(';').some((part) => cookies.some(({ name }) => part.trimStart().startsWith(`${name}=`))));
    }
    if (msg.method === 'Runtime.exceptionThrown') {
      const { exceptionDetails: info } = msg.params;
      countError(`exception/${errorKind(info.exception?.description ?? info.text)}`);
    }
    if (msg.method === 'Runtime.consoleAPICalled' && ['error', 'warning', 'assert'].includes(msg.params.type)) {
      countError(`console/${errorKind(msg.params.args.map((arg) => arg.description ?? arg.value ?? '').join(' '))}`);
    }
    if (msg.method === 'Log.entryAdded' && msg.params.entry.level === 'error') {
      countError(`browser/${msg.params.entry.source}/${errorKind(msg.params.entry.text)}`);
    }
  });
  function call(method, params = {}) {
    const id = ++seq;
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => { pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 10_000);
      pending.set(id, (msg) => {
        clearTimeout(timeout);
        pending.delete(id);
        if (msg.error) reject(new Error(`CDP failed: ${method} (${msg.error.code})`));
        else resolve(msg.result);
      });
      ws.send(JSON.stringify({ id, method, params }));
    });
  }
  async function evaluate(expression) {
    let result;
    try {
      result = await call('Runtime.evaluate', { expression, returnByValue: true });
    } catch (error) {
      // Cross-document history may replace the execution context mid-poll.
      if (error.message === 'CDP failed: Runtime.evaluate (-32000)') return undefined;
      throw error;
    }
    // Full DevTools errors/arguments may contain sensitive values; do not include them in diagnostics.
    assert(!result.exceptionDetails, 'Browser evaluation threw');
    return result.result.value;
  }
  async function response(url, status, after, type = 'Fetch', expectCookie) {
    const { origin, pathname } = new URL(url);
    const route = pathname.replace(/\/(?:csv%3A|csv:)[^/]+$/i, '/:recordId');
    let seen;
    try {
      seen = await until(() => responses.slice(after).find((r) => r.url === url && r.type === type), `${type} ${route}`);
    } catch (error) {
      const observed = responses.slice(after).reduce((counts, r) => {
        const key = `${r.type}/${r.status}${r.url === url ? '/target' : ''}`;
        counts[key] = (counts[key] ?? 0) + 1;
        return counts;
      }, {});
      throw new Error(`${error.message}; browser responses ${JSON.stringify(observed)}; errors ${JSON.stringify(browserErrors)}`);
    }
    assert(seen.status === status && !seen.cached, `${route}: expected fresh HTTP ${status}, got ${seen.status}`);
    if (expectCookie !== undefined) {
      await until(() => requestCookies.has(seen.id), 'actual outgoing request headers');
      assert(requestCookies.get(seen.id) === expectCookie, `${origin}: unexpected fixture cookie transmission`);
    }
  }
  const navigate = async (url) => {
    const result = await call('Page.navigate', { url: new URL(url, ui).href });
    assert(!result.errorText, `Browser navigation failed: ${result.errorText}`);
  };
  const dom = (expr, label) => until(() => evaluate(expr), label);
  try {
    await call('Network.enable');
    await call('Runtime.enable');
    await call('Log.enable');
    await call('Page.enable');
    await call('Network.setCacheDisabled', { cacheDisabled: true });
    await call('Page.addScriptToEvaluateOnNewDocument', { source: `addEventListener('pageshow', (e) => {
      window.a13Restored = e.persisted;
      window.a13SourceVisibleOnShow = !!document.querySelector('.source-detail');
    });` });
    await call('Network.setCookies', { cookies: cookies.map((cookie) => ({ ...cookie, url: `${ui}${auth.cookiePath}/`, path: auth.cookiePath, httpOnly: true, sameSite: 'Lax' })) });
  } catch (error) {
    ws.close();
    throw error;
  }
  return { close: () => ws.close(), call, evaluate, response, navigate, dom, mark: () => responses.length,
    postCount: (url) => posts.get(url) ?? 0,
    readCount: (url) => reads.get(url) ?? 0,
    async hasHttpOnlyFixtureCookie(url) {
      const { cookies: stored } = await call('Network.getCookies', { urls: [url] });
      return cookies.length > 0 && cookies.every(({ name }) => stored.some((candidate) =>
        candidate.name === name && candidate.httpOnly && candidate.domain === new URL(ui).hostname
        && candidate.path === auth.cookiePath));
    } };
}

async function openKnowledge(page) {
  const before = page.mark();
  if (await page.evaluate(`location.href === ${JSON.stringify(`${ui}/knowledge`)}`)) {
    await page.call('Page.reload', { ignoreCache: true });
  } else {
    await page.navigate('/knowledge');
  }
  await page.response(`${ui}/knowledge`, 200, before, 'Document', false);
  await page.response(`${bridge}/knowledge`, 200, before, 'Fetch', true);
  assert(await page.evaluate(`!document.cookie.includes(${JSON.stringify(auth.cookieName)})`), 'Fixture cookie is browser-readable');
}

async function submit(page, question) {
  await page.dom(`document.querySelector('#knowledge-query')?.value === ''`, 'empty search input');
  await page.evaluate(`document.querySelector('#knowledge-query').focus()`);
  await page.call('Input.insertText', { text: question });
  await page.dom(`document.querySelector('form.knowledge-search button')?.disabled === false`, 'hydrated search button');
  const submitted = page.mark();
  await page.evaluate(`document.querySelector('form.knowledge-search button').click()`);
  const url = `${bridge}/knowledge/search?q=${encodeURIComponent(question)}`;
  await page.response(url, 200, submitted);
  return url;
}

async function search(page, fixture) {
  const { question, answer, ref, digest, foreignAnswer } = fixture;
  const sourcePath = `/sources/${encodeURIComponent(ref)}`;
  const searchUrl = await submit(page, question);
  await page.dom(`(() => {
    const row = document.querySelector('.citation-row');
    return document.querySelector('.search-answer')?.innerText === ${JSON.stringify(answer)}
      && document.querySelector('.search-results .verified-tag')?.textContent === 'Supported'
      && row?.querySelector('.citation-excerpt')?.innerText === ${JSON.stringify(`“${answer}”`)}
      && row?.innerText.includes('csv:lines=1-3') && row?.innerText.includes(${JSON.stringify(digest)})
      && row?.querySelector('a[href^="/sources/"]')?.getAttribute('href') === ${JSON.stringify(sourcePath)};
  })()`, 'supported answer, bounded citation and source link');
  assert(await page.evaluate(`!document.body.innerText.includes(${JSON.stringify(foreignAnswer)})`), 'Foreign fixture leaked into knowledge UI');
  return { sourcePath, searchUrl };
}

async function source(page, fixture, { sourcePath }) {
  const before = page.mark();
  await page.evaluate(`document.querySelector('.citation-row a[href^="/sources/"]').click()`);
  await page.response(`${ui}${sourcePath}`, 200, before, 'Document');
  await page.response(`${bridge}${sourcePath}`, 200, before);
  await page.dom(`(() => {
    const view = document.querySelector('.source-detail');
    return view?.querySelector('h2')?.innerText === ${JSON.stringify(fixture.ref)}
      && Array.from(view.querySelectorAll('dt')).some((label) => label.textContent === 'Physical CSV lines (inclusive)'
        && label.nextElementSibling?.innerText === '1–3')
      && view.innerText.includes(${JSON.stringify(fixture.digest)}) && view.innerText.includes(${JSON.stringify(fixture.extracted)});
  })()`, 'linked source provenance');
}

// This protocol is attached to the parent harness's private pipe, never to an HTTP route.
const reply = (msg) => process.stdout.write(`${JSON.stringify(msg)}\n`);
let readerCookies, fixture, queryPage, result, backMark;
try {
  await new Promise((resolve, reject) => provider.once('error', reject).listen(9013, '127.0.0.1', resolve));
  for await (const line of createInterface({ input: process.stdin })) {
    const msg = JSON.parse(line);
    if (msg.step === 'sign') {
      const issued = await Promise.all(msg.identities.map(([sub, sid]) => issue(msg.issuer, sub, sid)));
      readerCookies = issued[0].set;
      reply({ tokens: issued.map(({ token }) => token), ...(msg.httpOnly ? {
        cookie: readerCookies.map(({ name, value }) => `${name}=${value}`).join('; '),
      } : {}) });
    } else if (msg.step.startsWith('a14-')) {
      if (msg.port) {
        queryPage?.close();
        queryPage = await browser(msg.port, readerCookies, { countPosts: true });
      }
      const { reviewStep } = await import('./a14-browser.mjs');
      await reviewStep(queryPage, msg);
      reply({ ok: true });
    } else if (msg.step === 'alternatives') {
      queryPage = await browser(msg.port, readerCookies);
      // Direct top-level navigations make Lax cookies eligible; use the bridge
      // prefix on every host so the path alone cannot satisfy this assertion.
      for (const origin of ['http://127.0.0.1:8013', auth.origin]) {
        const url = `${origin}${auth.cookiePath}/v1/knowledge`;
        const mark = queryPage.mark();
        await queryPage.navigate(url);
        await queryPage.response(url, 404, mark, 'Document', false);
      }
      await openKnowledge(queryPage);
      await submit(queryPage, msg.unrelated);
      // The status badges are uppercased by CSS, not by the component.
      await queryPage.dom(`document.querySelector('.search-results .verified-tag')?.textContent === 'Insufficient evidence'
        && !document.querySelector('.search-answer, .citation-row')`, 'insufficient state');
      await openKnowledge(queryPage);
      await submit(queryPage, msg.question);
      await queryPage.dom(`document.querySelector('.search-results .verified-tag')?.textContent === 'Conflicting evidence'
        && !document.querySelector('.search-answer') && document.querySelectorAll('.citation-row').length === 2`, 'conflicting state');
      reply({ ok: true });
    } else if (msg.step === 'before') {
      fixture = msg;
      await openKnowledge(queryPage);
      result = await search(queryPage, fixture);
      // Click the literal citation link, then park the source in browser history.
      await source(queryPage, fixture, result);
      await openKnowledge(queryPage);
      await search(queryPage, fixture);
      assert(jwksReads > 0, 'Workspace did not fetch the public fixture key');
      reply({ ok: true });
    } else if (msg.step === 'after') {
      const before = queryPage.mark();
      await queryPage.evaluate(`Array.from(document.querySelectorAll('button')).find((b) => b.innerText === 'Refresh evidence').click()`);
      await queryPage.response(result.searchUrl, 403, before);
      await queryPage.response(`${bridge}/knowledge`, 403, before);
      await queryPage.dom(`Boolean(document.querySelector('.search-results .state-denied'))
        && !document.querySelector('.search-answer, .citation-row, .knowledge-list')
        && !document.querySelector('a[href^="/sources/"]') && !document.body.innerText.includes(${JSON.stringify(fixture.answer)})`,
      'refresh denial with answer, citation and source link removed');
      reply({ ok: true });
    } else if (msg.step === 'back') {
      backMark = queryPage.mark();
      await queryPage.evaluate('history.back()');
      const matches = `location.pathname === ${JSON.stringify(result.sourcePath)}`;
      try {
        await queryPage.dom(`${matches} && typeof window.a13Restored === 'boolean'`, 'actual source history navigation');
      } catch (error) {
        const state = await queryPage.evaluate(`({ matches: ${matches}, ready: document.readyState,
          pageshow: typeof window.a13Restored === 'boolean', source: !!document.querySelector('.source-detail') })`);
        throw new Error(`${error.message}; history state ${JSON.stringify(state)}`);
      }
      assert(await queryPage.evaluate(`!window.a13SourceVisibleOnShow && !document.querySelector('.source-detail')
        && !document.body.innerText.includes(${JSON.stringify(fixture.digest)})`), 'Parked source evidence showed before revalidation');
      reply({ ok: true, bfcache: Boolean(await queryPage.evaluate('window.a13Restored')) });
    } else if (msg.step === 'back-pending') {
      assert(await queryPage.evaluate(`location.pathname === ${JSON.stringify(result.sourcePath)}
        && !document.querySelector('.source-detail, .state-denied')
        && !document.body.innerText.includes(${JSON.stringify(fixture.digest)})`), 'Parked evidence or denial present while the real request is held');
      reply({ ok: true });
    } else if (msg.step === 'back-result') {
      await queryPage.response(`${bridge}${result.sourcePath}`, 403, backMark);
      await queryPage.dom(`Boolean(document.querySelector('.state-denied')) && !document.querySelector('.source-detail')
        && !document.body.innerText.includes(${JSON.stringify(fixture.digest)})`, 'source denial with no provenance');
      reply({ ok: true });
    } else if (msg.step === 'stats') {
      reply({ jwksReads });
    } else {
      throw new Error('Unknown fixture protocol step');
    }
  }
} catch (error) {
  // Send only known-safe messages; assertion diffs and request metadata can carry cookies.
  reply({ error: String(error.message).split('\n')[0].replace(/[\w.-]{70,}/g, '[redacted]') });
  process.exitCode = 1;
} finally {
  queryPage?.close();
  provider.closeAllConnections();
  provider.close();
}
