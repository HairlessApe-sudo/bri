// A16.3 Chromium assertions (CDP transport from A15). Runs only on the disposable harness's private pipe.
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import { setTimeout as delay } from 'node:timers/promises';

const origin = 'http://127.0.0.2:3013';
const cookiePath = '/api/bri-local';
const api = `${origin}${cookiePath}/v1`;
const intake = `${api}/intake/xlsx`;
const reviews = `${api}/knowledge/proposals/xlsx`;
const evidenceSection = '[aria-label="Worksheet evidence"]';
const q = JSON.stringify;
assert(!process.stdin.isTTY && !process.stdout.isTTY);
let ws;
let seq = 0;
const responses = [];
const requests = [];
const pending = new Map();

async function until(check, label) {
  const stop = Date.now() + 45_000;
  do {
    if (await check()) return;
    await delay(100);
  } while (Date.now() < stop);
  throw new Error(`Timed out: ${label}`);
}

async function call(method, params = {}) {
  const id = ++seq;
  const { promise, resolve } = Promise.withResolvers();
  const timer = setTimeout(() => resolve({ error: true }), 10_000);
  pending.set(id, resolve);
  try {
    ws.send(q({ id, method, params }));
    const msg = await promise;
    if (msg.error) throw new Error(`Chromium command failed: ${method}`);
    return msg.result;
  } finally {
    clearTimeout(timer);
    pending.delete(id);
  }
}

async function attach(port) {
  assert(Number.isInteger(port) && port > 0 && port < 65536);
  const res = await fetch(`http://127.0.0.1:${port}/json/list`, { redirect: 'error', signal: AbortSignal.timeout(5000) });
  const page = (await res.json()).find(({ type }) => type === 'page');
  const endpoint = new URL(page.webSocketDebuggerUrl);
  assert.equal(endpoint.origin, `ws://127.0.0.1:${port}`);
  ws = new WebSocket(endpoint);
  await once(ws, 'open', { signal: AbortSignal.timeout(5000) });
  ws.addEventListener('message', ({ data }) => {
    const msg = JSON.parse(data);
    if (msg.id) pending.get(msg.id)?.(msg);
    if (msg.method === 'Network.requestWillBeSent') requests.push(msg.params.request);
    if (msg.method === 'Network.responseReceived') responses.push(msg.params.response);
  });
  await call('Network.enable');
  await call('Page.enable');
  await call('Network.setCacheDisabled', { cacheDisabled: true });
}

async function installCookie(cookie) {
  await call('Network.clearBrowserCookies');
  await call('Network.setCookies', { cookies: cookie.split('; ').map((pair) => {
    const eq = pair.indexOf('=');
    return { name: pair.slice(0, eq), value: pair.slice(eq + 1), url: `${origin}${cookiePath}/`,
      path: cookiePath, httpOnly: true, sameSite: 'Lax' };
  }) });
  const scoped = (await call('Network.getCookies', { urls: [intake] })).cookies;
  assert(scoped.length && scoped.every((item) => item.httpOnly && item.path === cookiePath && item.domain === '127.0.0.2'));
}

const evaluate = async (expression) => (await call('Runtime.evaluate', { expression, returnByValue: true })).result?.value;
const dom = (expression, label) => until(() => evaluate(expression), label);
async function response(url, status, mark) {
  try {
    await until(() => responses.slice(mark).some(r => r.url === url && r.status === status), `HTTP ${status} for ${new URL(url).pathname}`);
  } catch (error) {
    const observed = responses.slice(mark).filter(r => r.url.startsWith(api)).map(r => `${r.status} ${new URL(r.url).pathname}`);
    throw new Error(`${error.message}; browser API responses: ${observed.join(', ') || 'none'}`);
  }
}

const page = async (path) => {
  const mark = responses.length;
  await call('Page.navigate', { url: `${origin}${path}` });
  await response(`${origin}${path}`, 200, mark);
};
const button = (label) => `[...document.querySelectorAll('button')].find(b => b.textContent === ${q(label)})`;
const click = async (label) => {
  const find = button(label);
  await dom(`(() => {const b = ${find}; return b && !b.disabled && Object.keys(b).some(k => k.startsWith('__reactProps$'));})()`, label);
  await evaluate(`${find}.click()`);
};
const set = (name, value) => evaluate(`document.querySelector('input[name="${name}"]').value = ${q(value)}`);
const selector = (s) => `document.querySelector(${q(s)})`;
const detailPage = (job) => `/xlsx/review/${encodeURIComponent(`xlsx:${job}`)}`;
const detailApi = (job) => `${reviews}/${encodeURIComponent(`xlsx:${job}`)}`;
const missing = (text) => dom(`${selector('[role="alert"]')}?.textContent === ${q(text)} && !${selector(evidenceSection)} && !${selector('[aria-label="XLSX review decision"]')} && !${selector('a[href*="/evidence/"]')}`, 'generic denial with no evidence or controls');
const expected = [['A1','text','Policy'], ['B1','text','Evidence'], ['A2','text','Records'], ['B2','text','Employee files must be retained for ten years.'], ['A3','text','<demo-literal>café</demo-literal>'], ['B3','text','=1+1']];
const worksheet = () => dom(`(() => {
  const view = ${selector(evidenceSection)};
  if (!view || view.querySelector('p')?.textContent !== 'Worksheet Synthetic · Sheet ID 1 · A1:B3' || view.querySelector('demo-literal')) return false;
  const cells = [...view.querySelectorAll('dl div')].map(d => [...d.querySelector('dt').textContent.split(' · '), d.querySelector('dd').textContent]);
  return JSON.stringify(cells) === ${q(q(expected))};
})()`, 'exact typed coordinates, sheet, range and literal text');
const reviewState = (job, state) => dom(`[...document.querySelectorAll('p')].some(p => p.textContent === ${q(`xlsx:${job} · team · ${state}`)})`, `review state ${state}`);
let staleMark;

async function run({ step, port, cookie, file, job, jobs, state, record }) {
  if (port) await attach(port);
  if (cookie) await installCookie(cookie);
  if (step === 'upload') {
    await page('/xlsx');
    // Install the fixture bytes as a browser File; the real React form performs the upload.
    await dom(`!!${selector('input[name="workbook"]')}`, 'workbook input');
    await evaluate(`(() => {
      const data = new DataTransfer();
      data.items.add(new File([Uint8Array.from(atob(${q(file)}), c => c.charCodeAt(0))], 'synthetic.xlsx',
        {type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'}));
      const input = ${selector('input[name="workbook"]')};
      input.files = data.files;
      input.dispatchEvent(new Event('change', { bubbles: true }));
    })()`);
    await set('node', 'team');
    const mark = responses.length;
    await click('Upload workbook');
    await response(intake, 202, mark);
    await dom(`${selector('[role="status"]')}?.textContent.endsWith(' · ready')`, 'ready upload receipt');
    job = await evaluate(`${selector('[role="status"] code')}.textContent`);
    assert(/^[0-9a-f-]{36}$/.test(job), 'Missing job ID');
  }
  if (step === 'upload' || step === 'status') {
    await set('job', job);
    const mark = responses.length;
    await click('Check job status');
    await response(`${intake}/${job}`, 200, mark);
    await dom(`${selector('[role="status"]')}?.textContent === ${q(`Job ${job} · ${state}`)}`, `signed job status ${state}`);
    return { job };
  }
  if (step === 'review-denied') {
    const mark = responses.length;
    await page(detailPage(job));
    await response(detailApi(job), 403, mark);
    await missing('Access denied.');
  } else if (step === 'approve' || step === 'stale-open') {
    if (step === 'approve') {
      await page('/xlsx/review');
      const expectedQueue = jobs.map(id => [`xlsx:${id}`, 'team', 'proposed']);
      await dom(`JSON.stringify([...document.querySelectorAll('[aria-label="XLSX review queue"] tbody tr')].map(tr => [...tr.cells].map(td => td.textContent))) === ${q(q(expectedQueue))}`, 'exact pending queue');
      await evaluate(`${selector(`a[href="${detailPage(job)}"]`)}.click()`);
    } else await page(detailPage(job));
    await reviewState(job, 'proposed');
    await worksheet();
    const post = detailApi(job) + '/decision';
    const posts = () => requests.filter(r => r.url === post && r.method === 'POST').length;
    const before = posts();
    await click('Approve…');
    if (step === 'stale-open') {
      staleMark = before;
      assert.equal(posts(), before);
      return {};
    }
    await click('Cancel');
    assert.equal(posts(), before);
    await click('Approve…');
    const mark = responses.length;
    await click('Confirm approval');
    await response(post, 200, mark);
    await response(detailApi(job), 200, mark);
    await reviewState(job, 'approved');
    await worksheet();
    assert.equal(await evaluate(`!!${selector('[aria-label="XLSX review decision"]')}`), false);
    assert.equal(posts(), before + 1);
  } else if (step === 'stale-submit') {
    const post = detailApi(job) + '/decision';
    const posts = () => requests.filter(r => r.url === post && r.method === 'POST').length;
    assert.equal(posts(), staleMark);
    let mark = responses.length;
    await click('Confirm approval');
    await response(post, 409, mark);
    await missing('The proposal changed. Refresh the proposal before taking another action.');
    assert.equal(posts(), staleMark + 1);
    mark = responses.length;
    await click('Refresh proposal');
    await response(detailApi(job), 200, mark);
    await reviewState(job, 'rejected');
    await worksheet();
    assert.equal(await evaluate(`!!${selector('[aria-label="XLSX review decision"]')}`), false);
    assert.equal(posts(), staleMark + 1, 'Explicit refresh must not send another decision');
  } else if (step === 'closed' || step === 'open' || step === 'revoked' || step === 'switch-denied') {
    const path = `/xlsx/knowledge/${record}`;
    const target = `${api}/knowledge/xlsx/${record}`;
    const suffix = `/evidence/${job}`;
    const verifyClosed = async (evidence, refresh = false) => {
      const mark = responses.length;
      if (refresh) await click('Refresh evidence');
      else await page(path + (evidence ? suffix : ''));
      const denied = step === 'switch-denied';
      await response(target + (evidence ? suffix : ''), denied ? 403 : 404, mark);
      await missing(denied ? 'Access denied.' : evidence ? 'XLSX evidence not found.' : 'XLSX record not found.');
    };
    if (step === 'open') {
      let mark = responses.length;
      await page(path);
      await response(target, 200, mark);
      await dom(`JSON.stringify([...document.querySelectorAll('main dd')].map(d => d.textContent)) === ${q(q([record, job, 'team']))}`, 'exact published record and source version');
      mark = responses.length;
      await evaluate(`${selector(`a[href="${path + suffix}"]`)}.click()`);
      await response(target + suffix, 200, mark);
      await dom(`${selector('main p code')}?.textContent === ${q(job)}`, 'published evidence source version');
      await worksheet();
    } else {
      if (step !== 'closed') await worksheet();
      await verifyClosed(true, step !== 'closed');
      await verifyClosed(false);
    }
  } else throw new Error('Unknown A16.3 browser step');
  return {};
}

try {
  for await (const line of createInterface({ input: process.stdin })) {
    const result = await run(JSON.parse(line));
    process.stdout.write(`${q({ ok: true, ...result })}\n`);
  }
} catch (error) {
  // Controlled labels only, never dump CDP payloads, credentials or page text.
  process.stdout.write(`${q({ error: error.name === 'AssertionError' ? 'Browser assertion failed' : error.message })}\n`);
  process.exitCode = 1;
} finally {
  ws?.close();
}
