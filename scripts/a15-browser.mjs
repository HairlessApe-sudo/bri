// A15 Chromium assertions. Runs only on the disposable harness's private pipe.
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import { setTimeout as delay } from 'node:timers/promises';

const origin = 'http://127.0.0.2:3013';
const cookiePath = '/api/bri-local';
const report = `${origin}${cookiePath}/v1/reports/published-knowledge-inventory`;
const evidenceSection = '[aria-label="Inventory evidence"]';
const q = JSON.stringify;
assert(!process.stdin.isTTY && !process.stdout.isTTY);
let ws;
let seq = 0;
const responses = [];
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
  const scoped = (await call('Network.getCookies', { urls: [report] })).cookies;
  assert(scoped.length && scoped.every((item) => item.httpOnly && item.path === cookiePath && item.domain === '127.0.0.2'));
}

const evaluate = async (expression) => (await call('Runtime.evaluate', { expression, returnByValue: true })).result?.value;
const dom = (expression, label) => until(() => evaluate(expression), label);
const response = (url, status, mark) => until(() => responses.slice(mark).some((r) => r.url === url && r.status === status), 'expected HTTP response');

async function openReports() {
  const mark = responses.length;
  await call('Page.navigate', { url: `${origin}/reports` });
  await response(`${origin}/reports`, 200, mark);
  await dom(`!!document.querySelector('#inventory-scope')`, 'reports shell');
}

async function submit(code, scope = 'team') {
  // Wait for real React hydration before dispatching the native input event.
  await dom(`(() => {
    const input = document.querySelector('#inventory-scope');
    return input && Object.keys(input).some(key => key.startsWith('__reactProps$'));
  })()`, 'reports hydration');
  const mark = responses.length;
  await evaluate(`(() => {
    const input = document.querySelector('#inventory-scope');
    if (input.value !== ${q(scope)}) {
      Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, ${q(scope)});
      input.dispatchEvent(new Event('input', { bubbles: true }));
    }
  })()`);
  await evaluate(`document.querySelector('form button[type="submit"]').click()`);
  await response(`${report}?scope_node_id=${scope}`, code, mark);
}

async function complete(rows) {
  await submit(200);
  const expected = rows.map((row) => [row.record_id, `/knowledge/${encodeURIComponent(row.record_id)}`,
    `/sources/${encodeURIComponent(row.record_id)}`, row.source_version_id, row.original_sha256,
    row.content_sha256, `${row.first_line}–${row.last_line}`]);
  await dom(`(() => {
    const view = document.querySelector(${q(evidenceSection)});
    if (!view || document.querySelector('[role="status"]').textContent !== ${q(`Readable published records: ${rows.length}`)}) return false;
    const actual = [...view.querySelectorAll('li')].map(li => {
      const [record, source] = li.querySelectorAll('a');
      return [record.textContent, record.getAttribute('href'), source.getAttribute('href'), ...[...li.querySelectorAll('dd')].map(dd => dd.textContent)];
    });
    return JSON.stringify(actual) === ${q(q(expected))};
  })()`, 'DOM evidence exactly matches the signed API result');
}

try {
  for await (const line of createInterface({ input: process.stdin })) {
    const { step, port, cookie, rootCookie, evidence, ref } = JSON.parse(line);
    if (step === 'complete') {
      await attach(port);
      await installCookie(rootCookie);
      await openReports();
      await submit(200, 'root');
      await dom(`document.querySelector('[role="status"]')?.textContent === 'No readable published knowledge records at this node.'
        && !document.querySelector(${q(evidenceSection)})`, 'authorized empty with no evidence');
      await installCookie(cookie);
      await openReports();
      await complete(evidence);
      const source = `/sources/${encodeURIComponent(ref)}`;
      const mark = responses.length;
      await evaluate(`document.querySelector(${q(`${evidenceSection} a[href="${source}"]`)}).click()`);
      await response(`${origin}${cookiePath}/v1${source}`, 200, mark);
      await dom(`document.querySelector('.source-detail h2')?.textContent === ${q(ref)}`, 'freshly authorized source details');
      await openReports();
      await complete(evidence);
    } else if (step === 'restored') {
      await complete(evidence);
    } else if (step === 'unavailable' || step === 'denied') {
      const unavailable = step === 'unavailable';
      assert(await evaluate(`!!document.querySelector(${q(evidenceSection)})`), 'Expected visible previous evidence');
      await submit(unavailable ? 503 : 403);
      const text = unavailable ? 'The inventory could not be completed.' : 'This session is not authorized';
      await dom(`document.querySelector('[role="status"]')?.textContent.startsWith(${q(text)})
        && !document.querySelector(${q(evidenceSection)})`, 'fresh failure clears old evidence');
    } else if (step === 'dependency') {
      await submit(503);
      await dom(`document.querySelector('[role="status"]')?.textContent.startsWith('The local reporting service could not be reached')
        && !document.querySelector(${q(evidenceSection)})`, 'stopped dependency does not return metric data');
    } else throw new Error('Unknown A15 browser step');
    process.stdout.write('{"ok":true}\n');
  }
} catch (error) {
  // Only controlled assertion/timeout messages; do not emit cookies or page contents.
  process.stdout.write(`${q({ error: error.message })}\n`);
  process.exitCode = 1;
} finally {
  ws?.close();
}
