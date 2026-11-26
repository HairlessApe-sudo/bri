// A14-only browser assertions for the A13 private-pipe Chromium worker.
import assert from 'node:assert/strict';

const ui = 'http://127.0.0.2:3013';
const bridge = `${ui}/api/bri-local/v1/knowledge/proposals/csv`;
const queueUrl = (state) => `${bridge}?status=${state}&limit=50`;
const path = (ref) => `/review/${encodeURIComponent(ref)}`;
const detail = (ref) => `${bridge}/${encodeURIComponent(ref)}`;
const evidence = 'section[aria-label="Extracted evidence"]';
const provenance = 'section[aria-label="Provenance"]';
const actions = 'section[aria-label="Review decision"]';
const history = 'section[aria-label="Review history"]';
const rowLinks = 'table[aria-label="CSV review queue"] tbody a';
const q = JSON.stringify;

async function button(page, text) {
  await page.dom(`(() => {
    const el = [...document.querySelectorAll('button')].find((el) => !el.disabled
      && el.getClientRects().length && el.textContent.trim() === ${q(text)});
    if (!el) return false;
    el.click();
    return true;
  })()`, `button: ${text}`);
}

async function assertState(page, label, last, terminal = true, reasons = []) {
  const events = ['submitted', 'ready', 'claimed', ...(last === 'failed' ? [] : ['proposed']),
    ...(last === 'proposed' ? [] : [last])];
  await page.dom(`document.querySelector('[aria-label="Proposal state"] h2')?.textContent === ${q(label)}
    && JSON.stringify([...document.querySelectorAll(${q(`${history} li strong`)})].map(el => el.textContent)) === ${q(q(events))}
    && JSON.stringify([...document.querySelectorAll(${q(`${history} li code`)})].map(el => el.textContent)) === ${q(q(reasons))}
    && Boolean(document.querySelector(${q(actions)})) === ${!terminal}`, `${label} state/history/controls`);
}

async function queue(page, expected, filter = 'proposed') {
  const mark = page.mark();
  if (filter === 'proposed') {
    await page.navigate('/review');
    await page.response(`${ui}/review`, 200, mark, 'Document', false);
  } else {
    await page.evaluate(`(() => { const select = document.querySelector('[aria-label="Review queue"] select');
      select.value = ${q(filter)}; select.dispatchEvent(new Event('change', {bubbles: true})); })()`);
  }
  await page.response(queueUrl(filter), 200, mark, 'Fetch', true);
  await page.dom(`JSON.stringify([...document.querySelectorAll(${q(rowLinks)})].map(el => el.textContent).sort())
    === ${q(q([...expected].sort()))}${expected.length ? '' : " && document.body.innerText.includes('No proposals on this page.')"}`,
  `${filter} queue rows`);
}

async function openRow(page, ref) {
  const mark = page.mark();
  // Follow the rendered anchor itself; a wrapped inline link has no reliable
  // hit target at the center of its union rectangle in a narrow viewport.
  await page.evaluate(`document.querySelector(${q(`${rowLinks}[href=${q(path(ref))}]`)}).click()`);
  await page.response(`${ui}${path(ref)}`, 200, mark, 'Document', false);
  await page.response(`${detail(ref)}?offset=0`, 200, mark, 'Fetch', true);
}

export async function reviewStep(page, msg) {
  const { step, approved, stale, failed, ref } = msg;
  if (step === 'a14-denied') {
    // Use the exact cookie path on the other listener so host-only scope matters.
    const target = 'http://127.0.0.1:8114/api/bri-local/v1/knowledge/proposals/csv';
    let mark = page.mark();
    await page.navigate(target);
    await page.response(target, 404, mark, 'Document', false);
    mark = page.mark();
    await page.navigate(path(ref));
    await page.response(`${ui}${path(ref)}`, 200, mark, 'Document', false);
    await page.response(`${detail(ref)}?offset=0`, 403, mark, 'Fetch', true);
    await page.dom(`document.body.innerText.includes('This session is not authorized to review here.')
      && !document.querySelector(${q(`${evidence}, ${provenance}, ${actions}`)})`, 'signed non-reviewer denied');
    assert(await page.hasHttpOnlyFixtureCookie(`${detail(ref)}?offset=0`), 'Fixture cookie is not installed as expected');
  } else if (step === 'a14-approve') {
    await queue(page, [approved, stale]);
    await openRow(page, approved);
    await assertState(page, 'Proposed', 'proposed', false);
    const expected = ['Source ID', approved, 'Source version ID', approved, 'Source version', '1',
      'Extraction ID', approved, 'Original SHA-256', msg.original, 'Extracted SHA-256', msg.extracted,
      'CSV lines (inclusive)', '1–4'];
    await page.dom(`JSON.stringify([...document.querySelectorAll(${q(`${provenance} :is(dt,dd)`)})].map(el => el.textContent)) === ${q(q(expected))}
      && document.querySelector(${q(`${evidence} pre`)})?.textContent === ${q(msg.evidence)}
      && document.querySelector(${q(`${evidence} pre`)})?.childElementCount === 0
      && !document.querySelector('a14-literal')`, 'exact provenance, literal markup and formula text');
    const decision = `${detail(approved)}/decision`;
    await button(page, 'Approve…');
    await page.dom(`document.querySelector('fieldset legend')?.textContent === 'Confirm approval'`, 'approval confirmation');
    await button(page, 'Cancel');
    await page.dom(`!document.querySelector('fieldset') && !!document.querySelector(${q(actions)})`, 'cancelled approval');
    assert.equal(page.postCount(decision), 0, 'Opening and cancelling must not submit an approval');
    await button(page, 'Approve…');
    const mark = page.mark();
    await button(page, 'Confirm approval');
    await page.response(decision, 200, mark, 'Fetch', true);
    await page.response(`${detail(approved)}?offset=0`, 200, mark, 'Fetch', true);
    await assertState(page, 'Approved', 'approved');
    await page.dom(`document.body.innerText.includes('Approval does not publish the record or authorize access.')`, 'non-publication notice');
    assert.equal(page.postCount(decision), 1, 'Confirmation must submit one approval');
  } else if (step === 'a14-prepare-stale') {
    await queue(page, [ref]);
    await openRow(page, ref);
    await assertState(page, 'Proposed', 'proposed', false);
    await button(page, 'Approve…');
    await page.dom(`document.querySelector('fieldset legend')?.textContent === 'Confirm approval'`, 'stale decision confirmation open');
  } else if (step === 'a14-stale') {
    const endpoint = detail(ref);
    const decision = `${endpoint}/decision`;
    const priorReads = page.readCount(endpoint);
    assert.equal(page.postCount(decision), 0, 'Stale snapshot must not post before confirmation');
    let mark = page.mark();
    await button(page, 'Confirm approval');
    await page.response(decision, 409, mark, 'Fetch', true);
    await page.dom(`document.querySelector('[role="alert"]')?.textContent.includes('This proposal already changed.')
      && !document.querySelector(${q(`${evidence}, ${provenance}, ${actions}, ${history}`)})`, 'stale alert with old snapshot removed');
    assert.equal(page.readCount(endpoint), priorReads, 'The stale response must not start a detail read');
    mark = page.mark();
    await button(page, 'Refresh proposal');
    await page.response(`${detail(ref)}?offset=0`, 200, mark, 'Fetch', true);
    await assertState(page, 'Rejected', 'rejected');
    // The development remount may start more than one read. The invariant is
    // zero before refresh, then a fresh successful read without another POST.
    assert(page.readCount(endpoint) > priorReads, 'Explicit refresh must start a detail read');
    assert.equal(page.postCount(decision), 1, 'Refresh must not retry the decision');
  } else if (step === 'a14-terminal') {
    await queue(page, []);
    await queue(page, [approved], 'approved');
    await queue(page, [stale], 'rejected');
    await queue(page, [failed], 'failed');
    await openRow(page, failed);
    await assertState(page, 'Processing failed', 'failed', true, ['invalid_csv']);
    await page.dom(`document.querySelector(${q(evidence)})?.innerText.includes('No extracted evidence is available.')
      && !document.querySelector(${q(`${provenance}, ${evidence} pre`)})`, 'failed processing has no extraction or provenance');
  } else {
    throw new Error('Unknown A14 browser step');
  }
}
