#!/usr/bin/env python3
"""Exercise the disposable A19.1 candidate in actual signed Chromium."""
import base64
import json
import os
import pwd
import select
import shutil
import subprocess
import sys
from contextlib import ExitStack
from hashlib import sha256
from pathlib import Path
from tempfile import mkdtemp
from urllib.parse import quote
from uuid import UUID, uuid4

import a13_demo as harness
from a13_demo import BRIDGE, UI, report, require, status
from a18_2_demo import BRIDGE as UNIFIED, PAGE, SCOPES, Chromium, quoted
from a18_3_demo import WIDE, contains, go, legacy_receipt, png_size, private_directory, start_next, visual_worker_script
from a18_3_fixture import _csv_allow, _csv_bytes, _xlsx_bytes
from a19_1_fixture import (BASE, CLASS, ORIGINAL_LABEL, RENAMED_LABEL, classified_native_guard, metadata,
                           pending, pending_state, request, setup, unavailable_metadata_detail, xlsx_gate, xlsx_publish)

META = BRIDGE + BASE.removeprefix('/v1')
ADMIN = META + '/catalogue/admin'
EXACT = '[aria-label="Validated metadata"]'
PROPOSED = '[aria-label="Proposed classification"]'
INTAKE = '[aria-label="Classified XLSX submission"]'
EVIDENCE = Path(pwd.getpwuid(os.getuid()).pw_dir) / '.hermes/evidence/BRI/A19.1/AM2/browser'
SHOTS = {
    '01-catalogue-active': 'Active tenant catalogue after an explicit seed and classification creation',
    '02-classified-xlsx': 'Classified workbook staged against the exact source node, before submission',
    '03-csv-initial-review': 'Native CSV evidence and the submitter’s classified proposal before independent approval',
    '04-xlsx-review-replacement': 'Reviewer’s replacement classification metadata at explicit confirmation',
    '05-historical-classification': 'Exact-version record resolves the renamed classification as retired; original approval label remains in history',
    '06-correction-proposal': 'Exact-version correction submitted and acknowledged, with authoritative metadata unchanged',
    '07-correction-conflict': 'Stale browser decision denied with protected metadata cleared and explicit refresh available',
    '08-corrected-metadata': 'Refreshed exact-version metadata after the competing correction, at revision two',
}
BLOCKER_SHOT = 'correction-ack-unconfirmed'


class Browser(Chromium):
    def run(self, step, **kwargs):
        # Keep the upstream pipe protocol, but identify bounded browser-control
        # failures without emitting private command values or page data.
        stdin, stdout = self.child.stdin, self.child.stdout
        assert stdin is not None and stdout is not None
        stdin.write(json.dumps(dict(step=step, **kwargs)).encode() + b'\n')
        stdin.flush()
        require(select.select([stdout], [], [], 30)[0], f'CDP worker timed out during {step}')
        line = stdout.readline()
        require(line, f'CDP worker exited during {step}')
        reply = json.loads(line)
        require('error' not in reply, f'CDP {step}: {reply.get("error")}')
        return reply.get('value')


def start_browser(args, scratch, stack):
    port = harness.start_chromium(args, scratch, stack)
    expr = "  } else if (m.step === 'eval') {"
    script = visual_worker_script()
    input_field = 'input:p.request.postData'
    require(script.count(expr) == script.count(input_field) == 1, 'Expected CDP extension points')
    # Binary originals are verified by the native storage/job digest, not by
    # recording raw upload request bodies in the CDP transaction map.
    script = script.replace(input_field, 'input:url.pathname.endsWith("/uploads") ? undefined : p.request.postData')
    script = script.replace(expr, '''  } else if (m.step === 'routeSummary') {
    return {value:[...traffic.values()].filter(i=>i.ix>m.mark && i.path.startsWith(m.prefix))
      .map(i=>({method:i.method,status:i.status,noStore:i.noStore,finished:i.finished}))};
  } else if (m.step === 'file') {
    const {root} = await command('DOM.getDocument', {});
    const {nodeId} = await command('DOM.querySelector', {nodeId:root.nodeId,selector:m.selector});
    if (!nodeId) throw Error('Expected file control');
    await command('DOM.setFileInputFiles', {nodeId,files:[m.file]});
''' + expr)
    log = stack.enter_context((scratch / 'fixture-worker.log').open('ab'))
    child = harness.launch(stack, [args.node, '--input-type=module', '-e', script],
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log)
    assert child.stdin is not None and child.stdout is not None
    stack.callback(child.stdin.close)
    stack.callback(child.stdout.close)
    browser = Browser(child, port)
    browser.run('viewport', width=WIDE[0], height=WIDE[1])
    return browser


def change(browser, selector, value):
    match = f'document.querySelector({quoted(selector)})'
    browser.expect(f'({match}) && !({match}).disabled && ({match}).getClientRects().length && '
                   f'Object.keys({match}).some(k=>k.startsWith("__reactProps$"))', f'hydrated {selector}')
    browser.dom(f'''(() => {{const el={match};
        Object.getOwnPropertyDescriptor(Object.getPrototypeOf(el),'value').set.call(el,{quoted(value)});
        el.dispatchEvent(new Event('input',{{bubbles:true}}));
        el.dispatchEvent(new Event('change',{{bubbles:true}}));}})()''')
    require(browser.dom(f'({match}).value') == value, f'Control did not retain {selector}')


def absence(browser, *markers):
    browser.expect(f'''(() => {{const main=document.querySelector('main');
      return main && !{quoted(markers)}.some(s=>main.outerHTML.includes(s) ||
        [...main.querySelectorAll('input,select,textarea')].some(e=>e.value.includes(s)));}})()''',
                   'protected markers absent from visible and hidden document state')


def visible_buttons(browser):
    browser.paint()
    return browser.dom('''[...document.querySelectorAll('main button')].filter(e=>e.getClientRects().length)
      .map(e=>({label:e.textContent.trim(), enabled:!e.disabled,
        hydrated:Object.keys(e).some(k=>k.startsWith('__reactProps$'))}))''')


def review_detail(browser, fmt, job):
    item = quote(f'{fmt}:{job}', safe='')
    page = ('/review/' if fmt == 'csv' else '/xlsx/review/') + item
    return go(browser, page), BRIDGE + f'/knowledge/proposals/{fmt}/' + item


def native_pending(browser, fmt, job, marker):
    mark, native = review_detail(browser, fmt, job)
    receipt = browser.receipt(mark, native, 200)
    detail = receipt['body']
    require(detail['id'] == f'{fmt}:{job}' and detail['state'] == 'proposed' and
            marker in json.dumps(detail), f'{fmt}: wrong real native pending detail')
    contains(browser, 'main', [marker], f'{fmt} native pending evidence rendered')
    return mark, native, receipt


def browser_fetch(browser, path, code, *, value=None, method='GET', headers=None):
    """Real same-origin Chromium request, independently checked by CDP."""
    mark = browser.mark()
    opts = {'method': method, 'cache': 'no-store', 'credentials': 'same-origin'}
    if value is not None:
        opts |= {'headers': {'Content-Type': 'application/json'} | (headers or {}), 'body': json.dumps(value)}
    observed = browser.dom(f'fetch({quoted(path)},{quoted(opts)}).then(async r=>{{await r.arrayBuffer(); return r.status;}})')
    require(observed == code, f'Browser probe: expected {code}, got {observed}')
    return browser.receipt(mark, path, code, method=method, body=code == 200).get('body')


def wire_decision(fmt, action):
    return {'approve': 'approved', 'reject': 'rejected'}[action] if fmt == 'csv' else action


def submit_native(browser, fmt, job, native, action, *, code=200):
    path = native + '/decision'
    opened = browser.mark()
    browser.click('Approve…' if action == 'approve' else 'Reject…')
    browser.paint()
    require(browser.run('count', mark=opened, path=path, method='POST') == 0, 'Native mutation before confirmation')
    mark = browser.mark()
    browser.click('Confirm approval' if action == 'approve' else 'Confirm rejection')
    receipt = browser.receipt(mark, path, code, method='POST', body=code == 200)
    decision = wire_decision(fmt, action)
    require(json.loads(receipt['input']) == {'decision': decision}, 'Wrong native decision payload')
    if code == 200:
        require(receipt['body'] == {'id': f'{fmt}:{job}', 'decision': decision}, 'Wrong native decision receipt')
        state = browser.receipt(mark, native, 200)['body']['state']
        require(state == wire_decision('csv', action), 'Fresh native read did not show the committed decision')
        browser.expect(f"document.querySelector('main').textContent.toLowerCase().includes({quoted(state)})",
                       'committed native state rendered')
    else:
        browser.expect("Boolean(document.querySelector('main [role=alert]')?.getClientRects().length)",
                       'opaque protected native decision denial')
    require(browser.run('count', mark=mark, path=path, method='POST') == 1, 'Native decision was retried')


def unauthorized_native(demo, fmt, job, marker, *, metadata_enabled):
    b = demo.b
    demo.as_user('unauthorized')  # active signed member, no review assignment
    mark, native = review_detail(b, fmt, job)
    b.receipt(mark, native, 403, body=False)
    b.expect("Boolean(document.querySelector('main [role=alert]')?.getClientRects().length)", 'native authorization denied')
    require(not any('approve' in row['label'].lower() or 'reject' in row['label'].lower() for row in visible_buttons(b)),
            'Unauthorized native reviewer rendered decision controls')
    absence(b, marker, str(job))
    require(not b.run('routeSummary', mark=mark, prefix=META + '/'), 'Unauthorized native detail dispatched metadata')
    require(b.run('count', mark=mark, path=native + '/decision', method='POST') == 0, 'Unauthorized UI dispatched a mutation')
    headers = {'Idempotency-Key': str(uuid4())} if fmt == 'xlsx' else None
    browser_fetch(b, native + '/decision', 403, method='POST', value={'decision': wire_decision(fmt, 'approve')}, headers=headers)
    if metadata_enabled:
        demo.fetch(f'/{fmt}/review/{job}', 404)
    pending_state(demo.data, fmt, job, classified=metadata_enabled)
    report(f'PASS {fmt.upper()} unauthorized signed Chromium: native detail and explicit native decision probe denied; no controls or mutation')


def off_browser(demo):
    b = demo.b
    failures = []
    unclassified = {}
    for fmt in ('csv', 'xlsx'):
        marker = f'AM2 unclassified {fmt.upper()} evidence'
        job = pending(demo.data, fmt, marker)
        demo.as_user('reviewer')
        mark, native, receipt = native_pending(b, fmt, job, marker)
        unclassified[fmt] = (job, marker)
        # A completed review control or terminal metadata error makes absence
        # meaningful; do not sample a transient spinner or unhydrated shell.
        b.expect('''[...document.querySelectorAll('main button')].some(e=>e.textContent==='Approve…' &&
          !e.disabled && Object.keys(e).some(k=>k.startsWith('__reactProps$'))) ||
          [...document.querySelectorAll('main [role="alert"]')].some(e=>e.getClientRects().length)''',
                 f'{fmt} terminal native controls or metadata error')
        buttons = visible_buttons(b)
        labels = {button['label'] for button in buttons if button['enabled'] and button['hydrated']}
        missing = sorted({'Approve…', 'Reject…'} - labels)
        calls = b.run('routeSummary', mark=mark, prefix=META + '/')
        alert = b.dom("document.querySelector('main [role=alert]')?.textContent ?? null")
        report(f'OFF {fmt.upper()} signed Chromium: native detail HTTP {receipt["status"]}, private no-store, '
               f'state=proposed, rendered evidence, controls={sorted(labels)}, metadata={calls}, alert={alert!r}')
        if missing or calls:
            failures.append(f'{fmt.upper()} missing {missing}; metadata requests={len(calls)}')
    require(not failures, 'OFF legacy compatibility: ' + '; '.join(failures))
    demo.http('catalogue', '/catalogue/admin/seed', 'manager', 204, method='POST', json={})
    for fmt, (job, marker) in unclassified.items():
        unauthorized_native(demo, fmt, job, marker, metadata_enabled=False)
        demo.as_user('reviewer')
        mark, native, _ = native_pending(b, fmt, job, marker)
        submit_native(b, fmt, job, native, 'approve')
        require(not b.run('routeSummary', mark=mark, prefix=META + '/'), 'OFF approval fetched metadata')
        marker = f'AM2 unclassified {fmt.upper()} rejection evidence'
        job = pending(demo.data, fmt, marker)
        mark, native, _ = native_pending(b, fmt, job, marker)
        submit_native(b, fmt, job, native, 'reject')
        require(not b.run('routeSummary', mark=mark, prefix=META + '/'), 'OFF rejection fetched metadata')
        marker = f'AM2 protected {fmt.upper()} pending evidence'
        job = pending(demo.data, fmt, marker, metadata_value=metadata('Synthetic protected metadata', 'policy'),
                      service=f'{fmt}_seed')
        mark, native, _ = native_pending(b, fmt, job, marker)
        # CSV's native handler deliberately masks an unexpected DB guard error
        # as unavailable; XLSX turns insufficient privilege into not found.
        submit_native(b, fmt, job, native, 'approve', code=503 if fmt == 'csv' else 404)
        require(not b.run('routeSummary', mark=mark, prefix=META + '/'), 'OFF guarded decision fetched metadata')
        classified_native_guard(demo.data, fmt, job)
        pending_state(demo.data, fmt, job, classified=True)
        demo.fetch(f'/{fmt}/review/{job}', 404)  # explicit signed route probe, not an application fetch
        report(f'PASS OFF {fmt.upper()} native approve/reject; classified native approval blocked by PostgreSQL 42501; '
               'no application metadata traffic and explicit browser metadata route denied')


def run_off(args, scratch, _):
    os.environ.update(TMPDIR=str(scratch), BRI_LOCAL_METADATA_ENABLED='0')
    with ExitStack() as stack:
        data = setup(args, scratch, stack, metadata_enabled=False, legacy_baseline=False)
        b = start_browser(args, scratch, stack)
        start_next(args, scratch, stack, data['client'])
        sample = str(uuid4())
        for page in (f'/review/csv%3A{sample}', f'/xlsx/review/xlsx%3A{sample}'):
            status(data['client'].get(UI + page, timeout=90), 200, 'unsigned page shell')
        off_browser(Demo(b, data, scratch))
        check_runtime(b)
    report('PASS AM2 OFF signed Chromium and service teardown')


def check_runtime(browser):
    failures = browser.run('diagnose', mark=0, path='')['runtimeFailures']
    require(not (set(failures) - {'WebSocket101'}), 'Uncaught Chromium runtime failure: ' + repr(failures))


def on_available_only(demo, jobs):
    """ON: a real metadata dependency failure cannot select the legacy path."""
    b = demo.b
    for fmt, job in jobs.items():
        unauthorized_native(demo, fmt, job, demo.marker[fmt], metadata_enabled=True)
        demo.as_user('reviewer')
        plain_marker = f'AM2 ON legacy {fmt.upper()} pending evidence'
        unclassified = pending(demo.data, fmt, plain_marker)
        with unavailable_metadata_detail(demo.data, fmt):
            for target, marker, classified in ((job, demo.marker[fmt], True), (unclassified, plain_marker, False)):
                mark, native, _ = native_pending(b, fmt, target, marker)
                endpoint = META + f'/{fmt}/review/{target}'
                b.receipt(mark, endpoint, 503, body=False)
                contains(b, 'main [role="alert"]', ['Classification information is unavailable.'],
                         'real unavailable metadata is distinct from unclassified')
                require(not any('approve' in row['label'].lower() or 'reject' in row['label'].lower()
                                for row in visible_buttons(b)), 'ON unavailable metadata rendered a decision control')
                absence(b, demo.submitted[fmt]['title'], 'No classification was submitted')
                for path in (native + '/decision', endpoint + '/decision'):
                    require(b.run('count', mark=mark, path=path, method='POST') == 0, 'Unavailable ON UI dispatched a decision')
                pending_state(demo.data, fmt, target, classified=classified)
        mark = b.mark()
        b.click('Refresh proposal')
        b.receipt(mark, native, 200)
        reply = b.receipt(mark, META + f'/{fmt}/review/{unclassified}', 200)['body']
        require(reply == {'job_id': str(unclassified), 'node_id': demo.node, 'proposed_metadata': None},
                'Restored dependency did not unambiguously establish the legacy proposal is unclassified')
        contains(b, PROPOSED, ['No classification was submitted'], 'explicit fresh ON classification read')
        submit_native(b, fmt, unclassified, native, 'approve')
        report(f'PASS ON {fmt.upper()}: real metadata 503 with native detail 200 offered no decision controls for '
               'classified or unclassified jobs; restored dependency plus explicit fresh read enabled native legacy approval')


def png(browser, staging, name, anchor):
    query = f'document.querySelector({quoted(anchor)})'
    browser.expect(f'Boolean(({query})?.getClientRects().length)', name)
    browser.dom(f'({query}).scrollIntoView({{block:"start",behavior:"instant"}})')
    browser.dom('document.fonts.ready.then(()=>true)')
    browser.paint()
    require(browser.dom(f'innerWidth==={WIDE[0]} && innerHeight==={WIDE[1]} && '
                        'document.documentElement.scrollWidth<=innerWidth'), 'Unexpected screenshot dimensions/overflow')
    raw = base64.b64decode(browser.run('png'), validate=True)
    require(png_size(raw) == WIDE, 'Bad PNG dimensions')
    # Chromium decodes the actual produced bytes again; it neither requests an
    # external resource nor adds this image to the product DOM.
    require(browser.dom(f'''new Promise(resolve=>{{const img=new Image(); img.src="data:image/png;base64,{base64.b64encode(raw).decode()}";
      img.decode().then(()=>resolve(img.naturalWidth==={WIDE[0]} && img.naturalHeight==={WIDE[1]}),()=>resolve(false));}})'''),
            'Chromium could not decode the full screenshot')
    with (staging / f'{name}.png').open('xb') as out:
        out.write(raw)


def publish(staging, shots, prefix):
    private_directory(EVIDENCE)
    require({p.name for p in staging.iterdir()} == {f'{name}.png' for name in shots}, 'Incomplete screenshot set')
    pending = Path(mkdtemp(prefix='.pending-', dir=EVIDENCE))
    batch = EVIDENCE / f'{prefix}-{uuid4().hex}'
    try:
        title = 'Complete acceptance' if prefix == 'run' else 'Diagnostic only — acceptance failed'
        manifest = [f'# {title}: signed synthetic Chromium screenshot manifest', '', '| PNG | Dimensions | Bytes | SHA-256 | Product state |',
                    '| --- | --- | ---: | --- | --- |']
        for name, description in shots.items():
            file = f'{name}.png'
            raw = (staging / file).read_bytes()
            with (pending / file).open('xb') as out:
                out.write(raw)
            require((pending / file).read_bytes() == raw and png_size(raw) == WIDE, 'Screenshot copy mismatch')
            manifest.append(f'| `{file}` | {WIDE[0]}×{WIDE[1]} | {len(raw)} | `{sha256(raw).hexdigest()}` | {description} |')
        (pending / 'manifest.md').write_text('\n'.join(manifest) + '\n')
        pending.rename(batch)
    finally:
        if pending.exists():
            shutil.rmtree(pending)
    return batch


class Demo:
    def __init__(self, browser, data, scratch):
        self.b, self.data, self.node = browser, data, data['scopes']['social']
        self.screens = scratch / 'captures'
        self.screens.mkdir()
        self.diagnostic = scratch / 'diagnostic-captures'
        self.marker = {'csv': 'A19 CSV source evidence', 'xlsx': 'A19 worksheet source evidence'}
        self.submitted = {fmt: metadata(f'Submitted {fmt.upper()} guidance') for fmt in self.marker}
        self.replacement = metadata('Reviewer-validated workbook title')
        self.xlsx_raw = _xlsx_bytes(self.marker['xlsx'])
        self.file = scratch / 'synthetic-service-guide.xlsx'
        self.file.write_bytes(self.xlsx_raw)

    def as_user(self, who):
        self.b.cookie(self.data['cookies'][who])

    def http(self, service, suffix, who, code=200, **kwargs):
        return request(self.data, service, BASE + suffix, who, code, **kwargs)

    def screenshot(self, name, anchor):
        require(name in SHOTS, 'Unexpected acceptance screenshot name')
        png(self.b, self.screens, name, anchor)

    def fetch(self, suffix, code, *, value=None, method='GET'):
        """Negative route probes in the browser, not claims of UI coverage."""
        return browser_fetch(self.b, META + suffix, code, value=value, method=method)

    def admin(self, *, empty=False):
        b = self.b
        self.as_user('manager')
        mark = go(b, '/classification')
        rows = b.receipt(mark, ADMIN, 200)['body']
        require(rows == [] if empty else any(row['classification_id'] == CLASS for row in rows), 'Unexpected initial catalogue')
        return rows

    def catalogue_action(self, action, caption, fields=None):
        b = self.b
        b.click(caption + '…')
        for key, value in (fields or {}).items():
            change(b, f'[aria-label="Catalogue maintenance"] [name="{key}"]', value)
        mark = b.mark()
        b.click(caption)
        b.receipt(mark, ADMIN + '/' + action, 204, method='POST', body=False)
        require(b.run('count', mark=mark, path=ADMIN + '/' + action, method='POST') == 1, 'Unexpected catalogue write count')
        return b.receipt(mark, ADMIN, 200)['body']

    def catalogue(self):
        b = self.b
        self.http('catalogue', '/catalogue/admin', None, 401)
        self.as_user('reader')
        mark = go(b, '/classification')
        b.receipt(mark, ADMIN, 403, body=False)
        contains(b, 'main [role="alert"]', ['Access denied'], 'reader is not a catalogue manager')
        self.admin(empty=True)
        require(any(row['classification_id'] == 'policy' for row in self.catalogue_action('seed', 'Provision starter catalogue')),
                'Explicit starter provisioning did not persist')
        rows = self.catalogue_action('create', 'Create classification', {'category': 'general', 'classification': CLASS,
                                                                         'label': ORIGINAL_LABEL, 'description': 'Synthetic local guidance'})
        want = dict(category_id='general', category_label='General', classification_id=CLASS, label=ORIGINAL_LABEL,
                    description='Synthetic local guidance', retired=False)
        require(want in rows, 'Classification creation did not persist')
        contains(b, '[aria-label="Tenant catalogue"]', [ORIGINAL_LABEL, CLASS], 'created catalogue row')
        self.screenshot('01-catalogue-active', '[aria-label="Tenant catalogue"]')
        for who in ('manager', 'wrong_node', 'reader'):
            self.as_user(who)
            self.fetch('/catalogue/selection/xlsx_submit/' + self.node, 403)
        self.as_user('foreign_submitter')
        require(self.fetch('/catalogue/selection/xlsx_submit/' + self.node, 200) == [], 'Foreign tenant saw local catalogue')
        self.as_user('submitter')
        self.fetch('/catalogue/selection/xlsx_submit/' + self.node.replace(':', '%3A'), 404)
        self.fetch('/catalogue/selection/xlsx_submit/root', 403)
        require(want in self.fetch('/catalogue/selection/csv_submit/' + self.node, 200), 'CSV exact selection did not contain created classification')
        report('PASS browser seed/create and independent unsigned, admin, exact-node, encoded-node and foreign catalogue controls')

    def upload(self):
        from bri.ingestion.csv_intake import ProcessOutcome

        b = self.b
        self.as_user('submitter')
        go(b, '/xlsx')
        selector = INTAKE + ' input[type=file]'
        expr = f'document.querySelector({quoted(selector)})'
        b.expect(f'({expr}) && Object.keys({expr}).some(k=>k.startsWith("__reactProps$"))', 'classified file control hydrated')
        b.run('file', selector=selector, file=str(self.file))
        change(b, INTAKE + ' input:not([type=file])', self.node)
        mark = b.mark()
        b.click('Load submission classifications')
        path = META + '/catalogue/selection/xlsx_submit/' + self.node
        rows = b.receipt(mark, path, 200)['body']
        expected = [row['classification_id'] for row in rows]
        b.expect(f'''JSON.stringify([...document.querySelectorAll({quoted(INTAKE + ' select[name=primary] option')})]
          .map(o=>o.value).filter(Boolean))===JSON.stringify({quoted(expected)})''', 'exact authorized rendered choices')
        change(b, INTAKE + ' select[name=primary]', CLASS)
        change(b, INTAKE + ' input[name=title]', self.submitted['xlsx']['title'])
        self.screenshot('02-classified-xlsx', INTAKE)
        mark = b.mark()
        b.click('Upload classified workbook')
        b.receipt(mark, META + '/xlsx/uploads', 202, method='POST', body=False)
        job_code = f'document.querySelector({quoted(INTAKE + " [role=status] code")})'
        b.expect(f'Boolean(({job_code})?.getClientRects().length)', 'rendered classified XLSX job receipt')
        xlsx = UUID(b.dom(f'({job_code}).textContent'))
        contains(b, INTAKE + ' [role="status"]', [str(xlsx), 'ready'], 'classified workbook receipt')
        report('PASS signed Chromium classified XLSX upload and visible ready receipt')
        require(b.run('count', mark=mark, path=BRIDGE + '/intake/xlsx', method='POST') == 0,
                'Classified file was sent to legacy intake')
        require(self.data['xlsx_stage'].state.xlsx_worker.dispatch(xlsx, uuid4()) == 'completed', 'Native XLSX worker did not complete')
        change(b, 'input[name="job"]', str(xlsx))
        mark = b.mark()
        b.click('Check job status')
        fresh = b.receipt(mark, BRIDGE + '/intake/xlsx/' + str(xlsx), 200)['body']
        require(fresh == {'id': str(xlsx), 'state': 'proposed'}, 'Legacy XLSX lifecycle does not report the same proposal')
        raw = _csv_bytes(self.marker['csv'], 'Synthetic browser acceptance')
        encoded = base64.urlsafe_b64encode(json.dumps(self.submitted['csv']).encode()).decode().rstrip('=')
        upload_headers = {'Content-Type': 'text/csv', 'X-Node-ID': self.node, 'Idempotency-Key': str(uuid4()), 'X-BRI-Metadata': encoded}
        browser_denial = self.data['client'].post(UI + META + '/csv/uploads', content=raw, headers=upload_headers | {
            'Cookie': self.data['cookies']['submitter'], 'Origin': UI})
        status(browser_denial, 404, 'CSV submission is not exposed through the browser bridge')
        result = self.http('csv_intake', '/csv/uploads', 'submitter', 202, method='POST', headers=upload_headers, content=raw)
        csv = UUID(result['id'])
        require(result == {'id': str(csv), 'state': 'ready'} and
                self.data['csv_stage'].state.csv_worker.dispatch(csv) is ProcessOutcome.COMPLETED, 'Native CSV worker did not complete')
        with self.data['fixture'].connect('postgres') as db:
            for table, job, original in (('csv_jobs', csv, raw), ('xlsx_jobs', xlsx, self.xlsx_raw)):
                require(db.execute(f'SELECT original_sha256 FROM bri.{table} WHERE (tenant_id,job_id)=(%s,%s)',
                                   (self.data['fixture'].tenant, job)).fetchone() == (sha256(original).hexdigest(),),
                        'Native job was not bound to the original uploaded bytes')
        report('PASS classified browser XLSX upload and lifecycle lookup; CSV versioned HTTP fixture-only upload; both real workers and original digests')
        return {'csv': csv, 'xlsx': xlsx}

    def initial(self, fmt, job):
        b = self.b
        suffix = f'/{fmt}/review/{job}'
        service = 'csv_review' if fmt == 'csv' else 'xlsx_governance'
        item = quote(f'{fmt}:{job}', safe='')
        native = BRIDGE + f'/knowledge/proposals/{fmt}/' + item
        for who in ('submitter', 'wrong_node', 'foreign_reviewer'):
            self.as_user(who)
            self.fetch(suffix, 404)
        self.as_user('reviewer')
        mark = go(b, ('/review/' if fmt == 'csv' else '/xlsx/review/') + item)
        detail = b.receipt(mark, native, 200)['body']
        require(detail['id'] == f'{fmt}:{job}' and detail['state'] == 'proposed' and
                self.marker[fmt] in json.dumps(detail), 'Wrong native initial-review evidence')
        require(b.receipt(mark, META + suffix, 200)['body'] == {'job_id': str(job), 'node_id': self.node,
                                                                  'proposed_metadata': self.submitted[fmt]},
                'Browser initial metadata did not match submitter snapshot')
        b.receipt(mark, META + f'/catalogue/selection/{fmt}_review/' + self.node, 200)
        contains(b, 'main', [self.marker[fmt], self.submitted[fmt]['title']], fmt + ' evidence and initial metadata rendered')
        if fmt == 'csv':
            self.screenshot('03-csv-initial-review', '[aria-label="Extracted evidence"]')
            b.click('Approve as proposed…')
            send = 'Confirm approval'
        else:
            b.click('Correct and approve…')
            change(b, '[aria-label="Review decision"] input[name=title]', self.replacement['title'])
            self.screenshot('04-xlsx-review-replacement', '[aria-label="Review decision"]')
            send = 'Confirm corrected approval'
        mark = b.mark()
        b.click(send)
        decision = b.receipt(mark, META + suffix + '/decision', 200, method='POST')
        expected = {'action': 'approve'} | ({'metadata': self.replacement} if fmt == 'xlsx' else {})
        payload = json.loads(decision['input'])
        UUID(payload.pop('request_id'))
        require(payload == expected and decision['body'] == {'job_id': str(job), 'decision': 'approve', 'metadata_revision': '1'},
                'Browser initial approval did not validate the intended metadata')
        current = b.receipt(mark, native, 200)['body']
        require(current['state'] == 'approved' and b.run('count', mark=mark, path=META + suffix + '/decision', method='POST') == 1,
                'Native review was not refreshed and committed exactly once')
        self.http(service, suffix, 'reviewer', 404)
        return self.replacement if fmt == 'xlsx' else self.submitted[fmt]

    def exact_path(self, fmt, record, job):
        return f'/{fmt}/records/{record}/versions/{job}'

    def open_record(self, fmt, record, job, who):
        self.as_user(who)
        path = f'/xlsx/knowledge/{record}' if fmt == 'xlsx' else f'/knowledge/{quote(f"csv:{record}", safe="")}'
        mark = go(self.b, path)
        return self.b.receipt(mark, META + self.exact_path(fmt, record, job), 200)['body']

    def access(self, jobs):
        csv, xlsx = jobs['csv'], jobs['xlsx']
        fixture = self.data['fixture']
        with fixture.connect('postgres') as db:
            record, = db.execute('SELECT record_id FROM bri.xlsx_validated_knowledge WHERE (tenant_id,job_id)=(%s,%s)',
                                 (fixture.tenant, xlsx)).fetchone()
        paths = {'csv': self.exact_path('csv', csv, csv), 'xlsx': self.exact_path('xlsx', record, xlsx)}
        self.as_user('reader')
        for path in paths.values():
            self.fetch(path, 404)
        _csv_allow(fixture, fixture.tenant, f'csv:{csv}')
        xlsx_publish(self.data, record, xlsx)
        self.fetch(paths['xlsx'], 404)
        for who in ('reader', 'proposer', 'corrector', 'competing', 'revoked'):
            xlsx_gate(self.data, 'record', record, xlsx, who)
            if who == 'reader':
                self.fetch(paths['xlsx'], 404)
            xlsx_gate(self.data, 'version', record, xlsx, who)
        for fmt, rec in (('csv', csv), ('xlsx', record)):
            self.as_user('wrong_node')
            self.fetch(paths[fmt], 404)
            self.as_user('foreign_reader')
            self.fetch(paths[fmt], 404)
            self.as_user('reader')
            actual = self.fetch(paths[fmt], 200)['metadata']
            require(actual['revision'] == '1' and actual['responsible_node_id'] == self.node and
                    actual['primary_classification'] == {'classification_id': CLASS, 'label': ORIGINAL_LABEL, 'retired': False},
                    'Exact authority did not return the validated classification snapshot')
            require(actual['title'] == (self.replacement if fmt == 'xlsx' else self.submitted['csv'])['title'], 'Wrong authoritative title')
            self.fetch(self.exact_path(fmt, rec, uuid4()), 404)
        xlsx_gate(self.data, 'record', record, xlsx, 'reader', False)
        self.fetch(paths['xlsx'], 404)
        xlsx_gate(self.data, 'record', record, xlsx, 'reader')
        report('PASS both initial approvals (including explicit XLSX replacement), exact reads and independent wrong-node/tenant/version/access denials')
        return record

    def history(self, csv, xlsx, record):
        b = self.b
        self.admin()
        renamed = self.catalogue_action('rename', 'Rename classification', {'classification': CLASS, 'label': RENAMED_LABEL})
        require(any(row['classification_id'] == CLASS and row['label'] == RENAMED_LABEL for row in renamed), 'Rename not persisted')
        retired = self.catalogue_action('retire', 'Retire classification', {'classification': CLASS})
        require(any(row['classification_id'] == CLASS and row['label'] == RENAMED_LABEL and row['retired'] for row in retired),
                'Retirement not persisted')
        self.as_user('submitter')
        require(CLASS not in {row['classification_id'] for row in self.fetch('/catalogue/selection/xlsx_submit/' + self.node, 200)},
                'Retired classification still offered')
        for fmt, rec, ver in (('csv', csv, csv), ('xlsx', record, xlsx)):
            live = self.open_record(fmt, rec, ver, 'reader')['metadata']
            require(live['primary_classification'] == {'classification_id': CLASS, 'label': RENAMED_LABEL, 'retired': True} and
                    live['revision'] == '1' and live['responsible_node_id'] == self.node and
                    live['title'] == (self.replacement if fmt == 'xlsx' else self.submitted['csv'])['title'],
                    'Rename or retirement changed an authoritative revision instead of resolving the current label')
            contains(b, EXACT, [RENAMED_LABEL, '(retired)', self.node], 'current historical projection and retired state')
            fixture = self.data['fixture']
            with fixture.connect('postgres') as db:
                original = db.execute('SELECT record_id,revision,primary_label FROM bri.knowledge_metadata_revisions '
                                      'WHERE (tenant_id,format,job_id)=(%s,%s,%s)', (fixture.tenant, fmt, ver)).fetchall()
            require(original == [(rec, 1, ORIGINAL_LABEL)], 'Rename or retirement rewrote the immutable original approval snapshot')
        self.screenshot('05-historical-classification', EXACT)
        report('PASS browser rename/retire, current retired projection, immutable original DB labels and no new selection')

    def propose(self, fmt, record, job, title, expected):
        b = self.b
        self.open_record(fmt, record, job, 'proposer')
        b.click('Propose a metadata correction…')
        change(b, EXACT + ' input[name=primary]', 'policy')
        change(b, EXACT + ' input[name=title]', title)
        b.click('Inspect correction before submitting')
        b.expect(f'''[...document.querySelectorAll({quoted(EXACT + ' legend')})].some(e=>
          e.getClientRects().length && e.textContent.includes('Submit this proposal for independent review'))''',
                 'visible correction preview before confirmation')
        mark = b.mark()
        b.click('Confirm metadata correction proposal')
        route = META + self.exact_path(fmt, record, job) + '/corrections'
        reply = b.receipt(mark, route, 200, method='POST')
        payload, result = json.loads(reply['input']), reply['body']
        require(payload['metadata'] == metadata(title, 'policy') and payload['expected_revision'] == expected and
                result['expected_revision'] == expected and UUID(result['proposal_id']) != UUID(payload['request_id']) and
                result['record_id'] == str(record) and result['source_version_id'] == str(job), 'Wrong correction proposal correlation')
        b.expect(f'''(() => {{const section=document.querySelector({quoted(EXACT)});
          return Boolean(section?.querySelector('[role="alert"]') ||
            section?.querySelector('[role="status"]')?.textContent.includes('Correction proposed:'));}})()''',
                 'terminal correction proposal view')
        if b.dom(f'Boolean(document.querySelector({quoted(EXACT + " [role=alert]")}))'):
            self.diagnostic.mkdir()
            png(b, self.diagnostic, BLOCKER_SHOT, EXACT)
            service = 'csv_reader' if fmt == 'csv' else 'xlsx_governance'
            listing = self.http(service, self.exact_path(fmt, record, job) + '/corrections', 'corrector')
            require(isinstance(listing, dict) and any(row['proposal_id'] == result['proposal_id'] for row in listing['items']),
                    'Correction acknowledged but not persisted for the authorized reviewer')
            raise RuntimeError('Browser renders an unconfirmed correction error despite HTTP 200, a distinct server-issued proposal UUID, '
                               'and independent signed reviewer read-back of that persisted proposal')
        contains(b, EXACT + ' [role="status"]', [result['proposal_id'], 'Validated metadata is unchanged'],
                 'server-generated correction acknowledgement rendered; HTTP 200 alone is not a UI pass')
        return result['proposal_id']

    def correction_choice(self, fmt, record, job, who, proposal):
        b = self.b
        self.open_record(fmt, record, job, who)
        mark = b.mark()
        b.click('Inspect pending metadata corrections')
        base = META + self.exact_path(fmt, record, job) + '/corrections'
        rows = b.receipt(mark, base, 200)['body']['items']
        require(proposal in {row['proposal_id'] for row in rows}, 'Correction proposal absent for independent reviewer')
        b.expect(f'''(() => {{const item=[...document.querySelectorAll('[aria-label="Pending metadata correction"]')]
          .find(row=>row.querySelector('code')?.textContent==={quoted(proposal)});
          const button=[...(item?.querySelectorAll('button')||[])].find(b=>b.textContent==='Approve metadata correction…');
          if(!button || button.disabled)return false; button.click(); return true;}})()''', 'open exact correction confirmation')
        contains(b, EXACT + ' fieldset legend', ['Apply this correction'], 'pending independent confirmation')
        return base + '/' + proposal + '/decision'

    def stale_rejection(self, fmt, record, job, proposal, fresh):
        # A fresh UI disables stale controls. Exercise the protected decision
        # itself under the same signed Chromium reviewer, not a mocked denial.
        b = self.b
        self.as_user('corrector')
        target = self.exact_path(fmt, record, job)
        path = target + f'/corrections/{proposal}/decision'
        mark = b.mark()
        self.fetch(path, 409, method='POST', value={'action': 'reject', 'request_id': str(uuid4())})
        require(b.run('count', mark=mark, path=META + path, method='POST') == 1, 'Stale rejection retried')
        observed = self.fetch(target, 200)['metadata']
        require(observed == fresh, 'Stale rejection modified authoritative metadata')
        fixture = self.data['fixture']
        with fixture.connect('postgres') as db:
            require(db.execute('SELECT count(*) FROM bri.knowledge_metadata_correction_decisions '
                               'WHERE (tenant_id,format,job_id,proposal_id)=(%s,%s,%s,%s)',
                               (fixture.tenant, fmt, job, UUID(proposal))).fetchone() == (0,),
                    'A stale rejection left a committed decision')
        report(f'PASS {fmt.upper()} stale correction rejection: signed browser-origin HTTP 409, no decision or metadata change')

    def corrections(self, record, job, csv):
        b = self.b
        path = self.exact_path('xlsx', record, job)
        endpoint = path + '/corrections'
        stale_title, winner_title, revoked_title = 'Stale competing draft', 'Corrected service handbook', 'Revoked session draft'
        stale = self.propose('xlsx', record, job, stale_title, '1')
        self.screenshot('06-correction-proposal', EXACT)
        self.fetch(endpoint, 404)  # proposer cannot inspect even their own item
        stale_reject = self.propose('xlsx', record, job, 'Stale XLSX rejection draft', '1')
        winner = self.propose('xlsx', record, job, winner_title, '1')
        url = self.correction_choice('xlsx', record, job, 'corrector', stale)
        command = {'action': 'approve', 'request_id': str(uuid4())}
        # Separate signed client commits while Chromium holds a real revision-1 confirmation.
        successful = self.http('xlsx_governance', endpoint + '/' + winner + '/decision', 'competing', method='POST', json=command)
        require(successful['metadata_revision'] == '2' and successful['proposal_id'] == winner, 'Competing correction did not commit')
        mark = b.mark()
        b.click('Confirm metadata correction approval')
        b.receipt(mark, url, 409, method='POST', body=False)
        contains(b, EXACT + ' [role="alert"]', ['The state changed', 'Refresh'], 'stale correction recovery')
        absence(b, stale_title, self.replacement['title'], stale, winner_title)
        require(b.run('count', mark=mark, path=META + path, method='GET') == 0 and
                b.run('count', mark=mark, path=url, method='POST') == 1, 'Stale decision automatically refreshed or retried')
        self.screenshot('07-correction-conflict', EXACT)
        mark = b.mark()
        b.click('Refresh exact-version metadata')
        fresh = b.receipt(mark, META + path, 200)['body']['metadata']
        require(fresh['revision'] == '2' and fresh['title'] == winner_title, 'Explicit refresh did not recover competing revision')
        contains(b, EXACT, [winner_title, 'Metadata revision'], 'fresh metadata revision shown')
        self.screenshot('08-corrected-metadata', EXACT)
        self.stale_rejection('xlsx', record, job, stale_reject, fresh)
        pending = self.propose('xlsx', record, job, revoked_title, '2')
        url = self.correction_choice('xlsx', record, job, 'revoked', pending)
        fixture = self.data['fixture']
        with fixture.connect('postgres') as db:
            require(db.execute('UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() WHERE session_id=%s AND revoked_at IS NULL',
                               (self.data['actors']['revoked'][2],)).rowcount == 1, 'Session revocation did not commit')
        mark = b.mark()
        b.click('Confirm metadata correction approval')
        b.receipt(mark, url, 404, method='POST', body=False)
        contains(b, EXACT + ' [role="alert"]', ['not found or is not available'], 'revoked decision recovery')
        absence(b, revoked_title, winner_title, pending)
        still = self.open_record('xlsx', record, job, 'reader')['metadata']
        require(still == fresh, 'Stale or revoked correction changed authoritative metadata')
        with fixture.connect('postgres') as db:
            require(db.execute("SELECT revision FROM bri.knowledge_metadata_revisions WHERE (tenant_id,format,job_id)=(%s,'xlsx',%s) "
                               'ORDER BY revision', (fixture.tenant, job)).fetchall() == [(1,), (2,)], 'Unexpected committed DB revision history')
        csv_title = 'Corrected CSV guide'
        stale_csv = self.propose('csv', csv, csv, 'Stale CSV rejection draft', '1')
        proposal = self.propose('csv', csv, csv, csv_title, '1')
        url = self.correction_choice('csv', csv, csv, 'corrector', proposal)
        mark = b.mark()
        b.click('Confirm metadata correction approval')
        valid = b.receipt(mark, url, 200, method='POST')['body']
        require(valid == {'record_id': str(csv), 'source_version_id': str(csv), 'proposal_id': proposal,
                          'decision': 'approve', 'metadata_revision': '2'} and
                b.run('count', mark=mark, path=url, method='POST') == 1, 'Independent browser correction did not commit exactly once')
        csv_path = META + self.exact_path('csv', csv, csv)
        csv_fresh = b.receipt(mark, csv_path, 200)['body']['metadata']
        require(csv_fresh['title'] == csv_title, 'CSV approval did not fetch authoritative correction')
        contains(b, EXACT, [csv_title, 'Metadata revision'], 'independent browser approval visible')
        require(self.open_record('csv', csv, csv, 'reader')['metadata']['revision'] == '2', 'Independent reader did not see CSV revision two')
        self.stale_rejection('csv', csv, csv, stale_csv, csv_fresh)
        report('PASS server-issued proposals, independent CSV browser approval, XLSX stale/revoked decisions, explicit refresh and exact DB revision history')

    def legacy(self):
        b = self.b
        baseline = self.data['baseline']
        self.as_user('reviewer')
        legacy = baseline['pending']
        item = quote(legacy['legacy_ref'], safe='')
        mark = go(b, '/review/' + item)
        b.receipt(mark, META + '/csv/review/' + legacy['version_id'], 200)
        contains(b, PROPOSED, ['No classification was submitted'], 'legacy proposal remained unclassified')
        b.click('Approve…')
        mark = b.mark()
        b.click('Confirm approval')
        resource = '/knowledge/proposals/csv/' + item
        require(b.receipt(mark, BRIDGE + resource + '/decision', 200, method='POST')['body']['decision'] == 'approved',
                'Legacy review could not independently approve')
        require(legacy_receipt(b, mark, resource)['state'] == 'approved', 'Legacy review did not verify committed decision')
        self.as_user('reader')
        mark = go(b, '/knowledge')
        legacy_receipt(b, mark, '/knowledge')
        b.change('Search validated knowledge', harness.QUESTION)
        mark = b.mark()
        b.click('Search →')
        answer = legacy_receipt(b, mark, '/knowledge/search')
        require(answer['status'] == 'supported' and answer['answer'] == harness.ANSWER, 'Legacy knowledge question regressed')
        contains(b, '.search-results', ['Supported', harness.ANSWER], 'independent CSV answer rendered')
        go(b, '/reports')
        change(b, '#inventory-scope', baseline['csv']['scope'])
        mark = b.mark()
        b.click('Evaluate inventory')
        inventory = legacy_receipt(b, mark, '/reports/published-knowledge-inventory')['result']
        require(inventory['status'] == 'complete' and {row['record_id'] for row in inventory['evidence']} == {baseline['csv']['legacy_ref']},
                'Legacy inventory lost CSV-only isolation')
        mark = go(b, PAGE)
        b.receipt(mark, UNIFIED + SCOPES, 200)
        b.state('scopes', 'complete')
        b.change('Organisational scope', baseline['csv']['scope'])
        query = baseline['xlsx']['marker']
        expected = [('xlsx', baseline['xlsx']['record_id'], 'exact'), ('csv', baseline['csv']['record_id'], 'substring')]
        result = b.results(b.query(query), baseline['csv']['scope'], query, expected)
        require(len(result) == 2, 'Legacy unified results changed')
        worksheet = baseline['xlsx']
        mark = go(b, f'/xlsx/knowledge/{worksheet["record_id"]}/evidence/{worksheet["version_id"]}')
        receipt = b.receipt(mark, BRIDGE + worksheet['evidence_path'].removeprefix('/v2'), 200)['body']
        contains(b, '[aria-label="Worksheet evidence"]', [query], 'unchanged independent v1 worksheet')
        require(receipt['source_version_id'] == worksheet['version_id'], 'Legacy worksheet wrong exact version')
        report('PASS independent existing CSV question, legacy A14 approval, CSV-only reporting, unified mixed search, and v1 exact worksheet')


def run(args, scratch, _):
    # Chromium's process-singleton socket uses TMPDIR even with a fresh profile.
    # Keep it inside the directory the A13 launcher removes on failure as well.
    os.environ.update(TMPDIR=str(scratch), BRI_LOCAL_METADATA_ENABLED='1')
    with ExitStack() as stack:
        data = setup(args, scratch, stack)
        browser = start_browser(args, scratch, stack)
        start_next(args, scratch, stack, data['client'])
        # Only public document shells are warmed. All protected API reads are from signed Chromium.
        sample = str(uuid4())
        for page in ('/classification', '/xlsx', f'/review/csv%3A{sample}', f'/xlsx/review/xlsx%3A{sample}',
                     f'/knowledge/csv%3A{sample}', f'/xlsx/knowledge/{sample}', f'/xlsx/knowledge/{sample}/evidence/{sample}'):
            status(data['client'].get(UI + page, timeout=90), 200, 'unsigned page shell')
        demo = Demo(browser, data, scratch)
        demo.catalogue()
        jobs = demo.upload()
        on_available_only(demo, jobs)
        for fmt, job in jobs.items():
            demo.initial(fmt, job)
        record = demo.access(jobs)
        demo.history(jobs['csv'], jobs['xlsx'], record)
        demo.legacy()
        try:
            demo.corrections(record, jobs['xlsx'], jobs['csv'])
        except RuntimeError:
            if demo.diagnostic.exists():
                folder = publish(demo.diagnostic, {BLOCKER_SHOT: 'Browser displayed an error after a persisted HTTP 200 correction'}, 'diagnostic')
                report(f'DIAGNOSTIC ONLY (not an acceptance batch): {folder}')
            raise
        check_runtime(browser)
    report('PASS signed Chromium assertions and service teardown')
    batch = publish(demo.screens, SHOTS, 'run')
    report(f'PASS A19.1 AM2 ON signed Chromium: {len(SHOTS)} verified synthetic PNGs in {batch}')


if __name__ == '__main__':
    sys.exit(harness.main(run, entry=os.path.abspath(__file__), name='a19-1', browser_required=True, description=__doc__))
