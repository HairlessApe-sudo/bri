#!/usr/bin/env python3
"""Capture the governed A18.3 product demo using a private signed Chromium session."""
import base64
import json
import os
import pwd
import shutil
import stat
import struct
import subprocess
import sys
from contextlib import ExitStack
from pathlib import Path
from tempfile import mkdtemp
from urllib.parse import parse_qs, quote
from uuid import UUID, uuid4

import a13_demo as harness
from a13_demo import BRIDGE as LEGACY, ROOT, UI, report, require, status
from a18_2_demo import BRIDGE, CDP, PAGE, SCOPES, SEARCH, Chromium, Gate, quoted, wire_query

EVIDENCE_ROOT = Path(pwd.getpwuid(os.getuid()).pw_dir) / '.hermes/evidence/BRI/A18.3/screenshots'
WIDE = (1440, 1000)
NARROW = (980, 1000)
SHOTS = {
    '01-initial': WIDE,
    '02-scope-selector': WIDE,
    '03-mixed-results': WIDE,
    '04-csv-multiline-evidence': WIDE,
    '05-xlsx-worksheet': WIDE,
    '06-expanded-provenance': NARROW,
    '07-zero-results': WIDE,
    '08-unavailable': WIDE,
    '09-csv-review': WIDE,
    '10-csv-reporting': WIDE,
    '11-csv-question': WIDE,
    '12-xlsx-v1-evidence': WIDE,
    '13-csv-review-confirmation': WIDE,
}


def visual_worker_script():
    # Extend the accepted private-pipe driver, whose responses omit headers and
    # cookies. The only new payloads are URL query fields and rendered PNG bytes.
    before_eval = "  } else if (m.step === 'eval') {"
    traffic_path = 'path:url.pathname, cursor:'
    require(CDP.count(before_eval) == CDP.count(traffic_path) == 1, 'A18.2 CDP extension points changed')
    return CDP.replace(traffic_path, 'path:url.pathname, query:url.search, cursor:').replace(before_eval, '''
  } else if (m.step === 'viewport') {
    await command('Emulation.setDeviceMetricsOverride', {width:m.width, height:m.height, deviceScaleFactor:1, mobile:false});
  } else if (m.step === 'png') {
    const {data} = await command('Page.captureScreenshot', {format:'png', fromSurface:true, captureBeyondViewport:false});
    return {value:data};
''' + before_eval)


def start_visual_browser(args, scratch, stack):
    port = harness.start_chromium(args, scratch, stack)
    log = stack.enter_context((scratch / 'fixture-worker.log').open('ab'))
    child = harness.launch(stack, [args.node, '--input-type=module', '-e', visual_worker_script()],
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log)
    assert child.stdout is not None and child.stdin is not None
    stack.callback(child.stdout.close)
    stack.callback(child.stdin.close)
    browser = Chromium(child, port)
    browser.run('viewport', width=WIDE[0], height=WIDE[1])
    return browser


def png_size(data):
    require(data[:16] == b'\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR' and
            data[-12:] == b'\0\0\0\0IEND\xaeB`\x82' and len(data) > 1024,
            'Chromium did not return a complete PNG')
    return struct.unpack('>II', data[16:24])


class Screenshots:
    def __init__(self, directory, browser):
        directory.mkdir(mode=0o700)
        self.directory, self.browser = directory, browser

    def take(self, name, *, anchor=None):
        width, height = SHOTS[name]
        file = self.directory / f'{name}.png'
        require(not file.exists(), 'Duplicate screenshot name')
        self.browser.run('viewport', width=width, height=height)
        try:
            if anchor:
                node = f'document.querySelector({quoted(anchor)})'
                self.browser.expect(f'Boolean(({node})?.getClientRects().length)', f'{name} visible screenshot anchor')
                self.browser.dom(f'({node}).scrollIntoView({{block:"start",behavior:"instant"}})')
            else:
                self.browser.dom('window.scrollTo({top:0,behavior:"instant"})')
            self.browser.dom('document.fonts.ready.then(()=>true)')
            self.browser.paint()
            require(self.browser.dom(f'innerWidth==={width} && innerHeight==={height} && '
                                     'document.documentElement.scrollWidth<=innerWidth'),
                    f'Unexpected viewport size or horizontal overflow in {name}')
            data = base64.b64decode(self.browser.run('png'), validate=True)
            require(png_size(data) == (width, height), f'Unexpected dimensions in {name}')
            with file.open('xb') as out:
                out.write(data)
        finally:
            if (width, height) != WIDE:
                self.browser.run('viewport', width=WIDE[0], height=WIDE[1])


def private_directory(path):
    if not path.exists():
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    meta = path.lstat()
    require(path.resolve(strict=True) == path and stat.S_ISDIR(meta.st_mode) and
            meta.st_uid == os.getuid() and not meta.st_mode & 0o077,
            'Screenshot destination must be a private local directory without symlinks')


def publish_screenshots(directory):
    expected = {f'{name}.png': size for name, size in SHOTS.items()}
    require({p.name for p in directory.iterdir()} == set(expected), 'Incomplete or unexpected screenshot set')
    # Publish a new complete batch or nothing. Earlier successful runs stay intact.
    private_directory(EVIDENCE_ROOT.parent)
    private_directory(EVIDENCE_ROOT)
    batch = EVIDENCE_ROOT / f'run-{uuid4().hex}'
    staging = Path(mkdtemp(prefix='.pending-', dir=EVIDENCE_ROOT))
    try:
        for name, size in expected.items():
            original = (directory / name).read_bytes()
            copy = staging / name
            with copy.open('xb') as out:
                out.write(original)
            actual = copy.read_bytes()
            require(actual == original and png_size(actual) == size, 'Screenshot copy verification failed')
        staging.rename(batch)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    require({p.name for p in batch.iterdir()} == set(expected), 'Published screenshot count mismatch')
    return batch


def go(browser, path):
    mark = browser.mark()
    browser.page(path)
    browser.receipt(mark, path, 200, body=False)
    return mark


def contains(browser, selector, texts, label):
    browser.expect(f'''(() => {{const el=document.querySelector({quoted(selector)});
      return el?.getClientRects().length && {quoted(texts)}.every(s=>el.textContent.includes(s));}})()''', label)


def legacy_receipt(browser, mark, path, *, query=None):
    receipt = browser.receipt(mark, LEGACY + path, 200)
    if query is not None:
        require(parse_qs(receipt['query'].lstrip('?')) == query, 'Legacy request did not use exact query parameters')
    return receipt['body']


def open_evidence(browser, index, path, code=200):
    mark = browser.mark()
    browser.click('View evidence', index)
    return browser.evidence(mark, path, code)


def select_scope(browser, scope):
    browser.change('Organisational scope', scope)


def search(browser, scope, query, expected, **kwargs):
    return browser.results(browser.query(query), scope, query, expected, **kwargs)


def refresh(browser, code, state):
    mark = browser.mark()
    browser.click('Refresh scopes')
    value = browser.receipt(mark, BRIDGE + SCOPES, code, body=code == 200).get('body')
    browser.state('scopes', state)
    browser.no_search(mark)
    return value


def cells_for_dom(evidence):
    def address(row, col):
        letters = ''
        while col:
            col, n = divmod(col - 1, 26)
            letters = chr(65 + n) + letters
        return f'{letters}{row}'

    result = []
    for cell in evidence['cells']:
        pair = cell['value']
        kind, *value = pair or ['blank']
        text = str(value[0]).lower() if value and kind == 'boolean' else str(value[0]) if value else ''
        result.append([f'{address(cell["row"], cell["column"])} · {kind}', text])
    return result


def start_next(args, scratch, stack, client):
    web = harness.next_copy(scratch)
    log = stack.enter_context((scratch / 'next.log').open('wb'))
    server = harness.launch(stack, [args.node, 'local-workspace/server.mjs'], cwd=web,
                            env=harness.swc_environment(scratch, args.swc_archive), stdout=log, stderr=log)

    def ready():
        import httpx
        try:
            return client.get(UI + LEGACY + '/knowledge', timeout=1).status_code == 401
        except httpx.TransportError:
            return False

    harness.until(ready, 'Next unsigned legacy bridge 401', process=server, seconds=90)
    # Compile only public document shells; all protected reads are triggered by
    # the real signed browser and awaited independently by the CDP driver.
    for path in (PAGE, '/knowledge', '/review', '/reports'):
        status(client.get(UI + path, timeout=90), 200, 'unsigned public page shell')
    status(client.get(UI + BRIDGE + SCOPES), 401, 'unsigned unified discovery bridge')


def expected_hit(record, match):
    return (record['format'], record['record_id'], match)


def assert_hit(hit, record):
    digest_key = 'content_sha256' if record['format'] == 'csv' else 'canonical_sha256'
    checks = {'version': hit['source_version_id'] == record['version_id'],
              'evidence route': hit['evidence_url'] == record['evidence_path'],
              'original digest': hit['original_sha256'] == record['original_sha256'],
              'content digest': hit[digest_key] == record['extracted_sha256'],
              'folded excerpt': wire_query(record['marker']) in hit['excerpt']}
    require(all(checks.values()), 'Unexpected signed hit fields: ' + ', '.join(k for k, ok in checks.items() if not ok))


def verify_csv(browser, hit, record, receipt):
    require(hit['evidence'] == {'first_line': 2, 'last_line': 3} and
            receipt == {'record_id': record['record_id'], 'source_version_id': record['version_id'],
                        'first_line': 1, 'last_line': 3, 'original_sha256': record['original_sha256'],
                        'content_sha256': record['extracted_sha256']}, 'Unexpected CSV physical line or provenance receipt')
    contains(browser, '#knowledge-results', ['Physical CSV lines 2–3 (inclusive)'], 'CSV matched physical lines')
    contains(browser, '#knowledge-evidence', ['Physical CSV lines 1–3 (inclusive)',
             'Matched location: Physical CSV lines 2–3 (inclusive)', record['version_id']], 'CSV full and matched receipts')


def verify_xlsx(browser, hit, record, receipt):
    sheet = hit['evidence']
    require(sheet == {'sheet_id': '1', 'sheet_title': 'Service guidance', 'cell': 'B2'} and
            receipt['version'] == 2 and receipt['record_id'] == record['record_id'] and
            receipt['source_version_id'] == record['version_id'] and receipt['original_sha256'] == record['original_sha256'] and
            receipt['canonical_sha256'] == record['extracted_sha256'] and receipt['extractor_version'] == 1 and
            receipt['canonicalization_version'] == 1 and receipt['sheet_id'] == '1' and
            receipt['sheet_title'] == 'Service guidance' and receipt['cell_range'] == 'A1:B2' and
            {'row': 2, 'column': 2, 'value': ['text', record['marker']]} in receipt['cells'],
            'XLSX v2 receipt did not match the exact worksheet, cell, digests and version')
    contains(browser, '#knowledge-evidence', ['Matched worksheet cell: B2', 'Service guidance', 'A1:B2',
                                             record['marker']], 'XLSX evidence and matching worksheet cell')
    browser.worksheet('#knowledge-evidence [aria-label="Worksheet evidence"]', cells_for_dom(receipt))


def assert_restricted(records, browser, hits):
    excluded = [records[name] for name in ('hidden', 'record_only', 'foreign')]
    markers = [r[key] for r in excluded for key in ('record_id', 'version_id', 'marker')]
    require(not any(marker in json.dumps(hits) for marker in markers), 'Inaccessible fixture leaked in response')
    browser.expect(f'''!{quoted(markers)}.some(marker=>document.querySelector('main')?.textContent.includes(marker))''',
                   'hidden, unilateral and foreign markers absent in the actual DOM')


def legacy_screens(browser, photos, data, multiline, worksheet, v2):
    question = data['question']
    browser.cookie(data['cookies']['reader'])
    mark = go(browser, '/knowledge')
    legacy_receipt(browser, mark, '/knowledge')
    browser.change('Search validated knowledge', question['text'])
    mark = browser.mark()
    browser.click('Search →')
    result = legacy_receipt(browser, mark, '/knowledge/search', query={'q': [question['text']]})
    require(result['status'] == 'supported' and result['answer'] == question['answer'] and
            [row['record_id'] for row in result['citations']] == [question['record_id']],
            'A13 question did not return the supported CSV citation')
    contains(browser, '.search-results', ['Supported', question['answer']], 'A13 supported question answer')
    source = '/sources/' + quote(question['record_id'], safe='')
    citation = quoted(f'.search-results a[href="{source}"]')
    browser.expect(f'Boolean(document.querySelector({citation}))', 'A13 citation source link')
    photos.take('11-csv-question')
    mark = browser.mark()
    browser.dom(f'document.querySelector({citation}).click()')
    legacy_receipt(browser, mark, source)
    contains(browser, '.source-detail', [question['record_id'], 'Physical CSV lines'], 'A13 follows actual source link')
    report('PASS signed A13 supported CSV question and linked source')

    browser.cookie(data['cookies']['reviewer'])
    pending = data['records']['pending_csv']
    ref = pending['legacy_ref']
    mark = go(browser, '/review')
    resource = '/knowledge/proposals/csv'
    legacy_receipt(browser, mark, resource, query={'status': ['proposed'], 'limit': ['50']})
    detail = resource + '/' + quote(ref, safe='')
    page = '/review/' + quote(ref, safe='')
    row = quoted(f'table[aria-label="CSV review queue"] a[href="{page}"]')
    browser.expect(f'Boolean(document.querySelector({row}))', 'A14 pending proposal offered by actual review queue')
    mark = browser.mark()
    browser.dom(f'document.querySelector({row}).click()')
    browser.receipt(mark, page, 200, body=False)
    review = legacy_receipt(browser, mark, detail, query={'offset': ['0']})
    require(review['id'] == ref and review['state'] == 'proposed', 'A14 browser did not open the pending proposal')
    contains(browser, '[aria-label="Extracted evidence"]', [pending['marker']], 'A14 pending extraction shown')
    contains(browser, '[aria-label="Provenance"]', [ref, pending['original_sha256'], pending['extracted_sha256']],
             'A14 exact source provenance')
    browser.click('Approve…')
    contains(browser, 'fieldset legend', ['Confirm approval'], 'A14 explicit approval confirmation')
    photos.take('13-csv-review-confirmation', anchor='[aria-label="Review decision"]')
    mark = browser.mark()
    browser.click('Confirm approval')
    ack = browser.receipt(mark, LEGACY + detail + '/decision', 200, method='POST')
    require(ack['body'] == {'id': ref, 'decision': 'approved'} and json.loads(ack['input']) == {'decision': 'approved'},
            'A14 browser approval handshake did not match the selected proposal and decision')
    approved = legacy_receipt(browser, mark, detail, query={'offset': ['0']})
    require(approved['id'] == ref and approved['state'] == 'approved' and approved['history'][-1]['event'] == 'approved' and
            browser.run('count', mark=mark, path=LEGACY + detail + '/decision', method='POST') == 1,
            'A14 did not verify the committed approval through a fresh read')
    contains(browser, '[aria-label="Proposal state"]', ['Approved', 'Approval does not publish the record or authorize access.'],
             'A14 approved state and separate authorization notice')
    photos.take('09-csv-review')

    browser.cookie(data['cookies']['reader'])
    client = data['client']
    status(client.get(data['origins']['unified'] + pending['evidence_path'], headers=data['headers']['reader']),
           404, 'A14 approval without CSV access overlay must not expose exact evidence')
    report('PASS signed A14 actual review approval and fresh confirmation without new employee access')
    go(browser, '/reports')
    browser.expect('''(() => {const el=document.querySelector('#inventory-scope');
      return el && Object.keys(el).some(k=>k.startsWith('__reactProps$'));})()''', 'A15 report input hydrated')
    browser.change('Exact node ID', multiline['scope'])
    mark = browser.mark()
    browser.click('Evaluate inventory')
    inventory = legacy_receipt(browser, mark, '/reports/published-knowledge-inventory',
                               query={'scope_node_id': [multiline['scope']]})
    expected_ids = [multiline['legacy_ref']]
    evidence = inventory['result']['evidence']
    require(inventory['result']['status'] == 'complete' and inventory['result']['count'] == len(expected_ids) and
            sorted(row['record_id'] for row in evidence) == expected_ids, 'A15 report was not scoped CSV-only inventory')
    direct = status(client.get(data['origins']['csv_reader'] + '/v1/reports/published-knowledge-inventory',
                               params={'scope_node_id': multiline['scope']}, headers=data['headers']['reader']),
                    200, 'A15 direct consumer parity').json()
    require(direct == inventory, 'A15 UI/consumer parity failed')
    contains(browser, '#inventory-title', ['Published knowledge inventory'], 'A15 report heading')
    contains(browser, 'section[aria-labelledby="inventory-title"] [role="status"]',
             [f'Readable published records: {len(expected_ids)}'], 'A15 exact visible inventory count')
    contains(browser, '[aria-label="Inventory evidence"]', expected_ids + [multiline['extracted_sha256']], 'A15 CSV evidence links')
    photos.take('10-csv-reporting')

    page = f'/xlsx/knowledge/{worksheet["record_id"]}/evidence/{worksheet["version_id"]}'
    mark = go(browser, page)
    v1 = legacy_receipt(browser, mark, page.replace('/xlsx/knowledge/', '/knowledge/xlsx/', 1))
    require(v2 == v1 | {'version': 2, 'source_id': worksheet['version_id'], 'original_sha256': worksheet['original_sha256'],
                        'canonical_sha256': worksheet['extracted_sha256'], 'extractor_version': 1,
                        'canonicalization_version': 1}, 'A16 v1 worksheet differed from unified v2 except for intended provenance')
    browser.worksheet('[aria-label="Worksheet evidence"]', cells_for_dom(v1))
    photos.take('12-xlsx-v1-evidence')
    report('PASS signed A15 CSV-only inventory and A16 v1 worksheet parity with unified v2')


def run_product(browser, photos, data, gated):
    from a18_3_fixture import SCOPE_LABELS

    records, scopes = data['records'], data['scopes']
    reader_cookie = data['cookies']['reader']
    csv_record, xlsx_record = (records[key] for key in data['mixed']['records'])
    require(csv_record['format'] == 'csv' and xlsx_record['format'] == 'xlsx' and
            csv_record['scope'] == xlsx_record['scope'], 'Mixed demo needs both formats in one exact scope')
    scope, query = csv_record['scope'], data['mixed']['query']
    ordered = [expected_hit(xlsx_record, 'exact'), expected_hit(csv_record, 'substring')]
    option_pairs = sorted((SCOPE_LABELS[name] for name in ('social', 'information', 'hr', 'empty')),
                          key=lambda pair: (pair[1], pair[0]))
    options = [[node, f'{label} — {node}'] for node, label in option_pairs]
    discovery = {'version': 1, 'status': 'complete', 'scopes': [
        {'scope_node_id': node, 'display_label': label} for node, label in option_pairs]}

    def employee_workspace():
        browser.cookie(reader_cookie)
        mark = go(browser, PAGE)
        require(browser.receipt(mark, BRIDGE + SCOPES, 200)['body'] == discovery, 'Wrong signed employee scope catalog')
        browser.revalidated_view('complete', options=options)
        browser.no_search(mark)

    employee_workspace()
    contains(browser, '#unified-title', ['Knowledge Interface'], 'Knowledge Interface heading')
    photos.take('01-initial')
    select_scope(browser, scope)
    browser.scopes(options)
    assert_restricted(records, browser, [])
    photos.take('02-scope-selector')
    mixed = search(browser, scope, f'  {query.upper()}  ', ordered)
    require(search(browser, scope, query, ordered) == mixed, 'Normalized repeat changed result contents or order')
    assert_hit(mixed[0], xlsx_record)
    assert_hit(mixed[1], csv_record)
    assert_restricted(records, browser, mixed)
    photos.take('03-mixed-results')
    csv = open_evidence(browser, 1, csv_record['evidence_path'])
    verify_csv(browser, mixed[1], csv_record, csv)
    photos.take('04-csv-multiline-evidence', anchor='#knowledge-results li[data-format="csv"]')
    xlsx = open_evidence(browser, 0, xlsx_record['evidence_path'])
    verify_xlsx(browser, mixed[0], xlsx_record, xlsx)
    photos.take('05-xlsx-worksheet', anchor='#knowledge-evidence')
    browser.provenance(0, {'Record ID': xlsx_record['record_id'], 'Exact source version ID': xlsx_record['version_id'],
                           'Original SHA-256': xlsx_record['original_sha256'], 'Canonical SHA-256': xlsx_record['extracted_sha256'],
                           'Extractor version': '1', 'Canonicalization version': '1', 'Worksheet ID': '1'})
    photos.take('06-expanded-provenance', anchor='#knowledge-results li[data-format="xlsx"]')

    forbidden = [records[key][field] for key in ('hidden', 'record_only', 'foreign') for field in ('record_id', 'marker')]
    select_scope(browser, scopes['empty'])
    browser.cleared(xlsx_record['version_id'], csv_record['record_id'], *forbidden)
    search(browser, scopes['empty'], query, [])
    photos.take('07-zero-results')
    for key, match in (('social', 'exact'), ('information', 'substring'), ('hr', 'exact')):
        sample = records[key]
        if sample['query'] == query and sample['scope'] == scope:
            continue  # already asserted in the independently ordered mixed receipt
        select_scope(browser, sample['scope'])
        hits = search(browser, sample['scope'], sample['query'], [expected_hit(sample, match)])
        assert_hit(hits[0], sample)
    for key, node in (('foreign', scopes['social']), ('record_only', records['record_only']['scope']), ('hidden', scope)):
        select_scope(browser, node)
        search(browser, node, records[key]['query'], [])
    report('PASS employee authorized scope discovery, all three departments, exact-before-substring mixed results, and valid empty/hidden/foreign controls')

    db_fixture = data['fixture']
    select_scope(browser, scope)
    search(browser, scope, query, ordered)
    # Hold a successful real DB/API result beyond the existing bridge deadline.
    # Chromium must get the bridge's own unavailable envelope, not fabricated data.
    with gated.hold(SEARCH) as slow:
        mark = browser.query(query)
        require(slow.arrived.wait(3) and slow.status == 200, 'A genuine successful search was not withheld')
        browser.state('search-state', 'loading')
        browser.results(mark, scope, query, [], code=503, state='unavailable')
        require(not slow.finished.is_set(), 'Search dependency finished before the real bridge timeout')
    require(slow.finished.wait(3), 'The withheld search did not terminate after release')
    contains(browser, '#knowledge-search-state', ['Search could not be completed. No results are available.'], 'genuine search unavailable')
    photos.take('08-unavailable')
    search(browser, scope, query, ordered)

    open_evidence(browser, 0, xlsx_record['evidence_path'])
    browser.provenance(0, {'Canonical SHA-256': xlsx_record['extracted_sha256']})
    old = (query, xlsx_record['record_id'], xlsx_record['version_id'], xlsx_record['extracted_sha256'], csv_record['record_id'])
    browser.cookie(data['cookies']['foreign_reader'])
    with gated.hold(SCOPES) as pending:
        mark = browser.mark()
        browser.click('Refresh scopes')
        require(pending.arrived.wait(3) and pending.status == 200, 'Foreign identity discovery did not reach a genuine pending response')
        browser.revalidated_view('loading', *old)
        browser.no_search(mark)
    foreign_node, foreign_label = SCOPE_LABELS['social']
    require(browser.receipt(mark, BRIDGE + SCOPES, 200)['body'] == {'version': 1, 'status': 'complete', 'scopes': [
        {'scope_node_id': foreign_node, 'display_label': foreign_label}]}, 'Foreign identity discovered unexpected scopes')
    browser.revalidated_view('complete', *old, options=[[foreign_node, f'{foreign_label} — {foreign_node}']])
    browser.no_search(mark)
    select_scope(browser, foreign_node)
    foreign = records['foreign']
    hits = search(browser, foreign_node, foreign['query'], [expected_hit(foreign, 'substring')])
    assert_hit(hits[0], foreign)
    browser.cookie(data['cookies']['unauthorized'])
    require(refresh(browser, 200, 'empty') == {'version': 1, 'status': 'complete', 'scopes': []},
            'Unauthorized signed member should discover zero scopes')
    browser.revalidated_view('empty', foreign['marker'], foreign['record_id'], *old)

    legacy_screens(browser, photos, data, csv_record, xlsx_record, xlsx)
    employee_workspace()
    for gate_name, exact_version in (('record', ()), ('version', (UUID(xlsx_record['version_id']),))):
        select_scope(browser, scope)
        search(browser, scope, query, ordered)
        open_evidence(browser, 0, xlsx_record['evidence_path'])
        args = (UUID(xlsx_record['record_id']), *exact_version, data['actors']['reader'][0])
        change = f'xlsx_{gate_name}_access_change'
        require(db_fixture.governance('bri_xlsx_access_maintainer', change, *args, False, uuid4(), identity='access') is False,
                f'Governed XLSX {gate_name} revocation did not commit')
        try:
            open_evidence(browser, 0, xlsx_record['evidence_path'], code=404)
            browser.cleared(*old, selection=True)
            require(refresh(browser, 200, 'complete') == discovery, 'Revocation unexpectedly changed exact-scope authority')
            select_scope(browser, scope)
            search(browser, scope, query, [ordered[1]])
        finally:
            require(db_fixture.governance('bri_xlsx_access_maintainer', change, *args, True, uuid4(), identity='access') is True,
                    f'Governed XLSX {gate_name} restore did not commit')
    report('PASS independent protected record and exact-version revocations deny XLSX evidence and remove only the XLSX hit')

    select_scope(browser, scope)
    search(browser, scope, query, ordered)
    open_evidence(browser, 0, xlsx_record['evidence_path'])
    browser.provenance(0, {'Canonical SHA-256': xlsx_record['extracted_sha256']})
    session_id = data['actors']['reader'][2]
    with db_fixture.connect('postgres') as db:
        require(db.execute('UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() '
                           'WHERE session_id=%s AND revoked_at IS NULL', (session_id,)).rowcount == 1,
                'Expected revocation of exactly one live reader session')
    with db_fixture.connect('postgres') as db:
        require(db.execute('SELECT revoked_at IS NOT NULL FROM bri.auth_sessions WHERE session_id=%s',
                           (session_id,)).fetchone() == (True,), 'Committed session revocation not visible')
    denial = status(data['client'].post(data['origins']['unified'] + SEARCH,
                                       headers=data['headers']['reader'], json={'scope_node_id': scope, 'query': query}),
                    403, 'Fresh search under the revoked employee session')
    require('results' not in denial.json(), 'Revoked employee session received results')
    # The XLSX evidence contract masks denial as a non-disclosing 404.
    open_evidence(browser, 0, xlsx_record['evidence_path'], code=404)
    browser.cleared(*old, selection=True)
    refresh(browser, 403, 'denied')
    browser.revalidated_view('denied', *old)
    report('PASS real no-partial 503 and recovery, same-tab identity redaction while pending, replacement isolation, and committed session revocation')


def run(args, scratch, stack):
    sys.path[:0] = [str(ROOT), str(ROOT / 'src'), str(ROOT / 'tests')]
    from a18_3_fixture import setup_fixture

    gate = []

    # Tear the entire live stack down before installing the completed PNG batch.
    with ExitStack() as services:
        def gated_unified(app):
            gate.append(Gate(app))
            return gate[0]

        data = setup_fixture(args, scratch, services, wrap_unified=gated_unified)
        require(len(gate) == 1, 'Expected one real unified listener to attach the timing gate')
        browser = start_visual_browser(args, scratch, services)
        photos = Screenshots(scratch / 'screenshots', browser)
        start_next(args, scratch, services, data['client'])
        run_product(browser, photos, data, gate[0])
    folder = publish_screenshots(photos.directory)
    report(f'PASS A18.3 signed Chromium product demo: {len(SHOTS)} verified PNGs in {folder}')


if __name__ == '__main__':
    sys.exit(harness.main(run, entry=os.path.abspath(__file__), name='a18-3', browser_required=True,
                          description=__doc__))
