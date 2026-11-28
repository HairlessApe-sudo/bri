#!/usr/bin/env python3
"""Bounded A19.2 signed Chromium acceptance; requires the integrated candidate."""
import base64
import json
import os
import pwd
import shutil
import sys
from contextlib import ExitStack
from hashlib import sha256
from pathlib import Path
from tempfile import mkdtemp
from unittest.mock import patch
from urllib.parse import quote
from uuid import UUID, uuid4

import a13_demo as harness
import a19_1_demo as prior_browser
from a13_demo import BRIDGE, UI, report, require, status
from a18_2_demo import BRIDGE as UNIFIED, PAGE as SEARCH, SCOPES, quoted
from a18_3_demo import WIDE, contains, go, png_size, private_directory, start_next
from a19_1_demo import (ADMIN, EXACT, META, Demo as MetadataDemo, absence, browser_fetch, change,
                        check_runtime, native_pending, png, start_browser, submit_native, visible_buttons)
from a19_1_fixture import (MEDIA, ORIGINAL_LABEL, classified_native_guard, pending, pending_state,
                           unavailable_metadata_detail)
from a19_2_fixture import (API, DISPATCH, FORMATS, PRIMARY, assert_job, drop_submit, job_rows,
                           originals, process_fixture_job, setup)

PAGE = '/knowledge/administration'
ADMIN_BRIDGE = BRIDGE + API.removeprefix('/v1')
VISIBILITY = ADMIN_BRIDGE + '/catalogue-visibility'
SESSION = ADMIN_BRIDGE + '/session'
SESSION_HEADER = 'x-bri-administration-context'
DENIED_STATUS = {'csv': 403, 'xlsx': 404}
SUBMIT = '[aria-labelledby="classified-submit-title"]'
STATUS = '[aria-labelledby="my-submissions-title"]'
EVIDENCE = Path(pwd.getpwuid(os.getuid()).pw_dir) / '.hermes/evidence/BRI/A19.2/am1/browser'
SHOTS = {
    '01-csv-submission': 'CSV classification and original staged at the authorized exact source node.',
    '02-csv-ack-and-status': 'CSV acknowledgement and an explicitly read exact-job status; neither is approval.',
    '03-xlsx-ack-and-status': 'XLSX acknowledgement and an explicitly read exact-job status; neither is approval.',
    '04-native-csv-review': 'Independent CSV reviewer sees native extracted evidence and original proposed classification.',
    '05-native-xlsx-review': 'Independent XLSX reviewer sees native worksheet evidence and original proposed classification.',
    '06-search-exact-evidence': 'Governed Knowledge Interface with authorized exact XLSX worksheet evidence after fixture-side publication and access.',
    '07-correction': 'CSV exact-version correction acknowledged with its server-issued proposal identifier; current metadata unchanged.',
    '08-cleared-context': 'Submission and exact-job state cleared after a signed identity replacement, including a held old response.',
}


def upload_path(fmt):
    return f'{ADMIN_BRIDGE}/{fmt}/uploads'


def job_path(fmt, job):
    prefix = f'{BRIDGE}/sources/csv' if fmt == 'csv' else f'{ADMIN_BRIDGE}/xlsx/status'
    return f'{prefix}/{job}'


def start_observed_browser(args, scratch, stack):
    # Chromium sometimes discards these streaming bodies before CDP can read
    # them. Observe clones of actual responses without replacing any fetch.
    def instrument_worker():
        script = original()
        step = "  } else if (m.step === 'eval') {"
        require(script.count(step) == 1, 'Expected CDP instrumentation point')
        return script.replace(step, '''  } else if (m.step === 'observeFetch') {
    await command('Page.addScriptToEvaluateOnNewDocument', {source:m.source});
''' + step)

    original = prior_browser.visual_worker_script
    with patch.object(prior_browser, 'visual_worker_script', instrument_worker):
        browser = start_browser(args, scratch, stack)
    browser.run('observeFetch', source=f'''(() => {{
      const fetchOriginal=window.fetch.bind(window), last=new Map();
      const allowed=p=>p.startsWith({quoted(ADMIN_BRIDGE + '/')}) || p.startsWith({quoted(BRIDGE + '/sources/csv/')});
      Object.defineProperty(window,'__a19_2Receipt',{{value:(path, take=false)=>{{
        const item=last.get(path); if(take)last.delete(path); return item;
      }}}});
      window.fetch=async (...args)=>{{
        const response=await fetchOriginal(...args);
        const url=new URL(response.url || String(args[0]), location.href);
        if(url.origin===location.origin && allowed(url.pathname) && [200,202].includes(response.status)){{
          const copy=response.clone();
          void copy.json().then(value=>last.set(url.pathname,{{status:response.status,value}}),()=>{{}});
        }}
        return response;
      }};
    }})()''')
    return browser


def observed_reply(browser, mark, path, code, *, method='GET'):
    browser.receipt(mark, path, code, method=method, body=False)
    browser.expect(f'window.__a19_2Receipt({quoted(path)})?.status==={code}', f'observed actual response for {path}')
    return browser.dom(f'window.__a19_2Receipt({quoted(path)},true).value')


def signed_probe(browser, path, code, *, method='GET', headers=None, query='', raw=None, enabled=True):
    """Do not export the scoped context value or any session material to the harness."""
    mark = browser.mark()
    opts = dict(method=method, cache='no-store', credentials='same-origin', headers=headers or {})
    reference = f'''const session=await fetch({quoted(SESSION)},{{cache:'no-store'}});
        const context=session.headers.get({quoted(SESSION_HEADER)});
        if(session.status!==200 || !context) throw Error('Signed probe lacks a verified context');
        await session.arrayBuffer(); init.headers[{quoted(SESSION_HEADER)}]=context;''' if enabled else ''
    upload = f'init.body=Uint8Array.from(atob({quoted(base64.b64encode(raw).decode())}),c=>c.charCodeAt(0));' if raw else ''
    observed = browser.dom(f'''(async()=>{{const init={quoted(opts)}; {reference} {upload}
        const r=await fetch({quoted(path + query)},init); await r.arrayBuffer(); return r.status;}})()''')
    require(observed == code, f'Browser {method} probe on {path}: expected HTTP {code}, observed {observed}')
    if code in (200, 202):
        return observed_reply(browser, mark, path, code, method=method)
    browser.receipt(mark, path, code, method=method, body=False)
    return None


def click_link(browser, path, text=None):
    mark = browser.mark()
    browser.expect(f'''(() => {{const a=[...document.querySelectorAll('main a')].find(e=>
        e.getAttribute('href')==={quoted(path)} && e.getClientRects().length &&
        ({quoted(text)}===null || e.textContent.trim()==={quoted(text)}));
        if(!a)return false; a.click(); return true;}})()''', f'visible product link to {path}')
    browser.expect(f'location.pathname==={quoted(path)}', f'product link destination {path}')
    return mark


def file_input(browser, path):
    selector = 'main input[type=file]'
    browser.expect('''(() => {const e=document.querySelector('main input[type=file]');
       return e && !e.disabled && Object.keys(e).some(k=>k.startsWith('__reactProps$'));})()''', 'hydrated upload control')
    browser.run('file', selector=selector, file=str(path))
    require(browser.dom("document.querySelector('main input[type=file]').files[0]?.name") == path.name,
            'Chromium did not attach the native file')


def probe_upload(browser, path, raw, key, node, value, code, *, media, headers=None, enabled=True):
    """A same-origin Chromium route probe, not a click on a UI control."""
    h = {'Content-Type': media, 'Idempotency-Key': key, 'X-Node-ID': node,
         'X-BRI-Metadata': base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip('=')}
    return signed_probe(browser, path, code, method='POST', headers=h | (headers or {}), raw=raw, enabled=enabled)


class Demo(MetadataDemo):
    def __init__(self, browser, data, scratch):
        self.b, self.data, self.node = browser, data, data['scopes']['social']
        self.screens = scratch / 'captures'
        self.screens.mkdir()
        self.diagnostic = scratch / 'diagnostic-captures'
        self.inputs, self.bad = originals(scratch)
        self.marker = {fmt: item['marker'] for fmt, item in self.inputs.items()}
        self.submitted = {fmt: item['metadata'] for fmt, item in self.inputs.items()}
        self.replacement = self.submitted['xlsx'] | {'title': 'Reviewer-validated workbook timetable'}

    def screenshot(self, name, anchor):
        # A19.1 initial decision driver requests two unrelated captures. The
        # accepted captures here come from the workspace's native queue links.
        if name in ('03-csv-initial-review', '04-xlsx-review-replacement'):
            return
        require(name in SHOTS, 'Unexpected A19.2 screenshot')
        png(self.b, self.screens, name, anchor)

    def choose(self, label, value):
        control = f'''[...document.querySelectorAll('main label')].find(e=>
          [...e.childNodes].filter(n=>n.nodeType===3).map(n=>n.textContent).join('').trim()==={quoted(label)})?.control'''
        self.b.expect(f'''(() => {{const e={control};return e && !e.disabled &&
           Object.keys(e).some(k=>k.startsWith('__reactProps$'));}})()''', f'hydrated {label}')
        self.b.dom(f'''(() => {{const e={control};
           Object.getOwnPropertyDescriptor(Object.getPrototypeOf(e),'value').set.call(e,{quoted(value)});
           e.dispatchEvent(new Event('input',{{bubbles:true}})); e.dispatchEvent(new Event('change',{{bubbles:true}}));}})()''')
        require(self.b.dom(f'({control}).value') == value, f'Control did not retain {label}')

    def open(self, who):
        self.as_user(who)
        return go(self.b, PAGE)

    def stage(self, fmt, *, node=None, code=200, file=None):
        b = self.b
        node = node or self.node
        self.choose('Submission format', fmt)
        self.choose('Source node ID', node)
        file_input(b, file or self.inputs[fmt]['file'])
        mark = b.mark()
        b.click('Load submission classifications')
        path = f'{ADMIN_BRIDGE}/selection/{fmt}/{node}'
        if code != 200:
            b.receipt(mark, path, code, body=False)
            contains(b, 'main [role="alert"]', ['Access denied.'], 'exact selection denial rendered')
            require(not b.dom("[...document.querySelectorAll('main select[name=primary] option')].some(o=>o.value)"),
                    'Denied node showed protected classification choices')
            return
        choices = observed_reply(b, mark, path, code)
        expected = [row['classification_id'] for row in choices]
        b.expect(f'''JSON.stringify([...document.querySelectorAll('main select[name=primary] option')]
           .map(o=>o.value).filter(Boolean))===JSON.stringify({quoted(expected)})''', 'exact authorized classification choices')
        require(PRIMARY in expected, 'Expected starter classification is missing')
        change(b, 'main select[name=primary]', PRIMARY)
        change(b, 'main input[name=title]', self.submitted[fmt]['title'])

    def lookup(self, fmt, job, *, code=200, state=None):
        b = self.b
        self.choose('Job format', fmt)
        self.choose('Job ID', str(job))
        mark = b.mark()
        b.click('Check job status')
        path = job_path(fmt, job)
        body = observed_reply(b, mark, path, code) if code == 200 else None
        if code != 200:
            b.receipt(mark, path, code, body=False)
        require(b.run('count', mark=mark, path=job_path(fmt, job), method='GET') == 1, 'Unexpected exact status request count')
        if code == 200:
            require(body == {'id': str(job), 'state': state}, 'Wrong exact-job HTTP projection')
            selector = STATUS + ' [aria-label="Current job status"]'
            contains(b, selector, [str(job)], 'exact job rendered')
            b.expect(f'document.querySelector({quoted(selector + " strong")})?.textContent==={quoted(state)}',
                     'authoritative status rendered')
        else:
            contains(b, 'main [role="alert"]', ['Access denied.' if code == 403 else 'not found'], 'exact lookup denial rendered')
            absence(b, str(job))
        return body

    def route_boundaries(self, jobs):
        b = self.b
        before = job_rows(self.data)
        self.open('submitter')
        for fmt, job in jobs.items():
            for suffix in ('/jobs', f'/{job}/dispatch', f'/{job}/worker', '/worker'):
                browser_fetch(b, f'{ADMIN_BRIDGE}/{fmt}' + suffix, 404)
            native_prefix = f'{BRIDGE}/sources/csv' if fmt == 'csv' else f'{BRIDGE}/intake/xlsx'
            for suffix in (f'/{job}/dispatch', f'/{job}/workers'):
                browser_fetch(b, native_prefix + suffix, 404)
            browser_fetch(b, native_prefix, 404 if fmt == 'csv' else 405)
            browser_fetch(b, f'{ADMIN_BRIDGE}/{fmt}/{job}/dispatch', 404, method='POST', value={})
            browser_fetch(b, f'{ADMIN_BRIDGE}/{fmt}/dispatch', 404, method='POST', value={'id': str(job)})
            browser_fetch(b, f'{ADMIN_BRIDGE}/{fmt}/uploads', 405)
            signed_probe(b, job_path(fmt, job), 400, query='?list=1')
        browser_fetch(b, ADMIN_BRIDGE + '/jobs', 404)
        signed_probe(b, VISIBILITY, 403)
        require(job_rows(self.data) == before, 'Denied route probes changed fixture jobs')
        report('PASS signed browser-origin probes: no administration enumeration, dispatch, or worker route')

    def upload_pair(self):
        b = self.b
        jobs = {}
        self.open('submitter')
        contains(b, 'main', ['Knowledge Administration', 'Submit classified knowledge', 'My Submissions'], 'bounded workspace')
        for fmt in FORMATS:
            report(f'CHECK Chromium {fmt.upper()} exact-node classification and upload')
            self.stage(fmt)
            if fmt == 'csv':
                self.screenshot('01-csv-submission', 'main')
            mark, before = b.mark(), job_rows(self.data)
            b.click('Submit classified file')
            receipt = observed_reply(b, mark, upload_path(fmt), 202, method='POST')
            job = jobs[fmt] = UUID(receipt['id'])
            state = 'ready' if DISPATCH == 'fixture' else 'proposed'
            require(receipt == {'id': str(job), 'state': state}, 'Wrong native browser upload acknowledgement')
            contains(b, SUBMIT + ' [aria-label="Submission acknowledgement"]',
                     [str(job), state, 'This is not approval or publication.'], 'server-issued acknowledgement rendered')
            b.paint()
            summary = b.run('routeSummary', mark=mark, prefix=BRIDGE + '/')
            require([row['status'] for row in summary if row['method'] == 'POST'] == [202], 'Upload repeated or sent to a second parser')
            require(not b.run('count', mark=mark, path=job_path(fmt, job), method='GET'), 'Acknowledgement automatically looked up protected status')
            assert_job(self.data, fmt, job, self.inputs[fmt]['raw'], state)
            after = job_rows(self.data)
            other = 'xlsx' if fmt == 'csv' else 'csv'
            require(len(after[fmt]) == len(before[fmt]) + 1 and after[other] == before[other], 'Upload touched the wrong native job table')
            self.lookup(fmt, job, state=state)
            self.screenshot(f'0{2 if fmt == "csv" else 3}-{fmt}-ack-and-status', 'main')
            if DISPATCH == 'fixture':
                process_fixture_job(self.data, fmt, job)
                assert_job(self.data, fmt, job, self.inputs[fmt]['raw'], 'proposed')
                self.lookup(fmt, job, state='proposed')
            else:
                pending_state(self.data, fmt, job, classified=True)
            require(not b.dom(f'''[localStorage,sessionStorage].some(s=>Object.keys(s)
                .some(k=>k.includes({quoted(str(job))}) || s.getItem(k)?.includes({quoted(str(job))})))'''),
                    'Exact job unexpectedly persisted in browser storage')
            report(f'PASS actual Chromium {fmt.upper()} file, classified HTTP 202 {state}, rendered acknowledgement, explicit exact status and original SHA-256; dispatch={DISPATCH}')
        return jobs

    def incompatibility(self):
        # Correct filename/declared format with incompatible actual bytes.
        self.open('submitter')
        self.stage('xlsx', file=self.bad)
        before = job_rows(self.data)
        mark = self.b.mark()
        self.b.click('Submit classified file')
        self.b.receipt(mark, upload_path('xlsx'), 415, method='POST', body=False)
        contains(self.b, 'main [role="alert"]', [''], 'visible incompatible-format denial')
        self.b.paint()
        summary = self.b.run('routeSummary', mark=mark, prefix=BRIDGE + '/')
        require([row['status'] for row in summary if row['method'] == 'POST'] == [415], 'Incompatible input tried a second parser')
        require(job_rows(self.data) == before, 'Incompatible input created a native job')
        report('PASS actual Chromium incompatible XLSX bytes rejected without parser fallback or native job creation')

    def isolation(self, jobs):
        before = job_rows(self.data)
        b = self.b
        for who in ('wrong_node', 'other_owner', 'reader', 'foreign_submitter', 'manager'):
            self.open(who)
            for fmt, job in jobs.items():
                # Native lookup deliberately obscures wrong owner, node and tenant.
                # Reader/manager have no submit authority but still must not receive protected detail.
                signed_probe(b, job_path(fmt, job), 403 if who in ('reader', 'manager') else DENIED_STATUS[fmt])
                if who not in ('other_owner', 'foreign_submitter'):
                    data = self.inputs[fmt]
                    probe_upload(b, upload_path(fmt), data['raw'], str(uuid4()), self.node, data['metadata'], 403,
                                 media='text/csv' if fmt == 'csv' else MEDIA)
        for fmt in FORMATS:
            self.open('submitter')
            self.stage(fmt, node=self.data['scopes']['empty'], code=403)
        for fmt, job in jobs.items():
            other = 'xlsx' if fmt == 'csv' else 'csv'
            signed_probe(b, job_path(other, job), DENIED_STATUS[other])
            signed_probe(b, job_path(fmt, uuid4()), DENIED_STATUS[fmt])
            source = self.inputs[fmt]
            for spoof in ('X-Tenant-ID', 'X-Worker-ID', 'X-Principal-ID'):
                probe_upload(b, upload_path(fmt), source['raw'], str(uuid4()), self.node, source['metadata'], 400,
                             media='text/csv' if fmt == 'csv' else MEDIA, headers={spoof: 'synthetic-not-authority'})
        require(job_rows(self.data) == before, 'Unauthorized route touched native jobs')
        report('PASS exact signed scope, wrong format, absent job, other owner, foreign tenant and separated role boundaries')

    def workspace_retirement(self, job):
        b = self.b
        self.open('submitter')
        self.stage('csv')
        self.lookup('csv', job, state='proposed')
        exact = f'/v1/sources/csv/{job}'
        mark = b.mark()
        with self.data['gates']['csv'].hold(exact) as old:
            b.click('Check job status')
            require(old.arrived.wait(5) and old.status == 200, 'Real old signed status did not reach the fixture delay')
            self.as_user('foreign_submitter')
            b.dom(f'void window.__a19_2Receipt({quoted(SESSION)},true)')
            clear_mark = b.mark()
            b.click('Clear workspace context')
            hidden = (str(job), self.submitted['csv']['title'], self.inputs['csv']['file'].name, self.node, ORIGINAL_LABEL)
            absence(b, *hidden)
            require(observed_reply(b, clear_mark, SESSION, 200) == {'current': True}, 'Replacement session did not verify')
            require(b.dom("[...document.querySelectorAll('main input[type=file]')].every(e=>e.files.length===0)"),
                    'Old original is still selected after clear')
            old.release.set()
            require(old.finished.wait(5), 'Held real response did not finish')
            b.receipt(mark, job_path('csv', job), 200, body=False, retired=True)
            b.paint()
            absence(b, *hidden)
            require(b.run('count', mark=mark, path=job_path('csv', job), method='GET') == 1,
                    'Retired workspace retried or automatically looked up old job')
        self.screenshot('08-cleared-context', 'main')
        signed_probe(b, job_path('csv', job), DENIED_STATUS['csv'])
        self.open('submitter')
        self.lookup('csv', job, state='proposed')
        drop_submit(self.data)
        self.lookup('csv', job, code=DENIED_STATUS['csv'])
        pending_state(self.data, 'csv', job, classified=True)
        report('PASS signed identity replacement clears state while an actual 200 is held, suppresses delayed publication and retries; live owner node loss denies exact status')

    def navigation_and_review(self, jobs):
        b = self.b
        self.open('manager')
        mark = b.mark()
        b.click('Check catalogue access')
        require(observed_reply(b, mark, VISIBILITY, 200) == {'visible': True}, 'Shortcut discovery was not a projection-only result')
        mark = click_link(b, '/classification', 'Classification catalogue')
        require(any(row['classification_id'] == PRIMARY for row in b.receipt(mark, ADMIN, 200)['body']), 'Linked catalogue not authoritative')
        self.open('reader')
        mark = click_link(b, SEARCH, 'Knowledge Interface')
        b.receipt(mark, UNIFIED + SCOPES, 200)
        b.state('scopes', 'complete')
        b.change('Organisational scope', self.node)
        for fmt in FORMATS:
            b.results(b.query(self.marker[fmt]), self.node, self.marker[fmt], [])
        for fmt, job in jobs.items():
            suffix = '/review' if fmt == 'csv' else '/xlsx/review'
            target = suffix + '/' + quote(f'{fmt}:{job}', safe='')
            self.open('reviewer')
            click_link(b, suffix, f'{fmt.upper()} review queue')
            mark = click_link(b, target)
            native = f'{BRIDGE}/knowledge/proposals/{fmt}/' + quote(f'{fmt}:{job}', safe='')
            data = b.receipt(mark, native, 200)['body']
            require(data['state'] == 'proposed' and self.marker[fmt] in json.dumps(data), 'Linked native review wrong exact proposal')
            contains(b, 'main', [self.marker[fmt], self.submitted[fmt]['title']], 'native evidence and separately loaded classification')
            anchor = '[aria-label="Extracted evidence"]' if fmt == 'csv' else 'main'
            self.screenshot(f'0{4 if fmt == "csv" else 5}-native-{fmt}-review', anchor)
            endpoint = f'{META}/{fmt}/review/{job}'
            with unavailable_metadata_detail(self.data, fmt):
                mark = b.mark()
                b.click('Refresh proposal')
                b.receipt(mark, native, 200)
                b.receipt(mark, endpoint, 503, body=False)
                contains(b, 'main [role="alert"]', ['Classification information is unavailable.'], 'protected metadata failure rendered')
                absence(b, self.submitted[fmt]['title'])
                require(not any('approve' in row['label'].lower() or 'reject' in row['label'].lower()
                                for row in visible_buttons(b)), 'Native review reverted to legacy during a metadata failure')
                require(not b.run('count', mark=mark, path=endpoint + '/decision', method='POST') and
                        not b.run('count', mark=mark, path=native + '/decision', method='POST'),
                        'An unavailable review sent a decision')
                pending_state(self.data, fmt, job, classified=True)
            mark = b.mark()
            b.click('Refresh proposal')
            require(b.receipt(mark, endpoint, 200)['body']['proposed_metadata'] == self.submitted[fmt],
                    'Explicit native review refresh did not recover the correct metadata')
            self.initial(fmt, job)
        report('PASS Administration links open accepted governed search, separately authorized catalogue, and correct native independent queues/review decisions')

    def search_and_correct(self, jobs):
        b = self.b
        # Existing operations, deliberately restricted to disposable fixture-side
        # publication/access; Administration exposes none of these mutations.
        record = self.access(jobs)
        self.open('reader')
        mark = click_link(b, SEARCH, 'Knowledge Interface')
        b.receipt(mark, UNIFIED + SCOPES, 200)
        b.state('scopes', 'complete')
        b.change('Organisational scope', self.node)
        for fmt, rec in (('csv', jobs['csv']), ('xlsx', record)):
            job = jobs[fmt]
            match = 'substring' if fmt == 'csv' else 'exact'
            hits = b.results(b.query(self.marker[fmt]), self.node, self.marker[fmt], [(fmt, str(rec), match)])
            require(hits[0]['source_version_id'] == str(job), 'Governed search returned the wrong exact version')
            evidence = hits[0]['evidence_url']
            mark = b.mark()
            b.click('View evidence', 0)
            reply = b.evidence(mark, evidence)
            require(reply['source_version_id'] == str(job), 'Evidence did not reauthorize the exact source version')
        self.screenshot('06-search-exact-evidence', '#knowledge-evidence')
        csv = jobs['csv']
        title = 'Corrected CSV timetable'
        proposal = self.propose('csv', csv, csv, title, '1')
        self.screenshot('07-correction', EXACT)
        url = self.correction_choice('csv', csv, csv, 'corrector', proposal)
        mark = b.mark()
        b.click('Confirm metadata correction approval')
        reply = b.receipt(mark, url, 200, method='POST')['body']
        require(reply == {'record_id': str(csv), 'source_version_id': str(csv), 'proposal_id': proposal,
                          'decision': 'approve', 'metadata_revision': '2'}, 'Wrong independent exact-version correction receipt')
        require(self.open_record('csv', csv, csv, 'reader')['metadata']['title'] == title, 'Independent reader missed persisted correction')
        report('PASS governed exact search/evidence after labelled fixture publication/access; accepted CSV correction proposal, independent approval and persisted reader projection')

    def open_record(self, fmt, record, job, who):
        if who != 'proposer':
            return super().open_record(fmt, record, job, who)
        # Follow the new integration through the real exact-evidence panel, not
        # a direct classification URL or an injected proposal.
        b = self.b
        self.open(who)
        mark = click_link(b, SEARCH, 'Knowledge Interface')
        b.receipt(mark, UNIFIED + SCOPES, 200)
        b.state('scopes', 'complete')
        b.change('Organisational scope', self.node)
        match = 'substring' if fmt == 'csv' else 'exact'
        hits = b.results(b.query(self.marker[fmt]), self.node, self.marker[fmt], [(fmt, str(record), match)])
        require(hits[0]['source_version_id'] == str(job), 'Correction search returned a different version')
        mark = b.mark()
        b.click('View evidence', 0)
        require(b.evidence(mark, hits[0]['evidence_url'])['source_version_id'] == str(job), 'Correction evidence version mismatch')
        mark = b.mark()
        b.click('Open exact-version metadata and corrections')
        return b.receipt(mark, META + self.exact_path(fmt, record, job), 200)['body']


def off(demo):
    b = demo.b
    mark = demo.open('submitter')
    contains(b, 'main', ['Knowledge Administration'], 'OFF workspace shell')
    contains(b, 'main', ['Classified submission and My Submissions are disabled in this local mode.'], 'explicit OFF notice')
    require(not b.run('routeSummary', mark=mark, prefix=ADMIN_BRIDGE), 'OFF shell fetched a protected Administration route')
    require(not any(row['method'] == 'POST' for row in b.run('routeSummary', mark=mark, prefix=BRIDGE + '/')), 'OFF workspace dispatched a mutation')
    require(not b.dom("document.querySelector('main input[type=file]') || "
                      "[...document.querySelectorAll('main button')].some(b=>/classified file|job status/.test(b.textContent))"),
            'OFF exposed A19.2 controls')
    for fmt in FORMATS:
        fixture = demo.inputs[fmt]
        probe_upload(b, upload_path(fmt), fixture['raw'], str(uuid4()), demo.node, fixture['metadata'], 404,
                     media='text/csv' if fmt == 'csv' else MEDIA, enabled=False)
    demo.http('catalogue', '/catalogue/admin/seed', 'manager', 204, method='POST', json={})
    for fmt in FORMATS:
        for classified in (False, True):
            marker = f'A19.2 OFF native {fmt} fixture'
            seeded = demo.submitted[fmt] | {'primary_classification_id': 'policy'}
            job = pending(demo.data, fmt, marker, metadata_value=seeded if classified else None,
                          service=f'{fmt}_seed' if classified else None)
            demo.as_user('reviewer')
            mark, route, _ = native_pending(b, fmt, job, marker)
            submit_native(b, fmt, job, route, 'approve', code=(503 if fmt == 'csv' else 404) if classified else 200)
            require(not b.run('routeSummary', mark=mark, prefix=META + '/'), 'OFF native detail fetched application metadata')
            if classified:
                classified_native_guard(demo.data, fmt, job)
                pending_state(demo.data, fmt, job, classified=True)
    report('PASS mode OFF: Administration controls and write routes absent without selecting legacy via failure; native eligible approvals still work and classified native bypass remains blocked')


def publish(staging):
    private_directory(EVIDENCE)
    require({p.name for p in staging.iterdir()} == {f'{name}.png' for name in SHOTS}, 'Incomplete screenshot batch')
    batch = EVIDENCE / f'candidate-{uuid4().hex}'
    temporary = Path(mkdtemp(prefix='.pending-', dir=EVIDENCE))
    try:
        manifest = ['# A19.2 signed Chromium candidate captures', '',
                    'Synthetic local fixture only. Independent exact-export rerun and pixel review are separate gates.', '',
                    '| PNG | Dimensions | Bytes | SHA-256 | Product state |', '| --- | --- | ---: | --- | --- |']
        for name, description in SHOTS.items():
            filename = name + '.png'
            raw = (staging / filename).read_bytes()
            require(png_size(raw) == WIDE, 'Wrong screenshot dimensions')
            (temporary / filename).write_bytes(raw)
            require((temporary / filename).read_bytes() == raw, 'Screenshot copy mismatch')
            manifest.append(f'| `{filename}` | {WIDE[0]}×{WIDE[1]} | {len(raw)} | `{sha256(raw).hexdigest()}` | {description} |')
        (temporary / 'manifest.md').write_text('\n'.join(manifest) + '\n')
        temporary.rename(batch)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    return batch


def scenario(args, scratch, _):
    enabled = not Path(sys.argv[0]).stem.endswith('_off')
    os.environ.update(TMPDIR=str(scratch), BRI_LOCAL_METADATA_ENABLED='1' if enabled else '0')
    with ExitStack() as stack:
        data = setup(args, scratch, stack, enabled=enabled)
        b = start_observed_browser(args, scratch, stack) if enabled else start_browser(args, scratch, stack)
        start_next(args, scratch, stack, data['client'])
        report(f'CHECK staged A19.2 mode {"ON" if enabled else "OFF"}; signed fixture services started')
        sample = uuid4()
        for path in (PAGE, '/classification', '/xlsx/review', f'/review/csv%3A{sample}',
                     f'/xlsx/review/xlsx%3A{sample}', f'/knowledge/csv%3A{sample}', f'/xlsx/knowledge/{sample}'):
            status(data['client'].get(UI + path, timeout=90), 200, 'unsigned page shell')
        report('CHECK unsigned page shells warmed; beginning signed Chromium assertions')
        demo = Demo(b, data, scratch)
        if enabled:
            demo.http('catalogue', '/catalogue/admin/seed', 'manager', 204, method='POST', json={})
            demo.http('catalogue', '/catalogue/admin/create', 'manager', 204, method='POST',
                      json={'category_id': 'general', 'classification_id': PRIMARY, 'label': ORIGINAL_LABEL,
                            'description': 'Synthetic scope fixture'})
            jobs = demo.upload_pair()
            demo.incompatibility()
            demo.isolation(jobs)
            demo.route_boundaries(jobs)
            demo.workspace_retirement(jobs['csv'])
            demo.navigation_and_review(jobs)
            demo.search_and_correct(jobs)
        else:
            off(demo)
        check_runtime(b)
    report('PASS A19.2 signed Chromium assertions and service teardown')
    if enabled:
        batch = publish(demo.screens)
        report(f'PASS {len(SHOTS)} verified synthetic 1440×1000 PNGs in {batch}')


def run(args, scratch, stack):
    try:
        scenario(args, scratch, stack)
    except RuntimeError as exc:
        if isinstance(exc.__context__, RuntimeError):
            raise RuntimeError(f'{exc}; preceding: {exc.__context__}') from None
        raise


def main(entry):
    return harness.main(run, entry=os.path.abspath(entry), name='a19-2', browser_required=True, description=__doc__)


if __name__ == '__main__':
    sys.exit(main(__file__))
