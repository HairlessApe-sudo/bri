#!/usr/bin/env python3
"""Qualify AM2 recovery using real signed Chromium, native intake and disposable PG16.2."""
from base64 import urlsafe_b64encode
from contextlib import ExitStack, nullcontext
import json
import os
import sys
from time import sleep
from uuid import UUID

import a13_demo as harness
import a19_2_demo as prior
from a13_demo import report, require
from a18_3_demo import contains
from a18_3_fixture import _csv_bytes, _xlsx_bytes
from a19_1_demo import absence, check_runtime, png, visible_buttons
from a19_1_fixture import MEDIA
from a19_2_am2_chromium import assert_transport_loss, lose_response, malformed_client_receipt, start as chromium
from a19_2_am2_fault import committed_fault
from a19_2_am2_held import ACK, RETRY, SUBMIT, publish, start
from a19_2_fixture import FORMATS, assert_job, drop_submit, process_fixture_job

UNKNOWN = 'Submission outcome unknown. The original submission may already exist.'
REJECTION = 'Submission rejected. No submission was created by this attempt.'
ABANDON = 'Abandon recovery…'
CONFIRM = 'Abandon recovery and allow a new submission'
WARNING = 'Abandoning recovery does not cancel it. Starting a new submission could create a duplicate.'
ALERT = prior.SUBMIT + ' [role="alert"]'

LINEAGE = {
    'csv': ('csv_lineage_claims', 'source_records', 'source_versions', 'source_extractions',
            'csv_source_evidence', 'knowledge_proposals'),
    'xlsx': ('xlsx_sources', 'xlsx_source_versions', 'xlsx_extractions', 'xlsx_pending_proposals'),
}
ISOLATED = ('validation_decisions', 'validated_knowledge', 'knowledge_record_access', 'knowledge_version_access',
            'xlsx_review_decisions', 'xlsx_validated_knowledge', 'xlsx_publication_events', 'xlsx_record_access',
            'xlsx_version_access', 'xlsx_governance_audit_events', 'knowledge_metadata_initial_decisions',
            'knowledge_metadata_revisions', 'knowledge_metadata_correction_proposals', 'knowledge_metadata_correction_decisions')
BUSINESS = ('csv_jobs', 'xlsx_jobs', 'csv_audit_events', 'xlsx_audit_events', 'knowledge_metadata_initial',
            'knowledge_metadata_payloads', 'knowledge_metadata_additional', *LINEAGE['csv'], *LINEAGE['xlsx'], *ISOLATED)


def snapshot(data):
    # Read each exact table in one fresh observer snapshot; never export rows.
    with data['fixture'].connect('postgres') as owner:
        owner.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY')
        return {table: owner.execute(f'SELECT to_jsonb(t)::text FROM bri.{table} AS t ORDER BY 1').fetchall()
                for table in BUSINESS}


def fresh_job(data, fmt, job, raw, before, *, who='submitter'):
    assert_job(data, fmt, job, raw, 'ready', who=who)
    ready = snapshot(data)
    other = 'xlsx' if fmt == 'csv' else 'csv'
    for table, delta in ((f'{fmt}_jobs', 1), (f'{other}_jobs', 0), ('knowledge_metadata_initial', 1),
                         (f'{fmt}_audit_events', 2), *((name, 0) for name in ISOLATED)):
        require(len(ready[table]) == len(before[table]) + delta, f'Unexpected committed changes to {table}')
    return ready


def process(data, fmt, job, raw, ready):
    process_fixture_job(data, fmt, job)
    assert_job(data, fmt, job, raw, 'proposed')
    proposed = snapshot(data)
    for name in LINEAGE[fmt]:
        require(len(proposed[name]) == len(ready[name]) + int(name != 'csv_lineage_claims'),
                f'Native dispatcher produced unexpected count for {name}')
    require(len(proposed[f'{fmt}_audit_events']) == len(ready[f'{fmt}_audit_events']) + 2 and
            all(ready[name] == proposed[name] for name in ISOLATED),
            'Native dispatch changed publication/access or emitted unexpected audits')
    return proposed


class Recovery:
    def __init__(self, data, browser, demo, scratch):
        self.data, self.b, self.demo, self.scratch = data, browser, demo, scratch
        self.shots = {}

    def shoot(self, fmt, case, selector, description):
        name = f'{fmt}-{case}'
        png(self.b, self.demo.screens, name, selector)
        self.shots[name] = f'{fmt.upper()}: {description}'

    def stage(self, fmt, *, who='submitter', **kwargs):
        self.demo.open(who)
        self.demo.stage(fmt, **kwargs)

    def buttons(self):
        return {item['label'] for item in visible_buttons(self.b) if item['enabled']}

    def locked(self):
        self.b.expect(f'''(() => {{const form=document.querySelector({prior.quoted(prior.SUBMIT + ' form')});
            if (!form) return false;
            const edit=[...form.querySelectorAll('input,select,textarea,button')];
            return edit.length>=4 && edit.every(e=>e.disabled || e.closest('fieldset[disabled]'));}})()''',
                      'every submission edit disabled during wait or recovery')

    def unknown(self):
        contains(self.b, ALERT, [UNKNOWN], 'uncertain outcome without failed/succeeded assertion')
        require({RETRY, ABANDON} <= self.buttons() and SUBMIT not in self.buttons() and
                not self.b.dom(f'document.querySelector({prior.quoted(ACK)})'),
                'Uncertain submission falsely acknowledged or allowed a new command')
        self.locked()

    def acknowledgement(self, fmt, mark, job, *, state='ready'):
        require(prior.observed_reply(self.b, mark, prior.upload_path(fmt), 202, method='POST') ==
                {'id': str(job), 'state': state}, 'Signed bridge did not acknowledge the exact original job')
        contains(self.b, ACK, [str(job), state, 'This is not approval or publication.'], 'exact acknowledgement shown')
        require(not ({RETRY, ABANDON} & self.buttons()), 'Validated receipt left a recovery action')

    def double_action(self, label):
        self.b.expect(f'''(() => {{const button=[...document.querySelectorAll('main button')].find(e=>
            e.textContent.trim()==={prior.quoted(label)} && !e.disabled && Object.keys(e).some(k=>k.startsWith('__reactProps$')));
            if (!button) return false; button.click(); button.click(); return true;}})()''',
                      f'two consecutive {label} actions in same browser task')

    def traffic(self, mark, fmt, *, posts, no_status=None, settle=False):
        if settle:
            self.b.paint()
            sleep(.4)
        b, route = self.b, prior.upload_path(fmt)
        summary = b.run('routeSummary', mark=mark, prefix=prior.BRIDGE + '/')
        require(sum(row['method'] == 'POST' for row in summary) == posts and
                b.run('count', mark=mark, path=route, method='POST') == posts,
                'Unexpected automatic, duplicate, or wrong-format browser POST')
        if no_status:
            require(not b.run('count', mark=mark, path=prior.job_path(fmt, no_status), method='GET'),
                    'Browser looked up protected status without a user action')

    def release(self, fault):
        fault.release.set()
        require(fault.finished.wait(5), 'Held real native receipt did not finish')

    def storage(self, fmt, command, job):
        secrets = [str(job), command[0].decode(), self.demo.inputs[fmt]['file'].name, self.demo.submitted[fmt]['title']]
        require(not self.b.dom(f'''[localStorage,sessionStorage].some(s=>Object.keys(s).some(k=>
            {prior.quoted(secrets)}.some(v=>k.includes(v)||s.getItem(k)?.includes(v))))'''),
                'Recovery data entered browser persistence')

    def launch(self, fmt, *, who='submitter'):
        self.stage(fmt, who=who)
        b, gate = self.b, self.data['gates'][fmt]
        return self.demo.inputs[fmt]['raw'], gate, len(gate.seen()), snapshot(self.data), b.mark()

    def normal(self, fmt):
        raw, gate, n, before, mark = self.launch(fmt)
        with gate.arm(fmt) as fault:
            self.double_action(SUBMIT)
            job = committed_fault(self.data, fmt, fault, raw)
            self.locked()
            contains(self.b, prior.SUBMIT + ' [role="status"]', ['Submitting classified file'], 'pending upload only')
            require(not ({SUBMIT, RETRY, ABANDON} & self.buttons()), 'Concurrent upload exposed a second user action')
            self.traffic(mark, fmt, posts=1, no_status=job)
            ready = fresh_job(self.data, fmt, job, raw, before)
            self.release(fault)
        self.acknowledgement(fmt, mark, job)
        self.traffic(mark, fmt, posts=1, no_status=job, settle=True)
        require(len(gate.seen()) == n + 1, 'Simultaneous submit committed a second command')
        self.demo.lookup(fmt, job, state='ready')
        process(self.data, fmt, job, raw, ready)
        self.demo.lookup(fmt, job, state='proposed')
        report(f'PASS {fmt.upper()} valid receipt, simultaneous submit guards, explicit current status and one restricted native dispatch')

    def recover(self, fmt, mode):
        raw, gate, n, before, mark = self.launch(fmt)
        path = prior.upload_path(fmt)
        if mode == 'client-malformed':
            malformed_client_receipt(self.b, fmt)
        network = lose_response(self.b, fmt) if mode == 'transport-loss' else nullcontext()
        with network, gate.arm(fmt, corrupt=mode == 'bridge-502') as fault:
            self.b.click(SUBMIT)
            job = committed_fault(self.data, fmt, fault, raw)
            ready = fresh_job(self.data, fmt, job, raw, before)
            original = gate.seen()[n]
            self.release(fault)
            if mode == 'transport-loss':
                assert_transport_loss(self.b, mark, path)
            elif mode == 'bridge-502':
                self.b.receipt(mark, path, 502, method='POST', body=False)
            else:
                require(prior.observed_reply(self.b, mark, path, 202, method='POST') == fault.reply,
                        'Malformed client probe failed to prove a valid upstream/bridge receipt')
        self.unknown()
        self.storage(fmt, original, job)
        self.traffic(mark, fmt, posts=1, no_status=job, settle=True)
        require(gate.seen()[n:] == (original,) and snapshot(self.data) == ready,
                'Fault automatically retried or mutated committed state')
        self.shoot(fmt, mode, ALERT, f'uncertain UI after {mode}; owner already observed a committed job.')
        lease = process(self.data, fmt, job, raw, ready)
        mark_retry = self.b.mark()
        self.double_action(RETRY)
        self.acknowledgement(fmt, mark_retry, job, state='proposed')
        self.traffic(mark, fmt, posts=2, no_status=job, settle=True)
        require(gate.seen()[n:] == (original, original) and snapshot(self.data) == lease,
                'Retry did not reuse exact key, node, metadata and bytes, or added business audit/lineage/attempt')
        self.demo.lookup(fmt, job, state='proposed')
        if mode == 'bridge-502':
            self.shoot(fmt, 'original-recovered', ACK, 'explicit same-key retry recovered the original proposed job.')
            self.fingerprint_conflicts(fmt, raw, original, lease)
        report(f'PASS {fmt.upper()} {mode}: exact manual retry recovered original job; no duplicate request, native attempt, lineage, proposal or business audit')

    def fingerprint_conflicts(self, fmt, raw, original, before):
        key, node = original[0].decode(), original[1].decode()
        media = 'text/csv' if fmt == 'csv' else MEDIA
        other = self.data['scopes']['information']
        selection = f'{prior.ADMIN_BRIDGE}/selection/{fmt}/{other}'
        require(prior.signed_probe(self.b, selection, 200), 'Alternate exact node is not valid on its own')
        changed = (_csv_bytes('Different synthetic bytes', 'First fingerprint variant') if fmt == 'csv'
                   else _xlsx_bytes('Different synthetic bytes'))
        metadata = self.demo.submitted[fmt]
        gate = self.data['gates'][fmt]
        for index, body, scope, value in ((3, changed, node, metadata), (2, raw, node, metadata | {'title': 'Different synthetic title'}),
                                           (1, raw, other, metadata)):
            fields = ('version', 'title', 'description', 'primary_classification_id', 'additional_classification_ids',
                      'effective_date', 'review_date', 'expiry_date')
            wire = json.dumps({field: value[field] for field in fields}, separators=(',', ':'), ensure_ascii=False).encode()
            headers = {'Content-Type': media, 'Idempotency-Key': key, 'X-Node-ID': scope,
                       'X-BRI-Metadata': urlsafe_b64encode(wire).decode().rstrip('=')}
            prior.signed_probe(self.b, prior.upload_path(fmt), 409, method='POST', headers=headers, raw=body)
            observed = gate.seen()[-1]
            require(observed[-1] == 409 and [i for i in range(4) if observed[i] != original[i]] == [index] and
                    snapshot(self.data) == before, 'Changed fingerprint was not rejected alone or left business mutations')
        report(f'PASS {fmt.upper()} signed Chromium route probes: same key and changed bytes, metadata, or authorized node separately returned 409 and no business mutation')

    def rejection(self, fmt):
        bad = self.scratch / f'synthetic-invalid.{fmt}'
        bad.write_bytes(self.demo.inputs['xlsx' if fmt == 'csv' else 'csv']['raw'])
        self.stage(fmt, file=bad)
        before, mark = snapshot(self.data), self.b.mark()
        self.b.click(SUBMIT)
        self.b.receipt(mark, prior.upload_path(fmt), 415, method='POST', body=False)
        contains(self.b, ALERT, [REJECTION], 'definitive native format rejection')
        require(not ({ABANDON, RETRY} & self.buttons()) and snapshot(self.data) == before,
                'Definitive rejection retained recovery or created a native business record')
        self.traffic(mark, fmt, posts=1, settle=True)
        report(f'PASS {fmt.upper()} real native 415 definitively rejected incompatible selected bytes without parser fallback or job creation')

    def abandonment(self, fmt):
        raw, gate, n, before, mark = self.launch(fmt)
        with gate.arm(fmt, corrupt=True) as fault:
            self.b.click(SUBMIT)
            job = committed_fault(self.data, fmt, fault, raw)
            ready = fresh_job(self.data, fmt, job, raw, before)
            self.release(fault)
        self.b.receipt(mark, prior.upload_path(fmt), 502, method='POST', body=False)
        self.unknown()
        self.b.click(ABANDON)
        contains(self.b, 'main [aria-label="Confirm abandonment of submission recovery"]', [WARNING], 'explicit no-cancellation warning')
        self.shoot(fmt, 'confirm-abandon', '[aria-label="Confirm abandonment of submission recovery"]',
                   'confirmation makes the duplicate and no-cancellation consequences explicit.')
        self.b.click('Keep recovering')
        self.unknown()
        self.b.click(ABANDON)
        self.b.click(CONFIRM)
        absence(self.b, UNKNOWN, WARNING, str(job))
        require(not ({ABANDON, RETRY, SUBMIT} & self.buttons()) and snapshot(self.data) == ready and
                len(gate.seen()) == n + 1, 'Abandonment cancelled the old job or dispatched a new command')
        self.traffic(mark, fmt, posts=1, no_status=job, settle=True)
        self.demo.lookup(fmt, job, state='ready')
        report(f'PASS {fmt.upper()} abandon open/dismiss/confirm makes no request, deletes only local recovery; original still visible on explicit owner lookup')

    def retirement(self, fmt):
        raw, gate, n, before, mark = self.launch(fmt)
        with gate.arm(fmt) as fault:
            self.b.click(SUBMIT)
            job = committed_fault(self.data, fmt, fault, raw)
            ready = fresh_job(self.data, fmt, job, raw, before)
            self.demo.as_user('foreign_submitter')
            self.b.dom(f'void window.__a19_2Receipt({prior.quoted(prior.SESSION)},true)')
            switch = self.b.mark()
            self.b.click('Clear workspace context')
            require(prior.observed_reply(self.b, switch, prior.SESSION, 200) == {'current': True}, 'Replacement signed context did not verify')
            self.retired_view(fmt, job)
            self.release(fault)
            self.b.receipt(mark, prior.upload_path(fmt), 202, method='POST', body=False, retired=True)
        self.retired_view(fmt, job)
        self.traffic(mark, fmt, posts=1, no_status=job, settle=True)
        require(snapshot(self.data) == ready and len(gate.seen()) == n + 1, 'Retired upload resubmitted or mutated native state')
        prior.signed_probe(self.b, prior.job_path(fmt, job), prior.DENIED_STATUS[fmt])
        self.shoot(fmt, 'retired', 'main', 'replacement signed context exposes neither held receipt, old draft nor recovery actions.')
        report(f'PASS {fmt.upper()} real delayed old ASGI receipt after signed identity replacement did not publish or retry')

    def retired_view(self, fmt, job):
        absence(self.b, UNKNOWN, self.demo.submitted[fmt]['title'], self.demo.inputs[fmt]['file'].name,
                self.demo.node, str(job))
        require(not ({RETRY, ABANDON, SUBMIT} & self.buttons()) and
                self.b.dom("[...document.querySelectorAll('main input[type=file]')].every(e=>e.files.length===0)"),
                'Old browser command survived scope retirement')

    def unpublished(self):
        b = self.b
        self.demo.open('reader')
        mark = prior.click_link(b, prior.SEARCH, 'Knowledge Interface')
        b.receipt(mark, prior.UNIFIED + prior.SCOPES, 200)
        b.state('scopes', 'complete')
        b.change('Organisational scope', self.demo.node)
        for fmt in FORMATS:
            b.results(b.query(self.demo.marker[fmt]), self.demo.node, self.demo.marker[fmt], [])
        report('PASS signed authorized search did not publish or disclose processed synthetic intake')

    def scope_loss(self, fmt, who):
        # Grant changes advance the session cutoff. Use a different signed
        # fixture owner for each format rather than reviving retired authority.
        raw, gate, n, before, mark = self.launch(fmt, who=who)
        with gate.arm(fmt, corrupt=True) as fault:
            self.b.click(SUBMIT)
            job = committed_fault(self.data, fmt, fault, raw, who=who)
            ready = fresh_job(self.data, fmt, job, raw, before, who=who)
            self.release(fault)
        self.b.receipt(mark, prior.upload_path(fmt), 502, method='POST', body=False)
        self.unknown()
        drop_submit(self.data, who=who)
        retry = self.b.mark()
        self.b.click(RETRY)
        self.b.receipt(retry, prior.upload_path(fmt), 403, method='POST', body=False)
        self.b.expect(f'!document.querySelector({prior.quoted(prior.SUBMIT)})', 'actual authorization loss retires the workspace')
        contains(self.b, 'main', ['Recovery ended because access could not be confirmed. A previous submission may already exist.'],
                 'retired submission truthfully warns the earlier attempt may exist')
        self.retired_view(fmt, job)
        absence(self.b, REJECTION)
        self.traffic(mark, fmt, posts=2, no_status=job, settle=True)
        require(len(gate.seen()) == n + 2 and snapshot(self.data) == ready, 'Authorization loss mutated business state')
        report(f'PASS {fmt.upper()} actual exact-node authority removal denied explicit recovery without declaring the earlier upload rejected')


def run(args, scratch, _):
    with ExitStack() as stack:
        data, b, demo = start(args, scratch, stack, chromium)
        recovery = Recovery(data, b, demo, scratch)
        initial = snapshot(data)
        for fmt in FORMATS:
            recovery.normal(fmt)
            for mode in ('bridge-502', 'client-malformed', 'transport-loss'):
                recovery.recover(fmt, mode)
            recovery.rejection(fmt)
            recovery.abandonment(fmt)
            recovery.retirement(fmt)
        recovery.scope_loss('csv', 'submitter')
        recovery.scope_loss('xlsx', 'other_owner')
        recovery.unpublished()
        final = snapshot(data)
        require(all(initial[table] == final[table] for table in ISOLATED), 'Publication, decisions or access changed')
        report('PASS independent owner observations: publication, access and decision tables unchanged')
        check_runtime(b)
    publish(demo.screens, recovery.shots, 'candidate')
    report('PASS AM2 signed CSV/XLSX recovery and service teardown')


if __name__ == '__main__':
    sys.exit(harness.main(run, entry=os.path.abspath(__file__), name='a19-2-am2',
                          browser_required=True, description=__doc__))
