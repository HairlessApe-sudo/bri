#!/usr/bin/env python3
"""Reproduce lost receipt recovery in an isolated fresh held A19.2-AM1 export."""
import os
import sys
from contextlib import ExitStack
from pathlib import Path
from uuid import UUID

import a13_demo as harness
import a19_2_demo as prior
from a13_demo import report, require, status, UI
from a18_3_demo import contains, private_directory, start_next
from a19_1_demo import check_runtime, png, visible_buttons
from a19_1_fixture import ORIGINAL_LABEL
from a19_2_am2_fault import committed_fault, setup
from a19_2_fixture import FORMATS, PRIMARY, assert_job, job_rows

SUBMIT = 'Submit classified file'
RETRY = 'Retry the same submission'
ACK = prior.SUBMIT + ' [aria-label="Submission acknowledgement"]'


def start(args, scratch, stack, driver=prior.start_observed_browser):
    os.environ.update(TMPDIR=str(scratch), BRI_LOCAL_METADATA_ENABLED='1')
    data = setup(args, scratch, stack)
    browser = driver(args, scratch, stack)
    start_next(args, scratch, stack, data['client'])
    status(data['client'].get(UI + prior.PAGE, timeout=90), 200, 'unsigned administration page shell')
    demo = prior.Demo(browser, data, scratch)
    demo.http('catalogue', '/catalogue/admin/seed', 'manager', 204, method='POST', json={})
    demo.http('catalogue', '/catalogue/admin/create', 'manager', 204, method='POST',
              json={'category_id': 'general', 'classification_id': PRIMARY, 'label': ORIGINAL_LABEL,
                    'description': 'Synthetic recovery qualification fixture'})
    return data, browser, demo


def run(args, scratch, _):
    shots = {}
    with ExitStack() as stack:
        data, b, demo = start(args, scratch, stack)
        for fmt in FORMATS:
            demo.open('submitter')
            demo.stage(fmt)
            raw = demo.inputs[fmt]['raw']
            gate = data['gates'][fmt]
            before, previous, mark = job_rows(data), len(gate.seen()), b.mark()
            with gate.arm(fmt, corrupt=True) as fault:
                b.click(SUBMIT)
                job = committed_fault(data, fmt, fault, raw)
                after_commit = job_rows(data)
                require(len(after_commit[fmt]) == len(before[fmt]) + 1, 'Missing first committed native job')
                report(f'PASS held {fmt.upper()} owner observed committed ready native job before response corruption')
                fault.release.set()
                require(fault.finished.wait(5), 'Native corrupted response did not finish')
            b.receipt(mark, prior.upload_path(fmt), 502, method='POST', body=False)
            contains(b, 'main [role="alert"]', [], 'held genuine 502 rendered')
            b.paint()
            require(not b.dom(f'document.querySelector({prior.quoted(ACK)})') and
                    RETRY not in {button['label'] for button in visible_buttons(b)},
                    'Held baseline unexpectedly retained the recovery command')
            require(b.run('count', mark=mark, path=prior.upload_path(fmt), method='POST') == 1 and
                    job_rows(data) == after_commit, 'Held baseline unexpectedly retried')
            shot = f'{fmt}-lost-recovery'
            png(b, demo.screens, shot, 'main [role="alert"]')
            shots[shot] = f'{fmt.upper()}: real bridge 502; original job is already committed; no recovery command.'

            # Identical synthetic bytes, scope and metadata staged by the same UI.
            # The held user can only reopen context, re-stage and create a new command.
            clear = b.mark()
            b.click('Clear workspace context')
            require(prior.observed_reply(b, clear, prior.SESSION, 200) == {'current': True}, 'Held context did not reopen')
            demo.stage(fmt)
            mark = b.mark()
            b.click(SUBMIT)
            receipt = prior.observed_reply(b, mark, prior.upload_path(fmt), 202, method='POST')
            second = UUID(receipt['id'])
            contains(b, ACK, [str(second)], 'second held submission rendered')
            assert_job(data, fmt, second, raw, 'ready')
            commands = gate.seen()[previous:]
            rows = job_rows(data)
            other = 'xlsx' if fmt == 'csv' else 'csv'
            require(second != job and len(commands) == 2 and commands[0][0] != commands[1][0] and
                    commands[0][1:] == commands[1][1:] and len(rows[fmt]) == len(before[fmt]) + 2 and
                    rows[other] == before[other], 'Re-stage did not produce a different key and second native job')
            report(f'PASS held {fmt.upper()} bridge returned real 502; no retry or acknowledgement; manual re-stage used a new key and committed a second job')
        check_runtime(b)
    publish(demo.screens, shots, 'held')
    report('PASS held signed Chromium reproduction and service teardown')


def publish(screens, shots, category):
    from hashlib import sha256
    from pwd import getpwuid
    from tempfile import mkdtemp
    from a18_3_demo import png_size, WIDE

    root = Path(getpwuid(os.getuid()).pw_dir) / '.hermes/evidence/BRI/A19.2/am2/browser'
    private_directory(root)
    destination = Path(mkdtemp(prefix=f'{category}-', dir=root))
    lines = ['# Synthetic signed Chromium evidence', '']
    for name, description in shots.items():
        filename = f'{name}.png'
        raw = (screens / filename).read_bytes()
        require(png_size(raw) == WIDE, 'Unexpected evidence screenshot dimensions')
        target = destination / filename
        target.write_bytes(raw)
        require(target.read_bytes() == raw, 'Evidence copy mismatch')
        lines.append(f'- `{filename}` 1440×1000 `{sha256(raw).hexdigest()}` — {description}')
    (destination / 'manifest.md').write_text('\n'.join(lines) + '\n')
    report(f'PASS {len(shots)} verified synthetic 1440×1000 PNGs in {destination}')


if __name__ == '__main__':
    sys.exit(harness.main(run, entry=os.path.abspath(__file__), name='a19-2-am2-held',
                          browser_required=True, description=__doc__))
