"""Staged A19.2 HTTP + private socket-only PostgreSQL 16.2 qualification."""
import os
import unittest
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from typing import TypedDict, cast
from unittest.mock import patch
from uuid import UUID, uuid4
from zipfile import ZipFile

import httpx
from openpyxl import Workbook

import test_knowledge_metadata_api as fixture
from bri.api.app import create_app
from bri.api.csv_intake import Scope, create_staged_csv_intake_app
from bri.api.xlsx_intake import _Quarantine, create_staged_xlsx_intake_app
from bri.ingestion.csv_intake import LocalCsvQuarantine, ProcessOutcome
from bri.ingestion.xlsx_intake import LocalXlsxQuarantine, XlsxProcessOutcome

BASE = '/v1/knowledge-administration'
XLSX_MEDIA = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
CSV = b'\xef\xbb\xbfheading,note\r\nvalue,"line\r\nbreak"\r\n'


def workbook():
    file = BytesIO()
    wb = Workbook()
    sheet = wb.active
    assert sheet is not None
    sheet.append(['heading', 'note'])
    sheet.append(['value', 'worksheet fixture'])
    wb.save(file)
    return file.getvalue()


class AssemblyOptions(TypedDict):
    identity_scope: Scope
    private_socket: Path
    auth_transport: httpx.MockTransport
    enable_metadata: bool


@unittest.skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16.2')
class AdministrationHttpTests(unittest.TestCase):
    sock: Path
    tenant: str
    actors: list[tuple[UUID, UUID, UUID]]
    connect = fixture.MetadataHttpTests.__dict__['connect']
    setUpClass = fixture.MetadataHttpTests.__dict__['setUpClass']
    setUp = fixture.MetadataHttpTests.setUp
    install = fixture.MetadataHttpTests.install
    seed_catalogue = fixture.MetadataHttpTests.seed_catalogue
    credentials = fixture.MetadataHttpTests.credentials
    loopback_reader = fixture.MetadataHttpTests.loopback_reader
    grant = fixture.MetadataHttpTests.grant
    extra_actor = fixture.MetadataHttpTests.extra_actor

    def stage(self, fmt, *, enable=True, metadata=True, seed=True, root=None):
        if seed:
            self.seed_catalogue()
        actor, transport = self.credentials()
        if root is None:
            root = Path(self.enterContext(TemporaryDirectory()))
        common = AssemblyOptions(identity_scope=lambda: self.connect('bri_app'), private_socket=self.sock,
                                 auth_transport=transport, enable_metadata=metadata)
        if fmt == 'csv':
            for role, routines in {'bri_csv_intake': ('csv_submit_metadata_v1', 'csv_mark_ready'),
                                   'bri_csv_worker': ('csv_claim', 'csv_complete')}.items():
                for routine in routines:
                    self.install(role, routine)
            store = LocalCsvQuarantine(root)
            app = create_staged_csv_intake_app(**common, intake_scope=lambda: self.connect('bri_csv_intake'),
                                               worker_scope=lambda: self.connect('bri_csv_worker'), store=store,
                                               enable_knowledge_administration=enable)
        else:
            self.install('bri_xlsx_submitter', 'xlsx_submit_metadata_v1')
            with self.connect('postgres') as db:
                db.execute("DO $$ BEGIN CREATE ROLE bri_xlsx_worker LOGIN NOINHERIT NOBYPASSRLS; "
                           "EXCEPTION WHEN duplicate_object THEN NULL; END $$; "
                           "GRANT USAGE ON SCHEMA bri TO bri_xlsx_worker")
                for name, signature, role in (
                    ('xlsx_mark_ready', 'text,uuid,uuid,uuid,text,uuid,uuid', 'bri_xlsx_submitter'),
                    ('xlsx_status', 'text,uuid,uuid,uuid,text,uuid', 'bri_xlsx_submitter'),
                    ('xlsx_claim', 'uuid,uuid', 'bri_xlsx_worker'),
                    ('xlsx_complete', 'uuid,integer,text,text,integer,integer,text,text,text,uuid', 'bri_xlsx_worker'),
                    ('xlsx_fail', 'uuid,integer,text,uuid', 'bri_xlsx_worker'),
                ):
                    db.execute(f'GRANT EXECUTE ON FUNCTION bri.{name}({signature}) TO {role}')
            store = LocalXlsxQuarantine(root)
            app = create_staged_xlsx_intake_app(**common, submitter_scope=lambda: self.connect('bri_xlsx_submitter'),
                                                worker_scope=lambda: self.connect('bri_xlsx_worker'),
                                                store=cast(_Quarantine, store), enable_knowledge_administration=enable)
        if fmt == 'csv':
            with self.connect('postgres') as db:
                db.execute('GRANT EXECUTE ON FUNCTION bri.csv_status(text,uuid,uuid,text,uuid,uuid) TO bri_csv_intake')
                db.execute('GRANT EXECUTE ON FUNCTION bri.csv_fail(uuid,integer,text,boolean,uuid) TO bri_csv_worker')
        return app, actor, root

    @staticmethod
    def headers(actor, fmt, *, key=None):
        return {**actor(2), 'Content-Type': 'text/csv' if fmt == 'csv' else XLSX_MEDIA, 'X-Node-ID': 'team',
                'Idempotency-Key': str(key or uuid4()), 'X-BRI-Metadata': fixture.encoded(fixture.META)}

    def assert_no_store(self, response):
        self.assertEqual(response.headers['cache-control'], 'private, no-store')
        self.assertEqual(response.headers['x-content-type-options'], 'nosniff')
        UUID(response.headers['x-request-id'])

    def check_native_intake(self, fmt, raw, wrong):
        app, actor, root = self.stage(fmt)
        path = f'{BASE}/{fmt}/uploads'
        hdr = self.headers(actor, fmt)
        with self.loopback_reader(app) as api:
            mismatch = api.post(path, headers=hdr, content=wrong)
            self.assertEqual(mismatch.status_code, 415, mismatch.text)
            self.assert_no_store(mismatch)
            with self.connect('postgres') as db:
                self.assertEqual(db.execute(f'SELECT count(*) FROM bri.{fmt}_jobs WHERE tenant_id=%s',
                                            (self.tenant,)).fetchone(), (0,))
            self.assertFalse(any(root.iterdir()))
            reply = api.post(path, headers=hdr, content=raw)
            self.assertEqual(reply.status_code, 202, reply.text)
            self.assert_no_store(reply)
            job = reply.json()
            self.assertEqual(job, {'id': job['id'], 'state': 'ready'})
            UUID(job['id'])
            native = '/v1/sources/csv' if fmt == 'csv' else '/v1/intake/xlsx'
            self.assertEqual(api.get(f'{native}/{job["id"]}', headers=actor(2)).json(), job)
            self.assertEqual(api.post(path, headers=hdr, content=raw).json(), job)
            changed = {**hdr, 'X-BRI-Metadata': fixture.encoded({**fixture.META, 'title': 'Different title'})}
            self.assertEqual(api.post(path, headers=changed, content=raw).status_code, 409)
        self.assertEqual([p.read_bytes() for p in root.rglob('*') if p.is_file()], [raw])
        with self.connect('postgres') as db:
            rows = db.execute(f'SELECT job_id,original_sha256,attempt FROM bri.{fmt}_jobs WHERE tenant_id=%s',
                              (self.tenant,)).fetchall()
        self.assertEqual(rows, [(UUID(job['id']), sha256(raw).hexdigest(), 0)])

    def test_csv_accepts_original_bom_and_rejects_xlsx_before_reservation(self):
        self.check_native_intake('csv', CSV, workbook())

    def test_xlsx_accepts_original_zip_and_rejects_csv_before_reservation(self):
        self.check_native_intake('xlsx', workbook(), CSV)

    def test_inflight_request_admission_does_not_queue_a_duplicate(self):
        app, actor, root = self.stage('csv')
        path = f'{BASE}/csv/uploads'
        hdr = self.headers(actor, 'csv')
        entered, release = Event(), Event()
        install = LocalCsvQuarantine.install

        def pause(store, tenant, key, body):
            entered.set()
            if not release.wait(4):
                raise AssertionError('coordinator did not release install')
            return install(store, tenant, key, body)

        with self.loopback_reader(app) as api, patch.object(LocalCsvQuarantine, 'install', pause):
            with ThreadPoolExecutor(max_workers=1) as worker:
                first = worker.submit(api.post, path, headers=hdr, content=CSV)
                try:
                    self.assertTrue(entered.wait(4), 'first request never reached native quarantine')
                    self.assertEqual(api.post(path, headers=hdr, content=CSV, timeout=1).status_code, 503)
                finally:
                    release.set()
                accepted = first.result(timeout=5)
            self.assertEqual(accepted.status_code, 202, accepted.text)
        rebuilt, actor, _ = self.stage('csv', seed=False, root=root)
        with self.loopback_reader(rebuilt) as restarted:
            retry = self.headers(actor, 'csv', key=UUID(hdr['Idempotency-Key']))
            self.assertEqual(restarted.post(path, headers=retry, content=CSV).json(), accepted.json())
        self.assertEqual([p.read_bytes() for p in root.rglob('*') if p.is_file()], [CSV])
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT attempt,state FROM bri.csv_jobs WHERE tenant_id=%s',
                                        (self.tenant,)).fetchall(), [(0, 'ready')])

    def test_disabled_assemblies_do_not_mount_new_paths_or_reinterpret_existing_upload(self):
        for index, fmt in enumerate(('csv', 'xlsx')):
            with self.subTest(fmt=fmt):
                wrong = workbook() if fmt == 'csv' else CSV
                app, actor, _ = self.stage(fmt, enable=False, seed=index == 0)
                hdr = self.headers(actor, fmt)
                path = f'{BASE}/{fmt}/uploads'
                with self.loopback_reader(app) as api:
                    self.assertEqual(api.post(path, headers=actor(2), content=wrong).status_code, 404)
                    legacy = api.post(f'/v1/knowledge-metadata/{fmt}/uploads', headers=hdr, content=wrong)
                    self.assertEqual(legacy.status_code, 202, legacy.text)
                    self.assertEqual(legacy.json()['state'], 'ready')
                with self.assertRaisesRegex(ValueError, 'requires the staged metadata mode'):
                    self.stage(fmt, metadata=False, seed=False)
        with self.loopback_reader(create_app()) as release:
            for fmt in ('csv', 'xlsx'):
                self.assertEqual(release.post(f'{BASE}/{fmt}/uploads', content=CSV).status_code, 404)

    def test_exact_route_header_media_and_size_checks_reserve_nothing(self):
        file = BytesIO()
        with ZipFile(file, 'w') as archive:
            archive.writestr('unrelated.txt', 'Not a spreadsheet')
        for index, fmt in enumerate(('csv', 'xlsx')):
            with self.subTest(fmt=fmt):
                app, actor, root = self.stage(fmt, seed=index == 0)
                header, path = self.headers(actor, fmt), f'{BASE}/{fmt}/uploads'
                body = workbook() if fmt == 'xlsx' else CSV
                wrong = file.getvalue() if fmt == 'xlsx' else b'heading\n\xff\n'
                other = 'xlsx' if fmt == 'csv' else 'csv'
                with self.loopback_reader(app) as api:
                    cases = (
                        ('GET', path, {}, b'', 404),
                        ('POST', path + '/', header, body, 404),
                        ('POST', path.replace('uploads', '%75ploads'), header, body, 404),
                        ('POST', path.replace(f'/{fmt}/', f'/{other}/'), header, body, 404),
                        ('POST', path + '/dispatch', header, body, 404),
                        ('POST', path + '?job_id=' + str(uuid4()), header, body, 400),
                        ('POST', path, {**header, 'x-tenant-id': self.tenant}, body, 400),
                        ('POST', path, {**header, 'Content-Type': 'application/octet-stream'}, body, 415),
                        ('POST', path, {**header, 'Content-Encoding': 'gzip'}, body, 400),
                        ('POST', path, header, wrong, 415),
                        ('POST', path, header, b'x' * 5_000_001, 413),
                    )
                    for method, target, headers, raw, status in cases:
                        response = api.request(method, target, headers=headers, content=raw)
                        self.assertEqual(response.status_code, status, response.text)
                        self.assert_no_store(response)
                        self.assertEqual(set(response.json()), {'detail'})
                with self.connect('postgres') as db:
                    self.assertEqual(db.execute(f'SELECT count(*) FROM bri.{fmt}_jobs WHERE tenant_id=%s',
                                                (self.tenant,)).fetchone(), (0,))
                self.assertFalse(any(root.iterdir()))

    def test_native_worker_only_can_turn_a_ready_receipt_into_a_proposal(self):
        for index, fmt in enumerate(('csv', 'xlsx')):
            with self.subTest(fmt=fmt):
                app, actor, _ = self.stage(fmt, seed=index == 0)
                headers = self.headers(actor, fmt)
                raw = CSV if fmt == 'csv' else workbook()
                path = f'{BASE}/{fmt}/uploads'
                with self.loopback_reader(app) as api:
                    reply = api.post(path, headers=headers, content=raw)
                    self.assertEqual(reply.status_code, 202, reply.text)
                    ready = reply.json()
                    self.assertEqual(ready['state'], 'ready')
                    job = UUID(ready['id'])
                    if fmt == 'csv':
                        self.assertIs(app.state.csv_worker.dispatch(job), ProcessOutcome.COMPLETED)
                    else:
                        self.assertIs(app.state.xlsx_worker.dispatch(job, uuid4()), XlsxProcessOutcome.COMPLETED)
                    native = '/v1/sources/csv' if fmt == 'csv' else '/v1/intake/xlsx'
                    self.assertEqual(api.get(f'{native}/{job}', headers=actor(2)).json(),
                                     {'id': str(job), 'state': 'proposed'})
                    self.assertEqual(api.post(path, headers=headers, content=raw).json(),
                                     {'id': str(job), 'state': 'proposed'})
                with self.connect('postgres') as db:
                    self.assertEqual(db.execute(f'SELECT attempt,state FROM bri.{fmt}_jobs WHERE tenant_id=%s',
                                                (self.tenant,)).fetchall(), [(1, 'proposed')])

    def test_live_exact_node_role_and_job_owner_authority(self):
        own_tenant, own_actors = self.tenant, self.actors
        self.setUp()
        self.seed_catalogue()
        foreign_tenant, foreign_actor = self.tenant, self.actors[2]
        self.tenant, self.actors = own_tenant, own_actors
        self.actors.append(foreign_actor)
        foreign = len(self.actors) - 1
        reviewer = self.extra_actor()
        self.grant(reviewer, 'knowledge:review')
        other_owner = self.extra_actor()
        self.grant(other_owner, 'source:submit')
        for index, fmt in enumerate(('csv', 'xlsx')):
            with self.subTest(fmt=fmt):
                app, actor, _ = self.stage(fmt, seed=index == 0)
                path = f'{BASE}/{fmt}/uploads'
                native = '/v1/sources/csv' if fmt == 'csv' else '/v1/intake/xlsx'
                raw = CSV if fmt == 'csv' else workbook()
                headers = self.headers(actor, fmt)
                with self.loopback_reader(app) as api:
                    # Both forbidden members have live sessions; fixture admin
                    # has an exact "source:submit" grant but the wrong role.
                    for hdr in ({**headers, **actor(0)}, {**headers, **actor(reviewer)},
                                {**headers, 'X-Node-ID': 'root'}):
                        self.assertEqual(api.post(path, headers=hdr, content=raw).status_code, 403)
                    anonymous = {h: v for h, v in headers.items() if h != 'Authorization'}
                    self.assertEqual(api.post(path, headers=anonymous, content=raw).status_code, 401)
                    local = api.post(path, headers=headers, content=raw)
                    remote = api.post(path, headers={**headers, **actor(foreign)}, content=raw)
                    for response in (local, remote):
                        self.assertEqual(response.status_code, 202, response.text)
                    local_id, remote_id = local.json()['id'], remote.json()['id']
                    self.assertNotEqual(local_id, remote_id)
                    self.assertEqual(api.get(f'{native}/{local_id}', headers=actor(2)).json(), local.json())
                    self.assertEqual(api.get(f'{native}/{remote_id}', headers=actor(foreign)).json(), remote.json())
                    for job_id, who in ((local_id, foreign), (remote_id, 2), (local_id, other_owner)):
                        forbidden = api.get(f'{native}/{job_id}', headers=actor(who))
                        absent = api.get(f'{native}/{uuid4()}', headers=actor(who))
                        self.assertIn(forbidden.status_code, (403, 404))
                        self.assertEqual((forbidden.status_code, forbidden.json()), (absent.status_code, absent.json()))
                with self.connect('postgres') as db:
                    self.assertCountEqual(db.execute(f'SELECT job_id,tenant_id FROM bri.{fmt}_jobs WHERE '
                                                     'tenant_id IN (%s,%s)', (self.tenant, foreign_tenant)).fetchall(),
                                          [(UUID(local_id), self.tenant), (UUID(remote_id), foreign_tenant)])

    def test_screened_but_invalid_workbook_is_failed_only_by_native_worker(self):
        bad = BytesIO()
        with ZipFile(bad, 'w') as archive:
            for name in ('[Content_Types].xml', '_rels/.rels', 'xl/_rels/workbook.xml.rels'):
                archive.writestr(name, 'not valid workbook XML')
        app, actor, _ = self.stage('xlsx')
        path = f'{BASE}/xlsx/uploads'
        headers = self.headers(actor, 'xlsx')
        with self.loopback_reader(app) as api:
            response = api.post(path, headers=headers, content=bad.getvalue())
            self.assertEqual(response.status_code, 202, response.text)
            job = UUID(response.json()['id'])
            self.assertEqual(response.json()['state'], 'ready')
            self.assertIs(app.state.xlsx_worker.dispatch(job, uuid4()), XlsxProcessOutcome.FAILED)
            failed = {'id': str(job), 'state': 'failed'}
            self.assertEqual(api.get(f'/v1/intake/xlsx/{job}', headers=actor(2)).json(), failed)
            self.assertEqual(api.post(path, headers=headers, content=bad.getvalue()).json(), failed)
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT attempt,state FROM bri.xlsx_jobs WHERE job_id=%s',
                                        (job,)).fetchone(), (1, 'failed'))

    def test_revoked_uploader_cannot_replay_and_fixture_claim_loses_authority(self):
        app, actor, _ = self.stage('csv')
        path = f'{BASE}/csv/uploads'
        hdr = self.headers(actor, 'csv')
        with self.loopback_reader(app) as api:
            reply = api.post(path, headers=hdr, content=CSV)
            self.assertEqual(reply.status_code, 202, reply.text)
            job = UUID(reply.json()['id'])
            with self.connect('postgres') as db:
                db.execute('UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() WHERE session_id=%s',
                           (self.actors[2][2],))
            self.assertEqual(api.post(path, headers=hdr, content=CSV).status_code, 403)
            self.assertEqual(api.get(f'/v1/sources/csv/{job}', headers=actor(2)).status_code, 403)
            self.assertIs(app.state.csv_worker.dispatch(job), ProcessOutcome.NOT_CLAIMED)
        with self.connect('postgres') as db:
            self.assertEqual(db.execute('SELECT attempt,state FROM bri.csv_jobs WHERE job_id=%s',
                                        (job,)).fetchone(), (0, 'failed'))
