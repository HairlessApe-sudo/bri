"""Versioned metadata HTTP over real loopback and a disposable private database."""
import base64
import json
import os
import unittest
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID, uuid4

import httpx
from openpyxl import Workbook
from test_authentication import auth_server_response, make_token
import test_csv_intake_api as csv_fixture
import test_knowledge_metadata_postgres as metadata_fixture

from bri.api.csv_intake import create_staged_csv_intake_app, create_staged_csv_reader_app
from bri.api.csv_review_workspace import create_staged_csv_review_app
from bri.api.xlsx_governance import create_staged_xlsx_governance_app
from bri.api.xlsx_intake import create_staged_xlsx_intake_app
from bri.ingestion.csv_intake import LocalCsvQuarantine, ProcessOutcome
from bri.ingestion.xlsx_intake import LocalXlsxQuarantine

BASE = '/v1/knowledge-metadata'
META = metadata_fixture.META


def encoded(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).rstrip(b'=').decode()


@unittest.skipUnless(os.getenv('BRI_TEST_PG_BIN'), 'requires private PostgreSQL 16.2')
class MetadataHttpTests(unittest.TestCase):
    actors: list[tuple[UUID, UUID, UUID]]
    sock: Path
    tenant: str
    connect = metadata_fixture.MetadataPostgresTests.__dict__['connect']
    setUpClass = metadata_fixture.MetadataPostgresTests.__dict__['setUpClass']
    setUp = metadata_fixture.MetadataPostgresTests.setUp

    seed_catalogue = metadata_fixture.MetadataPostgresTests.seed_catalogue
    grant = metadata_fixture.MetadataPostgresTests.grant
    extra_actor = metadata_fixture.MetadataPostgresTests.extra_actor
    def loopback_reader(self, app):
        return csv_fixture.StagedCsvPostgres.loopback_reader(self, app)

    def install(self, role, routine):
        base = 'text,uuid,uuid,uuid,text,uuid'
        extra = {'csv_review_metadata_detail_v1': base + ',integer', 'xlsx_review_metadata_detail_v1': base,
                 'xlsx_list_metadata_corrections_v1': base + ',uuid,uuid,integer'}
        if routine not in extra:
            return metadata_fixture.MetadataPostgresTests.install(self, role, routine)
        signature = f'bri.{routine}({extra[routine]})'
        with self.connect('bri_app') as db:
            self.assertEqual(db.execute("SELECT has_function_privilege(to_regprocedure(%s),'EXECUTE')",
                                        (signature,)).fetchone(), (False,))
        with self.connect('postgres') as db:
            db.execute(f'GRANT EXECUTE ON FUNCTION {signature} TO {role}')

    def credentials(self):
        allow = {}

        def actor(who):
            _, sub, sid = self.actors[who]
            token = 'Bearer ' + make_token(sub=str(sub), session_id=str(sid))
            allow[token] = str(sub)
            return {'Authorization': token}

        def provider(request):
            user = allow.get(request.headers.get('authorization'))
            return auth_server_response(request, user_id=user or '', status=200 if user else 401)

        return actor, httpx.MockTransport(provider)

    def test_versioned_csv_submission_binds_metadata_to_native_quarantine_job(self):
        for role, routines in {'bri_csv_intake': ('csv_submit_metadata_v1', 'csv_mark_ready'),
                               'bri_csv_worker': ('csv_claim', 'csv_complete')}.items():
            for routine in routines:
                self.install(role, routine)
        self.seed_catalogue()
        actor, transport = self.credentials()
        root = Path(self.enterContext(TemporaryDirectory()))
        stage = create_staged_csv_intake_app(
            identity_scope=lambda: self.connect('bri_app'), private_socket=self.sock, auth_transport=transport,
            intake_scope=lambda: self.connect('bri_csv_intake'), worker_scope=lambda: self.connect('bri_csv_worker'),
            store=LocalCsvQuarantine(root), enable_metadata=True,
        )
        headers = {**actor(2), 'Content-Type': 'text/csv', 'X-Node-ID': 'team',
                   'Idempotency-Key': str(uuid4()), 'X-BRI-Metadata': encoded(META)}
        path = BASE + '/csv/uploads'
        with self.loopback_reader(stage) as api:
            reply = api.post(path, headers=headers, content=b'heading\nvalue\n')
            self.assertEqual(reply.status_code, 202, reply.text)
            self.assertEqual(reply.headers['cache-control'], 'private, no-store')
            first = reply.json()
            self.assertEqual(first.keys(), {'id', 'state'})
            self.assertEqual(first['state'], 'ready')
            self.assertEqual(api.post(path, headers=headers, content=b'heading\nvalue\n').json(), first)
            self.assertEqual(api.post(path, headers={**headers, 'X-BRI-Metadata': encoded({**META, 'title': 'changed'})},
                                      content=b'heading\nvalue\n').status_code, 409)
            self.assertEqual(api.post(path.replace('uploads', '%75ploads'), headers=headers,
                                      content=b'heading\nvalue\n').status_code, 404)
        self.assertIs(stage.state.csv_worker.dispatch(UUID(first['id'])), ProcessOutcome.COMPLETED)

        for routine in ('csv_review_metadata_detail_v1', 'csv_review_metadata_v1'):
            self.install('bri_csv_intake', routine)
        review = create_staged_csv_review_app(identity_scope=lambda: self.connect('bri_app'),
            private_socket=self.sock, auth_transport=transport, review_scope=lambda: self.connect('bri_csv_intake'),
            enable_metadata=True)
        job = first['id']
        path = f'{BASE}/csv/review/{job}'
        with self.loopback_reader(review) as api:
            self.assertEqual(api.get(path, headers=actor(2)).status_code, 404)
            self.assertEqual(api.get(path, headers=actor(0)).json(),
                             {'job_id': job, 'node_id': 'team', 'proposed_metadata': META})
            cmd = {'action': 'approve', 'request_id': str(uuid4()), 'metadata': {**META, 'title': 'Corrected initial'}}
            receipt = api.post(path + '/decision', headers=actor(0), json=cmd)
            self.assertEqual(receipt.status_code, 200, receipt.text)
            self.assertEqual(receipt.json(), {'job_id': job, 'decision': 'approve', 'metadata_revision': '1'})
            self.assertEqual(api.get(path, headers=actor(0)).status_code, 404)
            self.assertEqual(api.post(path + '/decision', headers=actor(0), json=cmd).json(), receipt.json())

        self.install('bri_csv_reader', 'csv_read_metadata_v1')
        self.grant(0, 'knowledge:read')
        reader = create_staged_csv_reader_app(identity_scope=lambda: self.connect('bri_app'),
            private_socket=self.sock, auth_transport=transport, reader_scope=lambda: self.connect('bri_csv_reader'),
            enable_metadata=True)
        path = f'{BASE}/csv/records/{job}/versions/{job}'
        with self.loopback_reader(reader) as api:
            self.assertEqual(api.get(path, headers=actor(0)).status_code, 404)
            ref = f'csv:{job}'
            with self.connect('bri_migrator') as db:
                db.execute("SELECT set_config('bri.tenant_id',%s,true)", (self.tenant,))
                db.execute('INSERT INTO bri.knowledge_record_access VALUES (%s,%s,true)', (self.tenant, ref))
                db.execute('INSERT INTO bri.knowledge_version_access VALUES (%s,%s,%s,true)', (self.tenant, ref, ref))
            found = api.get(path, headers=actor(0))
            self.assertEqual(found.status_code, 200, found.text)
            self.assertEqual((found.json()['record_id'], found.json()['source_version_id']), (job, job))
            self.assertEqual(found.json()['metadata']['title'], 'Corrected initial')
            self.assertEqual(api.get(path, headers={**actor(0), 'role-id': 'fixture'}).status_code, 400)
            self.assertEqual(api.get(path.replace(f'/versions/{job}', f'/versions/{uuid4()}'), headers=actor(0)).status_code, 404)

    def test_xlsx_correction_requires_fresh_exact_authority_and_separate_proposal(self):
        self.seed_catalogue()
        for role, routines in {
            'bri_xlsx_submitter': ('xlsx_submit_metadata_v1',),
            'bri_xlsx_reviewer': ('xlsx_review_metadata_v1', 'xlsx_review_metadata_detail_v1'),
            'bri_xlsx_reader': ('xlsx_read_metadata_v1', 'xlsx_propose_metadata_correction_v1',
                                'xlsx_list_metadata_corrections_v1', 'xlsx_review_metadata_correction_v1'),
        }.items():
            for routine in routines:
                self.install(role, routine)
        with self.connect('postgres') as db:
            ident = 'text,uuid,uuid,uuid,text'
            db.execute(f'GRANT EXECUTE ON FUNCTION bri.xlsx_mark_ready({ident},uuid,uuid) TO bri_xlsx_submitter')
            db.execute('CREATE ROLE bri_xlsx_worker LOGIN NOINHERIT NOBYPASSRLS; GRANT USAGE ON SCHEMA bri TO bri_xlsx_worker')
            db.execute('GRANT EXECUTE ON FUNCTION bri.xlsx_claim(uuid,uuid),'
                       'bri.xlsx_complete(uuid,integer,text,text,integer,integer,text,text,text,uuid),'
                       'bri.xlsx_fail(uuid,integer,text,uuid) TO bri_xlsx_worker')
        reviewer = self.extra_actor()
        self.grant(reviewer, 'knowledge:read')
        self.grant(reviewer, 'knowledge:metadata:review')
        self.grant(0, 'knowledge:read')
        self.grant(0, 'knowledge:metadata:propose')
        actor, transport = self.credentials()
        root = Path(self.enterContext(TemporaryDirectory()))
        fixture = dict(identity_scope=lambda: self.connect('bri_app'), private_socket=self.sock, auth_transport=transport,
                       enable_metadata=True)
        intake = create_staged_xlsx_intake_app(**fixture, submitter_scope=lambda: self.connect('bri_xlsx_submitter'),
            worker_scope=lambda: self.connect('bri_xlsx_worker'), store=LocalXlsxQuarantine(root))
        review = create_staged_xlsx_governance_app(**fixture, review_scope=lambda: self.connect('bri_xlsx_reviewer'),
            reader_scope=lambda: self.connect('bri_xlsx_reader'))
        book = Workbook()
        book.active.append(['Heading', 'Example'])
        book.active.append(['Row', 42])
        original = BytesIO()
        book.save(original)
        with self.loopback_reader(intake) as api:
            reply = api.post(BASE + '/xlsx/uploads', headers={**actor(2), 'X-Node-ID': 'team',
                'Idempotency-Key': str(uuid4()), 'X-BRI-Metadata': encoded(META),
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'}, content=original.getvalue())
            self.assertEqual(reply.status_code, 202, reply.text)
            job = reply.json()['id']
            self.assertEqual(reply.json(), {'id': job, 'state': 'ready'})
        intake.state.xlsx_worker.dispatch(UUID(job), uuid4())
        with self.loopback_reader(review) as api:
            path = f'{BASE}/xlsx/review/{job}'
            self.assertEqual(api.get(path, headers=actor(0)).json(),
                             {'job_id': job, 'node_id': 'team', 'proposed_metadata': META})
            reply = api.post(path + '/decision', headers=actor(0), json={'action': 'approve', 'request_id': str(uuid4())})
            self.assertEqual(reply.status_code, 200, reply.text)
            with self.connect('postgres') as db:
                record, = db.execute('SELECT record_id FROM bri.xlsx_validated_knowledge WHERE job_id=%s', (job,)).fetchone()
                db.execute('INSERT INTO bri.xlsx_publication_events (tenant_id,record_id,job_id,revision,action,actor_id) '
                           "VALUES (%s,%s,%s,1,'publish',%s)", (self.tenant, record, job, self.actors[0][0]))
                for who in (0, reviewer):
                    db.execute('INSERT INTO bri.xlsx_record_access VALUES (%s,%s,%s)', (self.tenant, record, self.actors[who][0]))
            path = f'{BASE}/xlsx/records/{record}/versions/{job}'
            self.assertEqual(api.get(path, headers=actor(0)).status_code, 404)
            with self.connect('postgres') as db:
                for who in (0, reviewer):
                    db.execute('INSERT INTO bri.xlsx_version_access VALUES (%s,%s,%s,%s)',
                               (self.tenant, record, job, self.actors[who][0]))
            before = api.get(path, headers=actor(0))
            self.assertEqual(before.status_code, 200, before.text)
            self.assertEqual(before.json()['metadata']['revision'], '1')
            corrections = path + '/corrections'
            key = str(uuid4())
            proposal = {'request_id': key, 'expected_revision': '1', 'metadata': {**META, 'title': 'Corrected'}}
            self.assertEqual(api.post(corrections, headers=actor(0), json={**proposal, 'expected_revision': 1}).status_code, 422)
            self.assertEqual(api.post(corrections, headers=actor(0), json={**proposal,
                'expected_revision': '9223372036854775808'}).status_code, 422)
            self.assertEqual(api.post(corrections, headers=actor(0), json={**proposal,
                'expected_revision': '9223372036854775807'}).status_code, 409)
            receipt = api.post(corrections, headers=actor(0), json=proposal)
            self.assertEqual(receipt.status_code, 200, receipt.text)
            identifier = receipt.json()['proposal_id']
            self.assertNotEqual(UUID(identifier), UUID(key))
            self.assertEqual(api.post(corrections, headers=actor(0), json=proposal).json(), receipt.json())
            self.assertEqual(api.get(corrections, headers=actor(0)).status_code, 404)
            self.assertEqual(api.get(corrections, headers=actor(reviewer)).json(), {'items': [dict(
                proposal_id=identifier, expected_revision='1', proposed_metadata=proposal['metadata'])], 'next_after': None})
            decision_url = corrections + f'/{identifier}/decision'
            decision = {'action': 'approve', 'request_id': str(uuid4())}
            self.assertEqual(api.post(decision_url, headers=actor(reviewer), json=decision).json()['metadata_revision'], '2')
            self.assertEqual(api.get(path, headers=actor(0)).json()['metadata']['title'], 'Corrected')
            self.assertEqual(api.post(corrections, headers=actor(0), json={**proposal, 'request_id': str(uuid4())}).status_code, 409)
            with self.connect('postgres') as db:
                db.execute('UPDATE bri.auth_sessions SET revoked_at=clock_timestamp() WHERE session_id=%s',
                           (self.actors[reviewer][2],))
            self.assertEqual(api.post(decision_url, headers=actor(reviewer), json=decision).status_code, 404)

    def test_catalogue_admin_and_exact_selection_are_independent(self):
        from bri.api.knowledge_metadata import create_staged_metadata_catalogue_app

        role = 'bri_classification_catalogue'
        identity = 'text,uuid,uuid,uuid,text'
        with self.connect('postgres') as db:
            db.execute(f'CREATE ROLE {role} LOGIN NOINHERIT NOBYPASSRLS; GRANT USAGE ON SCHEMA bri TO {role}')
            for name, extra in {'list': ',text,text', 'seed': '', 'create': ',text,text,text,text',
                                'rename': ',text,text', 'describe': ',text,text', 'retire': ',text'}.items():
                db.execute(f'GRANT EXECUTE ON FUNCTION bri.classification_catalogue_{name}({identity}{extra}) TO {role}')
        manager = self.extra_actor()
        self.grant(manager, 'classification:catalogue:manage', 'root')
        actor, transport = self.credentials()
        catalogue = create_staged_metadata_catalogue_app(identity_scope=lambda: self.connect('bri_app'),
            catalogue_scope=lambda: self.connect(role), private_socket=self.sock, auth_transport=transport)
        with self.loopback_reader(catalogue) as api:
            path = BASE + '/catalogue'
            admin, selection = path + '/admin', path + '/selection/xlsx_submit/team'
            self.assertEqual(api.get(admin).status_code, 401)
            self.assertEqual(api.get(admin, headers=actor(2)).status_code, 403)
            self.assertEqual(api.get(selection, headers=actor(manager)).status_code, 403)
            self.assertEqual(api.get(selection, headers=actor(2)).json(), [])
            self.assertEqual(api.post(admin + '/seed', headers=actor(manager), json={}).status_code, 204)
            self.assertEqual(api.post(admin + '/create', headers=actor(manager), json={'category_id': 'general',
                'classification_id': 'test', 'label': 'Fixture', 'description': None}).status_code, 204)
            self.assertEqual(api.post(admin + '/describe', headers=actor(manager), json={'classification_id': 'test',
                'description': ''}).status_code, 204)
            self.assertEqual(api.post(admin + '/retire', headers=actor(manager), json={'classification_id': 'test'}).status_code, 204)
            self.assertNotIn('test', {row['classification_id'] for row in api.get(selection, headers=actor(2)).json()})
            self.assertIn({'category_id': 'general', 'category_label': 'General', 'classification_id': 'test',
                'label': 'Fixture', 'description': '', 'retired': True}, api.get(admin, headers=actor(manager)).json())
