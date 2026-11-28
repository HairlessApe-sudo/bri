"""Only synthetic A19.2 fixture prerequisites and independent read-back."""
from hashlib import sha256
from unittest.mock import patch
from uuid import uuid4

import a19_1_fixture as prior
from a13_demo import require
from a18_2_demo import Gate
from a18_3_fixture import _csv_bytes, _xlsx_bytes
from a19_1_fixture import CLASS, metadata, pending_state

API = '/v1/knowledge-administration'
FORMATS = ('csv', 'xlsx')
# Set this only from the qualified staged backend interface, not from the UI.
DISPATCH = 'fixture'
PRIMARY = CLASS


def setup(args, scratch, stack, *, enabled):
    # Reuse the signed A19.1 disposable assembly without changing that harness.
    # The scoped factory adapters configure real product apps, not responses.
    import sys
    from a13_demo import ROOT

    sys.path[:0] = [str(ROOT), str(ROOT / 'src'), str(ROOT / 'tests')]
    from bri.api import csv_intake, xlsx_intake, knowledge_metadata

    gates = {}

    def observe(name, application):
        # Preserve the real ASGI app and place a one-request delay outside its
        # protected handler. State and app lifespan are still the originals.
        gate = gates[name] = Gate(application)
        return gate

    def configure(name, factory):
        def build(**kwargs):
            app = factory(**kwargs, enable_knowledge_administration=enabled)
            app.add_middleware(lambda app: observe(name, app))
            return app
        return build

    def catalogue(**kwargs):
        app = catalogue_factory(**kwargs)
        app.add_middleware(lambda app: observe('catalogue', app))
        return app

    def provision(fixture, issuer, scopes):
        tenant, foreign, actors = provision_prior(fixture, issuer, scopes)
        principal, user, _ = actors['other_owner'] = uuid4(), uuid4(), uuid4()
        with fixture.connect('postgres') as db:
            db.execute("INSERT INTO bri.auth_principals VALUES (%s,'active')", (principal,))
            db.execute("INSERT INTO bri.auth_identity_links(auth_user_id,principal_id,auth_issuer,auth_subject,"
                       "provider_type,provider_issuer,provider_subject) VALUES (%s,%s,%s,%s,'native',%s,%s)",
                       (user, principal, issuer, str(user), issuer, str(user)))
            db.execute("INSERT INTO bri.auth_tenant_memberships(tenant_id,principal_id,membership_type,status) "
                       "VALUES (%s,%s,'user','active')", (tenant, principal))
            db.execute("INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id) "
                       "VALUES (%s,%s,'source:submit',%s)", (tenant, principal, scopes['social']))
        return tenant, foreign, actors

    provision_prior = prior._provision
    catalogue_factory = knowledge_metadata.create_staged_metadata_catalogue_app
    if enabled:
        with (patch.object(prior, '_provision', provision),
              patch.object(csv_intake, 'create_staged_csv_intake_app',
                           configure('csv', csv_intake.create_staged_csv_intake_app)),
              patch.object(xlsx_intake, 'create_staged_xlsx_intake_app',
                           configure('xlsx', xlsx_intake.create_staged_xlsx_intake_app)),
              patch.object(knowledge_metadata, 'create_staged_metadata_catalogue_app', catalogue)):
            data = prior.setup(args, scratch, stack, metadata_enabled=True, legacy_baseline=False)
    else:
        data = prior.setup(args, scratch, stack, metadata_enabled=False, legacy_baseline=False)
    return data | {'gates': gates}


def originals(scratch):
    inputs = {}
    for fmt in FORMATS:
        marker = f'Bounded {fmt.upper()} hearing timetable'
        raw = _csv_bytes(marker, 'Synthetic administrative submission') if fmt == 'csv' else _xlsx_bytes(marker)
        file = scratch / f'synthetic-hearing-timetable.{fmt}'
        file.write_bytes(raw)
        inputs[fmt] = dict(marker=marker, raw=raw, file=file, metadata=metadata(f'Proposed {fmt.upper()} timetable', PRIMARY))
    # A filename accepted by the selector is not proof of native format.
    bad = scratch / 'mislabeled-workbook.xlsx'
    bad.write_bytes(inputs['csv']['raw'])
    return inputs, bad


def job_rows(data):
    """Snapshot both job tables, across all tenants, without exposing their contents."""
    fixture = data['fixture']
    with fixture.connect('postgres') as db:
        return {fmt: db.execute(f'SELECT tenant_id,job_id,state,original_sha256 FROM bri.{fmt}_jobs '
                                'ORDER BY tenant_id,job_id').fetchall() for fmt in FORMATS}


def assert_job(data, fmt, job, raw, state, *, who='submitter'):
    fixture = data['fixture']
    with fixture.connect('postgres') as db:
        rows = db.execute(f'SELECT state,original_sha256,byte_count,scope_node_id,actor_id,attempt FROM bri.{fmt}_jobs '
                          'WHERE (tenant_id,job_id)=(%s,%s)', (fixture.tenant, job)).fetchall()
        require(rows == [(state, sha256(raw).hexdigest(), len(raw), data['scopes']['social'],
                          data['actors'][who][0], 0 if state == 'ready' else 1)],
                f'{fmt} committed job state, bytes, authority, or worker attempt mismatch')
        require(db.execute('SELECT count(*) FROM bri.knowledge_metadata_initial '
                           'WHERE (tenant_id,format,job_id)=(%s,%s,%s)', (fixture.tenant, fmt, job)).fetchone() == (1,),
                f'{fmt} did not persist exactly one classified proposal')


def process_fixture_job(data, fmt, job):
    """Separate qualified worker authority; there is no browser worker call."""
    from bri.ingestion.csv_intake import ProcessOutcome

    if fmt == 'csv':
        require(data['csv_stage'].state.csv_worker.dispatch(job) is ProcessOutcome.COMPLETED,
                'Fixture CSV worker did not complete')
    else:
        require(data['xlsx_stage'].state.xlsx_worker.dispatch(job, uuid4()) == 'completed',
                'Fixture XLSX worker did not complete')
    pending_state(data, fmt, job, classified=True)


def drop_submit(data, *, who='submitter'):
    """Remove only the uploader's live submit grant at the exact node."""
    fixture = data['fixture']
    with fixture.connect('postgres') as db:
        require(db.execute("DELETE FROM bri.auth_role_assignments WHERE tenant_id=%s AND principal_id=%s "
                           "AND scope_node_id=%s AND role_id='source:submit'",
                           (fixture.tenant, data['actors'][who][0], data['scopes']['social'])).rowcount == 1,
                'Fixture exact-node grant removal did not commit')
