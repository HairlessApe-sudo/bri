"""Table manifest for the repository's additive, schema-qualified table DDL."""
import re


def declared_tables(files):
    # Current migrations declare permanent tables literally on their own line.
    # Renames/drops need an explicit manifest update, not a looser live assertion.
    tables = set()
    create = re.compile(r'^\s*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?bri\.([a-z_][a-z0-9_]*)\s*\(', re.IGNORECASE | re.MULTILINE)
    for path in files:
        text = path.read_text(encoding='utf-8')
        if re.search(r'^\s*(?:DROP\s+TABLE\b|ALTER\s+TABLE\s+bri\.\w+\s+RENAME\s+TO\b)', text, re.IGNORECASE | re.MULTILINE):
            raise ValueError('explicit catalog manifest support required for table drop or rename')
        tables.update(name.lower() for name in create.findall(text))
    tables.remove('schema_migrations')
    return tables


XLSX_TABLES = frozenset({
    'xlsx_worker_creators', 'xlsx_jobs', 'xlsx_sources', 'xlsx_source_versions',
    'xlsx_extractions', 'xlsx_pending_proposals', 'xlsx_audit_events',
    'xlsx_review_decisions', 'xlsx_validated_knowledge', 'xlsx_publication_events',
    'xlsx_record_access', 'xlsx_version_access', 'xlsx_governance_audit_events',
})

XLSX_GOVERNANCE_ROUTINES = {
    'bri_xlsx_reviewer': {
        'xlsx_review_queue': 'uuid,integer',
        'xlsx_review_detail': 'uuid',
        'xlsx_review_decide': 'uuid,text,uuid,uuid',
    },
    'bri_xlsx_publication_maintainer': {'xlsx_publication_change': 'uuid,uuid,text,uuid'},
    'bri_xlsx_access_maintainer': {
        'xlsx_record_access_change': 'uuid,uuid,boolean,uuid',
        'xlsx_version_access_change': 'uuid,uuid,uuid,boolean,uuid',
    },
    'bri_xlsx_reader': {'xlsx_published_detail': 'uuid', 'xlsx_published_evidence': 'uuid,uuid'},
}
XLSX_STAGE_ROLES = frozenset({'bri_xlsx_submitter', 'bri_xlsx_worker', *XLSX_GOVERNANCE_ROUTINES})


def verify_xlsx_catalog(db):
    tables = db.execute(
        "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity, pg_get_userbyid(c.relowner), "
        "has_table_privilege('bri_app', c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'), "
        "EXISTS (SELECT FROM aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee<>c.relowner) "
        "FROM pg_class c WHERE c.relnamespace='bri'::regnamespace AND c.relkind='r' AND left(c.relname,5)='xlsx_'"
    ).fetchall()
    if {r[0] for r in tables} != XLSX_TABLES or any(r[1:] != (True, True, 'bri_migrator', False, False) for r in tables):
        raise RuntimeError('unexpected release XLSX table catalog or grants')
    roles = db.execute('SELECT rolname FROM pg_roles WHERE rolname=ANY(%s)', (sorted(XLSX_STAGE_ROLES),)).fetchall()
    if roles:
        raise RuntimeError('XLSX stage roles must not exist in the release migration catalog')
    routines = db.execute(
        "SELECT p.proname, p.prosecdef, p.proconfig, pg_get_userbyid(p.proowner), "
        "has_function_privilege('bri_app',p.oid,'EXECUTE'), "
        "EXISTS (SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee<>p.proowner) "
        "FROM pg_proc p WHERE p.pronamespace='bri'::regnamespace AND left(p.proname,5)='xlsx_'"
    ).fetchall()
    if any(r[2:] != (['search_path=pg_catalog, pg_temp'], 'bri_migrator', False, False) for r in routines):
        raise RuntimeError('unsafe release XLSX routine configuration or grants')
    entry_points = {'xlsx_submit', 'xlsx_mark_ready', 'xlsx_status', 'xlsx_claim', 'xlsx_complete', 'xlsx_fail'}
    entry_points.update(name for routines in XLSX_GOVERNANCE_ROUTINES.values() for name in routines)
    if sorted(r[0] for r in routines if r[1]) != sorted(entry_points):
        raise RuntimeError('unexpected release XLSX definer entry points')
