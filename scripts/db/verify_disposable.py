"""Run the worktree migrations and backend suites; never accept a database URL.

See scripts/db/disposable/README.md. Requires a local Docker Engine, cached
postgres:16, Python 3.11+ and the project's Python requirements.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from collections import Counter
from contextlib import ExitStack, contextmanager, redirect_stdout
from hashlib import sha256
from io import StringIO
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SOCKET = 'unix:///var/run/docker.sock'
PIPE = 'npipe:////./pipe/dockerDesktopLinuxEngine'
NATIVE = {'test_security_lifecycle_postgres', 'test_provider_security_events_postgres',
          'test_privileged_approvals_pg', 'test_approval_routes', 'test_reenrollment_pg',
          'test_user_directory_postgres', 'test_user_provisioning_postgres', 'test_user_provisioning_api',
          'test_user_lifecycle_postgres', 'test_user_lifecycle_api', 'test_knowledge_authorization_postgres',
          'test_permission_delegation_postgres', 'test_user_delegation_api',
          'test_user_deactivation_postgres', 'test_user_deactivation_api',
          'test_account_history_postgres', 'test_account_history_api',
          'test_account_current_grants_postgres', 'test_account_current_grants_api',
          'test_mfa_reset_administration_postgres'}
GOV = 'test_client_governance_pg'


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def engine(host):
    require(host in {None, '', SOCKET, PIPE}, 'nonlocal or unsupported Docker endpoint')
    if host in {None, '', SOCKET} and Path('/var/run/docker.sock').is_socket() and shutil.which('docker'):
        return [shutil.which('docker'), '--host', SOCKET]
    require(host != SOCKET and shutil.which('docker.exe'), 'no local Docker endpoint available')
    return [shutil.which('docker.exe'), '--host', PIPE]


def run_cli(cmd, **kw):
    # Never propagate subprocess output on failure (bootstrap credentials).
    p = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=60, **kw)
    require(p.returncode == 0, f'local command failed ({Path(cmd[0]).name} {cmd[1]})')
    return p.stdout.strip()


def guard(mapping, opener):
    def connect(dsn='', **kw):
        require(isinstance(dsn, str) and dsn in mapping and not set(kw) - {'autocommit','connect_timeout','sslmode'}
                and kw.get('sslmode', 'require') == 'require', 'unrecognized database connection')
        return opener(mapping[dsn], autocommit=kw.get('autocommit', False))
    return connect


@contextmanager
def database(docker):
    import psycopg
    from psycopg import sql

    def cli(*cmd, **kw):
        return run_cli(docker + list(cmd), **kw)

    tag = secrets.token_hex(10)
    name, db = 'bri-verify-' + tag, 'verify_' + tag
    label = 'bri.disposable=' + tag
    passwords = {r: secrets.token_hex(32) for r in ('postgres','bri_migrator','bri_app')}
    image = cli('image','inspect','--format','{{.Id}}','postgres:16')
    # Only IDs returned by our create calls can be removed, never names or a prune.
    def cleanup(kind, rid):
        require(re.fullmatch('[0-9a-f]{64}', rid), 'invalid resource ID')
        prop = '.Config.Labels' if kind == 'container' else '.Labels'
        actual = cli(kind, 'inspect', '-f', '{{index '+prop+' "bri.disposable"}}',rid)
        require(actual == tag, 'refusing cleanup: label mismatch')
        cli(kind, 'rm', *(['-f'] if kind == 'container' else []), rid)
        require(not cli(kind,'ls',*(['-a'] if kind == 'container' else []),'--no-trunc','--filter','id='+rid,'-q'),
                'resource removal not verified')
        print('removed', kind, rid[:12], flush=True)

    with ExitStack() as stack:
        net = cli('network','create','--label',label,name)
        stack.callback(cleanup, 'network', net)
        cid = cli('container','create','--pull=never','--name',name,'--label',label,'--network',net,
                  '--tmpfs','/var/lib/postgresql/data:rw,size=384m','-p','127.0.0.1::5432',
                  '-e','POSTGRES_PASSWORD','-e','POSTGRES_DB='+db, image,
                  env={**os.environ, 'POSTGRES_PASSWORD':passwords['postgres'], 'WSLENV':'POSTGRES_PASSWORD'})
        stack.callback(cleanup, 'container', cid)
        cli('container','start',cid)
        def inspect(fmt):
            return json.loads(cli('container','inspect','-f','{{json '+fmt+'}}',cid))
        ports = inspect('.NetworkSettings.Ports')
        require(set(ports)=={'5432/tcp'} and len(ports['5432/tcp'])==1, 'ambiguous port mapping')
        bind = ports['5432/tcp'][0]
        require(bind['HostIp']=='127.0.0.1' and bind['HostPort'].isdigit(), 'non-loopback port')
        require(not inspect('.Mounts') and set(inspect('.HostConfig.Tmpfs'))=={'/var/lib/postgresql/data'}
                and set(inspect('.NetworkSettings.Networks'))=={name}
                and set(json.loads(cli('network','inspect','-f','{{json .Containers}}',net)))=={cid}, 'unexpected mounts/network')
        port = int(bind['HostPort'])
        real = psycopg.connect
        def open_database(dbname, role, **kw):
            return real(host='127.0.0.1',hostaddr='127.0.0.1',port=port,dbname=dbname,user=role,
                        password=passwords[role],passfile=os.devnull,sslmode='disable',gssencmode='disable',connect_timeout=3,**kw)
        def open_local(role, **kw):
            return open_database(db, role, **kw)

        @contextmanager
        def fresh_database():
            # Only the private container's maintenance DB and our migrated DB
            # may participate. The test never supplies a host or database name.
            child = 'case_' + secrets.token_hex(12)
            ident = sql.Identifier(child)
            with open_database('postgres', 'postgres', autocommit=True) as ctl:
                ctl.execute(sql.SQL('CREATE DATABASE {} TEMPLATE {}').format(ident, sql.Identifier(db)))
                try:
                    ctl.execute(sql.SQL('REVOKE ALL ON DATABASE {} FROM PUBLIC').format(ident))
                    ctl.execute(sql.SQL('GRANT CONNECT ON DATABASE {} TO bri_app').format(ident))
                    def connect(role):
                        require(role in {'bri_app', 'postgres'}, 'unexpected fixture role')
                        return open_database(child, role)
                    with connect('bri_app') as probe:
                        require(probe.execute('SELECT current_database(), session_user, current_user').fetchone()
                                == (child, 'bri_app', 'bri_app'), 'wrong fixture identity')
                    yield connect
                finally:
                    # A leaked connection fails teardown; no FORCE or global cleanup.
                    ctl.execute(sql.SQL('DROP DATABASE {}').format(ident))
                    require(not ctl.execute('SELECT 1 FROM pg_database WHERE datname=%s', (child,)).fetchone(),
                            'private test database still present')
                    print('removed per-test database', child, flush=True)

        for _ in range(100):
            try:
                admin = open_local('postgres'); break
            except psycopg.OperationalError:
                time.sleep(.2)
        else:
            raise RuntimeError('new PostgreSQL did not become ready')
        with admin:
            require(admin.execute("SELECT current_database(),current_user,current_setting('server_version_num')::int/10000,to_regnamespace('bri')").fetchone()
                    == (db,'postgres',16,None), 'unexpected cluster identity, version or initial schema')
            for role, limit in [('bri_app',10),('bri_migrator',2)]:
                admin.execute(sql.SQL('CREATE ROLE {} LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION CONNECTION LIMIT {} PASSWORD {}').format(sql.Identifier(role),sql.Literal(limit),sql.Literal(passwords[role])))
            admin.execute(sql.SQL('REVOKE ALL ON DATABASE {} FROM PUBLIC; GRANT CONNECT ON DATABASE {} TO bri_app,bri_migrator').format(sql.Identifier(db),sql.Identifier(db)))
            admin.execute('REVOKE ALL ON SCHEMA public FROM PUBLIC; CREATE SCHEMA bri AUTHORIZATION bri_migrator')
        print(f'{name} PostgreSQL 16 at 127.0.0.1:{port}; private network; tmpfs', flush=True)
        yield open_local, fresh_database


def migrations(files, config, opener):
    import psycopg

    from scripts.db import migrate
    def apply(directory, expected):
        adapter = guard({config['BRI_MIGRATION_ROLE_DATABASE_URL']:'bri_migrator'}, opener)
        with patch.object(migrate,'env_values',return_value=config), patch.object(migrate,'ROOT',directory), \
             patch.object(psycopg,'connect',adapter), redirect_stdout(StringIO()) as log:
            rc = migrate.main()
        print(log.getvalue().rstrip())
        require(rc == 0 and f'applied_count={expected}' in log.getvalue().splitlines(), 'migration runner failed')
    with tempfile.TemporaryDirectory() as tmp:
        sub = Path(tmp)/'db/migrations'; sub.mkdir(parents=True)
        for f in files[:5]: shutil.copyfile(f, sub/f.name)
        apply(Path(tmp), 5)
    with opener('postgres') as c:
        c.execute("INSERT INTO bri.tenants(tenant_id,display_name,sector) VALUES ('verify-backfill','Synthetic','test')")
    apply(ROOT,len(files)-5)
    def ledger():
        with opener('bri_migrator') as c:
            migrate.verify_ledger(c,files)
            return c.execute('SELECT version,checksum,applied_at FROM bri.schema_migrations ORDER BY version').fetchall()
    rows = ledger(); require([r[0] for r in rows] == [f.stem for f in files], 'ledger versions differ')
    apply(ROOT,0); require(ledger()==rows,'ledger changed during replay')
    with opener('postgres') as c:
        require(c.execute("SELECT count(*) FROM bri.tenant_admin_policies WHERE tenant_id='verify-backfill'").fetchone()==(1,), 'backfill missing')
        require(not c.execute("SELECT 1 FROM pg_policies WHERE schemaname='bri' AND policyname='migration_seed_tenant_admin_policies'").fetchone(),'temporary policy still present')
        require(not c.execute("SELECT 1 FROM pg_constraint WHERE connamespace='bri'::regnamespace AND NOT convalidated").fetchone(),'unvalidated constraint')
    with opener('bri_app') as c:
        catalog = c.execute("SELECT relname,relrowsecurity,relforcerowsecurity,pg_get_userbyid(relowner) FROM pg_class WHERE relnamespace='bri'::regnamespace AND relkind='r' AND relname<>'schema_migrations'").fetchall()
        from scripts.db.disposable.catalog import declared_tables
        require({row[0] for row in catalog} == declared_tables(files), 'catalog differs from migration table declarations')
        require(catalog and all(row[1:]==(True,True,'bri_migrator') for row in catalog),'unexpected RLS, FORCE or owner')
        print(f'PASS catalog as bri_app: {len(catalog)} non-ledger tables, all FORCE RLS and migrator-owned')
    print(f'PASS {len(rows)} ledger entries, all checksums, unchanged replay, backfill and constraint checks')


class Results(unittest.TestResult):
    """Count successful methods separately from subtest/tearDown errors."""
    def __init__(self):
        super().__init__()
        self.passed = 0

    def addSuccess(self, test):
        self.passed += 1
        super().addSuccess(test)

    def _exc_info_to_string(self, err, test):
        import traceback
        kind, exc, tb = err
        frames = traceback.extract_tb(tb)[-8:]
        details = [kind.__name__]
        if getattr(getattr(exc, "diag", None), "message_primary", None) == "role changes require read committed isolation":
            details.append("role changes require read committed isolation")
        # Restrict PostgreSQL diagnostics to identifiers, never SQL/row values.
        for attr in ('sqlstate', 'table_name', 'constraint_name'):
            value = getattr(getattr(exc, 'diag', None), attr, None)
            if isinstance(value, str) and re.fullmatch(r'[\w]{1,80}', value):
                details.append(value)
        if isinstance(exc, AttributeError) and isinstance(exc.name, str) and exc.name.isidentifier():
            details.append(exc.name)
        return ' '.join(details) + ' at ' + ' -> '.join(f'{Path(f.filename).name}:{f.lineno}' for f in frames)


def suite_run(pg_bin, core_env, adapter, fresh_database, *, fixture_suites=False):
    import psycopg
    stats = Counter()
    # Discover each module once, under its own opt-ins. Never give independent
    # cluster suites the loopback app or admin configuration of the core tests.
    for path in sorted((ROOT/'tests').glob('test_*.py')):
        mod = path.stem
        if fixture_suites and mod not in {'test_database_rls', 'test_durable_repository_integration'}:
            continue
        with ExitStack() as stack:
            if mod in NATIVE:
                env = {'BRI_TEST_PG_BIN':str(pg_bin), 'BRI_APPROVAL_PG_BIN':str(pg_bin)} if pg_bin else {}
            elif mod == GOV:
                env = {'BRI_RUN_GOVERNANCE_PG':'1'}
            else:
                env = core_env
                stack.enter_context(patch.object(psycopg,'connect',adapter))
            stack.enter_context(patch.dict(os.environ,env))
            suite = unittest.defaultTestLoader.loadTestsFromName(mod)
            if mod=='test_durable_repository_integration' and mod in sys.modules:
                cls = sys.modules[mod].DurableRepositoryIntegrationTests
                stack.enter_context(patch.object(cls, 'fresh_database', staticmethod(fresh_database)))
            if mod=='test_database_rls' and mod in sys.modules:
                fixture = sys.modules[mod]
                connect = stack.enter_context(fresh_database())
                from scripts.db.seed_synthetic_data import insert_or_verify
                require(fixture.FIXTURE.get('synthetic_only') is True, 'expected synthetic RLS fixture')
                with connect('postgres') as c:
                    c.execute('SET TRANSACTION ISOLATION LEVEL READ COMMITTED')
                    def ensure(table, columns, values, keys):
                        insert_or_verify(c, table=table, columns=columns, values=values, key_columns=keys)
                    for tenant in fixture.FIXTURE['tenants']:
                        c.execute("SELECT set_config('bri.tenant_id',%s,true)", (tenant['tenant_id'],))
                        fixture.ensure_role_catalog(tenant, ensure)
                # Only the verifier's clone persists this role catalog. The actual
                # tests retain their original role, SERIALIZABLE txn and rollback.
                def rls_open(role, *, autocommit=False, connect=connect):
                    require(role=='bri_app' and not autocommit, 'unexpected RLS connection')
                    return connect(role)
                guarded = guard({core_env['DATABASE_URL']:'bri_app'}, rls_open)
                stack.enter_context(patch.object(psycopg, 'connect', guarded))
                stack.enter_context(patch.object(fixture,'_local_env',return_value=core_env))
            result = Results(); suite.run(result)
            # setUpClass, teardown and subtest errors are not distinct test methods.
            stats.update(run=result.testsRun, passed=result.passed, failures=len(result.failures), errors=len(result.errors), skipped=len(result.skipped))
            print(f'{mod}: ran={result.testsRun} passed={result.passed} failed={len(result.failures)} errors={len(result.errors)} skipped={len(result.skipped)}',flush=True)
            for reason, count in Counter(reason for _,reason in result.skipped).items(): print(f'  SKIP {count}: {reason}')
            for test, diagnostic in result.failures + result.errors:
                print(f'  FAIL {test.id().split(" (")[0]}: {diagnostic}')
    print('TOTAL', dict(stats), flush=True)
    return 1 if stats['errors'] or stats['failures'] else (2 if stats['skipped'] else 0)


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('--pg-bin',type=Path,help='trusted local PostgreSQL 16 bin directory for private-cluster suites')
    ap.add_argument('--fixture-suites', action='store_true', help='run only tenant RLS and durable repository suites')
    args=ap.parse_args()
    require(not sys.flags.optimize,'optimized Python disables assertions in repository tests')
    docker = engine(os.getenv('DOCKER_HOST'))
    tempbase = tempfile.gettempdir()
    pg_bin = (args.pg_bin or Path('/usr/lib/postgresql/16/bin')).resolve()
    with tempfile.TemporaryDirectory(dir=tempbase,prefix='bri-v-') as tmp:
        safe_env = {'PATH':str(Path(docker[0]).parent)+os.pathsep+os.defpath,'HOME':tmp,'DOCKER_CONFIG':tmp,'LC_ALL':'C.UTF-8',
                    'TMPDIR':tmp,'PYTHON_DOTENV_DISABLED':'1'}
        if 'WSL_INTEROP' in os.environ: safe_env['WSL_INTEROP']=os.environ['WSL_INTEROP']
        with patch.dict(os.environ,safe_env,clear=True):
            tempfile.tempdir=tmp
            if not all((pg_bin/k).is_file() for k in ('postgres','pg_ctl','initdb')):
                require(args.pg_bin is None,'specified local pg-bin is incomplete'); pg_bin=None
            elif ' 16.' not in run_cli([str(pg_bin/'postgres'),'--version']):
                raise RuntimeError('native opt-ins require PostgreSQL 16')
            def no_dotenv(event, a):
                if event=='open' and isinstance(a[0],(str,bytes)) and Path(os.fsdecode(a[0])).name=='.env.local':
                    raise PermissionError('local dotenv is prohibited')
                if event in ('socket.connect','socket.getaddrinfo'):
                    peer=a[1] if event=='socket.connect' else (a[0],)
                    if isinstance(peer,tuple) and peer[0] not in ('127.0.0.1','::1','localhost',None):
                        raise PermissionError('nonlocal networking prohibited')
            sys.addaudithook(no_dotenv); sys.path[:0]=[str(ROOT),str(ROOT/'src'),str(ROOT/'tests')]; os.chdir(ROOT)
            from scripts.db import migrate
            files=sorted((ROOT/'db/migrations').glob('*.sql'))
            require(len(files)>=11 and [f.name[:5] for f in files]==[f'{i:04}_' for i in range(1,len(files)+1)],'expected consecutive migrations through at least 0011')
            snapshot={f:sha256(f.read_bytes()).digest() for f in files}
            token=lambda role:f'postgresql://{role}@db.{migrate.EXPECTED_REF}.supabase.co:5432/postgres?sslmode=require'
            config={'SUPABASE_URL':f'https://{migrate.EXPECTED_REF}.supabase.co','BRI_ENVIRONMENT':'development','BRI_MIGRATION_ROLE_DATABASE_URL':token('bri_migrator')}
            with database(docker) as (opener,fresh_database):
                migrations(files,config,opener)
                core={k:v for k,v in config.items() if k!='BRI_MIGRATION_ROLE_DATABASE_URL'}
                core.update(BRI_RUN_DB_TESTS='1', BRI_DEV_AUTH_ENABLED='true',BRI_AUTH_MODE='synthetic',DATABASE_URL=token('bri_app'))
                adapter=guard({token('bri_app'):'bri_app'},opener)
                rc=suite_run(pg_bin,core,adapter,fresh_database,fixture_suites=args.fixture_suites)
                require(snapshot=={f:sha256(f.read_bytes()).digest() for f in (ROOT/'db/migrations').glob('*.sql')},'migration files changed during validation')
                return rc


if __name__=='__main__':
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    try: sys.exit(main())
    except RuntimeError as exc: sys.exit(str(exc))
