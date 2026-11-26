-- Local synthetic stage only: no role creation, grants to stage roles, seed data,
-- or writes to existing ingestion/governance tables. No review or publish path.
CREATE TABLE bri.xlsx_worker_creators (
    tenant_id text PRIMARY KEY,
    creator_id uuid NOT NULL,
    FOREIGN KEY (tenant_id,creator_id) REFERENCES bri.auth_tenant_memberships (tenant_id,principal_id)
);

CREATE TABLE bri.xlsx_jobs (
    tenant_id text NOT NULL,
    job_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    artifact_key uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    scope_node_id text NOT NULL,
    actor_id uuid NOT NULL,
    creator_id uuid NOT NULL,
    auth_user_id uuid NOT NULL,
    session_id uuid NOT NULL,
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 512),
    request_key uuid NOT NULL,
    original_sha256 text NOT NULL CHECK (original_sha256 ~ '^[0-9a-f]{64}$'),
    byte_count integer NOT NULL CHECK (byte_count BETWEEN 1 AND 5000000),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    state text NOT NULL DEFAULT 'creating' CHECK (state IN ('creating','ready','processing','proposed','failed')),
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 3),
    lease_until timestamptz,
    available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    reason text CHECK (reason IN ('unsupported_workbook','resource_limit','integrity_failure','processing_failed',
                                  'infrastructure_unavailable','authority_lost','lease_expired')),
    PRIMARY KEY (tenant_id,job_id),
    UNIQUE (tenant_id,actor_id,request_key),
    UNIQUE (tenant_id,job_id,scope_node_id,creator_id),
    UNIQUE (tenant_id,job_id,original_sha256),
    FOREIGN KEY (tenant_id,scope_node_id) REFERENCES bri.org_nodes (tenant_id,node_id),
    FOREIGN KEY (tenant_id,actor_id) REFERENCES bri.auth_tenant_memberships (tenant_id,principal_id),
    FOREIGN KEY (tenant_id,creator_id) REFERENCES bri.auth_tenant_memberships (tenant_id,principal_id),
    FOREIGN KEY (auth_user_id,actor_id) REFERENCES bri.auth_identity_links (auth_user_id,principal_id),
    CHECK (actor_id <> creator_id),
    CHECK ((state='processing') = (lease_until IS NOT NULL)),
    CHECK (state NOT IN ('processing','proposed') OR attempt > 0),
    CHECK (state <> 'failed' OR reason IS NOT NULL)
);

-- Initial source, version, extraction and proposal share the job UUID, but
-- have distinct tenant-qualified keys and cannot be linked across jobs.
CREATE TABLE bri.xlsx_sources (
    tenant_id text NOT NULL,
    job_id uuid NOT NULL,
    scope_node_id text NOT NULL,
    creator_id uuid NOT NULL,
    PRIMARY KEY (tenant_id,job_id),
    FOREIGN KEY (tenant_id,job_id,scope_node_id,creator_id)
        REFERENCES bri.xlsx_jobs (tenant_id,job_id,scope_node_id,creator_id)
);

CREATE TABLE bri.xlsx_source_versions (
    tenant_id text NOT NULL,
    job_id uuid NOT NULL,
    original_sha256 text NOT NULL,
    canonical_sha256 text NOT NULL CHECK (canonical_sha256 ~ '^[0-9a-f]{64}$'),
    sheet_id text NOT NULL CHECK (sheet_id ~ '^[1-9][0-9]{0,9}$'),
    sheet_title text NOT NULL CHECK (length(sheet_title) BETWEEN 1 AND 31),
    cell_range text NOT NULL CHECK (cell_range ~ '^A1(:[A-Z]{1,2}[1-9][0-9]{0,4})?$'),
    PRIMARY KEY (tenant_id,job_id),
    UNIQUE (tenant_id,job_id,canonical_sha256),
    FOREIGN KEY (tenant_id,job_id) REFERENCES bri.xlsx_sources (tenant_id,job_id),
    FOREIGN KEY (tenant_id,job_id,original_sha256) REFERENCES bri.xlsx_jobs (tenant_id,job_id,original_sha256)
);

CREATE TABLE bri.xlsx_extractions (
    tenant_id text NOT NULL,
    job_id uuid NOT NULL,
    canonical_text text NOT NULL CHECK (octet_length(canonical_text) BETWEEN 1 AND 2097152),
    canonical_sha256 text NOT NULL,
    extractor_version integer NOT NULL CHECK (extractor_version = 1),
    canonicalization_version integer NOT NULL CHECK (canonicalization_version = 1),
    PRIMARY KEY (tenant_id,job_id),
    FOREIGN KEY (tenant_id,job_id,canonical_sha256)
        REFERENCES bri.xlsx_source_versions (tenant_id,job_id,canonical_sha256),
    CHECK (encode(sha256(convert_to(canonical_text,'UTF8')),'hex') = canonical_sha256)
);

CREATE TABLE bri.xlsx_pending_proposals (
    tenant_id text NOT NULL,
    job_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,job_id),
    FOREIGN KEY (tenant_id,job_id) REFERENCES bri.xlsx_extractions (tenant_id,job_id)
);

CREATE TABLE bri.xlsx_audit_events (
    tenant_id text NOT NULL,
    event_id uuid NOT NULL DEFAULT gen_random_uuid(),
    job_id uuid NOT NULL,
    actor_id uuid,
    correlation uuid NOT NULL,
    event text NOT NULL CHECK (event IN ('submitted','ready','claimed','retry','lease_expired','proposed','failed')),
    attempt integer NOT NULL CHECK (attempt BETWEEN 0 AND 3),
    reason text CHECK (reason IN ('unsupported_workbook','resource_limit','integrity_failure','processing_failed',
                                  'infrastructure_unavailable','authority_lost','lease_expired')),
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,event_id),
    FOREIGN KEY (tenant_id,job_id) REFERENCES bri.xlsx_jobs (tenant_id,job_id),
    FOREIGN KEY (tenant_id,actor_id) REFERENCES bri.auth_tenant_memberships (tenant_id,principal_id)
);
CREATE INDEX xlsx_audit_job_idx ON bri.xlsx_audit_events (tenant_id,job_id,occurred_at);

CREATE FUNCTION bri.xlsx_immutable() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'XLSX provenance is immutable' USING ERRCODE = '42501';
END $$;

DO $xlsx$
DECLARE rel text;
BEGIN
    FOREACH rel IN ARRAY ARRAY['xlsx_worker_creators','xlsx_jobs','xlsx_sources','xlsx_source_versions',
                               'xlsx_extractions','xlsx_pending_proposals','xlsx_audit_events'] LOOP
        EXECUTE format('ALTER TABLE bri.%I ENABLE ROW LEVEL SECURITY', rel);
        EXECUTE format('ALTER TABLE bri.%I FORCE ROW LEVEL SECURITY', rel);
        EXECUTE format('REVOKE ALL ON bri.%I FROM PUBLIC,bri_app', rel);
        EXECUTE format('CREATE POLICY xlsx_owner_read ON bri.%I FOR SELECT TO bri_migrator USING (true)', rel);
        IF rel NOT IN ('xlsx_worker_creators','xlsx_jobs') THEN
            EXECUTE format('CREATE TRIGGER xlsx_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON bri.%I
                            FOR EACH STATEMENT EXECUTE FUNCTION bri.xlsx_immutable()', rel);
        END IF;
        IF rel <> 'xlsx_worker_creators' THEN
            EXECUTE format('CREATE POLICY xlsx_owner_insert ON bri.%I FOR INSERT TO bri_migrator WITH CHECK (true)', rel);
        END IF;
    END LOOP;
END $xlsx$;
CREATE POLICY xlsx_creator_maintenance ON bri.xlsx_worker_creators TO bri_migrator
    USING (session_user='bri_migrator') WITH CHECK (session_user='bri_migrator');
CREATE POLICY xlsx_job_update ON bri.xlsx_jobs FOR UPDATE TO bri_migrator USING (true) WITH CHECK (true);
CREATE TRIGGER xlsx_job_metadata_immutable BEFORE UPDATE OF tenant_id,job_id,artifact_key,scope_node_id,
    actor_id,creator_id,auth_user_id,session_id,issuer,request_key,original_sha256,byte_count,created_at ON bri.xlsx_jobs
    FOR EACH STATEMENT EXECUTE FUNCTION bri.xlsx_immutable();
CREATE TRIGGER xlsx_terminal_immutable BEFORE UPDATE ON bri.xlsx_jobs FOR EACH ROW
    WHEN (OLD.state IN ('proposed','failed')) EXECUTE FUNCTION bri.xlsx_immutable();
CREATE TRIGGER xlsx_jobs_no_remove BEFORE DELETE OR TRUNCATE ON bri.xlsx_jobs
    FOR EACH STATEMENT EXECUTE FUNCTION bri.xlsx_immutable();

-- Explicit issuer visibility for these two private session identities only.
CREATE POLICY xlsx_bound_issuer ON bri.provider_event_source FOR SELECT TO bri_migrator
    USING (session_user IN ('bri_xlsx_submitter','bri_xlsx_worker') AND inet_server_addr() IS NULL);

-- Mirror the A12 source:submit predicates, using explicit verified sub/issuer.
CREATE FUNCTION bri.xlsx_has_authority(t text, actor uuid, sub uuid, sid uuid, issuer text, node text)
RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (SELECT FROM bri.provider_event_source src WHERE src.issuer = $5)
      AND EXISTS (SELECT FROM bri.client_activation a JOIN bri.tenant_admin_policies ap USING (tenant_id)
                  WHERE a.tenant_id=t AND (SELECT count(*) FROM bri.governance_eligible e WHERE e.tenant_id=t)
                        >= ap.min_emergency_admins)
      AND EXISTS (
        SELECT FROM bri.auth_sessions s JOIN bri.auth_identity_links i USING (auth_user_id,principal_id)
        JOIN bri.auth_principals p USING (principal_id) JOIN bri.auth_tenant_memberships m USING (principal_id)
        LEFT JOIN bri.session_guards g USING (principal_id)
        WHERE (s.principal_id,s.auth_user_id,s.session_id,m.tenant_id) = (actor,sub,sid,t)
          AND i.auth_issuer = issuer AND i.auth_subject = sub::text
          AND i.status = 'active' AND i.provider_type = 'native'
          AND s.revoked_at IS NULL AND s.started_at <= clock_timestamp()
          AND clock_timestamp() < least(s.expires_at,s.started_at + interval '8 hours')
          AND s.started_at > coalesce(g.primary_after,'-infinity'::timestamptz)
          AND p.status = 'active' AND p.deletion_requested_at IS NULL AND m.status = 'active'
          AND m.membership_type IN ('user','superuser')
          AND NOT EXISTS (SELECT FROM bri.auth_tenant_memberships x WHERE x.principal_id=actor AND x.tenant_id<>t)
          AND NOT EXISTS (SELECT FROM bri.platform_superadmins x WHERE x.principal_id=actor)
          AND NOT EXISTS (SELECT FROM bri.credential_operations c WHERE c.principal_id=actor AND c.confirmed_at IS NULL)
      ) AND EXISTS (
        SELECT FROM bri.auth_role_assignments a JOIN bri.role_permissions rp USING (tenant_id,role_id)
        WHERE (a.tenant_id,a.principal_id,a.scope_node_id,rp.permission) = (t,actor,node,'source:submit')
          AND a.status = 'active'
      );
$$;

CREATE FUNCTION bri.xlsx_creator_active(t text, creator uuid, issuer text) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (
        SELECT FROM bri.auth_principals p JOIN bri.auth_tenant_memberships m USING (principal_id)
        JOIN bri.auth_identity_links i USING (principal_id)
        WHERE (m.tenant_id,p.principal_id) = ($1,$2) AND i.auth_issuer=$3
          AND i.provider_type='native' AND i.status='active' AND i.auth_subject=i.auth_user_id::text
          AND p.status='active' AND p.deletion_requested_at IS NULL AND m.status='active'
          AND NOT EXISTS (SELECT FROM bri.auth_tenant_memberships x WHERE x.principal_id=$2 AND x.tenant_id<>$1)
          AND NOT EXISTS (SELECT FROM bri.platform_superadmins x WHERE x.principal_id=$2)
    );
$$;

-- Lock the same rows that governance and session writers fence with, without
-- updating or materializing any legacy row. READ COMMITTED is required so a
-- concurrent writer that committed while we waited cannot leave a stale view.
CREATE FUNCTION bri.xlsx_lock_actor(actor uuid, sub uuid, sid uuid) RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'XLSX mutation requires read committed' USING ERRCODE = '25001';
    END IF;
    PERFORM FROM bri.client_governance_fence WHERE id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'XLSX governance fence unavailable'; END IF;
    PERFORM FROM bri.session_guards WHERE principal_id=actor FOR UPDATE;
    PERFORM FROM bri.auth_sessions s WHERE (s.principal_id,s.auth_user_id,s.session_id)=(actor,sub,sid) AND s.revoked_at IS NULL
        FOR UPDATE;
END $$;

CREATE FUNCTION bri.xlsx_require_role(expected text) RETURNS void
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF session_user <> expected OR inet_server_addr() IS NOT NULL THEN
        RAISE EXCEPTION 'XLSX role denied' USING ERRCODE = '42501';
    END IF;
END $$;

CREATE FUNCTION bri.xlsx_receipt(j bri.xlsx_jobs, include_artifact boolean) RETURNS jsonb
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT jsonb_build_object('job_id',j.job_id,'state',j.state,'reason',j.reason)
        || CASE WHEN include_artifact THEN jsonb_build_object('artifact_key',j.artifact_key) ELSE '{}'::jsonb END;
$$;

CREATE FUNCTION bri.xlsx_audit(j bri.xlsx_jobs, event text, correlation uuid, who uuid DEFAULT NULL,
                               why text DEFAULT NULL) RETURNS void
LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$
    INSERT INTO bri.xlsx_audit_events (tenant_id,job_id,actor_id,correlation,event,attempt,reason)
        VALUES (j.tenant_id,j.job_id,who,correlation,event,j.attempt,why);
$$;

CREATE FUNCTION bri.xlsx_submit(t text, actor uuid, sub uuid, sid uuid, issuer text, node text,
                                request_key uuid, byte_count integer, original_sha256 text, correlation uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE j bri.xlsx_jobs; creator uuid;
BEGIN
    PERFORM bri.xlsx_require_role('bri_xlsx_submitter');
    PERFORM bri.xlsx_lock_actor(actor,sub,sid);
    IF NOT bri.xlsx_has_authority(t,actor,sub,sid,issuer,node) THEN
        RAISE EXCEPTION 'XLSX intake denied' USING ERRCODE = '42501';
    END IF;
    IF request_key IS NULL OR correlation IS NULL OR NOT coalesce(original_sha256 ~ '^[0-9a-f]{64}$',false)
       OR NOT coalesce(byte_count BETWEEN 1 AND 5000000,false) THEN
        RAISE EXCEPTION 'invalid XLSX submission metadata' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO j FROM bri.xlsx_jobs x WHERE (x.tenant_id,x.actor_id,x.request_key)=(t,actor,$7);
    IF FOUND THEN
        IF (j.scope_node_id,j.byte_count,j.original_sha256) <> (node,byte_count,original_sha256) THEN
            RAISE EXCEPTION 'XLSX request key conflict' USING ERRCODE = '23505';
        END IF;
    ELSE
        SELECT c.creator_id INTO creator FROM bri.xlsx_worker_creators c WHERE c.tenant_id=t;
        IF creator IS NOT DISTINCT FROM actor OR NOT bri.xlsx_creator_active(t,creator,issuer) THEN
            RAISE EXCEPTION 'XLSX creator binding unavailable' USING ERRCODE = '42501';
        END IF;
        INSERT INTO bri.xlsx_jobs (tenant_id,scope_node_id,actor_id,creator_id,auth_user_id,session_id,issuer,
                                   request_key,byte_count,original_sha256)
            VALUES (t,node,actor,creator,sub,sid,issuer,$7,$8,$9) RETURNING * INTO j;
        PERFORM bri.xlsx_audit(j,'submitted',correlation,actor);
    END IF;
    RETURN bri.xlsx_receipt(j,true);
END $$;

CREATE FUNCTION bri.xlsx_user_job(t text, actor uuid, sub uuid, sid uuid, issuer text, job uuid)
RETURNS bri.xlsx_jobs LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE j bri.xlsx_jobs;
BEGIN
    SELECT * INTO j FROM bri.xlsx_jobs x WHERE (x.tenant_id,x.actor_id,x.job_id,x.issuer)=(t,actor,job,$5);
    IF NOT FOUND OR NOT bri.xlsx_has_authority(t,actor,sub,sid,issuer,j.scope_node_id) THEN
        RAISE EXCEPTION 'XLSX intake denied' USING ERRCODE = '42501';
    END IF;
    RETURN j;
END $$;

CREATE FUNCTION bri.xlsx_mark_ready(t text, actor uuid, sub uuid, sid uuid, issuer text, job uuid, correlation uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE j bri.xlsx_jobs;
BEGIN
    PERFORM bri.xlsx_require_role('bri_xlsx_submitter');
    IF correlation IS NULL THEN RAISE EXCEPTION 'invalid XLSX correlation' USING ERRCODE = '22023'; END IF;
    PERFORM bri.xlsx_lock_actor(actor,sub,sid);
    j := bri.xlsx_user_job(t,actor,sub,sid,issuer,job);
    SELECT * INTO STRICT j FROM bri.xlsx_jobs x WHERE (x.tenant_id,x.job_id)=(t,job) FOR UPDATE;
    IF j.state='creating' THEN
        UPDATE bri.xlsx_jobs x SET state='ready',available_at=clock_timestamp()
            WHERE (x.tenant_id,x.job_id)=(t,job) RETURNING * INTO j;
        PERFORM bri.xlsx_audit(j,'ready',correlation,actor);
    END IF;
    RETURN bri.xlsx_receipt(j,false);
END $$;

CREATE FUNCTION bri.xlsx_status(t text, actor uuid, sub uuid, sid uuid, issuer text, job uuid)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM bri.xlsx_require_role('bri_xlsx_submitter');
    RETURN bri.xlsx_receipt(bri.xlsx_user_job(t,actor,sub,sid,issuer,job),false);
END $$;

CREATE FUNCTION bri.xlsx_worker_job(job uuid, correlation uuid) RETURNS bri.xlsx_jobs
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE j bri.xlsx_jobs;
BEGIN
    PERFORM bri.xlsx_require_role('bri_xlsx_worker');
    IF correlation IS NULL THEN RAISE EXCEPTION 'invalid XLSX correlation' USING ERRCODE = '22023'; END IF;
    SELECT * INTO j FROM bri.xlsx_jobs x WHERE x.job_id=job;
    IF NOT FOUND OR j.state NOT IN ('ready','processing') THEN RETURN NULL; END IF;
    PERFORM bri.xlsx_lock_actor(j.actor_id,j.auth_user_id,j.session_id);
    SELECT * INTO STRICT j FROM bri.xlsx_jobs x WHERE (x.tenant_id,x.job_id)=(j.tenant_id,job) FOR UPDATE;
    RETURN j;
END $$;

CREATE FUNCTION bri.xlsx_worker_authorized(j bri.xlsx_jobs) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT bri.xlsx_has_authority(j.tenant_id,j.actor_id,j.auth_user_id,j.session_id,j.issuer,j.scope_node_id)
       AND bri.xlsx_creator_active(j.tenant_id,j.creator_id,j.issuer);
$$;

CREATE FUNCTION bri.xlsx_end_attempt(j bri.xlsx_jobs, why text, correlation uuid, retry_at timestamptz DEFAULT NULL)
RETURNS text LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
DECLARE target text := CASE WHEN retry_at IS NULL THEN 'failed' ELSE 'ready' END;
BEGIN
    UPDATE bri.xlsx_jobs x SET state=target,lease_until=NULL,reason=why,available_at=coalesce(retry_at,x.available_at)
        WHERE (x.tenant_id,x.job_id)=(j.tenant_id,j.job_id);
    PERFORM bri.xlsx_audit(j,CASE target WHEN 'ready' THEN 'retry' ELSE 'failed' END,correlation,NULL,why);
    RETURN target;
END $$;

CREATE FUNCTION bri.xlsx_claim(job uuid, correlation uuid) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE j bri.xlsx_jobs; retry_at timestamptz;
BEGIN
    j := bri.xlsx_worker_job(job,correlation);
    IF j.job_id IS NULL OR j.state NOT IN ('ready','processing') OR j.available_at>clock_timestamp()
       OR j.lease_until>clock_timestamp() THEN RETURN NULL; END IF;
    IF NOT bri.xlsx_worker_authorized(j) THEN
        PERFORM bri.xlsx_end_attempt(j,'authority_lost',correlation);
        RETURN NULL;
    END IF;
    IF j.state='processing' THEN
        PERFORM bri.xlsx_audit(j,'lease_expired',correlation,NULL,'lease_expired');
        IF j.attempt=3 THEN
            PERFORM bri.xlsx_end_attempt(j,'lease_expired',correlation);
            RETURN NULL;
        END IF;
        retry_at := j.lease_until + CASE j.attempt WHEN 1 THEN interval '5 seconds' ELSE interval '15 seconds' END;
        PERFORM bri.xlsx_end_attempt(j,'lease_expired',correlation,retry_at);
        IF retry_at>clock_timestamp() THEN RETURN NULL; END IF;
    END IF;
    UPDATE bri.xlsx_jobs x SET state='processing',attempt=x.attempt+1,lease_until=clock_timestamp()+interval '60 seconds',reason=NULL
        WHERE (x.tenant_id,x.job_id)=(j.tenant_id,job) RETURNING * INTO j;
    PERFORM bri.xlsx_audit(j,'claimed',correlation);
    RETURN jsonb_build_object('job_id',j.job_id,'tenant_id',j.tenant_id,'artifact_key',j.artifact_key,
                              'byte_count',j.byte_count,'original_sha256',j.original_sha256,'attempt',j.attempt);
END $$;

CREATE FUNCTION bri.xlsx_complete(job uuid, attempt integer, canonical_text text, canonical_sha256 text,
                                   extractor_version integer, canonicalization_version integer, sheet_id text,
                                   sheet_title text, cell_range text, correlation uuid) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE j bri.xlsx_jobs; document jsonb;
BEGIN
    j := bri.xlsx_worker_job(job,correlation);
    IF j.job_id IS NULL OR j.state<>'processing' OR j.attempt IS DISTINCT FROM attempt
       OR j.lease_until<=clock_timestamp() THEN RETURN 'stale'; END IF;
    IF NOT bri.xlsx_worker_authorized(j) THEN RETURN bri.xlsx_end_attempt(j,'authority_lost',correlation); END IF;
    IF NOT coalesce(octet_length(canonical_text) BETWEEN 1 AND 2097152,false)
       OR NOT coalesce(canonical_sha256 ~ '^[0-9a-f]{64}$',false)
       OR encode(sha256(convert_to(canonical_text,'UTF8')),'hex') <> canonical_sha256
       OR extractor_version IS DISTINCT FROM 1 OR canonicalization_version IS DISTINCT FROM 1
       OR NOT coalesce(sheet_id ~ '^[1-9][0-9]{0,9}$',false)
       OR NOT coalesce(length(sheet_title) BETWEEN 1 AND 31,false)
       OR NOT coalesce(cell_range ~ '^A1(:[A-Z]{1,2}[1-9][0-9]{0,4})?$',false) THEN
        RAISE EXCEPTION 'invalid XLSX extraction metadata' USING ERRCODE = '22023';
    END IF;
    -- Strict canonicalization is performed by the bounded extractor; verify
    -- the digest and that the recorded locator agrees with the canonical frame.
    BEGIN
        document := canonical_text::jsonb;
    EXCEPTION WHEN data_exception THEN
        RAISE EXCEPTION 'invalid XLSX extraction metadata' USING ERRCODE = '22023';
    END;
    IF document->'version' IS DISTINCT FROM to_jsonb(canonicalization_version)
       OR document->'worksheet' IS DISTINCT FROM jsonb_build_object('identity',sheet_id,'title',sheet_title,'range',cell_range)
       OR jsonb_typeof(document->'rows') IS DISTINCT FROM 'array' THEN
        RAISE EXCEPTION 'invalid XLSX extraction metadata' USING ERRCODE = '22023';
    END IF;
    IF j.lease_until<=clock_timestamp() THEN RETURN 'stale'; END IF;
    IF NOT bri.xlsx_worker_authorized(j) THEN RETURN bri.xlsx_end_attempt(j,'authority_lost',correlation); END IF;
    INSERT INTO bri.xlsx_sources (tenant_id,job_id,scope_node_id,creator_id)
        VALUES (j.tenant_id,job,j.scope_node_id,j.creator_id);
    INSERT INTO bri.xlsx_source_versions (tenant_id,job_id,original_sha256,canonical_sha256,sheet_id,sheet_title,cell_range)
        VALUES (j.tenant_id,job,j.original_sha256,$4,$7,$8,$9);
    INSERT INTO bri.xlsx_extractions (tenant_id,job_id,canonical_text,canonical_sha256,extractor_version,canonicalization_version)
        VALUES (j.tenant_id,job,$3,$4,$5,$6);
    INSERT INTO bri.xlsx_pending_proposals (tenant_id,job_id) VALUES (j.tenant_id,job);
    UPDATE bri.xlsx_jobs x SET state='proposed',lease_until=NULL,reason=NULL
        WHERE (x.tenant_id,x.job_id)=(j.tenant_id,job) RETURNING * INTO j;
    PERFORM bri.xlsx_audit(j,'proposed',correlation,j.creator_id);
    RETURN j.state;
END $$;

CREATE FUNCTION bri.xlsx_fail(job uuid, attempt integer, reason text, correlation uuid) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE j bri.xlsx_jobs; retry_at timestamptz;
BEGIN
    j := bri.xlsx_worker_job(job,correlation);
    IF j.job_id IS NULL OR j.state<>'processing' OR j.attempt IS DISTINCT FROM attempt
       OR j.lease_until<=clock_timestamp() THEN RETURN 'stale'; END IF;
    IF NOT bri.xlsx_worker_authorized(j) THEN RETURN bri.xlsx_end_attempt(j,'authority_lost',correlation); END IF;
    reason := CASE WHEN reason IN ('unsupported_workbook','resource_limit','integrity_failure','processing_failed',
                                   'infrastructure_unavailable') THEN reason ELSE 'processing_failed' END;
    IF reason='infrastructure_unavailable' AND attempt<3 THEN
        retry_at := clock_timestamp() + CASE attempt WHEN 1 THEN interval '5 seconds' ELSE interval '15 seconds' END;
    END IF;
    RETURN bri.xlsx_end_attempt(j,reason,correlation,retry_at);
END $$;

REVOKE ALL ON FUNCTION bri.xlsx_immutable(), bri.xlsx_has_authority(text,uuid,uuid,uuid,text,text),
    bri.xlsx_creator_active(text,uuid,text), bri.xlsx_lock_actor(uuid,uuid,uuid), bri.xlsx_require_role(text),
    bri.xlsx_receipt(bri.xlsx_jobs,boolean), bri.xlsx_audit(bri.xlsx_jobs,text,uuid,uuid,text),
    bri.xlsx_user_job(text,uuid,uuid,uuid,text,uuid), bri.xlsx_worker_job(uuid,uuid),
    bri.xlsx_worker_authorized(bri.xlsx_jobs), bri.xlsx_end_attempt(bri.xlsx_jobs,text,uuid,timestamptz),
    bri.xlsx_submit(text,uuid,uuid,uuid,text,text,uuid,integer,text,uuid),
    bri.xlsx_mark_ready(text,uuid,uuid,uuid,text,uuid,uuid), bri.xlsx_status(text,uuid,uuid,uuid,text,uuid),
    bri.xlsx_claim(uuid,uuid), bri.xlsx_complete(uuid,integer,text,text,integer,integer,text,text,text,uuid),
    bri.xlsx_fail(uuid,integer,text,uuid) FROM PUBLIC,bri_app;
