-- A12 is inactive until a private fixture explicitly grants the RPCs. This
-- migration provisions neither logins nor source:submit assignments.
-- Trusted worker-to-native-principal binding. Not seeded or writable by stage logins.
CREATE TABLE bri.csv_worker_creators (
    tenant_id text PRIMARY KEY,
    creator_id uuid NOT NULL,
    FOREIGN KEY (tenant_id,creator_id) REFERENCES bri.auth_tenant_memberships (tenant_id,principal_id)
);
ALTER TABLE bri.csv_worker_creators ENABLE ROW LEVEL SECURITY;
ALTER TABLE bri.csv_worker_creators FORCE ROW LEVEL SECURITY;
REVOKE ALL ON bri.csv_worker_creators FROM PUBLIC,bri_app;
CREATE POLICY csv_creator_read ON bri.csv_worker_creators FOR SELECT TO bri_migrator USING (true);
CREATE POLICY csv_creator_maintenance ON bri.csv_worker_creators TO bri_migrator
    USING (session_user = 'bri_migrator') WITH CHECK (session_user = 'bri_migrator');

CREATE TABLE bri.csv_jobs (
    job_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    object_key uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    tenant_id text NOT NULL,
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
    state text NOT NULL DEFAULT 'creating' CHECK (state IN (
        'creating','ready','processing','proposed','approved','rejected','failed')),
    attempt integer NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 3),
    lease_until timestamptz,
    proposal_id text GENERATED ALWAYS AS ('csv:' || job_id::text) STORED,
    UNIQUE (tenant_id, job_id),
    UNIQUE (tenant_id, actor_id, request_key),
    UNIQUE (tenant_id, proposal_id),
    UNIQUE (tenant_id, proposal_id, creator_id),
    FOREIGN KEY (tenant_id, creator_id) REFERENCES bri.auth_tenant_memberships (tenant_id, principal_id),
    FOREIGN KEY (tenant_id, scope_node_id) REFERENCES bri.org_nodes (tenant_id, node_id),
    FOREIGN KEY (tenant_id, actor_id) REFERENCES bri.auth_tenant_memberships (tenant_id, principal_id),
    FOREIGN KEY (auth_user_id, actor_id) REFERENCES bri.auth_identity_links (auth_user_id, principal_id),
    CONSTRAINT csv_jobs_distinct_creator CHECK (actor_id <> creator_id),
    CHECK ((state = 'processing') = (lease_until IS NOT NULL))
);

CREATE TABLE bri.csv_audit_events (
    event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id text NOT NULL,
    job_id uuid NOT NULL,
    actor_id uuid REFERENCES bri.auth_principals (principal_id),
    correlation uuid NOT NULL,
    event text NOT NULL CHECK (event IN ('submitted','ready','claimed','lease_expired',
        'retry','failed','proposed','approved','rejected','record_access','version_access')),
    attempt integer NOT NULL CHECK (attempt BETWEEN 0 AND 3),
    reason text CHECK (reason IN ('invalid_csv','object_missing','digest_mismatch',
        'storage_error','processing_error','lease_expired','authority_lost')),
    -- NULL on policy removal; absence is still deny. Other events do not use this field.
    readable boolean,
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (tenant_id,job_id) REFERENCES bri.csv_jobs (tenant_id,job_id)
);
CREATE INDEX csv_audit_job_idx ON bri.csv_audit_events (tenant_id,job_id,occurred_at);

ALTER TABLE bri.csv_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE bri.csv_jobs FORCE ROW LEVEL SECURITY;
ALTER TABLE bri.csv_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE bri.csv_audit_events FORCE ROW LEVEL SECURITY;
REVOKE ALL ON bri.csv_jobs,bri.csv_audit_events FROM PUBLIC,bri_app;
CREATE POLICY csv_private_read ON bri.csv_jobs FOR SELECT TO bri_migrator USING (true);
CREATE POLICY csv_private_insert ON bri.csv_jobs FOR INSERT TO bri_migrator WITH CHECK (true);
CREATE POLICY csv_private_update ON bri.csv_jobs FOR UPDATE TO bri_migrator USING (true);
CREATE POLICY csv_audit_read ON bri.csv_audit_events FOR SELECT TO bri_migrator
    USING (session_user = 'bri_migrator' AND tenant_id = nullif(current_setting('bri.tenant_id',true),''));
CREATE POLICY csv_audit_insert ON bri.csv_audit_events FOR INSERT TO bri_migrator WITH CHECK (true);

CREATE FUNCTION bri.csv_guard_immutable() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    RAISE EXCEPTION 'immutable CSV evidence' USING ERRCODE = '42501';
END $$;
CREATE TRIGGER csv_audit_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON bri.csv_audit_events
FOR EACH STATEMENT EXECUTE FUNCTION bri.csv_guard_immutable();
CREATE TRIGGER csv_job_metadata_immutable BEFORE UPDATE OF job_id,object_key,tenant_id,scope_node_id,
    actor_id,creator_id,auth_user_id,session_id,issuer,request_key,original_sha256,byte_count,created_at ON bri.csv_jobs
FOR EACH STATEMENT EXECUTE FUNCTION bri.csv_guard_immutable();
CREATE TRIGGER csv_jobs_no_remove BEFORE DELETE OR TRUNCATE ON bri.csv_jobs
FOR EACH STATEMENT EXECUTE FUNCTION bri.csv_guard_immutable();

-- A release app login can edit the old synthetic role catalog. It must not
-- manufacture or remove CSV authority on a native role. Existing synthetic
-- knowledge permissions still work on roles with no native assignment.
CREATE FUNCTION bri.csv_guard_permission_catalog() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_TABLE_NAME = 'app_roles' THEN
        IF EXISTS (SELECT FROM bri.role_permissions r WHERE (r.tenant_id,r.role_id) = (OLD.tenant_id,OLD.role_id)
                   AND (r.permission = 'source:submit' OR (r.permission IN ('knowledge:read','knowledge:review')
                       AND EXISTS (SELECT FROM bri.auth_role_assignments a
                                   WHERE (a.tenant_id,a.role_id) = (r.tenant_id,r.role_id))))) THEN
            RAISE EXCEPTION 'CSV role is protected' USING ERRCODE = '42501';
        END IF;
        RETURN OLD;
    END IF;
    IF TG_OP <> 'INSERT' THEN
        IF OLD.permission = 'source:submit' OR (OLD.permission IN ('knowledge:read','knowledge:review') AND EXISTS (
            SELECT FROM bri.auth_role_assignments a WHERE (a.tenant_id,a.role_id) = (OLD.tenant_id,OLD.role_id))) THEN
            RAISE EXCEPTION 'CSV authority is protected' USING ERRCODE = '42501';
        END IF;
    END IF;
    IF TG_OP <> 'DELETE' THEN
        IF NEW.permission = 'source:submit' OR (NEW.permission IN ('knowledge:read','knowledge:review') AND EXISTS (
            SELECT FROM bri.auth_role_assignments a WHERE (a.tenant_id,a.role_id) = (NEW.tenant_id,NEW.role_id))) THEN
            RAISE EXCEPTION 'CSV authority is protected' USING ERRCODE = '42501';
        END IF;
        RETURN NEW;
    END IF;
    RETURN OLD;
END $$;
CREATE TRIGGER csv_protect_permissions BEFORE INSERT OR UPDATE OR DELETE ON bri.role_permissions
FOR EACH ROW WHEN (current_user = 'bri_app') EXECUTE FUNCTION bri.csv_guard_permission_catalog();
CREATE TRIGGER csv_protect_role_delete BEFORE DELETE ON bri.app_roles
FOR EACH ROW WHEN (current_user = 'bri_app') EXECUTE FUNCTION bri.csv_guard_permission_catalog();

CREATE POLICY csv_bound_issuer ON bri.provider_event_source FOR SELECT TO bri_migrator
USING (session_user IN ('bri_csv_intake','bri_csv_worker','bri_csv_reader'));

-- auth_user is the sub already verified by the trusted server, not a browser
-- setting. Scope is literal equality, never role/ancestor inference.
CREATE FUNCTION bri.csv_has_authority(t text, actor uuid, sub uuid, sid uuid, issuer text, node text, action text)
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
          AND (m.membership_type IN ('user','superuser') OR (action IN ('knowledge:review','knowledge:read') AND m.membership_type='admin'))
          AND NOT EXISTS (SELECT FROM bri.auth_tenant_memberships x WHERE x.principal_id=actor AND x.tenant_id<>t)
          AND NOT EXISTS (SELECT FROM bri.platform_superadmins x WHERE x.principal_id=actor)
          AND NOT EXISTS (SELECT FROM bri.credential_operations c WHERE c.principal_id=actor AND c.confirmed_at IS NULL)
      ) AND EXISTS (
        SELECT FROM bri.auth_role_assignments a JOIN bri.role_permissions rp USING (tenant_id,role_id)
        WHERE (a.tenant_id,a.principal_id,a.scope_node_id,rp.permission) = (t,actor,node,action)
          AND a.status = 'active'
      );
$$;

CREATE FUNCTION bri.csv_creator_active(t text, creator uuid, issuer text) RETURNS boolean
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

CREATE FUNCTION bri.csv_lock_actor(actor uuid) RETURNS void LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'CSV mutation requires read committed' USING ERRCODE = '25001';
    END IF;
    PERFORM bri.lock_user_provisioning_governance();
    -- Ignore unknown actors without trying to create a guard FK for them.
    IF EXISTS (SELECT FROM bri.auth_principals p WHERE p.principal_id=actor) THEN
        PERFORM bri.lock_session_guard(actor);
    END IF;
END $$;

CREATE FUNCTION bri.csv_audit(j bri.csv_jobs, action text, correlation uuid, who uuid DEFAULT NULL,
                              why text DEFAULT NULL, allowed boolean DEFAULT NULL)
RETURNS void LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$
    INSERT INTO bri.csv_audit_events (tenant_id,job_id,actor_id,correlation,event,attempt,reason,readable)
    VALUES (j.tenant_id,j.job_id,who,correlation,action,j.attempt,why,allowed);
$$;

CREATE FUNCTION bri.csv_submit(t text, actor uuid, sid uuid, issuer text, node text, request_key uuid,
                              original_sha256 text, byte_count integer, correlation uuid)
RETURNS TABLE(job_id uuid,state text,object_key uuid)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE j bri.csv_jobs; creator uuid; sub uuid := nullif(current_setting('bri.auth_user_id',true),'')::uuid;
BEGIN
    IF session_user <> 'bri_csv_intake' THEN
        RAISE EXCEPTION 'CSV intake denied' USING ERRCODE = '42501';
    END IF;
    PERFORM bri.csv_lock_actor(actor);
    IF NOT bri.csv_has_authority(t,actor,sub,sid,issuer,node,'source:submit') THEN
        RAISE EXCEPTION 'CSV intake denied' USING ERRCODE = '42501';
    END IF;
    IF request_key IS NULL OR correlation IS NULL OR NOT coalesce(original_sha256 ~ '^[0-9a-f]{64}$',false)
       OR NOT coalesce(byte_count BETWEEN 1 AND 5000000,false) THEN
        RAISE EXCEPTION 'invalid CSV submission metadata' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO j FROM bri.csv_jobs x WHERE (x.tenant_id,x.actor_id,x.request_key) = (t,actor,$6);
    IF FOUND THEN
        IF (j.scope_node_id,j.original_sha256,j.byte_count) <> (node,original_sha256,byte_count) THEN
            RAISE EXCEPTION 'CSV request key conflict' USING ERRCODE = '23505';
        END IF;
    ELSE
        SELECT c.creator_id INTO creator FROM bri.csv_worker_creators c WHERE c.tenant_id=t;
        IF creator IS NOT DISTINCT FROM actor OR NOT bri.csv_creator_active(t,creator,issuer) THEN
            RAISE EXCEPTION 'CSV creator binding unavailable' USING ERRCODE = '42501';
        END IF;
        INSERT INTO bri.csv_jobs (tenant_id,scope_node_id,actor_id,creator_id,auth_user_id,session_id,issuer,
                                  request_key,original_sha256,byte_count)
        VALUES (t,node,actor,creator,sub,sid,issuer,$6,$7,$8) RETURNING * INTO j;
        PERFORM bri.csv_audit(j,'submitted',correlation,actor);
    END IF;
    IF NOT bri.csv_has_authority(t,actor,sub,sid,issuer,node,'source:submit') THEN
        RAISE EXCEPTION 'CSV intake denied' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY SELECT j.job_id,j.state,j.object_key;
END $$;

REVOKE ALL ON FUNCTION bri.csv_guard_immutable(), bri.csv_guard_permission_catalog(),
    bri.csv_has_authority(text,uuid,uuid,uuid,text,text,text), bri.csv_creator_active(text,uuid,text), bri.csv_lock_actor(uuid),
    bri.csv_audit(bri.csv_jobs,text,uuid,uuid,text,boolean),
    bri.csv_submit(text,uuid,uuid,text,text,uuid,text,integer,uuid) FROM PUBLIC,bri_app;

-- Explicit lineage, enforced through composite parent FKs. Existing rows
-- default to synthetic regardless of spelling; an app insert cannot attach
-- synthetic children to a governed parent even without SELECT on that parent.
ALTER TABLE bri.source_records DROP CONSTRAINT source_records_source_kind_check;
ALTER TABLE bri.source_records ADD COLUMN csv_governed boolean NOT NULL DEFAULT false,
    ADD CHECK (source_kind = CASE WHEN csv_governed THEN 'governed_csv' ELSE 'synthetic_text' END),
    ADD UNIQUE (tenant_id,source_id,csv_governed);
ALTER TABLE bri.source_versions ADD COLUMN csv_governed boolean NOT NULL DEFAULT false,
    ADD UNIQUE (tenant_id,source_id,source_version_id,csv_governed),
    ADD FOREIGN KEY (tenant_id,source_id,csv_governed) REFERENCES bri.source_records (tenant_id,source_id,csv_governed);
ALTER TABLE bri.source_extractions ADD COLUMN csv_governed boolean NOT NULL DEFAULT false,
    ADD UNIQUE (tenant_id,extraction_id,csv_governed),
    ADD FOREIGN KEY (tenant_id,source_id,source_version_id,csv_governed)
        REFERENCES bri.source_versions (tenant_id,source_id,source_version_id,csv_governed);
ALTER TABLE bri.knowledge_proposals ADD COLUMN csv_governed boolean NOT NULL DEFAULT false,
    ADD COLUMN csv_creator_id uuid,
    ADD CHECK (csv_governed = (csv_creator_id IS NOT NULL)),
    ADD UNIQUE (tenant_id,proposal_id,csv_governed),
    ADD FOREIGN KEY (tenant_id,extraction_id,csv_governed) REFERENCES bri.source_extractions (tenant_id,extraction_id,csv_governed),
    ADD FOREIGN KEY (tenant_id,proposal_id,csv_creator_id) REFERENCES bri.csv_jobs (tenant_id,proposal_id,creator_id);
ALTER TABLE bri.validation_decisions ADD COLUMN csv_governed boolean NOT NULL DEFAULT false,
    ADD FOREIGN KEY (tenant_id,proposal_id,csv_governed) REFERENCES bri.knowledge_proposals (tenant_id,proposal_id,csv_governed);
ALTER TABLE bri.validated_knowledge ADD COLUMN csv_governed boolean NOT NULL DEFAULT false,
    ADD FOREIGN KEY (tenant_id,proposal_id,csv_governed) REFERENCES bri.knowledge_proposals (tenant_id,proposal_id,csv_governed);

-- Only canonical generated IDs need a claim. NULL job_ref records a legacy
-- claim, not a ban on the spelling: any legacy table may share that claim.
-- A governed claim instead belongs to the exact job and is never recycled.
CREATE TABLE bri.csv_lineage_claims (
    tenant_id text NOT NULL,
    lineage_id text NOT NULL,
    job_ref text CHECK (job_ref = lineage_id),
    PRIMARY KEY (tenant_id,lineage_id),
    FOREIGN KEY (tenant_id,job_ref) REFERENCES bri.csv_jobs (tenant_id,proposal_id)
);
ALTER TABLE bri.csv_lineage_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE bri.csv_lineage_claims FORCE ROW LEVEL SECURITY;
REVOKE ALL ON bri.csv_lineage_claims FROM PUBLIC,bri_app;
CREATE POLICY csv_lineage_claim_read ON bri.csv_lineage_claims FOR SELECT TO bri_migrator USING (true);
CREATE POLICY csv_lineage_claim_insert ON bri.csv_lineage_claims FOR INSERT TO bri_migrator WITH CHECK (true);
CREATE POLICY csv_lineage_claim_legacy_update ON bri.csv_lineage_claims FOR UPDATE TO bri_migrator
    USING (job_ref IS NULL) WITH CHECK (job_ref IS NULL);
CREATE TRIGGER csv_lineage_claim_no_remove BEFORE DELETE OR TRUNCATE ON bri.csv_lineage_claims
FOR EACH STATEMENT EXECUTE FUNCTION bri.csv_guard_immutable();

CREATE FUNCTION bri.csv_is_generated_ref(ref text) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
    SELECT $1 COLLATE "C" ~ '^csv:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';
$$;

CREATE FUNCTION bri.csv_claim_lineage_id() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE ref text;
BEGIN
    CASE TG_TABLE_NAME
        WHEN 'csv_jobs' THEN
            INSERT INTO bri.csv_lineage_claims (tenant_id,lineage_id,job_ref)
            VALUES (NEW.tenant_id,NEW.proposal_id,NEW.proposal_id);
            RETURN NULL;
        WHEN 'source_records' THEN ref := NEW.source_id;
        WHEN 'source_extractions' THEN ref := NEW.extraction_id;
        WHEN 'knowledge_proposals' THEN ref := NEW.proposal_id;
        WHEN 'validation_decisions' THEN ref := NEW.decision_id;
    END CASE;
    IF NEW.csv_governed THEN
        IF NOT EXISTS (SELECT FROM bri.csv_lineage_claims c WHERE (c.tenant_id,c.lineage_id,c.job_ref)
                       = (NEW.tenant_id,ref,ref)) THEN
            RAISE EXCEPTION 'CSV lineage requires a job reservation' USING ERRCODE = '23503';
        END IF;
    ELSIF bri.csv_is_generated_ref(ref) THEN
        -- The unique index arbitrates against concurrent job reservations,
        -- including when the other transaction was invisible to our snapshot.
        INSERT INTO bri.csv_lineage_claims AS c (tenant_id,lineage_id) VALUES (NEW.tenant_id,ref)
        ON CONFLICT (tenant_id,lineage_id) DO UPDATE SET job_ref=NULL WHERE c.job_ref IS NULL;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'lineage identity is reserved' USING ERRCODE = '23505';
        END IF;
    END IF;
    RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION bri.csv_is_generated_ref(text),bri.csv_claim_lineage_id() FROM PUBLIC,bri_app;

-- Versions are keyed by their parent source and validated rows by their
-- parent proposal; the existing lineage FKs protect those two namespaces.
-- ALTER TABLE above already holds write-excluding locks through commit.
DO $csv_claims$
DECLARE n text; k text;
BEGIN
    FOR n,k IN SELECT * FROM (VALUES ('source_records','source_id'), ('source_extractions','extraction_id'),
        ('knowledge_proposals','proposal_id'), ('validation_decisions','decision_id')) AS keys(table_name,key_name) LOOP
        EXECUTE format('CREATE POLICY csv_claim_backfill ON bri.%I FOR SELECT TO bri_migrator USING (true)',n);
        EXECUTE format('INSERT INTO bri.csv_lineage_claims (tenant_id,lineage_id)
            SELECT tenant_id,%I FROM bri.%I WHERE bri.csv_is_generated_ref(%I) ON CONFLICT DO NOTHING',k,n,k);
        EXECUTE format('DROP POLICY csv_claim_backfill ON bri.%I',n);
        EXECUTE format('CREATE TRIGGER csv_claim_lineage AFTER INSERT OR UPDATE OF tenant_id,%I,csv_governed ON bri.%I
            FOR EACH ROW EXECUTE FUNCTION bri.csv_claim_lineage_id()',k,n);
    END LOOP;
END $csv_claims$;
CREATE TRIGGER csv_reserve_lineage AFTER INSERT ON bri.csv_jobs
FOR EACH ROW EXECUTE FUNCTION bri.csv_claim_lineage_id();

DO $csv_lineage$
DECLARE n text; attribution_column text;
BEGIN
    FOR n,attribution_column IN SELECT * FROM (VALUES
        ('source_records','created_by'),('source_versions','created_by'),('source_extractions','created_by'),
        ('knowledge_proposals','proposed_by'),('validation_decisions','reviewer_id'),('validated_knowledge',NULL)
    ) AS ks(table_name,attribution) LOOP
        EXECUTE format('CREATE POLICY csv_legacy_only ON bri.%I AS RESTRICTIVE TO bri_app
            USING (NOT csv_governed) WITH CHECK (NOT csv_governed)',n);
        IF attribution_column IS NOT NULL THEN
            EXECUTE format('CREATE POLICY csv_legacy_attribution ON bri.%I AS RESTRICTIVE FOR INSERT TO bri_app
                WITH CHECK (%I <> ''__bri_governed_csv__'')',n,attribution_column);
        END IF;
        EXECUTE format('CREATE POLICY csv_lineage_read ON bri.%I FOR SELECT TO bri_migrator USING (csv_governed)',n);
        EXECUTE format('CREATE POLICY csv_lineage_write ON bri.%I FOR INSERT TO bri_migrator WITH CHECK (csv_governed)',n);
    END LOOP;
END $csv_lineage$;

-- Compatibility key for the preexisting synthetic FKs only. The actual
-- native creator is separately immutable and bound to both the job and proposal.
CREATE FUNCTION bri.csv_guard_synthetic_attribution() RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF (TG_OP <> 'INSERT' AND OLD.principal_id = '__bri_governed_csv__') OR
       (TG_OP <> 'DELETE' AND NEW.principal_id = '__bri_governed_csv__') THEN
        RAISE EXCEPTION 'CSV attribution is protected' USING ERRCODE = '42501';
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER csv_protect_synthetic_attribution BEFORE INSERT OR UPDATE OR DELETE ON bri.synthetic_principals
FOR EACH ROW WHEN (current_user <> 'bri_migrator') EXECUTE FUNCTION bri.csv_guard_synthetic_attribution();
CREATE POLICY csv_attribution_read ON bri.synthetic_principals FOR SELECT TO bri_migrator
    USING (principal_id = '__bri_governed_csv__');
CREATE POLICY csv_attribution_insert ON bri.synthetic_principals FOR INSERT TO bri_migrator
    WITH CHECK (principal_id = '__bri_governed_csv__');

CREATE TABLE bri.csv_source_evidence (
    tenant_id text NOT NULL,
    source_id text NOT NULL,
    source_version_id text NOT NULL,
    original_sha256 text NOT NULL CHECK (original_sha256 ~ '^[0-9a-f]{64}$'),
    first_line integer NOT NULL CHECK (first_line >= 1),
    last_line integer NOT NULL CHECK (last_line >= first_line),
    PRIMARY KEY (tenant_id, source_id, source_version_id),
    FOREIGN KEY (tenant_id, source_id, source_version_id)
        REFERENCES bri.source_versions (tenant_id, source_id, source_version_id)
);
ALTER TABLE bri.csv_source_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE bri.csv_source_evidence FORCE ROW LEVEL SECURITY;
REVOKE ALL ON bri.csv_source_evidence FROM PUBLIC,bri_app;
CREATE POLICY csv_evidence_insert ON bri.csv_source_evidence FOR INSERT TO bri_migrator
    WITH CHECK (source_id = source_version_id AND EXISTS (
        SELECT FROM bri.source_versions v WHERE (v.tenant_id,v.source_id,v.source_version_id) =
            (csv_source_evidence.tenant_id,csv_source_evidence.source_id,csv_source_evidence.source_version_id)
            AND v.csv_governed));
CREATE POLICY csv_evidence_read ON bri.csv_source_evidence FOR SELECT TO bri_migrator USING (true);
CREATE TRIGGER csv_evidence_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON bri.csv_source_evidence
FOR EACH STATEMENT EXECUTE FUNCTION bri.csv_guard_immutable();

CREATE FUNCTION bri.csv_user_job(t text, actor uuid, sub uuid, sid uuid, issuer text, job uuid)
RETURNS bri.csv_jobs LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE j bri.csv_jobs;
BEGIN
    SELECT * INTO j FROM bri.csv_jobs x WHERE (x.tenant_id,x.actor_id,x.job_id) = (t,actor,job);
    IF NOT FOUND OR NOT bri.csv_has_authority(t,actor,sub,sid,issuer,j.scope_node_id,'source:submit') THEN
        RAISE EXCEPTION 'CSV intake denied' USING ERRCODE = '42501';
    END IF;
    RETURN j;
END $$;

CREATE FUNCTION bri.csv_mark_ready(t text, actor uuid, sid uuid, issuer text, job uuid, correlation uuid)
RETURNS text LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE j bri.csv_jobs; sub uuid := nullif(current_setting('bri.auth_user_id',true),'')::uuid;
BEGIN
    IF session_user <> 'bri_csv_intake' OR correlation IS NULL THEN
        RAISE EXCEPTION 'CSV intake denied' USING ERRCODE = '42501';
    END IF;
    PERFORM bri.csv_lock_actor(actor);
    j := bri.csv_user_job(t,actor,sub,sid,issuer,job);
    SELECT * INTO STRICT j FROM bri.csv_jobs x WHERE x.job_id=job FOR UPDATE;
    IF j.state = 'creating' THEN
        UPDATE bri.csv_jobs x SET state='ready' WHERE x.job_id=job RETURNING * INTO j;
        PERFORM bri.csv_audit(j,'ready',correlation,actor);
    END IF;
    PERFORM bri.csv_user_job(t,actor,sub,sid,issuer,job);
    RETURN j.state;
END $$;

CREATE FUNCTION bri.csv_status(t text, actor uuid, sid uuid, issuer text, job uuid, correlation uuid)
RETURNS text LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF session_user <> 'bri_csv_intake' OR correlation IS NULL THEN
        RAISE EXCEPTION 'CSV intake denied' USING ERRCODE = '42501';
    END IF;
    RETURN (bri.csv_user_job(t,actor,nullif(current_setting('bri.auth_user_id',true),'')::uuid,sid,issuer,job)).state;
END $$;

CREATE FUNCTION bri.csv_claim(job uuid, correlation uuid)
RETURNS TABLE(job_id uuid,object_key uuid,original_sha256 text,byte_count integer,attempt integer,tenant_id text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE j bri.csv_jobs;
BEGIN
    IF session_user <> 'bri_csv_worker' OR correlation IS NULL THEN
        RAISE EXCEPTION 'CSV worker denied' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO j FROM bri.csv_jobs x WHERE x.job_id=job;
    IF NOT FOUND OR j.state NOT IN ('ready','processing') THEN RETURN; END IF;
    PERFORM bri.csv_lock_actor(j.actor_id);
    SELECT * INTO STRICT j FROM bri.csv_jobs x WHERE x.job_id=job FOR UPDATE;
    IF j.state NOT IN ('ready','processing') OR j.lease_until > clock_timestamp() THEN RETURN; END IF;
    IF NOT bri.csv_has_authority(j.tenant_id,j.actor_id,j.auth_user_id,j.session_id,j.issuer,j.scope_node_id,'source:submit')
       OR NOT bri.csv_creator_active(j.tenant_id,j.creator_id,j.issuer) THEN
        UPDATE bri.csv_jobs x SET state='failed',lease_until=NULL WHERE x.job_id=job RETURNING * INTO j;
        PERFORM bri.csv_audit(j,'failed',correlation,NULL,'authority_lost');
        RETURN;
    END IF;
    IF j.state = 'processing' THEN
        PERFORM bri.csv_audit(j,'lease_expired',correlation,NULL,'lease_expired');
    END IF;
    IF j.attempt = 3 THEN
        UPDATE bri.csv_jobs x SET state='failed',lease_until=NULL WHERE x.job_id=job RETURNING * INTO j;
        PERFORM bri.csv_audit(j,'failed',correlation,NULL,'lease_expired');
        RETURN;
    END IF;
    UPDATE bri.csv_jobs x SET state='processing',lease_until=clock_timestamp()+interval '2 minutes',attempt=x.attempt+1
        WHERE x.job_id=job RETURNING * INTO j;
    PERFORM bri.csv_audit(j,'claimed',correlation);
    RETURN QUERY SELECT j.job_id,j.object_key,j.original_sha256,j.byte_count,j.attempt,j.tenant_id;
END $$;

CREATE FUNCTION bri.csv_complete(job uuid, attempt integer, extracted_text text, extracted_sha256 text,
                                first_line integer, last_line integer, correlation uuid)
RETURNS text LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE j bri.csv_jobs; ref text; loc text;
        attribution constant text := '__bri_governed_csv__';
BEGIN
    IF session_user <> 'bri_csv_worker' OR correlation IS NULL THEN
        RAISE EXCEPTION 'CSV worker denied' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO j FROM bri.csv_jobs x WHERE x.job_id=job;
    IF NOT FOUND THEN RETURN 'stale'; END IF;
    PERFORM bri.csv_lock_actor(j.actor_id);
    SELECT * INTO STRICT j FROM bri.csv_jobs x WHERE x.job_id=job FOR UPDATE;
    IF j.state <> 'processing' OR j.attempt IS DISTINCT FROM attempt OR j.lease_until <= clock_timestamp() THEN
        RETURN 'stale';
    END IF;
    IF NOT bri.csv_has_authority(j.tenant_id,j.actor_id,j.auth_user_id,j.session_id,j.issuer,j.scope_node_id,'source:submit')
       OR NOT bri.csv_creator_active(j.tenant_id,j.creator_id,j.issuer) THEN
        UPDATE bri.csv_jobs x SET state='failed',lease_until=NULL WHERE x.job_id=job RETURNING * INTO j;
        PERFORM bri.csv_audit(j,'failed',correlation,NULL,'authority_lost');
        RETURN 'failed';
    END IF;
    IF NOT coalesce(octet_length(extracted_text) BETWEEN 1 AND 20000000,false)
       OR NOT coalesce(first_line >= 1 AND last_line >= first_line AND last_line <= j.byte_count,false)
       OR NOT coalesce(extracted_sha256 ~ '^[0-9a-f]{64}$',false)
       OR encode(sha256(convert_to(extracted_text,'UTF8')),'hex') <> extracted_sha256 THEN
        RAISE EXCEPTION 'invalid CSV extraction metadata' USING ERRCODE = '22023';
    END IF;
    ref := j.proposal_id;
    loc := format('csv:lines=%s-%s',first_line,last_line);
    INSERT INTO bri.synthetic_principals (tenant_id,principal_id,display_name)
        VALUES (j.tenant_id,attribution,'Governed CSV (synthetic attribution only)') ON CONFLICT DO NOTHING;
    INSERT INTO bri.source_records (tenant_id,source_id,scope_node_id,title,source_kind,created_by,csv_governed)
        VALUES (j.tenant_id,ref,j.scope_node_id,'Governed CSV','governed_csv',attribution,true);
    INSERT INTO bri.source_versions (tenant_id,source_id,source_version_id,version_label,content_sha256,source_location,created_by,csv_governed)
        VALUES (j.tenant_id,ref,ref,'1',extracted_sha256,loc,attribution,true);
    INSERT INTO bri.source_extractions (tenant_id,extraction_id,source_id,source_version_id,scope_node_id,content,
                                        content_sha256,source_location,extractor_name,extractor_version,created_by,csv_governed)
        VALUES (j.tenant_id,ref,ref,ref,j.scope_node_id,extracted_text,extracted_sha256,loc,'governed-csv','1',attribution,true);
    INSERT INTO bri.csv_source_evidence VALUES (j.tenant_id,ref,ref,j.original_sha256,first_line,last_line);
    INSERT INTO bri.knowledge_proposals (tenant_id,proposal_id,extraction_id,scope_node_id,proposed_by,csv_governed,csv_creator_id)
        VALUES (j.tenant_id,ref,ref,j.scope_node_id,attribution,true,j.creator_id);
    UPDATE bri.csv_jobs x SET state='proposed',lease_until=NULL WHERE x.job_id=job RETURNING * INTO j;
    PERFORM bri.csv_audit(j,'proposed',correlation,j.creator_id);
    IF NOT bri.csv_has_authority(j.tenant_id,j.actor_id,j.auth_user_id,j.session_id,j.issuer,j.scope_node_id,'source:submit')
       OR NOT bri.csv_creator_active(j.tenant_id,j.creator_id,j.issuer) THEN
        RAISE EXCEPTION 'CSV intake denied' USING ERRCODE = '42501';
    END IF;
    RETURN j.state;
END $$;

CREATE FUNCTION bri.csv_fail(job uuid, attempt integer, reason text, transient boolean, correlation uuid)
RETURNS text LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE j bri.csv_jobs; target text;
BEGIN
    IF session_user <> 'bri_csv_worker' OR correlation IS NULL THEN
        RAISE EXCEPTION 'CSV worker denied' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO j FROM bri.csv_jobs x WHERE x.job_id=job FOR UPDATE;
    IF NOT FOUND OR j.state <> 'processing' OR j.attempt IS DISTINCT FROM attempt OR j.lease_until <= clock_timestamp() THEN
        RETURN 'stale';
    END IF;
    -- Supplied by the trusted parser/storage adapter. Keep only a bounded
    -- category; unrecognized diagnostics never reach persisted audit.
    reason := CASE
        WHEN reason IN ('storage_missing','object_missing') THEN 'object_missing'
        WHEN reason IN ('storage_mismatch','digest_mismatch') THEN 'digest_mismatch'
        WHEN reason IN ('storage_configuration','storage_unavailable','storage_error') THEN 'storage_error'
        WHEN reason IN ('byte_limit','row_limit','column_limit','invalid_utf8','invalid_csv','invalid_headers','row_width')
            THEN 'invalid_csv'
        ELSE 'processing_error'
    END;
    target := CASE WHEN transient AND j.attempt < 3 AND reason NOT IN ('invalid_csv','digest_mismatch')
                   THEN 'ready' ELSE 'failed' END;
    UPDATE bri.csv_jobs x SET state=target,lease_until=NULL WHERE x.job_id=job RETURNING * INTO j;
    PERFORM bri.csv_audit(j,CASE WHEN target='ready' THEN 'retry' ELSE 'failed' END,correlation,NULL,reason);
    RETURN j.state;
END $$;

CREATE FUNCTION bri.csv_review(t text, actor uuid, sid uuid, issuer text, proposal_id text, decision text, correlation uuid)
RETURNS text LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE j bri.csv_jobs; sub uuid := nullif(current_setting('bri.auth_user_id',true),'')::uuid;
BEGIN
    IF session_user <> 'bri_csv_intake' OR correlation IS NULL THEN
        RAISE EXCEPTION 'CSV review denied' USING ERRCODE = '42501';
    END IF;
    PERFORM bri.csv_lock_actor(actor);
    SELECT * INTO j FROM bri.csv_jobs x WHERE x.tenant_id=t
        AND x.proposal_id = CASE WHEN left($5,4) = 'csv:' THEN $5 ELSE 'csv:' || $5 END FOR UPDATE;
    IF NOT FOUND OR actor IN (j.actor_id,j.creator_id) OR NOT bri.csv_has_authority(t,actor,sub,sid,issuer,j.scope_node_id,'knowledge:review') THEN
        RAISE EXCEPTION 'CSV review denied' USING ERRCODE = '42501';
    END IF;
    IF NOT coalesce(decision IN ('approved','rejected'),false) THEN
        RAISE EXCEPTION 'invalid CSV review decision' USING ERRCODE = '22023';
    END IF;
    IF j.state <> 'proposed' THEN
        RAISE EXCEPTION 'CSV proposal is not pending' USING ERRCODE = '23505';
    END IF;
    INSERT INTO bri.validation_decisions (tenant_id,decision_id,proposal_id,reviewer_id,decision,csv_governed)
        VALUES (t,j.proposal_id,j.proposal_id,'__bri_governed_csv__',$6,true);
    IF decision = 'approved' THEN
        INSERT INTO bri.validated_knowledge (tenant_id,proposal_id,decision_id,csv_governed) VALUES (t,j.proposal_id,j.proposal_id,true);
    END IF;
    UPDATE bri.csv_jobs x SET state=$6 WHERE x.job_id=j.job_id RETURNING * INTO j;
    PERFORM bri.csv_audit(j,decision,correlation,actor);
    IF NOT bri.csv_has_authority(t,actor,sub,sid,issuer,j.scope_node_id,'knowledge:review') THEN
        RAISE EXCEPTION 'CSV review denied' USING ERRCODE = '42501';
    END IF;
    RETURN j.state;
END $$;

-- Reuse the DB-only 0020 decisions. A CSV allow row is not an approval,
-- and the trigger refuses it until the actual governed validation exists.
CREATE FUNCTION bri.csv_policy_audit() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE r record; j bri.csv_jobs; action text; allowed boolean;
BEGIN
    IF TG_OP = 'DELETE' THEN r := OLD; ELSE r := NEW; allowed := NEW.readable; END IF;
    IF TG_OP = 'UPDATE' AND (to_jsonb(OLD) - 'readable') IS DISTINCT FROM (to_jsonb(NEW) - 'readable')
       AND EXISTS (SELECT FROM bri.source_records s WHERE s.csv_governed AND
                   (s.tenant_id,s.source_id) IN ((OLD.tenant_id,OLD.source_id),(NEW.tenant_id,NEW.source_id))) THEN
        RAISE EXCEPTION 'CSV access policy key is immutable' USING ERRCODE = '42501';
    END IF;
    IF NOT EXISTS (SELECT FROM bri.source_records s WHERE s.csv_governed
                   AND (s.tenant_id,s.source_id) = (r.tenant_id,r.source_id)) THEN RETURN NULL; END IF;
    IF session_user <> 'bri_migrator' THEN
        RAISE EXCEPTION 'CSV policy maintenance denied' USING ERRCODE = '42501';
    END IF;
    IF TG_OP = 'UPDATE' AND OLD.readable = NEW.readable THEN RETURN NULL; END IF;
    SELECT * INTO j FROM bri.csv_jobs x WHERE (x.tenant_id,x.proposal_id) = (r.tenant_id,r.source_id);
    IF NOT FOUND OR (allowed IS TRUE AND (j.state <> 'approved' OR NOT EXISTS (
        SELECT FROM bri.validated_knowledge v WHERE v.csv_governed
          AND (v.tenant_id,v.proposal_id)=(j.tenant_id,j.proposal_id)))) THEN
        RAISE EXCEPTION 'CSV policy requires governed approval' USING ERRCODE = '42501';
    END IF;
    IF TG_TABLE_NAME = 'knowledge_version_access' THEN
        IF r.source_version_id <> j.proposal_id THEN
            RAISE EXCEPTION 'CSV access policy version does not match' USING ERRCODE = '42501';
        END IF;
        action := 'version_access';
    ELSE
        action := 'record_access';
    END IF;
    PERFORM bri.csv_audit(j,action,gen_random_uuid(),NULL,NULL,allowed);
    RETURN NULL;
END $$;
CREATE TRIGGER csv_record_policy_audit AFTER INSERT OR UPDATE OR DELETE ON bri.knowledge_record_access
FOR EACH ROW EXECUTE FUNCTION bri.csv_policy_audit();
CREATE TRIGGER csv_version_policy_audit AFTER INSERT OR UPDATE OR DELETE ON bri.knowledge_version_access
FOR EACH ROW EXECUTE FUNCTION bri.csv_policy_audit();

REVOKE ALL ON FUNCTION bri.csv_guard_synthetic_attribution(),bri.csv_user_job(text,uuid,uuid,uuid,text,uuid),
    bri.csv_mark_ready(text,uuid,uuid,text,uuid,uuid),bri.csv_status(text,uuid,uuid,text,uuid,uuid),
    bri.csv_claim(uuid,uuid),bri.csv_complete(uuid,integer,text,text,integer,integer,uuid),
    bri.csv_fail(uuid,integer,text,boolean,uuid),bri.csv_review(text,uuid,uuid,text,text,text,uuid),
    bri.csv_policy_audit() FROM PUBLIC,bri_app;

-- The release role cannot read governed lineage or its policy metadata.
CREATE POLICY csv_metadata_legacy_record ON bri.knowledge_record_access AS RESTRICTIVE FOR SELECT TO bri_app
    USING (EXISTS (SELECT FROM bri.source_records s WHERE (s.tenant_id,s.source_id) =
           (knowledge_record_access.tenant_id,knowledge_record_access.source_id)));
CREATE POLICY csv_metadata_legacy_version ON bri.knowledge_version_access AS RESTRICTIVE FOR SELECT TO bri_app
    USING (EXISTS (SELECT FROM bri.source_records s WHERE (s.tenant_id,s.source_id) =
           (knowledge_version_access.tenant_id,knowledge_version_access.source_id)));

-- Only an explicitly provisioned local reader is trusted to pass a verified
-- provider identity. No release EXECUTE and no authority from caller GUCs.
CREATE POLICY csv_read_record_gate ON bri.knowledge_record_access FOR SELECT TO bri_migrator
    USING (session_user='bri_csv_reader' AND inet_server_addr() IS NULL AND current_setting('listen_addresses')='');
CREATE POLICY csv_read_version_gate ON bri.knowledge_version_access FOR SELECT TO bri_migrator
    USING (session_user='bri_csv_reader' AND inet_server_addr() IS NULL AND current_setting('listen_addresses')='');
CREATE FUNCTION bri.csv_read_published(t text, actor uuid, sub uuid, sid uuid, issuer text)
RETURNS TABLE(proposal_id text, tenant_id text, scope_node_id text, proposed_by text, proposed_at timestamptz,
              title text, source_id text, source_version_id text, version_label text, extraction_id text,
              content text, content_sha256 text, extractor_name text, extractor_version text, source_location text,
              original_sha256 text, first_line integer, last_line integer)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF session_user <> 'bri_csv_reader' OR inet_server_addr() IS NOT NULL
       OR current_setting('listen_addresses') <> '' THEN
        RAISE EXCEPTION 'CSV published read denied' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY
    SELECT p.proposal_id,p.tenant_id,p.scope_node_id,p.proposed_by,p.proposed_at,
           s.title,s.source_id,sv.source_version_id,sv.version_label,x.extraction_id,x.content,
           x.content_sha256,x.extractor_name,x.extractor_version,x.source_location,e.original_sha256,e.first_line,e.last_line
    FROM bri.csv_jobs j
    JOIN bri.knowledge_proposals p ON (p.tenant_id,p.proposal_id,p.scope_node_id,p.csv_creator_id) =
                                      (j.tenant_id,j.proposal_id,j.scope_node_id,j.creator_id)
    JOIN bri.validated_knowledge k ON (k.tenant_id,k.proposal_id)=(p.tenant_id,p.proposal_id) AND k.csv_governed
    JOIN bri.source_extractions x ON (x.tenant_id,x.extraction_id,x.scope_node_id) =
                                      (p.tenant_id,p.extraction_id,p.scope_node_id) AND x.csv_governed
    JOIN bri.source_records s ON (s.tenant_id,s.source_id,s.scope_node_id) =
                                  (x.tenant_id,x.source_id,x.scope_node_id) AND s.csv_governed
    JOIN bri.source_versions sv ON (sv.tenant_id,sv.source_id,sv.source_version_id) =
                                    (x.tenant_id,x.source_id,x.source_version_id) AND sv.csv_governed
    JOIN bri.knowledge_record_access r ON (r.tenant_id,r.source_id)=(s.tenant_id,s.source_id) AND r.readable
    JOIN bri.knowledge_version_access v ON (v.tenant_id,v.source_id,v.source_version_id) =
                                           (sv.tenant_id,sv.source_id,sv.source_version_id) AND v.readable
    LEFT JOIN bri.csv_source_evidence e ON (e.tenant_id,e.source_id,e.source_version_id) =
                                            (sv.tenant_id,sv.source_id,sv.source_version_id)
    WHERE j.tenant_id=$1 AND j.state='approved' AND s.source_id=j.proposal_id AND sv.source_version_id=j.proposal_id
      AND bri.csv_has_authority($1,$2,$3,$4,$5,j.scope_node_id,'knowledge:read')
    ORDER BY p.proposed_at,p.proposal_id;
END $$;
REVOKE ALL ON FUNCTION bri.csv_read_published(text,uuid,uuid,uuid,text) FROM PUBLIC,bri_app;

CREATE INDEX csv_pending_tenant_age_idx ON bri.csv_jobs (tenant_id,created_at,job_id) WHERE state='proposed';
CREATE FUNCTION bri.csv_pending_review(t text, actor uuid, sid uuid, issuer text, correlation uuid)
RETURNS TABLE(proposal_id text,scope_node_id text,extracted_text text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE sub uuid := nullif(current_setting('bri.auth_user_id',true),'')::uuid;
BEGIN
    IF session_user <> 'bri_csv_intake' OR correlation IS NULL THEN
        RAISE EXCEPTION 'CSV review denied' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY SELECT j.proposal_id,j.scope_node_id,x.content
        FROM bri.csv_jobs j JOIN bri.source_extractions x ON (x.tenant_id,x.extraction_id) = (j.tenant_id,j.proposal_id)
        WHERE j.tenant_id=t AND j.state='proposed' AND actor NOT IN (j.actor_id,j.creator_id)
          AND bri.csv_has_authority(t,actor,sub,sid,$4,j.scope_node_id,'knowledge:review')
        ORDER BY j.created_at,j.job_id LIMIT 20;
END $$;
REVOKE ALL ON FUNCTION bri.csv_pending_review(text,uuid,uuid,text,uuid) FROM PUBLIC,bri_app;
