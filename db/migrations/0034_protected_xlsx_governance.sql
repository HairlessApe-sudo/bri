-- Private local XLSX governance. No stage login, grant, or assignment is provisioned.
CREATE TABLE bri.xlsx_review_decisions (
    tenant_id text NOT NULL,
    job_id uuid NOT NULL,
    actor_id uuid NOT NULL,
    request_id uuid NOT NULL,
    decision text NOT NULL CHECK (decision IN ('approve','reject')),
    decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,job_id),
    UNIQUE (tenant_id,job_id,decision),
    UNIQUE (tenant_id,actor_id,request_id),
    FOREIGN KEY (tenant_id,job_id) REFERENCES bri.xlsx_pending_proposals,
    FOREIGN KEY (tenant_id,actor_id) REFERENCES bri.auth_tenant_memberships
);

CREATE TABLE bri.xlsx_validated_knowledge (
    tenant_id text NOT NULL,
    record_id uuid NOT NULL DEFAULT gen_random_uuid(),
    job_id uuid NOT NULL,
    decision text NOT NULL DEFAULT 'approve' CHECK (decision = 'approve'),
    PRIMARY KEY (tenant_id,record_id),
    UNIQUE (tenant_id,job_id),
    UNIQUE (tenant_id,record_id,job_id),
    FOREIGN KEY (tenant_id,job_id,decision) REFERENCES bri.xlsx_review_decisions (tenant_id,job_id,decision),
    FOREIGN KEY (tenant_id,job_id) REFERENCES bri.xlsx_source_versions
);

CREATE TABLE bri.xlsx_publication_events (
    tenant_id text NOT NULL,
    record_id uuid NOT NULL,
    job_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    action text NOT NULL CHECK (action IN ('publish','withdraw')),
    actor_id uuid NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,record_id,revision),
    FOREIGN KEY (tenant_id,record_id,job_id) REFERENCES bri.xlsx_validated_knowledge (tenant_id,record_id,job_id),
    FOREIGN KEY (tenant_id,actor_id) REFERENCES bri.auth_tenant_memberships
);

CREATE TABLE bri.xlsx_record_access (
    tenant_id text NOT NULL,
    record_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    PRIMARY KEY (tenant_id,record_id,principal_id),
    FOREIGN KEY (tenant_id,record_id) REFERENCES bri.xlsx_validated_knowledge,
    FOREIGN KEY (tenant_id,principal_id) REFERENCES bri.auth_tenant_memberships
);

CREATE TABLE bri.xlsx_version_access (
    tenant_id text NOT NULL,
    record_id uuid NOT NULL,
    job_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    PRIMARY KEY (tenant_id,record_id,job_id,principal_id),
    FOREIGN KEY (tenant_id,record_id,job_id) REFERENCES bri.xlsx_validated_knowledge (tenant_id,record_id,job_id),
    FOREIGN KEY (tenant_id,principal_id) REFERENCES bri.auth_tenant_memberships
);

CREATE TABLE bri.xlsx_governance_audit_events (
    tenant_id text NOT NULL,
    event_id uuid NOT NULL DEFAULT gen_random_uuid(),
    job_id uuid NOT NULL,
    actor_id uuid NOT NULL,
    target_id uuid,
    correlation uuid NOT NULL,
    event text NOT NULL CHECK (event IN ('approve','reject','publish','withdraw','record_grant',
        'record_revoke','version_grant','version_revoke')),
    state_changed boolean NOT NULL DEFAULT true,
    publication_revision bigint,
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id,event_id),
    FOREIGN KEY (tenant_id,job_id) REFERENCES bri.xlsx_pending_proposals,
    FOREIGN KEY (tenant_id,actor_id) REFERENCES bri.auth_tenant_memberships,
    FOREIGN KEY (tenant_id,target_id) REFERENCES bri.auth_tenant_memberships,
    CHECK ((target_id IS NOT NULL) = (event IN ('record_grant','record_revoke','version_grant','version_revoke'))),
    CHECK ((publication_revision IS NOT NULL) = (event IN ('publish','withdraw'))),
    CHECK (publication_revision > 0 OR (publication_revision = 0 AND event = 'withdraw' AND NOT state_changed))
);

-- Maintenance correlation is a tenant-scoped request key, shared across the
-- three mutation entry points. Review has its own explicit request_id instead.
CREATE UNIQUE INDEX xlsx_governance_maintenance_request
    ON bri.xlsx_governance_audit_events (tenant_id,correlation) WHERE event NOT IN ('approve','reject');

DO $private$
DECLARE rel text;
BEGIN
    FOREACH rel IN ARRAY ARRAY['xlsx_review_decisions','xlsx_validated_knowledge','xlsx_publication_events',
                              'xlsx_record_access','xlsx_version_access','xlsx_governance_audit_events'] LOOP
        EXECUTE format('ALTER TABLE bri.%I ENABLE ROW LEVEL SECURITY', rel);
        EXECUTE format('ALTER TABLE bri.%I FORCE ROW LEVEL SECURITY', rel);
        EXECUTE format('REVOKE ALL ON bri.%I FROM PUBLIC,bri_app', rel);
        EXECUTE format('CREATE POLICY xlsx_governance_owner_read ON bri.%I FOR SELECT TO bri_migrator USING (true)', rel);
        EXECUTE format('CREATE POLICY xlsx_governance_owner_insert ON bri.%I FOR INSERT TO bri_migrator WITH CHECK (true)', rel);
        IF rel IN ('xlsx_record_access','xlsx_version_access') THEN
            EXECUTE format('CREATE POLICY xlsx_governance_owner_delete ON bri.%I FOR DELETE TO bri_migrator USING (true)', rel);
        ELSE
            EXECUTE format('CREATE TRIGGER xlsx_governance_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON bri.%I
                            FOR EACH STATEMENT EXECUTE FUNCTION bri.xlsx_immutable()', rel);
        END IF;
    END LOOP;
END $private$;

CREATE POLICY xlsx_governance_bound_issuer ON bri.provider_event_source FOR SELECT TO bri_migrator
    USING (session_user IN ('bri_xlsx_reviewer','bri_xlsx_publication_maintainer',
           'bri_xlsx_access_maintainer','bri_xlsx_reader') AND inet_server_addr() IS NULL
           AND current_setting('listen_addresses') = '');

CREATE FUNCTION bri.xlsx_governance_role(expected text) RETURNS void
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM bri.xlsx_require_role(expected);
    IF current_setting('listen_addresses') <> '' THEN
        RAISE EXCEPTION 'XLSX role denied' USING ERRCODE='42501';
    END IF;
    -- Do not admit a retained transaction snapshot from before revocation.
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'XLSX governance requires read committed' USING ERRCODE='25001';
    END IF;
END $$;

-- The 0033 submit predicate is mirrored intentionally: this slice accepts only
-- these four explicit exact-node permissions, never implies them from a title.
CREATE FUNCTION bri.xlsx_governance_authorized(t text, actor uuid, sub uuid, sid uuid,
                                              issuer text, node text, permission text)
RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT $7 IN ('knowledge:review','knowledge:read','knowledge:publish','knowledge:access_manage')
      AND EXISTS (SELECT FROM bri.provider_event_source src WHERE src.issuer=$5)
      AND EXISTS (SELECT FROM bri.client_activation a JOIN bri.tenant_admin_policies ap USING (tenant_id)
                  WHERE a.tenant_id=$1 AND (SELECT count(*) FROM bri.governance_eligible e WHERE e.tenant_id=$1)
                        >= ap.min_emergency_admins)
      AND EXISTS (
        SELECT FROM bri.auth_sessions s JOIN bri.auth_identity_links i USING (auth_user_id,principal_id)
        JOIN bri.auth_principals p USING (principal_id) JOIN bri.auth_tenant_memberships m USING (principal_id)
        LEFT JOIN bri.session_guards g USING (principal_id)
        WHERE (s.principal_id,s.auth_user_id,s.session_id,m.tenant_id)=($2,$3,$4,$1)
          AND i.auth_issuer=$5 AND i.auth_subject=$3::text AND i.status='active' AND i.provider_type='native'
          AND s.revoked_at IS NULL AND s.started_at<=clock_timestamp()
          AND clock_timestamp()<least(s.expires_at,s.started_at+interval '8 hours')
          AND s.started_at>coalesce(g.primary_after,'-infinity'::timestamptz)
          AND p.status='active' AND p.deletion_requested_at IS NULL AND m.status='active'
          AND m.membership_type IN ('user','superuser','admin')
          AND NOT EXISTS (SELECT FROM bri.auth_tenant_memberships x WHERE x.principal_id=$2 AND x.tenant_id<>$1)
          AND NOT EXISTS (SELECT FROM bri.platform_superadmins x WHERE x.principal_id=$2)
          AND NOT EXISTS (SELECT FROM bri.credential_operations c WHERE c.principal_id=$2 AND c.confirmed_at IS NULL)
      ) AND EXISTS (
        SELECT FROM bri.auth_role_assignments a JOIN bri.role_permissions rp USING (tenant_id,role_id)
        WHERE (a.tenant_id,a.principal_id,a.scope_node_id,rp.permission)=($1,$2,$6,$7) AND a.status='active'
      );
$$;

CREATE FUNCTION bri.xlsx_review_visible(t text, actor uuid, sub uuid, sid uuid, issuer text)
RETURNS TABLE(job_id uuid,node_id text,state text) LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT j.job_id,j.scope_node_id,CASE d.decision WHEN 'approve' THEN 'approved' WHEN 'reject' THEN 'rejected' ELSE 'proposed' END
    FROM bri.xlsx_jobs j JOIN bri.xlsx_pending_proposals p USING (tenant_id,job_id)
    LEFT JOIN bri.xlsx_review_decisions d USING (tenant_id,job_id)
    WHERE j.tenant_id=$1 AND j.state='proposed' AND $2 NOT IN (j.actor_id,j.creator_id)
      AND bri.xlsx_governance_authorized($1,$2,$3,$4,$5,j.scope_node_id,'knowledge:review');
$$;

CREATE FUNCTION bri.xlsx_review_queue(t text, actor uuid, sub uuid, sid uuid, issuer text,
                                     after_id uuid, page_size integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM bri.xlsx_governance_role('bri_xlsx_reviewer');
    IF page_size IS NULL OR page_size NOT BETWEEN 1 AND 21 THEN
        RAISE EXCEPTION 'Invalid XLSX review page' USING ERRCODE='22023';
    END IF;
    RETURN (WITH visible AS NOT MATERIALIZED (SELECT * FROM bri.xlsx_review_visible(t,actor,sub,sid,issuer)),
        page AS (SELECT v.* FROM visible v WHERE after_id IS NULL OR (v.job_id>after_id AND
                 EXISTS (SELECT FROM visible a WHERE a.job_id=after_id)) ORDER BY v.job_id LIMIT page_size)
        SELECT coalesce(jsonb_agg(to_jsonb(page) ORDER BY page.job_id),'[]'::jsonb) FROM page);
END $$;

CREATE FUNCTION bri.xlsx_worksheet_frame(t text, job uuid) RETURNS jsonb
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT jsonb_build_object('source_version_id',job,'sheet_id',v.sheet_id,'sheet_title',v.sheet_title,
        'cell_range',v.cell_range,'original_sha256',v.original_sha256,'canonical_sha256',v.canonical_sha256,
        'extractor_version',x.extractor_version,'canonicalization_version',x.canonicalization_version,
        'rows',x.canonical_text::jsonb->'rows')
    FROM bri.xlsx_source_versions v JOIN bri.xlsx_extractions x USING (tenant_id,job_id,canonical_sha256)
    WHERE (v.tenant_id,v.job_id)=(t,job);
$$;

CREATE FUNCTION bri.xlsx_review_detail(t text, actor uuid, sub uuid, sid uuid, issuer text, job uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE visible record;
BEGIN
    PERFORM bri.xlsx_governance_role('bri_xlsx_reviewer');
    SELECT v.* INTO visible FROM bri.xlsx_review_visible(t,actor,sub,sid,issuer) v WHERE v.job_id=job;
    IF NOT FOUND THEN RETURN NULL; END IF;
    RETURN to_jsonb(visible) || bri.xlsx_worksheet_frame(t,job);
END $$;

CREATE FUNCTION bri.xlsx_review_decide(t text, actor uuid, sub uuid, sid uuid, issuer text,
                                      job uuid, action text, request_id uuid, correlation uuid) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE j bri.xlsx_jobs; prior bri.xlsx_review_decisions;
BEGIN
    PERFORM bri.xlsx_governance_role('bri_xlsx_reviewer');
    IF action IS NULL OR action NOT IN ('approve','reject') OR request_id IS NULL OR correlation IS NULL THEN
        RAISE EXCEPTION 'Invalid XLSX decision' USING ERRCODE='22023';
    END IF;
    -- No locks (not even the shared mutation fence) for a hidden request.
    IF NOT EXISTS (SELECT FROM bri.xlsx_review_visible(t,actor,sub,sid,issuer) v WHERE v.job_id=job) THEN
        RETURN NULL;
    END IF;
    PERFORM bri.xlsx_lock_actor(actor,sub,sid);
    SELECT x.* INTO j FROM bri.xlsx_jobs x WHERE (x.tenant_id,x.job_id)=(t,job)
      AND EXISTS (SELECT FROM bri.xlsx_review_visible(t,actor,sub,sid,xlsx_review_decide.issuer) v WHERE v.job_id=x.job_id)
      FOR UPDATE;
    IF NOT FOUND OR NOT EXISTS (SELECT FROM bri.xlsx_review_visible(t,actor,sub,sid,issuer) v WHERE v.job_id=job) THEN
        RETURN NULL;
    END IF;
    SELECT d.* INTO prior FROM bri.xlsx_review_decisions d WHERE (d.tenant_id,d.job_id)=(t,job);
    IF FOUND THEN
        IF (prior.actor_id,prior.request_id,prior.decision) IS DISTINCT FROM (actor,request_id,action) THEN
            RAISE EXCEPTION 'XLSX decision conflict' USING ERRCODE='23505';
        END IF;
    ELSE
        INSERT INTO bri.xlsx_review_decisions (tenant_id,job_id,actor_id,request_id,decision)
        VALUES (t,job,actor,request_id,action);
        IF action='approve' THEN
            INSERT INTO bri.xlsx_validated_knowledge (tenant_id,job_id) VALUES (t,job);
        END IF;
        INSERT INTO bri.xlsx_governance_audit_events (tenant_id,job_id,actor_id,correlation,event)
        VALUES (t,job,actor,correlation,action);
    END IF;
    RETURN action;
END $$;

REVOKE ALL ON FUNCTION bri.xlsx_governance_role(text),
    bri.xlsx_governance_authorized(text,uuid,uuid,uuid,text,text,text),
    bri.xlsx_review_visible(text,uuid,uuid,uuid,text), bri.xlsx_worksheet_frame(text,uuid),
    bri.xlsx_review_queue(text,uuid,uuid,uuid,text,uuid,integer),
    bri.xlsx_review_detail(text,uuid,uuid,uuid,text,uuid),
    bri.xlsx_review_decide(text,uuid,uuid,uuid,text,uuid,text,uuid,uuid) FROM PUBLIC,bri_app;

CREATE FUNCTION bri.xlsx_governed_record(t text, actor uuid, sub uuid, sid uuid, issuer text,
                                       record uuid, version uuid, permission text)
RETURNS TABLE(record_id uuid,job_id uuid,node_id text) LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT k.record_id,k.job_id,j.scope_node_id
    FROM bri.xlsx_validated_knowledge k JOIN bri.xlsx_jobs j USING (tenant_id,job_id)
    WHERE (k.tenant_id,k.record_id)=($1,$6) AND ($7 IS NULL OR k.job_id=$7)
      AND bri.xlsx_governance_authorized($1,$2,$3,$4,$5,j.scope_node_id,$8);
$$;

CREATE FUNCTION bri.xlsx_publication_change(t text, actor uuid, sub uuid, sid uuid, issuer text,
                                           record_id uuid, version uuid, action text, correlation uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE prior bri.xlsx_publication_events; receipt bri.xlsx_governance_audit_events;
        next_revision bigint; changed boolean;
BEGIN
    PERFORM bri.xlsx_governance_role('bri_xlsx_publication_maintainer');
    IF action IS NULL OR action NOT IN ('publish','withdraw') OR correlation IS NULL OR version IS NULL THEN
        RAISE EXCEPTION 'Invalid XLSX publication' USING ERRCODE='22023';
    END IF;
    IF NOT EXISTS (SELECT FROM bri.xlsx_governed_record(t,actor,sub,sid,issuer,record_id,version,'knowledge:publish')) THEN
        RETURN NULL;
    END IF;
    -- The same fence serializes publication, access changes and live authority
    -- writers. Inspect state only in a fresh snapshot after acquiring it.
    PERFORM bri.xlsx_lock_actor(actor,sub,sid);
    IF NOT EXISTS (SELECT FROM bri.xlsx_governed_record(t,actor,sub,sid,issuer,record_id,version,'knowledge:publish')) THEN
        RETURN NULL;
    END IF;
    -- The immutable validated record has exactly one job per tenant, which
    -- binds both the record and version without duplicating their identifiers.
    SELECT a.* INTO receipt FROM bri.xlsx_governance_audit_events a
    WHERE (a.tenant_id,a.correlation)=(t,xlsx_publication_change.correlation) AND a.event NOT IN ('approve','reject');
    IF FOUND THEN
        IF (receipt.job_id,receipt.actor_id,receipt.event) IS DISTINCT FROM (version,actor,action) THEN
            RAISE EXCEPTION 'XLSX governance request conflict' USING ERRCODE='23505';
        END IF;
        next_revision := receipt.publication_revision;
    ELSE
        SELECT p.* INTO prior FROM bri.xlsx_publication_events p
        WHERE (p.tenant_id,p.record_id)=(t,xlsx_publication_change.record_id) ORDER BY p.revision DESC LIMIT 1;
        next_revision := coalesce(prior.revision,0);
        changed := coalesce(prior.action,'withdraw') <> action;
        IF changed THEN
            next_revision := next_revision+1;
            INSERT INTO bri.xlsx_publication_events (tenant_id,record_id,job_id,revision,action,actor_id)
            VALUES (t,record_id,version,next_revision,action,actor);
        END IF;
        INSERT INTO bri.xlsx_governance_audit_events (tenant_id,job_id,actor_id,correlation,event,state_changed,publication_revision)
        VALUES (t,version,actor,correlation,action,changed,next_revision);
    END IF;
    -- A retry acknowledges the original request, not the current state.
    RETURN jsonb_build_object('record_id',record_id,'source_version_id',version,
        'state',CASE WHEN next_revision=0 THEN 'unpublished' WHEN action='publish' THEN 'published' ELSE 'withdrawn' END,
        'revision',next_revision);
END $$;

REVOKE ALL ON FUNCTION bri.xlsx_governed_record(text,uuid,uuid,uuid,text,uuid,uuid,text),
    bri.xlsx_publication_change(text,uuid,uuid,uuid,text,uuid,uuid,text,uuid) FROM PUBLIC,bri_app;

CREATE FUNCTION bri.xlsx_change_access(t text, actor uuid, sub uuid, sid uuid, issuer text,
                                       record_id uuid, version uuid, target uuid,
                                       allow_access boolean, correlation uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, pg_temp AS $$
DECLARE governed record; audit_event text; receipt bri.xlsx_governance_audit_events; changed boolean;
BEGIN
    IF target IS NULL OR allow_access IS NULL OR correlation IS NULL THEN
        RAISE EXCEPTION 'Invalid XLSX access change' USING ERRCODE='22023';
    END IF;
    IF (allow_access AND target=actor) OR NOT EXISTS (
        SELECT FROM bri.xlsx_governed_record(t,actor,sub,sid,issuer,record_id,version,'knowledge:access_manage')
    ) THEN RETURN NULL; END IF;
    PERFORM bri.xlsx_lock_actor(actor,sub,sid);
    SELECT x.* INTO governed FROM
        bri.xlsx_governed_record(t,actor,sub,sid,issuer,record_id,version,'knowledge:access_manage') x;
    IF NOT FOUND THEN RETURN NULL; END IF;
    -- Revocation may still remove an inactive member's retained gate, but an
    -- absent or foreign target is hidden and must not reveal key collisions.
    IF allow_access THEN
        IF NOT bri.xlsx_creator_active(t,target,issuer) THEN RETURN NULL; END IF;
    ELSIF NOT EXISTS (SELECT FROM bri.auth_tenant_memberships m WHERE (m.tenant_id,m.principal_id)=(t,target)) THEN
        RETURN NULL;
    END IF;
    audit_event := (CASE WHEN version IS NULL THEN 'record_' ELSE 'version_' END)
                   || (CASE WHEN allow_access THEN 'grant' ELSE 'revoke' END);
    SELECT a.* INTO receipt FROM bri.xlsx_governance_audit_events a
    WHERE (a.tenant_id,a.correlation)=(t,xlsx_change_access.correlation) AND a.event NOT IN ('approve','reject');
    IF FOUND THEN
        IF (receipt.job_id,receipt.actor_id,receipt.target_id,receipt.event)
            IS DISTINCT FROM (governed.job_id,actor,target,audit_event) THEN
            RAISE EXCEPTION 'XLSX governance request conflict' USING ERRCODE='23505';
        END IF;
        RETURN allow_access;
    END IF;
    IF version IS NULL THEN
        IF allow_access THEN
            INSERT INTO bri.xlsx_record_access (tenant_id,record_id,principal_id)
            VALUES (t,governed.record_id,target) ON CONFLICT DO NOTHING;
        ELSE
            DELETE FROM bri.xlsx_record_access a WHERE (a.tenant_id,a.record_id,a.principal_id)=(t,governed.record_id,target);
        END IF;
    ELSE
        IF allow_access THEN
            INSERT INTO bri.xlsx_version_access (tenant_id,record_id,job_id,principal_id)
            VALUES (t,governed.record_id,version,target) ON CONFLICT DO NOTHING;
        ELSE
            DELETE FROM bri.xlsx_version_access a WHERE (a.tenant_id,a.record_id,a.job_id,a.principal_id)=(t,governed.record_id,version,target);
        END IF;
    END IF;
    changed := FOUND;
    INSERT INTO bri.xlsx_governance_audit_events (tenant_id,job_id,actor_id,target_id,correlation,event,state_changed)
    VALUES (t,governed.job_id,actor,target,correlation,audit_event,changed);
    RETURN allow_access;
END $$;

CREATE FUNCTION bri.xlsx_record_access_change(t text, actor uuid, sub uuid, sid uuid, issuer text,
                                            record_id uuid, target uuid, allow_access boolean, correlation uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM bri.xlsx_governance_role('bri_xlsx_access_maintainer');
    RETURN bri.xlsx_change_access(t,actor,sub,sid,issuer,record_id,NULL,target,allow_access,correlation);
END $$;

CREATE FUNCTION bri.xlsx_version_access_change(t text, actor uuid, sub uuid, sid uuid, issuer text,
                                              record_id uuid, version uuid, target uuid, allow_access boolean,
                                              correlation uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM bri.xlsx_governance_role('bri_xlsx_access_maintainer');
    IF version IS NULL THEN RETURN NULL; END IF;
    RETURN bri.xlsx_change_access(t,actor,sub,sid,issuer,record_id,version,target,allow_access,correlation);
END $$;

-- These STABLE reader operations share the statement snapshot for permission,
-- current publication, both targeted gates, provenance and worksheet bytes.
CREATE FUNCTION bri.xlsx_readable_record(t text, actor uuid, sub uuid, sid uuid, issuer text,
                                        record_id uuid, version uuid)
RETURNS TABLE(record_id_out uuid,job_id uuid,node_id text) LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT k.record_id,k.job_id,k.node_id
    FROM bri.xlsx_governed_record($1,$2,$3,$4,$5,$6,$7,'knowledge:read') k
    WHERE 'publish'=(SELECT p.action FROM bri.xlsx_publication_events p
                     WHERE (p.tenant_id,p.record_id)=($1,k.record_id) ORDER BY p.revision DESC LIMIT 1)
      AND EXISTS (SELECT FROM bri.xlsx_record_access a WHERE (a.tenant_id,a.record_id,a.principal_id)=($1,k.record_id,$2))
      AND EXISTS (SELECT FROM bri.xlsx_version_access a
                  WHERE (a.tenant_id,a.record_id,a.job_id,a.principal_id)=($1,k.record_id,k.job_id,$2));
$$;

CREATE FUNCTION bri.xlsx_published_detail(t text, actor uuid, sub uuid, sid uuid, issuer text, record_id uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM bri.xlsx_governance_role('bri_xlsx_reader');
    RETURN (SELECT jsonb_build_object('record_id',k.record_id_out,'source_version_id',k.job_id,
             'node_id',k.node_id,'state','published')
            FROM bri.xlsx_readable_record(t,actor,sub,sid,issuer,record_id,NULL) k);
END $$;

CREATE FUNCTION bri.xlsx_published_evidence(t text, actor uuid, sub uuid, sid uuid, issuer text,
                                           record_id uuid, version uuid) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    PERFORM bri.xlsx_governance_role('bri_xlsx_reader');
    IF version IS NULL THEN RETURN NULL; END IF;
    RETURN (SELECT jsonb_build_object('record_id',k.record_id_out,'source_version_id',k.job_id,
             'node_id',k.node_id,'state','published') || bri.xlsx_worksheet_frame(t,k.job_id)
            FROM bri.xlsx_readable_record(t,actor,sub,sid,issuer,record_id,version) k);
END $$;

REVOKE ALL ON FUNCTION bri.xlsx_change_access(text,uuid,uuid,uuid,text,uuid,uuid,uuid,boolean,uuid),
    bri.xlsx_record_access_change(text,uuid,uuid,uuid,text,uuid,uuid,boolean,uuid),
    bri.xlsx_version_access_change(text,uuid,uuid,uuid,text,uuid,uuid,uuid,boolean,uuid),
    bri.xlsx_readable_record(text,uuid,uuid,uuid,text,uuid,uuid),
    bri.xlsx_published_detail(text,uuid,uuid,uuid,text,uuid),
    bri.xlsx_published_evidence(text,uuid,uuid,uuid,text,uuid,uuid) FROM PUBLIC,bri_app;
