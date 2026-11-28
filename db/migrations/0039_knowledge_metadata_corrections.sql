-- A19.1 exact-version metadata reads and corrections. No changes to native
-- provenance, publication, record access or version access decisions.
CREATE TABLE bri.knowledge_metadata_correction_proposals (
    tenant_id text NOT NULL,
    format text NOT NULL CHECK (format IN ('csv','xlsx')),
    job_id uuid NOT NULL,
    record_id uuid NOT NULL,
    proposer_id uuid NOT NULL,
    proposal_id uuid NOT NULL DEFAULT gen_random_uuid(),
    request_id uuid NOT NULL,
    correlation uuid NOT NULL,
    expected_revision bigint NOT NULL CHECK (expected_revision>=0),
    payload_id uuid NOT NULL,
    proposed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    csv_ref text GENERATED ALWAYS AS (CASE WHEN format='csv' THEN 'csv:'||job_id::text END) STORED,
    csv_version text GENERATED ALWAYS AS (CASE WHEN format='csv' THEN 'csv:'||job_id::text END) STORED,
    xlsx_job uuid GENERATED ALWAYS AS (CASE WHEN format='xlsx' THEN job_id END) STORED,
    xlsx_record uuid GENERATED ALWAYS AS (CASE WHEN format='xlsx' THEN record_id END) STORED,
    CHECK (format <> 'csv' OR record_id=job_id),
    PRIMARY KEY (tenant_id,format,job_id,proposal_id),
    UNIQUE (tenant_id,format,proposer_id,request_id),
    UNIQUE (tenant_id,format,job_id,proposal_id,proposer_id),
    FOREIGN KEY (tenant_id,proposer_id) REFERENCES bri.auth_tenant_memberships,
    FOREIGN KEY (tenant_id,csv_ref) REFERENCES bri.validated_knowledge (tenant_id,proposal_id),
    FOREIGN KEY (tenant_id,csv_ref,csv_version) REFERENCES bri.source_versions (tenant_id,source_id,source_version_id),
    FOREIGN KEY (tenant_id,xlsx_record,xlsx_job) REFERENCES bri.xlsx_validated_knowledge (tenant_id,record_id,job_id),
    FOREIGN KEY (tenant_id,payload_id) REFERENCES bri.knowledge_metadata_payloads
);
CREATE TABLE bri.knowledge_metadata_correction_decisions (
    tenant_id text NOT NULL,
    format text NOT NULL,
    job_id uuid NOT NULL,
    proposal_id uuid NOT NULL,
    proposer_id uuid NOT NULL,
    reviewer_id uuid NOT NULL CHECK (reviewer_id <> proposer_id),
    request_id uuid NOT NULL,
    correlation uuid NOT NULL,
    decision text NOT NULL CHECK (decision IN ('approve','reject')),
    metadata_revision bigint,
    decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK ((decision='approve')=(metadata_revision IS NOT NULL)),
    PRIMARY KEY (tenant_id,format,job_id,proposal_id),
    UNIQUE (tenant_id,format,reviewer_id,request_id),
    FOREIGN KEY (tenant_id,format,job_id,proposal_id,proposer_id)
        REFERENCES bri.knowledge_metadata_correction_proposals (tenant_id,format,job_id,proposal_id,proposer_id),
    FOREIGN KEY (tenant_id,reviewer_id) REFERENCES bri.auth_tenant_memberships,
    FOREIGN KEY (tenant_id,format,job_id,metadata_revision) REFERENCES bri.knowledge_metadata_revisions
);

CREATE INDEX km_correction_review_page ON bri.knowledge_metadata_correction_proposals
    (tenant_id,format,job_id,expected_revision,proposal_id);

DO $private$
DECLARE rel text;
BEGIN
    FOREACH rel IN ARRAY ARRAY['knowledge_metadata_correction_proposals','knowledge_metadata_correction_decisions'] LOOP
        EXECUTE format('ALTER TABLE bri.%I ENABLE ROW LEVEL SECURITY',rel);
        EXECUTE format('ALTER TABLE bri.%I FORCE ROW LEVEL SECURITY',rel);
        EXECUTE format('REVOKE ALL ON bri.%I FROM PUBLIC,bri_app',rel);
        EXECUTE format('CREATE POLICY km_owner_read ON bri.%I FOR SELECT TO bri_migrator USING (true)',rel);
        EXECUTE format('CREATE POLICY km_owner_insert ON bri.%I FOR INSERT TO bri_migrator WITH CHECK (true)',rel);
        EXECUTE format('CREATE TRIGGER km_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON bri.%I
                        FOR EACH STATEMENT EXECUTE FUNCTION bri.xlsx_immutable()',rel);
    END LOOP;
END $private$;

-- CSV policy maintenance is direct DB-only (0020/0030), unlike the XLSX
-- commands, which already acquire the governance fence before their writes.
-- Take the same fence before touching policy rows, so a correction either
-- precedes a revocation or rechecks after it, without taking access write locks.
-- TRUNCATE already conflicts with the preflight's table read lock; taking the
-- fence after its ACCESS EXCLUSIVE lock would invert the correction order.
CREATE TRIGGER km_record_access_fence BEFORE INSERT OR UPDATE OR DELETE ON bri.knowledge_record_access
    FOR EACH STATEMENT EXECUTE FUNCTION bri.governance_serialize();
CREATE TRIGGER km_version_access_fence BEFORE INSERT OR UPDATE OR DELETE ON bri.knowledge_version_access
    FOR EACH STATEMENT EXECUTE FUNCTION bri.governance_serialize();

CREATE FUNCTION bri.km_exact_node(t text,actor uuid,sub uuid,sid uuid,issuer text,record_id uuid,version uuid,fmt text)
RETURNS text LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE node text;
BEGIN
    IF record_id IS NULL OR version IS NULL THEN RETURN NULL; END IF;
    IF fmt='xlsx' THEN
        RETURN (SELECT k.node_id FROM bri.xlsx_readable_record(t,actor,sub,sid,issuer,record_id,version) k);
    END IF;
    IF record_id IS DISTINCT FROM version THEN RETURN NULL; END IF;
    SELECT j.scope_node_id INTO node FROM bri.csv_jobs j WHERE (j.tenant_id,j.job_id)=(t,record_id);
    IF NOT FOUND OR bri.csv_has_authority(t,actor,sub,sid,issuer,node,'knowledge:read') IS NOT TRUE
        OR NOT EXISTS (SELECT FROM bri.unified_csv_candidates(t,node,record_id,1)) THEN
        RETURN NULL;
    END IF;
    RETURN node;
END $$;

CREATE FUNCTION bri.km_project(t text,fmt text,record_id uuid,version uuid) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $$
    SELECT jsonb_build_object('record_id',$3,'source_version_id',$4,'metadata',(
        SELECT jsonb_build_object('revision',r.revision::text,'responsible_node_id',p.responsible_node_id,
            'title',p.title,'description',p.description,
            'effective_date',p.effective_date,'review_date',p.review_date,'expiry_date',p.expiry_date,
            'primary_classification',jsonb_build_object('classification_id',c.classification_id,
                'label',c.label,'retired',c.retired_at IS NOT NULL),
            'additional_classifications',(SELECT coalesce(jsonb_agg(jsonb_build_object('classification_id',ac.classification_id,
                        'label',ac.label,'retired',ac.retired_at IS NOT NULL) ORDER BY a.position),'[]'::jsonb)
                FROM bri.knowledge_metadata_additional a JOIN bri.knowledge_classifications ac
                    ON (ac.tenant_id,ac.classification_id)=(a.tenant_id,a.classification_id)
                WHERE (a.tenant_id,a.payload_id)=(p.tenant_id,p.payload_id)))
        FROM bri.knowledge_metadata_revisions r JOIN bri.knowledge_metadata_payloads p USING (tenant_id,payload_id)
        JOIN bri.knowledge_classifications c ON (c.tenant_id,c.classification_id)=(p.tenant_id,p.primary_id)
        WHERE (r.tenant_id,r.format,r.job_id,r.record_id)=($1,$2,$4,$3)
        ORDER BY r.revision DESC LIMIT 1));
$$;

CREATE FUNCTION bri.km_correction_node(t text,actor uuid,sub uuid,sid uuid,issuer text,record_id uuid,version uuid,
    fmt text,permission text) RETURNS text
LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE node text := bri.km_exact_node(t,actor,sub,sid,issuer,record_id,version,fmt);
BEGIN
    IF node IS NULL OR NOT EXISTS (
        SELECT FROM bri.auth_role_assignments a JOIN bri.role_permissions rp USING (tenant_id,role_id)
        WHERE (a.tenant_id,a.principal_id,a.scope_node_id,rp.permission)=(t,actor,node,$9) AND a.status='active'
    ) THEN RETURN NULL; END IF;
    IF fmt='csv' THEN
        IF NOT EXISTS (SELECT FROM bri.csv_jobs j WHERE (j.tenant_id,j.job_id)=(t,version)
                        AND actor NOT IN (j.actor_id,j.creator_id)) THEN RETURN NULL; END IF;
    ELSE
        IF NOT EXISTS (SELECT FROM bri.xlsx_jobs j WHERE (j.tenant_id,j.job_id)=(t,version)
                        AND actor NOT IN (j.actor_id,j.creator_id)) THEN RETURN NULL; END IF;
    END IF;
    RETURN node;
END $$;

CREATE FUNCTION bri.km_current_revision(t text,fmt text,version uuid) RETURNS bigint
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $$
    SELECT coalesce((SELECT r.revision FROM bri.knowledge_metadata_revisions r
        WHERE (r.tenant_id,r.format,r.job_id)=($1,$2,$3) ORDER BY r.revision DESC LIMIT 1),0);
$$;

CREATE FUNCTION bri.km_list_corrections(t text,actor uuid,sub uuid,sid uuid,issuer text,record_id uuid,version uuid,
    after_id uuid,page_size integer,fmt text) RETURNS jsonb
LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE rev bigint;
BEGIN
    IF bri.km_correction_node(t,actor,sub,sid,issuer,record_id,version,fmt,'knowledge:metadata:review') IS NULL THEN
        RETURN NULL;
    END IF;
    IF page_size IS NULL OR page_size NOT BETWEEN 1 AND 20 THEN
        RAISE EXCEPTION 'Invalid metadata correction page' USING ERRCODE='22023';
    END IF;
    rev := bri.km_current_revision(t,fmt,version);
    RETURN (WITH visible AS NOT MATERIALIZED (
        SELECT p.proposal_id,p.payload_id FROM bri.knowledge_metadata_correction_proposals p
        WHERE (p.tenant_id,p.format,p.job_id,p.record_id,p.expected_revision)=(t,fmt,version,$6,rev)
          AND p.proposer_id<>actor AND NOT EXISTS (SELECT FROM bri.knowledge_metadata_correction_decisions d
            WHERE (d.tenant_id,d.format,d.job_id,d.proposal_id)=(t,fmt,version,p.proposal_id))
    ), page AS MATERIALIZED (
        SELECT v.*,row_number() OVER (ORDER BY v.proposal_id) AS n FROM visible v
        WHERE after_id IS NULL OR v.proposal_id>after_id ORDER BY v.proposal_id LIMIT page_size+1
    ) SELECT CASE WHEN after_id IS NULL OR EXISTS (SELECT FROM visible v WHERE v.proposal_id=after_id) THEN
        jsonb_build_object('items',(SELECT coalesce(jsonb_agg(jsonb_build_object('proposal_id',p.proposal_id,
            'expected_revision',rev::text,'proposed_metadata',bri.km_proposal_wire(t,p.payload_id))
            ORDER BY p.proposal_id),'[]'::jsonb) FROM page p WHERE p.n<=page_size),
            'next_after',(SELECT p.proposal_id FROM page p WHERE p.n=page_size AND
                EXISTS (SELECT FROM page more WHERE more.n=page_size+1)))
    END);
END $$;

CREATE FUNCTION bri.km_propose_correction(t text,actor uuid,sub uuid,sid uuid,issuer text,record_id uuid,version uuid,
    expected_revision bigint,request_id uuid,correlation uuid,metadata jsonb,fmt text) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE p bri.knowledge_metadata_correction_proposals; node text; m bri.km_input;
DECLARE permission constant text := 'knowledge:metadata:propose';
BEGIN
    IF bri.km_correction_node(t,actor,sub,sid,issuer,record_id,version,fmt,permission) IS NULL THEN RETURN NULL; END IF;
    PERFORM bri.xlsx_lock_actor(actor,sub,sid);
    node := bri.km_correction_node(t,actor,sub,sid,issuer,record_id,version,fmt,permission);
    IF node IS NULL THEN RETURN NULL; END IF;
    IF request_id IS NULL OR correlation IS NULL OR expected_revision IS NULL OR expected_revision<0 THEN
        RAISE EXCEPTION 'Invalid metadata correction' USING ERRCODE='22023';
    END IF;
    m := bri.km_parse(metadata);
    SELECT x.* INTO p FROM bri.knowledge_metadata_correction_proposals x
    WHERE (x.tenant_id,x.format,x.proposer_id,x.request_id)=(t,fmt,actor,$9);
    IF FOUND THEN
        IF (p.record_id,p.job_id,p.expected_revision) IS DISTINCT FROM (record_id,version,expected_revision)
                OR bri.km_input_for(t,p.payload_id) IS DISTINCT FROM m THEN
            RAISE EXCEPTION 'Metadata correction request conflict' USING ERRCODE='23505';
        END IF;
    ELSE
        IF bri.km_current_revision(t,fmt,version) <> expected_revision THEN
            RAISE EXCEPTION 'Metadata revision conflict' USING ERRCODE='23505';
        END IF;
        INSERT INTO bri.knowledge_metadata_correction_proposals
            (tenant_id,format,job_id,record_id,proposer_id,request_id,correlation,expected_revision,payload_id)
        VALUES (t,fmt,version,record_id,actor,request_id,correlation,expected_revision,bri.km_store(t,node,m)) RETURNING * INTO p;
        IF bri.km_correction_node(t,actor,sub,sid,issuer,record_id,version,fmt,permission) IS NULL THEN
            RAISE EXCEPTION 'Metadata correction lost authority' USING ERRCODE='42501';
        END IF;
    END IF;
    RETURN jsonb_build_object('record_id',record_id,'source_version_id',version,
        'proposal_id',p.proposal_id,'expected_revision',p.expected_revision::text);
END $$;

CREATE FUNCTION bri.km_review_correction(t text,actor uuid,sub uuid,sid uuid,issuer text,record_id uuid,version uuid,
    proposal_id uuid,action text,request_id uuid,correlation uuid,fmt text) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE p bri.knowledge_metadata_correction_proposals; d bri.knowledge_metadata_correction_decisions; revised bigint;
DECLARE permission constant text := 'knowledge:metadata:review';
BEGIN
    IF bri.km_correction_node(t,actor,sub,sid,issuer,record_id,version,fmt,permission) IS NULL THEN RETURN NULL; END IF;
    PERFORM bri.xlsx_lock_actor(actor,sub,sid);
    IF bri.km_correction_node(t,actor,sub,sid,issuer,record_id,version,fmt,permission) IS NULL THEN RETURN NULL; END IF;
    SELECT x.* INTO p FROM bri.knowledge_metadata_correction_proposals x
    WHERE (x.tenant_id,x.format,x.job_id,x.record_id,x.proposal_id)=(t,fmt,version,$6,$8) AND x.proposer_id<>actor;
    IF NOT FOUND THEN RETURN NULL; END IF;
    IF request_id IS NULL OR correlation IS NULL OR NOT coalesce(action IN ('approve','reject'),false) THEN
        RAISE EXCEPTION 'Invalid metadata correction decision' USING ERRCODE='22023';
    END IF;
    SELECT x.* INTO d FROM bri.knowledge_metadata_correction_decisions x
    WHERE (x.tenant_id,x.format,x.job_id,x.proposal_id)=(t,fmt,version,$8);
    IF FOUND THEN
        IF (d.reviewer_id,d.request_id,d.decision) IS DISTINCT FROM (actor,request_id,action) THEN
            RAISE EXCEPTION 'Metadata correction decision conflict' USING ERRCODE='23505';
        END IF;
    ELSE
        IF action='approve' THEN
            IF bri.km_current_revision(t,fmt,version) <> p.expected_revision THEN
                RAISE EXCEPTION 'Metadata revision conflict' USING ERRCODE='23505';
            END IF;
            revised := p.expected_revision+1;
            PERFORM bri.km_revision(t,fmt,version,record_id,revised,p.payload_id);
        END IF;
        INSERT INTO bri.knowledge_metadata_correction_decisions
            (tenant_id,format,job_id,proposal_id,proposer_id,reviewer_id,request_id,correlation,decision,metadata_revision)
        VALUES (t,fmt,version,proposal_id,p.proposer_id,actor,request_id,correlation,action,revised) RETURNING * INTO d;
        IF bri.km_correction_node(t,actor,sub,sid,issuer,record_id,version,fmt,permission) IS NULL THEN
            RAISE EXCEPTION 'Metadata correction lost authority' USING ERRCODE='42501';
        END IF;
    END IF;
    RETURN jsonb_build_object('record_id',record_id,'source_version_id',version,
        'proposal_id',d.proposal_id,'decision',d.decision,'metadata_revision',d.metadata_revision::text);
END $$;

-- These format-specific transport entry points are deliberately ungranted.
DO $entry$
DECLARE fmt text;
BEGIN
    FOREACH fmt IN ARRAY ARRAY['csv','xlsx'] LOOP
        EXECUTE format($sql$
            CREATE FUNCTION bri.%I(t text,actor uuid,sub uuid,sid uuid,issuer text,record_id uuid,source_version_id uuid)
            RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $body$
            BEGIN
                PERFORM bri.xlsx_governance_role(%L);
                IF bri.km_exact_node(t,actor,sub,sid,issuer,record_id,source_version_id,%L) IS NULL THEN RETURN NULL; END IF;
                RETURN bri.km_project(t,%L,record_id,source_version_id);
            END $body$
        $sql$,fmt||'_read_metadata_v1','bri_'||fmt||'_reader',fmt,fmt);
        EXECUTE format($sql$
            CREATE FUNCTION bri.%I(t text,actor uuid,sub uuid,sid uuid,issuer text,record_id uuid,source_version_id uuid,
                after_id uuid,page_size integer)
            RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $body$
            BEGIN
                PERFORM bri.xlsx_governance_role(%L);
                RETURN bri.km_list_corrections(t,actor,sub,sid,issuer,record_id,source_version_id,after_id,page_size,%L);
            END $body$
        $sql$,fmt||'_list_metadata_corrections_v1','bri_'||fmt||'_reader',fmt);
        EXECUTE format($sql$
            CREATE FUNCTION bri.%I(t text,actor uuid,sub uuid,sid uuid,issuer text,record_id uuid,source_version_id uuid,
                expected_revision bigint,request_id uuid,correlation uuid,metadata jsonb)
            RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $body$
            BEGIN
                PERFORM bri.xlsx_governance_role(%L);
                RETURN bri.km_propose_correction(t,actor,sub,sid,issuer,record_id,source_version_id,
                    expected_revision,request_id,correlation,metadata,%L);
            END $body$
        $sql$,fmt||'_propose_metadata_correction_v1','bri_'||fmt||'_reader',fmt);
        EXECUTE format($sql$
            CREATE FUNCTION bri.%I(t text,actor uuid,sub uuid,sid uuid,issuer text,record_id uuid,source_version_id uuid,
                proposal_id uuid,action text,request_id uuid,correlation uuid)
            RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $body$
            BEGIN
                PERFORM bri.xlsx_governance_role(%L);
                RETURN bri.km_review_correction(t,actor,sub,sid,issuer,record_id,source_version_id,
                    proposal_id,action,request_id,correlation,%L);
            END $body$
        $sql$,fmt||'_review_metadata_correction_v1','bri_'||fmt||'_reader',fmt);
    END LOOP;
END $entry$;

DO $acl$
DECLARE fn record; grantee_role name;
BEGIN
    FOR fn IN SELECT p.oid::regprocedure AS signature,p.proowner,p.proacl FROM pg_proc p
        WHERE p.pronamespace='bri'::regnamespace AND (p.proname LIKE 'km\_%' OR p.proname IN
            ('csv_read_metadata_v1','xlsx_read_metadata_v1','csv_propose_metadata_correction_v1',
             'xlsx_propose_metadata_correction_v1','csv_review_metadata_correction_v1','xlsx_review_metadata_correction_v1',
             'csv_list_metadata_corrections_v1','xlsx_list_metadata_corrections_v1')) LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',fn.signature);
        FOR grantee_role IN SELECT DISTINCT r.rolname FROM aclexplode(fn.proacl) a
            JOIN pg_roles r ON r.oid=a.grantee WHERE r.oid<>fn.proowner LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',fn.signature,grantee_role);
        END LOOP;
    END LOOP;
END $acl$;
