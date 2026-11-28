-- A19.1. Keep native job, lineage, decision and business-audit transactions.
-- Only private local wrappers can bind metadata; no runtime grants ship here.
-- Only the owning definer sees catalogue rows in these local format contexts.
-- The format session logins have no direct table rights.
CREATE POLICY km_classification_select ON bri.knowledge_classifications FOR SELECT TO bri_migrator
    USING (session_user IN ('bri_csv_intake','bri_xlsx_submitter','bri_xlsx_reviewer','bri_csv_reader','bri_xlsx_reader')
           AND inet_server_addr() IS NULL AND current_setting('listen_addresses')='');

CREATE TYPE bri.km_input AS (
    primary_id text, additional_ids text[], title text, description text,
    effective_date date, review_date date, expiry_date date
);

CREATE TABLE bri.knowledge_metadata_payloads (
    tenant_id text NOT NULL,
    payload_id uuid NOT NULL DEFAULT gen_random_uuid(),
    responsible_node_id text NOT NULL,
    primary_id text NOT NULL,
    primary_proposed_label text NOT NULL,
    title text NOT NULL CHECK (octet_length(title) BETWEEN 1 AND 160),
    description text CHECK (octet_length(description) BETWEEN 1 AND 2048),
    effective_date date,
    review_date date,
    expiry_date date,
    PRIMARY KEY (tenant_id,payload_id),
    FOREIGN KEY (tenant_id,responsible_node_id) REFERENCES bri.org_nodes,
    FOREIGN KEY (tenant_id,primary_id) REFERENCES bri.knowledge_classifications (tenant_id,classification_id)
);
CREATE TABLE bri.knowledge_metadata_additional (
    tenant_id text NOT NULL,
    payload_id uuid NOT NULL,
    position integer NOT NULL CHECK (position BETWEEN 1 AND 8),
    classification_id text NOT NULL,
    proposed_label text NOT NULL,
    PRIMARY KEY (tenant_id,payload_id,position),
    UNIQUE (tenant_id,payload_id,classification_id),
    FOREIGN KEY (tenant_id,payload_id) REFERENCES bri.knowledge_metadata_payloads,
    FOREIGN KEY (tenant_id,classification_id) REFERENCES bri.knowledge_classifications (tenant_id,classification_id)
);
CREATE TABLE bri.knowledge_metadata_initial (
    tenant_id text NOT NULL,
    format text NOT NULL CHECK (format IN ('csv','xlsx')),
    job_id uuid NOT NULL,
    payload_id uuid NOT NULL,
    csv_job uuid GENERATED ALWAYS AS (CASE WHEN format='csv' THEN job_id END) STORED,
    xlsx_job uuid GENERATED ALWAYS AS (CASE WHEN format='xlsx' THEN job_id END) STORED,
    PRIMARY KEY (tenant_id,format,job_id),
    FOREIGN KEY (tenant_id,csv_job) REFERENCES bri.csv_jobs (tenant_id,job_id),
    FOREIGN KEY (tenant_id,xlsx_job) REFERENCES bri.xlsx_jobs (tenant_id,job_id),
    FOREIGN KEY (tenant_id,payload_id) REFERENCES bri.knowledge_metadata_payloads
);
CREATE TABLE bri.knowledge_metadata_revisions (
    tenant_id text NOT NULL,
    format text NOT NULL CHECK (format IN ('csv','xlsx')),
    job_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision > 0),
    record_id uuid NOT NULL,
    payload_id uuid NOT NULL,
    primary_label text NOT NULL,
    additional_labels text[] NOT NULL CHECK (cardinality(additional_labels) <= 8),
    authoritative_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    csv_ref text GENERATED ALWAYS AS (CASE WHEN format='csv' THEN 'csv:'||job_id::text END) STORED,
    csv_version text GENERATED ALWAYS AS (CASE WHEN format='csv' THEN 'csv:'||job_id::text END) STORED,
    xlsx_job uuid GENERATED ALWAYS AS (CASE WHEN format='xlsx' THEN job_id END) STORED,
    xlsx_record uuid GENERATED ALWAYS AS (CASE WHEN format='xlsx' THEN record_id END) STORED,
    CHECK (format <> 'csv' OR record_id=job_id),
    PRIMARY KEY (tenant_id,format,job_id,revision),
    FOREIGN KEY (tenant_id,csv_ref) REFERENCES bri.validated_knowledge (tenant_id,proposal_id),
    FOREIGN KEY (tenant_id,csv_ref,csv_version) REFERENCES bri.source_versions (tenant_id,source_id,source_version_id),
    FOREIGN KEY (tenant_id,xlsx_record,xlsx_job) REFERENCES bri.xlsx_validated_knowledge (tenant_id,record_id,job_id),
    FOREIGN KEY (tenant_id,payload_id) REFERENCES bri.knowledge_metadata_payloads
);
CREATE TABLE bri.knowledge_metadata_initial_decisions (
    tenant_id text NOT NULL,
    format text NOT NULL CHECK (format IN ('csv','xlsx')),
    job_id uuid NOT NULL,
    actor_id uuid NOT NULL,
    request_id uuid NOT NULL,
    correlation uuid NOT NULL,
    decision text NOT NULL CHECK ((format='csv' AND decision IN ('approved','rejected'))
                               OR (format='xlsx' AND decision IN ('approve','reject'))),
    metadata_revision bigint CHECK (metadata_revision=1 AND decision IN ('approved','approve')),
    replacement_payload_id uuid CHECK (replacement_payload_id IS NULL OR metadata_revision IS NOT NULL),
    decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    csv_job uuid GENERATED ALWAYS AS (CASE WHEN format='csv' THEN job_id END) STORED,
    xlsx_job uuid GENERATED ALWAYS AS (CASE WHEN format='xlsx' THEN job_id END) STORED,
    PRIMARY KEY (tenant_id,format,job_id),
    UNIQUE (tenant_id,format,actor_id,request_id),
    FOREIGN KEY (tenant_id,csv_job) REFERENCES bri.csv_jobs (tenant_id,job_id),
    FOREIGN KEY (tenant_id,xlsx_job) REFERENCES bri.xlsx_jobs (tenant_id,job_id),
    FOREIGN KEY (tenant_id,actor_id) REFERENCES bri.auth_tenant_memberships,
    FOREIGN KEY (tenant_id,replacement_payload_id) REFERENCES bri.knowledge_metadata_payloads,
    FOREIGN KEY (tenant_id,format,job_id,metadata_revision) REFERENCES bri.knowledge_metadata_revisions
        DEFERRABLE INITIALLY DEFERRED
);

DO $private$
DECLARE rel text;
BEGIN
    FOREACH rel IN ARRAY ARRAY['payloads','additional','initial','revisions','initial_decisions'] LOOP
        rel := 'knowledge_metadata_'||rel;
        EXECUTE format('ALTER TABLE bri.%I ENABLE ROW LEVEL SECURITY',rel);
        EXECUTE format('ALTER TABLE bri.%I FORCE ROW LEVEL SECURITY',rel);
        EXECUTE format('REVOKE ALL ON bri.%I FROM PUBLIC,bri_app',rel);
        EXECUTE format('CREATE POLICY km_owner_read ON bri.%I FOR SELECT TO bri_migrator USING (true)',rel);
        EXECUTE format('CREATE POLICY km_owner_insert ON bri.%I FOR INSERT TO bri_migrator WITH CHECK (true)',rel);
        EXECUTE format('CREATE TRIGGER km_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON bri.%I
                        FOR EACH STATEMENT EXECUTE FUNCTION bri.xlsx_immutable()',rel);
    END LOOP;
END $private$;

CREATE FUNCTION bri.km_parse(m jsonb) RETURNS bri.km_input
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE result bri.km_input; k text;
BEGIN
    IF jsonb_typeof(m) IS DISTINCT FROM 'object'
       OR NOT (m ?& ARRAY['version','primary_classification_id','additional_classification_ids','title',
                          'description','effective_date','review_date','expiry_date']) THEN
        RAISE EXCEPTION 'Invalid metadata' USING ERRCODE='22023';
    END IF;
    IF m - ARRAY['version','primary_classification_id','additional_classification_ids','title',
                 'description','effective_date','review_date','expiry_date'] <> '{}'::jsonb
       OR m->'version' <> '1'::jsonb OR m->>'version' <> '1'
       OR jsonb_typeof(m->'primary_classification_id') <> 'string'
       OR m->>'primary_classification_id' COLLATE "C" !~ '^[a-z0-9][a-z0-9_.-]{0,63}$'
       OR jsonb_typeof(m->'additional_classification_ids') <> 'array'
       OR jsonb_typeof(m->'title') <> 'string' OR m->>'title' !~ '[^[:space:]]'
       OR octet_length(m->>'title') > 160
       OR jsonb_typeof(m->'description') NOT IN ('string','null')
       OR (m->>'description' IS NOT NULL AND
           (octet_length(m->>'description') > 2048 OR m->>'description' !~ '[^[:space:]]')) THEN
        RAISE EXCEPTION 'Invalid metadata' USING ERRCODE='22023';
    END IF;
    result.primary_id := m->>'primary_classification_id';
    IF jsonb_array_length(m->'additional_classification_ids') > 8 OR EXISTS (
        SELECT FROM jsonb_array_elements(m->'additional_classification_ids') AS e(value)
        WHERE jsonb_typeof(value) <> 'string' OR (value #>> '{}') COLLATE "C" !~ '^[a-z0-9][a-z0-9_.-]{0,63}$'
    ) THEN
        RAISE EXCEPTION 'Invalid additional classifications' USING ERRCODE='22023';
    END IF;
    SELECT ARRAY(SELECT DISTINCT value COLLATE "C" FROM jsonb_array_elements_text(m->'additional_classification_ids')
                 ORDER BY value COLLATE "C") INTO result.additional_ids;
    IF cardinality(result.additional_ids) <> jsonb_array_length(m->'additional_classification_ids')
        OR result.primary_id=ANY(result.additional_ids) THEN
        RAISE EXCEPTION 'Duplicate classification' USING ERRCODE='22023';
    END IF;
    FOREACH k IN ARRAY ARRAY['effective_date','review_date','expiry_date'] LOOP
        IF jsonb_typeof(m->k) NOT IN ('string','null') OR (m->>k) COLLATE "C" !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' THEN
            RAISE EXCEPTION 'Invalid metadata date' USING ERRCODE='22023';
        END IF;
    END LOOP;
    result.title := m->>'title';
    result.description := m->>'description';
    result.effective_date := (m->>'effective_date')::date;
    result.review_date := (m->>'review_date')::date;
    result.expiry_date := (m->>'expiry_date')::date;
    RETURN result;
EXCEPTION WHEN invalid_datetime_format OR datetime_field_overflow THEN
    RAISE EXCEPTION 'Invalid metadata date' USING ERRCODE='22023';
END $$;

CREATE FUNCTION bri.km_labels(t text, class_ids text[]) RETURNS text[]
LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE labels text[];
BEGIN
    SELECT array_agg(c.label ORDER BY ids.ordinality) INTO labels
    FROM unnest(class_ids) WITH ORDINALITY AS ids(id,ordinality)
    JOIN bri.knowledge_classifications c ON (c.tenant_id,c.classification_id)=(t,ids.id)
    WHERE c.retired_at IS NULL;
    IF cardinality(class_ids) IS DISTINCT FROM cardinality(labels) THEN
        RAISE EXCEPTION 'Invalid classification selection' USING ERRCODE='22023';
    END IF;
    RETURN labels;
END $$;

CREATE FUNCTION bri.km_store(t text, node text, m bri.km_input) RETURNS uuid
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE id uuid; labels text[] := bri.km_labels(t,ARRAY[m.primary_id]||m.additional_ids);
BEGIN
    INSERT INTO bri.knowledge_metadata_payloads
        (tenant_id,responsible_node_id,primary_id,primary_proposed_label,title,description,effective_date,review_date,expiry_date)
    VALUES (t,node,m.primary_id,labels[1],m.title,m.description,m.effective_date,m.review_date,m.expiry_date)
    RETURNING payload_id INTO id;
    INSERT INTO bri.knowledge_metadata_additional (tenant_id,payload_id,position,classification_id,proposed_label)
    SELECT t,id,a.ordinality,a.classification_id,labels[a.ordinality+1]
    FROM unnest(m.additional_ids) WITH ORDINALITY AS a(classification_id,ordinality);
    RETURN id;
END $$;

CREATE FUNCTION bri.km_input_for(t text, id uuid) RETURNS bri.km_input
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $$
    SELECT p.primary_id,ARRAY(SELECT a.classification_id FROM bri.knowledge_metadata_additional a
          WHERE (a.tenant_id,a.payload_id)=($1,$2) ORDER BY a.position),
          p.title,p.description,p.effective_date,p.review_date,p.expiry_date
    FROM bri.knowledge_metadata_payloads p WHERE (p.tenant_id,p.payload_id)=($1,$2);
$$;

CREATE FUNCTION bri.km_proposal_wire(t text, id uuid) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $$
    SELECT jsonb_build_object('version',1,'primary_classification_id',m.primary_id,
        'additional_classification_ids',m.additional_ids,'title',m.title,'description',m.description,
        'effective_date',m.effective_date,'review_date',m.review_date,'expiry_date',m.expiry_date)
    FROM bri.km_input_for($1,$2) m WHERE m.primary_id IS NOT NULL;
$$;

CREATE FUNCTION bri.km_revision(t text, fmt text, job uuid, record_id uuid, rev bigint, payload uuid) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE m bri.km_input := bri.km_input_for(t,payload);
DECLARE labels text[] := bri.km_labels(t,ARRAY[m.primary_id]||m.additional_ids);
BEGIN
    INSERT INTO bri.knowledge_metadata_revisions(tenant_id,format,job_id,record_id,revision,payload_id,primary_label,additional_labels)
        VALUES (t,fmt,job,record_id,rev,payload,labels[1],labels[2:9]);
END $$;

CREATE FUNCTION bri.km_bind_initial(t text, fmt text, job uuid, node text, existed boolean, metadata jsonb) RETURNS void
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE m bri.km_input := bri.km_parse(metadata); p uuid;
BEGIN
    IF existed THEN
        SELECT i.payload_id INTO p FROM bri.knowledge_metadata_initial i
        WHERE (i.tenant_id,i.format,i.job_id)=(t,fmt,job);
        IF NOT FOUND OR bri.km_input_for(t,p) IS DISTINCT FROM m THEN
            RAISE EXCEPTION 'Metadata reservation conflict' USING ERRCODE='23505';
        END IF;
    ELSE
        INSERT INTO bri.knowledge_metadata_initial (tenant_id,format,job_id,payload_id)
        VALUES (t,fmt,job,bri.km_store(t,node,m));
    END IF;
END $$;

CREATE FUNCTION bri.csv_submit_metadata_v1(t text,actor uuid,sid uuid,issuer text,node text,request_key uuid,
    original_sha256 text,byte_count integer,correlation uuid,metadata jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE existed boolean; receipt record;
BEGIN
    PERFORM bri.xlsx_governance_role('bri_csv_intake');
    PERFORM bri.csv_lock_actor(actor);
    SELECT EXISTS (SELECT FROM bri.csv_jobs x WHERE (x.tenant_id,x.actor_id,x.request_key)=(t,actor,$6)) INTO existed;
    SELECT * INTO STRICT receipt FROM bri.csv_submit(t,actor,sid,issuer,node,request_key,original_sha256,byte_count,correlation);
    PERFORM bri.km_bind_initial(t,'csv',receipt.job_id,node,existed,metadata);
    IF bri.csv_has_authority(t,actor,nullif(current_setting('bri.auth_user_id',true),'')::uuid,sid,issuer,node,'source:submit') IS NOT TRUE THEN
        RAISE EXCEPTION 'Metadata reservation lost authority' USING ERRCODE='42501';
    END IF;
    RETURN to_jsonb(receipt);
END $$;

CREATE FUNCTION bri.xlsx_submit_metadata_v1(t text,actor uuid,sub uuid,sid uuid,issuer text,node text,request_key uuid,
    byte_count integer,original_sha256 text,correlation uuid,metadata jsonb) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE existed boolean; receipt jsonb;
BEGIN
    PERFORM bri.xlsx_governance_role('bri_xlsx_submitter');
    PERFORM bri.xlsx_lock_actor(actor,sub,sid);
    SELECT EXISTS (SELECT FROM bri.xlsx_jobs x WHERE (x.tenant_id,x.actor_id,x.request_key)=(t,actor,$7)) INTO existed;
    receipt := bri.xlsx_submit(t,actor,sub,sid,issuer,node,request_key,byte_count,original_sha256,correlation);
    PERFORM bri.km_bind_initial(t,'xlsx',(receipt->>'job_id')::uuid,node,existed,metadata);
    IF bri.xlsx_has_authority(t,actor,sub,sid,issuer,node) IS NOT TRUE THEN
        RAISE EXCEPTION 'Metadata reservation lost authority' USING ERRCODE='42501';
    END IF;
    RETURN receipt;
END $$;

-- Covers core CSV, workspace CSV (which delegates to core) and native XLSX.
-- The guard checks a protected row, not a caller-set convention or GUC.
-- A classified decision binding cannot commit without the actual revision (FK).
CREATE FUNCTION bri.km_initial_approval_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE fmt text; job uuid;
BEGIN
    IF TG_TABLE_NAME='validated_knowledge' THEN
        IF NOT NEW.csv_governed THEN RETURN NEW; END IF;
        fmt := 'csv';
        SELECT j.job_id INTO job FROM bri.csv_jobs j WHERE (j.tenant_id,j.proposal_id)=(NEW.tenant_id,NEW.proposal_id);
    ELSE
        fmt := 'xlsx';
        job := NEW.job_id;
    END IF;
    IF EXISTS (SELECT FROM bri.knowledge_metadata_initial i WHERE (i.tenant_id,i.format,i.job_id)=(NEW.tenant_id,fmt,job))
       AND NOT EXISTS (SELECT FROM bri.knowledge_metadata_initial_decisions d
                       WHERE (d.tenant_id,d.format,d.job_id)=(NEW.tenant_id,fmt,job) AND d.metadata_revision=1) THEN
        RAISE EXCEPTION 'Metadata validation required' USING ERRCODE='42501';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER km_csv_initial_approval BEFORE INSERT ON bri.validated_knowledge
    FOR EACH ROW EXECUTE FUNCTION bri.km_initial_approval_guard();
CREATE TRIGGER km_xlsx_initial_approval BEFORE INSERT ON bri.xlsx_validated_knowledge
    FOR EACH ROW EXECUTE FUNCTION bri.km_initial_approval_guard();

CREATE FUNCTION bri.km_initial_receipt(d bri.knowledge_metadata_initial_decisions) RETURNS jsonb
LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $$
    SELECT jsonb_build_object('job_id',d.job_id,'decision',d.decision,'metadata_revision',d.metadata_revision::text);
$$;

CREATE FUNCTION bri.km_decide_initial(t text,actor uuid,sub uuid,sid uuid,issuer text,job uuid,decision text,
    request_id uuid,correlation uuid,fmt text,metadata jsonb) RETURNS jsonb
LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE j bri.csv_jobs; d bri.knowledge_metadata_initial_decisions; p uuid; record_id uuid;
DECLARE native_result text; revised bigint; node text; replacement uuid; m bri.km_input;
BEGIN
    IF request_id IS NULL OR correlation IS NULL OR NOT coalesce(
            (fmt='csv' AND decision IN ('approved','rejected')) OR (fmt='xlsx' AND decision IN ('approve','reject')),false) THEN
        RAISE EXCEPTION 'Invalid metadata decision' USING ERRCODE='22023';
    END IF;
    IF fmt='csv' THEN
        -- Same fence and row ordering as the workspace/native review path.
        PERFORM bri.csv_lock_actor(actor);
        SELECT x.* INTO j FROM bri.csv_jobs x WHERE (x.tenant_id,x.job_id)=(t,job)
          AND x.state IN ('proposed','approved','rejected','failed') AND actor NOT IN (x.actor_id,x.creator_id)
          AND bri.csv_has_authority(t,actor,sub,sid,km_decide_initial.issuer,x.scope_node_id,'knowledge:review') FOR UPDATE;
        IF NOT FOUND OR j.state NOT IN ('proposed','approved','rejected','failed') OR actor IN (j.actor_id,j.creator_id)
            OR NOT bri.csv_has_authority(t,actor,sub,sid,issuer,j.scope_node_id,'knowledge:review') THEN RETURN NULL; END IF;
        node := j.scope_node_id;
    ELSE
        IF NOT EXISTS (SELECT FROM bri.xlsx_review_visible(t,actor,sub,sid,issuer) v WHERE v.job_id=job) THEN RETURN NULL; END IF;
        PERFORM bri.xlsx_lock_actor(actor,sub,sid);
        SELECT x.scope_node_id INTO node FROM bri.xlsx_jobs x WHERE (x.tenant_id,x.job_id)=(t,job)
          AND EXISTS (SELECT FROM bri.xlsx_review_visible(t,actor,sub,sid,km_decide_initial.issuer) v WHERE v.job_id=x.job_id)
          FOR UPDATE;
        IF NOT FOUND OR NOT EXISTS (SELECT FROM bri.xlsx_review_visible(t,actor,sub,sid,issuer) v WHERE v.job_id=job) THEN RETURN NULL; END IF;
    END IF;
    SELECT x.* INTO d FROM bri.knowledge_metadata_initial_decisions x WHERE (x.tenant_id,x.format,x.job_id)=(t,fmt,job);
    IF FOUND THEN
        IF (d.actor_id,d.request_id,d.decision,d.replacement_payload_id IS NOT NULL)
            IS DISTINCT FROM (actor,request_id,decision,metadata IS NOT NULL) THEN
            RAISE EXCEPTION 'Metadata decision conflict' USING ERRCODE='23505';
        END IF;
        IF metadata IS NOT NULL THEN
            BEGIN
                m := bri.km_parse(metadata);
            EXCEPTION WHEN invalid_parameter_value THEN
                RAISE EXCEPTION 'Metadata decision conflict' USING ERRCODE='23505';
            END;
            IF bri.km_input_for(t,d.replacement_payload_id) IS DISTINCT FROM m THEN
                RAISE EXCEPTION 'Metadata decision conflict' USING ERRCODE='23505';
            END IF;
        END IF;
        RETURN bri.km_initial_receipt(d);
    END IF;
    IF decision IN ('approve','approved') THEN
        SELECT i.payload_id INTO p FROM bri.knowledge_metadata_initial i WHERE (i.tenant_id,i.format,i.job_id)=(t,fmt,job);
        IF FOUND THEN revised := 1; END IF;
    END IF;
    IF metadata IS NOT NULL THEN
        IF revised IS NULL THEN
            RAISE EXCEPTION 'Replacement requires approval of a classified proposal' USING ERRCODE='22023';
        END IF;
        replacement := bri.km_store(t,node,bri.km_parse(metadata));
        p := replacement;
    END IF;
    INSERT INTO bri.knowledge_metadata_initial_decisions
        (tenant_id,format,job_id,actor_id,request_id,correlation,decision,metadata_revision,replacement_payload_id)
        VALUES (t,fmt,job,actor,request_id,correlation,decision,revised,replacement) RETURNING * INTO d;
    IF fmt='csv' THEN
        native_result := bri.csv_review_decide(t,actor,sid,issuer,job,decision,correlation);
        record_id := job;
    ELSE
        native_result := bri.xlsx_review_decide(t,actor,sub,sid,issuer,job,decision,request_id,correlation);
        IF revised IS NOT NULL THEN
            SELECT k.record_id INTO STRICT record_id FROM bri.xlsx_validated_knowledge k WHERE (k.tenant_id,k.job_id)=(t,job);
        END IF;
    END IF;
    IF native_result IS DISTINCT FROM decision THEN
        RAISE EXCEPTION 'Metadata decision lost authority' USING ERRCODE='42501';
    END IF;
    IF revised IS NOT NULL THEN PERFORM bri.km_revision(t,fmt,job,record_id,revised,p); END IF;
    IF (CASE WHEN fmt='csv' THEN bri.csv_has_authority(t,actor,sub,sid,issuer,j.scope_node_id,'knowledge:review')
             ELSE EXISTS (SELECT FROM bri.xlsx_review_visible(t,actor,sub,sid,issuer) v WHERE v.job_id=job) END) IS NOT TRUE THEN
        RAISE EXCEPTION 'Metadata decision lost authority' USING ERRCODE='42501';
    END IF;
    RETURN bri.km_initial_receipt(d);
END $$;

CREATE FUNCTION bri.csv_review_metadata_v1(t text,actor uuid,sid uuid,issuer text,job uuid,decision text,request_id uuid,
    correlation uuid,metadata jsonb DEFAULT NULL)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    PERFORM bri.xlsx_governance_role('bri_csv_intake');
    RETURN bri.km_decide_initial(t,actor,nullif(current_setting('bri.auth_user_id',true),'')::uuid,sid,issuer,job,
        decision,request_id,correlation,'csv',metadata);
END $$;

CREATE FUNCTION bri.xlsx_review_metadata_v1(t text,actor uuid,sub uuid,sid uuid,issuer text,job uuid,action text,request_id uuid,
    correlation uuid,metadata jsonb DEFAULT NULL)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    PERFORM bri.xlsx_governance_role('bri_xlsx_reviewer');
    RETURN bri.km_decide_initial(t,actor,sub,sid,issuer,job,action,request_id,correlation,'xlsx',metadata);
END $$;

CREATE FUNCTION bri.km_initial_detail(t text, fmt text, job uuid, detail jsonb) RETURNS jsonb
LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    IF detail->>'state' IS DISTINCT FROM 'proposed' THEN RETURN NULL; END IF;
    RETURN jsonb_build_object('detail',detail,'proposed_metadata',(
        SELECT bri.km_proposal_wire(t,i.payload_id) FROM bri.knowledge_metadata_initial i
        WHERE (i.tenant_id,i.format,i.job_id)=(t,fmt,job)));
END $$;

CREATE FUNCTION bri.csv_review_metadata_detail_v1(t text,actor uuid,sub uuid,sid uuid,issuer text,
    job uuid,evidence_offset integer) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    PERFORM bri.xlsx_governance_role('bri_csv_intake');
    RETURN bri.km_initial_detail(t,'csv',job,bri.csv_review_detail(t,actor,sub,sid,issuer,job,evidence_offset));
END $$;

CREATE FUNCTION bri.xlsx_review_metadata_detail_v1(t text,actor uuid,sub uuid,sid uuid,issuer text,job uuid)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    PERFORM bri.xlsx_governance_role('bri_xlsx_reviewer');
    RETURN bri.km_initial_detail(t,'xlsx',job,bri.xlsx_review_detail(t,actor,sub,sid,issuer,job));
END $$;

DO $acl$
DECLARE fn record; grantee_role name;
BEGIN
    FOR fn IN SELECT p.oid::regprocedure AS signature,p.proowner,p.proacl FROM pg_proc p
        WHERE p.pronamespace='bri'::regnamespace AND (p.proname LIKE 'km\_%' OR p.proname IN
            ('csv_submit_metadata_v1','xlsx_submit_metadata_v1','csv_review_metadata_v1','xlsx_review_metadata_v1',
             'csv_review_metadata_detail_v1','xlsx_review_metadata_detail_v1')) LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',fn.signature);
        FOR grantee_role IN SELECT DISTINCT r.rolname FROM aclexplode(fn.proacl) a
            JOIN pg_roles r ON r.oid=a.grantee WHERE r.oid<>fn.proowner LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',fn.signature,grantee_role);
        END LOOP;
    END LOOP;
END $acl$;
REVOKE ALL ON TYPE bri.km_input FROM PUBLIC,bri_app;
