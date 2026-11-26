-- A14 private review workspace. No login, role assignment or EXECUTE grant is
-- provisioned here; only disposable fixtures enable these RPCs.
CREATE INDEX csv_review_queue_idx ON bri.csv_jobs (tenant_id,state,created_at,job_id)
    WHERE state IN ('proposed','approved','rejected','failed');

-- csv_audit_events is already FORCE RLS. Allow only the lifecycle subset
-- for the exact authorized tenant/job bound by csv_review_detail below.
-- This does not grant raw audit access to the intake login.
CREATE POLICY csv_review_history_read ON bri.csv_audit_events FOR SELECT TO bri_migrator
    USING (session_user = 'bri_csv_intake' AND inet_server_addr() IS NULL
           AND current_setting('listen_addresses') = ''
           AND tenant_id = nullif(current_setting('bri.csv_review_tenant',true),'')
           AND job_id::text = current_setting('bri.csv_review_job',true)
           AND event IN ('submitted','ready','claimed','lease_expired','retry',
                         'failed','proposed','approved','rejected'));

CREATE FUNCTION bri.csv_review_queue(t text,actor uuid,sub uuid,sid uuid,issuer text,
                                     status text,after_id uuid,page_size integer)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE result jsonb;
BEGIN
    IF session_user <> 'bri_csv_intake' OR inet_server_addr() IS NOT NULL
       OR current_setting('listen_addresses') <> '' THEN
        RAISE EXCEPTION 'CSV review denied' USING ERRCODE = '42501';
    END IF;
    IF status IS NULL OR status NOT IN ('proposed','approved','rejected','failed')
       OR page_size IS NULL OR page_size NOT BETWEEN 1 AND 50 THEN
        RAISE EXCEPTION 'invalid CSV review page' USING ERRCODE = '22023';
    END IF;

    -- Both the anchor and the page resolve against the same visible relation.
    -- An absent/hidden/wrong-status anchor produces an empty page, not a scan
    -- from the beginning or a position derived from an inaccessible row.
    WITH visible AS NOT MATERIALIZED (
        SELECT j.job_id,j.proposal_id,j.state,j.scope_node_id,j.created_at
        FROM bri.csv_jobs j
        WHERE j.tenant_id=t AND j.state=status
          AND j.state IN ('proposed','approved','rejected','failed')
          AND actor NOT IN (j.actor_id,j.creator_id)
          AND bri.csv_has_authority(t,actor,sub,sid,$5,j.scope_node_id,'knowledge:review')
    ), anchor AS (
        SELECT v.created_at,v.job_id FROM visible v WHERE v.job_id=after_id
    ), page AS (
        SELECT v.* FROM visible v
        WHERE after_id IS NULL OR (v.created_at,v.job_id) > (SELECT a.created_at,a.job_id FROM anchor a)
        ORDER BY v.created_at,v.job_id LIMIT page_size + 1
    ), numbered AS (
        SELECT p.*,row_number() OVER (ORDER BY p.created_at,p.job_id) AS ordinal FROM page p
    )
    -- Bound display labels only; visibility above uses the full scope key.
    SELECT jsonb_build_object(
        'items',coalesce(jsonb_agg(jsonb_build_object('id',n.proposal_id,'state',n.state,
                   'node_id',CASE WHEN char_length(n.scope_node_id) > 256
                                  THEN left(n.scope_node_id,255) || '…' ELSE n.scope_node_id END,
                   'created_at',n.created_at) ORDER BY n.ordinal)
                   FILTER (WHERE n.ordinal <= page_size),'[]'::jsonb),
        'next_cursor',CASE WHEN count(*) > page_size THEN
            max(n.job_id::text) FILTER (WHERE n.ordinal = page_size) END)
    INTO result FROM numbered n;
    RETURN result;
END $$;

CREATE FUNCTION bri.csv_review_detail(t text,actor uuid,sub uuid,sid uuid,issuer text,
                                      item_id uuid,evidence_offset integer)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    j bri.csv_jobs;
    provenance jsonb;
    evidence_page text;
    next_offset integer;
    history jsonb;
    previous_tenant text;
    previous_job text;
    chunk_size constant integer := 4096;
BEGIN
    IF session_user <> 'bri_csv_intake' OR inet_server_addr() IS NOT NULL
       OR current_setting('listen_addresses') <> '' THEN
        RAISE EXCEPTION 'CSV review denied' USING ERRCODE = '42501';
    END IF;
    IF evidence_offset IS NULL OR evidence_offset NOT BETWEEN 0 AND 20000000 THEN
        RAISE EXCEPTION 'invalid CSV review evidence offset' USING ERRCODE = '22023';
    END IF;

    SELECT x.* INTO j FROM bri.csv_jobs x
    WHERE (x.tenant_id,x.job_id)=(t,item_id) AND x.state IN ('proposed','approved','rejected','failed')
      AND actor NOT IN (x.actor_id,x.creator_id)
      AND bri.csv_has_authority(t,actor,sub,sid,$5,x.scope_node_id,'knowledge:review');
    IF NOT FOUND THEN RETURN NULL; END IF;

    -- A failed intake is not a proposal. For reviewable lineage require the
    -- exact governed parent chain, including the A12 job's generated IDs.
    IF j.state <> 'failed' THEN
        SELECT jsonb_build_object('source_id',s.source_id,'source_version_id',v.source_version_id,
                   'source_version',v.version_label,'extraction_id',x.extraction_id,
                   'original_sha256',e.original_sha256,'content_sha256',x.content_sha256,
                   'csv_first_line',e.first_line,'csv_last_line',e.last_line),
               substring(x.content FROM evidence_offset + 1 FOR chunk_size + 1)
        INTO provenance,evidence_page
        FROM bri.knowledge_proposals p
        JOIN bri.source_extractions x ON (x.tenant_id,x.extraction_id,x.scope_node_id) =
                                         (p.tenant_id,p.extraction_id,p.scope_node_id) AND x.csv_governed
        JOIN bri.source_records s ON (s.tenant_id,s.source_id,s.scope_node_id) =
                                      (x.tenant_id,x.source_id,x.scope_node_id) AND s.csv_governed
        JOIN bri.source_versions v ON (v.tenant_id,v.source_id,v.source_version_id,v.content_sha256) =
                                       (x.tenant_id,x.source_id,x.source_version_id,x.content_sha256) AND v.csv_governed
        JOIN bri.csv_source_evidence e ON (e.tenant_id,e.source_id,e.source_version_id) =
                                           (v.tenant_id,v.source_id,v.source_version_id)
        WHERE (p.tenant_id,p.proposal_id,p.scope_node_id,p.csv_creator_id) =
              (j.tenant_id,j.proposal_id,j.scope_node_id,j.creator_id) AND p.csv_governed
          AND (x.extraction_id,s.source_id,v.source_version_id,e.original_sha256) =
              (j.proposal_id,j.proposal_id,j.proposal_id,j.original_sha256);
        IF char_length(evidence_page) > chunk_size THEN
            evidence_page := left(evidence_page,chunk_size);
            next_offset := evidence_offset + chunk_size;
        END IF;
    END IF;

    -- Bind the keys from the authorized row only, never from caller settings.
    -- Restore the caller's settings on success; an error rolls them back.
    previous_tenant := current_setting('bri.csv_review_tenant',true);
    previous_job := current_setting('bri.csv_review_job',true);
    PERFORM set_config('bri.csv_review_tenant',j.tenant_id,true),
            set_config('bri.csv_review_job',j.job_id::text,true);
    SELECT coalesce(jsonb_agg(jsonb_build_object('event',a.event,'occurred_at',a.occurred_at,
               'reason',CASE WHEN a.event IN ('failed','retry','lease_expired') THEN a.reason END)
               ORDER BY a.occurred_at,a.event_id),'[]'::jsonb)
    INTO history FROM (
        SELECT h.event,h.occurred_at,h.reason,h.event_id FROM bri.csv_audit_events h
        WHERE (h.tenant_id,h.job_id)=(j.tenant_id,j.job_id)
          AND h.event IN ('submitted','ready','claimed','lease_expired','retry',
                          'failed','proposed','approved','rejected')
        ORDER BY h.occurred_at,h.event_id LIMIT 32
    ) a;
    PERFORM set_config('bri.csv_review_tenant',coalesce(previous_tenant,''),true),
            set_config('bri.csv_review_job',coalesce(previous_job,''),true);

    RETURN jsonb_build_object('id',j.proposal_id,'state',j.state,
        'node_id',CASE WHEN char_length(j.scope_node_id) > 256
                       THEN left(j.scope_node_id,255) || '…' ELSE j.scope_node_id END,
        'created_at',j.created_at,'provenance',provenance,'evidence',evidence_page,
        'next_evidence_offset',next_offset,'history',history);
END $$;

CREATE FUNCTION bri.csv_review_decide(t text,actor uuid,sid uuid,issuer text,
                                      item_id uuid,decision text,correlation uuid)
RETURNS text LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE j bri.csv_jobs;
BEGIN
    IF session_user <> 'bri_csv_intake' OR inet_server_addr() IS NOT NULL
       OR current_setting('listen_addresses') <> '' OR correlation IS NULL THEN
        RAISE EXCEPTION 'CSV review workspace denied' USING ERRCODE = '42501';
    END IF;

    -- Take the A12 governance fence and session guard before checking visibility.
    PERFORM bri.csv_lock_actor(actor);
    -- Qualify the row before LockRows so a hidden job is not a lock target.
    SELECT x.* INTO j FROM bri.csv_jobs x
    WHERE (x.tenant_id,x.job_id)=(t,item_id) AND x.state IN ('proposed','approved','rejected','failed')
      AND actor NOT IN (x.actor_id,x.creator_id)
      AND bri.csv_has_authority(t,actor,nullif(current_setting('bri.auth_user_id',true),'')::uuid,
                                sid,csv_review_decide.issuer,x.scope_node_id,'knowledge:review')
    FOR UPDATE;
    -- Recheck the locked row and live authority after a possible wait.
    IF NOT FOUND OR j.state NOT IN ('proposed','approved','rejected','failed')
       OR actor IN (j.actor_id,j.creator_id)
       OR NOT bri.csv_has_authority(t,actor,nullif(current_setting('bri.auth_user_id',true),'')::uuid,
                                    sid,issuer,j.scope_node_id,'knowledge:review') THEN
        RETURN NULL;
    END IF;

    -- A12 takes the same locks again in this transaction, on its own locked
    -- rows. It alone decides, including terminal conflicts and the audit write.
    RETURN bri.csv_review(t,actor,sid,issuer,j.proposal_id,decision,correlation);
END $$;

REVOKE ALL ON FUNCTION bri.csv_review_queue(text,uuid,uuid,uuid,text,text,uuid,integer),
    bri.csv_review_detail(text,uuid,uuid,uuid,text,uuid,integer),
    bri.csv_review_decide(text,uuid,uuid,text,uuid,text,uuid) FROM PUBLIC,bri_app;
-- The optional fixture roles need not exist when the normal runner applies 0031.
DO $$
DECLARE role_name text;
BEGIN
    FOR role_name IN SELECT rolname FROM pg_roles
        WHERE rolname IN ('bri_csv_intake','bri_csv_worker','bri_csv_reader') LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION bri.csv_review_queue(text,uuid,uuid,uuid,text,text,uuid,integer),
            bri.csv_review_detail(text,uuid,uuid,uuid,text,uuid,integer),
            bri.csv_review_decide(text,uuid,uuid,text,uuid,text,uuid) FROM %I',role_name);
    END LOOP;
END $$;
