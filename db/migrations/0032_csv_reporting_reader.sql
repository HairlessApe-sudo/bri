-- A15-AM1: private, socket-only reporting provenance. The trusted reader
-- supplies verified identity and sets SET LOCAL statement_timeout (1..5000ms)
-- in a separate command before invoking this routine. A function SET clause
-- cannot arm the timeout for the already running client statement.
CREATE INDEX csv_reporting_approved_scope_idx
    ON bri.csv_jobs (tenant_id,scope_node_id,proposal_id) WHERE state='approved';

CREATE FUNCTION bri.csv_read_reporting(t text, actor uuid, sub uuid, sid uuid, issuer text, node text)
RETURNS TABLE(proposal_id text, source_version_id text, original_sha256 text,
              content_sha256 text, first_line integer, last_line integer)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
SET work_mem = '1MB'
SET hash_mem_multiplier = 1
SET max_parallel_workers_per_gather = 0
AS $$
DECLARE
    candidate record;
    seen integer := 0;
BEGIN
    IF session_user <> 'bri_csv_reader' OR inet_server_addr() IS NOT NULL
       OR current_setting('listen_addresses') <> '' THEN
        RAISE EXCEPTION 'CSV reporting read denied' USING ERRCODE = '42501';
    END IF;

    -- temp_file_limit is a privileged, per-process cluster/role setting. Do
    -- not grant SET or run the read with no bound. Parallel work is disabled.
    IF NOT EXISTS (SELECT FROM pg_settings WHERE name='temp_file_limit' AND setting::integer BETWEEN 0 AND 16384)
       OR NOT EXISTS (SELECT FROM pg_settings WHERE name='statement_timeout' AND setting::integer BETWEEN 1 AND 5000) THEN
        RAISE EXCEPTION 'CSV reporting resource limits are not configured' USING ERRCODE = '55000';
    END IF;

    IF bri.csv_has_authority(t,actor,sub,sid,issuer,node,'knowledge:read') IS NOT TRUE THEN
        RAISE EXCEPTION 'CSV reporting read denied' USING ERRCODE = '42501';
    END IF;

    -- Mirror the published joins/allow predicates from 0030; do not call the
    -- wide content reader. Exact-node authority above covers every candidate.
    -- The lateral fence keeps the indexed job scope on the outside and runs
    -- the publication probes before LIMIT. A tenant's job proposal ID is
    -- unique, and each join (including both allow gates) is on a unique key,
    -- so the limit counts distinct IDs without a wide DISTINCT or sort.
    FOR candidate IN
        SELECT j.proposal_id, published.*
        FROM bri.csv_jobs j
        CROSS JOIN LATERAL (
            SELECT sv.source_version_id,e.original_sha256,x.content_sha256,e.first_line,e.last_line
            FROM bri.knowledge_proposals p
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
            WHERE (p.tenant_id,p.proposal_id,p.scope_node_id,p.csv_creator_id) =
                  (j.tenant_id,j.proposal_id,j.scope_node_id,j.creator_id)
              AND s.source_id=j.proposal_id AND sv.source_version_id=j.proposal_id
            OFFSET 0
        ) published
        WHERE j.tenant_id=$1 AND j.scope_node_id=$6 AND j.state='approved'
        ORDER BY j.proposal_id
        LIMIT 1001
    LOOP
        seen := seen + 1;
        IF seen > 1000 THEN
            RAISE EXCEPTION 'CSV reporting scope exceeds the row limit' USING ERRCODE = '54000';
        END IF;
        IF (candidate.original_sha256 ~ '^[0-9a-f]{64}$'
            AND candidate.content_sha256 ~ '^[0-9a-f]{64}$'
            AND candidate.first_line >= 1 AND candidate.last_line >= candidate.first_line) IS NOT TRUE THEN
            RAISE EXCEPTION 'CSV reporting provenance is incomplete' USING ERRCODE = '22000';
        END IF;
        proposal_id := candidate.proposal_id;
        source_version_id := candidate.source_version_id;
        original_sha256 := candidate.original_sha256;
        content_sha256 := candidate.content_sha256;
        first_line := candidate.first_line;
        last_line := candidate.last_line;
        RETURN NEXT;
    END LOOP;
END $$;

REVOKE ALL ON FUNCTION bri.csv_read_reporting(text,uuid,uuid,uuid,text,text) FROM PUBLIC,bri_app;
-- Drop any inherited default ACL entries on this routine (not just the known
-- stage roles). Grant the exact pre-existing transport, if provisioned.
DO $$
DECLARE role_name name;
BEGIN
    FOR role_name IN
        SELECT DISTINCT r.rolname
        FROM pg_proc p CROSS JOIN LATERAL aclexplode(p.proacl) a
        JOIN pg_roles r ON r.oid=a.grantee
        WHERE p.oid='bri.csv_read_reporting(text,uuid,uuid,uuid,text,text)'::regprocedure
          AND r.oid<>p.proowner
    LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION bri.csv_read_reporting(text,uuid,uuid,uuid,text,text) FROM %I', role_name);
    END LOOP;
    IF EXISTS (SELECT FROM pg_roles WHERE rolname='bri_csv_reader') THEN
        GRANT EXECUTE ON FUNCTION bri.csv_read_reporting(text,uuid,uuid,uuid,text,text) TO bri_csv_reader;
    END IF;
END $$;
