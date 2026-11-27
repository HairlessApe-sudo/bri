-- Local staged reader; provision its socket-only login and only the two entry
-- point grants in the disposable fixture, never in the migration runner.
CREATE POLICY unified_bound_issuer ON bri.provider_event_source FOR SELECT TO bri_migrator
    USING (session_user='bri_unified_knowledge_reader' AND inet_server_addr() IS NULL
           AND current_setting('listen_addresses')='');

CREATE POLICY unified_csv_record_gate ON bri.knowledge_record_access FOR SELECT TO bri_migrator
    USING (session_user='bri_unified_knowledge_reader' AND inet_server_addr() IS NULL
           AND current_setting('listen_addresses')='' AND readable
           AND EXISTS (SELECT FROM bri.source_records s WHERE s.csv_governed
                       AND (s.tenant_id,s.source_id)=(knowledge_record_access.tenant_id,knowledge_record_access.source_id)));
CREATE POLICY unified_csv_version_gate ON bri.knowledge_version_access FOR SELECT TO bri_migrator
    USING (session_user='bri_unified_knowledge_reader' AND inet_server_addr() IS NULL
           AND current_setting('listen_addresses')='' AND readable
           AND EXISTS (SELECT FROM bri.source_versions s WHERE s.csv_governed AND
                      (s.tenant_id,s.source_id,s.source_version_id)=(knowledge_version_access.tenant_id,
                       knowledge_version_access.source_id,knowledge_version_access.source_version_id)));

CREATE FUNCTION bri.unified_read_guard() RETURNS void
LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    PERFORM bri.xlsx_governance_role('bri_unified_knowledge_reader');
    -- The trusted caller arms the timeout in a separate command. Setting it
    -- inside an already running statement does not arm that statement.
    IF NOT EXISTS (SELECT FROM pg_settings WHERE name='temp_file_limit' AND setting::int BETWEEN 0 AND 16384)
       OR NOT EXISTS (SELECT FROM pg_settings WHERE name='statement_timeout' AND setting::int BETWEEN 1 AND 5000) THEN
        RAISE EXCEPTION 'Unified knowledge resource limits are not configured' USING ERRCODE='55000';
    END IF;
END $$;

CREATE FUNCTION bri.unified_fold(value text) RETURNS text
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog,pg_temp AS $$
    SELECT translate(btrim(regexp_replace($1 COLLATE "C", '[[:space:]]+', ' ', 'g')),
                     'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz');
$$;

-- Elect from readable record keys, then require the independent version allow
-- before looking up the approved job and checking governed same-node lineage.
-- The correlated OFFSET barriers prevent a job/payload-driven join order.
CREATE FUNCTION bri.unified_csv_candidates(t text, node text, target uuid, budget int)
RETURNS TABLE(id uuid, node_id text, ref text) LANGUAGE sql STABLE
SET search_path=pg_catalog,pg_temp AS $$
    SELECT j.job_id,j.scope_node_id,j.proposal_id
    FROM bri.knowledge_record_access ar
    CROSS JOIN LATERAL (
        SELECT av.source_id FROM bri.knowledge_version_access av
        WHERE (av.tenant_id,av.source_id,av.source_version_id)=(ar.tenant_id,ar.source_id,ar.source_id)
          AND av.readable
        OFFSET 0
    ) allowed
    CROSS JOIN LATERAL (
        SELECT cj.job_id,cj.scope_node_id,cj.proposal_id,cj.creator_id
        FROM bri.csv_jobs cj
        WHERE (cj.tenant_id,cj.proposal_id)=(ar.tenant_id,allowed.source_id)
          AND cj.scope_node_id=$2 AND cj.state='approved'
          AND ($3 IS NULL OR cj.job_id=$3)
        OFFSET 0
    ) j
    CROSS JOIN LATERAL (
        SELECT 1
        FROM bri.knowledge_proposals p
        JOIN bri.validated_knowledge k ON (k.tenant_id,k.proposal_id)=(p.tenant_id,p.proposal_id) AND k.csv_governed
        JOIN bri.source_extractions x ON (x.tenant_id,x.extraction_id,x.scope_node_id)=
             (p.tenant_id,p.extraction_id,p.scope_node_id) AND x.csv_governed
        JOIN bri.source_records s ON (s.tenant_id,s.source_id,s.scope_node_id)=
             (x.tenant_id,x.source_id,x.scope_node_id) AND s.csv_governed
        JOIN bri.source_versions v ON (v.tenant_id,v.source_id,v.source_version_id)=
             (x.tenant_id,x.source_id,x.source_version_id) AND v.csv_governed
        WHERE (p.tenant_id,p.proposal_id,p.scope_node_id)=(ar.tenant_id,j.proposal_id,j.scope_node_id)
          AND p.csv_governed AND p.csv_creator_id=j.creator_id
          AND x.extraction_id=j.proposal_id AND s.source_id=j.proposal_id AND v.source_version_id=j.proposal_id
        OFFSET 0
    ) lineage
    WHERE ar.tenant_id=$1 AND ar.readable
      AND ($3 IS NULL OR ar.source_id='csv:'||$3::text)
    LIMIT $4;
$$;

-- Start with principal-targeted version keys; require the independent record
-- allow before checking validated lineage, node and the latest publication.
CREATE FUNCTION bri.unified_xlsx_candidates(t text, actor uuid, node text, budget int)
RETURNS TABLE(id uuid, version uuid) LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $$
    SELECT k.record_id,k.job_id
    FROM bri.xlsx_version_access av
    CROSS JOIN LATERAL (
        SELECT ar.record_id FROM bri.xlsx_record_access ar
        WHERE (ar.tenant_id,ar.record_id,ar.principal_id)=(av.tenant_id,av.record_id,av.principal_id)
        OFFSET 0
    ) allowed
    CROSS JOIN LATERAL (
        SELECT v.record_id,v.job_id
        FROM bri.xlsx_validated_knowledge v
        JOIN bri.xlsx_jobs j ON (j.tenant_id,j.job_id)=(v.tenant_id,v.job_id)
        WHERE (v.tenant_id,v.record_id,v.job_id)=(av.tenant_id,allowed.record_id,av.job_id)
          AND j.scope_node_id=$3
        OFFSET 0
    ) k
    CROSS JOIN LATERAL (
        SELECT p.action FROM bri.xlsx_publication_events p
        WHERE (p.tenant_id,p.record_id)=(av.tenant_id,k.record_id)
        ORDER BY p.revision DESC LIMIT 1
    ) latest
    WHERE av.tenant_id=$1 AND av.principal_id=$2 AND latest.action='publish'
    LIMIT $4;
$$;

-- Output one bounded match per version (best rank, then earliest cell).
-- Also validate all CSV records, including the header, even after a match.
CREATE FUNCTION bri.unified_csv_projection(t text, ref text, query text)
RETURNS TABLE(original_sha256 text, content_sha256 text, first_line int, last_line int,
              source_id text, source_version_id uuid, score int, excerpt text, excerpt_truncated boolean, coordinate jsonb)
LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE c record; frame jsonb; row_values jsonb; field jsonb; value text;
    span_start int := 1; span_end int := 0; header_width int; position int;
    choice text; choice_pos int; rank int; row_won boolean;
BEGIN
    SELECT x.content,x.content_sha256,v.content_sha256 AS version_sha,j.original_sha256 AS job_sha,
           v.source_id AS source_key, v.source_version_id AS version_key,
           e.original_sha256 AS original_sha,e.first_line AS stored_first,e.last_line AS stored_last,
           j.byte_count,x.source_location,v.source_location AS version_location,x.extractor_name,x.extractor_version
    INTO c
    FROM bri.csv_jobs j
    JOIN bri.source_extractions x ON (x.tenant_id,x.extraction_id)=(j.tenant_id,j.proposal_id) AND x.csv_governed
    JOIN bri.source_versions v ON (v.tenant_id,v.source_id,v.source_version_id)=(j.tenant_id,j.proposal_id,j.proposal_id) AND v.csv_governed
    LEFT JOIN bri.csv_source_evidence e ON (e.tenant_id,e.source_id,e.source_version_id)=(v.tenant_id,v.source_id,v.source_version_id)
    WHERE (j.tenant_id,j.proposal_id)=($1,$2);
    IF (c.original_sha COLLATE "C" ~ '^[0-9a-f]{64}$' AND c.original_sha=c.job_sha
        AND c.content_sha256 COLLATE "C" ~ '^[0-9a-f]{64}$' AND c.content_sha256=c.version_sha
        AND c.stored_first=1 AND c.stored_last BETWEEN 1 AND c.byte_count
        AND c.source_location=format('csv:lines=1-%s',c.stored_last) AND c.version_location=c.source_location
        AND (c.extractor_name,c.extractor_version)=('governed-csv','1')
        AND octet_length(c.content) BETWEEN 1 AND 20000000
        AND encode(sha256(convert_to(c.content,'UTF8')),'hex')=c.content_sha256) IS NOT TRUE THEN
        RAISE EXCEPTION 'Unified knowledge provenance is invalid' USING ERRCODE='22000';
    END IF;
    -- The canonical Python producer accepts embedded NUL and writes \u0000.
    -- PostgreSQL text cannot represent NUL. Use a non-searchable control
    -- placeholder only after checking the original canonical digest. Match
    -- only unescaped JSON escapes (a literal backslash-u0000 stays literal).
    -- A placeholder preserves string boundaries and never affects line counts.
    IF strpos(c.content,$escape$\u0000$escape$)>0 THEN
        frame := regexp_replace(c.content COLLATE "C",$nul$(?<!\\)((?:\\\\)*)\\u0000$nul$,
                                $replacement$\1\\u0001$replacement$,'g')::jsonb;
    ELSE
        frame := c.content::jsonb;
    END IF;
    IF (jsonb_typeof(frame)='object' AND frame - ARRAY['headers','rows']='{}'::jsonb
        AND jsonb_typeof(frame->'headers')='array' AND jsonb_typeof(frame->'rows')='array') IS NOT TRUE THEN
        RAISE EXCEPTION 'Unified knowledge provenance is invalid' USING ERRCODE='22000';
    END IF;
    header_width := jsonb_array_length(frame->'headers');
    IF header_width NOT BETWEEN 1 AND 50 OR jsonb_array_length(frame->'rows') > 10000 THEN
        RAISE EXCEPTION 'Unified knowledge provenance is invalid' USING ERRCODE='22000';
    END IF;
    FOR i IN 0..jsonb_array_length(frame->'rows') LOOP
        row_values := CASE WHEN i=0 THEN frame->'headers' ELSE frame->'rows'->(i-1) END;
        IF jsonb_typeof(row_values) <> 'array' OR jsonb_array_length(row_values) <> header_width THEN
            RAISE EXCEPTION 'Unified knowledge provenance is invalid' USING ERRCODE='22000';
        END IF;
        span_end := span_start;
        row_won := false;
        FOR col IN 0..header_width-1 LOOP
            field := row_values->col;
            IF jsonb_typeof(field) <> 'string' THEN
                RAISE EXCEPTION 'Unified knowledge provenance is invalid' USING ERRCODE='22000';
            END IF;
            value := field #>> '{}';
            span_end := span_end + regexp_count(value COLLATE "C", E'\r\n|[\r\n]');
            IF query IS NOT NULL AND score IS DISTINCT FROM 0 THEN
                value := bri.unified_fold(value);
                position := strpos(value COLLATE "C",query COLLATE "C");
                IF position > 0 THEN
                    rank := CASE WHEN value COLLATE "C" = query COLLATE "C" THEN 0 ELSE 1 END;
                    IF score IS NULL OR rank < score THEN
                        score := rank; choice := value; choice_pos := position; row_won := true;
                    END IF;
                END IF;
            END IF;
        END LOOP;
        IF row_won THEN
            SELECT e.* INTO excerpt,excerpt_truncated
            FROM bri.unified_excerpt(replace(choice,chr(1),U&'\FFFD'),choice_pos) e;
            coordinate := jsonb_build_object('first_line',span_start,'last_line',span_end);
        END IF;
        span_start := span_end+1;
    END LOOP;
    IF span_end <> c.stored_last THEN
        RAISE EXCEPTION 'Unified knowledge provenance is invalid' USING ERRCODE='22000';
    END IF;
    original_sha256 := c.original_sha; content_sha256 := c.content_sha256;
    source_id := c.source_key;
    -- 0030 pins the governed identity to csv:<job UUID>; the route uses its UUID component.
    source_version_id := substring(c.version_key FROM 5)::uuid;
    first_line := 1; last_line := span_end;
    RETURN NEXT;
END $$;

CREATE FUNCTION bri.unified_excerpt(value text, match_pos int) RETURNS TABLE(excerpt text, truncated boolean)
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path=pg_catalog,pg_temp AS $$
DECLARE start_at int := greatest(1,match_pos-128);
    clipped text := substr(value,start_at,2048);
    prefix text := CASE WHEN start_at > 1 THEN U&'\2026' ELSE '' END;
    budget int := 2048-octet_length(prefix);
    lo int := 0; hi int := length(clipped); mid int;
BEGIN
    IF hi = length(value)-start_at+1 AND octet_length(clipped) <= budget THEN
        excerpt := prefix||clipped;
        truncated := start_at > 1;
        RETURN NEXT;
        RETURN;
    END IF;
    -- Mark each shortened side and include its UTF-8 bytes in the budget.
    -- At most 128 preceding characters and 256 match bytes fit before clipping.
    budget := budget-octet_length(U&'\2026');
    WHILE lo < hi LOOP
        mid := (lo+hi+1)/2;
        IF octet_length(left(clipped,mid)) <= budget THEN lo := mid; ELSE hi := mid-1; END IF;
    END LOOP;
    excerpt := prefix||left(clipped,lo)||U&'\2026';
    truncated := true;
    RETURN NEXT;
END $$;

CREATE FUNCTION bri.unified_xlsx_projection(t text, version uuid, query text)
RETURNS TABLE(source_id text, source_version_id uuid, original_sha256 text, canonical_sha256 text,
              extractor_version int, canonicalization_version int, score int, excerpt text,
              excerpt_truncated boolean, coordinate jsonb)
LANGUAGE plpgsql STABLE SET search_path=pg_catalog,pg_temp AS $$
DECLARE c record; rows jsonb; r jsonb; cell jsonb; value text; pos int; rank int;
    row_no int := 0; col int; width int; label text;
BEGIN
    SELECT x.canonical_text,v.sheet_id,v.sheet_title,v.cell_range,
           v.job_id AS version_key,s.job_id AS source_key,v.original_sha256 AS original_digest,
           v.canonical_sha256 AS canonical_digest,x.extractor_version AS extractor,
           x.canonicalization_version AS canonicalization INTO c
    FROM bri.xlsx_source_versions v JOIN bri.xlsx_extractions x USING (tenant_id,job_id,canonical_sha256)
    JOIN bri.xlsx_sources s ON (s.tenant_id,s.job_id)=(v.tenant_id,v.job_id)
    WHERE (v.tenant_id,v.job_id)=($1,$2);
    IF NOT FOUND THEN RAISE EXCEPTION 'Unified knowledge provenance is invalid' USING ERRCODE='22000'; END IF;
    source_id := c.source_key::text; source_version_id := c.version_key;
    original_sha256 := c.original_digest; canonical_sha256 := c.canonical_digest;
    extractor_version := c.extractor; canonicalization_version := c.canonicalization;
    -- 0033 checks immutable bytes/digest; the trusted strict producer binds
    -- the dense A1-origin matrix and typed cell tuples to this worksheet.
    rows := c.canonical_text::jsonb;
    IF (rows->'worksheet'=jsonb_build_object('identity',c.sheet_id,'title',c.sheet_title,'range',c.cell_range)
        AND rows->'version'='1'::jsonb AND jsonb_typeof(rows->'rows')='array') IS NOT TRUE THEN
        RAISE EXCEPTION 'Unified knowledge provenance is invalid' USING ERRCODE='22000';
    END IF;
    rows := rows->'rows';
    FOR r IN SELECT cells.value FROM jsonb_array_elements(rows) AS cells(value) LOOP
        row_no := row_no+1;
        width := jsonb_array_length(r);
        FOR col IN 1..width LOOP
            cell := r->(col-1);
            IF (cell->>0 IN ('text','number','date','time','datetime') AND jsonb_typeof(cell->1)='string')
               OR (cell->>0='boolean' AND jsonb_typeof(cell->1)='boolean') THEN
                value := bri.unified_fold(cell->>1);
            ELSE
                CONTINUE;
            END IF;
            pos := strpos(value COLLATE "C",query COLLATE "C");
            IF pos=0 THEN CONTINUE; END IF;
            rank := CASE WHEN value COLLATE "C" = query COLLATE "C" THEN 0 ELSE 1 END;
            IF score IS NULL OR rank < score THEN
                score := rank;
                SELECT e.* INTO excerpt,excerpt_truncated FROM bri.unified_excerpt(value,pos) e;
                label := CASE WHEN col <= 26 THEN '' ELSE chr(64+(col-1)/26) END || chr(65+(col-1)%26) || row_no;
                coordinate := jsonb_build_object('sheet_id',c.sheet_id,'sheet_title',c.sheet_title,'cell',label);
                IF score=0 THEN RETURN NEXT; RETURN; END IF;
            END IF;
        END LOOP;
    END LOOP;
    RETURN NEXT;
END $$;

CREATE FUNCTION bri.unified_knowledge_search(t text, actor uuid, sub uuid, sid uuid, issuer text, node text, query text)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET work_mem='1MB' SET hash_mem_multiplier=1 SET max_parallel_workers_per_gather=0 AS $$
DECLARE csv_ids uuid[] := ARRAY[]::uuid[]; xlsx_ids uuid[] := ARRAY[]::uuid[]; xlsx_versions uuid[];
    csv_ok boolean; xlsx_ok boolean; q text; result jsonb; matched record;
    exact_matches jsonb := '[]'; partial_matches jsonb := '[]'; item jsonb; id uuid;
    n int; i int; separator_spaces int;
BEGIN
    PERFORM bri.unified_read_guard();
    IF query IS NULL OR octet_length(query) NOT BETWEEN 1 AND 4096 THEN
        RAISE EXCEPTION 'Invalid knowledge query' USING ERRCODE='22023';
    END IF;
    q := bri.unified_fold(query);
    IF octet_length(q) NOT BETWEEN 1 AND 256 OR strpos(q,chr(1))>0 THEN
        RAISE EXCEPTION 'Invalid knowledge query' USING ERRCODE='22023';
    END IF;
    csv_ok := bri.csv_has_authority(t,actor,sub,sid,issuer,node,'knowledge:read');
    xlsx_ok := bri.xlsx_governance_authorized(t,actor,sub,sid,issuer,node,'knowledge:read');
    IF csv_ok IS NOT TRUE AND xlsx_ok IS NOT TRUE THEN
        RAISE EXCEPTION 'Knowledge scope denied' USING ERRCODE='42501';
    END IF;
    IF csv_ok IS TRUE THEN
        SELECT coalesce(array_agg(c.id ORDER BY c.id),ARRAY[]::uuid[]) INTO csv_ids
        FROM bri.unified_csv_candidates(t,node,NULL,1001) c;
    END IF;
    n := cardinality(csv_ids);
    IF n <= 1000 AND xlsx_ok IS TRUE THEN
        SELECT coalesce(array_agg(c.id ORDER BY c.id),ARRAY[]::uuid[]),array_agg(c.version ORDER BY c.id)
        INTO xlsx_ids,xlsx_versions
        FROM bri.unified_xlsx_candidates(t,actor,node,1001-n) c;
    END IF;
    IF n+cardinality(xlsx_ids)>1000 THEN
        RAISE EXCEPTION 'Unified knowledge scope exceeds the candidate limit' USING ERRCODE='54000';
    END IF;
    FOR i IN 1..n+cardinality(xlsx_ids) LOOP
        IF i <= n THEN
            id := csv_ids[i];
            SELECT * INTO matched FROM bri.unified_csv_projection(t,'csv:'||id,q);
            item := jsonb_build_object('format','csv','record_id',id,'content_sha256',matched.content_sha256,
                'evidence_url',format('/v1/knowledge/csv/%s/versions/%s/evidence',id,matched.source_version_id));
        ELSE
            id := xlsx_ids[i-n];
            SELECT * INTO matched FROM bri.unified_xlsx_projection(t,xlsx_versions[i-n],q);
            item := jsonb_build_object('format','xlsx','record_id',id,'canonical_sha256',matched.canonical_sha256,
                'extractor_version',matched.extractor_version,'canonicalization_version',matched.canonicalization_version,
                'evidence_url',format('/v2/knowledge/xlsx/%s/evidence/%s',id,matched.source_version_id));
        END IF;
        IF matched.score IS NOT NULL THEN
            item := item || jsonb_build_object('source_id',matched.source_id,'source_version_id',matched.source_version_id,
                'original_sha256',matched.original_sha256,'match',CASE matched.score WHEN 0 THEN 'exact' ELSE 'substring' END,
                'excerpt',matched.excerpt,'excerpt_truncated',matched.excerpt_truncated,'evidence',matched.coordinate);
            IF matched.score=0 AND jsonb_array_length(exact_matches)<20 THEN
                exact_matches := exact_matches || item;
            ELSIF matched.score=1 AND jsonb_array_length(partial_matches)<20 THEN
                partial_matches := partial_matches || item;
            END IF;
        END IF;
    END LOOP;
    -- jsonb::text adds one space per object colon/comma and array comma.
    -- Subtract only these structural separators; the API independently checks the actual body.
    SELECT jsonb_build_object('version',1,'status','complete','results',coalesce(jsonb_agg(e.item ORDER BY e.ord),'[]')),
           5 + greatest(count(*)-1,0) + coalesce(sum(
               2*(SELECT count(*) FROM jsonb_object_keys(e.item)) - 1 +
               2*(SELECT count(*) FROM jsonb_object_keys(e.item->'evidence')) - 1),0)
    INTO result,separator_spaces FROM (SELECT * FROM jsonb_array_elements(exact_matches||partial_matches)
                      WITH ORDINALITY AS x(item,ord) LIMIT 20) e;
    IF octet_length(result::text)-separator_spaces>131072 THEN
        RAISE EXCEPTION 'Unified knowledge response exceeds the byte limit' USING ERRCODE='54000';
    END IF;
    RETURN result;
END $$;

CREATE FUNCTION bri.unified_csv_evidence(t text, actor uuid, sub uuid, sid uuid, issuer text, record_id uuid, version uuid)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET work_mem='1MB' SET hash_mem_multiplier=1 SET max_parallel_workers_per_gather=0 AS $$
DECLARE node text; provenance record;
BEGIN
    PERFORM bri.unified_read_guard();
    IF record_id IS NULL OR version IS DISTINCT FROM record_id THEN RETURN NULL; END IF;
    SELECT j.scope_node_id INTO node FROM bri.csv_jobs j WHERE (j.tenant_id,j.job_id)=(t,record_id);
    IF NOT FOUND OR bri.csv_has_authority(t,actor,sub,sid,issuer,node,'knowledge:read') IS NOT TRUE THEN RETURN NULL; END IF;
    IF NOT EXISTS (SELECT FROM bri.unified_csv_candidates(t,node,record_id,1)) THEN RETURN NULL; END IF;
    SELECT * INTO provenance FROM bri.unified_csv_projection(t,'csv:'||record_id,NULL);
    RETURN jsonb_build_object('record_id',record_id,'source_version_id',version,
        'first_line',provenance.first_line,'last_line',provenance.last_line,
        'original_sha256',provenance.original_sha256,'content_sha256',provenance.content_sha256);
END $$;

-- Remove PUBLIC and any role grants inherited from an altered default ACL.
DO $$
DECLARE fn record; grantee_role name;
BEGIN
    FOR fn IN SELECT p.oid,p.oid::regprocedure AS signature,p.proowner,p.proacl FROM pg_proc p
        WHERE p.pronamespace='bri'::regnamespace AND p.proname IN
            ('unified_read_guard','unified_fold','unified_csv_candidates','unified_xlsx_candidates',
             'unified_csv_projection','unified_excerpt','unified_xlsx_projection','unified_knowledge_search','unified_csv_evidence') LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC',fn.signature);
        FOR grantee_role IN SELECT DISTINCT r.rolname FROM aclexplode(fn.proacl) a
            JOIN pg_roles r ON r.oid=a.grantee WHERE r.oid<>fn.proowner LOOP
            EXECUTE format('REVOKE ALL ON FUNCTION %s FROM %I',fn.signature,grantee_role);
        END LOOP;
    END LOOP;
END $$;
