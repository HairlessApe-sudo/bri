-- Local-only; grant this named entry point to the existing private reader
-- only when provisioning the disposable socket-only fixture, just as in 0035.
CREATE FUNCTION bri.unified_knowledge_search_scopes(t text, actor uuid, sub uuid, sid uuid, issuer text)
RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp
SET work_mem='1MB' SET hash_mem_multiplier=1 SET max_parallel_workers_per_gather=0 AS $$
DECLARE node_ids text[]; labels jsonb[] := ARRAY[]::jsonb[]; item record; raw_bytes bigint := 0;
BEGIN
    PERFORM bri.unified_read_guard();
    -- The identity/session part of the existing 0030/0034 gates, without the
    -- node predicate: an eligible identity can legitimately have zero grants.
    -- Keep the independent authoritative search predicates on emitted nodes.
    IF NOT EXISTS (SELECT FROM bri.provider_event_source src WHERE src.issuer=$5)
       OR NOT EXISTS (
           SELECT FROM bri.client_activation a JOIN bri.tenant_admin_policies ap USING (tenant_id)
           WHERE a.tenant_id=$1 AND (SELECT count(*) FROM bri.governance_eligible e WHERE e.tenant_id=$1)
                >= ap.min_emergency_admins
       ) OR NOT EXISTS (
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
       ) THEN
        RAISE EXCEPTION 'Knowledge scope denied' USING ERRCODE='42501';
    END IF;

    -- For each tenant-qualified permission-bearing role, constrain the
    -- assignment lookup by the existing (tenant, principal, role) PK prefix.
    -- The lateral barrier prevents flattening into an assignment-driven join.
    -- The unchanged authoritative guards below still check each exact node.
    SELECT ARRAY(
        SELECT DISTINCT picked.scope_node_id COLLATE "C"
        FROM bri.role_permissions rp
        CROSS JOIN LATERAL (
            SELECT a.scope_node_id FROM bri.auth_role_assignments a
            WHERE (a.tenant_id,a.principal_id,a.role_id)=(rp.tenant_id,$2,rp.role_id)
              AND a.status='active'
              AND a.scope_node_id COLLATE "C" ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$'
            OFFSET 0
        ) picked
        WHERE (rp.tenant_id,rp.permission)=($1,'knowledge:read')
        LIMIT 501
    ) INTO node_ids;
    IF cardinality(node_ids)>500 THEN
        RAISE EXCEPTION 'Knowledge selectable scope limit exceeded' USING ERRCODE='54000';
    END IF;

    -- Foreign key: each selected assignment refers to this exact tenant/node.
    -- Fetch the length first so one huge toasted label need not enter JSON.
    FOR item IN SELECT id, n.nbytes FROM unnest(node_ids) AS ids(id)
        CROSS JOIN LATERAL (
            SELECT octet_length(o.display_name) AS nbytes FROM bri.org_nodes o
            WHERE (o.tenant_id,o.node_id)=($1,ids.id) OFFSET 0
        ) n
    LOOP
        IF bri.csv_has_authority($1,$2,$3,$4,$5,item.id,'knowledge:read') IS NOT TRUE
           AND bri.xlsx_governance_authorized($1,$2,$3,$4,$5,item.id,'knowledge:read') IS NOT TRUE THEN
            RAISE EXCEPTION 'Knowledge scope denied' USING ERRCODE='42501';
        END IF;
        raw_bytes := raw_bytes + item.nbytes;
        IF raw_bytes>131072 THEN
            RAISE EXCEPTION 'Knowledge scope labels exceed receipt budget' USING ERRCODE='54000';
        END IF;
    END LOOP;
    FOR item IN SELECT id, n.display_name FROM unnest(node_ids) AS ids(id)
        CROSS JOIN LATERAL (
            SELECT o.display_name FROM bri.org_nodes o WHERE (o.tenant_id,o.node_id)=($1,ids.id) OFFSET 0
        ) n ORDER BY n.display_name COLLATE "C", id COLLATE "C"
    LOOP
        labels := array_append(labels,jsonb_build_object('scope_node_id',item.id,'display_label',item.display_name));
    END LOOP;
    IF cardinality(labels)<>cardinality(node_ids) THEN
        RAISE EXCEPTION 'Knowledge scope association unavailable' USING ERRCODE='55000';
    END IF;
    RETURN jsonb_build_object('version',1,'status','complete','scopes',to_jsonb(labels));
END $$;

DO $$
DECLARE grantee_role name;
BEGIN
    REVOKE ALL ON FUNCTION bri.unified_knowledge_search_scopes(text,uuid,uuid,uuid,text) FROM PUBLIC;
    FOR grantee_role IN SELECT DISTINCT r.rolname FROM pg_proc p
        CROSS JOIN LATERAL aclexplode(p.proacl) a JOIN pg_roles r ON r.oid=a.grantee
        WHERE p.oid='bri.unified_knowledge_search_scopes(text,uuid,uuid,uuid,text)'::regprocedure AND r.oid<>p.proowner
    LOOP
        EXECUTE format('REVOKE ALL ON FUNCTION bri.unified_knowledge_search_scopes(text,uuid,uuid,uuid,text) FROM %I',grantee_role);
    END LOOP;
END $$;
