-- A11.9: structured filters on the existing directory projection. Apply them
-- before the offset and the extra row used by has_more.
CREATE FUNCTION bri.read_user_directory_page(t text, actor uuid, sid uuid, issuer text,
    target uuid, query_name text, query_id uuid, page_size integer, page_offset integer,
    filter_status text, filter_role text, filter_mfa_status text)
RETURNS TABLE (id uuid, display_name text, status text, role text, mfa_status text)
LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    read_at timestamptz := clock_timestamp();
BEGIN
    IF t IS NULL OR t IS DISTINCT FROM nullif(current_setting('bri.tenant_id', true), '')
        OR bri.client_is_operational(t) IS NOT TRUE
        OR NOT EXISTS (
            SELECT FROM bri.auth_sessions s JOIN bri.auth_identity_links i USING (auth_user_id, principal_id)
            JOIN bri.auth_principals p USING (principal_id)
            JOIN bri.auth_tenant_memberships m USING (principal_id)
            WHERE s.principal_id = actor AND s.session_id = sid AND m.tenant_id = t
              AND i.auth_user_id::text = current_setting('bri.auth_user_id', true)
              AND i.status = 'active' AND i.auth_issuer = issuer AND i.auth_subject = i.auth_user_id::text
              AND s.revoked_at IS NULL AND s.started_at <= read_at
              AND read_at < least(s.expires_at, s.started_at + interval '8 hours')
              AND p.status = 'active' AND p.deletion_requested_at IS NULL
              AND m.membership_type = 'admin' AND m.status = 'active'
              AND NOT EXISTS (SELECT FROM bri.auth_tenant_memberships other
                              WHERE other.principal_id = actor AND other.tenant_id <> t)
              AND NOT EXISTS (SELECT FROM bri.platform_superadmins x WHERE x.principal_id = actor)
        ) OR NOT EXISTS (
            SELECT FROM bri.auth_role_assignments a
            JOIN bri.role_permissions rp USING (tenant_id, role_id)
            JOIN bri.org_nodes n ON (n.tenant_id, n.node_id) = (a.tenant_id, a.scope_node_id)
            WHERE a.tenant_id = t AND a.principal_id = actor AND a.status = 'active'
              AND rp.permission = 'user:directory:read' AND n.parent_node_id IS NULL
              AND NOT EXISTS (SELECT FROM bri.org_nodes other
                              WHERE other.tenant_id = t AND other.parent_node_id IS NULL AND other.node_id <> n.node_id)
        ) THEN
        RAISE EXCEPTION 'directory access denied' USING ERRCODE = '42501';
    END IF;

    IF page_size IS NULL OR page_size NOT BETWEEN 1 AND 100 OR
       page_offset IS NULL OR page_offset NOT BETWEEN 0 AND 10000 OR
       char_length(query_name) > 128 OR
       filter_status NOT IN ('pending', 'active', 'suspended', 'deactivated') OR
       filter_role NOT IN ('user', 'superuser') OR
       filter_mfa_status NOT IN ('verified', 'unknown') THEN
        RAISE EXCEPTION 'invalid directory query' USING ERRCODE = '22023';
    END IF;

    RETURN QUERY
    WITH directory_rows AS (
        SELECT p.principal_id AS id, p.display_name,
            -- Deletion requests block access but are not completed deactivation.
            CASE WHEN 'deactivated' IN (p.status, m.status) THEN 'deactivated'
                 WHEN p.deletion_requested_at IS NOT NULL OR 'suspended' IN (p.status, m.status) THEN 'suspended'
                 WHEN 'pending' IN (p.status, m.status) THEN 'pending'
                 ELSE 'active' END AS status,
            m.membership_type AS role,
            CASE WHEN p.status = 'active' AND m.status = 'active' AND p.deletion_requested_at IS NULL
              AND NOT EXISTS (SELECT FROM bri.credential_operations c WHERE c.principal_id = p.principal_id
                              AND c.confirmed_at IS NULL)
              AND EXISTS (
                SELECT FROM bri.client_totp_observations e
                JOIN bri.auth_identity_links i USING (auth_user_id, principal_id, auth_issuer)
                WHERE e.tenant_id = t AND e.principal_id = p.principal_id
                  AND i.status = 'active' AND i.provider_type = 'native' AND i.auth_issuer = issuer
                  AND i.auth_subject = i.auth_user_id::text
                  AND e.observed_at <= read_at AND read_at < e.verified_until
                  -- Do not revive evidence once an intervening security event invalidated it.
                  AND NOT EXISTS (SELECT FROM bri.session_guards g WHERE g.principal_id = p.principal_id
                                  AND (e.observed_at <= g.primary_after OR e.observed_at <= g.latest_provider_change))
            ) THEN 'verified' ELSE 'unknown' END AS mfa_status
        FROM bri.auth_tenant_memberships m JOIN bri.auth_principals p USING (principal_id)
        WHERE m.tenant_id = t AND m.membership_type IN ('user', 'superuser')
          AND NOT EXISTS (SELECT FROM bri.platform_superadmins x WHERE x.principal_id = p.principal_id)
          AND NOT EXISTS (SELECT FROM bri.auth_tenant_memberships other
                          WHERE other.principal_id = p.principal_id AND other.tenant_id <> t)
          AND (target IS NULL OR p.principal_id = target)
          AND (query_name IS NULL OR p.principal_id = query_id OR
               strpos(lower(p.display_name), lower(query_name)) > 0)
    )
    SELECT d.id, d.display_name, d.status, d.role, d.mfa_status
    FROM directory_rows d
    WHERE (filter_status IS NULL OR d.status = filter_status)
      AND (filter_role IS NULL OR d.role = filter_role)
      AND (filter_mfa_status IS NULL OR d.mfa_status = filter_mfa_status)
    ORDER BY d.id
    LIMIT page_size + 1 OFFSET page_offset;
END $$;
REVOKE ALL ON FUNCTION bri.read_user_directory_page(text,uuid,uuid,text,uuid,text,uuid,integer,integer,text,text,text)
    FROM PUBLIC, bri_app;

-- Shared actor-side A11.7 gate. The directory read separately enforces
-- the exact target boundary; grant visibility never participates in this bit.
CREATE FUNCTION bri.has_account_current_grants_authority(t text, actor uuid, sid uuid)
RETURNS boolean
LANGUAGE sql STABLE SECURITY INVOKER SET search_path = pg_catalog, pg_temp AS $$
    SELECT session_user = 'bri_app' AND t IS NOT NULL
       AND t IS NOT DISTINCT FROM nullif(current_setting('bri.tenant_id',true),'')
       AND EXISTS (
            SELECT FROM bri.auth_role_assignments a JOIN bri.role_permissions rp USING (tenant_id,role_id)
            JOIN bri.org_nodes n ON (n.tenant_id,n.node_id) = (a.tenant_id,a.scope_node_id)
            WHERE a.tenant_id = t AND a.principal_id = actor AND a.status = 'active'
              AND rp.permission = 'account:grants:read' AND n.node_type = 'root' AND n.parent_node_id IS NULL
              AND NOT EXISTS (SELECT FROM bri.org_nodes x
                              WHERE x.tenant_id = t AND x.parent_node_id IS NULL AND x.node_id <> n.node_id)
        ) AND EXISTS (
            SELECT FROM bri.auth_sessions s LEFT JOIN bri.session_guards g USING (principal_id)
            WHERE s.principal_id = actor AND s.session_id = sid
              AND s.auth_user_id::text = nullif(current_setting('bri.auth_user_id',true),'')
              AND s.started_at > coalesce(g.primary_after,'-infinity'::timestamptz)
        ) AND NOT EXISTS (SELECT FROM bri.credential_operations c
                     WHERE c.principal_id = actor AND c.confirmed_at IS NULL);
$$;
REVOKE ALL ON FUNCTION bri.has_account_current_grants_authority(text,uuid,uuid) FROM PUBLIC, bri_app;

-- Keep the existing signature, parameter names, projection, owner and ACL
-- for directory detail and existing account-history, grants and MFA callers.
CREATE OR REPLACE FUNCTION bri.read_user_directory(t text, actor uuid, sid uuid, issuer text,
    target uuid, query_name text, query_id uuid, page_size integer, page_offset integer)
RETURNS TABLE (id uuid, display_name text, status text, role text, mfa_status text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT d.id, d.display_name, d.status, d.role, d.mfa_status
    FROM bri.read_user_directory_page(t,actor,sid,issuer,target,query_name,query_id,page_size,page_offset,
                                     NULL,NULL,NULL) d
    ORDER BY d.id;
$$;

-- The only additional runtime entry point is list-only. Both reads use the
-- same snapshot, and the actor's authority is computed once, not per target.
CREATE FUNCTION bri.read_user_directory_overview(t text, actor uuid, sid uuid, issuer text,
    query_name text, query_id uuid, page_size integer, page_offset integer,
    filter_status text, filter_role text, filter_mfa_status text)
RETURNS TABLE (id uuid, display_name text, status text, role text, mfa_status text, can_view_grants boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE
    grants_authorized boolean := bri.has_account_current_grants_authority(t,actor,sid);
BEGIN
    RETURN QUERY
    SELECT d.id, d.display_name, d.status, d.role, d.mfa_status, grants_authorized
    FROM bri.read_user_directory_page(t,actor,sid,issuer,NULL,query_name,query_id,page_size,page_offset,
                                     filter_status,filter_role,filter_mfa_status) d
    ORDER BY d.id;
END $$;
REVOKE ALL ON FUNCTION bri.read_user_directory_overview(text,uuid,uuid,text,text,uuid,integer,integer,text,text,text)
    FROM PUBLIC, bri_app;
GRANT EXECUTE ON FUNCTION bri.read_user_directory_overview(text,uuid,uuid,text,text,uuid,integer,integer,text,text,text)
    TO bri_app;

CREATE OR REPLACE FUNCTION bri.read_account_current_grants(t text, actor uuid, sid uuid, issuer text, target uuid)
RETURNS TABLE(account_class text, account_status text, scope_id text, scope_name text,
              permission text, eligible boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT bri.has_account_current_grants_authority(t,actor,sid) THEN
        RAISE EXCEPTION 'account current grants access denied' USING ERRCODE = '42501';
    END IF;

    -- Never pass a NULL target to the directory's list mode. Match the
    -- returned ID to the original target, including in the NULL case.
    RETURN QUERY
    SELECT d.role, d.status, visible.node_id, visible.display_name, visible.permission,
           -- Eligibility reflects disclosed directory lifecycle only, not session
           -- admission. The API applies the shared role ceiling separately.
           CASE WHEN visible.node_id IS NOT NULL THEN d.status = 'active' END
    FROM bri.read_user_directory(t,actor,sid,issuer,coalesce(target,actor),NULL,NULL,1,0) d
    LEFT JOIN LATERAL (
        SELECT DISTINCT n.node_id, n.display_name, rp.permission
        FROM bri.auth_role_assignments a JOIN bri.role_permissions rp USING (tenant_id,role_id)
        JOIN bri.org_nodes n ON (n.tenant_id,n.node_id) = (a.tenant_id,a.scope_node_id)
        WHERE a.tenant_id = t AND a.principal_id = d.id AND a.status = 'active'
          AND rp.permission IN ('organisation:read','knowledge:read')
          -- Neither an ancestor grant nor the target's own authority counts.
          AND EXISTS (
              SELECT FROM bri.auth_role_assignments v JOIN bri.role_permissions vr USING (tenant_id,role_id)
              WHERE v.tenant_id = t AND v.principal_id = actor AND v.status = 'active'
                AND v.scope_node_id = n.node_id AND vr.permission = 'organisation:read'
          )
    ) visible ON true
    WHERE d.id = target;
END $$;
