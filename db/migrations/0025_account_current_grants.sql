-- A11.7: exact directory target, with a separate root-scoped read authority.
-- Keep the existing trigger, governance serialization, owner and ACL.
-- Preserve the precedence of the older protected permissions explicitly.
CREATE OR REPLACE FUNCTION bri.guard_deactivation_root() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE old_tenant text; new_tenant text; protected_permission text;
BEGIN
    IF TG_OP = 'UPDATE' AND (OLD.tenant_id,OLD.node_id,OLD.node_type,OLD.parent_node_id IS NULL)
        IS NOT DISTINCT FROM (NEW.tenant_id,NEW.node_id,NEW.node_type,NEW.parent_node_id IS NULL) THEN
        RETURN NEW;
    END IF;
    IF TG_OP <> 'INSERT' AND OLD.parent_node_id IS NULL THEN old_tenant := OLD.tenant_id; END IF;
    IF TG_OP <> 'DELETE' AND NEW.parent_node_id IS NULL THEN new_tenant := NEW.tenant_id; END IF;
    SELECT r.permission INTO protected_permission
    FROM bri.auth_role_assignments a JOIN bri.role_permissions r USING (tenant_id,role_id)
    WHERE a.tenant_id IN (old_tenant,new_tenant) AND a.status = 'active'
      AND r.permission IN ('user:deactivate','account:history:read','account:grants:read')
    ORDER BY CASE r.permission WHEN 'user:deactivate' THEN 1 WHEN 'account:history:read' THEN 2 ELSE 3 END
    LIMIT 1;
    IF protected_permission = 'user:deactivate' THEN
        RAISE EXCEPTION 'deactivation root topology is protected' USING ERRCODE = '42501';
    ELSIF protected_permission = 'account:history:read' THEN
        RAISE EXCEPTION 'account history root topology is protected' USING ERRCODE = '42501';
    ELSIF protected_permission = 'account:grants:read' THEN
        RAISE EXCEPTION 'account grants root topology is protected' USING ERRCODE = '42501';
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END $$;

CREATE FUNCTION bri.read_account_current_grants(t text, actor uuid, sid uuid, issuer text, target uuid)
RETURNS TABLE(account_class text, account_status text, scope_id text, scope_name text,
              permission text, eligible boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF session_user <> 'bri_app' OR t IS NULL OR t IS DISTINCT FROM nullif(current_setting('bri.tenant_id',true),'')
        OR NOT EXISTS (
            SELECT FROM bri.auth_role_assignments a JOIN bri.role_permissions rp USING (tenant_id,role_id)
            JOIN bri.org_nodes n ON (n.tenant_id,n.node_id) = (a.tenant_id,a.scope_node_id)
            WHERE a.tenant_id = t AND a.principal_id = actor AND a.status = 'active'
              AND rp.permission = 'account:grants:read' AND n.node_type = 'root' AND n.parent_node_id IS NULL
              AND NOT EXISTS (SELECT FROM bri.org_nodes x
                              WHERE x.tenant_id = t AND x.parent_node_id IS NULL AND x.node_id <> n.node_id)
        ) OR NOT EXISTS (
            SELECT FROM bri.auth_sessions s LEFT JOIN bri.session_guards g USING (principal_id)
            WHERE s.principal_id = actor AND s.session_id = sid
              AND s.auth_user_id::text = nullif(current_setting('bri.auth_user_id',true),'')
              AND s.started_at > coalesce(g.primary_after,'-infinity'::timestamptz)
        ) OR EXISTS (SELECT FROM bri.credential_operations c
                     WHERE c.principal_id = actor AND c.confirmed_at IS NULL) THEN
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

REVOKE ALL ON FUNCTION bri.read_account_current_grants(text,uuid,uuid,text,uuid) FROM PUBLIC, bri_app;
GRANT EXECUTE ON FUNCTION bri.read_account_current_grants(text,uuid,uuid,text,uuid) TO bri_app;
