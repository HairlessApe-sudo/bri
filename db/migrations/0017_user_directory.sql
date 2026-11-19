-- A11.1 read boundary. No grants are seeded and no runtime profile writes are added.
ALTER TABLE bri.auth_principals ADD COLUMN display_name text
    CHECK (char_length(display_name) BETWEEN 1 AND 128);

-- The legacy role catalog is writable by the runtime; this permission is not.
CREATE POLICY directory_permission_insert ON bri.role_permissions AS RESTRICTIVE FOR INSERT TO bri_app
    WITH CHECK (permission <> 'user:directory:read');
CREATE POLICY directory_permission_update ON bri.role_permissions AS RESTRICTIVE FOR UPDATE TO bri_app
    USING (permission <> 'user:directory:read') WITH CHECK (permission <> 'user:directory:read');
CREATE POLICY directory_permission_delete ON bri.role_permissions AS RESTRICTIVE FOR DELETE TO bri_app
    USING (permission <> 'user:directory:read');

-- Cascading FK deletes do not honor the app's child-table RLS. Protect the
-- parent even before any authenticated principal has been assigned the role.
CREATE FUNCTION bri.guard_directory_role_delete() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF EXISTS (SELECT FROM bri.role_permissions rp
               WHERE (rp.tenant_id, rp.role_id) = (OLD.tenant_id, OLD.role_id)
                 AND rp.permission = 'user:directory:read') THEN
        RAISE EXCEPTION 'directory role is protected' USING ERRCODE = '42501';
    END IF;
    RETURN OLD;
END $$;
CREATE TRIGGER directory_role_delete BEFORE DELETE ON bri.app_roles
FOR EACH ROW WHEN (current_user = 'bri_app') EXECUTE FUNCTION bri.guard_directory_role_delete();
REVOKE ALL ON FUNCTION bri.guard_directory_role_delete() FROM PUBLIC, bri_app;

-- A runtime org-node update must not turn a scoped grant into a root grant.
-- The existing governance statement triggers serialize topology and grant
-- changes. The definer also sees assignments belonging to other principals.
CREATE FUNCTION bri.guard_directory_root_scope() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF EXISTS (SELECT FROM bri.auth_role_assignments a
               JOIN bri.role_permissions rp USING (tenant_id, role_id)
               WHERE (a.tenant_id, a.scope_node_id) = (OLD.tenant_id, OLD.node_id)
                 AND rp.permission = 'user:directory:read') THEN
        RAISE EXCEPTION 'directory scope is protected' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER directory_root_scope BEFORE UPDATE ON bri.org_nodes FOR EACH ROW
WHEN (current_user = 'bri_app' AND
      (OLD.parent_node_id IS NULL) IS DISTINCT FROM (NEW.parent_node_id IS NULL))
EXECUTE FUNCTION bri.guard_directory_root_scope();
REVOKE ALL ON FUNCTION bri.guard_directory_root_scope() FROM PUBLIC, bri_app;

-- Existing owner-only SELECT policies cover this definer. Runtime direct-read
-- policies on principals, memberships, sessions and evidence are unchanged.
CREATE FUNCTION bri.read_user_directory(t text, actor uuid, sid uuid, issuer text,
                                         target uuid, query_name text, query_id uuid,
                                         page_size integer, page_offset integer)
RETURNS TABLE (id uuid, display_name text, status text, role text, mfa_status text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
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
       char_length(query_name) > 128 THEN
        RAISE EXCEPTION 'invalid directory query' USING ERRCODE = '22023';
    END IF;

    RETURN QUERY
    SELECT p.principal_id, p.display_name,
        -- Deletion requests block access but are not completed deactivation.
        CASE WHEN 'deactivated' IN (p.status, m.status) THEN 'deactivated'
             WHEN p.deletion_requested_at IS NOT NULL OR 'suspended' IN (p.status, m.status) THEN 'suspended'
             WHEN 'pending' IN (p.status, m.status) THEN 'pending'
             ELSE 'active' END,
        m.membership_type,
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
        ) THEN 'verified' ELSE 'unknown' END
    FROM bri.auth_tenant_memberships m JOIN bri.auth_principals p USING (principal_id)
    WHERE m.tenant_id = t AND m.membership_type IN ('user', 'superuser')
      AND NOT EXISTS (SELECT FROM bri.platform_superadmins x WHERE x.principal_id = p.principal_id)
      AND NOT EXISTS (SELECT FROM bri.auth_tenant_memberships other
                      WHERE other.principal_id = p.principal_id AND other.tenant_id <> t)
      AND (target IS NULL OR p.principal_id = target)
      AND (query_name IS NULL OR p.principal_id = query_id OR
           strpos(lower(p.display_name), lower(query_name)) > 0)
    ORDER BY p.principal_id
    LIMIT page_size + 1 OFFSET page_offset;
END $$;

REVOKE ALL ON FUNCTION bri.read_user_directory(text, uuid, uuid, text, uuid, text, uuid, integer, integer)
    FROM PUBLIC, bri_app;
GRANT EXECUTE ON FUNCTION bri.read_user_directory(text, uuid, uuid, text, uuid, text, uuid, integer, integer)
    TO bri_app;
