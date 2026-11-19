-- Retired assignments retain their foreign keys, not structural authority.
-- Preserve the trigger, owner, ACL and governance lock established earlier.
CREATE OR REPLACE FUNCTION bri.guard_deactivation_root() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE old_tenant text; new_tenant text;
BEGIN
    IF TG_OP = 'UPDATE' AND (OLD.tenant_id,OLD.node_id,OLD.node_type,OLD.parent_node_id IS NULL)
        IS NOT DISTINCT FROM (NEW.tenant_id,NEW.node_id,NEW.node_type,NEW.parent_node_id IS NULL) THEN
        RETURN NEW;
    END IF;
    IF TG_OP <> 'INSERT' AND OLD.parent_node_id IS NULL THEN old_tenant := OLD.tenant_id; END IF;
    IF TG_OP <> 'DELETE' AND NEW.parent_node_id IS NULL THEN new_tenant := NEW.tenant_id; END IF;
    IF EXISTS (SELECT FROM bri.auth_role_assignments a JOIN bri.role_permissions r USING (tenant_id,role_id)
               WHERE a.tenant_id IN (old_tenant,new_tenant) AND a.status = 'active'
                 AND r.permission = 'user:deactivate') THEN
        RAISE EXCEPTION 'deactivation root topology is protected' USING ERRCODE = '42501';
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END $$;
