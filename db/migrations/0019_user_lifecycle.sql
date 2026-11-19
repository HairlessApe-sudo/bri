-- A11.3. Runner owns the transaction. No permissions, provider I/O or routes
-- are enabled by default. Only the trusted API supplies verified AMR evidence.
CREATE TABLE bri.user_lifecycle_state (
    principal_id uuid PRIMARY KEY REFERENCES bri.auth_principals ON UPDATE CASCADE ON DELETE CASCADE,
    version bigint NOT NULL CHECK (version > 0),
    suspension_tenant text REFERENCES bri.tenants,
    totp_after timestamptz
);
ALTER TABLE bri.user_lifecycle_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE bri.user_lifecycle_state FORCE ROW LEVEL SECURITY;
REVOKE ALL ON bri.user_lifecycle_state FROM PUBLIC, bri_app;
CREATE POLICY user_lifecycle_state_owner ON bri.user_lifecycle_state TO bri_migrator USING (true);

-- Every relevant write advances the revision and consumes provenance. Only a
-- successful A11.3 suspend can mark the *resulting* revision as reversible.
-- A10 already advances the cutoff for identity, membership, grants, provider
-- changes and credential barriers. Observe cutoff writes, not guard lock-only
-- upserts. The principal trigger also catches same-status platform holds and
-- display-name changes that do not trigger A10.
CREATE FUNCTION bri.bump_user_lifecycle_revision() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    INSERT INTO bri.user_lifecycle_state AS ls(principal_id,version) VALUES (NEW.principal_id,1)
    ON CONFLICT (principal_id) DO UPDATE SET version = ls.version + 1, suspension_tenant = NULL;
    RETURN NULL;
END $$;
CREATE TRIGGER user_lifecycle_principal_revision AFTER UPDATE ON bri.auth_principals
FOR EACH ROW EXECUTE FUNCTION bri.bump_user_lifecycle_revision();
CREATE TRIGGER user_lifecycle_cutoff_revision AFTER UPDATE OF primary_after, latest_provider_change ON bri.session_guards
FOR EACH ROW EXECUTE FUNCTION bri.bump_user_lifecycle_revision();
REVOKE ALL ON FUNCTION bri.bump_user_lifecycle_revision() FROM PUBLIC, bri_app;

-- A hold is disqualifying even if an out-of-band writer subsequently removes
-- it. Track the hold rows themselves as well as A10's ordinary cutoff writes.
CREATE FUNCTION bri.invalidate_user_lifecycle_hold() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE old_principal uuid; new_principal uuid; guard_id uuid;
BEGIN
    IF TG_OP <> 'INSERT' AND OLD.confirmed_at IS NULL THEN old_principal := OLD.principal_id; END IF;
    IF TG_OP <> 'DELETE' AND NEW.confirmed_at IS NULL THEN new_principal := NEW.principal_id; END IF;
    FOR guard_id IN SELECT DISTINCT p FROM (VALUES (old_principal),(new_principal)) v(p)
                    WHERE p IS NOT NULL ORDER BY p LOOP
        PERFORM bri.lock_session_guard(guard_id);
        INSERT INTO bri.user_lifecycle_state AS ls(principal_id,version) VALUES (guard_id,1)
        ON CONFLICT (principal_id) DO UPDATE SET version = ls.version + 1, suspension_tenant = NULL;
    END LOOP;
    RETURN NULL;
END $$;
CREATE TRIGGER user_lifecycle_hold_revision AFTER INSERT OR UPDATE OR DELETE ON bri.credential_operations
FOR EACH ROW EXECUTE FUNCTION bri.invalidate_user_lifecycle_hold();
REVOKE ALL ON FUNCTION bri.invalidate_user_lifecycle_hold() FROM PUBLIC, bri_app;

CREATE POLICY user_lifecycle_permission_insert ON bri.role_permissions AS RESTRICTIVE FOR INSERT TO bri_app
    WITH CHECK (permission NOT IN ('user:profile:edit','user:suspend','user:reactivate'));
CREATE POLICY user_lifecycle_permission_update ON bri.role_permissions AS RESTRICTIVE FOR UPDATE TO bri_app
    USING (permission NOT IN ('user:profile:edit','user:suspend','user:reactivate'))
    WITH CHECK (permission NOT IN ('user:profile:edit','user:suspend','user:reactivate'));
CREATE POLICY user_lifecycle_permission_delete ON bri.role_permissions AS RESTRICTIVE FOR DELETE TO bri_app
    USING (permission NOT IN ('user:profile:edit','user:suspend','user:reactivate'));

CREATE FUNCTION bri.guard_user_lifecycle_catalog() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE old_tenant text; new_tenant text;
BEGIN
    IF TG_TABLE_NAME = 'app_roles' THEN
        -- A parent delete cascades even when the protected role is unassigned.
        IF EXISTS (SELECT FROM bri.role_permissions r WHERE (r.tenant_id,r.role_id) = (OLD.tenant_id,OLD.role_id)
                   AND r.permission IN ('user:profile:edit','user:suspend','user:reactivate')) THEN
            RAISE EXCEPTION 'lifecycle role is protected' USING ERRCODE = '42501';
        END IF;
        RETURN OLD;
    END IF;
    IF TG_OP = 'UPDATE' AND (OLD.tenant_id,OLD.node_id,OLD.node_type,OLD.parent_node_id IS NULL)
        IS NOT DISTINCT FROM (NEW.tenant_id,NEW.node_id,NEW.node_type,NEW.parent_node_id IS NULL) THEN
        RETURN NEW;
    END IF;
    IF TG_OP <> 'INSERT' AND OLD.parent_node_id IS NULL THEN old_tenant := OLD.tenant_id; END IF;
    IF TG_OP <> 'DELETE' AND NEW.parent_node_id IS NULL THEN new_tenant := NEW.tenant_id; END IF;
    -- Also protect competing roots: deleting one could make a different grant
    -- root-authorized without modifying the assigned node or its permission.
    IF EXISTS (SELECT FROM bri.auth_role_assignments a JOIN bri.role_permissions r USING (tenant_id,role_id)
               WHERE a.tenant_id IN (old_tenant,new_tenant)
                 AND r.permission IN ('user:profile:edit','user:suspend','user:reactivate')) THEN
        RAISE EXCEPTION 'lifecycle root topology is protected' USING ERRCODE = '42501';
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER user_lifecycle_role_delete BEFORE DELETE ON bri.app_roles
FOR EACH ROW WHEN (current_user = 'bri_app') EXECUTE FUNCTION bri.guard_user_lifecycle_catalog();
CREATE TRIGGER governance_serialize BEFORE INSERT OR UPDATE OR DELETE ON bri.app_roles
FOR EACH STATEMENT EXECUTE FUNCTION bri.governance_serialize();
CREATE TRIGGER user_lifecycle_root_topology BEFORE INSERT OR UPDATE OR DELETE ON bri.org_nodes
FOR EACH ROW WHEN (current_user = 'bri_app') EXECUTE FUNCTION bri.guard_user_lifecycle_catalog();
REVOKE ALL ON FUNCTION bri.guard_user_lifecycle_catalog() FROM PUBLIC, bri_app;

DO $extend$
DECLARE old_check text;
BEGIN
    SELECT pg_get_expr(conbin,conrelid) INTO STRICT old_check FROM pg_constraint
    WHERE conrelid = 'bri.security_audit_events'::regclass AND conname = 'security_audit_events_event_type_check';
    ALTER TABLE bri.security_audit_events DROP CONSTRAINT security_audit_events_event_type_check;
    EXECUTE format('ALTER TABLE bri.security_audit_events ADD CONSTRAINT security_audit_events_event_type_check
        CHECK ((%s) OR event_type IN (%L,%L,%L))', old_check,
        'tenant.user.lifecycle.edited','tenant.user.lifecycle.suspended','tenant.user.lifecycle.reactivated');
END $extend$;
ALTER TABLE bri.security_audit_events ADD COLUMN lifecycle_reason text,
    ADD CONSTRAINT user_lifecycle_reason_check CHECK (CASE event_type
        WHEN 'tenant.user.lifecycle.suspended' THEN lifecycle_reason IS NOT NULL
            AND lifecycle_reason IN ('policy_violation','access_review','temporary_leave')
        WHEN 'tenant.user.lifecycle.reactivated' THEN lifecycle_reason IS NOT NULL
            AND lifecycle_reason IN ('review_complete','access_restored')
        ELSE lifecycle_reason IS NULL END);
CREATE POLICY user_lifecycle_audit_boundary ON bri.security_audit_events AS RESTRICTIVE FOR INSERT TO bri_app
    WITH CHECK (event_type NOT LIKE 'tenant.user.lifecycle.%' AND lifecycle_reason IS NULL);

CREATE POLICY user_lifecycle_issuer_read ON bri.provider_event_source FOR SELECT TO bri_migrator
    USING (session_user = 'bri_app');
CREATE TRIGGER governance_serialize BEFORE INSERT OR UPDATE OR DELETE ON bri.provider_event_source
FOR EACH STATEMENT EXECUTE FUNCTION bri.governance_serialize();
CREATE POLICY user_lifecycle_principal_write ON bri.auth_principals FOR UPDATE TO bri_migrator
    USING (session_user = 'bri_app' AND status IN ('active','suspended') AND deletion_requested_at IS NULL
           AND EXISTS (SELECT FROM bri.auth_tenant_memberships m WHERE m.principal_id = auth_principals.principal_id
                       AND m.tenant_id = nullif(current_setting('bri.tenant_id',true),'')
                       AND m.membership_type IN ('user','superuser') AND m.status = 'active'));

CREATE FUNCTION bri.user_lifecycle_permissions(t text, actor uuid, sid uuid, issuer text, checked_at timestamptz)
RETURNS text[] LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT ARRAY(
        SELECT DISTINCT r.permission
        FROM bri.auth_role_assignments a JOIN bri.role_permissions r USING (tenant_id,role_id)
        JOIN bri.org_nodes n ON (n.tenant_id,n.node_id) = (a.tenant_id,a.scope_node_id)
        WHERE a.tenant_id = t AND a.principal_id = actor AND a.status = 'active'
          AND r.permission IN ('user:profile:edit','user:suspend','user:reactivate')
          AND n.node_type = 'root' AND n.parent_node_id IS NULL
          AND NOT EXISTS (SELECT FROM bri.org_nodes x WHERE x.tenant_id = t AND x.parent_node_id IS NULL AND x.node_id <> n.node_id)
    ) WHERE session_user = 'bri_app' AND t = nullif(current_setting('bri.tenant_id',true),'')
      AND EXISTS (SELECT FROM bri.provider_event_source src WHERE src.issuer = $4)
      AND bri.client_is_operational(t)
      AND EXISTS (
        SELECT FROM bri.auth_sessions s JOIN bri.auth_identity_links i USING (auth_user_id,principal_id)
        JOIN bri.auth_principals p USING (principal_id) JOIN bri.auth_tenant_memberships m USING (principal_id)
        WHERE s.principal_id = actor AND s.session_id = sid AND m.tenant_id = t
          AND i.auth_user_id::text = nullif(current_setting('bri.auth_user_id',true),'')
          AND i.auth_issuer = issuer AND i.auth_subject = i.auth_user_id::text
          AND i.status = 'active' AND i.provider_type = 'native'
          AND s.revoked_at IS NULL AND s.started_at <= checked_at
          AND checked_at < least(s.expires_at,s.started_at + interval '8 hours')
          AND p.status = 'active' AND p.deletion_requested_at IS NULL
          AND m.status = 'active' AND m.membership_type = 'admin'
          AND NOT EXISTS (SELECT FROM bri.auth_tenant_memberships x WHERE x.principal_id = actor AND x.tenant_id <> t)
          AND NOT EXISTS (SELECT FROM bri.platform_superadmins x WHERE x.principal_id = actor)
          AND NOT EXISTS (SELECT FROM bri.credential_operations c WHERE c.principal_id = actor AND c.confirmed_at IS NULL)
      );
$$;

CREATE FUNCTION bri.user_lifecycle_target(t text, target uuid, permissions text[])
RETURNS TABLE(id uuid,display_name text,status text,role text,version bigint,
              can_edit boolean,can_suspend boolean,can_reactivate boolean)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT p.principal_id,p.display_name,p.status,m.membership_type,coalesce(ls.version,0),
           p.status = 'active' AND 'user:profile:edit' = ANY(permissions),
           p.status = 'active' AND 'user:suspend' = ANY(permissions),
           p.status = 'suspended' AND 'user:reactivate' = ANY(permissions)
    FROM bri.auth_principals p JOIN bri.auth_tenant_memberships m USING (principal_id)
    LEFT JOIN bri.user_lifecycle_state ls USING (principal_id)
    WHERE p.principal_id = target AND m.tenant_id = t AND m.status = 'active'
      AND m.membership_type IN ('user','superuser') AND NOT m.emergency_admin
      AND (p.status = 'active' OR (p.status = 'suspended' AND ls.suspension_tenant = t))
      AND p.deletion_requested_at IS NULL
      AND NOT EXISTS (SELECT FROM bri.auth_tenant_memberships x WHERE x.principal_id = target AND x.tenant_id <> t)
      AND NOT EXISTS (SELECT FROM bri.platform_superadmins x WHERE x.principal_id = target)
      AND NOT EXISTS (SELECT FROM bri.credential_operations c WHERE c.principal_id = target AND c.confirmed_at IS NULL)
      AND NOT EXISTS (SELECT FROM bri.auth_identity_links i WHERE i.principal_id = target AND i.status <> 'active');
$$;
REVOKE ALL ON FUNCTION bri.user_lifecycle_permissions(text,uuid,uuid,text,timestamptz),
    bri.user_lifecycle_target(text,uuid,text[]) FROM PUBLIC, bri_app;

CREATE FUNCTION bri.read_user_lifecycle(t text, actor uuid, sid uuid, issuer text, target uuid)
RETURNS TABLE(id uuid,display_name text,status text,role text,version bigint,
              can_edit boolean,can_suspend boolean,can_reactivate boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE permissions text[] := bri.user_lifecycle_permissions(t,actor,sid,issuer,clock_timestamp());
BEGIN
    IF coalesce(cardinality(permissions),0) = 0 THEN
        RAISE EXCEPTION 'lifecycle access denied' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY SELECT * FROM bri.user_lifecycle_target(t,target,permissions);
END $$;

-- PostgreSQL reserves display_name for the TABLE output; argument 8 is the
-- new display name. Callers use positional arguments for the SQL contract.
CREATE FUNCTION bri.change_user_lifecycle(t text, actor uuid, sid uuid, issuer text, target uuid, action text,
    expected_version bigint, new_display_name text, reason text, totp_at timestamptz, correlation uuid)
RETURNS TABLE(id uuid,display_name text,status text,role text,version bigint,
              can_edit boolean,can_suspend boolean,can_reactivate boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE required_permission text; permissions text[]; checked_at timestamptz; guard_id uuid;
    candidate record; eligible boolean; name text := btrim(new_display_name); event_name text; previous_correlation text;
BEGIN
    required_permission := CASE action WHEN 'edit' THEN 'user:profile:edit'
        WHEN 'suspend' THEN 'user:suspend' WHEN 'reactivate' THEN 'user:reactivate' END;
    permissions := bri.user_lifecycle_permissions(t,actor,sid,issuer,clock_timestamp());
    IF (required_permission = ANY(permissions)) IS NOT TRUE THEN
        RAISE EXCEPTION 'lifecycle access denied' USING ERRCODE = '42501';
    END IF;

    -- 0009's write fence before session guards, in UUID order. Recheck live
    -- authority and freshness after all waits, before exposing state/version.
    PERFORM bri.lock_user_provisioning_governance();
    eligible := EXISTS (SELECT FROM bri.user_lifecycle_target(t,target,permissions));
    FOR guard_id IN SELECT DISTINCT p FROM (VALUES (actor),(CASE WHEN eligible THEN target END)) v(p)
                    WHERE p IS NOT NULL ORDER BY p LOOP
        PERFORM bri.lock_session_guard(guard_id);
    END LOOP;
    checked_at := clock_timestamp();
    permissions := bri.user_lifecycle_permissions(t,actor,sid,issuer,checked_at);
    IF (required_permission = ANY(permissions)) IS NOT TRUE
       OR totp_at IS NULL OR NOT isfinite(totp_at) OR totp_at > checked_at
       OR (action <> 'edit' AND totp_at <= checked_at - interval '15 minutes')
       OR EXISTS (SELECT FROM bri.session_guards g WHERE g.principal_id = actor
                  AND (totp_at <= g.primary_after OR totp_at <= g.latest_provider_change)) THEN
        RAISE EXCEPTION 'lifecycle access denied' USING ERRCODE = '42501';
    END IF;
    IF NOT eligible THEN RETURN; END IF;
    SELECT q.* INTO candidate FROM bri.user_lifecycle_target(t,target,permissions) q;
    IF NOT FOUND THEN RETURN; END IF;
    IF expected_version IS DISTINCT FROM candidate.version THEN
        RAISE EXCEPTION 'lifecycle version changed' USING ERRCODE = '40001';
    END IF;
    IF NOT (CASE action WHEN 'edit' THEN candidate.can_edit WHEN 'suspend' THEN candidate.can_suspend
                        ELSE candidate.can_reactivate END) THEN
        RAISE EXCEPTION 'lifecycle state conflict' USING ERRCODE = '55000';
    END IF;
    IF correlation IS NULL OR (action = 'edit' AND (reason IS NOT NULL OR name IS NULL
        OR char_length(name) NOT BETWEEN 1 AND 128 OR name ~ '[[:cntrl:]]'))
       OR (action <> 'edit' AND new_display_name IS NOT NULL)
       OR (action = 'suspend' AND (reason IS NULL OR reason NOT IN ('policy_violation','access_review','temporary_leave')))
       OR (action = 'reactivate' AND (reason IS NULL OR reason NOT IN ('review_complete','access_restored'))) THEN
        RAISE EXCEPTION 'invalid lifecycle change' USING ERRCODE = '22023';
    END IF;

    IF action = 'edit' THEN
        UPDATE bri.auth_principals p SET display_name = name WHERE p.principal_id = target;
        IF NOT FOUND THEN RAISE EXCEPTION 'lifecycle state conflict' USING ERRCODE = '55000'; END IF;
        event_name := 'tenant.user.lifecycle.edited';
    ELSE
        -- A10's principal trigger owns revocation + the no-replay primary
        -- cutoff. Its events and the attributed event share this correlation.
        previous_correlation := current_setting('bri.correlation_id',true);
        PERFORM set_config('bri.correlation_id',correlation::text,true);
        UPDATE bri.auth_principals p SET status = CASE action WHEN 'suspend' THEN 'suspended' ELSE 'active' END,
            status_changed_at = clock_timestamp() WHERE p.principal_id = target;
        IF NOT FOUND THEN RAISE EXCEPTION 'lifecycle state conflict' USING ERRCODE = '55000'; END IF;
        PERFORM set_config('bri.correlation_id',coalesce(previous_correlation,''),true);
        IF action = 'suspend' THEN
            UPDATE bri.user_lifecycle_state ls SET suspension_tenant = t WHERE ls.principal_id = target;
            event_name := 'tenant.user.lifecycle.suspended';
        ELSE
            UPDATE bri.user_lifecycle_state ls SET totp_after = greatest(ls.totp_after,clock_timestamp())
            WHERE ls.principal_id = target;
            event_name := 'tenant.user.lifecycle.reactivated';
        END IF;
        IF NOT FOUND THEN RAISE EXCEPTION 'lifecycle state conflict' USING ERRCODE = '55000'; END IF;
    END IF;
    INSERT INTO bri.security_audit_events(tenant_id,actor_principal_id,subject_principal_id,event_type,
        outcome,request_id,occurred_at,lifecycle_reason)
    VALUES(t,actor,target,event_name,'success',correlation,clock_timestamp(),reason);
    RETURN QUERY SELECT * FROM bri.user_lifecycle_target(t,target,permissions);
END $$;
REVOKE ALL ON FUNCTION bri.read_user_lifecycle(text,uuid,uuid,text,uuid),
    bri.change_user_lifecycle(text,uuid,uuid,text,uuid,text,bigint,text,text,timestamptz,uuid) FROM PUBLIC, bri_app;
GRANT EXECUTE ON FUNCTION bri.read_user_lifecycle(text,uuid,uuid,text,uuid),
    bri.change_user_lifecycle(text,uuid,uuid,text,uuid,text,bigint,text,text,timestamptz,uuid) TO bri_app;

-- Keep the reviewed A10/A16 session logic intact behind a private entry. The
-- legacy API may still start unaffected sessions, but cannot start/replay a
-- reactivated account's session without explicitly verified structured TOTP.
ALTER FUNCTION bri.start_security_session(text,uuid,timestamptz,uuid) RENAME TO start_security_session_core;
REVOKE ALL ON FUNCTION bri.start_security_session_core(text,uuid,timestamptz,uuid) FROM PUBLIC, bri_app;
CREATE FUNCTION bri.start_security_session(issuer text, sid uuid, primary_at timestamptz,
    totp_at timestamptz, correlation uuid) RETURNS timestamptz
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE uid uuid := nullif(current_setting('bri.auth_user_id',true),'')::uuid; p uuid; cutoff timestamptz;
BEGIN
    IF sid IS NULL OR correlation IS NULL THEN RETURN NULL; END IF;
    SELECT i.principal_id INTO p FROM bri.auth_identity_links i
    WHERE i.auth_user_id = uid AND i.auth_issuer = issuer AND i.auth_subject = uid::text;
    IF NOT FOUND THEN RETURN NULL; END IF;
    PERFORM bri.lock_session_guard(p);
    -- Do not hand off to the core if the identity was rebound while waiting.
    IF NOT EXISTS (SELECT FROM bri.auth_identity_links i WHERE i.auth_user_id = uid
                   AND i.principal_id = p AND i.auth_issuer = issuer AND i.auth_subject = uid::text) THEN RETURN NULL; END IF;
    SELECT ls.totp_after INTO cutoff FROM bri.user_lifecycle_state ls WHERE ls.principal_id = p;
    IF cutoff IS NOT NULL AND (primary_at IS NULL OR NOT isfinite(primary_at) OR primary_at <= cutoff
       OR totp_at IS NULL OR NOT isfinite(totp_at) OR totp_at <= cutoff
       OR totp_at < primary_at OR totp_at > clock_timestamp()) THEN RETURN NULL; END IF;
    RETURN bri.start_security_session_core(issuer,sid,primary_at,correlation);
END $$;
CREATE FUNCTION bri.start_security_session(issuer text, sid uuid, primary_at timestamptz, correlation uuid)
RETURNS timestamptz LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
    SELECT bri.start_security_session($1,$2,$3,NULL::timestamptz,$4);
$$;
REVOKE ALL ON FUNCTION bri.start_security_session(text,uuid,timestamptz,timestamptz,uuid),
    bri.start_security_session(text,uuid,timestamptz,uuid) FROM PUBLIC, bri_app;
GRANT EXECUTE ON FUNCTION bri.start_security_session(text,uuid,timestamptz,timestamptz,uuid),
    bri.start_security_session(text,uuid,timestamptz,uuid) TO bri_app;
