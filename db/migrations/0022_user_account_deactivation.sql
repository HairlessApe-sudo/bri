-- A11.5. Runner owns the transaction. No permission assignment or release
-- EXECUTE grant: SQL cannot attest to caller-supplied provider freshness.

DO $audit$
DECLARE old_check text;
BEGIN
    SELECT pg_get_expr(conbin,conrelid) INTO STRICT old_check FROM pg_constraint
    WHERE conrelid = 'bri.security_audit_events'::regclass AND conname = 'security_audit_events_event_type_check';
    ALTER TABLE bri.security_audit_events DROP CONSTRAINT security_audit_events_event_type_check;
    EXECUTE format('ALTER TABLE bri.security_audit_events ADD CONSTRAINT security_audit_events_event_type_check
        CHECK ((%s) OR event_type = %L)', old_check, 'tenant.user.lifecycle.deactivated');
END $audit$;
ALTER TABLE bri.security_audit_events DROP CONSTRAINT user_lifecycle_reason_check,
    ADD CONSTRAINT user_lifecycle_reason_check CHECK (CASE event_type
        WHEN 'tenant.user.lifecycle.suspended' THEN lifecycle_reason IS NOT NULL
            AND lifecycle_reason IN ('policy_violation','access_review','temporary_leave')
        WHEN 'tenant.user.lifecycle.reactivated' THEN lifecycle_reason IS NOT NULL
            AND lifecycle_reason IN ('review_complete','access_restored')
        WHEN 'tenant.user.lifecycle.deactivated' THEN lifecycle_reason IS NOT NULL
            AND lifecycle_reason IN ('account_closed','access_review','policy_violation')
        ELSE lifecycle_reason IS NULL END);
-- The existing lifecycle audit policy already prevents bri_app from forging
-- this event or setting lifecycle_reason through direct table access.

CREATE FUNCTION bri.guard_deactivation_root() RETURNS trigger
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
               WHERE a.tenant_id IN (old_tenant,new_tenant) AND r.permission = 'user:deactivate') THEN
        RAISE EXCEPTION 'deactivation root topology is protected' USING ERRCODE = '42501';
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END $$;
-- A11.4 already denies native assignment and role catalog DML to bri_app;
-- its bundle allowlist excludes this permission. Root topology is separate.
CREATE TRIGGER user_deactivation_root_topology BEFORE INSERT OR UPDATE OR DELETE ON bri.org_nodes
FOR EACH ROW WHEN (current_user = 'bri_app') EXECUTE FUNCTION bri.guard_deactivation_root();

-- These tables already share the governance write fence. Do not change any
-- nonterminal A10 transition (pending/active/suspended). Retain the terminal
-- bindings and reject activation against either a terminal parent or member.
CREATE FUNCTION bri.guard_deactivated_account() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE terminal_old boolean := false; terminal_new boolean := false;
BEGIN
    IF TG_TABLE_NAME = 'auth_principals' THEN
        IF OLD.status = 'deactivated' AND (TG_OP = 'DELETE' OR
            (NEW.principal_id,NEW.status) IS DISTINCT FROM (OLD.principal_id,OLD.status)) THEN
            RAISE EXCEPTION 'deactivated principal is terminal' USING ERRCODE = '55000';
        END IF;
    ELSIF TG_TABLE_NAME = 'auth_tenant_memberships' THEN
        IF TG_OP <> 'INSERT' AND OLD.status = 'deactivated' AND (TG_OP = 'DELETE' OR
            (NEW.tenant_id,NEW.principal_id,NEW.membership_type,NEW.emergency_admin,NEW.status)
            IS DISTINCT FROM (OLD.tenant_id,OLD.principal_id,OLD.membership_type,OLD.emergency_admin,OLD.status)) THEN
            RAISE EXCEPTION 'deactivated membership is terminal' USING ERRCODE = '55000';
        END IF;
        IF TG_OP <> 'DELETE' AND NEW.status = 'active' AND EXISTS (
            SELECT FROM bri.auth_principals p WHERE p.principal_id = NEW.principal_id AND p.status = 'deactivated') THEN
            RAISE EXCEPTION 'deactivated principal cannot acquire active membership' USING ERRCODE = '55000';
        END IF;
    ELSIF TG_TABLE_NAME = 'platform_superadmins' THEN
        IF EXISTS (SELECT FROM bri.auth_principals p WHERE p.principal_id = NEW.principal_id AND p.status = 'deactivated') THEN
            RAISE EXCEPTION 'deactivated principal cannot acquire active platform grant' USING ERRCODE = '55000';
        END IF;
    ELSE
        IF TG_OP <> 'INSERT' THEN
            terminal_old := EXISTS (SELECT FROM bri.auth_principals p
                JOIN bri.auth_tenant_memberships m USING (principal_id)
                WHERE (m.tenant_id,p.principal_id) = (OLD.tenant_id,OLD.principal_id)
                  AND (p.status = 'deactivated' OR m.status = 'deactivated'));
        END IF;
        IF TG_OP <> 'DELETE' THEN
            terminal_new := EXISTS (SELECT FROM bri.auth_principals p
                JOIN bri.auth_tenant_memberships m USING (principal_id)
                WHERE (m.tenant_id,p.principal_id) = (NEW.tenant_id,NEW.principal_id)
                  AND (p.status = 'deactivated' OR m.status = 'deactivated'));
        END IF;
        -- At a terminal account, permit only status-only retirement; never
        -- delete or move the old row, rewrite provenance, or mint a new grant.
        IF (terminal_old OR terminal_new) AND NOT (TG_OP = 'UPDATE'
            AND OLD.status = 'active' AND NEW.status = 'revoked'
            AND (NEW.tenant_id,NEW.principal_id,NEW.role_id,NEW.scope_node_id,NEW.assigned_by_principal_id,NEW.assigned_at)
                IS NOT DISTINCT FROM
                (OLD.tenant_id,OLD.principal_id,OLD.role_id,OLD.scope_node_id,OLD.assigned_by_principal_id,OLD.assigned_at)) THEN
            RAISE EXCEPTION 'deactivated account assignment is protected' USING ERRCODE = '55000';
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER deactivation_terminal_principal BEFORE UPDATE OR DELETE ON bri.auth_principals
FOR EACH ROW EXECUTE FUNCTION bri.guard_deactivated_account();
CREATE TRIGGER deactivation_terminal_membership BEFORE INSERT OR UPDATE OR DELETE ON bri.auth_tenant_memberships
FOR EACH ROW EXECUTE FUNCTION bri.guard_deactivated_account();
CREATE TRIGGER deactivation_terminal_assignment BEFORE INSERT OR UPDATE OR DELETE ON bri.auth_role_assignments
FOR EACH ROW EXECUTE FUNCTION bri.guard_deactivated_account();
CREATE TRIGGER deactivation_terminal_platform_grant BEFORE INSERT OR UPDATE ON bri.platform_superadmins
FOR EACH ROW WHEN (NEW.status = 'active') EXECUTE FUNCTION bri.guard_deactivated_account();

-- Add exactly one exception to A11.4's update freeze. Require both terminal
-- bindings, an unchanged native row except for status, and the *exact* bundle
-- tuple already reconciled to ungranted. No caller-settable flag is authority.
CREATE OR REPLACE FUNCTION bri.guard_delegation_assignment() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE old_permission text; new_permission text;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        SELECT b.permission INTO old_permission FROM bri.user_delegation_bundles b
        WHERE (b.tenant_id,b.role_id) = (OLD.tenant_id,OLD.role_id);
    END IF;
    IF TG_OP <> 'DELETE' THEN
        SELECT b.permission INTO new_permission FROM bri.user_delegation_bundles b
        WHERE (b.tenant_id,b.role_id) = (NEW.tenant_id,NEW.role_id);
    END IF;
    IF TG_OP = 'UPDATE' AND old_permission IS NOT NULL
       AND OLD.status = 'active' AND NEW.status = 'revoked'
       AND (NEW.tenant_id,NEW.principal_id,NEW.role_id,NEW.scope_node_id,NEW.assigned_by_principal_id,NEW.assigned_at)
           IS NOT DISTINCT FROM
           (OLD.tenant_id,OLD.principal_id,OLD.role_id,OLD.scope_node_id,OLD.assigned_by_principal_id,OLD.assigned_at)
       AND EXISTS (SELECT FROM bri.auth_principals p JOIN bri.auth_tenant_memberships m USING (principal_id)
                   WHERE (m.tenant_id,p.principal_id) = (OLD.tenant_id,OLD.principal_id)
                     AND p.status = 'deactivated' AND m.status = 'deactivated')
       AND EXISTS (SELECT FROM bri.user_delegation_state s WHERE NOT s.granted AND
                   (s.tenant_id,s.principal_id,s.scope_node_id,s.permission) =
                   (OLD.tenant_id,OLD.principal_id,OLD.scope_node_id,old_permission)) THEN
        RETURN NEW;
    END IF;
    IF (TG_OP = 'UPDATE' AND (old_permission IS NOT NULL OR new_permission IS NOT NULL))
       OR (TG_OP = 'INSERT' AND new_permission IS NOT NULL AND NOT EXISTS (
           SELECT FROM bri.user_delegation_state s WHERE s.granted AND
           (s.tenant_id,s.principal_id,s.scope_node_id,s.permission) =
           (NEW.tenant_id,NEW.principal_id,NEW.scope_node_id,new_permission)))
       OR (TG_OP = 'DELETE' AND old_permission IS NOT NULL AND NOT EXISTS (
           SELECT FROM bri.user_delegation_state s WHERE NOT s.granted AND
           (s.tenant_id,s.principal_id,s.scope_node_id,s.permission) =
           (OLD.tenant_id,OLD.principal_id,OLD.scope_node_id,old_permission))) THEN
        RAISE EXCEPTION 'delegation assignment is protected' USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END $$;

-- A11.3 supplies the eligible OLD principal predicate, not the terminal NEW
-- row. Add a checked transition without widening the existing lifecycle policy.
CREATE POLICY deactivation_principal_write ON bri.auth_principals FOR UPDATE TO bri_migrator
USING (false)
WITH CHECK (session_user = 'bri_app' AND status = 'deactivated' AND deletion_requested_at IS NULL
            AND EXISTS (SELECT FROM bri.auth_tenant_memberships m WHERE m.principal_id = auth_principals.principal_id
                        AND m.tenant_id = nullif(current_setting('bri.tenant_id',true),'')
                        AND m.membership_type IN ('user','superuser') AND m.status = 'active' AND NOT m.emergency_admin));
CREATE POLICY deactivation_membership_write ON bri.auth_tenant_memberships FOR UPDATE TO bri_migrator
USING (session_user = 'bri_app' AND tenant_id = nullif(current_setting('bri.tenant_id',true),'')
       AND status = 'active' AND membership_type IN ('user','superuser') AND NOT emergency_admin
       AND EXISTS (SELECT FROM bri.auth_principals p WHERE p.principal_id = auth_tenant_memberships.principal_id
                   AND p.status = 'deactivated'))
WITH CHECK (session_user = 'bri_app' AND tenant_id = nullif(current_setting('bri.tenant_id',true),'')
            AND status = 'deactivated' AND membership_type IN ('user','superuser') AND NOT emergency_admin
            AND EXISTS (SELECT FROM bri.auth_principals p WHERE p.principal_id = auth_tenant_memberships.principal_id
                        AND p.status = 'deactivated'));
CREATE FUNCTION bri.deactivation_assignment_terminal(t text, p uuid) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT session_user = 'bri_app' AND t = nullif(current_setting('bri.tenant_id',true),'') AND EXISTS (
        SELECT FROM bri.auth_principals a JOIN bri.auth_tenant_memberships m USING (principal_id)
        WHERE (m.tenant_id,a.principal_id) = (t,p) AND a.status = 'deactivated' AND m.status = 'deactivated'
          AND m.membership_type IN ('user','superuser') AND NOT m.emergency_admin);
$$;
CREATE POLICY deactivation_assignment_retire ON bri.auth_role_assignments FOR UPDATE TO bri_migrator
USING (status = 'active' AND bri.deactivation_assignment_terminal(tenant_id,principal_id))
WITH CHECK (status = 'revoked' AND bri.deactivation_assignment_terminal(tenant_id,principal_id));

CREATE FUNCTION bri.user_deactivation_actor(t text, actor uuid, sid uuid, issuer text, checked_at timestamptz)
RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    -- A11.3 returns NULL for an ineligible actor, and an empty array for an
    -- eligible admin without its actions. Reuse its identity/session checks
    -- but require our own explicit root grant; no A11.3 permission suffices.
    SELECT bri.user_lifecycle_permissions(t,actor,sid,issuer,checked_at) IS NOT NULL
      AND EXISTS (SELECT FROM bri.auth_sessions s LEFT JOIN bri.session_guards g USING (principal_id)
                  WHERE s.principal_id = actor AND s.session_id = sid
                    AND s.auth_user_id::text = nullif(current_setting('bri.auth_user_id',true),'')
                    AND s.started_at > coalesce(g.primary_after,'-infinity'::timestamptz))
      AND EXISTS (SELECT FROM bri.auth_role_assignments a JOIN bri.role_permissions r USING (tenant_id,role_id)
                  JOIN bri.org_nodes n ON (n.tenant_id,n.node_id) = (a.tenant_id,a.scope_node_id)
                  WHERE a.tenant_id = t AND a.principal_id = actor AND a.status = 'active'
                    AND r.permission = 'user:deactivate' AND n.node_type = 'root' AND n.parent_node_id IS NULL
                    AND NOT EXISTS (SELECT FROM bri.org_nodes x WHERE x.tenant_id = t
                                    AND x.parent_node_id IS NULL AND x.node_id <> n.node_id));
$$;

CREATE FUNCTION bri.user_deactivation_target(t text, actor uuid, target uuid)
RETURNS TABLE(version bigint,status text) LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT coalesce(ls.version,0),p.status
    FROM bri.auth_principals p JOIN bri.auth_tenant_memberships m USING (principal_id)
    LEFT JOIN bri.user_lifecycle_state ls USING (principal_id)
    WHERE target <> actor AND p.principal_id = target AND m.tenant_id = t
      AND m.membership_type IN ('user','superuser') AND NOT m.emergency_admin
      AND ((m.status = 'active' AND (p.status = 'active' OR (p.status = 'suspended' AND ls.suspension_tenant = t)))
           OR (m.status = 'deactivated' AND p.status = 'deactivated'))
      AND p.deletion_requested_at IS NULL
      AND NOT EXISTS (SELECT FROM bri.auth_tenant_memberships x WHERE x.principal_id = target AND x.tenant_id <> t)
      AND NOT EXISTS (SELECT FROM bri.platform_superadmins x WHERE x.principal_id = target)
      AND NOT EXISTS (SELECT FROM bri.credential_operations c WHERE c.principal_id = target AND c.confirmed_at IS NULL)
      AND EXISTS (SELECT FROM bri.auth_identity_links i WHERE i.principal_id = target AND i.status = 'active'
                  AND i.provider_type = 'native' AND i.auth_subject = i.auth_user_id::text
                  AND EXISTS (SELECT FROM bri.provider_event_source src WHERE src.issuer = i.auth_issuer))
      AND NOT EXISTS (SELECT FROM bri.auth_identity_links i WHERE i.principal_id = target
                      AND (i.status <> 'active' OR i.provider_type <> 'native' OR i.auth_subject <> i.auth_user_id::text
                           OR NOT EXISTS (SELECT FROM bri.provider_event_source src WHERE src.issuer = i.auth_issuer)));
$$;

CREATE FUNCTION bri.read_user_deactivation(t text, actor uuid, sid uuid, issuer text, target uuid)
RETURNS TABLE(version bigint,status text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT bri.user_deactivation_actor(t,actor,sid,issuer,clock_timestamp()) THEN
        RAISE EXCEPTION 'deactivation access denied' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY SELECT * FROM bri.user_deactivation_target(t,actor,target) q;
END $$;

CREATE FUNCTION bri.deactivate_user_account(t text, actor uuid, sid uuid, issuer text, target uuid,
    expected_version bigint, reason text, totp_at timestamptz, correlation uuid)
RETURNS TABLE(version bigint,status text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE checked_at timestamptz; candidate record; eligible boolean; guard_id uuid; role_key bigint; previous_correlation text;
BEGIN
    IF NOT bri.user_deactivation_actor(t,actor,sid,issuer,clock_timestamp()) THEN
        RAISE EXCEPTION 'deactivation access denied' USING ERRCODE = '42501';
    END IF;
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'deactivation requires read committed' USING ERRCODE = '55000';
    END IF;
    PERFORM bri.lock_user_provisioning_governance();
    eligible := EXISTS (SELECT FROM bri.user_deactivation_target(t,actor,target));
    IF eligible THEN
        -- Acquire the complete set before any session guard, using the same
        -- sorted hash keys as A10. The fence prevents native grant phantoms.
        FOR role_key IN
            SELECT DISTINCT hashtextextended(json_build_array(a.tenant_id,a.role_id)::text,17811) k
            FROM bri.auth_role_assignments a WHERE (a.tenant_id,a.principal_id) = (t,target)
            ORDER BY k
        LOOP
            PERFORM pg_advisory_xact_lock(role_key);
        END LOOP;
    END IF;
    FOR guard_id IN SELECT DISTINCT p FROM (VALUES (actor),(CASE WHEN eligible THEN target END)) v(p)
                    WHERE p IS NOT NULL ORDER BY p LOOP
        PERFORM bri.lock_session_guard(guard_id);
    END LOOP;
    checked_at := clock_timestamp();
    IF NOT bri.user_deactivation_actor(t,actor,sid,issuer,checked_at)
       OR NOT bri.user_delegation_fresh_totp(actor,totp_at,checked_at) THEN
        RAISE EXCEPTION 'deactivation access denied' USING ERRCODE = '42501';
    END IF;
    IF NOT eligible THEN RETURN; END IF;
    SELECT q.* INTO candidate FROM bri.user_deactivation_target(t,actor,target) q;
    IF NOT FOUND THEN RETURN; END IF;
    IF expected_version IS DISTINCT FROM candidate.version THEN
        RAISE EXCEPTION 'deactivation version changed' USING ERRCODE = '40001';
    END IF;
    IF candidate.status = 'deactivated' THEN
        RAISE EXCEPTION 'deactivation state conflict' USING ERRCODE = '55000';
    END IF;
    IF correlation IS NULL OR reason IS NULL OR reason NOT IN ('account_closed','access_review','policy_violation') THEN
        RAISE EXCEPTION 'invalid deactivation change' USING ERRCODE = '22023';
    END IF;

    -- Do not adopt legacy rows into A11.4 ownership or silently bless drift.
    IF EXISTS (SELECT FROM bri.user_delegation_state s JOIN bri.user_delegation_bundles b USING (tenant_id,permission)
               WHERE (s.tenant_id,s.principal_id) = (t,target) AND s.granted AND NOT EXISTS (
                   SELECT FROM bri.auth_role_assignments a WHERE a.status = 'active' AND
                   (a.tenant_id,a.principal_id,a.scope_node_id,a.role_id) = (t,target,s.scope_node_id,b.role_id)))
       OR EXISTS (SELECT FROM bri.auth_role_assignments a JOIN bri.user_delegation_bundles b USING (tenant_id,role_id)
                  WHERE (a.tenant_id,a.principal_id) = (t,target) AND a.status = 'active' AND NOT EXISTS (
                      SELECT FROM bri.user_delegation_state s WHERE s.granted AND
                      (s.tenant_id,s.principal_id,s.scope_node_id,s.permission) = (t,target,a.scope_node_id,b.permission))) THEN
        RAISE EXCEPTION 'deactivation assignment state conflict' USING ERRCODE = '55000';
    END IF;

    -- A10's triggers revoke sessions and advance the primary cutoff, and
    -- A11.3 clears suspension provenance and advances the lifecycle version.
    previous_correlation := current_setting('bri.correlation_id',true);
    PERFORM set_config('bri.correlation_id',correlation::text,true);
    UPDATE bri.auth_principals p SET status = 'deactivated', status_changed_at = checked_at
    WHERE p.principal_id = target AND p.status = candidate.status;
    IF NOT FOUND THEN RAISE EXCEPTION 'deactivation principal state conflict' USING ERRCODE = '55000'; END IF;
    UPDATE bri.auth_tenant_memberships m SET status = 'deactivated', status_changed_at = checked_at
    WHERE (m.tenant_id,m.principal_id) = (t,target) AND m.status = 'active';
    IF NOT FOUND THEN RAISE EXCEPTION 'deactivation membership state conflict' USING ERRCODE = '55000'; END IF;
    UPDATE bri.user_delegation_state s SET granted = false, version = s.version + 1
    WHERE (s.tenant_id,s.principal_id) = (t,target) AND s.granted;
    UPDATE bri.auth_role_assignments a SET status = 'revoked'
    WHERE (a.tenant_id,a.principal_id) = (t,target) AND a.status = 'active';
    IF EXISTS (SELECT FROM bri.auth_role_assignments a
               WHERE (a.tenant_id,a.principal_id) = (t,target) AND a.status = 'active') THEN
        RAISE EXCEPTION 'deactivation assignment retirement incomplete' USING ERRCODE = '55000';
    END IF;
    PERFORM set_config('bri.correlation_id',coalesce(previous_correlation,''),true);
    INSERT INTO bri.security_audit_events(tenant_id,actor_principal_id,subject_principal_id,event_type,
        outcome,request_id,occurred_at,lifecycle_reason)
    VALUES(t,actor,target,'tenant.user.lifecycle.deactivated','success',correlation,clock_timestamp(),reason);

    -- A triggered write or the audit insert can wait after authorization.
    checked_at := clock_timestamp();
    IF NOT bri.user_deactivation_actor(t,actor,sid,issuer,checked_at)
       OR NOT bri.user_delegation_fresh_totp(actor,totp_at,checked_at) THEN
        RAISE EXCEPTION 'deactivation access denied' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY SELECT ls.version,'deactivated'::text FROM bri.user_lifecycle_state ls WHERE ls.principal_id = target;
END $$;

REVOKE ALL ON FUNCTION bri.guard_deactivation_root(), bri.guard_deactivated_account(),
    bri.deactivation_assignment_terminal(text,uuid), bri.user_deactivation_actor(text,uuid,uuid,text,timestamptz),
    bri.user_deactivation_target(text,uuid,uuid), bri.read_user_deactivation(text,uuid,uuid,text,uuid),
    bri.deactivate_user_account(text,uuid,uuid,text,uuid,bigint,text,timestamptz,uuid) FROM PUBLIC,bri_app;
-- Intentionally no EXECUTE grant, wrapper, or seeded user:deactivate assignment.
