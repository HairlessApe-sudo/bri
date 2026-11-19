-- A11.4. The runner owns the transaction. No authority or bundle is seeded.
-- The app retains catalog reads. The only mutating incoming catalog FK is
-- role_permissions -> app_roles ON DELETE CASCADE; app_roles -> tenants is
-- NO ACTION, as are the role/scope/membership FKs on native assignments.
-- Existing runtime-callable definers do not write either role catalog or
-- native assignments. Synthetic assignments have no native authority.
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON bri.app_roles, bri.role_permissions,
    bri.auth_role_assignments FROM PUBLIC, bri_app;

CREATE TABLE bri.user_delegation_bundles (
    tenant_id text NOT NULL,
    permission text NOT NULL CHECK (permission IN ('organisation:read','knowledge:read')),
    role_id text NOT NULL,
    PRIMARY KEY (tenant_id, permission),
    UNIQUE (tenant_id, role_id),
    FOREIGN KEY (tenant_id, role_id, permission) REFERENCES bri.role_permissions
);
CREATE TABLE bri.user_delegation_authority (
    tenant_id text NOT NULL,
    principal_id uuid NOT NULL,
    scope_node_id text NOT NULL,
    permission text NOT NULL,
    PRIMARY KEY (tenant_id, principal_id, scope_node_id, permission),
    FOREIGN KEY (tenant_id, permission) REFERENCES bri.user_delegation_bundles,
    FOREIGN KEY (tenant_id, scope_node_id) REFERENCES bri.org_nodes,
    FOREIGN KEY (tenant_id, principal_id) REFERENCES bri.auth_tenant_memberships ON DELETE CASCADE
);
-- Revocation preserves the revision, not a native assignment. This state is
-- the ownership marker; never adopt an existing/manual assignment.
CREATE TABLE bri.user_delegation_state (
    tenant_id text NOT NULL,
    principal_id uuid NOT NULL REFERENCES bri.auth_principals ON DELETE CASCADE,
    scope_node_id text NOT NULL,
    permission text NOT NULL,
    version bigint NOT NULL CHECK (version > 0),
    granted boolean NOT NULL,
    PRIMARY KEY (tenant_id, principal_id, scope_node_id, permission),
    FOREIGN KEY (tenant_id, permission) REFERENCES bri.user_delegation_bundles
);
DO $private$
DECLARE rel text;
BEGIN
    FOREACH rel IN ARRAY ARRAY['user_delegation_bundles','user_delegation_authority','user_delegation_state'] LOOP
        EXECUTE format('ALTER TABLE bri.%I ENABLE ROW LEVEL SECURITY',rel);
        EXECUTE format('ALTER TABLE bri.%I FORCE ROW LEVEL SECURITY',rel);
        EXECUTE format('REVOKE ALL ON bri.%I FROM PUBLIC,bri_app',rel);
        EXECUTE format('CREATE POLICY delegation_owner ON bri.%I TO bri_migrator USING (true)',rel);
        EXECUTE format('CREATE TRIGGER governance_serialize BEFORE INSERT OR UPDATE OR DELETE ON bri.%I
                        FOR EACH STATEMENT EXECUTE FUNCTION bri.governance_serialize()',rel);
    END LOOP;
END $private$;

-- A registered mapping is permanent. Disable delegation by removing the
-- exact authority rows, not by recycling a role identifier. The FK pins
-- the required permission; this guard additionally rules out extra rows,
-- pre-existing assignments and post-registration catalog changes.
CREATE FUNCTION bri.guard_delegation_bundle() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_TABLE_NAME = 'user_delegation_bundles' THEN
        IF TG_OP <> 'INSERT' THEN
            RAISE EXCEPTION 'delegation bundle registration is immutable' USING ERRCODE = '55000';
        END IF;
        IF (SELECT array_agg(r.permission) FROM bri.role_permissions r
            WHERE (r.tenant_id,r.role_id) = (NEW.tenant_id,NEW.role_id)) IS DISTINCT FROM ARRAY[NEW.permission]
           OR EXISTS (SELECT FROM bri.auth_role_assignments a
                      WHERE (a.tenant_id,a.role_id) = (NEW.tenant_id,NEW.role_id))
           OR EXISTS (SELECT FROM bri.role_assignments a
                      WHERE (a.tenant_id,a.role_id) = (NEW.tenant_id,NEW.role_id)) THEN
            RAISE EXCEPTION 'delegation bundle must be an unused singleton' USING ERRCODE = '55000';
        END IF;
    ELSE
        IF TG_OP <> 'INSERT' AND EXISTS (SELECT FROM bri.user_delegation_bundles b
                 WHERE (b.tenant_id,b.role_id) = (OLD.tenant_id,OLD.role_id)) THEN
            RAISE EXCEPTION 'delegation bundle is protected' USING ERRCODE = '55000';
        END IF;
        IF TG_OP <> 'DELETE' AND EXISTS (SELECT FROM bri.user_delegation_bundles b
                 WHERE (b.tenant_id,b.role_id) = (NEW.tenant_id,NEW.role_id)) THEN
            RAISE EXCEPTION 'delegation bundle is protected' USING ERRCODE = '55000';
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END $$;
CREATE POLICY delegation_synthetic_lookup ON bri.role_assignments FOR SELECT TO bri_migrator USING (true);
CREATE TRIGGER delegation_validate_bundle BEFORE INSERT ON bri.user_delegation_bundles
FOR EACH ROW EXECUTE FUNCTION bri.guard_delegation_bundle();
CREATE TRIGGER delegation_freeze_bundle BEFORE UPDATE OR DELETE OR TRUNCATE ON bri.user_delegation_bundles
FOR EACH STATEMENT EXECUTE FUNCTION bri.guard_delegation_bundle();
CREATE TRIGGER delegation_freeze_permissions BEFORE INSERT OR UPDATE OR DELETE ON bri.role_permissions
FOR EACH ROW EXECUTE FUNCTION bri.guard_delegation_bundle();
CREATE TRIGGER delegation_protect_synthetic BEFORE INSERT OR UPDATE ON bri.role_assignments
FOR EACH ROW EXECUTE FUNCTION bri.guard_delegation_bundle();
CREATE TRIGGER governance_serialize BEFORE INSERT OR UPDATE ON bri.role_assignments
FOR EACH STATEMENT EXECUTE FUNCTION bri.governance_serialize();

-- An assignment to a dedicated bundle can only be inserted after the
-- workflow marks that exact tuple granted, or deleted after marking it
-- revoked. No updates can repurpose it (including moving its scope).
CREATE FUNCTION bri.guard_delegation_assignment() RETURNS trigger
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
CREATE TRIGGER delegation_manage_assignment BEFORE INSERT OR UPDATE OR DELETE ON bri.auth_role_assignments
FOR EACH ROW EXECUTE FUNCTION bri.guard_delegation_assignment();
CREATE POLICY delegation_native_insert ON bri.auth_role_assignments FOR INSERT TO bri_migrator
WITH CHECK (session_user = 'bri_app' AND status = 'active' AND EXISTS (
    SELECT FROM bri.user_delegation_bundles b JOIN bri.user_delegation_state s USING (tenant_id,permission)
    WHERE (s.tenant_id,s.principal_id,b.role_id,s.scope_node_id) =
          (auth_role_assignments.tenant_id,auth_role_assignments.principal_id,
           auth_role_assignments.role_id,auth_role_assignments.scope_node_id) AND s.granted
          AND s.tenant_id = nullif(current_setting('bri.tenant_id',true),'')));
CREATE POLICY delegation_native_delete ON bri.auth_role_assignments FOR DELETE TO bri_migrator
USING (session_user = 'bri_app' AND EXISTS (
    SELECT FROM bri.user_delegation_bundles b JOIN bri.user_delegation_state s USING (tenant_id,permission)
    WHERE (s.tenant_id,s.principal_id,b.role_id,s.scope_node_id) =
          (auth_role_assignments.tenant_id,auth_role_assignments.principal_id,
           auth_role_assignments.role_id,auth_role_assignments.scope_node_id) AND NOT s.granted
          AND s.tenant_id = nullif(current_setting('bri.tenant_id',true),'')));

DO $audit$
DECLARE old_check text;
BEGIN
    SELECT pg_get_expr(conbin,conrelid) INTO STRICT old_check FROM pg_constraint
    WHERE conrelid = 'bri.security_audit_events'::regclass AND conname = 'security_audit_events_event_type_check';
    ALTER TABLE bri.security_audit_events DROP CONSTRAINT security_audit_events_event_type_check;
    EXECUTE format('ALTER TABLE bri.security_audit_events ADD CONSTRAINT security_audit_events_event_type_check
        CHECK ((%s) OR event_type IN (%L,%L))',old_check,
        'tenant.user.delegation.granted','tenant.user.delegation.revoked');
END $audit$;
ALTER TABLE bri.security_audit_events ADD COLUMN delegation_permission text, ADD COLUMN delegation_scope_node_id text,
    ADD CONSTRAINT delegation_audit_fields CHECK (CASE WHEN event_type IN
        ('tenant.user.delegation.granted','tenant.user.delegation.revoked') THEN
        delegation_permission IS NOT NULL AND delegation_permission IN ('organisation:read','knowledge:read')
        AND delegation_scope_node_id IS NOT NULL
        ELSE delegation_permission IS NULL AND delegation_scope_node_id IS NULL END);
CREATE POLICY delegation_audit_boundary ON bri.security_audit_events AS RESTRICTIVE FOR INSERT TO bri_app
    WITH CHECK (event_type NOT LIKE 'tenant.user.delegation.%');

CREATE FUNCTION bri.user_delegation_actor(t text, actor uuid, sid uuid, issuer text, node text,
    permission text, checked_at timestamptz) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT coalesce(session_user = 'bri_app' AND t = nullif(current_setting('bri.tenant_id',true),'')
      AND EXISTS (SELECT FROM bri.provider_event_source src WHERE src.issuer = $4)
      AND bri.client_is_operational(t)
      AND EXISTS (SELECT FROM bri.user_delegation_authority a
                  WHERE (a.tenant_id,a.principal_id,a.scope_node_id,a.permission) = ($1,$2,$5,$6))
      AND EXISTS (
        SELECT FROM bri.auth_sessions s JOIN bri.auth_identity_links i USING (auth_user_id,principal_id)
        JOIN bri.auth_principals p USING (principal_id) JOIN bri.auth_tenant_memberships m USING (principal_id)
        LEFT JOIN bri.session_guards g USING (principal_id)
        WHERE s.principal_id = actor AND s.session_id = sid AND m.tenant_id = t
          AND i.auth_user_id::text = nullif(current_setting('bri.auth_user_id',true),'')
          AND i.auth_issuer = issuer AND i.auth_subject = i.auth_user_id::text
          AND i.status = 'active' AND i.provider_type = 'native'
          AND s.revoked_at IS NULL AND s.started_at <= checked_at
          AND checked_at < least(s.expires_at,s.started_at + interval '8 hours')
          AND s.started_at > coalesce(g.primary_after,'-infinity'::timestamptz)
          AND p.status = 'active' AND p.deletion_requested_at IS NULL
          AND m.status = 'active' AND m.membership_type = 'admin'
          AND NOT EXISTS (SELECT FROM bri.auth_tenant_memberships x WHERE x.principal_id = actor AND x.tenant_id <> t)
          AND NOT EXISTS (SELECT FROM bri.platform_superadmins x WHERE x.principal_id = actor)
          AND NOT EXISTS (SELECT FROM bri.credential_operations c WHERE c.principal_id = actor AND c.confirmed_at IS NULL)
      ),false);
$$;

CREATE FUNCTION bri.user_delegation_target(t text, actor uuid, target uuid) RETURNS text
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT m.membership_type FROM bri.auth_principals p JOIN bri.auth_tenant_memberships m USING (principal_id)
    WHERE target <> actor AND p.principal_id = target AND m.tenant_id = t AND m.status = 'active'
      AND m.membership_type IN ('user','superuser') AND NOT m.emergency_admin
      AND p.status = 'active' AND p.deletion_requested_at IS NULL
      AND NOT EXISTS (SELECT FROM bri.auth_tenant_memberships x WHERE x.principal_id = target AND x.tenant_id <> t)
      AND NOT EXISTS (SELECT FROM bri.platform_superadmins x WHERE x.principal_id = target)
      AND NOT EXISTS (SELECT FROM bri.credential_operations c WHERE c.principal_id = target AND c.confirmed_at IS NULL)
      AND EXISTS (SELECT FROM bri.auth_identity_links i WHERE i.principal_id = target AND i.status = 'active')
      AND NOT EXISTS (SELECT FROM bri.auth_identity_links i WHERE i.principal_id = target AND i.status <> 'active');
$$;

CREATE FUNCTION bri.user_delegation_fresh_totp(actor uuid, totp_at timestamptz, checked_at timestamptz)
RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT coalesce(isfinite(totp_at) AND totp_at <= checked_at AND totp_at > checked_at - interval '15 minutes'
       AND NOT EXISTS (SELECT FROM bri.session_guards g WHERE g.principal_id = actor
                       AND (totp_at <= g.primary_after OR totp_at <= g.latest_provider_change))
       AND NOT EXISTS (SELECT FROM bri.user_lifecycle_state ls WHERE ls.principal_id = actor AND totp_at <= ls.totp_after),false);
$$;

-- This is the intersection with src/bri/access/roles.py, not a second role
-- catalog. role_allows_permission preserves both explicit actions for User
-- and SuperUser. Validate the ENTIRE registered role's exact-node delta,
-- not just the presence of a requested permission in a larger bundle.
CREATE FUNCTION bri.user_delegation_delta_allowed(t text, bundle text, permission text, target_role text)
RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT coalesce(target_role IN ('user','superuser') AND $3 IN ('organisation:read','knowledge:read')
       AND (SELECT array_agg(r.permission) FROM bri.role_permissions r
            WHERE (r.tenant_id,r.role_id) = (t,bundle)) = ARRAY[$3],false);
$$;

CREATE FUNCTION bri.read_user_delegation(t text, actor uuid, sid uuid, issuer text, target uuid, node text, permission text)
RETURNS TABLE(version bigint, granted boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT bri.user_delegation_actor(t,actor,sid,issuer,node,permission,clock_timestamp()) THEN
        RAISE EXCEPTION 'delegation access denied' USING ERRCODE = '42501';
    END IF;
    IF bri.user_delegation_target(t,actor,target) IS NULL THEN RETURN; END IF;
    RETURN QUERY SELECT coalesce(s.version,0),coalesce(s.granted,false)
    FROM (VALUES (t,target,node,permission)) k(tenant_id,principal_id,scope_node_id,permission)
    LEFT JOIN bri.user_delegation_state s USING (tenant_id,principal_id,scope_node_id,permission);
END $$;

CREATE FUNCTION bri.change_user_delegation(t text, actor uuid, sid uuid, issuer text, target uuid, node text, permission text,
    action text, expected_version bigint, totp_at timestamptz, correlation uuid)
RETURNS TABLE(version bigint, granted boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE checked_at timestamptz; guard_id uuid; eligible boolean; target_role text; bundle text;
    previous_version bigint; was_granted boolean; next_version bigint; now_granted boolean;
    previous_correlation text;
BEGIN
    IF NOT bri.user_delegation_actor(t,actor,sid,issuer,node,permission,clock_timestamp())
       OR action IS NULL OR action NOT IN ('grant','revoke') OR correlation IS NULL THEN
        RAISE EXCEPTION 'delegation access denied' USING ERRCODE = '42501';
    END IF;
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'delegation requires read committed' USING ERRCODE = '55000';
    END IF;

    -- Same order as A10's role changes: governance fence -> A10 role key ->
    -- session guards in UUID order. A10's assignment trigger reacquires the
    -- same locks, advances the cutoff, and records correlated invalidation.
    PERFORM bri.lock_user_provisioning_governance();
    SELECT b.role_id INTO bundle FROM bri.user_delegation_bundles b WHERE (b.tenant_id,b.permission) = ($1,$7);
    PERFORM pg_advisory_xact_lock(hashtextextended(json_build_array(t,bundle)::text,17811));
    eligible := bri.user_delegation_target(t,actor,target) IS NOT NULL;
    FOR guard_id IN SELECT DISTINCT p FROM (VALUES (actor),(CASE WHEN eligible THEN target END)) v(p)
                    WHERE p IS NOT NULL ORDER BY p LOOP
        PERFORM bri.lock_session_guard(guard_id);
    END LOOP;
    checked_at := clock_timestamp();
    IF NOT bri.user_delegation_actor(t,actor,sid,issuer,node,permission,checked_at)
       OR NOT bri.user_delegation_fresh_totp(actor,totp_at,checked_at) THEN
        RAISE EXCEPTION 'delegation access denied' USING ERRCODE = '42501';
    END IF;
    IF NOT eligible THEN RETURN; END IF;
    target_role := bri.user_delegation_target(t,actor,target);
    IF target_role IS NULL THEN RETURN; END IF;
    IF NOT bri.user_delegation_delta_allowed(t,bundle,permission,target_role) THEN
        RAISE EXCEPTION 'delegation bundle no longer valid' USING ERRCODE = '55000';
    END IF;

    SELECT s.version,s.granted INTO previous_version,was_granted FROM bri.user_delegation_state s
    WHERE (s.tenant_id,s.principal_id,s.scope_node_id,s.permission) = ($1,$5,$6,$7);
    IF expected_version IS DISTINCT FROM coalesce(previous_version,0) THEN
        RAISE EXCEPTION 'delegation version changed' USING ERRCODE = '40001';
    END IF;
    now_granted := action = 'grant';
    IF now_granted = coalesce(was_granted,false) OR (now_granted AND EXISTS (
        SELECT FROM bri.auth_role_assignments a JOIN bri.role_permissions r USING (tenant_id,role_id)
        WHERE (a.tenant_id,a.principal_id,a.scope_node_id,r.permission) = ($1,$5,$6,$7) AND a.status = 'active')) THEN
        RAISE EXCEPTION 'delegation state conflict' USING ERRCODE = '55000';
    END IF;
    next_version := coalesce(previous_version,0) + 1;
    INSERT INTO bri.user_delegation_state(tenant_id,principal_id,scope_node_id,permission,version,granted)
    VALUES(t,target,node,permission,next_version,now_granted)
    ON CONFLICT ON CONSTRAINT user_delegation_state_pkey DO UPDATE
        SET version = excluded.version, granted = excluded.granted;

    previous_correlation := current_setting('bri.correlation_id',true);
    PERFORM set_config('bri.correlation_id',correlation::text,true);
    IF now_granted THEN
        INSERT INTO bri.auth_role_assignments(tenant_id,principal_id,role_id,scope_node_id,status,assigned_by_principal_id)
        VALUES(t,target,bundle,node,'active',actor) ON CONFLICT DO NOTHING;
    ELSE
        DELETE FROM bri.auth_role_assignments a WHERE
            (a.tenant_id,a.principal_id,a.role_id,a.scope_node_id) = (t,target,bundle,node) AND a.status = 'active';
    END IF;
    IF NOT FOUND THEN RAISE EXCEPTION 'delegation state conflict' USING ERRCODE = '55000'; END IF;
    PERFORM set_config('bri.correlation_id',coalesce(previous_correlation,''),true);
    INSERT INTO bri.security_audit_events(tenant_id,actor_principal_id,subject_principal_id,event_type,
        outcome,request_id,occurred_at,delegation_permission,delegation_scope_node_id)
    VALUES(t,actor,target,CASE WHEN now_granted THEN 'tenant.user.delegation.granted' ELSE 'tenant.user.delegation.revoked' END,
        'success',correlation,clock_timestamp(),permission,node);
    -- Native and audit inserts can also wait (e.g. on a maintenance lock).
    -- Recheck wall-clock validity before returning success; any failure rolls
    -- back the assignment, audit, version and session invalidation together.
    checked_at := clock_timestamp();
    IF NOT bri.user_delegation_actor(t,actor,sid,issuer,node,permission,checked_at)
       OR NOT bri.user_delegation_fresh_totp(actor,totp_at,checked_at) THEN
        RAISE EXCEPTION 'delegation access denied' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY SELECT next_version,now_granted;
END $$;
REVOKE ALL ON FUNCTION bri.guard_delegation_bundle(), bri.guard_delegation_assignment(),
    bri.user_delegation_actor(text,uuid,uuid,text,text,text,timestamptz), bri.user_delegation_target(text,uuid,uuid),
    bri.user_delegation_fresh_totp(uuid,timestamptz,timestamptz),
    bri.user_delegation_delta_allowed(text,text,text,text), bri.read_user_delegation(text,uuid,uuid,text,uuid,text,text),
    bri.change_user_delegation(text,uuid,uuid,text,uuid,text,text,text,bigint,timestamptz,uuid) FROM PUBLIC,bri_app;
-- No runtime EXECUTE grant. Only private disposable fixtures explicitly
-- activate these routines, after proving the ordinary runtime ACL denies both.
