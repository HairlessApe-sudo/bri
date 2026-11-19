-- A11.2. Runner owns the transaction. No provider I/O, configuration data,
-- role bootstrap, session creation or automatic permission assignments.
CREATE TABLE bri.user_provisioning (
    tenant_id text NOT NULL,
    request_key uuid NOT NULL,
    principal_id uuid NOT NULL UNIQUE,
    actor_id uuid NOT NULL,
    actor_user uuid NOT NULL,
    actor_session uuid NOT NULL,
    actor_totp_at timestamptz NOT NULL,
    expected_issuer text NOT NULL,
    -- Keep plaintext only while a dispatch can still need it. The private,
    -- tenant-bound digest preserves duplicate suppression after erasure; it is
    -- not anonymous data and must remain under the same access controls.
    email text,
    email_digest bytea NOT NULL,
    status text NOT NULL DEFAULT 'pending_setup' CHECK (status IN (
        'pending_setup','inviting','invitation_sent','invitation_retryable','invitation_unresolved','active')),
    dispatch_at timestamptz,
    attempt_id uuid,
    provider_user uuid UNIQUE,
    PRIMARY KEY (tenant_id, request_key),
    UNIQUE (tenant_id, email_digest),
    FOREIGN KEY (tenant_id, principal_id) REFERENCES bri.auth_tenant_memberships,
    FOREIGN KEY (tenant_id, actor_id) REFERENCES bri.auth_tenant_memberships,
    CHECK ((status IN ('invitation_sent','active')) = (provider_user IS NOT NULL)),
    CHECK ((status = 'pending_setup') = (dispatch_at IS NULL)),
    CHECK ((dispatch_at IS NULL) = (attempt_id IS NULL)),
    CHECK ((email IS NOT NULL) = (status IN ('pending_setup','inviting','invitation_retryable')))
);
ALTER TABLE bri.user_provisioning ENABLE ROW LEVEL SECURITY;
ALTER TABLE bri.user_provisioning FORCE ROW LEVEL SECURITY;
REVOKE ALL ON bri.user_provisioning FROM PUBLIC, bri_app;
CREATE POLICY provisioning_owner_read ON bri.user_provisioning FOR SELECT TO bri_migrator USING (true);
CREATE POLICY provisioning_owner_insert ON bri.user_provisioning FOR INSERT TO bri_migrator WITH CHECK (true);
CREATE POLICY provisioning_owner_update ON bri.user_provisioning FOR UPDATE TO bri_migrator USING (true);

-- Reuse the existing, unseeded singleton issuer allowlist. Do not accept an
-- arbitrary provider from any provisioning caller, including the worker.
CREATE POLICY provisioning_source_read ON bri.provider_event_source FOR SELECT TO bri_migrator
    USING (session_user IN ('bri_app','bri_provision_worker','bri_provision_activator'));

CREATE POLICY provisioning_permission_insert ON bri.role_permissions AS RESTRICTIVE FOR INSERT TO bri_app
    WITH CHECK (permission <> 'user:provision:create');
CREATE POLICY provisioning_permission_update ON bri.role_permissions AS RESTRICTIVE FOR UPDATE TO bri_app
    USING (permission <> 'user:provision:create') WITH CHECK (permission <> 'user:provision:create');
CREATE POLICY provisioning_permission_delete ON bri.role_permissions AS RESTRICTIVE FOR DELETE TO bri_app
    USING (permission <> 'user:provision:create');

CREATE FUNCTION bri.guard_provisioning_catalog() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF TG_TABLE_NAME = 'app_roles' THEN
        -- Cascading FK deletes bypass child-table RLS, even with no assignment.
        IF EXISTS (SELECT FROM bri.role_permissions r
                   WHERE (r.tenant_id,r.role_id) = (OLD.tenant_id,OLD.role_id)
                     AND r.permission = 'user:provision:create') THEN
            RAISE EXCEPTION 'provisioning role is protected' USING ERRCODE = '42501';
        END IF;
        RETURN OLD;
    END IF;
    IF EXISTS (SELECT FROM bri.auth_role_assignments a JOIN bri.role_permissions r USING (tenant_id,role_id)
               WHERE (a.tenant_id,a.scope_node_id) = (OLD.tenant_id,OLD.node_id)
                 AND r.permission = 'user:provision:create') THEN
        RAISE EXCEPTION 'provisioning scope is protected' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER provisioning_role_delete BEFORE DELETE ON bri.app_roles
FOR EACH ROW WHEN (current_user = 'bri_app') EXECUTE FUNCTION bri.guard_provisioning_catalog();
CREATE TRIGGER provisioning_root_scope BEFORE UPDATE ON bri.org_nodes
FOR EACH ROW WHEN (current_user = 'bri_app' AND (OLD.node_type, OLD.parent_node_id IS NULL)
    IS DISTINCT FROM (NEW.node_type, NEW.parent_node_id IS NULL)) EXECUTE FUNCTION bri.guard_provisioning_catalog();
REVOKE ALL ON FUNCTION bri.guard_provisioning_catalog() FROM PUBLIC, bri_app;

DO $extend$
DECLARE old_check text;
BEGIN
    SELECT pg_get_expr(conbin,conrelid) INTO STRICT old_check FROM pg_constraint
      WHERE conrelid='bri.security_audit_events'::regclass AND conname='security_audit_events_event_type_check';
    ALTER TABLE bri.security_audit_events DROP CONSTRAINT security_audit_events_event_type_check;
    EXECUTE format('ALTER TABLE bri.security_audit_events ADD CONSTRAINT security_audit_events_event_type_check
        CHECK ((%s) OR event_type IN (''tenant.user.provisioning.requested'',''tenant.user.provisioning.claimed'',
        ''tenant.user.provisioning.invitation_sent'',''tenant.user.provisioning.invitation_retryable'',
        ''tenant.user.provisioning.invitation_unresolved'',''tenant.user.provisioning.active''))',old_check);
END $extend$;
CREATE POLICY provisioning_audit_boundary ON bri.security_audit_events AS RESTRICTIVE FOR INSERT TO bri_app
    WITH CHECK (event_type NOT LIKE 'tenant.user.provisioning.%');
-- Immutable claim history fences every prior attempt, not just the last one.
CREATE UNIQUE INDEX provisioning_attempt_once ON bri.security_audit_events(subject_principal_id, request_id)
    WHERE event_type = 'tenant.user.provisioning.claimed';
CREATE POLICY provisioning_claim_history ON bri.security_audit_events FOR SELECT TO bri_migrator
    USING (event_type = 'tenant.user.provisioning.claimed');

CREATE POLICY provisioning_pending_principal ON bri.auth_principals FOR INSERT TO bri_migrator
    WITH CHECK (session_user = 'bri_app' AND status = 'pending');
CREATE POLICY provisioning_pending_membership ON bri.auth_tenant_memberships FOR INSERT TO bri_migrator
    WITH CHECK (session_user = 'bri_app' AND status = 'pending' AND membership_type = 'user' AND NOT emergency_admin);
CREATE POLICY provisioning_principal_activate ON bri.auth_principals FOR UPDATE TO bri_migrator
    USING (session_user = 'bri_provision_activator' AND status = 'pending' AND deletion_requested_at IS NULL)
    WITH CHECK (status = 'active' AND deletion_requested_at IS NULL);
CREATE POLICY provisioning_membership_activate ON bri.auth_tenant_memberships FOR UPDATE TO bri_migrator
    USING (session_user = 'bri_provision_activator' AND status = 'pending' AND membership_type = 'user')
    WITH CHECK (status = 'active' AND membership_type = 'user' AND NOT emergency_admin);
CREATE POLICY provisioning_invited_identity ON bri.auth_identity_links FOR INSERT TO bri_migrator
    WITH CHECK (session_user = 'bri_provision_worker' AND provider_type = 'native'
        AND status = 'active' AND auth_subject = auth_user_id::text);

-- Private checks run only with the owner's forced-RLS visibility. The worker
-- receives no GUC-derived authority; it rechecks the persisted initiating session.
CREATE FUNCTION bri.provisioning_admin(t text, actor uuid, uid text, sid uuid, issuer text, checked_at timestamptz)
RETURNS boolean LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (SELECT FROM bri.provider_event_source src WHERE src.issuer = $5)
    AND EXISTS (
        SELECT FROM bri.auth_sessions s JOIN bri.auth_identity_links i USING (auth_user_id,principal_id)
        JOIN bri.auth_principals p USING (principal_id)
        JOIN bri.auth_tenant_memberships m USING (principal_id)
        JOIN bri.client_activation ca ON ca.tenant_id = m.tenant_id
        JOIN bri.tenant_admin_policies ap ON ap.tenant_id = m.tenant_id
        WHERE s.principal_id = actor AND s.session_id = sid AND m.tenant_id = t
          AND i.auth_user_id::text = uid AND i.status = 'active' AND i.provider_type = 'native'
          AND i.auth_issuer = issuer AND i.auth_subject = i.auth_user_id::text
          AND s.revoked_at IS NULL AND s.started_at <= checked_at
          AND checked_at < least(s.expires_at, s.started_at + interval '8 hours')
          AND p.status = 'active' AND p.deletion_requested_at IS NULL
          AND m.membership_type = 'admin' AND m.status = 'active'
          AND NOT EXISTS (SELECT FROM bri.auth_tenant_memberships x WHERE x.principal_id = actor AND x.tenant_id <> t)
          AND NOT EXISTS (SELECT FROM bri.platform_superadmins x WHERE x.principal_id = actor)
          AND NOT EXISTS (SELECT FROM bri.credential_operations c WHERE c.principal_id = actor AND c.confirmed_at IS NULL)
          AND (SELECT count(*) FROM bri.governance_eligible e WHERE e.tenant_id = t) >= ap.min_emergency_admins
    ) AND EXISTS (
        SELECT FROM bri.auth_role_assignments a JOIN bri.role_permissions r USING (tenant_id,role_id)
        JOIN bri.org_nodes n ON (n.tenant_id,n.node_id) = (a.tenant_id,a.scope_node_id)
        WHERE a.tenant_id = t AND a.principal_id = actor AND a.status = 'active'
          AND r.permission = 'user:provision:create' AND n.node_type = 'root' AND n.parent_node_id IS NULL
          AND NOT EXISTS (SELECT FROM bri.org_nodes x WHERE x.tenant_id = t AND x.parent_node_id IS NULL AND x.node_id <> n.node_id)
    );
$$;

-- The real governance write fence also fails closed if a repeatable-read
-- writer waited behind a policy, identity, grant or topology mutation.
CREATE FUNCTION bri.lock_user_provisioning_governance() RETURNS void
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    UPDATE bri.client_governance_fence SET id=true WHERE id;
    IF NOT FOUND THEN RAISE EXCEPTION 'governance fence unavailable'; END IF;
END $$;

CREATE FUNCTION bri.provisioning_pending_user(t text, target uuid) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT EXISTS (
        SELECT FROM bri.auth_principals p JOIN bri.auth_tenant_memberships m USING (principal_id)
        WHERE p.principal_id = target AND p.status = 'pending' AND p.deletion_requested_at IS NULL
          AND m.tenant_id = t AND m.membership_type = 'user' AND m.status = 'pending' AND NOT m.emergency_admin
    ) AND NOT EXISTS (SELECT FROM bri.auth_tenant_memberships m WHERE m.principal_id = target AND m.tenant_id <> t)
      AND NOT EXISTS (SELECT FROM bri.platform_superadmins s WHERE s.principal_id = target)
      AND NOT EXISTS (SELECT FROM bri.auth_role_assignments a WHERE a.principal_id = target AND a.status = 'active')
      AND NOT EXISTS (SELECT FROM bri.credential_operations c WHERE c.principal_id = target AND c.confirmed_at IS NULL);
$$;

CREATE FUNCTION bri.audit_provisioning(t text, actor uuid, target uuid, transition text, correlation uuid) RETURNS void
LANGUAGE sql SET search_path = pg_catalog, pg_temp AS $$
    INSERT INTO bri.security_audit_events(tenant_id,actor_principal_id,subject_principal_id,event_type,outcome,request_id,occurred_at)
    VALUES(t,actor,target,'tenant.user.provisioning.'||transition,
        CASE WHEN transition IN ('invitation_retryable','invitation_unresolved') THEN 'failure' ELSE 'success' END,
        correlation,clock_timestamp());
$$;
REVOKE ALL ON FUNCTION bri.provisioning_admin(text,uuid,text,uuid,text,timestamptz),
    bri.lock_user_provisioning_governance(), bri.provisioning_pending_user(text,uuid),
    bri.audit_provisioning(text,uuid,uuid,text,uuid) FROM PUBLIC, bri_app;

CREATE FUNCTION bri.request_user_provisioning(t text, actor uuid, sid uuid, issuer text, totp_at timestamptz,
                                              request_key uuid, display_name text, email text, correlation uuid)
RETURNS TABLE(id uuid,status text) LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE uid text := nullif(current_setting('bri.auth_user_id',true),'');
    checked_at timestamptz; op bri.user_provisioning; target uuid;
    name text := btrim(display_name); address text := lower(btrim(email) COLLATE pg_catalog."C"); digest bytea;
BEGIN
    IF t IS NULL OR t IS DISTINCT FROM nullif(current_setting('bri.tenant_id',true),'')
       OR NOT bri.provisioning_admin(t,actor,uid,sid,issuer,clock_timestamp()) THEN
        RAISE EXCEPTION 'provisioning access denied' USING ERRCODE = '42501';
    END IF;
    PERFORM bri.lock_user_provisioning_governance();
    PERFORM bri.lock_session_guard(actor);
    checked_at := clock_timestamp();
    IF NOT bri.provisioning_admin(t,actor,uid,sid,issuer,checked_at)
       OR totp_at IS NULL OR NOT isfinite(totp_at) OR totp_at > checked_at
       OR totp_at <= checked_at - interval '15 minutes'
       OR EXISTS (SELECT FROM bri.session_guards g WHERE g.principal_id = actor
                  AND (totp_at <= g.primary_after OR totp_at <= g.latest_provider_change)) THEN
        RAISE EXCEPTION 'provisioning access denied' USING ERRCODE = '42501';
    END IF;
    IF request_key IS NULL OR correlation IS NULL OR name IS NULL OR char_length(name) NOT BETWEEN 1 AND 128
       OR name ~ '[[:cntrl:]]' OR address IS NULL OR octet_length(address) NOT BETWEEN 3 AND 254
       OR address COLLATE pg_catalog."C" !~ '^[a-z0-9.!#$%&''*+/=?^_`{|}~-]+@[a-z0-9-]+(\.[a-z0-9-]+)+$' THEN
        RAISE EXCEPTION 'invalid provisioning request' USING ERRCODE = '22023';
    END IF;
    digest := sha256(convert_to(t || ':' || address, 'UTF8'));
    SELECT q.* INTO op FROM bri.user_provisioning q WHERE q.tenant_id = t AND q.request_key = $6;
    IF FOUND THEN
        IF (op.actor_id,op.expected_issuer,op.email_digest) IS DISTINCT FROM (actor,issuer,digest)
           OR NOT EXISTS (SELECT FROM bri.auth_principals p WHERE p.principal_id = op.principal_id AND p.display_name = name) THEN
            RAISE EXCEPTION 'provisioning request conflicts' USING ERRCODE = '23505';
        END IF;
        IF op.status IN ('pending_setup','invitation_retryable') THEN
            UPDATE bri.user_provisioning q SET actor_user = uid::uuid, actor_session = sid, actor_totp_at = totp_at
            WHERE q.principal_id = op.principal_id;
        END IF;
        RETURN QUERY SELECT op.principal_id,op.status;
        RETURN;
    END IF;
    IF EXISTS (SELECT FROM bri.user_provisioning q WHERE q.tenant_id = t AND q.email_digest = digest) THEN
        RAISE EXCEPTION 'provisioning request conflicts' USING ERRCODE = '23505';
    END IF;
    INSERT INTO bri.auth_principals(status,display_name) VALUES('pending',name) RETURNING principal_id INTO target;
    INSERT INTO bri.auth_tenant_memberships(tenant_id,principal_id,membership_type,status) VALUES(t,target,'user','pending');
    INSERT INTO bri.user_provisioning(tenant_id,request_key,principal_id,actor_id,actor_user,actor_session,
        actor_totp_at,expected_issuer,email,email_digest) VALUES(t,$6,target,actor,uid::uuid,sid,totp_at,issuer,address,digest);
    PERFORM bri.audit_provisioning(t,actor,target,'requested',correlation);
    RETURN QUERY SELECT target,'pending_setup'::text;
END $$;

CREATE FUNCTION bri.status_user_provisioning(t text, actor uuid, sid uuid, issuer text, request_key uuid)
RETURNS TABLE(id uuid,status text) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF t IS NULL OR t IS DISTINCT FROM nullif(current_setting('bri.tenant_id',true),'')
       OR NOT bri.provisioning_admin(t,actor,current_setting('bri.auth_user_id',true),sid,issuer,clock_timestamp()) THEN
        RAISE EXCEPTION 'provisioning access denied' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY SELECT q.principal_id,q.status FROM bri.user_provisioning q WHERE q.tenant_id = t AND q.request_key = $5;
END $$;
REVOKE ALL ON FUNCTION bri.request_user_provisioning(text,uuid,uuid,text,timestamptz,uuid,text,text,uuid),
    bri.status_user_provisioning(text,uuid,uuid,text,uuid) FROM PUBLIC, bri_app;
GRANT EXECUTE ON FUNCTION bri.request_user_provisioning(text,uuid,uuid,text,timestamptz,uuid,text,text,uuid),
    bri.status_user_provisioning(text,uuid,uuid,text,uuid) TO bri_app;

CREATE FUNCTION bri.provisioning_service(expected text) RETURNS boolean
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT session_user = expected AND EXISTS (
        SELECT FROM pg_roles r WHERE r.rolname = expected AND r.rolcanlogin
          AND NOT (r.rolsuper OR r.rolcreatedb OR r.rolcreaterole OR r.rolreplication OR r.rolbypassrls OR r.rolinherit)
          AND NOT EXISTS (SELECT FROM pg_auth_members m WHERE m.member = r.oid OR (m.roleid = r.oid AND NOT (
              pg_get_userbyid(m.member) = 'postgres' AND pg_get_userbyid(m.grantor) = 'supabase_admin'
              AND m.admin_option AND NOT m.inherit_option AND NOT m.set_option)))
    );
$$;
REVOKE ALL ON FUNCTION bri.provisioning_service(text) FROM PUBLIC, bri_app;

-- Unlike the tenant-local request UUID, the returned account ID is globally
-- unique and safe as an internal worker selector. No browser ID is authority.
CREATE FUNCTION bri.work_user_provisioning(request_key uuid, action text, worker_issuer text,
                                           provider_user uuid, correlation uuid)
RETURNS TABLE(id uuid,status text,email text) LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE op bri.user_provisioning; checked_at timestamptz; next_state text; disclosed text;
BEGIN
    IF NOT bri.provisioning_service('bri_provision_worker') OR
       NOT EXISTS (SELECT FROM bri.provider_event_source src WHERE src.issuer = worker_issuer) THEN
        RAISE EXCEPTION 'provisioning worker denied' USING ERRCODE = '42501';
    END IF;
    IF request_key IS NULL OR correlation IS NULL OR action IS NULL OR
       action NOT IN ('CLAIM','INVITED','RETRYABLE','UNRESOLVED','RECONCILED_INVITED') OR
       ((action IN ('INVITED','RECONCILED_INVITED')) <> (provider_user IS NOT NULL)) THEN
        RAISE EXCEPTION 'invalid provisioning worker operation' USING ERRCODE = '22023';
    END IF;
    PERFORM bri.lock_user_provisioning_governance();
    SELECT q.* INTO op FROM bri.user_provisioning q WHERE q.principal_id = $1 AND q.expected_issuer = worker_issuer FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    IF action = 'CLAIM' THEN
        IF op.status NOT IN ('pending_setup','invitation_retryable') OR EXISTS (
            SELECT FROM bri.security_audit_events e WHERE e.subject_principal_id = op.principal_id
              AND e.event_type = 'tenant.user.provisioning.claimed' AND e.request_id = correlation
        ) THEN
            RETURN QUERY SELECT op.principal_id,op.status,NULL::text;
            RETURN;
        END IF;
        PERFORM bri.lock_session_guard(op.actor_id);
        checked_at := clock_timestamp();
        IF NOT bri.provisioning_admin(op.tenant_id,op.actor_id,op.actor_user::text,op.actor_session,worker_issuer,checked_at)
           OR op.actor_totp_at <= checked_at - interval '15 minutes' OR op.actor_totp_at > checked_at
           OR EXISTS (SELECT FROM bri.session_guards g WHERE g.principal_id = op.actor_id
                      AND (op.actor_totp_at <= g.primary_after OR op.actor_totp_at <= g.latest_provider_change))
           OR NOT bri.provisioning_pending_user(op.tenant_id,op.principal_id)
           OR EXISTS (SELECT FROM bri.auth_identity_links i WHERE i.principal_id = op.principal_id) THEN
            RAISE EXCEPTION 'provisioning dispatch denied' USING ERRCODE = '42501';
        END IF;
        UPDATE bri.user_provisioning q SET status = 'inviting', dispatch_at = clock_timestamp(), attempt_id = correlation
        WHERE q.principal_id = op.principal_id;
        PERFORM bri.audit_provisioning(op.tenant_id,NULL,op.principal_id,'claimed',correlation);
        disclosed := op.email;
        next_state := 'inviting';
    ELSE
        IF op.attempt_id IS DISTINCT FROM correlation THEN
            RAISE EXCEPTION 'provisioning attempt mismatch' USING ERRCODE = '42501';
        END IF;
        IF action IN ('INVITED','RECONCILED_INVITED') AND
           (op.status = 'inviting' OR (action = 'RECONCILED_INVITED' AND op.status = 'invitation_unresolved')) THEN
            -- An authenticated operation-bound receipt is the worker's responsibility.
            -- A UID already linked to anybody (or a target already linked) is
            -- never attached, even if the provider claims a matching address.
            IF bri.provisioning_pending_user(op.tenant_id,op.principal_id) AND NOT EXISTS (
                SELECT FROM bri.auth_identity_links i WHERE i.principal_id = op.principal_id
            ) THEN
                INSERT INTO bri.auth_identity_links(auth_user_id,principal_id,auth_issuer,auth_subject,
                    provider_type,provider_issuer,provider_subject)
                VALUES($4,op.principal_id,worker_issuer,$4::text,'native',worker_issuer,$4::text)
                ON CONFLICT DO NOTHING;
                IF FOUND THEN next_state := 'invitation_sent'; END IF;
            END IF;
            next_state := coalesce(next_state,'invitation_unresolved');
        ELSIF op.status = 'inviting' AND action IN ('UNRESOLVED','RETRYABLE') THEN
            next_state := CASE action WHEN 'UNRESOLVED' THEN 'invitation_unresolved' ELSE 'invitation_retryable' END;
        ELSIF action IN ('INVITED','RECONCILED_INVITED') AND op.provider_user IS NOT NULL
              AND op.provider_user <> $4 THEN
            RAISE EXCEPTION 'provisioning receipt mismatch' USING ERRCODE = '42501';
        ELSE
            next_state := op.status;
        END IF;
        IF next_state <> op.status THEN
            UPDATE bri.user_provisioning q SET status = next_state,
                email = CASE WHEN next_state = 'invitation_retryable' THEN q.email END,
                provider_user = CASE WHEN next_state = 'invitation_sent' THEN $4 END
            WHERE q.principal_id = op.principal_id;
            PERFORM bri.audit_provisioning(op.tenant_id,NULL,op.principal_id,next_state,correlation);
        END IF;
    END IF;
    RETURN QUERY SELECT op.principal_id,next_state,disclosed;
END $$;

CREATE FUNCTION bri.activate_user_provisioning(issuer text, provider_user uuid,
                                                primary_at timestamptz, totp_at timestamptz, correlation uuid)
RETURNS TABLE(id uuid,status text) LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE op bri.user_provisioning; checked_at timestamptz;
BEGIN
    IF NOT bri.provisioning_service('bri_provision_activator') OR
       NOT EXISTS (SELECT FROM bri.provider_event_source src WHERE src.issuer = $1) THEN
        RAISE EXCEPTION 'provisioning activation denied' USING ERRCODE = '42501';
    END IF;
    IF provider_user IS NULL OR correlation IS NULL OR primary_at IS NULL OR totp_at IS NULL OR
       NOT isfinite(primary_at) OR NOT isfinite(totp_at) THEN RETURN; END IF;
    PERFORM bri.lock_user_provisioning_governance();
    SELECT q.* INTO op FROM bri.user_provisioning q WHERE q.provider_user = $2 AND q.expected_issuer = $1
        AND q.status IN ('invitation_sent','active') FOR UPDATE;
    IF NOT FOUND THEN RETURN; END IF;
    PERFORM bri.lock_session_guard(op.principal_id);
    checked_at := clock_timestamp();
    IF primary_at <= op.dispatch_at OR totp_at < primary_at OR totp_at > checked_at
       OR primary_at <= checked_at - interval '15 minutes'
       OR NOT EXISTS (SELECT FROM bri.auth_identity_links i WHERE i.auth_user_id = $2
          AND i.principal_id = op.principal_id AND i.auth_issuer = $1 AND i.auth_subject = $2::text
          AND i.provider_type = 'native' AND i.status = 'active')
       OR EXISTS (SELECT FROM bri.auth_identity_links i WHERE i.principal_id = op.principal_id AND i.auth_user_id <> $2)
       OR EXISTS (SELECT FROM bri.session_guards g WHERE g.principal_id = op.principal_id AND primary_at <= g.latest_provider_change)
       THEN RETURN;
    END IF;
    IF op.status = 'active' THEN
        IF EXISTS (SELECT FROM bri.auth_principals p JOIN bri.auth_tenant_memberships m USING (principal_id)
                   WHERE p.principal_id = op.principal_id AND p.status = 'active' AND p.deletion_requested_at IS NULL
                     AND m.tenant_id = op.tenant_id AND m.status = 'active' AND m.membership_type = 'user') THEN
            RETURN QUERY SELECT op.principal_id,'active'::text;
        END IF;
        RETURN;
    END IF;
    IF NOT bri.provisioning_pending_user(op.tenant_id,op.principal_id) THEN RETURN; END IF;
    UPDATE bri.auth_principals p SET status = 'active', status_changed_at = checked_at
    WHERE p.principal_id = op.principal_id AND p.status = 'pending';
    IF NOT FOUND THEN RAISE EXCEPTION 'provisioning principal unavailable'; END IF;
    UPDATE bri.auth_tenant_memberships m SET status = 'active', status_changed_at = checked_at
    WHERE m.tenant_id = op.tenant_id AND m.principal_id = op.principal_id AND m.status = 'pending';
    IF NOT FOUND THEN RAISE EXCEPTION 'provisioning membership unavailable'; END IF;
    UPDATE bri.user_provisioning q SET status = 'active' WHERE q.principal_id = op.principal_id;
    PERFORM bri.audit_provisioning(op.tenant_id,op.principal_id,op.principal_id,'active',correlation);
    RETURN QUERY SELECT op.principal_id,'active'::text;
END $$;

-- As with A10 workers, separately provision each NOINHERIT login with only
-- schema USAGE and EXECUTE on its own endpoint. Migration runs without them.
REVOKE ALL ON FUNCTION bri.work_user_provisioning(uuid,text,text,uuid,uuid),
    bri.activate_user_provisioning(text,uuid,timestamptz,timestamptz,uuid) FROM PUBLIC, bri_app;
