-- Runner-owned transaction. No grants on provider schemas, no provider I/O.
-- Reuse 0006's audit stream. System/provider events have no human actor;
-- never label the affected user as the administrator who changed their access.
ALTER TABLE bri.security_audit_events ALTER COLUMN actor_principal_id DROP NOT NULL;
ALTER TABLE bri.security_audit_events ADD COLUMN session_audit_key uuid;
ALTER TABLE bri.security_audit_events ADD COLUMN lifecycle_cause text CHECK (lifecycle_cause IN
    ('logout','password_reset','factor_reenrollment','principal','identity','membership',
     'assignment','platform_grant','role_permission'));
-- Preserve the original event vocabulary when extending the allowlist.
DO $migration$
DECLARE old_check text;
BEGIN
    SELECT pg_get_expr(conbin,conrelid) INTO STRICT old_check FROM pg_constraint
    WHERE conrelid='bri.security_audit_events'::regclass AND conname='security_audit_events_event_type_check';
    ALTER TABLE bri.security_audit_events DROP CONSTRAINT security_audit_events_event_type_check;
    EXECUTE format('ALTER TABLE bri.security_audit_events ADD CONSTRAINT security_audit_events_event_type_check CHECK ((%s) OR event_type IN (%L,%L))',
                   old_check,'auth.access.changed','auth.password.changed');
END $migration$;

CREATE FUNCTION bri.deny_audit_mutation() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN RAISE EXCEPTION 'security audit history is immutable'; END $$;
CREATE TRIGGER immutable_security_history BEFORE UPDATE OR DELETE OR TRUNCATE ON bri.security_audit_events
FOR EACH STATEMENT EXECUTE FUNCTION bri.deny_audit_mutation();
REVOKE ALL ON FUNCTION bri.deny_audit_mutation() FROM PUBLIC;

-- The 0006 self-insert policy must not permit forged lifecycle events.
CREATE POLICY lifecycle_events_only_from_boundary ON bri.security_audit_events AS RESTRICTIVE
FOR INSERT TO bri_app WITH CHECK (event_type NOT IN ('auth.session.started','auth.session.revoked',
 'auth.password.reset_requested','auth.password.changed','auth.access.changed',
 'auth.mfa.recovery_initiated','auth.mfa.factor_removed','auth.mfa.factor_enrolled'));
CREATE POLICY lifecycle_audit_append ON bri.security_audit_events FOR INSERT TO bri_migrator WITH CHECK (true);
CREATE TABLE bri.security_retention_policy (
    singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
    retention_days integer NOT NULL DEFAULT 365 CHECK (retention_days > 0)
);
INSERT INTO bri.security_retention_policy DEFAULT VALUES;
-- Advisory retention only: no purge, expiry or DELETE privilege.
ALTER TABLE bri.security_retention_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE bri.security_retention_policy FORCE ROW LEVEL SECURITY;
CREATE POLICY retention_read ON bri.security_retention_policy FOR SELECT TO bri_migrator USING (true);
CREATE POLICY retention_configure ON bri.security_retention_policy FOR UPDATE TO bri_migrator USING (true) WITH CHECK (true);

CREATE TABLE bri.session_guards (
    principal_id uuid PRIMARY KEY REFERENCES bri.auth_principals,
    primary_after timestamptz NOT NULL DEFAULT '-infinity'
);
CREATE TABLE bri.credential_operations (
    operation_id uuid PRIMARY KEY,
    principal_id uuid NOT NULL REFERENCES bri.auth_principals,
    auth_user_id uuid NOT NULL,
    auth_issuer text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('password_reset','factor_reenrollment')),
    recovery_session_id uuid,
    reserved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    confirmed_at timestamptz,
    UNIQUE(auth_user_id,recovery_session_id)
);
CREATE UNIQUE INDEX one_pending_credential_operation ON bri.credential_operations(principal_id) WHERE confirmed_at IS NULL;
CREATE TABLE bri.credential_event_receipts (
    event_id uuid PRIMARY KEY,
    auth_user_id uuid NOT NULL,
    auth_issuer text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('password_reset','factor_reenrollment')),
    operation_id uuid REFERENCES bri.credential_operations,
    received_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE bri.auth_sessions ADD COLUMN session_audit_key uuid;
CREATE INDEX session_invalidation_idx ON bri.auth_sessions(principal_id) WHERE revoked_at IS NULL;
REVOKE INSERT (auth_user_id,principal_id,session_id), UPDATE (revoked_at) ON bri.auth_sessions FROM bri_app;
-- Explicitly remove possible schema bootstrap default privileges on new tables.
REVOKE ALL ON bri.session_guards,bri.credential_operations,bri.credential_event_receipts,bri.security_retention_policy FROM PUBLIC,bri_app;
DO $rls$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['session_guards','credential_operations','credential_event_receipts'] LOOP
        EXECUTE format('ALTER TABLE bri.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE bri.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format('CREATE POLICY lifecycle_select ON bri.%I FOR SELECT TO bri_migrator USING (true)',t);
        EXECUTE format('CREATE POLICY lifecycle_insert ON bri.%I FOR INSERT TO bri_migrator WITH CHECK (true)',t);
    END LOOP;
    FOREACH t IN ARRAY ARRAY['auth_principals','auth_identity_links','auth_role_assignments',
        'auth_tenant_memberships','platform_superadmins','auth_sessions'] LOOP
        EXECUTE format('CREATE POLICY lifecycle_lookup ON bri.%I FOR SELECT TO bri_migrator USING (true)',t);
    END LOOP;
END $rls$;
CREATE POLICY lifecycle_cutoff ON bri.session_guards FOR UPDATE TO bri_migrator USING (true) WITH CHECK (true);
CREATE POLICY lifecycle_confirm ON bri.credential_operations FOR UPDATE TO bri_migrator USING (confirmed_at IS NULL) WITH CHECK (confirmed_at IS NOT NULL);
CREATE POLICY lifecycle_start ON bri.auth_sessions FOR INSERT TO bri_migrator WITH CHECK (true);
CREATE POLICY lifecycle_revoke ON bri.auth_sessions FOR UPDATE TO bri_migrator USING (revoked_at IS NULL) WITH CHECK (revoked_at IS NOT NULL);

-- The guard upsert is a write even on conflict. This serializes unknown/new
-- sessions with barriers, and stale repeatable-read snapshots fail, not pass.
CREATE FUNCTION bri.lock_session_guard(p uuid) RETURNS timestamptz LANGUAGE sql SET search_path=pg_catalog,pg_temp AS $$
    INSERT INTO bri.session_guards VALUES (p,'-infinity') ON CONFLICT(principal_id) DO UPDATE
    SET principal_id=excluded.principal_id RETURNING primary_after
$$;
CREATE FUNCTION bri.audit_tenant(p uuid) RETURNS text LANGUAGE sql STABLE SET search_path=pg_catalog,pg_temp AS $$
    SELECT tenant_id FROM bri.auth_tenant_memberships WHERE principal_id=p AND membership_type<>'platform_superadmin'
$$;
CREATE FUNCTION bri.audit_session_event(p uuid, actor uuid, event_name text, cause text, correlation uuid,
                                       audit_key uuid, tenant text) RETURNS void
LANGUAGE sql SET search_path=pg_catalog,pg_temp AS $$
    INSERT INTO bri.security_audit_events(tenant_id,actor_principal_id,subject_principal_id,event_type,
        outcome,request_id,occurred_at,lifecycle_cause,session_audit_key)
    VALUES(tenant,actor,p,event_name,'success',correlation,clock_timestamp(),cause,audit_key)
$$;
CREATE FUNCTION bri.invalidate_security_sessions(p uuid, actor uuid, cause text, correlation uuid, tenant text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    PERFORM bri.lock_session_guard(p);
    UPDATE bri.session_guards SET primary_after=greatest(primary_after,clock_timestamp()) WHERE principal_id=p;
    WITH changed AS (
        UPDATE bri.auth_sessions SET revoked_at=clock_timestamp(), session_audit_key=coalesce(session_audit_key,gen_random_uuid())
        WHERE principal_id=p AND revoked_at IS NULL RETURNING session_audit_key
    ) INSERT INTO bri.security_audit_events(tenant_id,actor_principal_id,subject_principal_id,event_type,
          outcome,request_id,occurred_at,lifecycle_cause,session_audit_key)
      SELECT tenant,actor,p,'auth.session.revoked','success',correlation,clock_timestamp(),cause,session_audit_key FROM changed;
END $$;

CREATE FUNCTION bri.start_security_session(issuer text, sid uuid, primary_at timestamptz, correlation uuid)
RETURNS timestamptz LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE u uuid := nullif(current_setting('bri.auth_user_id',true),'')::uuid;
        p uuid; cutoff timestamptz; t timestamptz; expiry timestamptz; audit_key uuid;
BEGIN
    IF correlation IS NULL OR sid IS NULL THEN RETURN NULL; END IF;
    SELECT principal_id INTO p FROM bri.auth_identity_links WHERE auth_user_id=u AND auth_issuer=issuer AND auth_subject=u::text;
    IF NOT FOUND THEN RETURN NULL; END IF;
    cutoff := bri.lock_session_guard(p);
    t := clock_timestamp();
    IF NOT EXISTS (SELECT 1 FROM bri.auth_identity_links i JOIN bri.auth_principals a USING(principal_id)
                   WHERE i.auth_user_id=u AND i.principal_id=p AND i.auth_issuer=issuer AND i.auth_subject=u::text
                   AND i.status='active' AND a.status='active')
       OR NOT (EXISTS (SELECT 1 FROM bri.auth_tenant_memberships WHERE principal_id=p AND status='active'
                       AND membership_type <> 'platform_superadmin') OR EXISTS
                      (SELECT 1 FROM bri.platform_superadmins WHERE principal_id=p AND status='active'))
       OR EXISTS (SELECT 1 FROM bri.credential_operations WHERE (principal_id=p AND confirmed_at IS NULL)
                  OR (auth_user_id=u AND recovery_session_id=sid))
       OR primary_at > t OR (primary_at IS NOT NULL AND NOT isfinite(primary_at))
       OR (cutoff <> '-infinity' AND (primary_at IS NULL OR primary_at <= cutoff)) THEN RETURN NULL; END IF;
    INSERT INTO bri.auth_sessions(auth_user_id,principal_id,session_id,started_at,expires_at,session_audit_key)
    VALUES(u,p,sid,t,t+interval '8 hours',gen_random_uuid()) ON CONFLICT(auth_user_id,session_id) DO NOTHING
    RETURNING session_audit_key,expires_at INTO audit_key,expiry;
    IF FOUND THEN
        PERFORM bri.audit_session_event(p,p,'auth.session.started',NULL,correlation,audit_key,bri.audit_tenant(p));
    ELSE
        SELECT expires_at INTO expiry FROM bri.auth_sessions WHERE auth_user_id=u AND principal_id=p AND session_id=sid
              AND revoked_at IS NULL AND expires_at>t;
    END IF;
    RETURN expiry;
END $$;
CREATE FUNCTION bri.revoke_security_session(sid uuid, correlation uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE u uuid := nullif(current_setting('bri.auth_user_id',true),'')::uuid; p uuid; audit_key uuid;
BEGIN
    IF correlation IS NULL THEN RETURN false; END IF;
    UPDATE bri.auth_sessions SET revoked_at=clock_timestamp(),session_audit_key=coalesce(session_audit_key,gen_random_uuid())
        WHERE auth_user_id=u AND session_id=sid AND revoked_at IS NULL RETURNING principal_id,session_audit_key INTO p,audit_key;
    IF NOT FOUND THEN RETURN false; END IF;
    PERFORM bri.audit_session_event(p,p,'auth.session.revoked','logout',correlation,audit_key,bri.audit_tenant(p));
    RETURN true;
END $$;

-- A validated write can touch both the previous and the new principal. For
-- shared role definitions, fan out to every active assignee of either key.
CREATE FUNCTION bri.on_security_binding_change() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE cause text := TG_ARGV[0]; actor uuid; affected uuid; before_p uuid; after_p uuid;
        old_t text; new_t text; old_role text; new_role text; t text;
        correlation uuid := coalesce(nullif(current_setting('bri.correlation_id',true),'')::uuid,gen_random_uuid());
BEGIN
    IF TG_OP='UPDATE' AND OLD IS NOT DISTINCT FROM NEW THEN RETURN NULL; END IF;
    SELECT principal_id INTO actor FROM bri.auth_identity_links WHERE auth_user_id=
        nullif(current_setting('bri.auth_user_id',true),'')::uuid AND status='active';
    IF cause IN ('membership','assignment','role_permission') THEN
        IF TG_OP <> 'INSERT' THEN old_t := OLD.tenant_id; END IF;
        IF TG_OP <> 'DELETE' THEN new_t := NEW.tenant_id; END IF;
    END IF;
    IF cause IN ('assignment','role_permission') THEN
        -- Serialize matching assignment changes and definition edits. Fresh
        -- READ COMMITTED command snapshots observe assignees after the wait.
        IF current_setting('transaction_isolation') <> 'read committed' THEN
            RAISE EXCEPTION 'role changes require read committed isolation';
        END IF;
        IF TG_OP <> 'INSERT' THEN old_role := OLD.role_id; END IF;
        IF TG_OP <> 'DELETE' THEN new_role := NEW.role_id; END IF;
        PERFORM pg_advisory_xact_lock(k) FROM (SELECT DISTINCT hashtextextended(json_build_array(tid,rid)::text,17811) k
           FROM (VALUES (old_t,old_role),(new_t,new_role)) v(tid,rid) WHERE tid IS NOT NULL ORDER BY k) locks;
    END IF;
    IF cause <> 'role_permission' THEN
        IF TG_OP <> 'INSERT' THEN before_p := OLD.principal_id; END IF;
        IF TG_OP <> 'DELETE' THEN after_p := NEW.principal_id; END IF;
    END IF;
    FOR affected IN
        SELECT principal FROM (SELECT before_p AS principal UNION SELECT after_p UNION
           SELECT a.principal_id FROM bri.auth_role_assignments a WHERE cause='role_permission'
           AND a.status='active' AND ((a.tenant_id,a.role_id)=(old_t,old_role) OR (a.tenant_id,a.role_id)=(new_t,new_role))) s
        WHERE principal IS NOT NULL ORDER BY principal
    LOOP
        t := CASE WHEN old_t IS NOT NULL AND new_t IS NOT NULL AND old_t<>new_t THEN NULL
                  ELSE coalesce(new_t,old_t,bri.audit_tenant(affected)) END;
        PERFORM bri.invalidate_security_sessions(affected,actor,cause,correlation,t);
        PERFORM bri.audit_session_event(affected,actor,'auth.access.changed',cause,correlation,NULL,t);
    END LOOP;
    RETURN NULL;
END $$;
CREATE TRIGGER invalidate_principal AFTER UPDATE OF status ON bri.auth_principals
FOR EACH ROW WHEN (OLD.status IS DISTINCT FROM NEW.status) EXECUTE FUNCTION bri.on_security_binding_change('principal');
CREATE TRIGGER invalidate_identity AFTER INSERT OR DELETE OR UPDATE ON bri.auth_identity_links
FOR EACH ROW EXECUTE FUNCTION bri.on_security_binding_change('identity');
CREATE TRIGGER invalidate_membership AFTER INSERT OR DELETE OR UPDATE ON bri.auth_tenant_memberships
FOR EACH ROW EXECUTE FUNCTION bri.on_security_binding_change('membership');
CREATE TRIGGER invalidate_assignment AFTER INSERT OR DELETE OR UPDATE ON bri.auth_role_assignments
FOR EACH ROW EXECUTE FUNCTION bri.on_security_binding_change('assignment');
CREATE TRIGGER invalidate_platform_grant AFTER INSERT OR DELETE OR UPDATE ON bri.platform_superadmins
FOR EACH ROW EXECUTE FUNCTION bri.on_security_binding_change('platform_grant');
CREATE TRIGGER invalidate_role_permission AFTER INSERT OR DELETE OR UPDATE ON bri.role_permissions
FOR EACH ROW EXECUTE FUNCTION bri.on_security_binding_change('role_permission');

-- Commit reservation BEFORE external I/O. One pending operation per principal;
-- no timeout auto-unblocks it. The provider recovery session is permanently
-- consumed, even if it never started a BRI session. Never store credentials.
CREATE FUNCTION bri.reserve_credential_change(u uuid, sid uuid, actor uuid, op uuid, correlation uuid, change_kind text, recovery_at timestamptz)
RETURNS boolean LANGUAGE plpgsql SET search_path=pg_catalog,pg_temp AS $$
DECLARE p uuid; issuer text; t text; cutoff timestamptz;
BEGIN
    SELECT principal_id INTO p FROM bri.auth_identity_links WHERE auth_user_id=u;
    IF p IS NULL OR op IS NULL OR correlation IS NULL THEN RETURN false; END IF;
    cutoff := bri.lock_session_guard(p);
    SELECT auth_issuer INTO issuer FROM bri.auth_identity_links WHERE auth_user_id=u AND principal_id=p
      AND provider_type='native' AND status='active' AND auth_subject=u::text;
    IF NOT FOUND THEN RETURN false; END IF;
    IF change_kind='password_reset' THEN
        IF sid IS NULL OR (recovery_at IS NOT NULL AND (NOT isfinite(recovery_at) OR recovery_at>clock_timestamp()))
          OR (cutoff <> '-infinity' AND (recovery_at IS NULL OR recovery_at<=cutoff)
              AND NOT EXISTS (SELECT 1 FROM bri.auth_sessions WHERE auth_user_id=u AND principal_id=p
                              AND session_id=sid AND revoked_at IS NULL AND expires_at>clock_timestamp()))
          OR NOT EXISTS (SELECT 1 FROM bri.auth_principals WHERE principal_id=p AND status='active')
          OR NOT EXISTS (SELECT 1 FROM bri.auth_tenant_memberships m WHERE m.principal_id=p AND m.status='active'
              AND (m.membership_type<>'platform_superadmin' OR EXISTS
                   (SELECT 1 FROM bri.platform_superadmins WHERE principal_id=p AND status='active')))
          OR EXISTS (SELECT 1 FROM bri.auth_sessions WHERE auth_user_id=u AND session_id=sid
                     AND (revoked_at IS NOT NULL OR expires_at<=clock_timestamp())) THEN RETURN false; END IF;
        actor := p;
    END IF;
    INSERT INTO bri.credential_operations(operation_id,principal_id,auth_user_id,auth_issuer,kind,recovery_session_id)
    VALUES(op,p,u,issuer,change_kind,sid) ON CONFLICT DO NOTHING;
    IF NOT FOUND THEN RETURN false; END IF;
    t := bri.audit_tenant(p);
    PERFORM bri.invalidate_security_sessions(p,actor,change_kind,correlation,t);
    PERFORM bri.audit_session_event(p,actor,CASE change_kind WHEN 'password_reset' THEN 'auth.password.reset_requested'
         ELSE 'auth.mfa.recovery_initiated' END,change_kind,correlation,NULL,t);
    RETURN true;
END $$;
CREATE FUNCTION bri.reserve_password_recovery(sid uuid, correlation uuid, recovery_at timestamptz DEFAULT NULL) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
    SELECT bri.reserve_credential_change(nullif(current_setting('bri.auth_user_id',true),'')::uuid,
                                         sid,NULL,correlation,correlation,'password_reset',recovery_at)
$$;
-- Approval executor only, after separate dual-control authorization, never bri_app.
CREATE FUNCTION bri.reserve_factor_reenrollment(u uuid, actor uuid, op uuid, correlation uuid) RETURNS boolean
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
    SELECT bri.reserve_credential_change(u,NULL,actor,op,correlation,'factor_reenrollment',NULL)
$$;

-- Trusted receiver ONLY. Verify provider authenticity/project/issuer, subject,
-- event type, immutable event ID and completed change. Pin a locally initiated
-- operation using authenticated provider-side causality, not browser assertions
-- or merely finding an outstanding request for that user. For MFA require
-- independently verified controlled re-enrollment, not removal, stale AAL2 or
-- the presence of any factor. Failed/ambiguous/unmatched completions do not
-- release a barrier. NULL op = authenticated out-of-band password change that
-- invalidates sessions but cannot complete an unrelated pending operation.
-- Receipts make exact duplicate deliveries idempotent, reject ID substitution.
-- A delayed webhook alone does NOT prevent use before delivery. Do not enable
-- hosted access until *all* credential changes are preblocked or checked using
-- synchronous authoritative evidence on protected access. No provider wiring
-- or privilege grants for this future server-only consumer are installed here.
CREATE FUNCTION bri.confirm_credential_change(u uuid, issuer text, change_kind text, eid uuid, op uuid, correlation uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE p uuid; receipt bri.credential_event_receipts; t text;
BEGIN
    IF correlation IS NULL OR eid IS NULL OR change_kind IS NULL OR change_kind NOT IN ('password_reset','factor_reenrollment')
       OR (change_kind='factor_reenrollment' AND op IS NULL) THEN RETURN false; END IF;
    SELECT principal_id INTO p FROM bri.auth_identity_links WHERE auth_user_id=u AND auth_issuer=issuer AND auth_subject=u::text AND provider_type='native';
    IF NOT FOUND THEN RETURN false; END IF;
    PERFORM bri.lock_session_guard(p);
    IF NOT EXISTS (SELECT 1 FROM bri.auth_identity_links WHERE auth_user_id=u AND principal_id=p
                   AND auth_issuer=issuer AND auth_subject=u::text AND provider_type='native') THEN RETURN false; END IF;
    SELECT * INTO receipt FROM bri.credential_event_receipts WHERE event_id=eid;
    IF FOUND THEN RETURN (receipt.auth_user_id, receipt.auth_issuer, receipt.kind, receipt.operation_id)
             IS NOT DISTINCT FROM (u,issuer,change_kind,op); END IF;
    IF op IS NOT NULL THEN
        UPDATE bri.credential_operations SET confirmed_at=clock_timestamp() WHERE operation_id=op AND principal_id=p
            AND auth_user_id=u AND auth_issuer=issuer AND kind=change_kind AND confirmed_at IS NULL;
        IF NOT FOUND THEN RETURN false; END IF;
    END IF;
    INSERT INTO bri.credential_event_receipts(event_id,auth_user_id,auth_issuer,kind,operation_id) VALUES(eid,u,issuer,change_kind,op);
    t := bri.audit_tenant(p);
    PERFORM bri.invalidate_security_sessions(p,NULL,change_kind,correlation,t);
    PERFORM bri.audit_session_event(p,NULL,CASE change_kind WHEN 'password_reset' THEN 'auth.password.changed'
            ELSE 'auth.mfa.factor_enrolled' END,change_kind,correlation,NULL,t);
    RETURN true;
END $$;

REVOKE ALL ON FUNCTION bri.lock_session_guard(uuid), bri.audit_tenant(uuid),
 bri.audit_session_event(uuid,uuid,text,text,uuid,uuid,text), bri.invalidate_security_sessions(uuid,uuid,text,uuid,text),
 bri.on_security_binding_change(), bri.reserve_credential_change(uuid,uuid,uuid,uuid,uuid,text,timestamptz),
 bri.reserve_factor_reenrollment(uuid,uuid,uuid,uuid), bri.confirm_credential_change(uuid,text,text,uuid,uuid,uuid),
 bri.start_security_session(text,uuid,timestamptz,uuid), bri.revoke_security_session(uuid,uuid),
 bri.reserve_password_recovery(uuid,uuid,timestamptz) FROM PUBLIC,bri_app;
GRANT EXECUTE ON FUNCTION bri.start_security_session(text,uuid,timestamptz,uuid),
 bri.revoke_security_session(uuid,uuid), bri.reserve_password_recovery(uuid,uuid,timestamptz) TO bri_app;
