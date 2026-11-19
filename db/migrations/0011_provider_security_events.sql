-- Runner owns the transaction. Deliberately inert: no source, login, or runtime grant.
-- Compare provider times only with provider times. The 0008 primary_after
-- cutoff also moves on membership changes and local wall-clock receipt; it is
-- not proof that a provider change with an earlier timestamp was processed.
ALTER TABLE bri.session_guards ADD COLUMN latest_provider_change timestamptz;
CREATE TABLE bri.provider_event_source (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    issuer text NOT NULL CHECK (issuer ~ '^https://[a-z0-9.-]+/auth/v1$' AND length(issuer)<=512)
);
CREATE TABLE bri.provider_event_receipts (
    issuer text NOT NULL, event_id uuid NOT NULL, subject uuid NOT NULL,
    action text NOT NULL, outcome text NOT NULL, source_time timestamptz NOT NULL,
    operation_id uuid, received_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    correlation uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(), PRIMARY KEY (issuer,event_id)
);
ALTER TABLE bri.provider_event_source ENABLE ROW LEVEL SECURITY;
ALTER TABLE bri.provider_event_source FORCE ROW LEVEL SECURITY;
ALTER TABLE bri.provider_event_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE bri.provider_event_receipts FORCE ROW LEVEL SECURITY;
REVOKE ALL ON bri.provider_event_source,bri.provider_event_receipts FROM PUBLIC,bri_app;
CREATE POLICY provision_event_source ON bri.provider_event_source FOR INSERT TO bri_migrator
    WITH CHECK (session_user='bri_migrator');
CREATE POLICY read_bound_source ON bri.provider_event_source FOR SELECT TO bri_migrator
    USING (session_user='bri_provider_ingest');
CREATE POLICY insert_provider_receipt ON bri.provider_event_receipts FOR INSERT TO bri_migrator
    WITH CHECK (session_user='bri_provider_ingest' AND issuer=(SELECT issuer FROM bri.provider_event_source));
CREATE POLICY read_provider_receipt ON bri.provider_event_receipts FOR SELECT TO bri_migrator
    USING (session_user='bri_provider_ingest' AND issuer=(SELECT issuer FROM bri.provider_event_source));
CREATE TRIGGER immutable_provider_receipts BEFORE UPDATE OR DELETE OR TRUNCATE ON bri.provider_event_receipts
    FOR EACH STATEMENT EXECUTE FUNCTION bri.deny_audit_mutation();

-- Keep the entire existing vocabulary and reserve the provider namespace.
DO $extend$
DECLARE old_check text;
BEGIN
    SELECT pg_get_expr(conbin,conrelid) INTO STRICT old_check FROM pg_constraint
      WHERE conrelid='bri.security_audit_events'::regclass AND conname='security_audit_events_event_type_check';
    ALTER TABLE bri.security_audit_events DROP CONSTRAINT security_audit_events_event_type_check;
    EXECUTE format('ALTER TABLE bri.security_audit_events ADD CONSTRAINT security_audit_events_event_type_check
        CHECK ((%s) OR event_type LIKE %L)',old_check,'auth.provider.%');
END $extend$;
ALTER TABLE bri.security_audit_events DROP CONSTRAINT security_audit_events_outcome_check;
ALTER TABLE bri.security_audit_events ADD CONSTRAINT security_audit_events_outcome_check CHECK (
    outcome IN ('success','denied','failure') OR (event_type LIKE 'auth.provider.%' AND outcome='observed'));
CREATE POLICY provider_audit_only_from_boundary ON bri.security_audit_events AS RESTRICTIVE
    FOR INSERT TO bri_app WITH CHECK (event_type NOT LIKE 'auth.provider.%' AND event_type <> 'auth.mfa.factor_removed');

CREATE FUNCTION bri.ingest_provider_security_event(src text,eid uuid,uid uuid,act text,result text,
                                                   happened timestamptz,op uuid)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE change_event boolean; receipt bri.provider_event_receipts; correlation_id uuid;
        p uuid; tenant text; latest_change timestamptz; confirmed boolean := false;
BEGIN
    IF session_user <> 'bri_provider_ingest' OR NOT EXISTS (
        SELECT FROM pg_roles r WHERE rolname=session_user AND rolcanlogin AND NOT
        (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR rolinherit)
        AND NOT EXISTS (SELECT FROM pg_auth_members WHERE member=r.oid OR roleid=r.oid AND NOT (
            pg_get_userbyid(member)='postgres' AND pg_get_userbyid(grantor)='supabase_admin'
            AND admin_option AND NOT inherit_option AND NOT set_option)))
       OR current_setting('transaction_isolation') <> 'read committed'
       OR NOT EXISTS (SELECT FROM bri.provider_event_source WHERE issuer=src)
    THEN RAISE EXCEPTION 'inactive provider boundary' USING ERRCODE='42501'; END IF;
    change_event := act IN ('user_updated_password','factor_deleted','factor_unenrolled','factor_updated',
                            'generate_recovery_codes','recovery_codes_deleted');
    IF eid IS NULL OR uid IS NULL OR '00000000-0000-0000-0000-000000000000'::uuid IN (eid,uid,coalesce(op,eid))
       OR happened IS NULL OR NOT isfinite(happened) OR happened>clock_timestamp()
       OR act IS NULL OR result IS NULL OR result NOT IN ('success','failure','denied','observed')
       OR (change_event AND result<>'success') OR (op IS NOT NULL AND act<>'user_updated_password')
       OR NOT (change_event OR act IN ('login','logout','user_recovery_requested','user_reauthenticate_requested',
                                      'factor_in_progress','challenge_created','verification_attempted','mfa_code_login'))
    THEN RAISE EXCEPTION 'invalid provider event'; END IF;

    INSERT INTO bri.provider_event_receipts(issuer,event_id,subject,action,outcome,source_time,operation_id)
        VALUES(src,eid,uid,act,result,happened,op) ON CONFLICT (issuer,event_id) DO NOTHING
        RETURNING correlation INTO correlation_id;
    IF NOT FOUND THEN
        SELECT * INTO STRICT receipt FROM bri.provider_event_receipts WHERE issuer=src AND event_id=eid;
        IF (receipt.subject,receipt.action,receipt.outcome,receipt.source_time,receipt.operation_id)
            IS DISTINCT FROM (uid,act,result,happened,op) THEN RAISE EXCEPTION 'event identity collision'; END IF;
        RETURN 'duplicate';
    END IF;
    -- Match 0009's lock order: a concurrent membership change takes this
    -- fence before 0008's session guard. Serialize the identity/observation
    -- comparison with the attestor too, not just the subsequent upsert.
    IF act IN ('factor_deleted','factor_unenrolled','factor_updated') THEN
        UPDATE bri.client_governance_fence SET id=true WHERE id;
        IF NOT FOUND THEN RAISE EXCEPTION 'governance fence unavailable'; END IF;
    END IF;
    SELECT principal_id INTO STRICT p FROM bri.auth_identity_links WHERE auth_user_id=uid
        AND auth_issuer=src AND auth_subject=uid::text AND provider_type='native';
    PERFORM bri.lock_session_guard(p);
    IF NOT EXISTS (SELECT FROM bri.auth_identity_links WHERE principal_id=p AND auth_user_id=uid
        AND auth_issuer=src AND auth_subject=uid::text AND provider_type='native')
    THEN RAISE EXCEPTION 'subject binding changed'; END IF;
    tenant := bri.audit_tenant(p);
    IF change_event THEN
        -- Never infer a local operation from its subject or timing. A trusted
        -- causal ID is additionally checked against the reservation and its clock.
        SELECT latest_provider_change INTO STRICT latest_change FROM bri.session_guards WHERE principal_id=p;
        IF (latest_change IS NULL OR happened>=latest_change) AND op IS NOT NULL AND EXISTS (SELECT FROM bri.credential_operations WHERE operation_id=op
            AND principal_id=p AND auth_user_id=uid AND auth_issuer=src AND kind='password_reset'
            AND confirmed_at IS NULL AND reserved_at < happened) THEN
            confirmed := bri.confirm_credential_change(uid,src,'password_reset',correlation_id,op,correlation_id);
            IF confirmed IS NOT TRUE THEN RAISE EXCEPTION 'credential reconciliation incomplete'; END IF;
        END IF;
        IF (latest_change IS NULL OR happened>=latest_change) THEN
            UPDATE bri.session_guards SET latest_provider_change=happened WHERE principal_id=p;
            IF NOT confirmed THEN
                PERFORM bri.invalidate_security_sessions(p,NULL,CASE WHEN act='user_updated_password'
                    THEN 'password_reset' ELSE 'factor_reenrollment' END,correlation_id,tenant);
            END IF;
        END IF;
        -- Negative only; no factor log proves a currently usable TOTP. Do not
        -- replace a different linked identity's attestation. 0009 handles ties.
        IF act IN ('factor_deleted','factor_unenrolled','factor_updated') AND EXISTS (
            SELECT FROM bri.auth_tenant_memberships WHERE principal_id=p AND tenant_id=tenant AND membership_type='admin')
            AND NOT EXISTS (SELECT FROM bri.client_totp_observations WHERE principal_id=p AND tenant_id=tenant
                            AND (auth_user_id,auth_issuer) IS DISTINCT FROM (uid,src)) THEN
            PERFORM bri.record_client_totp_observation(tenant,p,uid,src,happened,NULL);
        END IF;
    END IF;
    INSERT INTO bri.security_audit_events(tenant_id,actor_principal_id,subject_principal_id,event_type,
                                          outcome,request_id,occurred_at)
        VALUES(tenant,NULL,p,'auth.provider.'||act,result,correlation_id,happened);
    RETURN 'applied';
END $$;
REVOKE ALL ON FUNCTION bri.ingest_provider_security_event(text,uuid,uuid,text,text,timestamptz,uuid) FROM PUBLIC,bri_app;
