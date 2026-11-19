-- Reuse the immutable 0006/0008 stream and its read policies. The API can
-- report only unsuccessful boundary operations, never a successful transition.
ALTER TABLE bri.security_audit_events ADD COLUMN boundary_phase text CHECK (boundary_phase IN
    ('input','authentication','mfa','membership','session','authority','operation'));
DO $migration$
DECLARE old_check text;
BEGIN
    SELECT pg_get_expr(conbin,conrelid) INTO STRICT old_check FROM pg_constraint
    WHERE conrelid='bri.security_audit_events'::regclass AND conname='security_audit_events_event_type_check';
    ALTER TABLE bri.security_audit_events DROP CONSTRAINT security_audit_events_event_type_check;
    EXECUTE format('ALTER TABLE bri.security_audit_events ADD CONSTRAINT security_audit_events_event_type_check
        CHECK ((%s) OR event_type IN (''auth.boundary.authenticate'',''auth.boundary.session_start'',
          ''auth.boundary.session_end'',''auth.boundary.recovery'',''auth.boundary.approval_request'',
          ''auth.boundary.approval_decision'',''auth.boundary.approval_status'',
          ''auth.approval.approved'',''auth.approval.rejected'',''auth.approval.expired''))',old_check);
END $migration$;
CREATE POLICY boundary_only_via_functions ON bri.security_audit_events AS RESTRICTIVE
FOR INSERT TO bri_app WITH CHECK (event_type NOT LIKE 'auth.boundary.%' AND event_type NOT LIKE 'auth.approval.%');

CREATE FUNCTION bri.record_boundary_denial(action text, phase text, result text, correlation uuid,
                                          verified_user uuid, verified_issuer text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE actor uuid; tenant text;
BEGIN
    IF action IS NULL OR action NOT IN ('authenticate','session_start','session_end','recovery',
            'approval_request','approval_decision','approval_status') OR phase IS NULL OR
            result IS NULL OR result NOT IN ('denied','failure') OR correlation IS NULL THEN
        RAISE EXCEPTION 'invalid boundary event';
    END IF;
    -- No caller-supplied tenant, principal, subject, path, session or approval ID.
    SELECT principal_id INTO actor FROM bri.auth_identity_links WHERE auth_user_id=verified_user
        AND auth_subject=verified_user::text AND auth_issuer=verified_issuer AND status='active';
    SELECT min(tenant_id) INTO tenant FROM bri.auth_tenant_memberships WHERE principal_id=actor
        AND status='active' AND membership_type<>'platform_superadmin' HAVING count(*)=1;
    INSERT INTO bri.security_audit_events(tenant_id,actor_principal_id,subject_principal_id,event_type,
                                        outcome,request_id,boundary_phase)
    VALUES(tenant,actor,CASE WHEN action NOT IN ('approval_request','approval_decision','approval_status')
        THEN actor END,'auth.boundary.'||action,result,correlation,phase);
END $$;
REVOKE ALL ON FUNCTION bri.record_boundary_denial(text,text,text,uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION bri.record_boundary_denial(text,text,text,uuid,uuid,text) TO bri_app;

-- The existing immutable transition is the sole source: retries that only read
-- state produce no event, and a failed append rolls back the state and vote.
CREATE FUNCTION bri.audit_approval_outcome() RETURNS trigger LANGUAGE plpgsql
SET search_path=pg_catalog,pg_temp AS $$
BEGIN
    INSERT INTO bri.security_audit_events(tenant_id,actor_principal_id,subject_principal_id,event_type,outcome,request_id)
        SELECT tenant_id,NEW.actor,target,'auth.approval.'||lower(NEW.state),'success',NEW.correlation_id
        FROM bri.privileged_approvals WHERE approval_id=NEW.approval_id;
    IF NOT FOUND THEN RAISE EXCEPTION 'approval context unavailable'; END IF;
    RETURN NULL;
END $$;
REVOKE ALL ON FUNCTION bri.audit_approval_outcome() FROM PUBLIC,bri_app;
CREATE TRIGGER approval_security_outcome AFTER INSERT ON bri.approval_events
FOR EACH ROW WHEN (NEW.state IN ('APPROVED','REJECTED','EXPIRED')) EXECUTE FUNCTION bri.audit_approval_outcome();
