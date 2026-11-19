-- The checked-in runner owns this transaction. No role, source, secret or grant bootstrap.
-- Keep 0010's reviewed state machine, OID and deployed ACL; change only its old
-- quarantine write. Assert each literal once rather than silently accepting drift.
DO $upgrade$
DECLARE
    fn regprocedure;
    old_fragment text;
    new_fragment text;
    definition text;
BEGIN
    FOR fn, old_fragment, new_fragment IN VALUES
      ('bri.approval_work(text,text,uuid,text,uuid[])'::regprocedure,
$old$            UPDATE bri.auth_principals SET status='suspended',status_changed_at=clock_timestamp()
                WHERE principal_id=r.target AND status='active';
            IF NOT FOUND THEN RAISE EXCEPTION 'quarantine failed'; END IF;$old$,
$new$            -- The reservation below is the session quarantine; never mutate administrative status.$new$),
      ('bri.approval_target(text,uuid,boolean)'::regprocedure,
$old$p.status=CASE WHEN quarantined THEN 'suspended' ELSE 'active' END$old$,
$new$p.status='active' AND quarantined = EXISTS (
          SELECT FROM bri.credential_operations co WHERE co.principal_id=who AND co.confirmed_at IS NULL)$new$),
      ('bri.start_security_session(text,uuid,timestamptz,uuid)'::regprocedure,
$old$i.status='active' AND a.status='active'$old$,
$new$i.status='active' AND a.status='active' AND a.deletion_requested_at IS NULL$new$)
    LOOP
        definition := pg_get_functiondef(fn);
        IF array_length(string_to_array(definition,old_fragment),1) <> 2 THEN
            RAISE EXCEPTION 'unexpected lifecycle definition: %',fn;
        END IF;
        EXECUTE replace(definition,old_fragment,new_fragment);
    END LOOP;
END $upgrade$;
DROP POLICY approval_quarantine ON bri.auth_principals;
CREATE TRIGGER invalidate_deletion_request AFTER UPDATE OF deletion_requested_at ON bri.auth_principals
FOR EACH ROW WHEN (OLD.deletion_requested_at IS DISTINCT FROM NEW.deletion_requested_at)
EXECUTE FUNCTION bri.on_security_binding_change('principal');

-- One immutable platform case plus its independently authenticated provider proof.
-- The platform assertion binds the proofed human to this replacement factor;
-- the provider assertion binds creation and successful TOTP challenge to that case.
CREATE TABLE bri.reenrollment_proofs (
    authority text NOT NULL CHECK (authority IN ('platform','provider')),
    event_id uuid NOT NULL UNIQUE,
    operation_id uuid NOT NULL REFERENCES bri.privileged_approvals,
    tenant_id text NOT NULL, issuer text NOT NULL, subject uuid NOT NULL, factor_id uuid NOT NULL,
    case_id uuid NOT NULL, happened_at timestamptz NOT NULL, created_at timestamptz,
    PRIMARY KEY (operation_id,authority),
    CHECK ((authority='platform' AND event_id=case_id AND created_at IS NULL) OR
           (authority='provider' AND event_id<>case_id AND created_at IS NOT NULL AND created_at<=happened_at))
);
ALTER TABLE bri.reenrollment_proofs ENABLE ROW LEVEL SECURITY;
ALTER TABLE bri.reenrollment_proofs FORCE ROW LEVEL SECURITY;
REVOKE ALL ON bri.reenrollment_proofs FROM PUBLIC,bri_app;
CREATE POLICY reenrollment_read ON bri.reenrollment_proofs FOR SELECT TO bri_migrator USING (true);
CREATE POLICY reenrollment_append ON bri.reenrollment_proofs FOR INSERT TO bri_migrator
    WITH CHECK (session_user='bri_reenrollment_'||authority);
CREATE TRIGGER immutable_reenrollment BEFORE UPDATE OR DELETE OR TRUNCATE ON bri.reenrollment_proofs
FOR EACH STATEMENT EXECUTE FUNCTION bri.deny_audit_mutation();
CREATE POLICY reenrollment_source ON bri.provider_event_source FOR SELECT TO bri_migrator
    USING (session_user IN ('bri_reenrollment_platform','bri_reenrollment_provider'));

-- Even an older grant on the generic 0008 confirmer cannot clear the barrier.
-- Password reconciliation from 0011 is unchanged. Provider proof insert and the
-- 0008 receipt, audit, cutoff advance and confirmation commit or roll back together.
CREATE POLICY require_reenrollment_proof ON bri.credential_operations AS RESTRICTIVE
FOR UPDATE TO bri_migrator USING (true) WITH CHECK (kind <> 'factor_reenrollment' OR (
    session_user='bri_reenrollment_provider' AND EXISTS (
        SELECT FROM bri.reenrollment_proofs v JOIN bri.reenrollment_proofs h
        USING (operation_id,tenant_id,issuer,subject,factor_id,case_id)
        WHERE v.operation_id=credential_operations.operation_id AND v.authority='provider' AND h.authority='platform'
          AND v.subject=credential_operations.auth_user_id AND v.issuer=credential_operations.auth_issuer)));

CREATE FUNCTION bri.record_reenrollment_proof(t text, op uuid, src text, uid uuid, factor uuid,
    case_key uuid, eid uuid, happened timestamptz, created timestamptz) RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE side text; existing bri.reenrollment_proofs; platform bri.reenrollment_proofs;
        target_id uuid; removed timestamptz; cutoff timestamptz; latest timestamptz;
BEGIN
    side := CASE session_user WHEN 'bri_reenrollment_platform' THEN 'platform'
                              WHEN 'bri_reenrollment_provider' THEN 'provider' END;
    IF side IS NULL OR NOT EXISTS (SELECT FROM pg_roles r WHERE rolname=session_user AND rolcanlogin AND NOT
        (rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls OR rolinherit)
        AND NOT EXISTS (SELECT FROM pg_auth_members WHERE member=r.oid OR roleid=r.oid AND NOT (
            pg_get_userbyid(member)='postgres' AND pg_get_userbyid(grantor)='supabase_admin'
            AND admin_option AND NOT inherit_option AND NOT set_option)))
       OR NOT EXISTS (SELECT FROM bri.provider_event_source WHERE issuer=src) THEN
        RAISE EXCEPTION 'inactive proof boundary' USING ERRCODE='42501'; END IF;
    PERFORM bri.approval_lock();
    SELECT * INTO existing FROM bri.reenrollment_proofs WHERE event_id=eid;
    IF FOUND THEN
        IF (existing.authority,existing.operation_id,existing.tenant_id,existing.issuer,existing.subject,
            existing.factor_id,existing.case_id,existing.happened_at,existing.created_at)
           IS DISTINCT FROM (side,op,t,src,uid,factor,case_key,happened,created) THEN
            RAISE EXCEPTION 'proof identity collision'; END IF;
        RETURN 'duplicate'; -- No confirmation, cutoff, privilege or session change on replay.
    END IF;
    SELECT r.target,e.occurred_at INTO target_id,removed FROM bri.privileged_approvals r
        JOIN bri.approval_events e ON e.approval_id=r.approval_id AND e.state='COMPLETED'
        JOIN bri.credential_operations c ON c.operation_id=r.approval_id AND c.principal_id=r.target
        WHERE r.approval_id=op AND r.tenant_id=t AND r.target_auth=uid AND r.action='USER_MFA_RESET'
          AND r.state='COMPLETED' AND cardinality(r.factor_ids)>0 AND factor<>ALL(r.factor_ids)
          AND c.auth_issuer=src AND c.auth_user_id=uid AND c.kind='factor_reenrollment' AND c.confirmed_at IS NULL;
    IF NOT FOUND THEN RAISE EXCEPTION 'no matching completed removal'; END IF;
    cutoff := bri.lock_session_guard(target_id);
    SELECT latest_provider_change INTO STRICT latest FROM bri.session_guards WHERE principal_id=target_id;
    PERFORM set_config('bri.auth_issuer',src,true);
    IF bri.approval_target(t,target_id,true) IS DISTINCT FROM uid OR uid IS NULL
        OR happened IS NULL OR NOT isfinite(happened) OR happened<=greatest(removed,cutoff,latest)
        OR happened>clock_timestamp() OR happened<clock_timestamp()-interval '15 minutes'
        OR '00000000-0000-0000-0000-000000000000'::uuid IN (uid,op,factor,case_key,eid) THEN
        RAISE EXCEPTION 'ineligible target or stale proof'; END IF;
    IF side='provider' THEN
        SELECT * INTO platform FROM bri.reenrollment_proofs h WHERE h.operation_id=op AND h.authority='platform'
            AND (h.tenant_id,h.issuer,h.subject,h.factor_id,h.event_id)=(t,src,uid,factor,case_key);
        IF NOT FOUND OR platform.happened_at<=greatest(cutoff,latest)
           OR platform.happened_at<clock_timestamp()-interval '15 minutes' OR happened<platform.happened_at
           OR created IS NULL OR NOT isfinite(created) OR created<=removed OR created>happened THEN
            RAISE EXCEPTION 'missing matching fresh case or new factor proof'; END IF;
    END IF;
    INSERT INTO bri.reenrollment_proofs(authority,event_id,operation_id,tenant_id,issuer,subject,factor_id,
                                        case_id,happened_at,created_at)
        VALUES(side,eid,op,t,src,uid,factor,case_key,happened,created);
    IF side='platform' THEN RETURN 'awaiting_provider'; END IF;
    IF bri.confirm_credential_change(uid,src,'factor_reenrollment',eid,op,eid) IS NOT TRUE THEN
        RAISE EXCEPTION 'credential confirmation refused'; END IF;
    IF NOT EXISTS (
        SELECT FROM bri.credential_operations WHERE operation_id=op AND confirmed_at IS NOT NULL) THEN
        RAISE EXCEPTION 'credential confirmation incomplete'; END IF;
    RETURN 'confirmed';
END $$;
REVOKE ALL ON FUNCTION bri.record_reenrollment_proof(text,uuid,text,uuid,uuid,uuid,uuid,timestamptz,timestamptz)
    FROM PUBLIC,bri_app;
