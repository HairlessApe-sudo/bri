-- Private staged entry points. Take the existing A10 locks in the same order:
-- governance fence, admin mapping, actor session, then A10's approval rows.
-- Keep the lock and visibility checks in separate statements in these VOLATILE
-- functions: at READ COMMITTED the checks get a new snapshot after any wait
-- (including the STABLE 0026 projections called by those checks).
CREATE FUNCTION bri.approval_admin_request(t text, act text, target_id uuid, why text, request_key uuid)
RETURNS text LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE who uuid; sid uuid; issuer text; may_request boolean;
BEGIN
    PERFORM bri.approval_lock();
    who := bri.approval_actor(t);
    sid := current_setting('bri.session_id')::uuid;
    issuer := current_setting('bri.auth_issuer');
    SELECT auth.may_request INTO may_request FROM bri.mfa_reset_read_authority(t,who,sid,issuer) auth;
    -- Check exact directory visibility, not the form's eligibility affordance.
    -- A10 owns eligibility for new requests, exact replay and safe handoff.
    IF may_request IS NOT TRUE OR target_id IS NULL OR NOT EXISTS (
        SELECT FROM bri.read_user_directory(t,who,sid,issuer,coalesce(target_id,who),NULL,NULL,1,0) d
        WHERE d.id = target_id
    ) THEN
        RAISE EXCEPTION 'approval denied' USING ERRCODE = '42501';
    END IF;
    RETURN bri.approval_request(t,act,target_id,why,request_key);
END $$;

CREATE FUNCTION bri.approval_admin_decide(t text, act text, a uuid, choice text)
RETURNS text LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE who uuid; sid uuid; issuer text; review_wide boolean;
BEGIN
    PERFORM bri.approval_lock();
    who := bri.approval_actor(t);
    sid := current_setting('bri.session_id')::uuid;
    issuer := current_setting('bri.auth_issuer');
    SELECT auth.review_wide INTO review_wide FROM bri.mfa_reset_read_authority(t,who,sid,issuer) auth;
    IF review_wide IS NOT TRUE OR a IS NULL OR NOT EXISTS (
        SELECT FROM bri.mfa_reset_visible_page(t,who,sid,issuer,false,true,a,NULL,NULL,1)
    ) THEN
        RAISE EXCEPTION 'approval denied' USING ERRCODE = '42501';
    END IF;
    -- Visibility is independent of the UI's can_decide hint. A10 still owns
    -- replay, expiry, conflicts and the distinct-person check.
    RETURN bri.approval_decide(t,act,a,choice);
END $$;

REVOKE ALL ON FUNCTION bri.approval_admin_request(text,text,uuid,text,uuid),
    bri.approval_admin_decide(text,text,uuid,text) FROM PUBLIC, bri_app;
