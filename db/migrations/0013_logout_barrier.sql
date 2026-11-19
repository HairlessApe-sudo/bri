-- No new login or table. Reuse 0006's unique (auth_user_id, session_id)
-- ledger and FORCE RLS: 0008 removed bri_app's direct session INSERT/UPDATE.
-- An unseen logout gets a revoked row, not a fictitious successful sign-in.
-- For these marked rows started_at/expires_at bound the synthetic row only:
-- there is no start event, and the denial lasts beyond expires_at.
ALTER TABLE bri.auth_sessions ADD COLUMN logout_tombstone boolean NOT NULL DEFAULT false
    CHECK (NOT logout_tombstone OR revoked_at IS NOT NULL);

CREATE OR REPLACE FUNCTION bri.revoke_security_session(sid uuid, correlation uuid) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE u uuid := nullif(current_setting('bri.auth_user_id',true),'')::uuid;
        p uuid; audit_key uuid; t timestamptz;
BEGIN
    IF u IS NULL OR sid IS NULL OR correlation IS NULL THEN RETURN false; END IF;
    SELECT principal_id INTO p FROM bri.auth_identity_links WHERE auth_user_id=u;
    IF NOT FOUND THEN RETURN false; END IF;
    -- Same write fence as start, recovery and invalidation. Re-read after wait.
    PERFORM bri.lock_session_guard(p);
    IF NOT EXISTS (SELECT FROM bri.auth_identity_links WHERE auth_user_id=u AND principal_id=p) THEN
        RETURN false;
    END IF;
    t := clock_timestamp();
    INSERT INTO bri.auth_sessions(auth_user_id,principal_id,session_id,started_at,expires_at,
                                  revoked_at,session_audit_key,logout_tombstone)
      VALUES(u,p,sid,t,t+interval '8 hours',t,gen_random_uuid(),true)
      ON CONFLICT(auth_user_id,session_id) DO NOTHING RETURNING session_audit_key INTO audit_key;
    IF NOT FOUND THEN
        UPDATE bri.auth_sessions SET revoked_at=t,session_audit_key=coalesce(session_audit_key,gen_random_uuid())
          WHERE auth_user_id=u AND principal_id=p AND session_id=sid AND revoked_at IS NULL
          RETURNING session_audit_key INTO audit_key;
        IF NOT FOUND THEN
            RETURN EXISTS (SELECT FROM bri.auth_sessions WHERE auth_user_id=u AND principal_id=p
                           AND session_id=sid AND revoked_at IS NOT NULL);
        END IF;
    END IF;
    PERFORM bri.audit_session_event(p,p,'auth.session.revoked','logout',correlation,audit_key,bri.audit_tenant(p));
    RETURN true;
END $$;
REVOKE ALL ON FUNCTION bri.revoke_security_session(uuid,uuid) FROM PUBLIC,bri_app;
GRANT EXECUTE ON FUNCTION bri.revoke_security_session(uuid,uuid) TO bri_app;
