-- Existing rows retain their original timestamps. As in 0012, replace only
-- the reviewed fragments, preserving locks, audit, function OIDs and ACLs.
DO $upgrade$
DECLARE fn regprocedure; old_fragment text; new_fragment text; definition text;
BEGIN
    FOR fn, old_fragment, new_fragment IN VALUES
      ('bri.start_security_session(text,uuid,timestamptz,uuid)'::regprocedure,
$old$SELECT expires_at INTO expiry FROM bri.auth_sessions WHERE auth_user_id=u AND principal_id=p AND session_id=sid
              AND revoked_at IS NULL AND expires_at>t;$old$,
$new$SELECT least(expires_at, started_at + interval '8 hours') INTO expiry
          FROM bri.auth_sessions WHERE auth_user_id=u AND principal_id=p AND session_id=sid
              AND revoked_at IS NULL AND started_at <= t AND t < least(expires_at, started_at + interval '8 hours');$new$),
      -- An unseen recovery session can present independent provider evidence.
      -- For a persisted session, even fresh evidence cannot revive its ID.
      ('bri.reserve_credential_change(uuid,uuid,uuid,uuid,uuid,text,timestamptz)'::regprocedure,
$old$AND session_id=sid AND revoked_at IS NULL AND expires_at>clock_timestamp()$old$,
$new$AND session_id=sid AND revoked_at IS NULL AND started_at <= clock_timestamp()
                              AND clock_timestamp() < least(expires_at, started_at + interval '8 hours')$new$),
      ('bri.reserve_credential_change(uuid,uuid,uuid,uuid,uuid,text,timestamptz)'::regprocedure,
$old$AND (revoked_at IS NOT NULL OR expires_at<=clock_timestamp())$old$,
$new$AND (revoked_at IS NOT NULL OR started_at > clock_timestamp()
                          OR least(expires_at, started_at + interval '8 hours') <= clock_timestamp())$new$)
    LOOP
        definition := pg_get_functiondef(fn);
        IF array_length(string_to_array(definition, old_fragment), 1) <> 2 THEN
            RAISE EXCEPTION 'unexpected session lifecycle definition: %', fn;
        END IF;
        EXECUTE replace(definition, old_fragment, new_fragment);
    END LOOP;
END $upgrade$;
