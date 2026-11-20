-- Account writes consume verified provider evidence and remain staged-only.
-- Keep read endpoints and the separate provisioning service ACLs unchanged.
REVOKE EXECUTE ON FUNCTION bri.request_user_provisioning(text,uuid,uuid,text,timestamptz,uuid,text,text,uuid),
    bri.change_user_lifecycle(text,uuid,uuid,text,uuid,text,bigint,text,text,timestamptz,uuid)
    FROM PUBLIC, bri_app;
