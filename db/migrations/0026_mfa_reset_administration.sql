-- A10 entry points consume provider verification context. Keep them off the
-- runtime role until there is an approved trusted invocation boundary.
REVOKE EXECUTE ON FUNCTION bri.approval_request(text,text,uuid,text,uuid),
    bri.approval_decide(text,text,uuid,text), bri.approval_status(text,text,uuid)
    FROM PUBLIC, bri_app;

-- Role catalog DML is already closed to bri_app (A11.4). Extend the existing
-- runtime topology guard so editing nodes cannot create a queue root grant.
CREATE OR REPLACE FUNCTION bri.guard_deactivation_root() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE old_tenant text; new_tenant text; protected_permission text;
BEGIN
    IF TG_OP = 'UPDATE' AND (OLD.tenant_id,OLD.node_id,OLD.node_type,OLD.parent_node_id IS NULL)
        IS NOT DISTINCT FROM (NEW.tenant_id,NEW.node_id,NEW.node_type,NEW.parent_node_id IS NULL) THEN
        RETURN NEW;
    END IF;
    IF TG_OP <> 'INSERT' AND OLD.parent_node_id IS NULL THEN old_tenant := OLD.tenant_id; END IF;
    IF TG_OP <> 'DELETE' AND NEW.parent_node_id IS NULL THEN new_tenant := NEW.tenant_id; END IF;
    SELECT r.permission INTO protected_permission
    FROM bri.auth_role_assignments a JOIN bri.role_permissions r USING (tenant_id,role_id)
    WHERE a.tenant_id IN (old_tenant,new_tenant) AND a.status = 'active'
      AND r.permission IN ('user:deactivate','account:history:read','account:grants:read','account:mfa-reset:queue:read')
    ORDER BY CASE r.permission WHEN 'user:deactivate' THEN 1 WHEN 'account:history:read' THEN 2
                               WHEN 'account:grants:read' THEN 3 ELSE 4 END
    LIMIT 1;
    IF protected_permission = 'user:deactivate' THEN
        RAISE EXCEPTION 'deactivation root topology is protected' USING ERRCODE = '42501';
    ELSIF protected_permission = 'account:history:read' THEN
        RAISE EXCEPTION 'account history root topology is protected' USING ERRCODE = '42501';
    ELSIF protected_permission = 'account:grants:read' THEN
        RAISE EXCEPTION 'account grants root topology is protected' USING ERRCODE = '42501';
    ELSIF protected_permission = 'account:mfa-reset:queue:read' THEN
        RAISE EXCEPTION 'MFA reset queue root topology is protected' USING ERRCODE = '42501';
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END $$;

-- Private invoker helpers run as the definer only through the staged reads.
CREATE FUNCTION bri.mfa_reset_read_authority(t text, actor uuid, sid uuid, issuer text)
RETURNS TABLE (may_request boolean, review_wide boolean)
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF session_user <> 'bri_app' OR t IS NULL OR t IS DISTINCT FROM nullif(current_setting('bri.tenant_id',true),'')
        OR NOT EXISTS (
            SELECT FROM bri.auth_sessions s LEFT JOIN bri.session_guards g USING (principal_id)
            WHERE s.principal_id = actor AND s.session_id = sid
              AND s.auth_user_id::text = nullif(current_setting('bri.auth_user_id',true),'')
              AND s.started_at > coalesce(g.primary_after,'-infinity'::timestamptz)
        ) OR EXISTS (SELECT FROM bri.credential_operations c
                     WHERE c.principal_id = actor AND c.confirmed_at IS NULL) THEN
        RAISE EXCEPTION 'MFA reset administration access denied' USING ERRCODE = '42501';
    END IF;

    -- Exact lookup intentionally returns no row for the admin viewer; it
    -- still enforces directory authority, verified identity and live session.
    PERFORM FROM bri.read_user_directory(t,actor,sid,issuer,actor,NULL,NULL,1,0);

    may_request := bri.approval_person(t,actor,'user:mfa_reset:request') IS NOT NULL;
    review_wide := bri.approval_person(t,actor,'user:mfa_reset:decide') IS NOT NULL AND EXISTS (
        SELECT FROM bri.approval_admin_people ap
        JOIN bri.auth_role_assignments a USING (tenant_id,principal_id,scope_node_id)
        JOIN bri.role_permissions r USING (tenant_id,role_id)
        JOIN bri.org_nodes n ON (n.tenant_id,n.node_id) = (ap.tenant_id,ap.scope_node_id)
        WHERE ap.tenant_id = t AND ap.principal_id = actor AND NOT ap.revoked AND a.status = 'active'
          AND r.permission = 'account:mfa-reset:queue:read' AND n.node_type = 'root' AND n.parent_node_id IS NULL
    );
    RETURN NEXT;
END $$;

-- Read-only form of A10 target eligibility with an explicit, verified issuer.
-- Do not change auth GUCs or expose the returned auth ID to a caller.
CREATE FUNCTION bri.mfa_reset_eligible_identity(t text, target uuid, issuer text, quarantined boolean)
RETURNS uuid LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT i.auth_user_id
    FROM bri.auth_identity_links i JOIN bri.auth_principals p USING (principal_id)
    JOIN bri.auth_tenant_memberships m USING (principal_id)
    WHERE m.tenant_id = t AND m.membership_type = 'user' AND m.status = 'active' AND i.principal_id = target
      AND p.deletion_requested_at IS NULL AND p.status = 'active'
      AND quarantined = EXISTS (
          SELECT FROM bri.credential_operations c WHERE c.principal_id = target AND c.confirmed_at IS NULL)
      AND i.status = 'active' AND i.provider_type = 'native' AND i.auth_subject = i.auth_user_id::text
      AND i.auth_issuer = issuer
      AND NOT EXISTS (SELECT FROM bri.auth_identity_links x WHERE x.principal_id = target
                      AND x.auth_user_id <> i.auth_user_id AND x.status = 'active')
      AND NOT EXISTS (SELECT FROM bri.auth_tenant_memberships x WHERE x.principal_id = target AND x.tenant_id <> t)
      AND NOT EXISTS (SELECT FROM bri.platform_superadmins x WHERE x.principal_id = target)
$$;

CREATE FUNCTION bri.can_request_mfa_reset(t text, actor uuid, sid uuid, issuer text, target uuid)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
    IF NOT (SELECT may_request FROM bri.mfa_reset_read_authority(t,actor,sid,issuer)) THEN
        RAISE EXCEPTION 'MFA reset request access denied' USING ERRCODE = '42501';
    END IF;
    RETURN target IS NOT NULL AND EXISTS (
        SELECT FROM bri.read_user_directory(t,actor,sid,issuer,coalesce(target,actor),NULL,NULL,1,0) d
        WHERE d.id = target AND d.role = 'user' AND d.status = 'active'
          AND bri.mfa_reset_eligible_identity(t,d.id,issuer,false) IS NOT NULL
    );
END $$;

-- Keep the item/cursor lookup and the page on the same visibility predicate.
CREATE FUNCTION bri.mfa_reset_visible_page(t text, actor uuid, sid uuid, issuer text,
    may_request boolean, review_wide boolean, item uuid, before_at timestamptz, before_id uuid, row_limit integer)
RETURNS TABLE (approval bri.privileged_approvals, target_name text)
LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
    SELECT a, d.display_name
    FROM bri.privileged_approvals a
    CROSS JOIN LATERAL bri.read_user_directory(t,actor,sid,issuer,a.target,NULL,NULL,1,0) d
    WHERE a.tenant_id = t AND a.action = 'USER_MFA_RESET'
      AND (review_wide OR (may_request AND a.requester = actor))
      AND (item IS NULL OR a.approval_id = item)
      AND (before_id IS NULL OR (a.created_at,a.approval_id) < (before_at,before_id))
    ORDER BY a.created_at DESC, a.approval_id DESC LIMIT row_limit
$$;

CREATE FUNCTION bri.read_mfa_reset_queue(t text, actor uuid, sid uuid, issuer text,
    page_size integer, before_id uuid, item_id uuid)
RETURNS TABLE (approval_id uuid, target_id uuid, target_name text, reason text,
    requested_at timestamptz, expires_at timestamptz, state text, reconciliation text, can_decide boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE may_request boolean; review_wide boolean; cursor_at timestamptz; read_at timestamptz := statement_timestamp();
BEGIN
    SELECT auth.may_request, auth.review_wide INTO may_request, review_wide
    FROM bri.mfa_reset_read_authority(t,actor,sid,issuer) auth;
    IF NOT (may_request OR review_wide) THEN
        RAISE EXCEPTION 'MFA reset queue access denied' USING ERRCODE = '42501';
    END IF;
    IF page_size IS NULL OR page_size NOT BETWEEN 1 AND 100 OR (before_id IS NOT NULL AND item_id IS NOT NULL) THEN
        RAISE EXCEPTION 'invalid MFA reset queue query' USING ERRCODE = '22023';
    END IF;
    IF before_id IS NOT NULL THEN
        SELECT (p.approval).created_at INTO cursor_at
        FROM bri.mfa_reset_visible_page(t,actor,sid,issuer,may_request,review_wide,before_id,NULL,NULL,1) p;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'MFA reset queue cursor unavailable' USING ERRCODE = '22023';
        END IF;
    END IF;

    RETURN QUERY
    SELECT (p.approval).approval_id, (p.approval).target, p.target_name, (p.approval).reason,
           (p.approval).created_at, (p.approval).expires_at,
           CASE WHEN (p.approval).state IN ('PENDING','APPROVED') AND (p.approval).expires_at <= read_at
                THEN 'EXPIRED' ELSE (p.approval).state END,
           CASE WHEN (p.approval).state = 'COMPLETED' THEN 'VERIFIED_ABSENT'
                WHEN (p.approval).state = 'FAILED' AND (p.approval).sealed AND o.outcome = 'SAFE_HANDOFF' THEN 'SAFE_HANDOFF'
                WHEN (p.approval).state = 'FAILED' THEN 'UNRESOLVED'
                WHEN (p.approval).state = 'EXECUTING' THEN 'PENDING'
                ELSE 'NONE' END,
           -- An affordance only: A10 still serializes and rechecks on mutation.
           CASE WHEN review_wide AND (p.approval).requester <> actor AND (p.approval).state = 'PENDING'
                  AND (p.approval).expires_at > read_at THEN
                bri.mfa_reset_eligible_identity(t,(p.approval).target,issuer,(p.approval).retry_of IS NOT NULL)
                    IS NOT DISTINCT FROM (p.approval).target_auth
                AND EXISTS (
                    SELECT FROM bri.approval_votes v
                    JOIN bri.auth_sessions s ON (s.auth_user_id,s.session_id,s.principal_id) = (v.auth_id,v.session_id,v.actor)
                    JOIN bri.auth_identity_links i USING (auth_user_id,principal_id)
                    LEFT JOIN bri.session_guards g USING (principal_id)
                    WHERE v.approval_id = (p.approval).approval_id AND v.decision = 'REQUEST'
                      AND v.actor = (p.approval).requester
                      AND v.person_id = bri.approval_person(t,v.actor,'user:mfa_reset:request')
                      AND i.status = 'active' AND i.auth_issuer = issuer AND i.auth_subject = i.auth_user_id::text
                      AND s.revoked_at IS NULL AND s.started_at <= read_at
                      AND read_at < least(s.expires_at,s.started_at+interval '8 hours')
                      AND s.started_at > coalesce(g.primary_after,'-infinity'::timestamptz)
                      AND NOT EXISTS (SELECT FROM bri.credential_operations c WHERE c.principal_id = v.actor AND c.confirmed_at IS NULL)
                ) ELSE false END
    FROM bri.mfa_reset_visible_page(t,actor,sid,issuer,may_request,review_wide,item_id,cursor_at,before_id,page_size+1) p
    LEFT JOIN LATERAL (
        SELECT obs.outcome FROM bri.approval_observations obs
        WHERE obs.approval_id = (p.approval).approval_id AND obs.phase = 'RECORD'
          AND (p.approval).state = 'FAILED' AND (p.approval).sealed
        ORDER BY obs.occurred_at DESC, obs.correlation DESC LIMIT 1
    ) o ON true
    ORDER BY (p.approval).created_at DESC, (p.approval).approval_id DESC;
END $$;

REVOKE ALL ON FUNCTION bri.mfa_reset_read_authority(text,uuid,uuid,text),
    bri.mfa_reset_eligible_identity(text,uuid,text,boolean),
    bri.mfa_reset_visible_page(text,uuid,uuid,text,boolean,boolean,uuid,timestamptz,uuid,integer),
    bri.read_mfa_reset_queue(text,uuid,uuid,text,integer,uuid,uuid),
    bri.can_request_mfa_reset(text,uuid,uuid,text,uuid)
    FROM PUBLIC, bri_app;
