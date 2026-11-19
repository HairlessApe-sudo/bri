-- A11.6: read-only projection over existing immutable audit events.
-- Retire legacy raw runtime reads, preserving append and worker policies.
REVOKE SELECT ON bri.security_audit_events FROM PUBLIC, bri_app;
DROP POLICY security_audit_admin_read ON bri.security_audit_events;

-- The catalog/assignments are already protected by A11.4. Extend the
-- existing governance-serialized topology guard, not its trigger or ACL.
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
    SELECT max(r.permission COLLATE "C") INTO protected_permission
    FROM bri.auth_role_assignments a JOIN bri.role_permissions r USING (tenant_id,role_id)
    WHERE a.tenant_id IN (old_tenant,new_tenant) AND a.status = 'active'
      AND r.permission IN ('user:deactivate','account:history:read');
    IF protected_permission = 'user:deactivate' THEN
        RAISE EXCEPTION 'deactivation root topology is protected' USING ERRCODE = '42501';
    ELSIF protected_permission = 'account:history:read' THEN
        RAISE EXCEPTION 'account history root topology is protected' USING ERRCODE = '42501';
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
    RETURN NEW;
END $$;

-- One closed mapping controls the RLS policy, cursor lookup and page.
CREATE FUNCTION bri.account_history_action(event_type text) RETURNS text
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
    SELECT CASE event_type
        WHEN 'tenant.user.provisioning.requested' THEN 'provisioned'
        WHEN 'tenant.user.provisioning.active' THEN 'activated'
        WHEN 'tenant.user.lifecycle.edited' THEN 'display_name_changed'
        WHEN 'tenant.user.lifecycle.suspended' THEN 'suspended'
        WHEN 'tenant.user.lifecycle.reactivated' THEN 'reactivated'
        WHEN 'tenant.user.delegation.granted' THEN 'permission_granted'
        WHEN 'tenant.user.delegation.revoked' THEN 'permission_revoked'
        WHEN 'tenant.user.lifecycle.deactivated' THEN 'deactivated'
    END;
$$;
REVOKE ALL ON FUNCTION bri.account_history_action(text) FROM PUBLIC, bri_app;

CREATE POLICY account_history_owner_read ON bri.security_audit_events FOR SELECT TO bri_migrator
    USING (session_user = 'bri_app' AND tenant_id = nullif(current_setting('bri.tenant_id',true),'')
           AND bri.account_history_action(event_type) IS NOT NULL);
-- Do not invoke the private mapping helper in an index predicate: the
-- restricted audit writer must be able to append without executing it.
CREATE INDEX security_audit_account_history_idx ON bri.security_audit_events
    (tenant_id, subject_principal_id, occurred_at DESC, event_id DESC);

CREATE FUNCTION bri.read_account_history(t text, actor uuid, sid uuid, issuer text,
                                         target uuid, page_size integer, before_event uuid)
RETURNS TABLE(event_id uuid, occurred_at timestamptz, action text, outcome text,
              reason_code text, actor_id uuid, actor_display_name text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE cursor_at timestamptz;
BEGIN
    IF session_user <> 'bri_app' OR t IS NULL OR t IS DISTINCT FROM nullif(current_setting('bri.tenant_id',true),'')
        OR NOT EXISTS (
            SELECT FROM bri.auth_role_assignments a JOIN bri.role_permissions rp USING (tenant_id,role_id)
            JOIN bri.org_nodes n ON (n.tenant_id,n.node_id) = (a.tenant_id,a.scope_node_id)
            WHERE a.tenant_id = t AND a.principal_id = actor AND a.status = 'active'
              AND rp.permission = 'account:history:read' AND n.node_type = 'root' AND n.parent_node_id IS NULL
              AND NOT EXISTS (SELECT FROM bri.org_nodes x
                              WHERE x.tenant_id = t AND x.parent_node_id IS NULL AND x.node_id <> n.node_id)
        ) OR NOT EXISTS (
            SELECT FROM bri.auth_sessions s LEFT JOIN bri.session_guards g USING (principal_id)
            WHERE s.principal_id = actor AND s.session_id = sid
              AND s.auth_user_id::text = nullif(current_setting('bri.auth_user_id',true),'')
              AND s.started_at > coalesce(g.primary_after,'-infinity'::timestamptz)
        ) OR EXISTS (SELECT FROM bri.credential_operations c
                     WHERE c.principal_id = actor AND c.confirmed_at IS NULL) THEN
        RAISE EXCEPTION 'account history access denied' USING ERRCODE = '42501';
    END IF;

    -- Reuse the directory's session, permission and visibility checks. Never
    -- pass a NULL target (which would turn an exact lookup into a listing).
    PERFORM FROM bri.read_user_directory(t,actor,sid,issuer,coalesce(target,actor),NULL,NULL,1,0);
    IF NOT FOUND OR target IS NULL THEN RETURN; END IF;

    IF page_size IS NULL OR page_size NOT BETWEEN 1 AND 100 THEN
        RAISE EXCEPTION 'invalid account history page' USING ERRCODE = '22023';
    END IF;
    IF before_event IS NOT NULL THEN
        SELECT e.occurred_at INTO cursor_at FROM bri.security_audit_events e
        WHERE e.event_id = before_event AND e.tenant_id = t AND e.subject_principal_id = target
          AND bri.account_history_action(e.event_type) IS NOT NULL;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'invalid account history cursor' USING ERRCODE = '22023';
        END IF;
    END IF;

    RETURN QUERY
    SELECT e.event_id, e.occurred_at, bri.account_history_action(e.event_type), e.outcome,
           -- The existing validated lifecycle constraint bounds these codes.
           CASE WHEN e.event_type IN ('tenant.user.lifecycle.suspended','tenant.user.lifecycle.reactivated',
                                      'tenant.user.lifecycle.deactivated') THEN e.lifecycle_reason END,
           d.id, d.display_name
    FROM (
        SELECT a.event_id, a.occurred_at, a.event_type, a.outcome, a.lifecycle_reason, a.actor_principal_id
        FROM bri.security_audit_events a
        WHERE a.tenant_id = t AND a.subject_principal_id = target
          AND bri.account_history_action(a.event_type) IS NOT NULL
          AND (before_event IS NULL OR (a.occurred_at,a.event_id) < (cursor_at,before_event))
        ORDER BY a.occurred_at DESC, a.event_id DESC LIMIT page_size + 1
    ) e
    -- A system event with no actor must not invoke directory list mode.
    LEFT JOIN LATERAL bri.read_user_directory(t,actor,sid,issuer,coalesce(e.actor_principal_id,actor),NULL,NULL,1,0) d
      ON d.id = e.actor_principal_id
    ORDER BY e.occurred_at DESC, e.event_id DESC;
    IF NOT FOUND THEN
        RETURN QUERY SELECT NULL::uuid, NULL::timestamptz, NULL::text, NULL::text, NULL::text, NULL::uuid, NULL::text;
    END IF;
END $$;

REVOKE ALL ON FUNCTION bri.read_account_history(text,uuid,uuid,text,uuid,integer,uuid) FROM PUBLIC, bri_app;
GRANT EXECUTE ON FUNCTION bri.read_account_history(text,uuid,uuid,text,uuid,integer,uuid) TO bri_app;
