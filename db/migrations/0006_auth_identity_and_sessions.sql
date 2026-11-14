-- Provider-independent BRI identity mapping and fail-closed session governance.
-- Apply through scripts/db/migrate.py after explicit target approval; the corrected revision was validated only against disposable local PostgreSQL, not shared Supabase.

CREATE TABLE bri.auth_principals (
    principal_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'active', 'suspended', 'deactivated')),
    created_at timestamptz NOT NULL DEFAULT now(),
    status_changed_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE bri.auth_identity_links (
    auth_user_id uuid PRIMARY KEY,
    principal_id uuid NOT NULL,
    auth_issuer text NOT NULL CHECK (length(auth_issuer) BETWEEN 1 AND 512),
    auth_subject text NOT NULL CHECK (length(auth_subject) BETWEEN 1 AND 255),
    provider_type text NOT NULL CHECK (provider_type IN ('native', 'enterprise_sso')),
    provider_issuer text NOT NULL CHECK (length(provider_issuer) BETWEEN 1 AND 512),
    provider_subject text NOT NULL CHECK (length(provider_subject) BETWEEN 1 AND 255),
    provider_connection_id text,
    status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (auth_issuer, auth_subject),
    UNIQUE (provider_issuer, provider_subject),
    UNIQUE (auth_user_id, principal_id),
    FOREIGN KEY (principal_id) REFERENCES bri.auth_principals (principal_id),
    CHECK (
        (provider_type = 'native'
            AND provider_connection_id IS NULL
            AND provider_issuer = auth_issuer
            AND provider_subject = auth_subject)
        OR (provider_type = 'enterprise_sso' AND provider_connection_id IS NOT NULL)
    )
);

CREATE TABLE bri.auth_tenant_memberships (
    tenant_id text NOT NULL,
    principal_id uuid NOT NULL,
    membership_type text NOT NULL DEFAULT 'user'
        CHECK (membership_type IN ('user', 'superuser', 'admin', 'platform_superadmin')),
    status text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'active', 'suspended', 'deactivated')),
    emergency_admin boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    status_changed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, principal_id),
    FOREIGN KEY (tenant_id) REFERENCES bri.tenants (tenant_id),
    FOREIGN KEY (principal_id) REFERENCES bri.auth_principals (principal_id),
    CHECK (NOT emergency_admin OR membership_type = 'admin')
);
CREATE UNIQUE INDEX auth_one_client_org_per_principal
    ON bri.auth_tenant_memberships (principal_id)
    WHERE membership_type IN ('user', 'superuser', 'admin');

CREATE TABLE bri.auth_role_assignments (
    tenant_id text NOT NULL,
    principal_id uuid NOT NULL,
    role_id text NOT NULL,
    scope_node_id text NOT NULL,
    status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'revoked')),
    assigned_by_principal_id uuid,
    assigned_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, principal_id, role_id, scope_node_id),
    FOREIGN KEY (tenant_id, principal_id)
        REFERENCES bri.auth_tenant_memberships (tenant_id, principal_id),
    FOREIGN KEY (tenant_id, role_id)
        REFERENCES bri.app_roles (tenant_id, role_id),
    FOREIGN KEY (tenant_id, scope_node_id)
        REFERENCES bri.org_nodes (tenant_id, node_id),
    FOREIGN KEY (assigned_by_principal_id)
        REFERENCES bri.auth_principals (principal_id)
);

CREATE TABLE bri.platform_superadmins (
    principal_id uuid PRIMARY KEY,
    status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'revoked')),
    created_by_principal_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (principal_id) REFERENCES bri.auth_principals (principal_id),
    FOREIGN KEY (created_by_principal_id) REFERENCES bri.auth_principals (principal_id)
);

CREATE OR REPLACE FUNCTION bri.require_platform_superadmin_membership()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    IF NEW.membership_type = 'platform_superadmin'
       AND NOT EXISTS (
           SELECT 1 FROM bri.platform_superadmins s
           WHERE s.principal_id = NEW.principal_id AND s.status = 'active'
       ) THEN
        RAISE EXCEPTION 'platform superadmin membership requires an active platform grant';
    END IF;
    RETURN NEW;
END;
$function$;
CREATE TRIGGER platform_superadmin_membership_requires_grant
    BEFORE INSERT OR UPDATE OF membership_type, principal_id
    ON bri.auth_tenant_memberships
    FOR EACH ROW EXECUTE FUNCTION bri.require_platform_superadmin_membership();
REVOKE ALL ON FUNCTION bri.require_platform_superadmin_membership() FROM PUBLIC;

CREATE TABLE bri.tenant_admin_policies (
    tenant_id text PRIMARY KEY,
    min_emergency_admins integer NOT NULL DEFAULT 2 CHECK (min_emergency_admins >= 2),
    max_client_admins integer CHECK (max_client_admins IS NULL OR max_client_admins >= min_emergency_admins),
    configured_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id) REFERENCES bri.tenants (tenant_id)
);

CREATE TABLE bri.auth_sessions (
    auth_user_id uuid NOT NULL,
    principal_id uuid NOT NULL,
    session_id uuid NOT NULL,
    started_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL DEFAULT (now() + interval '8 hours'),
    revoked_at timestamptz,
    PRIMARY KEY (auth_user_id, session_id),
    FOREIGN KEY (auth_user_id, principal_id)
        REFERENCES bri.auth_identity_links (auth_user_id, principal_id),
    CHECK (expires_at > started_at),
    CHECK (revoked_at IS NULL OR revoked_at >= started_at)
);

CREATE TABLE bri.security_audit_events (
    event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id text,
    actor_principal_id uuid NOT NULL,
    subject_principal_id uuid,
    event_type text NOT NULL CHECK (event_type IN (
        'auth.session.started',
        'auth.session.revoked',
        'auth.password.reset_requested',
        'auth.mfa.factor_enrolled',
        'auth.mfa.factor_removed',
        'auth.mfa.recovery_initiated',
        'platform.tenant.created',
        'platform.client_admin.created',
        'platform.client_admin.suspended',
        'platform.client_admin.password_reset',
        'platform.client_admin.mfa_recovery',
        'platform.client_admin.role_assigned',
        'platform.client_admin.role_revoked',
        'tenant.user.created',
        'tenant.user.suspended',
        'tenant.user.password_reset',
        'tenant.user.role_assigned',
        'tenant.user.role_revoked'
    )),
    outcome text NOT NULL CHECK (outcome IN ('success', 'denied', 'failure')),
    request_id uuid,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id) REFERENCES bri.tenants (tenant_id),
    FOREIGN KEY (actor_principal_id) REFERENCES bri.auth_principals (principal_id),
    FOREIGN KEY (subject_principal_id) REFERENCES bri.auth_principals (principal_id)
);
CREATE INDEX security_audit_tenant_time_idx
    ON bri.security_audit_events (tenant_id, occurred_at DESC);
CREATE INDEX security_audit_actor_time_idx
    ON bri.security_audit_events (actor_principal_id, occurred_at DESC);

CREATE OR REPLACE FUNCTION bri.stamp_auth_session_revocation()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
    IF OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NULL THEN
        RAISE EXCEPTION 'a BRI session revocation cannot be undone';
    END IF;
    IF OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL THEN
        NEW.revoked_at := clock_timestamp();
    END IF;
    RETURN NEW;
END;
$function$;
CREATE TRIGGER auth_session_revocation_is_one_way
    BEFORE UPDATE OF revoked_at ON bri.auth_sessions
    FOR EACH ROW EXECUTE FUNCTION bri.stamp_auth_session_revocation();
REVOKE ALL ON FUNCTION bri.stamp_auth_session_revocation() FROM PUBLIC;

CREATE POLICY migration_seed_tenant_admin_policies ON bri.tenants
    FOR SELECT TO bri_migrator USING (true);

INSERT INTO bri.tenant_admin_policies (tenant_id)
SELECT tenant_id FROM bri.tenants
ON CONFLICT (tenant_id) DO NOTHING;

DROP POLICY migration_seed_tenant_admin_policies ON bri.tenants;

DO $rls$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'auth_principals',
        'auth_identity_links',
        'auth_tenant_memberships',
        'auth_role_assignments',
        'platform_superadmins',
        'tenant_admin_policies',
        'auth_sessions',
        'security_audit_events'
    ] LOOP
        EXECUTE format('ALTER TABLE bri.%I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE bri.%I FORCE ROW LEVEL SECURITY', table_name);
    END LOOP;
END
$rls$;

CREATE POLICY auth_identity_self_read ON bri.auth_identity_links
    FOR SELECT TO bri_app
    USING (
        auth_user_id = nullif(current_setting('bri.auth_user_id', true), '')::uuid
        AND status = 'active'
    );

CREATE POLICY auth_principal_self_read ON bri.auth_principals
    FOR SELECT TO bri_app
    USING (
        principal_id IN (
            SELECT principal_id FROM bri.auth_identity_links
            WHERE auth_user_id = nullif(current_setting('bri.auth_user_id', true), '')::uuid
              AND status = 'active'
        )
    );

CREATE POLICY auth_membership_self_read ON bri.auth_tenant_memberships
    FOR SELECT TO bri_app
    USING (
        status = 'active'
        AND principal_id IN (
            SELECT principal_id FROM bri.auth_identity_links
            WHERE auth_user_id = nullif(current_setting('bri.auth_user_id', true), '')::uuid
              AND status = 'active'
        )
        AND (
            membership_type <> 'platform_superadmin'
            OR EXISTS (
                SELECT 1 FROM bri.platform_superadmins s
                WHERE s.principal_id = bri.auth_tenant_memberships.principal_id
                  AND s.status = 'active'
            )
        )
    );

CREATE POLICY auth_role_assignment_self_read ON bri.auth_role_assignments
    FOR SELECT TO bri_app
    USING (
        status = 'active'
        AND tenant_id = nullif(current_setting('bri.tenant_id', true), '')
        AND EXISTS (
            SELECT 1 FROM bri.auth_tenant_memberships m
            WHERE m.tenant_id = bri.auth_role_assignments.tenant_id
              AND m.principal_id = bri.auth_role_assignments.principal_id
              AND m.status = 'active'
        )
        AND principal_id IN (
            SELECT principal_id FROM bri.auth_identity_links
            WHERE auth_user_id = nullif(current_setting('bri.auth_user_id', true), '')::uuid
              AND status = 'active'
        )
    );

CREATE POLICY platform_superadmin_self_read ON bri.platform_superadmins
    FOR SELECT TO bri_app
    USING (
        status = 'active'
        AND principal_id IN (
            SELECT principal_id FROM bri.auth_identity_links
            WHERE auth_user_id = nullif(current_setting('bri.auth_user_id', true), '')::uuid
              AND status = 'active'
        )
    );

CREATE POLICY tenant_admin_policy_member_read ON bri.tenant_admin_policies
    FOR SELECT TO bri_app
    USING (
        tenant_id = nullif(current_setting('bri.tenant_id', true), '')
        AND EXISTS (
            SELECT 1 FROM bri.auth_tenant_memberships m
            WHERE m.tenant_id = bri.tenant_admin_policies.tenant_id
              AND m.status = 'active'
              AND m.principal_id IN (
                  SELECT principal_id FROM bri.auth_identity_links
                  WHERE auth_user_id = nullif(current_setting('bri.auth_user_id', true), '')::uuid
                    AND status = 'active'
              )
        )
    );

CREATE POLICY auth_session_self_access ON bri.auth_sessions
    FOR ALL TO bri_app
    USING (auth_user_id = nullif(current_setting('bri.auth_user_id', true), '')::uuid)
    WITH CHECK (
        auth_user_id = nullif(current_setting('bri.auth_user_id', true), '')::uuid
        AND EXISTS (
            SELECT 1 FROM bri.auth_identity_links i
            JOIN bri.auth_principals p ON p.principal_id = i.principal_id
            WHERE i.auth_user_id = bri.auth_sessions.auth_user_id
              AND i.principal_id = bri.auth_sessions.principal_id
              AND i.status = 'active'
              AND p.status = 'active'
        )
    );

CREATE POLICY security_audit_self_insert ON bri.security_audit_events
    FOR INSERT TO bri_app
    WITH CHECK (
        actor_principal_id IN (
            SELECT principal_id FROM bri.auth_identity_links
            WHERE auth_user_id = nullif(current_setting('bri.auth_user_id', true), '')::uuid
              AND status = 'active'
        )
        AND (
            (event_type LIKE 'platform.%' AND EXISTS (
                SELECT 1 FROM bri.platform_superadmins s
                WHERE s.principal_id = actor_principal_id AND s.status = 'active'
            ))
            OR (event_type LIKE 'tenant.%'
                AND tenant_id = nullif(current_setting('bri.tenant_id', true), '')
                AND EXISTS (
                    SELECT 1
                    FROM bri.auth_role_assignments a
                    JOIN bri.role_permissions rp
                      ON rp.tenant_id = a.tenant_id AND rp.role_id = a.role_id
                    JOIN bri.auth_tenant_memberships m
                      ON m.tenant_id = a.tenant_id AND m.principal_id = a.principal_id
                    WHERE a.tenant_id = bri.security_audit_events.tenant_id
                      AND a.principal_id = bri.security_audit_events.actor_principal_id
                      AND a.status = 'active'
                      AND m.status = 'active'
                      AND rp.permission = 'security:audit:write'
                ))
            OR (event_type LIKE 'auth.%'
                AND (tenant_id IS NULL OR tenant_id = nullif(current_setting('bri.tenant_id', true), '')))
        )
    );

CREATE POLICY security_audit_admin_read ON bri.security_audit_events
    FOR SELECT TO bri_app
    USING (
        ((event_type LIKE 'platform.%' OR event_type LIKE 'auth.%') AND EXISTS (
            SELECT 1 FROM bri.platform_superadmins s
            WHERE s.status = 'active'
              AND s.principal_id IN (
                  SELECT principal_id FROM bri.auth_identity_links
                  WHERE auth_user_id = nullif(current_setting('bri.auth_user_id', true), '')::uuid
                    AND status = 'active'
              )
        ))
        OR (tenant_id IS NOT NULL AND EXISTS (
            SELECT 1 FROM bri.platform_superadmins s
            WHERE s.status = 'active'
              AND s.principal_id IN (
                  SELECT principal_id FROM bri.auth_identity_links
                  WHERE auth_user_id = nullif(current_setting('bri.auth_user_id', true), '')::uuid
                    AND status = 'active'
              )
        ))
        OR (tenant_id = nullif(current_setting('bri.tenant_id', true), '') AND EXISTS (
            SELECT 1
            FROM bri.auth_role_assignments a
            JOIN bri.role_permissions rp
              ON rp.tenant_id = a.tenant_id AND rp.role_id = a.role_id
            JOIN bri.auth_tenant_memberships m
              ON m.tenant_id = a.tenant_id AND m.principal_id = a.principal_id
            WHERE a.tenant_id = bri.security_audit_events.tenant_id
              AND a.principal_id IN (
                  SELECT principal_id FROM bri.auth_identity_links
                  WHERE auth_user_id = nullif(current_setting('bri.auth_user_id', true), '')::uuid
                    AND status = 'active'
              )
              AND a.status = 'active'
              AND m.status = 'active'
              AND rp.permission = 'security:audit:read'
        ))
    );

REVOKE ALL ON bri.auth_principals, bri.auth_identity_links,
    bri.auth_tenant_memberships, bri.auth_role_assignments,
    bri.platform_superadmins, bri.tenant_admin_policies,
    bri.auth_sessions, bri.security_audit_events FROM PUBLIC, bri_app;

GRANT SELECT ON bri.auth_principals TO bri_app;
GRANT SELECT ON bri.auth_identity_links TO bri_app;
GRANT SELECT ON bri.auth_tenant_memberships TO bri_app;
GRANT SELECT ON bri.auth_role_assignments TO bri_app;
GRANT SELECT ON bri.platform_superadmins TO bri_app;
GRANT SELECT ON bri.tenant_admin_policies TO bri_app;
GRANT SELECT ON bri.auth_sessions TO bri_app;
GRANT INSERT (auth_user_id, principal_id, session_id) ON bri.auth_sessions TO bri_app;
GRANT UPDATE (revoked_at) ON bri.auth_sessions TO bri_app;
GRANT SELECT ON bri.security_audit_events TO bri_app;
GRANT INSERT (
    tenant_id,
    actor_principal_id,
    subject_principal_id,
    event_type,
    outcome,
    request_id
) ON bri.security_audit_events TO bri_app;
