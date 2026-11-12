-- BRI development-only tenant foundation. Apply through the restricted bri_migrator role.
BEGIN;

CREATE TABLE bri.tenants (
    tenant_id text PRIMARY KEY,
    display_name text NOT NULL,
    sector text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE bri.org_nodes (
    tenant_id text NOT NULL,
    node_id text NOT NULL,
    node_type text NOT NULL,
    display_name text NOT NULL,
    parent_node_id text,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, node_id),
    FOREIGN KEY (tenant_id) REFERENCES bri.tenants (tenant_id),
    FOREIGN KEY (tenant_id, parent_node_id)
        REFERENCES bri.org_nodes (tenant_id, node_id)
        DEFERRABLE INITIALLY DEFERRED
);
CREATE INDEX org_nodes_parent_idx ON bri.org_nodes (tenant_id, parent_node_id);

CREATE TABLE bri.org_relationships (
    tenant_id text NOT NULL,
    relationship_id text NOT NULL,
    from_node_id text NOT NULL,
    to_node_id text NOT NULL,
    relationship_type text NOT NULL,
    grants_access boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, relationship_id),
    FOREIGN KEY (tenant_id) REFERENCES bri.tenants (tenant_id),
    FOREIGN KEY (tenant_id, from_node_id)
        REFERENCES bri.org_nodes (tenant_id, node_id),
    FOREIGN KEY (tenant_id, to_node_id)
        REFERENCES bri.org_nodes (tenant_id, node_id),
    CHECK (from_node_id <> to_node_id)
);
CREATE INDEX org_relationships_from_idx ON bri.org_relationships (tenant_id, from_node_id);
CREATE INDEX org_relationships_to_idx ON bri.org_relationships (tenant_id, to_node_id);

CREATE TABLE bri.app_roles (
    tenant_id text NOT NULL,
    role_id text NOT NULL,
    display_name text NOT NULL,
    PRIMARY KEY (tenant_id, role_id),
    FOREIGN KEY (tenant_id) REFERENCES bri.tenants (tenant_id)
);

CREATE TABLE bri.role_permissions (
    tenant_id text NOT NULL,
    role_id text NOT NULL,
    permission text NOT NULL,
    PRIMARY KEY (tenant_id, role_id, permission),
    FOREIGN KEY (tenant_id, role_id)
        REFERENCES bri.app_roles (tenant_id, role_id) ON DELETE CASCADE
);

CREATE TABLE bri.synthetic_principals (
    tenant_id text NOT NULL,
    principal_id text NOT NULL,
    display_name text NOT NULL,
    synthetic_only boolean NOT NULL DEFAULT true CHECK (synthetic_only),
    PRIMARY KEY (tenant_id, principal_id),
    FOREIGN KEY (tenant_id) REFERENCES bri.tenants (tenant_id)
);

CREATE TABLE bri.role_assignments (
    tenant_id text NOT NULL,
    principal_id text NOT NULL,
    role_id text NOT NULL,
    scope_node_id text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, principal_id, role_id, scope_node_id),
    FOREIGN KEY (tenant_id, principal_id)
        REFERENCES bri.synthetic_principals (tenant_id, principal_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, role_id)
        REFERENCES bri.app_roles (tenant_id, role_id),
    FOREIGN KEY (tenant_id, scope_node_id)
        REFERENCES bri.org_nodes (tenant_id, node_id)
);
CREATE INDEX role_assignments_scope_idx ON bri.role_assignments (tenant_id, scope_node_id);

CREATE TABLE bri.schema_migrations (
    version text PRIMARY KEY,
    applied_at timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON bri.schema_migrations FROM PUBLIC, bri_app;
GRANT SELECT, INSERT ON bri.schema_migrations TO bri_migrator;

DO $rls$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'tenants', 'org_nodes', 'org_relationships', 'app_roles',
        'role_permissions', 'synthetic_principals', 'role_assignments'
    ] LOOP
        EXECUTE format('ALTER TABLE bri.%I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE bri.%I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format(
            'CREATE POLICY tenant_context_isolation ON bri.%I TO bri_app USING (tenant_id = nullif(current_setting(%L, true), %L)) WITH CHECK (tenant_id = nullif(current_setting(%L, true), %L))',
            table_name, 'bri.tenant_id', '', 'bri.tenant_id', ''
        );
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON bri.%I TO bri_app', table_name);
    END LOOP;
END
$rls$;

GRANT USAGE ON SCHEMA bri TO bri_app;
REVOKE ALL ON SCHEMA bri FROM PUBLIC;

INSERT INTO bri.schema_migrations (version) VALUES ('0001_tenant_foundation');
COMMIT;
