-- Durable prompt and Privacy Shield histories. The migration runner owns the transaction and checksum ledger.
CREATE TABLE bri.prompt_versions (
    layer text NOT NULL CHECK (layer IN ('platform', 'client')),
    tenant_id text,
    version integer NOT NULL CHECK (version > 0),
    version_id text NOT NULL CHECK (length(version_id) BETWEEN 1 AND 128),
    author_id text NOT NULL CHECK (length(author_id) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL,
    change_description text NOT NULL CHECK (length(change_description) BETWEEN 1 AND 512),
    previous_version_ref text,
    restored_from_version_id text,
    content_hash text NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
    content text NOT NULL CHECK (length(content) BETWEEN 1 AND 32000),
    PRIMARY KEY (version_id),
    UNIQUE (layer, tenant_id, version),
    UNIQUE (version_id, layer, tenant_id, version),
    FOREIGN KEY (tenant_id) REFERENCES bri.tenants (tenant_id),
    CHECK ((layer = 'platform' AND tenant_id IS NULL) OR (layer = 'client' AND tenant_id IS NOT NULL)),
    CHECK ((version = 1 AND previous_version_ref IS NULL) OR (version > 1 AND previous_version_ref IS NOT NULL))
);
CREATE UNIQUE INDEX prompt_version_platform_sequence_uq ON bri.prompt_versions (version) WHERE layer='platform';
CREATE UNIQUE INDEX prompt_version_client_sequence_uq ON bri.prompt_versions (tenant_id, version) WHERE layer='client';
CREATE TABLE bri.prompt_lifecycle_events (
    event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    layer text NOT NULL,
    tenant_id text,
    version integer NOT NULL,
    version_id text NOT NULL REFERENCES bri.prompt_versions (version_id),
    action text NOT NULL CHECK (action IN ('created', 'approved', 'activated', 'deactivated')),
    actor_id text NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 128),
    occurred_at timestamptz NOT NULL,
    status text NOT NULL CHECK (status IN ('draft', 'approved', 'active', 'inactive')),
    content_hash text NOT NULL CHECK (content_hash ~ '^[0-9a-f]{64}$'),
    FOREIGN KEY (version_id, layer, tenant_id, version) REFERENCES bri.prompt_versions (version_id, layer, tenant_id, version),
    FOREIGN KEY (tenant_id) REFERENCES bri.tenants (tenant_id)
);
CREATE TABLE bri.prompt_active_versions (
    active_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    layer text NOT NULL,
    tenant_id text,
    version integer NOT NULL,
    version_id text NOT NULL REFERENCES bri.prompt_versions(version_id),
    changed_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (layer, tenant_id, version) REFERENCES bri.prompt_versions (layer, tenant_id, version),
    FOREIGN KEY (tenant_id) REFERENCES bri.tenants (tenant_id),
    CHECK ((layer = 'platform' AND tenant_id IS NULL) OR (layer = 'client' AND tenant_id IS NOT NULL))
);
CREATE UNIQUE INDEX prompt_active_platform_uq ON bri.prompt_active_versions (layer) WHERE layer='platform';
CREATE UNIQUE INDEX prompt_active_client_uq ON bri.prompt_active_versions (layer, tenant_id) WHERE layer='client';
CREATE TABLE bri.signature_package_versions (
    package_id text NOT NULL CHECK (package_id ~ '^[a-z][a-z0-9-]{0,63}$'),
    version text NOT NULL CHECK (version ~ '^[A-Za-z0-9._-]{1,40}$'),
    jurisdiction text CHECK (jurisdiction IS NULL OR jurisdiction ~ '^[A-Z]{2}$'),
    available boolean NOT NULL DEFAULT true,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object'),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (package_id, version),
    CHECK ((package_id = 'global' AND jurisdiction IS NULL) OR (package_id <> 'global' AND jurisdiction IS NOT NULL))
);
CREATE TABLE bri.signature_package_activation (
    package_id text PRIMARY KEY,
    version text NOT NULL,
    activated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (package_id, version) REFERENCES bri.signature_package_versions (package_id, version)
);
INSERT INTO bri.signature_package_versions(package_id,version,jurisdiction,metadata) VALUES
    ('global','1',NULL,'{"engine_managed":true}'::jsonb),
    ('netherlands','1','NL','{"engine_managed":true}'::jsonb),
    ('australia','1','AU','{"engine_managed":true}'::jsonb);
INSERT INTO bri.signature_package_activation(package_id,version) VALUES
    ('global','1'),('netherlands','1'),('australia','1');
CREATE TABLE bri.tenant_signature_revisions (
    tenant_id text NOT NULL,
    version integer NOT NULL CHECK (version > 0),
    signatures jsonb NOT NULL CHECK (jsonb_typeof(signatures) = 'array'),
    restored_from_version integer,
    created_by text NOT NULL CHECK (length(created_by) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, version),
    FOREIGN KEY (tenant_id) REFERENCES bri.tenants (tenant_id),
    FOREIGN KEY (tenant_id, restored_from_version) REFERENCES bri.tenant_signature_revisions (tenant_id, version)
);
CREATE TABLE bri.shield_config_revisions (
    tenant_id text NOT NULL,
    version integer NOT NULL CHECK (version > 0),
    primary_jurisdiction text NOT NULL CHECK (primary_jurisdiction ~ '^[A-Z]{2}$'),
    additional_regions text[] NOT NULL DEFAULT '{}',
    restored_from_version integer,
    created_by text NOT NULL CHECK (length(created_by) BETWEEN 1 AND 128),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, version),
    FOREIGN KEY (tenant_id) REFERENCES bri.tenants (tenant_id),
    FOREIGN KEY (tenant_id, restored_from_version) REFERENCES bri.shield_config_revisions (tenant_id, version),
    CHECK (NOT primary_jurisdiction = ANY(additional_regions))
);
CREATE TABLE bri.configuration_audit_events (
    event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id text,
    actor_id text NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 128),
    action text NOT NULL CHECK (length(action) BETWEEN 1 AND 80),
    resource_type text NOT NULL CHECK (resource_type IN ('prompt', 'signature_package', 'tenant_signatures', 'shield_configuration')),
    resource_version text NOT NULL CHECK (length(resource_version) BETWEEN 1 AND 128),
    content_hash text CHECK (content_hash IS NULL OR content_hash ~ '^[0-9a-f]{64}$'),
    occurred_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id) REFERENCES bri.tenants (tenant_id)
);

DO $rls$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['prompt_versions','prompt_lifecycle_events','prompt_active_versions','signature_package_versions','signature_package_activation','tenant_signature_revisions','shield_config_revisions','configuration_audit_events'] LOOP
    EXECUTE format('ALTER TABLE bri.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE bri.%I FORCE ROW LEVEL SECURITY', t);
  END LOOP;
END
$rls$;

-- Tenant histories require the transaction-local tenant context. Platform rows are
-- visible only to the currently authenticated, active BRS platform administrator.
CREATE POLICY prompt_versions_tenant_access ON bri.prompt_versions TO bri_app
  USING (tenant_id = nullif(current_setting('bri.tenant_id', true), '') OR
    (tenant_id IS NULL AND EXISTS (SELECT 1 FROM bri.platform_superadmins s JOIN bri.auth_identity_links i USING (principal_id) WHERE s.status='active' AND i.auth_user_id=nullif(current_setting('bri.auth_user_id', true), '')::uuid AND i.status='active')))
  WITH CHECK ((tenant_id IS NOT NULL AND tenant_id = nullif(current_setting('bri.tenant_id', true), '')) OR
    (tenant_id IS NULL AND EXISTS (SELECT 1 FROM bri.platform_superadmins s JOIN bri.auth_identity_links i USING (principal_id) WHERE s.status='active' AND i.auth_user_id=nullif(current_setting('bri.auth_user_id', true), '')::uuid AND i.status='active')));
CREATE POLICY prompt_platform_active_read ON bri.prompt_versions FOR SELECT TO bri_app
  USING (layer='platform' AND EXISTS (
    SELECT 1 FROM bri.prompt_active_versions a
    WHERE a.layer='platform' AND a.tenant_id IS NULL AND a.version=bri.prompt_versions.version
      AND EXISTS (
        SELECT 1 FROM bri.auth_role_assignments r
        JOIN bri.role_permissions p ON p.tenant_id=r.tenant_id AND p.role_id=r.role_id
        WHERE r.tenant_id=nullif(current_setting('bri.tenant_id', true), '')
          AND r.status='active' AND p.permission='prompt:platform:read'
      )
  ));
CREATE POLICY prompt_active_platform_tenant_read ON bri.prompt_active_versions FOR SELECT TO bri_app
  USING (layer='platform' AND tenant_id IS NULL AND EXISTS (
    SELECT 1 FROM bri.auth_role_assignments r
    JOIN bri.role_permissions p ON p.tenant_id=r.tenant_id AND p.role_id=r.role_id
    WHERE r.tenant_id=nullif(current_setting('bri.tenant_id', true), '')
      AND r.status='active' AND p.permission='prompt:platform:read'
  ));
CREATE POLICY prompt_events_tenant_access ON bri.prompt_lifecycle_events TO bri_app
  USING (tenant_id = nullif(current_setting('bri.tenant_id', true), '') OR
    (tenant_id IS NULL AND EXISTS (SELECT 1 FROM bri.platform_superadmins s JOIN bri.auth_identity_links i USING (principal_id) WHERE s.status='active' AND i.auth_user_id=nullif(current_setting('bri.auth_user_id', true), '')::uuid AND i.status='active')))
  WITH CHECK ((tenant_id IS NOT NULL AND tenant_id = nullif(current_setting('bri.tenant_id', true), '')) OR
    (tenant_id IS NULL AND EXISTS (SELECT 1 FROM bri.platform_superadmins s JOIN bri.auth_identity_links i USING (principal_id) WHERE s.status='active' AND i.auth_user_id=nullif(current_setting('bri.auth_user_id', true), '')::uuid AND i.status='active')));
CREATE POLICY prompt_active_tenant_access ON bri.prompt_active_versions TO bri_app
  USING (tenant_id = nullif(current_setting('bri.tenant_id', true), '') OR
    (tenant_id IS NULL AND EXISTS (SELECT 1 FROM bri.platform_superadmins s JOIN bri.auth_identity_links i USING (principal_id) WHERE s.status='active' AND i.auth_user_id=nullif(current_setting('bri.auth_user_id', true), '')::uuid AND i.status='active')))
  WITH CHECK ((tenant_id IS NOT NULL AND tenant_id = nullif(current_setting('bri.tenant_id', true), '')) OR
    (tenant_id IS NULL AND EXISTS (SELECT 1 FROM bri.platform_superadmins s JOIN bri.auth_identity_links i USING (principal_id) WHERE s.status='active' AND i.auth_user_id=nullif(current_setting('bri.auth_user_id', true), '')::uuid AND i.status='active')));
CREATE POLICY tenant_signature_revision_access ON bri.tenant_signature_revisions TO bri_app
  USING (tenant_id = nullif(current_setting('bri.tenant_id', true), ''))
  WITH CHECK (tenant_id = nullif(current_setting('bri.tenant_id', true), ''));
CREATE POLICY shield_config_revision_access ON bri.shield_config_revisions TO bri_app
  USING (tenant_id = nullif(current_setting('bri.tenant_id', true), ''))
  WITH CHECK (tenant_id = nullif(current_setting('bri.tenant_id', true), ''));
CREATE POLICY configuration_audit_tenant_access ON bri.configuration_audit_events TO bri_app
  USING (tenant_id IS NOT NULL AND tenant_id = nullif(current_setting('bri.tenant_id', true), '') OR
    (tenant_id IS NULL AND EXISTS (SELECT 1 FROM bri.platform_superadmins s JOIN bri.auth_identity_links i USING (principal_id) WHERE s.status='active' AND i.auth_user_id=nullif(current_setting('bri.auth_user_id', true), '')::uuid AND i.status='active')))
  WITH CHECK ((tenant_id IS NOT NULL AND tenant_id = nullif(current_setting('bri.tenant_id', true), '')) OR
    (tenant_id IS NULL AND EXISTS (SELECT 1 FROM bri.platform_superadmins s JOIN bri.auth_identity_links i USING (principal_id) WHERE s.status='active' AND i.auth_user_id=nullif(current_setting('bri.auth_user_id', true), '')::uuid AND i.status='active')));
CREATE POLICY package_platform_access ON bri.signature_package_versions TO bri_app
  USING (EXISTS (SELECT 1 FROM bri.platform_superadmins s JOIN bri.auth_identity_links i USING (principal_id) WHERE s.status='active' AND i.auth_user_id=nullif(current_setting('bri.auth_user_id', true), '')::uuid AND i.status='active'))
  WITH CHECK (EXISTS (SELECT 1 FROM bri.platform_superadmins s JOIN bri.auth_identity_links i USING (principal_id) WHERE s.status='active' AND i.auth_user_id=nullif(current_setting('bri.auth_user_id', true), '')::uuid AND i.status='active'));
CREATE POLICY package_activation_platform_access ON bri.signature_package_activation TO bri_app
  USING (EXISTS (SELECT 1 FROM bri.platform_superadmins s JOIN bri.auth_identity_links i USING (principal_id) WHERE s.status='active' AND i.auth_user_id=nullif(current_setting('bri.auth_user_id', true), '')::uuid AND i.status='active'))
  WITH CHECK (EXISTS (SELECT 1 FROM bri.platform_superadmins s JOIN bri.auth_identity_links i USING (principal_id) WHERE s.status='active' AND i.auth_user_id=nullif(current_setting('bri.auth_user_id', true), '')::uuid AND i.status='active'));
CREATE POLICY package_active_tenant_read ON bri.signature_package_versions FOR SELECT TO bri_app
  USING (EXISTS (SELECT 1 FROM bri.signature_package_activation a WHERE a.package_id=bri.signature_package_versions.package_id AND a.version=bri.signature_package_versions.version)
    AND EXISTS (SELECT 1 FROM bri.auth_role_assignments r JOIN bri.role_permissions p ON p.tenant_id=r.tenant_id AND p.role_id=r.role_id WHERE r.tenant_id=nullif(current_setting('bri.tenant_id', true), '') AND r.status='active' AND p.permission IN ('privacy:configuration:read','privacy:configuration:manage')));
CREATE POLICY package_active_tenant_read ON bri.signature_package_activation FOR SELECT TO bri_app
  USING (EXISTS (SELECT 1 FROM bri.auth_role_assignments r JOIN bri.role_permissions p ON p.tenant_id=r.tenant_id AND p.role_id=r.role_id WHERE r.tenant_id=nullif(current_setting('bri.tenant_id', true), '') AND r.status='active' AND p.permission IN ('privacy:configuration:read','privacy:configuration:manage')));

REVOKE ALL ON bri.prompt_versions,bri.prompt_lifecycle_events,bri.prompt_active_versions,bri.signature_package_versions,bri.signature_package_activation,bri.tenant_signature_revisions,bri.shield_config_revisions,bri.configuration_audit_events FROM PUBLIC,bri_app;
GRANT SELECT, INSERT ON bri.prompt_versions,bri.prompt_lifecycle_events,bri.tenant_signature_revisions,bri.shield_config_revisions,bri.configuration_audit_events TO bri_app;
GRANT SELECT, INSERT, UPDATE ON bri.prompt_active_versions TO bri_app;
GRANT SELECT, INSERT, UPDATE ON bri.signature_package_activation TO bri_app;
GRANT SELECT, INSERT ON bri.signature_package_versions TO bri_app;

