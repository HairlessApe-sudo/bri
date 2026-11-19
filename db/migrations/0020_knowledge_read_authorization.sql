-- Access policy is independent of immutable content, provenance and validation.
-- No backfill: prior approval does not establish a current disclosure decision.
CREATE TABLE bri.knowledge_record_access (
    tenant_id text NOT NULL,
    source_id text NOT NULL,
    readable boolean NOT NULL DEFAULT false,
    PRIMARY KEY (tenant_id, source_id),
    FOREIGN KEY (tenant_id, source_id)
        REFERENCES bri.source_records (tenant_id, source_id)
);

CREATE TABLE bri.knowledge_version_access (
    tenant_id text NOT NULL,
    source_id text NOT NULL,
    source_version_id text NOT NULL,
    readable boolean NOT NULL DEFAULT false,
    PRIMARY KEY (tenant_id, source_id, source_version_id),
    FOREIGN KEY (tenant_id, source_id, source_version_id)
        REFERENCES bri.source_versions (tenant_id, source_id, source_version_id)
);

ALTER TABLE bri.knowledge_record_access ENABLE ROW LEVEL SECURITY;
ALTER TABLE bri.knowledge_record_access FORCE ROW LEVEL SECURITY;
ALTER TABLE bri.knowledge_version_access ENABLE ROW LEVEL SECURITY;
ALTER TABLE bri.knowledge_version_access FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_knowledge_record_read ON bri.knowledge_record_access
    FOR SELECT TO bri_app USING (tenant_id = nullif(current_setting('bri.tenant_id', true), ''));
CREATE POLICY tenant_knowledge_version_read ON bri.knowledge_version_access
    FOR SELECT TO bri_app USING (tenant_id = nullif(current_setting('bri.tenant_id', true), ''));
GRANT SELECT ON bri.knowledge_record_access, bri.knowledge_version_access TO bri_app;

-- Maintenance is database-only. No application role, API or hosted writer.
CREATE POLICY tenant_knowledge_record_maintenance ON bri.knowledge_record_access
    TO bri_migrator USING (tenant_id = nullif(current_setting('bri.tenant_id', true), ''))
    WITH CHECK (tenant_id = nullif(current_setting('bri.tenant_id', true), ''));
CREATE POLICY tenant_knowledge_version_maintenance ON bri.knowledge_version_access
    TO bri_migrator USING (tenant_id = nullif(current_setting('bri.tenant_id', true), ''))
    WITH CHECK (tenant_id = nullif(current_setting('bri.tenant_id', true), ''));
