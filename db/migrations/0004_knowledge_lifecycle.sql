-- Persistent synthetic sources and immutable knowledge validation records.
CREATE TABLE bri.source_records (
    tenant_id text NOT NULL,
    source_id text NOT NULL,
    scope_node_id text NOT NULL,
    title text NOT NULL,
    source_kind text NOT NULL CHECK (source_kind = 'synthetic_text'),
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, source_id),
    UNIQUE (tenant_id, source_id, scope_node_id),
    FOREIGN KEY (tenant_id) REFERENCES bri.tenants (tenant_id),
    FOREIGN KEY (tenant_id, scope_node_id)
        REFERENCES bri.org_nodes (tenant_id, node_id),
    FOREIGN KEY (tenant_id, created_by)
        REFERENCES bri.synthetic_principals (tenant_id, principal_id)
);

CREATE TABLE bri.source_versions (
    tenant_id text NOT NULL,
    source_id text NOT NULL,
    source_version_id text NOT NULL,
    version_label text NOT NULL,
    content_sha256 text NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    source_location text NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, source_id, source_version_id),
    UNIQUE (tenant_id, source_id, version_label),
    FOREIGN KEY (tenant_id, source_id)
        REFERENCES bri.source_records (tenant_id, source_id),
    FOREIGN KEY (tenant_id, created_by)
        REFERENCES bri.synthetic_principals (tenant_id, principal_id)
);

CREATE TABLE bri.source_extractions (
    tenant_id text NOT NULL,
    extraction_id text NOT NULL,
    source_id text NOT NULL,
    source_version_id text NOT NULL,
    scope_node_id text NOT NULL,
    content text NOT NULL,
    content_sha256 text NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    source_location text NOT NULL,
    extractor_name text NOT NULL,
    extractor_version text NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, extraction_id),
    UNIQUE (tenant_id, extraction_id, scope_node_id),
    FOREIGN KEY (tenant_id, source_id, source_version_id)
        REFERENCES bri.source_versions (tenant_id, source_id, source_version_id),
    FOREIGN KEY (tenant_id, source_id, scope_node_id)
        REFERENCES bri.source_records (tenant_id, source_id, scope_node_id),
    FOREIGN KEY (tenant_id, created_by)
        REFERENCES bri.synthetic_principals (tenant_id, principal_id)
);
CREATE INDEX source_extractions_scope_idx
    ON bri.source_extractions (tenant_id, scope_node_id, extraction_id);

CREATE TABLE bri.knowledge_proposals (
    tenant_id text NOT NULL,
    proposal_id text NOT NULL,
    extraction_id text NOT NULL,
    scope_node_id text NOT NULL,
    proposed_by text NOT NULL,
    proposed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, proposal_id),
    UNIQUE (tenant_id, proposal_id, extraction_id, scope_node_id),
    FOREIGN KEY (tenant_id, extraction_id, scope_node_id)
        REFERENCES bri.source_extractions (tenant_id, extraction_id, scope_node_id),
    FOREIGN KEY (tenant_id, proposed_by)
        REFERENCES bri.synthetic_principals (tenant_id, principal_id)
);
CREATE INDEX knowledge_proposals_scope_idx
    ON bri.knowledge_proposals (tenant_id, scope_node_id, proposed_at);

CREATE TABLE bri.validation_decisions (
    tenant_id text NOT NULL,
    decision_id text NOT NULL,
    proposal_id text NOT NULL,
    reviewer_id text NOT NULL,
    decision text NOT NULL CHECK (decision IN ('approved', 'rejected')),
    comment text,
    decided_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, decision_id),
    UNIQUE (tenant_id, proposal_id),
    UNIQUE (tenant_id, decision_id, proposal_id, decision),
    FOREIGN KEY (tenant_id, proposal_id)
        REFERENCES bri.knowledge_proposals (tenant_id, proposal_id),
    FOREIGN KEY (tenant_id, reviewer_id)
        REFERENCES bri.synthetic_principals (tenant_id, principal_id)
);

CREATE TABLE bri.validated_knowledge (
    tenant_id text NOT NULL,
    proposal_id text NOT NULL,
    decision_id text NOT NULL,
    decision text NOT NULL DEFAULT 'approved' CHECK (decision = 'approved'),
    PRIMARY KEY (tenant_id, proposal_id),
    FOREIGN KEY (tenant_id, proposal_id)
        REFERENCES bri.knowledge_proposals (tenant_id, proposal_id),
    FOREIGN KEY (tenant_id, decision_id, proposal_id, decision)
        REFERENCES bri.validation_decisions (tenant_id, decision_id, proposal_id, decision)
);
CREATE INDEX validated_knowledge_tenant_idx
    ON bri.validated_knowledge (tenant_id, proposal_id);

DO $rls$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'source_records', 'source_versions', 'source_extractions',
        'knowledge_proposals', 'validation_decisions', 'validated_knowledge'
    ] LOOP
        EXECUTE format('ALTER TABLE bri.%I ENABLE ROW LEVEL SECURITY', table_name);
        EXECUTE format('ALTER TABLE bri.%I FORCE ROW LEVEL SECURITY', table_name);
        EXECUTE format(
            'CREATE POLICY tenant_context_isolation ON bri.%I TO bri_app USING (tenant_id = nullif(current_setting(%L, true), %L)) WITH CHECK (tenant_id = nullif(current_setting(%L, true), %L))',
            table_name, 'bri.tenant_id', '', 'bri.tenant_id', ''
        );
        EXECUTE format('GRANT SELECT, INSERT ON bri.%I TO bri_app', table_name);
    END LOOP;
END
$rls$;
