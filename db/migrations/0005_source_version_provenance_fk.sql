-- Enforce that extracted provenance metadata identifies its exact source version.
-- The fields already exist on both tables; this additive key/FK avoids rewriting
-- or dropping existing provenance while preventing hash/location mismatches.
ALTER TABLE bri.source_versions
    ADD CONSTRAINT source_versions_provenance_unique
    UNIQUE (tenant_id, source_id, source_version_id, content_sha256, source_location);

ALTER TABLE bri.source_extractions
    ADD CONSTRAINT source_extractions_version_provenance_fk
    FOREIGN KEY (
        tenant_id,
        source_id,
        source_version_id,
        content_sha256,
        source_location
    )
    REFERENCES bri.source_versions (
        tenant_id,
        source_id,
        source_version_id,
        content_sha256,
        source_location
    );
