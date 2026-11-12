-- Enable checksums for immutable migration history.
ALTER TABLE bri.schema_migrations
    ADD COLUMN checksum text CHECK (checksum IS NULL OR checksum ~ '^[0-9a-f]{64}$');
