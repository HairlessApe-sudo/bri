-- Make parent references fail immediately rather than at transaction commit.
BEGIN;
ALTER TABLE bri.org_nodes
    ALTER CONSTRAINT org_nodes_tenant_id_parent_node_id_fkey NOT DEFERRABLE;
INSERT INTO bri.schema_migrations (version) VALUES ('0002_immediate_parent_fk');
COMMIT;
