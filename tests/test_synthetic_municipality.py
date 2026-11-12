import json
import unittest
from pathlib import Path


FIXTURE = Path(__file__).parent / "fixtures" / "synthetic_municipalities.json"


class SyntheticMunicipalFixtureTests(unittest.TestCase):
    def test_fixture_has_two_isolated_configurable_municipalities(self):
        data = json.loads(FIXTURE.read_text(encoding="utf-8"))

        self.assertTrue(data["synthetic_only"])
        self.assertEqual(len(data["tenants"]), 2)
        tenant_ids = {tenant["tenant_id"] for tenant in data["tenants"]}
        self.assertEqual(len(tenant_ids), 2)

        for tenant in data["tenants"]:
            node_ids = {node["node_id"] for node in tenant["org_nodes"]}
            self.assertTrue(any(node["node_type"] == "municipality" for node in tenant["org_nodes"]))
            self.assertTrue(any(node["node_type"] == "department" for node in tenant["org_nodes"]))
            self.assertTrue(any(node["node_type"] == "team" for node in tenant["org_nodes"]))
            self.assertTrue(tenant["users"])
            self.assertTrue(tenant["roles"])
            for node in tenant["org_nodes"]:
                if node.get("parent_id"):
                    self.assertIn(node["parent_id"], node_ids)
            for user in tenant["users"]:
                for assignment in user["role_assignments"]:
                    self.assertIn(assignment["role_id"], {role["role_id"] for role in tenant["roles"]})
                    self.assertIn(assignment["scope_node_id"], node_ids)

    def test_fixture_includes_separate_scoped_proposer_and_reviewer_identities(self):
        data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        from bri.api.catalog import load_catalog
        from bri.access.policy import Resource, is_authorized

        catalog = load_catalog(FIXTURE)
        for tenant in data["tenants"]:
            tenant_id = tenant["tenant_id"]
            suffix = "noordlicht" if tenant_id.endswith("noordlicht") else "zilvermeer"
            scope = "org-noordlicht-policy-team" if suffix == "noordlicht" else "org-zilvermeer-culture-team"
            proposer = catalog.principals[f"user-{suffix}-proposer"]
            reviewer = catalog.principals[f"user-{suffix}-reviewer"]
            reader = catalog.principals[f"user-{suffix}-reader"]
            resource = Resource(tenant_id, scope)
            self.assertTrue(is_authorized(proposer, "knowledge:propose", resource))
            self.assertFalse(is_authorized(proposer, "knowledge:review", resource))
            self.assertTrue(is_authorized(reviewer, "knowledge:review", resource))
            self.assertFalse(is_authorized(reviewer, "knowledge:propose", resource))
            self.assertTrue(is_authorized(reader, "knowledge:read", resource))

    def test_source_fixture_is_synthetic_and_covers_both_tenants(self):
        source_path = FIXTURE.parent / "synthetic_sources.json"
        data = json.loads(source_path.read_text(encoding="utf-8"))
        self.assertIs(data["synthetic_only"], True)
        self.assertEqual(
            {source["tenant_id"] for source in data["sources"]},
            {"tenant-synth-noordlicht", "tenant-synth-zilvermeer"},
        )
        for source in data["sources"]:
            self.assertTrue(source["source_id"].startswith("source-synth-"))
            self.assertTrue(source["extraction_id"].startswith("extract-synth-"))
            self.assertTrue(source["content"])
            self.assertTrue(source["source_location"].startswith("fixture://synthetic/"))

    def test_seed_does_not_reuse_organization_or_user_identifiers_across_tenants(self):
        data = json.loads(FIXTURE.read_text(encoding="utf-8"))
        identifiers = []
        for tenant in data["tenants"]:
            identifiers.append(tenant["tenant_id"])
            identifiers.extend(node["node_id"] for node in tenant["org_nodes"])
            identifiers.extend(user["user_id"] for user in tenant["users"])
        self.assertEqual(len(identifiers), len(set(identifiers)))


if __name__ == "__main__":
    unittest.main()
