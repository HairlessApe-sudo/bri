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
