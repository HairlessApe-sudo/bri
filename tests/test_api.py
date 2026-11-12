from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
import os
from typing import Iterator
import unittest

from fastapi.testclient import TestClient

from bri.api.app import ApiSettings, DatabaseUnavailable, create_app
from bri.api.database import Database, TenantSession, is_approved_app_target


@unittest.skipUnless(
    os.environ.get("BRI_RUN_DB_TESTS") == "1",
    "set BRI_RUN_DB_TESTS=1 to opt in to verified bri_app API database tests",
)
class ApiDatabaseIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        settings = ApiSettings.from_environment()
        if settings.environment.strip().lower() != "development":
            self.fail("live API tests require explicit development environment")
        if not is_approved_app_target(settings.supabase_url, settings.database_url):
            self.fail("live API tests require the approved project and bri_app database URL")
        settings = replace(settings, dev_auth_enabled=True)
        self.client = TestClient(
            create_app(settings=settings, database=Database(settings.supabase_url, settings.database_url)),
            client=("127.0.0.1", 51000),
        )

    def test_health_connects_with_restricted_application_role(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok", "database": "ok"})

    def test_authenticated_request_sets_rls_tenant_context_without_writes(self) -> None:
        response = self.client.get(
            "/v1/organizations/structure",
            headers={"X-Dev-Identity": "user-noordlicht-org-reader"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.json()["nodes"]), 6)


class DatabaseTargetTests(unittest.TestCase):
    api_url = "https://bwqdyibvuecgthtatrtv.supabase.co"

    def test_accepts_only_the_approved_project_and_bri_app_role(self) -> None:
        pooler = (
            "postgresql://bri_app.bwqdyibvuecgthtatrtv@"
            "aws-1-eu-west-1.pooler.supabase.com:5432/postgres?sslmode=require"
        )
        direct = "postgresql://bri_app@db.bwqdyibvuecgthtatrtv.supabase.co:5432/postgres?sslmode=require"
        self.assertTrue(is_approved_app_target(self.api_url, pooler))
        self.assertTrue(is_approved_app_target(self.api_url, pooler.split("?", 1)[0]))
        self.assertTrue(is_approved_app_target(self.api_url, direct))
        self.assertFalse(
            is_approved_app_target(
                self.api_url,
                pooler.replace("bri_app.", "postgres.", 1),
            )
        )
        self.assertFalse(
            is_approved_app_target(
                self.api_url,
                pooler.replace("bri_app.", "bri_migrator.", 1),
            )
        )
        self.assertFalse(
            is_approved_app_target(
                self.api_url,
                pooler.split("?", 1)[0] + "?host=attacker.example",
            )
        )
        self.assertFalse(
            is_approved_app_target(
                self.api_url,
                pooler.replace("sslmode=require", "sslmode=disable"),
            )
        )
        self.assertFalse(
            is_approved_app_target(
                self.api_url,
                pooler.replace("aws-1-eu-west-1.pooler.supabase.com", "attacker.pooler.supabase.com"),
            )
        )
        self.assertFalse(
            is_approved_app_target(
                self.api_url,
                pooler.replace("bwqdyibvuecgthtatrtv", "aaaaaaaaaaaaaaaaaaaa"),
            )
        )


class FakeResult:
    def __init__(self, rows):
        self.rows = rows

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def fetchall(self):
        return self.rows


class FakeReadConnection:
    def __init__(self) -> None:
        self.queries: list[tuple[str, tuple | None]] = []

    def execute(self, query: str, params: tuple | None = None) -> FakeResult:
        normalized = " ".join(query.split())
        self.queries.append((normalized, params))
        if "FROM bri.tenants WHERE tenant_id=%s" in normalized:
            return FakeResult([("tenant-synth-noordlicht", "Database Noordlicht", "municipality")])
        if "FROM bri.org_nodes WHERE tenant_id=%s" in normalized:
            return FakeResult(
                [
                    ("org-noordlicht-root", "municipality", "Database Root", None),
                    ("org-noordlicht-policy", "department", "Database Policy", "org-noordlicht-root"),
                    ("org-noordlicht-policy-team", "team", "Database Policy Team", "org-noordlicht-policy"),
                    ("org-noordlicht-information", "functional_group", "Database Information", "org-noordlicht-root"),
                    ("org-noordlicht-public", "department", "Database Public", "org-noordlicht-root"),
                    ("org-noordlicht-public-team", "team", "Database Public Team", "org-noordlicht-public"),
                ]
            )
        if "FROM bri.org_relationships WHERE tenant_id=%s" in normalized:
            return FakeResult([])
        raise AssertionError("unexpected query in API test")


class FakeDatabase:
    def __init__(self, healthy: bool = True, session: TenantSession | None = None) -> None:
        self.healthy = healthy
        self.session = session
        self.contexts: list[str] = []

    def healthcheck(self) -> None:
        if not self.healthy:
            raise DatabaseUnavailable("private connection detail must not escape")

    @contextmanager
    def tenant_context(self, tenant_id: str) -> Iterator[TenantSession]:
        self.contexts.append(tenant_id)
        yield self.session or TenantSession(tenant_id, None)


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.database = FakeDatabase()
        settings = ApiSettings(environment="development", dev_auth_enabled=True)
        self.app = create_app(settings=settings, database=self.database)
        self.client = TestClient(self.app, client=("127.0.0.1", 51000))

    def test_health_checks_database_without_disclosing_connection_details(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok", "database": "ok"})

        unavailable = create_app(
            settings=ApiSettings(environment="development", dev_auth_enabled=True),
            database=FakeDatabase(healthy=False),
        )
        failed = TestClient(unavailable, client=("127.0.0.1", 51000)).get("/health")
        self.assertEqual(failed.status_code, 503)
        self.assertNotIn("private connection detail", failed.text)

    def test_openapi_documents_health_and_read_only_routes(self) -> None:
        response = self.client.get("/openapi.json")
        self.assertEqual(response.status_code, 200)
        schema = response.json()
        self.assertIn("/v1/organizations/structure", schema["paths"])
        self.assertIn("/v1/organizations/nodes/{node_id}", schema["paths"])
        self.assertIn("/v1/knowledge", schema["paths"])
        self.assertIn("/v1/knowledge/search", schema["paths"])
        self.assertIn("/v1/sources/{record_id}", schema["paths"])
        parameters = schema["paths"]["/v1/knowledge"]["get"]["parameters"]
        self.assertTrue(any(parameter["name"] == "X-Dev-Identity" for parameter in parameters))
        self.assertEqual(self.client.get("/docs").status_code, 200)

    def test_missing_or_unknown_development_identity_is_unauthorized(self) -> None:
        self.assertEqual(self.client.get("/v1/knowledge").status_code, 401)
        response = self.client.get(
            "/v1/knowledge", headers={"X-Dev-Identity": "not-a-synthetic-user"}
        )
        self.assertEqual(response.status_code, 401)

    def test_organization_structure_contains_only_exactly_authorized_tenant_nodes(self) -> None:
        response = self.client.get(
            "/v1/organizations/structure",
            headers={"X-Dev-Identity": "user-noordlicht-org-reader"},
        )
        self.assertEqual(response.status_code, 200)
        result = response.json()
        node_ids = {node["node_id"] for node in result["nodes"]}
        self.assertEqual(
            node_ids,
            {
                "org-noordlicht-root",
                "org-noordlicht-policy",
                "org-noordlicht-policy-team",
                "org-noordlicht-information",
                "org-noordlicht-public",
                "org-noordlicht-public-team",
            },
        )
        self.assertTrue(all("zilvermeer" not in node_id for node_id in node_ids))
        self.assertEqual(len(result["relationships"]), 1)
        self.assertEqual(self.database.contexts, ["tenant-synth-noordlicht"])

    def test_organization_endpoint_prefers_rls_scoped_database_rows_when_present(self) -> None:
        connection = FakeReadConnection()
        session = TenantSession("tenant-synth-noordlicht", connection)
        database = FakeDatabase(session=session)
        app = create_app(
            settings=ApiSettings(environment="development", dev_auth_enabled=True),
            database=database,
        )
        client = TestClient(app, client=("127.0.0.1", 51000))
        response = client.get(
            "/v1/organizations/nodes/org-noordlicht-root",
            headers={"X-Dev-Identity": "user-noordlicht-org-reader"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["display_name"], "Database Root")
        self.assertEqual(len(connection.queries), 3)
        self.assertTrue(all(params == ("tenant-synth-noordlicht",) for _, params in connection.queries))

    def test_database_backed_structure_uses_database_relationship_rows(self) -> None:
        connection = FakeReadConnection()
        app = create_app(
            settings=ApiSettings(environment="development", dev_auth_enabled=True),
            database=FakeDatabase(session=TenantSession("tenant-synth-noordlicht", connection)),
        )
        response = TestClient(app, client=("127.0.0.1", 51000)).get(
            "/v1/organizations/structure",
            headers={"X-Dev-Identity": "user-noordlicht-org-reader"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            [node["display_name"] for node in response.json()["nodes"]],
            [
                "Database Root",
                "Database Policy",
                "Database Policy Team",
                "Database Information",
                "Database Public",
                "Database Public Team",
            ],
        )
        self.assertEqual(response.json()["relationships"], [])

    def test_exact_node_endpoint_hides_cross_tenant_and_out_of_scope_nodes(self) -> None:
        headers = {"X-Dev-Identity": "user-noordlicht-reader"}
        self.assertEqual(
            self.client.get(
                "/v1/organizations/nodes/org-zilvermeer-culture-team", headers=headers
            ).status_code,
            404,
        )
        self.assertEqual(
            self.client.get(
                "/v1/organizations/nodes/org-noordlicht-root", headers=headers
            ).status_code,
            404,
        )

    def test_missing_permissions_are_denied(self) -> None:
        org_denied = self.client.get(
            "/v1/organizations/structure",
            headers={"X-Dev-Identity": "user-noordlicht-reader"},
        )
        knowledge_denied = self.client.get(
            "/v1/knowledge",
            headers={"X-Dev-Identity": "user-noordlicht-admin"},
        )
        self.assertEqual(org_denied.status_code, 403)
        self.assertEqual(knowledge_denied.status_code, 403)

    def test_knowledge_records_and_sources_are_validated_scoped_and_tenant_isolated(self) -> None:
        headers = {"X-Dev-Identity": "user-noordlicht-reader"}
        response = self.client.get("/v1/knowledge", headers=headers)
        self.assertEqual(response.status_code, 200)
        records = response.json()
        self.assertEqual([item["record_id"] for item in records], ["knowledge-noordlicht-retention"])
        self.assertEqual(records[0]["validation_state"], "approved")
        self.assertNotIn("knowledge-zilvermeer-policy", {item["record_id"] for item in records})
        self.assertNotIn("knowledge-noordlicht-proposed", {item["record_id"] for item in records})

        source = self.client.get(
            "/v1/sources/knowledge-noordlicht-retention", headers=headers
        )
        self.assertEqual(source.status_code, 200)
        self.assertEqual(source.json()["source_version"], "v1")
        self.assertEqual(
            self.client.get("/v1/sources/knowledge-zilvermeer-policy", headers=headers).status_code,
            404,
        )
        self.assertEqual(
            self.client.get("/v1/sources/knowledge-noordlicht-proposed", headers=headers).status_code,
            404,
        )

    def test_knowledge_search_uses_existing_evidence_retrieval(self) -> None:
        response = self.client.get(
            "/v1/knowledge/search",
            params={"q": "How many years must employee files be retained?"},
            headers={"X-Dev-Identity": "user-noordlicht-reader"},
        )
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertEqual(result["status"], "supported")
        self.assertEqual(result["answer"], "Employee files must be retained for seven years.")
        self.assertEqual(result["citations"][0]["record_id"], "knowledge-noordlicht-retention")

    def test_tenant_selection_headers_query_and_body_are_rejected(self) -> None:
        identity = {"X-Dev-Identity": "user-noordlicht-reader"}
        header_spoof = self.client.get(
            "/v1/knowledge", headers={**identity, "X-Tenant-ID": "tenant-synth-zilvermeer"}
        )
        query_spoof = self.client.get(
            "/v1/knowledge?tenant_id=tenant-synth-zilvermeer", headers=identity
        )
        body_spoof = self.client.request(
            "GET",
            "/v1/knowledge",
            headers=identity,
            json={"tenant_id": "tenant-synth-zilvermeer"},
        )
        self.assertEqual(header_spoof.status_code, 400)
        self.assertEqual(query_spoof.status_code, 400)
        self.assertEqual(body_spoof.status_code, 400)

    def test_dev_identity_is_disabled_outside_explicit_local_development(self) -> None:
        app = create_app(
            settings=ApiSettings(environment="production", dev_auth_enabled=False),
            database=FakeDatabase(),
        )
        response = TestClient(app, client=("127.0.0.1", 51000)).get(
            "/v1/knowledge", headers={"X-Dev-Identity": "user-noordlicht-reader"}
        )
        self.assertEqual(response.status_code, 503)

        with self.assertRaises(ValueError):
            ApiSettings(environment="production", dev_auth_enabled=True)

    def test_development_identity_adapter_refuses_non_loopback_clients(self) -> None:
        remote_client = TestClient(self.app, client=("192.0.2.4", 51000))
        response = remote_client.get(
            "/v1/knowledge", headers={"X-Dev-Identity": "user-noordlicht-reader"}
        )
        self.assertEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
