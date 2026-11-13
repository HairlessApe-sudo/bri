from __future__ import annotations

from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import os
from typing import Iterator
import unittest

from fastapi.testclient import TestClient

from bri.access.policy import Principal
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
        self.database = Database(settings.supabase_url, settings.database_url)
        self.client = TestClient(
            create_app(settings=settings, database=self.database),
            client=("127.0.0.1", 51000),
        )

    def test_write_context_is_transaction_local_and_uses_bri_app(self) -> None:
        with self.database.write_tenant_context("tenant-synth-noordlicht") as session:
            self.assertEqual(session.tenant_id, "tenant-synth-noordlicht")
            row = session.connection.execute(
                "SELECT current_user, current_setting('bri.tenant_id', true), "
                "current_setting('transaction_read_only')"
            ).fetchone()
            self.assertEqual(row, ("bri_app", "tenant-synth-noordlicht", "off"))

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


class FakeKnowledgeConnection:
    def __init__(self) -> None:
        content_noordlicht = "Employee files must be retained for seven years."
        content_zilvermeer = "Public library opening hours are 09:00 to 17:00 on weekdays."
        self.sources = {
            ("tenant-synth-noordlicht", "extract-synth-noordlicht-retention-v1"): (
                "org-noordlicht-policy-team", "Synthetic Records Retention Policy",
                "source-synth-noordlicht-retention", "source-version-synth-noordlicht-retention-v1",
                "v1", "extract-synth-noordlicht-retention-v1", content_noordlicht,
                hashlib.sha256(content_noordlicht.encode()).hexdigest(),
                "synthetic-fixture", "1",
                "fixture://synthetic/noordlicht/retention-policy/v1#page=2",
            ),
            ("tenant-synth-zilvermeer", "extract-synth-zilvermeer-culture-v1"): (
                "org-zilvermeer-culture-team", "Synthetic Culture Service Schedule",
                "source-synth-zilvermeer-culture", "source-version-synth-zilvermeer-culture-v1",
                "v1", "extract-synth-zilvermeer-culture-v1", content_zilvermeer,
                hashlib.sha256(content_zilvermeer.encode()).hexdigest(),
                "synthetic-fixture", "1",
                "fixture://synthetic/zilvermeer/culture-schedule/v1#section=opening-hours",
            ),
        }
        self.proposals: dict[tuple[str, str], tuple] = {}
        self.decisions: dict[tuple[str, str], tuple] = {}
        self.validated: set[tuple[str, str]] = set()

    def execute(self, query: str, params=()) -> FakeResult:
        normalized = " ".join(query.split())
        if "FROM bri.source_extractions x" in normalized:
            return FakeResult([self.sources[(params[0], params[1])]] if (params[0], params[1]) in self.sources else [])
        if normalized.startswith("INSERT INTO bri.knowledge_proposals"):
            tenant_id, proposal_id, extraction_id, scope_id, proposed_by = params
            source = self.sources[(tenant_id, extraction_id)]
            proposed_at = datetime.now(timezone.utc)
            row = (
                proposal_id, tenant_id, scope_id, proposed_by, proposed_at,
                source[1], source[2], source[3], source[4], source[5], source[6],
                source[7], source[8], source[9], source[10],
            )
            self.proposals[(tenant_id, proposal_id)] = row
            return FakeResult([(proposed_at,)])
        if normalized.startswith("INSERT INTO bri.validation_decisions"):
            tenant_id, decision_id, proposal_id, reviewer_id, decision, comment = params
            key = (tenant_id, proposal_id)
            if key in self.decisions:
                return FakeResult([])
            decided_at = datetime.now(timezone.utc)
            self.decisions[key] = (decision_id, reviewer_id, decision, comment, decided_at)
            return FakeResult([(decided_at,)])
        if normalized.startswith("INSERT INTO bri.validated_knowledge"):
            self.validated.add((params[0], params[1]))
            return FakeResult([])
        if "JOIN bri.validated_knowledge v" in normalized:
            tenant_id, scopes = params
            return FakeResult([
                row for key, row in self.proposals.items()
                if key[0] == tenant_id and key in self.validated and row[2] in scopes
            ])
        if "LEFT JOIN bri.validation_decisions d" in normalized:
            tenant_id, scopes = params
            return FakeResult([
                row for key, row in self.proposals.items()
                if key[0] == tenant_id and key not in self.decisions and row[2] in scopes
            ])
        if normalized.startswith("SELECT p.proposal_id"):
            tenant_id, proposal_id = params
            row = self.proposals.get((tenant_id, proposal_id))
            return FakeResult([row] if row else [])
        raise AssertionError("unexpected knowledge SQL in API test")


class FakeDatabase:
    def __init__(
        self,
        healthy: bool = True,
        session: TenantSession | None = None,
        connection: object | None = None,
    ) -> None:
        self.healthy = healthy
        self.session = session
        self.connection = connection
        self.contexts: list[str] = []

    def healthcheck(self) -> None:
        if not self.healthy:
            raise DatabaseUnavailable("private connection detail must not escape")

    @contextmanager
    def tenant_context(self, tenant_id: str) -> Iterator[TenantSession]:
        self.contexts.append(tenant_id)
        yield self.session or TenantSession(tenant_id, self.connection)

    @contextmanager
    def write_tenant_context(self, tenant_id: str) -> Iterator[TenantSession]:
        self.contexts.append(tenant_id)
        yield self.session or TenantSession(tenant_id, self.connection)


class ApiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.database = FakeDatabase()
        settings = ApiSettings(environment="development", dev_auth_enabled=True)
        self.app = create_app(settings=settings, database=self.database)
        self.client = TestClient(self.app, client=("127.0.0.1", 51000))

    def knowledge_client(self):
        connection = FakeKnowledgeConnection()
        database = FakeDatabase(connection=connection)
        app = create_app(
            settings=ApiSettings(environment="development", dev_auth_enabled=True),
            database=database,
        )
        return TestClient(app, client=("127.0.0.1", 51000)), app, connection

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

    def test_openapi_documents_health_and_knowledge_lifecycle_routes(self) -> None:
        response = self.client.get("/openapi.json")
        self.assertEqual(response.status_code, 200)
        schema = response.json()
        self.assertIn("/v1/organizations/structure", schema["paths"])
        self.assertIn("/v1/organizations/nodes/{node_id}", schema["paths"])
        self.assertIn("/v1/knowledge", schema["paths"])
        self.assertIn("/v1/knowledge/proposals", schema["paths"])
        self.assertIn("get", schema["paths"]["/v1/knowledge/proposals"])
        self.assertIn("post", schema["paths"]["/v1/knowledge/proposals"])
        self.assertIn("post", schema["paths"]["/v1/knowledge/proposals/{proposal_id}/decision"])
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

    def test_knowledge_reads_fail_closed_when_database_session_is_unavailable(self) -> None:
        response = self.client.get(
            "/v1/knowledge",
            headers={"X-Dev-Identity": "user-noordlicht-reader"},
        )
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("Employee files must be retained", response.text)

    def test_only_proposers_can_create_knowledge_proposals(self) -> None:
        response = self.client.post(
            "/v1/knowledge/proposals",
            headers={"X-Dev-Identity": "user-noordlicht-reader"},
            json={"extraction_id": "extract-synth-noordlicht-retention-v1"},
        )
        self.assertEqual(response.status_code, 403)

    def test_combined_workspace_identity_reads_authorized_routes_without_write_access(self) -> None:
        identity = {"X-Dev-Identity": "user-noordlicht-workspace-reader"}
        organization = self.client.get("/v1/organizations/structure", headers=identity)
        self.assertEqual(organization.status_code, 200)
        self.assertEqual(len(organization.json()["nodes"]), 6)

        client, _, _ = self.knowledge_client()
        proposer = {"X-Dev-Identity": "user-noordlicht-proposer"}
        reviewer = {"X-Dev-Identity": "user-noordlicht-reviewer"}
        created = client.post(
            "/v1/knowledge/proposals",
            headers=proposer,
            json={"extraction_id": "extract-synth-noordlicht-retention-v1"},
        )
        self.assertEqual(created.status_code, 201)
        proposal_id = created.json()["proposal_id"]
        decided = client.post(
            f"/v1/knowledge/proposals/{proposal_id}/decision",
            headers=reviewer,
            json={"decision": "approved"},
        )
        self.assertEqual(decided.status_code, 200)

        records = client.get("/v1/knowledge", headers=identity)
        self.assertEqual(records.status_code, 200)
        self.assertEqual([item["title"] for item in records.json()], ["Synthetic Records Retention Policy"])
        record_id = records.json()[0]["record_id"]
        self.assertEqual(client.get(f"/v1/sources/{record_id}", headers=identity).status_code, 200)
        search = client.get("/v1/knowledge/search?q=employee%20files", headers=identity)
        self.assertEqual(search.status_code, 200)
        self.assertEqual([item["title"] for item in search.json()["citations"]], ["Synthetic Records Retention Policy"])

        self.assertEqual(client.get("/v1/knowledge/proposals", headers=identity).status_code, 403)
        self.assertEqual(
            client.post("/v1/knowledge/proposals", headers=identity, json={"extraction_id": "extract-synth-noordlicht-retention-v1"}).status_code,
            403,
        )
        self.assertEqual(
            client.post(f"/v1/knowledge/proposals/{proposal_id}/decision", headers=identity, json={"decision": "approved"}).status_code,
            403,
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

    def test_proposal_review_scope_and_approval_publish_validated_knowledge(self) -> None:
        client, _, _ = self.knowledge_client()
        proposer = {"X-Dev-Identity": "user-noordlicht-proposer"}
        reviewer = {"X-Dev-Identity": "user-noordlicht-reviewer"}
        employee = {"X-Dev-Identity": "user-noordlicht-reader"}

        created = client.post(
            "/v1/knowledge/proposals",
            headers=proposer,
            json={"extraction_id": "extract-synth-noordlicht-retention-v1"},
        )
        self.assertEqual(created.status_code, 201)
        proposal_id = created.json()["proposal_id"]
        self.assertEqual(created.json()["proposed_by"], "user-noordlicht-proposer")
        self.assertEqual(created.json()["status"], "proposed")

        pending = client.get("/v1/knowledge/proposals", headers=reviewer)
        self.assertEqual(pending.status_code, 200)
        self.assertEqual([item["proposal_id"] for item in pending.json()], [proposal_id])
        self.assertEqual(client.get("/v1/knowledge/proposals", headers=employee).status_code, 403)
        self.assertEqual(
            client.get("/v1/knowledge/proposals", headers={"X-Dev-Identity": "user-noordlicht-steward"}).json(),
            [],
        )
        self.assertEqual(
            client.get("/v1/knowledge/proposals", headers={"X-Dev-Identity": "user-zilvermeer-reviewer"}).json(),
            [],
        )
        self.assertEqual(client.get("/v1/knowledge", headers=employee).json(), [])
        before_approval = client.get(
            "/v1/knowledge/search",
            params={"q": "How many years must employee files be retained?"},
            headers=employee,
        ).json()
        self.assertEqual(before_approval["status"], "insufficient")
        self.assertEqual(before_approval["citations"], [])
        self.assertEqual(client.get(f"/v1/knowledge/{proposal_id}", headers={"X-Dev-Identity": "user-zilvermeer-reader"}).status_code, 404)
        self.assertEqual(
            client.post(
                f"/v1/knowledge/proposals/{proposal_id}/decision",
                headers={"X-Dev-Identity": "user-noordlicht-steward"},
                json={"decision": "approved"},
            ).status_code,
            403,
        )
        self.assertEqual(
            client.post(
                f"/v1/knowledge/proposals/{proposal_id}/decision",
                headers=employee,
                json={"decision": "approved"},
            ).status_code,
            403,
        )
        self.assertEqual(
            client.post(
                f"/v1/knowledge/proposals/{proposal_id}/decision",
                headers=proposer,
                json={"decision": "approved"},
            ).status_code,
            403,
        )

        decision = client.post(
            f"/v1/knowledge/proposals/{proposal_id}/decision",
            headers=reviewer,
            json={"decision": "approved", "comment": "Synthetic review passed."},
        )
        self.assertEqual(decision.status_code, 200)
        self.assertEqual(decision.json()["reviewer_id"], "user-noordlicht-reviewer")
        self.assertEqual(decision.json()["decision"], "approved")
        self.assertEqual(client.get("/v1/knowledge/proposals", headers=reviewer).json(), [])
        self.assertEqual(
            client.post(
                f"/v1/knowledge/proposals/{proposal_id}/decision",
                headers=reviewer,
                json={"decision": "rejected"},
            ).status_code,
            409,
        )

        record = client.get(f"/v1/knowledge/{proposal_id}", headers=employee)
        self.assertEqual(record.status_code, 200)
        record_json = record.json()
        self.assertEqual(record_json["validation_state"], "approved")
        self.assertEqual(record_json["source_id"], "source-synth-noordlicht-retention")
        self.assertEqual(record_json["source_version_id"], "source-version-synth-noordlicht-retention-v1")
        self.assertEqual(record_json["extraction_id"], "extract-synth-noordlicht-retention-v1")
        self.assertEqual(
            record_json["content_sha256"],
            hashlib.sha256(record_json["content"].encode()).hexdigest(),
        )
        source = client.get(f"/v1/sources/{proposal_id}", headers=employee)
        self.assertEqual(source.status_code, 200)
        self.assertEqual(source.json()["source_location"], "fixture://synthetic/noordlicht/retention-policy/v1#page=2")
        answer = client.get(
            "/v1/knowledge/search",
            params={"q": "How many years must employee files be retained?"},
            headers=employee,
        ).json()
        self.assertEqual(answer["status"], "supported")
        self.assertEqual(answer["citations"][0]["record_id"], proposal_id)
        self.assertEqual(answer["citations"][0]["source_version_id"], record_json["source_version_id"])
        self.assertEqual(answer["citations"][0]["content_sha256"], record_json["content_sha256"])

    def test_rejected_proposals_are_terminal_and_never_searchable(self) -> None:
        client, _, _ = self.knowledge_client()
        proposal = client.post(
            "/v1/knowledge/proposals",
            headers={"X-Dev-Identity": "user-noordlicht-proposer"},
            json={"extraction_id": "extract-synth-noordlicht-retention-v1"},
        ).json()
        proposal_id = proposal["proposal_id"]
        rejected = client.post(
            f"/v1/knowledge/proposals/{proposal_id}/decision",
            headers={"X-Dev-Identity": "user-noordlicht-reviewer"},
            json={"decision": "rejected", "comment": "Synthetic rejection."},
        )
        self.assertEqual(rejected.status_code, 200)
        self.assertEqual(rejected.json()["reviewer_id"], "user-noordlicht-reviewer")
        self.assertEqual(client.get("/v1/knowledge/proposals", headers={"X-Dev-Identity": "user-noordlicht-reviewer"}).json(), [])
        self.assertEqual(
            client.get(
                "/v1/knowledge/search",
                params={"q": "How many years must employee files be retained?"},
                headers={"X-Dev-Identity": "user-noordlicht-reader"},
            ).json()["status"],
            "insufficient",
        )
        self.assertEqual(
            client.get(f"/v1/knowledge/{proposal_id}", headers={"X-Dev-Identity": "user-noordlicht-reader"}).status_code,
            404,
        )
        self.assertEqual(
            client.post(
                f"/v1/knowledge/proposals/{proposal_id}/decision",
                headers={"X-Dev-Identity": "user-noordlicht-reviewer"},
                json={"decision": "approved"},
            ).status_code,
            409,
        )

    def test_cross_tenant_source_and_revoked_read_grant_are_denied(self) -> None:
        client, app, _ = self.knowledge_client()
        denied = client.post(
            "/v1/knowledge/proposals",
            headers={"X-Dev-Identity": "user-noordlicht-proposer"},
            json={"extraction_id": "extract-synth-zilvermeer-culture-v1"},
        )
        self.assertEqual(denied.status_code, 404)
        proposal = client.post(
            "/v1/knowledge/proposals",
            headers={"X-Dev-Identity": "user-noordlicht-proposer"},
            json={"extraction_id": "extract-synth-noordlicht-retention-v1"},
        ).json()
        proposal_id = proposal["proposal_id"]
        client.post(
            f"/v1/knowledge/proposals/{proposal_id}/decision",
            headers={"X-Dev-Identity": "user-noordlicht-reviewer"},
            json={"decision": "approved"},
        )
        identity = "user-noordlicht-reader"
        original = app.state.catalog.principals[identity]
        app.state.catalog.principals[identity] = Principal(original.subject_id, original.tenant_ids, ())
        self.assertEqual(
            client.get(f"/v1/knowledge/{proposal_id}", headers={"X-Dev-Identity": identity}).status_code,
            403,
        )

    def test_corrupt_extracted_content_fails_closed(self) -> None:
        client, _, connection = self.knowledge_client()
        key = ("tenant-synth-noordlicht", "extract-synth-noordlicht-retention-v1")
        source = connection.sources[key]
        connection.sources[key] = (*source[:7], "0" * 64, *source[8:])
        response = client.post(
            "/v1/knowledge/proposals",
            headers={"X-Dev-Identity": "user-noordlicht-proposer"},
            json={"extraction_id": key[1]},
        )
        self.assertEqual(response.status_code, 503)
        self.assertEqual(connection.proposals, {})

    def test_multi_tenant_identity_is_rejected_before_scoped_database_access(self) -> None:
        identity = "user-noordlicht-reader"
        original = self.app.state.catalog.principals[identity]
        self.app.state.catalog.principals[identity] = Principal(
            original.subject_id,
            frozenset({"tenant-synth-noordlicht", "tenant-synth-zilvermeer"}),
            original.grants,
        )
        response = self.client.get("/v1/knowledge", headers={"X-Dev-Identity": identity})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.database.contexts, [])

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
        write_body_spoof = self.client.post(
            "/v1/knowledge/proposals",
            headers={"X-Dev-Identity": "user-noordlicht-proposer"},
            json={
                "extraction_id": "extract-synth-noordlicht-retention-v1",
                "tenant_id": "tenant-synth-zilvermeer",
            },
        )
        self.assertEqual(header_spoof.status_code, 400)
        self.assertEqual(query_spoof.status_code, 400)
        self.assertEqual(body_spoof.status_code, 400)
        self.assertEqual(write_body_spoof.status_code, 422)

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
