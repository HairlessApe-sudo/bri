"""Explicit, non-overwriting synthetic municipality and source seed."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable

from bri.api.app import ApiSettings
from bri.api.database import Database, TenantSession, is_approved_app_target

ROOT = Path(__file__).resolve().parents[2]
MUNICIPALITIES_PATH = ROOT / "tests" / "fixtures" / "synthetic_municipalities.json"
SOURCES_PATH = ROOT / "tests" / "fixtures" / "synthetic_sources.json"
_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]*$")


class SeedConflict(RuntimeError):
    """An existing key has values different from the checked-in synthetic seed."""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        required=True,
        help="explicitly write the synthetic seed to the verified development database",
    )
    return parser


def _validate_identifiers(table: str, columns: Iterable[str]) -> None:
    parts = table.split(".")
    if len(parts) != 2 or parts[0] != "bri" or not all(_IDENTIFIER.fullmatch(part) for part in parts):
        raise ValueError("seed table is not an approved BRI identifier")
    if not all(_IDENTIFIER.fullmatch(column) for column in columns):
        raise ValueError("seed column is not an approved SQL identifier")


def insert_or_verify(
    connection: Any,
    *,
    table: str,
    columns: tuple[str, ...],
    values: tuple[Any, ...],
    key_columns: tuple[str, ...],
) -> bool:
    """Insert once; on conflict require exact fixture equality and never update."""
    if len(columns) != len(values) or not key_columns or not set(key_columns) <= set(columns):
        raise ValueError("invalid synthetic seed row shape")
    _validate_identifiers(table, (*columns, *key_columns))
    names = ", ".join(columns)
    placeholders = ", ".join("%s" for _ in columns)
    keys = ", ".join(key_columns)
    inserted = connection.execute(
        f"INSERT INTO {table} ({names}) VALUES ({placeholders}) "
        f"ON CONFLICT DO NOTHING RETURNING {keys}",
        values,
    ).fetchone()
    if inserted is not None:
        return True

    where = " AND ".join(f"{column}=%s" for column in key_columns)
    key_values = tuple(values[columns.index(column)] for column in key_columns)
    existing = connection.execute(
        f"SELECT {names} FROM {table} WHERE {where}",
        key_values,
    ).fetchone()
    if existing is None or tuple(existing) != values:
        raise SeedConflict("existing BRI row conflicts with the checked-in synthetic seed")
    return False


def seed_tenant(
    connection: Any,
    tenant: dict[str, Any],
    sources: list[dict[str, Any]],
) -> tuple[int, int]:
    """Seed one tenant within the caller's tenant-scoped transaction."""
    tenant_id = tenant["tenant_id"]
    inserted_count = 0
    verified_count = 0

    def put(table: str, columns: tuple[str, ...], values: tuple[Any, ...], keys: tuple[str, ...]) -> None:
        nonlocal inserted_count, verified_count
        if insert_or_verify(connection, table=table, columns=columns, values=values, key_columns=keys):
            inserted_count += 1
        else:
            verified_count += 1

    put(
        "bri.tenants",
        ("tenant_id", "display_name", "sector"),
        (tenant_id, tenant["display_name"], tenant["sector"]),
        ("tenant_id",),
    )
    for node in tenant["org_nodes"]:
        put(
            "bri.org_nodes",
            ("tenant_id", "node_id", "node_type", "display_name", "parent_node_id"),
            (tenant_id, node["node_id"], node["node_type"], node["display_name"], node.get("parent_id")),
            ("tenant_id", "node_id"),
        )
    for role in tenant["roles"]:
        put(
            "bri.app_roles",
            ("tenant_id", "role_id", "display_name"),
            (tenant_id, role["role_id"], role["display_name"]),
            ("tenant_id", "role_id"),
        )
        for permission in role["permissions"]:
            put(
                "bri.role_permissions",
                ("tenant_id", "role_id", "permission"),
                (tenant_id, role["role_id"], permission),
                ("tenant_id", "role_id", "permission"),
            )
    for user in tenant["users"]:
        put(
            "bri.synthetic_principals",
            ("tenant_id", "principal_id", "display_name", "synthetic_only"),
            (tenant_id, user["user_id"], user["display_name"], True),
            ("tenant_id", "principal_id"),
        )
        for assignment in user["role_assignments"]:
            put(
                "bri.role_assignments",
                ("tenant_id", "principal_id", "role_id", "scope_node_id"),
                (tenant_id, user["user_id"], assignment["role_id"], assignment["scope_node_id"]),
                ("tenant_id", "principal_id", "role_id", "scope_node_id"),
            )
    for relationship in tenant["relationships"]:
        put(
            "bri.org_relationships",
            (
                "tenant_id", "relationship_id", "from_node_id", "to_node_id",
                "relationship_type", "grants_access",
            ),
            (
                tenant_id, relationship["relationship_id"], relationship["from_node_id"],
                relationship["to_node_id"], relationship["relationship_type"],
                relationship["grants_access"],
            ),
            ("tenant_id", "relationship_id"),
        )

    tenant_sources = [source for source in sources if source["tenant_id"] == tenant_id]
    if not tenant_sources:
        raise ValueError("a synthetic source is missing for a fixture tenant")
    for source in tenant_sources:
        if source.get("source_kind") != "synthetic_text":
            raise ValueError("only explicitly synthetic text sources may be seeded")
        content_hash = hashlib.sha256(source["content"].encode("utf-8")).hexdigest()
        put(
            "bri.source_records",
            (
                "tenant_id", "source_id", "scope_node_id", "title", "source_kind", "created_by",
            ),
            (
                tenant_id, source["source_id"], source["scope_node_id"], source["title"],
                source["source_kind"], source["created_by"],
            ),
            ("tenant_id", "source_id"),
        )
        put(
            "bri.source_versions",
            (
                "tenant_id", "source_id", "source_version_id", "version_label",
                "content_sha256", "source_location", "created_by",
            ),
            (
                tenant_id, source["source_id"], source["source_version_id"],
                source["version_label"], content_hash, source["source_location"],
                source["created_by"],
            ),
            ("tenant_id", "source_id", "source_version_id"),
        )
        put(
            "bri.source_extractions",
            (
                "tenant_id", "extraction_id", "source_id", "source_version_id",
                "scope_node_id", "content", "content_sha256", "source_location",
                "extractor_name", "extractor_version", "created_by",
            ),
            (
                tenant_id, source["extraction_id"], source["source_id"],
                source["source_version_id"], source["scope_node_id"], source["content"],
                content_hash, source["source_location"], source["extractor_name"],
                source["extractor_version"], source["created_by"],
            ),
            ("tenant_id", "extraction_id"),
        )
    return inserted_count, verified_count


def main(argv: list[str] | None = None) -> int:
    build_parser().parse_args(argv)
    settings = ApiSettings.from_environment()
    if settings.environment.strip().lower() != "development":
        print("SEED_STOP development_environment_required")
        return 2
    if not is_approved_app_target(settings.supabase_url, settings.database_url):
        print("SEED_STOP approved_development_project_and_bri_app_required")
        return 2
    try:
        municipalities = json.loads(MUNICIPALITIES_PATH.read_text(encoding="utf-8"))
        source_fixture = json.loads(SOURCES_PATH.read_text(encoding="utf-8"))
        if municipalities.get("synthetic_only") is not True or source_fixture.get("synthetic_only") is not True:
            print("SEED_STOP fixtures_not_explicitly_synthetic")
            return 2
        sources = source_fixture["sources"]
        database = Database(settings.supabase_url, settings.database_url)
        inserted = 0
        verified = 0
        for tenant in municipalities["tenants"]:
            tenant_id = tenant["tenant_id"]
            with database.write_tenant_context(tenant_id) as session:
                tenant_inserted, tenant_verified = seed_tenant(
                    session.connection,
                    tenant,
                    sources,
                )
            inserted += tenant_inserted
            verified += tenant_verified
    except Exception:
        print("SEED_STOP database_unavailable_or_existing_synthetic_data_conflicts")
        return 2
    print(f"SEED_COMPLETE inserted={inserted} existing_verified={verified}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
