# BRI — Organisational Intelligence Infrastructure

Status: New independent product; Assignment 01 local synthetic implementation in progress
Last updated: 2026-11-10

## Identity

BRI is an organisation-independent intelligence infrastructure platform. It connects to existing business systems, transforms organisational information into governed knowledge, supports knowledge and decision intelligence, and exposes validated intelligence to people, applications and AI agents. BRI is infrastructure first; its own web interface is one client of the platform.

This workspace is a new clean documentation baseline. It is not a continuation, migration or refactoring of the previous BRI implementation.

## Current status

- Product direction: taken from the initiating project brief; not silently expanded.
- Architecture: proposed; decision register is in `architecture/architecture-decisions.md`.
- Implementation: Assignment 01 authorizes local synthetic development; the first tested code slices exist. No production services or real data are involved.
- Data: synthetic examples only.
- Independent boundary: see `governance/independent-development-boundary.md`.
- Legal ownership/licensing questions: unresolved; see `governance/ownership-and-dependencies.md`.

## Local development (current implemented slice)

The source currently contains bounded CSV, selectable-text PDF and XLSX extraction; a fail-closed exact-tenant/action/scope policy primitive; deterministic evidence-first Knowledge Intelligence over already-validated records; a two-tenant fictional municipal test fixture; and a development-only Supabase PostgreSQL tenant foundation with composite tenant references and forced RLS. It is not yet a running web application or authenticated API. On the verified Python 3.14.9 environment:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests -v
```

For the development database, follow `db/README.md`; Docker is not required. Database integration tests are opt-in and use transactions that roll back all fixture writes:

```sh
PYTHONPATH=src BRI_RUN_DB_TESTS=1 .venv/bin/python -m unittest discover -s tests -p 'test_database_rls.py' -v
```

The database foundation is development-only and uses synthetic data. PDF extraction is text-only; OCR is not implemented. XLSX formulas are preserved as text and not executed. No production database, real data or external AI provider is supported.

## Document map

| Area | Document | Purpose |
|---|---|---|
| Context | `BRI_PROJECT_CONTEXT.md` | Concise persistent operating context and links |
| Product | `product/product-definition.md` | Product identity, users, scope and boundaries |
| Product | `product/product-requirements.md` | Traceable functional/non-functional requirements and proposed acceptance |
| Architecture | `architecture/architecture.md` | System context, components, boundaries and flows |
| Architecture | `architecture/domain-model.md` | Platform and domain concepts and bounded contexts |
| Architecture | `architecture/data-model.md` | Logical entities, invariants and storage responsibilities |
| Database | `db/README.md` | Supabase development setup, role usage, migrations and safe integration tests |
| Architecture | `architecture/security-model.md` | Identity, tenancy, authorization, privacy and threat boundaries |
| Architecture | `architecture/integration-architecture.md` | Inbound/outbound APIs, connectors and integration controls |
| Architecture | `architecture/knowledge-architecture.md` | Ingestion, validation, provenance, lifecycle and retrieval |
| Architecture | `architecture/intelligence-architecture.md` | Knowledge/decision intelligence and AI orchestration |
| Architecture | `architecture/analytics-and-reporting.md` | Metrics, dashboards, reproducible reporting and exports |
| Architecture | `architecture/deployment.md` | SaaS/private deployment options and operations |
| Architecture | `architecture/architecture-decisions.md` | Proposed decisions, alternatives, dependencies and status |
| Governance | `governance/independent-development-boundary.md` | Clean-room constraints and permitted references |
| Governance | `governance/ownership-and-dependencies.md` | Ownership, legal and external dependencies requiring review |
| Planning | `planning/development-roadmap.md` | Staged delivery and approval gates |
| Planning | `planning/implementation-plan.md` | Proposed MVP boundary and implementation sequencing; not authorisation |
| Planning | `planning/risk-register.md` | Risks, status, mitigations and decision gates |
| Planning | `planning/testing-strategy.md` | Synthetic-data test layers and release criteria |
| Planning | `planning/progress.md` | Current status, blockers and decision log |

## Decision-status vocabulary

- User-provided baseline: explicitly stated in the initiating brief; not a claim of external legal or executive approval.
- Proposed: recommended for review; not binding until explicitly accepted by the designated owner.
- Approved: only after an explicit approval is recorded with approver/date and, for material architecture choices, a decision record.
- Assumption: temporary premise used to make the design discussable; validate or remove before implementation.
- Unresolved: alternatives remain open; do not implement as if decided.

## Reference-only lessons

Do not treat materials from the previous development effort as implementation inputs or as automatically cleared for reuse. They are outside this repository; any future reference requires separate provenance and legal/permission review. The current project documents are the working architecture baseline, subject to their recorded decision statuses.
