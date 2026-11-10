# Product Definition — BRI

Status: Product direction transcribed from the initiating brief; detailed scope/acceptance remains proposed

## 1. Product identity

BRI means Organisational Intelligence Infrastructure. It is an organisation-independent platform that connects to existing business systems, transforms organisational information into governed knowledge, supports knowledge and decision intelligence, and makes validated intelligence accessible to people, applications and AI agents.

BRI is infrastructure first. The BRI web experience is one consumer of its capabilities, not the product boundary. It must serve varied sectors and organisation models without hardcoding municipal, healthcare, education or commercial workflows into the core.

## 2. Customer problem and outcomes

Organisations hold fragmented records, documents, decisions and operational information across systems. They need to govern how that information is imported, interpreted, validated, related, searched, analysed and shared.

BRI aims to enable an organisation to:
- Connect approved sources and bring information into a governed lifecycle.
- Configure its organisational and access model.
- Distinguish original evidence from extracted, interpreted and validated information.
- Maintain knowledge and historical decision records with provenance.
- Ask questions and investigate organisational history using permitted evidence.
- Produce transparent analytics and reports.
- Expose approved data/intelligence through APIs and integrations.
- Select AI providers/models consistent with organisational and deployment policy.

These are product outcomes, not promises of legal, professional or decision correctness.

## 3. Customers and users

Potential sectors named in the brief include municipalities, government, education, healthcare and commercial organisations. No single sector’s law, taxonomy, terminology, retention or workflow is assumed to be universal.

Candidate user classes, for requirements design (roles are not approved names):
- Organisation/platform administrator.
- Integration/data steward.
- Knowledge curator and validator.
- Analyst or decision researcher.
- General employee/end user.
- Auditor/governance reviewer.
- External application or AI agent using scoped APIs.
- BRS operator for SaaS operations, with restricted customer-content access.

## 4. Product capability map

1. Platform foundation: tenant/org administration, identity context, configurable organisational relationships, policy enforcement, audit and configuration.
2. Integration: authenticated inbound ingestion and controlled outbound APIs/connectors.
3. Knowledge infrastructure: source registration, extraction, classification proposals, validation, versioning, provenance, lifecycle and retrieval.
4. Knowledge Intelligence: find, relate, summarise and explain validated organisational knowledge.
5. Decision Intelligence: model recorded decisions, evidence, reasoning status, actions and outcomes; investigate patterns without inventing missing history.
6. Analytics and reporting: configurable dashboards and reproducible metrics/reports with scope and evidence.
7. AI orchestration: provider-independent capability routing subject to policy, tenant, purpose and deployment.
8. Experience: BRI user interface plus API/agent consumers.

The exact module split and delivery order are proposed in architecture documents.

## 5. Product boundaries

In scope for the platform direction:
- Flexible organisational structures and cross-organisational relationships.
- API, CSV, Excel and PDF inbound paths, with future extensible connectors.
- Outbound APIs and future integrations such as Power BI, SharePoint and Cognos.
- Governed knowledge, decision records, analytics, audit and data lifecycle.
- SaaS and private deployment using the same underlying platform.

Not implied by this brief:
- Autonomous or legally binding decisions.
- Any sector-specific professional/legal advice guarantee.
- Immediate delivery of every named enterprise connector.
- Use of historical municipal code, data or systems.
- A particular cloud, identity provider, database, model provider, deployment orchestrator or policy engine.
- Training shared models on customer data.

## 6. Product principles

Keep original information distinct from interpretation and validated knowledge; preserve provenance; enforce access before use; require human validation before interaction-derived knowledge is shared; support secure inbound and outbound integration; make model/provider decisions replaceable; configure retention/deletion; and expose capabilities consistently to UI, APIs and agents.

## 7. Success evidence (proposed)

A bounded pilot should show that synthetic organisations can configure different structures, import supported information, review and publish knowledge, capture a decision and evidence, retrieve permitted material, generate a sourced report, and access approved results through a documented API without cross-tenant or cross-unit leakage. Numeric quality, latency, availability and adoption targets remain unresolved until users and reference workloads are selected.
