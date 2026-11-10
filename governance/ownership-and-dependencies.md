# Ownership, Licensing and External Dependencies

Status: Governance register; legal and contractual conclusions are unresolved

## 1. Ownership and permitted materials

The product initiative is sponsored by Black Raven Studios, but this document does not determine ownership of prior work, employee/contractor contributions, third-party code, data, documents, names or inventions. Technical separation alone does not resolve rights or prove a clean-room process.

Before implementation or external distribution, obtain specialist review of:
- Ownership and chain of title for the new initiative and contributors.
- Rights and provenance for any prior assessment reports used as lessons.
- Confidentiality, trade-secret and contractual restrictions affecting prior work.
- Whether the product name/mark “BRI” is available and appropriate.
- Open-source and commercial dependency licenses, notices, source obligations and patent terms.
- Rights to customer-provided data, extracted content, derived knowledge, prompts, embeddings, analytics and backups.
- Cross-border transfers, subprocessors, retention, deletion, audit, export and incident obligations by target sector/jurisdiction.
- Model/provider terms for retention, training, subprocessors, residency, intellectual property and output use.

Until resolved, do not make legal guarantees or import disputed materials.

## 2. Dependency categories

| Category | Examples/options | Required control / unresolved question |
|---|---|---|
| Runtime/framework | UI, API, workers, language/runtime | Approve supported versions, security updates, private package strategy and licenses. |
| Database/search | relational DB, object store, full-text/vector index | Confirm tenancy, encryption, backup, portability, licensing and support. |
| Identity | customer IdP, federation protocol | Define supported protocols and customer responsibility. |
| AI/model | hosted or self-hosted model, embedding, reranker | Approve per data class, deployment and contract; no default provider. |
| Extraction | CSV/XLSX/PDF parsers, OCR, malware scanning | Review licenses, sandboxing, format limits, languages and retention. |
| Integration | Power BI, SharePoint, Cognos, future connectors | Each connector requires scope, API terms, credential ownership and security review. |
| Observability | logs, traces, metrics, error tracking | Ensure data minimization, residency, tenant separation and retention. |
| Packaging/operations | containers, orchestrator, CI/CD, signing | Select only after deployment profile and customer operations are known. |

These examples are categories/options, not selected vendors or installed dependencies.

## 3. Data rights and lifecycle questions

For each source and customer contract, define who owns source data, derived/extracted content, validated knowledge, annotations, generated outputs, metrics, audit metadata, embeddings and backups. Define permitted purposes, access, correction, export, deletion, legal hold, model training prohibition/permission, portability on termination, and responsibility for source-system synchronization. These are legal/product decisions, not inferred from technical storage.

## 4. Approval gates

Before code dependencies: legal/license inventory and architecture approval. Before customer data: data-processing terms, classification, DPIA/privacy/security review as applicable, retention/deletion and incident responsibilities. Before external model use: provider and data-flow approval for the specific deployment and data classes. Before connector release: API terms, security review, least-privilege scope and revocation/deletion behavior. Before launch: ownership, notices, support and vulnerability-response process.

## 5. Open owners

Accountable legal reviewer, product owner, security owner, data-protection/privacy lead, deployment operator, connector owner and AI/provider approver are not named in the initiating brief. Assign them before relevant gates.
