# BRI Knowledge Architecture

Status: Proposed knowledge lifecycle and retrieval design

## 1. Knowledge is governed, not merely indexed

The Knowledge Infrastructure converts incoming information into traceable, scoped and governed knowledge. It preserves separate representations for:
1. Original source object and source-system identity.
2. Immutable source/version metadata and content hash where available.
3. Extracted text, tables, structure and source locations.
4. Machine/human interpretation and classification proposals.
5. Review decisions and validated knowledge records.
6. Search/index projections and generated responses.

A vector index or extracted text is not the authoritative source. A model-generated answer is not automatically organisational knowledge.

## 2. Proposed lifecycle

Receive → authenticate and resolve tenant → quarantine → validate type/size and scan → register source/version → extract in isolated processing → normalise without altering original → classify and assess sensitivity → apply deterministic policy → route for human review as required → create candidate knowledge with provenance → approve/publish to scoped collection → index → monitor, supersede or delete.

Jobs must be idempotent, observable and safely retryable. Unknown sensitivity defaults to restricted/quarantined pending policy. AI classification is a proposal, not sole approval for high-sensitivity content.

## 3. Source and knowledge model

Potential source types: API records, CSV, Excel, PDF and future connectors. Each source reference should include tenant, source identity, external object key, import time, version/hash, owner/scope, retention category and lifecycle.

A knowledge record should include type, title/content or structured data, tenant and collection, scope/classification, validation status, effective/valid time where relevant, recorded/validated time and actor, rules/model version if derived, and provenance links to exact source version/location. Knowledge relationships are typed and evidence-linked. Customer-specific taxonomies should be configurable with validation; universal ontology details are open.

## 4. Classification and validation

Combine deterministic customer rules, source metadata, content signals, approved taxonomies and AI-assisted suggestions. Keep proposed and approved values distinct, record confidence/author/tool/version, and allow authorized correction/rejection. Define reviewer requirements by data class and use case. Human validation is mandatory before interaction-derived material becomes shared organisational knowledge.

## 5. Retrieval and indexing

Candidate architecture: full-text + vector/hybrid retrieval with tenant, collection, node, classification, lifecycle, temporal and policy filters. Search ranking can consider semantic/lexical relevance, source quality, validation state and recency. Similarity is not permission, evidence authority, or calibrated confidence. The access policy is enforced before content is available to the model and rechecked before citations/response.

Indexes store source/version/location and index-generation identifiers and can be rebuilt. Access changes, supersession and deletion trigger reindex/invalidation or read-time revalidation. Provider/model/dimension changes require versioned re-embedding; do not mix vector spaces silently.

### Implemented: A11.4-P1 current read authorization

A logical knowledge record uses the existing tenant-qualified `source_id`; a version uses that record and its `source_version_id`. The public `record_id` still identifies a specific validated proposal, linked to one exact version through immutable extraction provenance. Multiple publications of a version share its version restriction.

Migration `0020_knowledge_read_authorization.sql` adds independent, tenant-scoped record and version decisions. Only an explicit `readable=true` in **both** tables permits a published version to be considered for display. `false` or a missing decision denies it. Use a version denial when that version is withdrawn, restricted, or superseded and no longer authorized; a record denial restricts every version independently of their individual decisions. The system does not infer supersession from labels, timestamps, or the existence of a newer version. The migration creates no allow rows, and validation does not create an allow decision. Existing publications and provenance are retained; legacy and new content without explicit decisions stay unavailable to readers until reviewed and enabled through the database maintenance boundary. There is no hosted policy-writing or classification-management API.

List, detail, search and source references share `read_authorized_knowledge` in `src/bri/api/app.py`. It loads approved publications through a server-verified tenant read transaction, matches the exact `knowledge:read` node, and joins both current decisions before returning content or provenance. API knowledge responses are not cacheable. Revocation applies to reads using a database snapshot taken after the policy transaction commits; it cannot recall data already delivered or stop a read that is already using an earlier snapshot. The existing separately authorized exact-node proposal/review workflow can still show pending source extraction text and provenance. A published denial is not a source-wide embargo, and review alone grants no published-read access.

Migration `0020` adds the policy state; the updated reader enforces it. A future rollout must not serve pre-P1 knowledge handlers while relying on these decisions. If rolling back the reader, disable the four published read endpoints rather than serving them through handlers that ignore current policy.

Future search indexes, AI retrieval and exports must treat indexed IDs as candidates only; hydrate evidence and provenance through this same current decision boundary using the verified request identity before scoring, passing content to a model, or serializing it. They must not serve cached text, stale snippets, or an earlier authorization result after access changes. No index, AI retrieval or export was added in this prerequisite.

## 6. Extraction and format limits

Product direction includes CSV, Excel and PDF. Define a format capability matrix: tables/layout, formulas, hidden sheets, scanned PDFs, language/OCR, page/row/cell source locations, encrypted/password-protected files, macros and malformed inputs. The proposed MVP should state whether PDF means text-based extraction only; OCR remains uncommitted until technology, languages, quality and security are approved.

## 7. Knowledge lifecycle, retention and deletion

Lifecycle states and transitions require approval; candidate states include received, quarantined, processing, awaiting review, approved, rejected, superseded, archived, deletion pending and deleted. Source change flags dependent knowledge for review. Deletion traverses originals, extracted artefacts, chunks, embeddings, knowledge, intelligence cache, reports and exports, with retention/legal hold governed separately. The legal basis, periods, backup expiry and deletion confirmation are unresolved.

## 8. MVP recommendation

Demonstrate synthetic API and file ingestion, provenance, review of a classification/knowledge candidate, a validated record, permission-aware full-text search and a source-linked result. Keep the index and vector provider replaceable; defer advanced OCR, automated knowledge ontology discovery and broad connector catalog until evaluation demonstrates need.
