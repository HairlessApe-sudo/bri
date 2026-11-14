# BRI Intelligence Architecture

Status: Proposed separation of Knowledge Intelligence, Decision Intelligence and AI orchestration

## 1. Two connected intelligence capabilities

Knowledge Intelligence operates over governed organisational knowledge: locate, relate, summarise and explain information with sources, scope and uncertainty.

Decision Intelligence operates over structured historical decisions and their evidence, recorded reasoning, actions and outcomes: investigate what was decided, what was documented, how records relate, and what patterns appear. A historical decision is evidence that an organisation recorded that decision, not proof the decision was correct. Missing reasoning/outcome remains unknown, not generated as historical fact.

Both capabilities share tenant/policy, provenance, retrieval and response contracts. Their record semantics and evaluation remain distinct.

## 2. Mandatory Privacy Shield and proposed request lifecycle

The Privacy Shield is a required server-side boundary for every model-bound item. Documents, historical cases, user questions, attachments, retrieved passages and background-job inputs must be screened before any AI provider receives them. The browser cannot bypass it. The AI Gateway must reject a call unless a trusted server component supplies a current, request-bound pass covering all content and the selected provider/purpose.

Signature-based detection of AVG/GDPR-sensitive information is mandatory. It is only a baseline: add extensible detection and policy stages (such as named-entity recognition, contextual sensitivity classification, tenant/purpose policy, and escalation/review) and fail closed if any required check is missing, unavailable or uncertain. Redact/tokenize/minimize before provider egress; keep mappings and raw content within BRI-controlled boundaries. A signature pass is not a legal-compliance guarantee. No such Privacy Shield or AI Gateway enforcement is currently implemented in the repository; the present question-answering path is deterministic/local and no external model call is present in the inspected application code.

1. Authenticate principal and resolve active tenant/membership.
2. Authorize operation, purpose, time range and permitted data scope.
3. Clarify ambiguity or produce a structured query/analysis specification.
4. Retrieve only permitted knowledge, source versions, decisions and evidence.
5. Revalidate access, lifecycle and source version.
6. Assess evidence sufficiency, contradiction, recency and missing data.
7. Pass every provider-bound input through the Privacy Shield and verify its server-generated attestation in the AI Gateway; reject if any item is unchecked or disallowed.
8. Use deterministic calculations/tools where appropriate; call a permitted model only after the gateway accepts the shielded request.
9. Validate output schema, citations, scope and claims where feasible.
10. Return supported facts, calculations, summaries, inferences, recommendations and unknowns distinctly, with limitations and citations.
11. Record minimised audit/usage metadata and policy/model/configuration versions without storing sensitive prompt content by default.

If evidence, access, shield status or policy cannot be established, fail closed, ask for clarification or abstain according to an approved policy. No provider adapter, ingestion worker, attachment processor or alternate API may call around the gateway.

## 3. Provider-independent orchestration

Define capability interfaces, not only a generic “chat” API: text generation, structured output, embeddings, reranking, OCR/vision and tool calling when required. Declare each provider/model’s capabilities, limits, data handling, supported formats and version. Routing is constrained by deployment, tenant, purpose, classification, cost/latency policy and explicit approvals.

Credentials are external secret references. Responses record provider/model/config version, prompt/template version where relevant, retrieval/index generation, timings and usage without storing sensitive prompt content by default. Fallback is not automatic across data-handling boundaries. Embedding model changes create a new index generation and controlled reindex.

## 4. Evidence and response contract

Every important factual claim/report item should reference accessible source type, identifier, version, location and retrieval rank/support rationale where available. Citation validation verifies existence, version and permission; it does not by itself prove logical support. Evaluation and human review remain necessary for high-impact uses.

Distinguish:
- Direct source-backed statement.
- Deterministic calculation and its inputs/method.
- Summary of evidence.
- Inference or hypothesis.
- Recommendation.
- Conflicting or missing evidence.
- Unknown/not recorded.

Do not expose inaccessible source titles or existence through errors, citations, counts or response timing.

## 5. Agent and tool surface

Applications/agents call the same governed APIs as human clients. Tools are explicit capabilities with scopes, quotas, tenant context, purpose, audit and revocation. The model cannot call arbitrary network endpoints, change policy, choose an unauthorized tenant, or access broad service credentials. Tool authorization is independent of model output.

## 6. Evaluation and reliability

Maintain synthetic, permission-aware evaluation sets for retrieval relevance, citation precision, source-version correctness, unsupported-claim rate, abstention, contradictions, temporal reasoning, decision attribution, prompt injection, tenant leakage and provider regression. Score by task and tenant configuration; no universal “accuracy” number substitutes for task-specific acceptance. Thresholds and human review triggers are unresolved.

## 7. MVP boundary

Proposed first slice: retrieve a validated knowledge record or generic decision plus evidence from two synthetic tenants, run a simple evidence-grounded question, return citations and explicit insufficiency, and expose the same result through an API and minimal BRI UI. Use mock/local provider adapters first; live external models require separate approval. Advanced autonomous agents, broad tool execution and generative analytics are out of MVP.
