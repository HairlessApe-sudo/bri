# BRI Intelligence Architecture

Status: Proposed separation of Knowledge Intelligence, Decision Intelligence and AI orchestration

## 1. Two connected intelligence capabilities

Knowledge Intelligence operates over governed organisational knowledge: locate, relate, summarise and explain information with sources, scope and uncertainty.

Decision Intelligence operates over structured historical decisions and their evidence, recorded reasoning, actions and outcomes: investigate what was decided, what was documented, how records relate, and what patterns appear. A historical decision is evidence that an organisation recorded that decision, not proof the decision was correct. Missing reasoning/outcome remains unknown, not generated as historical fact.

Both capabilities share tenant/policy, provenance, retrieval and response contracts. Their record semantics and evaluation remain distinct.

## 2. Proposed request lifecycle

1. Authenticate principal and resolve active tenant/membership.
2. Authorize operation, purpose, time range and permitted data scope.
3. Clarify ambiguity or produce a structured query/analysis specification.
4. Retrieve only permitted knowledge, source versions, decisions and evidence.
5. Revalidate access, lifecycle and source version.
6. Assess evidence sufficiency, contradiction, recency and missing data.
7. Use deterministic calculations/tools where appropriate; call a permitted model only for capabilities requiring it.
8. Validate output schema, citations, scope and claims where feasible.
9. Return supported facts, calculations, summaries, inferences, recommendations and unknowns distinctly, with limitations and citations.
10. Record minimised audit/usage metadata and policy/model/configuration versions.

If evidence is insufficient or access cannot be established, fail closed, ask for clarification or abstain according to an approved policy.

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
