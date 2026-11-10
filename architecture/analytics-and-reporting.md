# BRI Analytics and Reporting Architecture

Status: Proposed domain and control model; metric semantics and outputs require product approval

## 1. Purpose

Analytics and reporting turn governed knowledge, decisions, outcomes and permitted source information into scoped, explainable outputs. They are a distinct platform capability, not merely an LLM response or an ungoverned query over raw tenant tables.

## 2. Proposed report flow

Natural-language request or API request → resolve tenant/principal and authorization → compile a structured report specification (question, scope, filters, period, dimensions, metrics, method, sources, output) → validate policy and query limits → deterministic data retrieval/calculation → optional model-assisted narrative constrained to results → citation/provenance validation → present report with scope, methodology, freshness, limitations and evidence → audit and export only to approved destinations.

## 3. Data and metric controls

- Metric definitions are versioned and have owner, meaning, formula, dimensions, inclusion/exclusion rules and effective date.
- Deterministic calculations are preferred for counts, sums, rates and comparisons; models may explain but must not invent numeric results.
- Reports record data snapshot/query time, source versions or index generation, metric-definition version, policy scope and calculation code/config version sufficient for the chosen reproducibility level.
- Distinguish descriptive correlation/trend from causal explanation.
- Surface missing, conflicting, stale or unvalidated data.
- Apply tenant/resource filters before aggregation; prevent small-cell disclosure where customer policy requires it. Thresholds and suppression rules are unresolved.

## 4. Dashboards and APIs

Dashboard definitions should be customer-configurable within an approved metric catalogue and permission model. The same report specification should be addressable through the BRI interface and versioned API where feasible. External analytics tools should consume explicitly scoped APIs/exports, not direct access to internal database tables. Power BI, SharePoint and Cognos are examples of future consumers, not MVP integrations or configured services.

## 5. Options

- Compute-on-read: simpler freshness, but may increase load and complicate reproducibility.
- Precomputed/materialized reports: faster and useful for dashboards, but introduce stale-data, cache invalidation and policy-revocation risks.
- Recommendation: begin with bounded compute-on-read for a small synthetic report set; add versioned materializations only after performance need and invalidation design are proven.
- LLM-only narrative: flexible but weakly reproducible. Recommendation: structured specification + deterministic calculation + optional constrained narrative.

## 6. Open decisions

Define MVP metrics and owners; report snapshot semantics; permitted free-form filters; privacy-safe aggregation; export formats; report retention/deletion; API pagination and versioning; cache scope and invalidation; model use for narrative; and report reproducibility guarantees. No quantitative or sector-specific metric is assumed by this document.
