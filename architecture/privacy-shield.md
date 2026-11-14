# Privacy Shield Foundation

Status: standalone local implementation for Assignments 07 and 07B. This is not an AI Gateway and is not connected to any provider egress path.

## Scope and components

`src/bri/privacy/` is a text-processing domain module with no network calls or AI-provider dependencies.

- `SignatureDetector` retains the Assignment 07 baseline for Dutch BSN (elfproef), email, Dutch and international-format phone, checksum-validated IBANs for its explicit country-length registry, contextual bank-account numbers, Dutch-style postal addresses, valid dates in birth-date context and legacy tenant literal signatures/terms. Jurisdiction-specific checks are explicitly gated; `RegionalSignatureDetector` composes mandatory global detection with only the tenant's selected regional packages and de-duplicates identical `(category, start, end)` findings. Distinct categories and distinct overlapping spans remain separate.
- `RegionalSignatureRegistry` defines independently versioned `global`, `netherlands` and `australia` packages. Global signatures always run. The primary jurisdiction activates only its corresponding regional package; extra regions are enabled only through explicit configuration. Missing/unavailable selected packages raise a generic configuration error and the processing service blocks. Initial regional signatures include Dutch BSN/phone/address checks and an Australian labelled, checksum-validated TFN check; country-specific identifiers are not run across jurisdictions.
- `Detector` is a protocol so later BRS-managed local/contextual detectors can be composed. `TenantSignatureManager` provides tenant-scoped create/read/update/deactivate/history/restore and synthetic-example testing. Signature changes require a trusted `Principal` carrying an exact tenant-scoped `privacy:signature:manage` grant; jurisdiction/additional-package changes require `privacy:configuration:manage`. Inspection/history/test can use the corresponding `:read` grant; manage grants also permit reads. Role claims or caller-supplied tenant IDs alone are insufficient. Tenant signatures can add detections only; their category is restricted to tenant-sensitive, and they cannot alter the engine or platform policy floor.
- Tenant regexes use a conservative Python-regex subset: no groups, alternation, lookarounds, backreferences or unbounded quantifiers; at most one finite quantifier with bounds no greater than 64; pattern length is capped at 128 and synthetic/process test text at 100,000 characters. Arbitrary code is not accepted. Literal signatures remain supported.
- `PrivacyShieldConfig` and append-only in-memory stores version jurisdiction/additional-region settings and tenant signature snapshots. Restore appends a new revision. The registry's engine and package version labels are independent; effective configuration versions are deterministic fingerprints over tenant config, selected package versions and tenant-signature revision. `SignatureVersionProvenance` is included in every successful configured processing result and bound into the signed Gateway envelope.
- `InMemoryTenantSignatureStore`, `InMemoryShieldConfigurationStore` and `MappingSignatureConfigurationProvider` are local/test reference implementations only. They are process-local and non-durable. Persistent deployments need a separately approved tenant-isolated repository, durable append-only history, transactional version allocation and role-permission mapping; no database migration is included in Assignment 07B.
- `TenantPolicy`, `PlatformPolicy` and `PolicyEngine` evaluate allow/mask/block rules deterministically. The platform floor cannot allow a detected category through: every finding is at least masked, and tenant rules can only make handling more restrictive.
- `PrivacyShieldService.process(ProcessingRequest)` validates context, input type, purpose, destination and text size, requires a versioned tenant signature-configuration provider, detects, evaluates policy, masks or blocks, returns typed metadata with signature provenance, and records a safe audit summary. Missing tenant configuration/package, invalid context/configuration, detector/policy/audit failures, and AI-envelope failures block processing. The Assignment 07 unversioned constructor path is no longer permitted for content processing.
- `TenantContextAuthority` issues short-lived signed processing contexts only for `privacy:process`; the signed fields include tenant, principal, action, resource scope, input type, purpose and destination. Its issuer must be held behind BRI's existing authentication/authorization checks. This module is not wired to that boundary and does not make a caller-supplied tenant ID trustworthy.
- `ShieldAttestor` produces short-lived HMAC `GatewayEnvelope` attestations only for AI-provider destinations. The envelope binds exact sanitized content, tenant and resource scope, input type, purpose, destination, allow/mask decision, policy IDs/versions, signature-engine/package/tenant/configuration versions, detection counts and expiry. Verification requires the future Gateway to provide expected tenant, scope, input type, purpose and destination from its own trusted request context. Tampered, stale, blocked or non-AI envelopes are rejected.
- `AuditSink` accepts metadata-only `AuditSummary` objects. `InMemoryAuditSink` is for tests/local use; no durable audit persistence is implemented.

HMAC keys are injected at trusted server composition, never placed in request payloads or logs. Because HMAC verification requires the secret, do not distribute the signing key to an untrusted or lower-trust Gateway. If Shield and Gateway become separate trust domains, use a verifier-only service or an asymmetric signature scheme before integration.

## Security and enforcement boundary

This package is only a building block. Assignment 07 does not connect it to the existing API authorization flow, document parsing/extraction, database audit storage, retrieval, workers, attachments or an AI Gateway. No provider call exists in this change. Do not interpret `ProcessingStatus.APPROVED` as authorization to call a model except through a future Gateway that independently verifies the exact envelope and request scope.

For future integration:

1. Authenticate and authorize the principal, tenant, action, purpose and exact resource scope using the existing BRI boundary before issuing `TenantContext`.
2. Process each document, case, question, attachment and retrieved item under its own authorized scope; do not omit items when assembling model context.
3. Load only approved policy for the verified tenant. Never fall back to another tenant's policy or a weaker default.
4. Give the Gateway only sanitized content plus the signed envelope. Derive expected tenant/scope from Gateway-side authorization state, verify the envelope and reject missing, expired, altered, wrong-purpose, wrong-scope or non-AI content before every provider call.
5. Ensure no alternate API, ingestion worker, connector or background job can call a provider around that gate. Add integration tests for every provider-bound entry point before enabling egress.
6. Keep audit storage content-free and access-controlled; add retention, key rotation and failure monitoring before production use.

## Detection limitations

The detector is intentionally signature-based and incomplete. It can miss unstructured names, novel identifiers, OCR-only content, context-dependent sensitive information, unsupported IBAN countries, misspellings and formats outside its patterns. Heuristics can also produce false positives. Passing the detector is not evidence that text contains no personal or sensitive information and is not an AVG/GDPR compliance determination. No real client information or network detector is used by the tests.

## Local verification

Run the focused synthetic suite from the repository root:

```bash
PYTHONPATH=src .venv/bin/python -m unittest tests.test_privacy_shield tests.test_privacy_policy tests.test_privacy_service -v
```

The detector and policy results expose categories, spans/counts and policy metadata, not matched substrings. Raw request text, tenant literal values, sanitized content and HMAC context proofs are excluded from public dataclass representations. This reduces accidental leakage but does not protect callers that deliberately inspect in-process objects or memory.
