# Privacy Shield Foundation

Status: standalone local implementation for Assignment 07. This is not an AI Gateway and is not connected to any provider egress path.

## Scope and components

`src/bri/privacy/` is a text-processing domain module with no network calls or AI-provider dependencies.

- `SignatureDetector` implements deterministic, local signatures for Dutch BSNs (including the elfproef), email addresses, Dutch and international-format phone numbers, checksum-validated IBANs for its explicit country-length registry, bank-account numbers only when labelled by account context, recognizable Dutch-style postal addresses, valid dates in birth-date context, and tenant-configured literal signatures/terms.
- `Detector` is a protocol so later local or contextual detectors can be composed without changing the processing service. Tenant signatures are literals, not administrator-supplied regular expressions.
- `TenantPolicy`, `PlatformPolicy` and `PolicyEngine` evaluate allow/mask/block rules deterministically. The platform floor cannot allow a detected category through: every finding is at least masked, and tenant rules can only make handling more restrictive.
- `PrivacyShieldService.process(ProcessingRequest)` validates context, input type, purpose, destination and text size, detects, evaluates policy, masks or blocks, returns typed metadata, and records a safe audit summary. Invalid context/configuration, detector/policy/audit failures, and AI-envelope failures block processing.
- `TenantContextAuthority` issues short-lived signed processing contexts only for `privacy:process`; the signed fields include tenant, principal, action, resource scope, input type, purpose and destination. Its issuer must be held behind BRI's existing authentication/authorization checks. This module is not wired to that boundary and does not make a caller-supplied tenant ID trustworthy.
- `ShieldAttestor` produces short-lived HMAC `GatewayEnvelope` attestations only for AI-provider destinations. The envelope binds exact sanitized content, tenant and resource scope, input type, purpose, destination, allow/mask decision, policy IDs/versions, detection counts and expiry. Verification requires the future Gateway to provide expected tenant, scope, input type, purpose and destination from its own trusted request context. Tampered, stale, blocked or non-AI envelopes are rejected.
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
