# Versioned Prompt Management — Assignment 07C

Status: standalone backend domain component. It is not connected to an API, AI Gateway, model provider, or durable database.

## Purpose and boundaries

`src/bri/prompts/` manages two independent prompt layers:

- Platform layer: one BRS-wide prompt, managed only through the explicit `prompt:platform:manage` platform-scoped grant. It contains BRS-owned operating instructions and is never tenant-editable.
- Client layer: one prompt history per tenant, managed with exact tenant-scoped grants. It is not allowed to replace or mutate the platform layer.

The service accepts only server-resolved `Principal` objects. Role labels alone grant nothing. The identity/role-permission mapping must issue platform grants only to authorized BRS SuperAdmins, tenant-management grants to the correct tenant Admins, and any cross-tenant platform administration grant only to explicitly authorized SuperAdmins.

## Authorization contract

The module uses the existing exact tenant/action/scope authorization primitive for tenant-bound operations:

- Tenant Admin read: `prompt:client:read`, scope equal to the tenant ID.
- Tenant Admin write/approve/activate/restore: `prompt:client:manage`, scope equal to the tenant ID.
- Explicit platform administration of a tenant prompt: `platform:prompt:tenant:manage`, scoped to that exact tenant.
- BRS platform prompt management: `AccessGrant("brs-platform", "prompt:platform:manage", "platform-prompt")`.
- Client Admin reading the active BRS prompt: `prompt:platform:read` scoped to their tenant. This grants active-version read only; platform history and platform audit events remain BRS-only.

Platform SuperAdmins managing the BRS prompt have read access through their manage grant. Assigning these permissions to the four role classes remains an identity/permission-catalog integration task; the standalone component does not infer authority from a role name.

## Version and activation model

`PromptVersion` is immutable and records layer, optional tenant, monotonic version, opaque version ID, server-derived author, timezone-aware creation time, change description, prior-version ID, SHA-256 content hash and content. Restore copies a chosen historical body into a new version and records `restored_from_version_id`; no old row is rewritten.

New versions begin as drafts. An authorized manager explicitly approves a version before activation. Activation uses compare-and-swap on the expected current active version. Creating a version uses compare-and-swap on the expected latest version. The in-memory implementation protects allocation, approval, activation and metadata audit events with one lock. Stale updates fail with a conflict instead of silently overwriting concurrent work.

Audit events are append-only metadata: action/status, version ID, actor, timestamp and content hash. Prompt bodies are not copied into audit events. Activation and deactivation statuses are represented by events rather than mutating historical version records.

`PromptRepository` is the persistence abstraction. A future PostgreSQL implementation should perform expected-latest checks, version insertion and audit insertion in a transaction; use a transactionally guarded active-version pointer; enforce tenant ownership with composite tenant keys and RLS; and prevent ordinary application roles from updating/deleting historical version rows. No migration is included or applied here.

## Prompt assembly contract

`PromptManager.assemble(principal, tenant_id)` requires explicit read authority for both layers and active approved versions for both. The repository returns both active versions from one consistent snapshot, preventing platform/client activation races from producing a mixed read. Missing active content fails closed. It returns a deterministic `AssembledPrompt` with exactly two ordered sections:

1. `trusted_platform` — the active BRS version.
2. `untrusted_tenant_instruction` — the active tenant version.

The sections remain separate typed values, not a concatenated prompt string. `PromptProvenance` binds both version IDs, sequence numbers and content hashes. Assembly has no clock/randomized decoration, so the same active revisions produce the same result.

The future Gateway must consume the platform section in its trusted system/developer channel and keep the client section in a lower-trust instruction/context channel; it must not merge them at equal priority or let a tenant value replace platform policy. It must apply authorization and Privacy Shield checks independently of prompt wording, revalidate the selected versions/provenance, and screen every provider-bound prompt, user input, attachment and retrieved item through Privacy Shield before any external model call. This component does not authorize provider egress.

## Validation and risk

Prompt text must be a non-empty valid Unicode string, no more than 32,000 characters, with no NUL/disallowed control characters. Change descriptions are bounded. The validator rejects common credential forms (including private-key headers, selected vendor key formats and credential-style assignments) before storing versions; this is only a conservative guard, not a complete secret scanner. Prompt bodies are excluded from version/audit representations where practical, but remain accessible to authorized in-process callers.

Client text is always represented as lower-trust content. Prompt assembly cannot eliminate prompt injection or make arbitrary instructions safe. The Gateway must enforce tool permissions, data access, output policy and the mandatory Privacy Shield boundary outside the prompt text. Tests use synthetic tenants/prompts only.

## Planned integration

- AI Gateway: call the authorized assembler, preserve the separate trust channels, enforce current version provenance, and independently apply Privacy Shield before provider egress. No Gateway/provider integration is present.
- Privacy Shield: remain mandatory for every provider-bound prompt and other input; this module does not replace or weaken it.
- Tenant configuration: provide server-verified tenant context and the explicitly authorized prompt read/manage grants; no caller-selected tenant is trusted.
- Admin interface: a future UI can expose draft/version comparison, approval, activation, restore and audit status by calling an authenticated server API. No UI/API routes are included.
- Persistent storage: replace `InMemoryPromptRepository` with a PostgreSQL adapter implementing atomic compare-and-swap, append-only history, RLS and metadata-only audit. In-memory data is lost on process exit and is not production durable.
