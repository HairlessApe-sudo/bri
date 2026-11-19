# Provider MFA: verified claims and admin wire contract

**Status: upstream contract checked, mock transport tested, hosted execution blocked.** No privileged provider endpoint is enabled by this adapter. Documentation and local mocks are not evidence that a deployed project uses a particular Auth release or that any factor has been removed.

## Evidence delivered to the session and recovery code

The API inspects AMR only after the pinned Auth user endpoint accepts the exact token and the verifier checks issuer, subject, session, audience, role, time claims, AAL2 and an enrolled verified TOTP factor. Supabase documents `password`, `recovery`, `otp`, `magiclink` and `token_refresh` as distinct methods. Its TypeScript definitions include both `totp` and `mfa/totp`; token hooks may also emit method strings with no timestamps. [JWT claims reference](https://supabase.com/docs/guides/auth/jwt-fields) · [Auth JS method names and shapes](https://github.com/supabase/supabase-js/blob/f5013780c00ae1796922a103f659ded2e2503c00/packages/core/auth-js/src/lib/types.ts#L371-L408)

| Interface | BRI interpretation |
|---|---|
| `identity.totp_authenticated_at` and `has_recent_mfa(identity)` | One structured TOTP event across both spellings. Require a positive integer Unix time, not in the future; check the inclusive 900-second window at action time. Aliases normalize to `totp` in `assurance_methods`, but duplicates cannot establish freshness. |
| `identity.primary_authenticated_at` | Timestamp of a single unambiguous native password authentication. |
| `identity.recovery_authenticated_at` | First-factor time **for comparing against a recovery cutoff only**: one unambiguous `password` or explicit `recovery` event. Ordinary OTP, magic link, and MFA recovery codes are not inferred to mean account recovery. No AMR event proves the password was changed or that recovery completed. |

Times are integer Unix seconds or `None`. Untimed strings and mixed string/object arrays supply no clock, and refreshed token `iat` is never a substitute. Legacy identity constructors supply no clock. The SSR `recoveryState` check is for presentation only; neither browser data nor rendering a form authorizes a mutation. Session expiry remains independent of step-up.

## Privileged wire contract (not the SDK return type)

Relative to the pinned project’s `/auth/v1` base, the upstream [OpenAPI paths](https://github.com/supabase/auth/blob/10ef10789d1ee4fb422b448047e67e3e264c0482/openapi.yaml#L1992-L2090), [admin router](https://github.com/supabase/auth/blob/10ef10789d1ee4fb422b448047e67e3e264c0482/internal/api/api.go#L379-L398), and [Go handlers](https://github.com/supabase/auth/blob/10ef10789d1ee4fb422b448047e67e3e264c0482/internal/api/admin.go#L661-L693) agree:

| Request | Documented HTTP 200 body |
|---|---|
| `GET /admin/users/{userId}/factors` | A top-level JSON array of factor objects, **not** `{"factors": [...]}`. Select only `factor_type == "totp"` and `status == "verified"` for the caller’s approved-factor snapshot. |
| `DELETE /admin/users/{userId}/factors/{factorId}` | The deleted factor object. BRI discards the body: it is not a receipt establishing absence. |

Both routes require admin authentication; `userId` and `factorId` are UUID path parameters. The [Auth JS admin methods](https://github.com/supabase/supabase-js/blob/f5013780c00ae1796922a103f659ded2e2503c00/packages/core/auth-js/src/GoTrueAdminApi.ts#L874-L925) call these paths and wrap the list for SDK consumers. The adapter targets the HTTP contract, not that wrapper.

`ProviderMfaAdmin()` is disabled. Only `test_transport=httpx.MockTransport(...)` enables an in-process test with synthetic headers. There is no key/environment lookup, network transport, redirect handling to another origin, or web credential. `list_totp_factor_ids(user_id)` returns sorted ID strings. `remove_totp_factor(user_id, factor_id)` requires the exact approved canonical UUIDs: pre-list, at most one DELETE, then re-list after success or an ambiguous result. An already absent target requires no DELETE; a present but now ineligible factor is not removed. The full inventory must establish absence, not merely loss of verified status. A failed list or inconclusive removal raises `ProviderMfaError`. This checks provider state only, not authorization, durable execution, session invalidation or reenrollment.

## External gate — not exercised

Keep hosted administration disabled. A separately authorized isolated provider project and disposable user would be required to validate the deployed Auth version, actual signed AMR on login/recovery/challenge/refresh, and admin list/delete/list on a specifically approved factor. Verify non-target factors survive and ambiguous responses do not cause a second mutation. Credential isolation, durable authorization and reconciliation, session invalidation, and trusted confirmation of credential changes are separate prerequisites. No hosted credential, user, factor or project setting was accessed for this check.
