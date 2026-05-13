# ADR-009: Multi-Audience Token Revocation Semantics

**Status**: Accepted
**Date**: 2026-05-08
**Deciders**: Architecture Team

## Context

jwtauth supports multi-audience refresh tokens. A token issued with
`WithAudience("svc-payments", "svc-reports")` carries both audience values in its stored
`RefreshToken.Audience []string` field, and the Redis audience-index sets for both values
include the token's ID.

When `RevokeAllForAudience(ctx, "svc-payments")` is called, every token whose audience
list contains `"svc-payments"` is revoked — including tokens that also list other audiences.
For the token above, this means `svc-reports` can no longer use the token either. The
revocation is global, not scoped to the targeted audience.

This behaviour has been present since v0.5.0 and is expressed in the `RefreshStore`
interface contract:

> "A token with multiple audiences is revoked globally — not per-audience — so every
> service the token could reach is invalidated when any one of its audiences is targeted."

The behaviour is correct and intentional but had not been formally documented beyond a
one-line note in `UPGRADING.md`.

## Decision

**A refresh token is a single session grant. Revocation is applied to the token record —
not to individual audience entries within that record.**

When any targeted audience value matches one of a token's listed audiences, the entire
token is revoked. This applies to both `RevokeAllForAudience` and
`RevokeAllForUserAndAudience`.

The `RefreshToken` struct carries a single `Revoked bool` flag. There is no per-audience
revocation state. This is not a limitation — it is the correct model for a session
credential.

## Alternatives Considered

**Per-audience revocation flags on the token record** — Rejected. This would require an
`audienceRevoked map[string]bool` field on `RefreshToken` and corresponding changes to
`Revoke`, `Retrieve`, `RevokeAllForAudience`, and `RevokeAllForUserAndAudience`. It models
"partial authorization" within a single session credential, which creates a confusing
security surface:

- A token is simultaneously valid for one service and revoked for another.
- `Retrieve` would need a per-audience call signature, breaking the interface.
- The revocation state of a token becomes context-dependent, making audit and
  introspection ambiguous — `IntrospectToken` would need to return a per-audience status
  rather than a single `Revoked` flag.
- Any implementation gap (e.g., missing an audience during partial revocation) silently
  leaves access open.

**Issue separate tokens per audience** — This is the recommended pattern when independent
revocability per audience is required. Callers should issue distinct tokens for each
downstream service rather than bundling multiple services into one credential. The
`WithAudience` option on all six issuing methods makes this straightforward.

## Consequences

**Positive:**
- Revocation semantics are simple and unambiguous: one token, one `Revoked` state.
- `IntrospectToken` returns a single `Revoked bool` that is accurate regardless of how
  many audiences the token covers.
- No schema changes to `RefreshToken` are needed. The interface contract is stable.
- For audience-based session flows — where revoking access to any service should end the
  session globally — this is the correct and desired behavior.

**Operator guidance:**
- Design audience schemes with global revocation in mind. A multi-audience token is an
  atomic authorization unit. Revoking for any one of its audiences revokes access to all
  of them.
- If a service requires the ability to revoke its own authorization independently of other
  services sharing the same token, issue separate tokens per service at issuance time using
  `WithAudience`.

**Implementation note — Redis concurrency:**
`RevokeAllForAudience` uses an SSCAN loop to enumerate the audience index set, followed by
a pipelined HSet to mark tokens revoked. These two steps are not wrapped in a MULTI-EXEC
transaction. Tokens issued between the SSCAN completion and the pipeline execution may not
be captured by the current call. This is an acceptable best-effort characteristic — callers
who need strict guarantees should ensure that new token issuance for the targeted audience
is quiesced at the application layer before calling revocation. `MemoryRefreshStore` does
not have this gap — all reads and writes within a revocation call are protected by a single
`sync.RWMutex`.

## References

- Related: ADR-002 (Stateful Refresh Tokens) — established the opaque, server-side refresh
  token model that this decision elaborates on
- Issue #135 — introduced `RevokeAllForAudience` and `RevokeAllForUserAndAudience`
- Issue #182 — formalized this decision in an ADR
- `doc/UPGRADING.md` v0.5.0 section — operator-facing note on this behavior
- `doc/DEPLOYMENT.md#audience-scoped-revocation` — operational patterns and use cases
