# ADR-010: JTI Uniqueness and Replay Prevention Stance

**Status**: Accepted
**Date**: 2026-05-20
**Deciders**: Architecture Team

## Context

Every access token issued by jwtauth carries a `jti` claim — a UUID v4 value generated
by `uuid.New().String()` at issuance time (one per token, never reused). The `jti` is
cryptographically bound to the token payload at RS256 signing — the payload cannot be
altered post-issuance. The value is surfaced through `IntrospectToken` as
`TokenMetadata.TokenID`, logged as a structured key (`"tokenID"`) on issue and validate
operations, and set as a span attribute (`"token_id"`) for distributed tracing.

Despite this, jwtauth performs no JTI-based replay prevention for access tokens.
`ValidateAccessToken` verifies the RS256 signature, issuer, audience, and expiry — but
does not consult a JTI revocation cache. A stolen, unexpired access token could be replayed
until it expires.

Security-focused operators and compliance reviewers frequently ask about the JTI threat
model. The absence of a formal stance leaves the design implicit and undiscoverable.

## Decision

**jwtauth does not perform JTI-based replay prevention for access tokens.**

The `jti` claim serves as a unique, auditable identifier for correlation across log, trace,
and metric pipelines. It is not used as a revocation key.

## Rationale

**Short-lived access tokens mitigate the replay window.** Access tokens are designed to be
short-lived (minutes, not hours). Replay within that window is a residual risk the operator
controls by tuning the access token TTL. JTI tracking adds latency and storage overhead to
every validation call without eliminating the window — it only narrows it.

**Refresh tokens already provide replay prevention for the refresh flow.** Refresh tokens
are stateful and stored in `RefreshStore`. `RevokeRefreshToken` marks the token revoked;
subsequent calls to `RefreshAccessToken` check the revocation flag and return
`ErrTokenRevoked`. A revoked refresh token cannot produce new access tokens. Token rotation
(`RefreshAccessToken`) also revokes the consumed refresh token immediately after issuing a
new one, preventing replay of the old refresh token.

**JTI tracking duplicates the existing RefreshStore model at scale.** Replay prevention
for access tokens requires a shared revocation store (e.g. a Redis SET) with at-least-TTL
retention, consulted on every `ValidateAccessToken` call. This is structurally identical
to `RefreshStore` but adds latency on the hot validation path. The library's positioning
— post-login token lifecycle management, not a general-purpose security layer — makes this
a caller concern, not a library concern. Operators who need it can add it in middleware.

**The `jti` value is still useful.** Even without replay prevention, a unique `jti` per
token enables precise audit trails, distributed log correlation, and incident response.
`IntrospectToken` exposes the `jti` via `TokenMetadata.TokenID`, making it available to
callers who need to build revocation indexes at the application layer.

## Consequences

**Operators must accept the residual replay window for access tokens.** A stolen,
unexpired access token can be replayed until it expires. The window is bounded by the
access token TTL configured on the `Manager`.

**Operators requiring JTI-based replay prevention must implement it in middleware.** The
recommended pattern:

1. After `ValidateAccessToken` succeeds, check the `jti` claim against a Redis SET (or
   equivalent shared store) keyed by tenant/namespace.
2. On first use: add the `jti` to a deny-list SET with TTL equal to the remaining token
   lifetime.
3. On subsequent requests: reject tokens whose `jti` appears in the deny-list before
   calling `ValidateAccessToken`.

This can be wired transparently in an HTTP middleware layer without changing the jwtauth
API surface.

**`jti` is suitable for audit logging and correlation.** Every issuance, validation,
and refresh operation in jwtauth logs and traces the `jti` (`"tokenID"` in structured
logs, `"token_id"` span attribute). Operators can correlate token lifecycle events across
distributed services using this value.

**This stance is consistent with the library's positioning.** jwtauth manages post-login
token lifecycle — issuance, rotation, revocation of refresh tokens, and audience-scoped
cleanup. It is not a general-purpose security layer. Replay prevention for access tokens
is an application-layer concern.

## References

- Related: ADR-002 (Stateful Refresh Tokens) — establishes the refresh token revocation
  model that provides replay prevention for the refresh flow
- Related: ADR-005 (Security Boundaries) — covers the validation-side trust model for
  `jti` and other claims
- Issue #185 — formal documentation of this stance
- RFC 7519 §4.1.7 — `jti` (JWT ID) Claim
