# ADR-008: Reserved Claims Protection at Token Issuance

**Status**: Accepted  
**Date**: 2026-04-29  
**Deciders**: Architecture Team

## Context

jwtauth exposes `CustomClaims` (a `map[string]interface{}`) on `IssueAccessTokenWithClaims`
and `IssueTokenPairWithClaims` so callers can embed application-specific data in access
tokens. Standard JWT claims — `sub`, `iss`, `aud`, `exp`, `iat`, `nbf`, `jti` — are
controlled by the `Manager` instance and set from its configuration at issuance time.

Without an explicit guard, a caller could pass any of these keys in `CustomClaims` and
silently overwrite the manager-set value. The `aud` claim was missing from the guard until
issue #109 was filed, making the audience overrideable by any caller with access to
`IssueAccessTokenWithClaims`.

Per-call audience override has a legitimate use case — service-to-service tokens targeting
different downstream services from a single manager — but allowing it silently through
`CustomClaims` is the wrong mechanism. It is invisible at the call site, untestable in
isolation, and undermines the manager's security invariants for callers who are unaware of
the interaction.

## Decision

**All standard JWT claims that the `Manager` controls at the instance level are declared
as reserved and silently dropped — with a warning log — if a caller passes them in
`CustomClaims`.**

The reserved set is:

```go
reservedClaims := map[string]bool{
    "sub": true, "iss": true, "aud": true, "exp": true,
    "iat": true, "nbf": true, "jti": true,
}
```

Any key in this map that appears in `CustomClaims` is dropped before the JWT is built.
A `Warn`-level log entry is emitted so the mistake is visible during development and
integration testing.

Per-call audience targeting is intentionally **not** supported through `CustomClaims`.
If that capability is needed in the future, it must be exposed through an explicit API
surface — for example, a functional option:

```go
IssueAccessTokenWithClaims(ctx, userID, claims, tokens.WithAudience("svc-payments"))
```

This makes the override visible at the call site, allows it to be tested independently,
and does not require callers to know which claim keys are reserved.

## Consequences

**Positive:**
- Manager security invariants — particularly audience binding — cannot be undermined
  through `CustomClaims`, regardless of how the caller constructs their claims map.
- The warn-log drop path makes mistakes visible during development without causing a
  hard failure that breaks production callers on upgrade.
- The design is consistent with ADR-005: every security-sensitive claim has a named
  gate, whether on the validation path (inbound tokens) or the issuance path (outbound).

**Negative:**
- Callers who legitimately need per-call audience targeting cannot do so today. They
  must either instantiate one `Manager` per audience or wait for an explicit option
  to be added to the API.
- The silent-drop behaviour means a misconfigured caller will not receive an error —
  they will issue tokens without their intended custom claim. This is the standard
  tradeoff for reserved-key guards in extensible claim maps.

## References

- Related: ADR-005 (Security Boundaries — Attacker-Controlled Token Fields) — covers
  the validation-side gate for `aud` and other claims
- Issue #109 — identified the missing `aud` entry in the reserved claims guard
- RFC 7519 §4.1 — Registered Claim Names
