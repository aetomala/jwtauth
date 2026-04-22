# ADR-005: Security Boundaries — Attacker-Controlled Token Fields

**Status**: Accepted  
**Date**: 2026-04-21  
**Deciders**: Architecture Team

## Context

A JWT token is produced by one party (the issuer) and presented by another party
(the bearer, who may be an attacker). Every field in the token header and claims is
attacker-controlled until the library verifies the signature and validates the claims.

jwtauth processes two categories of attacker-controlled input:

1. **Token header fields** — `alg`, `kid`, and any custom header parameters
2. **Token claims** — `iss`, `aud`, `sub`, `exp`, `nbf`, `iat`, and custom claims

Each category must be treated as untrusted until explicitly validated. The failure
mode when this principle is violated is that attacker-supplied data flows directly
into security-sensitive operations (filesystem paths, Redis key lookups, issuer
comparisons, audience grants).

## Decision

**Every attacker-controlled token field must pass through an explicit validation
gate before being used in any security-sensitive operation.**

The gates implemented in jwtauth are:

| Field | Validation Gate | Rejection Response |
|-------|----------------|--------------------|
| `alg` | Asserted as `RS256` unconditionally | Parse error |
| `kid` | UUID v4 regex at every KeyStore method | `ErrKeyStoreInvalidKeyID` |
| `iss` | Compared against configured `Issuer` after parse | `ErrTokenInvalidClaims` |
| `aud` | Compared against configured `Audience` after parse | `ErrTokenInvalidClaims` |
| `exp` | Checked against `time.Now()` with leeway | `ErrTokenExpired` |
| Custom claims | Caller-validated after extraction | n/a (caller responsibility) |

The gates are applied in the order listed above. An invalid `alg` or `kid` is
rejected before signature verification is attempted. Claims validation occurs after
a successful signature check.

## Consequences

**Positive:**
- The security model is explicit and auditable — each attacker-controlled field has
  a named gate, and bypassing any single gate is not sufficient
- Early rejection (before I/O) limits the blast radius of malformed tokens
- Logging and metrics fire on each gate failure, making attacks observable

**Negative:**
- Strict validation breaks callers that pass informal values (e.g. plain-string key
  IDs instead of UUIDs) — this is intentional; strict input is required
- Adding new header parameters requires explicitly placing them behind a gate

## What Is Not a Security Boundary

The following fields are populated by jwtauth itself during token issuance and are
therefore trusted without further validation:

- `jti` (token ID) — generated internally by `uuid.New()`
- `iat` (issued-at) — set to `time.Now()` at issuance
- `nbf` (not-before) — set alongside `iat`
- Token type marker (`typ` claim) — set to `"access"` or `"refresh"` at issuance

## References

- Related: ADR-003 (RS256 Only) — `alg` validation
- Related: ADR-004 (kid Validation) — `kid` validation
- OWASP: Testing for JWT Attacks
- RFC 7519 §7.2: JWT validation requirements
