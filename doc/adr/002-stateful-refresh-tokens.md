# ADR-002: Stateful Refresh Tokens

**Status**: Accepted  
**Date**: 2026-03-18  
**Deciders**: Architecture Team

## Context

JWT tokens can be stateless (no server-side storage) or stateful (server tracks issued tokens). Should jwtauth use stateful refresh tokens?

**Stateless approach:**
- Refresh tokens are self-contained JWTs
- No server-side storage required
- Cannot revoke before expiry

**Stateful approach:**
- Refresh tokens are opaque IDs stored server-side
- Requires storage backend (Memory, Redis, Postgres)
- Can revoke instantly

**Use cases requiring revocation:**
- User logout (invalidate all sessions)
- Password change (force re-authentication)
- Account compromise (emergency revocation)
- Device management (revoke specific device)

## Decision

**We will use stateful refresh tokens with server-side storage.**

Refresh tokens are opaque identifiers (UUIDs) stored in a RefreshStore backend. Access tokens remain stateless JWTs (no storage required for validation).

**Storage backends:**
- `MemoryRefreshStore`: In-memory (single-instance, testing)
- `RedisRefreshStore`: Redis (distributed, production)
- Extensible via RefreshStore interface

## Consequences

**Positive:**
- Instant revocation (RevokeRefreshToken, RevokeAllUserTokens)
- Session management (know which devices are logged in)
- Security event response (compromise → revoke immediately)
- Compliance (GDPR "right to be forgotten" — revoke all tokens)

**Negative:**
- Storage dependency (Redis for distributed deployments)
- Slightly slower refresh operations (storage lookup required)
- Cleanup required (expired tokens must be purged)

**Mitigations:**
- Background cleanup goroutine (automatic)
- RefreshStore interface (swap storage backends)
- MemoryRefreshStore for single-instance deployments
- Document horizontal scale path (Memory → Redis)

## Alternatives Considered

**Alternative 1: Stateless refresh tokens**
- Rejected: Cannot revoke before expiry
- Security issue for compromised accounts

**Alternative 2: Blocklist**
- Store revoked token IDs instead of issued tokens
- Rejected: Blocklist grows indefinitely, cleanup complex

**Alternative 3: Hybrid (stateless with optional revocation)**
- Rejected: Adds complexity, most users need revocation

## References

- Related: Storage interface design (pkg/storage/interface.go)
- See: Horizontal scale path in README.md
