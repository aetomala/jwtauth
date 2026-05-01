# Architecture Decision Records (ADRs)

This directory contains records of major architectural decisions made for jwtauth.

## What is an ADR?

An Architecture Decision Record (ADR) captures an important architectural decision along with its context and consequences.

## Format

Each ADR includes:
- **Status**: Proposed, Accepted, Deprecated, Superseded
- **Context**: The issue motivating this decision
- **Decision**: The change we're proposing or have agreed to
- **Consequences**: The resulting context, positive and negative

## Index

- [ADR-001: No Rate Limiting in Library](001-no-rate-limiting.md)
- [ADR-002: Stateful Refresh Tokens](002-stateful-refresh-tokens.md)
- [ADR-003: RS256 Only](003-rs256-only.md)
- [ADR-004: Key ID (kid) Validation at the KeyStore Boundary](004-kid-validation.md)
- [ADR-005: Security Boundaries — Attacker-Controlled Token Fields](005-security-boundaries.md)
- [ADR-006: KeyPrefix — Namespace Isolation in Redis Backends](006-keyprefix-namespace-isolation.md)
- [ADR-007: Namespace Field on Manager Configs for Observability Consistency](007-namespace-consistency-contract.md)
- [ADR-008: Reserved Claims Protection at Token Issuance](008-reserved-claims-at-issuance.md)
