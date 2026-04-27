# ADR-007: Namespace Field on Manager Configs for Observability Consistency

**Date**: 2026-04-27  
**Status**: Accepted

## Context

ADR-006 introduced `KeyPrefix` on Redis store configs (`RedisKeyStoreConfig`,
`RedisRefreshStoreConfig`) to prevent keyspace collisions when multiple manager
instances share a Redis cluster. That field satisfies the data isolation requirement — Redis
keys from distinct namespaces never collide.

`KeyPrefix` is a backend-specific implementation detail. When operators run multiple
manager instances — one per tenant, one per environment, or for test isolation — observability
signals (log lines, trace spans, metric labels) emitted by different instances are
indistinguishable. A log entry stating `"key rotated"` carries no information about which
manager produced it. This makes multi-manager deployments difficult to monitor and debug.

A decoupled surface is needed: a first-class namespace label that the manager carries through
its observability output, independent of any backend key-prefix scheme.

## Decision

Add an optional `Namespace string` field to `KeyManagerConfig` and `TokenManagerConfig`.
The zero value preserves existing behavior exactly — no label is injected into logs, traces,
or metrics. When non-empty, the namespace is stored in the manager struct and is available for
attachment to observability output.

The field is inert in this phase. No existing log call, span attribute, or metric label is
modified here. This ADR records the configuration surface; a subsequent phase wires the field
into observability output (see issue #112).

The field is not validated or interpreted. The library treats it as an opaque label — format,
naming conventions, and semantics are entirely the consumer's decision.

## Consequences

- Operators deploying multiple manager instances can assign distinct namespaces to
  disambiguate observability output once wiring is added
- Zero-value preserves backward compatibility — existing deployments require no change
- `Namespace` is decoupled from `KeyPrefix` — they may be set independently, set to the
  same value, or one may be non-empty while the other is not; neither implies the other
- The contract between `Namespace` on a manager config and `KeyPrefix` on a store config is
  intentionally loose: both solve isolation in their respective layers (observability vs.
  data storage), and callers are free to use different values for each
