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

At the time of this decision the field was inert — no log call, span attribute, or metric label
was modified. This ADR recorded the configuration surface only; wiring was deferred to a
subsequent phase (see issue #112 and Addendum below).

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

## Addendum — Namespace fully wired (issue #112, PRs #113–#118, 2026-04-27)

The `Namespace` field is now fully wired across all observability output in both managers:

- **Log lines** — every `Logger` call in `KeyManager` and `TokenManager` carries the namespace
  as a structured key (`"namespace"`) when the field is non-empty.
- **Trace spans** — span attributes include `namespace` on every span opened by either manager.
- **Metric labels** — all counters, gauges, histograms, and duration recordings carry a
  `namespace` label; an empty namespace emits an empty string (preserving prior cardinality).

The deferred "subsequent phase" referenced in the original Decision is complete. No interface
changes were required — the field was already present on both config types.

## Addendum — DiskKeyStore namespace wired (issue #184, 2026-05-19)

`DiskKeyStore` now accepts an optional `Namespace string` field on `DiskKeyStoreConfig`.
When non-empty:

- **Log lines** — the logger is enriched with `With("namespace", namespace)` at construction;
  all log lines carry the namespace automatically without per-call overhead.
- **Trace spans** — the `startSpan` helper pre-seeds every span with `"storage.namespace"`.
- **Metric labels** — all five KeyStore operation metrics (`LoadAll`, `Save`, `UpdateMetadata`,
  `LoadKey`, `Delete`) include `"namespace"` in their label maps.

An empty string preserves prior behavior exactly. With this change, all six components tracked
in ADR-007 are fully wired: KeyManager, TokenManager, DiskKeyStore, RedisKeyStore,
RedisRefreshStore, and MemoryRefreshStore (single-tenant; namespace="" by design).
