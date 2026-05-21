# ADR-011: Cursor Semantics and Pagination Consistency Contract

**Status**: Accepted
**Date**: 2026-05-20
**Deciders**: Architecture Team

## Context

`ListTokens`, `ListTokensForUser`, and `ListTokensForAudience` use cursor-based pagination.
The cursor type is `string` in all cases, but the encoding differs across backends and
methods:

- `MemoryRefreshStore.ListTokens` — cursor is the `tokenID` of the last token in the
  previous page; the next call filters to tokens with `tokenID > cursor` in a
  deterministically sorted slice.
- `MemoryRefreshStore.ListTokensForUser` / `ListTokensForAudience` — cursor is a base-10
  integer string encoding a positional offset into a sorted token ID slice.
- `RedisRefreshStore` (all three methods) — cursor is a base-10 uint64 string that
  transparently passes through the value returned by Redis `SCAN` or `SSCAN`.

Callers receive cursors only from previous list call responses, but the consistency
guarantees — ordering stability, duplicate visibility, behaviour under concurrent
insertion/deletion — have never been formally documented. Security-focused operators
and compliance reviewers building audit pipelines need a discoverable contract.

## Decision

**Cursors in jwtauth are opaque byte sequences.** Callers must not attempt to decode,
construct, compare, or persist cursor values across backend changes or library upgrades.
The only valid cursor operations are:

1. Start with an empty string (`""`) as the initial cursor.
2. Pass the cursor returned by a list call as the cursor argument of the next call.
3. Treat an empty string cursor in the response as the end of the sequence.

**Pagination is best-effort.** jwtauth provides no stronger consistency guarantee than
Redis `SCAN`: tokens inserted or deleted between pages may appear on a subsequent page,
be skipped entirely, or appear more than once in a single traversal.

**Iteration order is not guaranteed to be stable** between calls, between backends, or
across library upgrades. Callers must not rely on a specific ordering.

## Rationale

**The opaque contract is the only safe abstraction across backends.** Memory and Redis
cursors are structurally incompatible. Memory cursors encode application-layer state
(sorted offsets or token ID comparisons); Redis cursors encode internal hash-table
positions. Exposing the encoding would couple callers to implementation details and make
backend migrations breaking changes.

**Normalising cursors adds complexity with no caller benefit.** Encoding Redis cursors
into an application-level format (e.g. JSON with a backend tag) would require decoding
on every call, add allocation on the hot path, and still not provide a stable ordering
guarantee — Redis SCAN makes no ordering promise. The divergence is an intentional
trade-off: each backend uses the most efficient cursor mechanism available to it.

**Redis SCAN semantics are the least-common-denominator contract.** `MemoryRefreshStore`
provides sorted-order iteration within a single call's snapshot, which is strictly
stronger. However, operators must target the weaker Redis contract because production
deployments use Redis. Documenting Redis SCAN semantics as the floor prevents operators
from building pipelines that depend on Memory's stronger ordering and fail under
production load.

## Consequences

**Callers must treat cursors as single-use, connection-scoped values.** Saving a cursor
to disk and resuming a traversal later, or using a cursor from one `Manager` instance on
another, is undefined behaviour.

**Audit pipelines that require complete enumeration without duplicates must snapshot the
store.** The recommended pattern: hold a write lock (or application-level mutex), call
`ListTokensForAudience` (or `ListTokens`) to exhaustion, then process the snapshot. Do
not rely on cursor stability under concurrent mutation for correctness-critical pipelines.

**Ordering-dependent code will break.** Any caller that sorts or de-duplicates across
pages based on cursor position is relying on undefined behaviour. Collect all pages first,
then sort the result set.

**Future backends can use any cursor encoding.** Provided the backend satisfies the
opaque, best-effort contract described here, no API change is required.

## References

- Related: ADR-002 (Stateful Refresh Tokens) — establishes the `RefreshStore` model that
  `ListTokens` operates on
- Related: ADR-006 (KeyPrefix) — the Redis key namespace scheme that SCAN cursors traverse
- Issue #186 — formal documentation of this contract
- Redis SCAN documentation — https://redis.io/docs/latest/commands/scan/ (best-effort, no ordering guarantee)
