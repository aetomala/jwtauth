# Performance

## Overview

This document covers library-level performance baselines for jwtauth. All measurements
isolate the library's own overhead — cryptographic cost, storage operations, and
observability dispatch. Real Redis network RTT is not included; see
[What These Numbers Don't Include](#what-these-numbers-dont-include).

**Throughput vs. latency.** Benchmarks marked *parallel* use `b.RunParallel` across
`GOMAXPROCS` goroutines — their ns/op is wall time divided by total operations, i.e. aggregate
throughput on 16 cores, not the latency of one call. Unmarked benchmarks run serially and report
single-call latency. Ratios within a parallel table (observability tax, golang-jwt baseline,
rotation under load) compare like with like. For scale: one RSA-2048 signature takes ~0.7 ms
serially on the reference machine, which the parallel issuance figures below amortize to ~60 µs.

---

## Reference Machine

| Field | Value |
|---|---|
| **Date** | 2026-09-30 (v1.1.2) |
| Hardware | Apple M4 Max |
| OS | macOS 26.6.2 (darwin/arm64) |
| Go | 1.26.8 |
| `GOMAXPROCS` | 16 |
| Redis (storage layer) | in-process miniredis (no network) |

Reproduction command:
```bash
go test -bench=. -benchmem -run=^$ ./pkg/storage/ ./pkg/keys/ ./pkg/tokens/ \
  | tee bench.txt
benchstat bench.txt
```

> **Note:** `-run=^$` skips Ginkgo specs — Ginkgo rejects `-count=N` for N > 1.
> Use `benchstat` with multiple `-count` runs for regression comparisons (see
> [Regression Detection](#regression-detection)).

---

## Results: Storage Layer

All operations measured on `MemoryRefreshStore` and `RedisRefreshStore` (miniredis). The
`WithAudience` variants include the two additional `SAdd` calls added in PR #135.

### Single-token operations

| Benchmark | Memory ns/op | Memory B/op | Memory allocs | Redis ns/op | Redis B/op | Redis allocs |
|---|---|---|---|---|---|---|
| `Store` | 951 | 2,358 | 24 | 36,139 | 7,152 | 161 |
| `Store` (WithAudience) | 998 | 2,476 | 25 | 45,382 | 8,279 | 205 |
| `Retrieve` | 505 | 1,456 | 16 | 24,755 | 2,987 | 74 |
| `Revoke` | 1,283 | 1,264 | 13 | 49,168 | 2,222 | 54 |

As of v1.1.0, `Store` performs one additional `ZAdd` per call to populate the expiry index
`Cleanup` reads from (see below) — a small, deterministic allocation increase (Redis: 135 → 159
allocs/op) that trades off against `Cleanup`'s complexity improvement. See
`doc/benchmarks/v1.1.0-report.md` for the full analysis.

As of v1.1.1, every operation that handles a refresh token emits it only as a `tokenref.Ref`
digest in logs and spans (ADR-012) — one SHA-256 and 2 allocations per token, about 90 ns, paid
even when the logger is a no-op. As of v1.1.2 (#282), `MemoryRefreshStore.Store` also computes
each new token's SHA-256 once and keeps it in the token's record for listing. Together these
put in-memory `Store`, `Retrieve`, and `Revoke` 16–21% above v1.1.0; on `RedisRefreshStore` the
cost is lost in the round trip. This exceeds the 15% threshold and is accepted as the cost of the
GHSA-hwqw-6hv9-q5v6 fix on a store intended for testing; the optimization is tracked in #300.
See `doc/benchmarks/v1.1.2-report.md`.

### Bulk revocation (N tokens per call)

| Benchmark | N | Memory ns/op | Redis ns/op |
|---|---|---|---|
| `RevokeAllForUser` | 10 | 3,069 | 87,895 |
| `RevokeAllForUser` | 100 | 21,362 | 416,189 |
| `RevokeAllForUser` | 1,000 | 174,133 | 3,776,378 |
| `RevokeAllForAudience` | 10 | 3,269 | 93,872 |
| `RevokeAllForAudience` | 100 | 22,172 | 470,076 |
| `RevokeAllForAudience` | 1,000 | 182,415 | 5,535,938 |
| `RevokeAllForUserAndAudience` | 10 | 3,573 | 88,804 |
| `RevokeAllForUserAndAudience` | 100 | 24,484 | 413,160 |
| `RevokeAllForUserAndAudience` | 1,000 | 197,758 | 3,811,449 |

The in-memory figures are roughly double v1.1.0's: each revoked token's `Debug` line computes a
`tokenref.Ref` digest inside the loop (2 allocations per token). See the note above and #300.

### Cursor-based listing (full scan, page size 100)

| Benchmark | N tokens | Memory ns/op | Redis ns/op |
|---|---|---|---|
| `ListTokens` | 100 | 4,015 | 549,985 |
| `ListTokens` | 1,000 | 51,916 | 4,954,899 |
| `ListTokens` | 10,000 | 505,761 | 50,207,167 |
| `ListTokensForUser` | 100 | 4,015 | 582,833 |
| `ListTokensForUser` | 1,000 | 47,768 | 7,086,395 |
| `ListTokensForUser` | 10,000 | 445,079 | 227,786,992 |
| `ListTokensForAudience` | 100 | 5,096 | 606,195 |
| `ListTokensForAudience` | 1,000 | 63,462 | 7,369,926 |
| `ListTokensForAudience` | 10,000 | 613,226 | 232,558,333 |

As of v1.1.2 (#282), `MemoryRefreshStore.ListTokens` pages through a digest-sorted index instead
of sorting the full token set on every page. The index holds each token's SHA-256 digest — taken
from the token's record — and is rebuilt lazily, only on the first listing after `Store` adds a
token or `Cleanup` removes one. Full pagination at N=10,000 drops from ~79 ms to ~0.5 ms (−99.4%),
and cursors are hex digests rather than raw tokens (ADR-011, ADR-012). `ListTokensForUser` /
`ListTokensForAudience` read through the same record layout and cost 6–13% more than in v1.1.1.

### Cleanup (expiry-indexed discovery, N stored tokens, zero expired)

As of v1.1.0 (#271), `Cleanup` no longer scans the full token keyspace on either backend.
`MemoryRefreshStore` discovers expired tokens via an expiry-ordered `container/heap` min-heap
populated at `Store` time — O(k log n), where k is the number of expired tokens, not N.
`RedisRefreshStore` discovers them via a namespace-scoped Redis sorted set (`token_expiry_index`)
populated at `Store` time, swept with paginated `ZRangeByScore`/`ZRem` — O(log n + k). Both
figures below measure the zero-expired-token case (N stored, 0 to discover), isolating pure
discovery cost from removal cost.

| N | Memory ns/op | Redis ns/op |
|---|---|---|
| 100 | 548.6 | 50,759 |
| 1,000 | 583.0 | 129,981 |
| 10,000 | 517.8 | 1,139,637 |

Memory cleanup allocations are flat at 13 allocs/op regardless of N (unchanged from the
pre-rewrite baseline — the heap traversal itself was already allocation-free per entry; the
complexity change is in comparisons, not allocations). Redis cleanup allocations drop from
scaling linearly with N (600,150 allocs/op at N=10,000 pre-rewrite) to a flat 70 allocs/op —
paginated `ZRangeByScore` calls replace the old per-token `SCAN` cursor walk. See
`doc/benchmarks/v1.1.0-report.md` for the full before/after comparison, including the
`~209x` improvement at N=10,000/Redis and the corresponding `Store` cost increase (`Store`
now performs one additional `ZAdd` to populate the index — within the 15% latency gate, see
that report for the allocation-count tradeoff analysis).

---

## Results: Key Manager

| Benchmark | ns/op | B/op | allocs/op | Notes |
|---|---|---|---|---|
| `GetPublicKey` (cache hit) — parallel | 154 | 440 | 6 | In-memory read-lock path — overwhelmingly common |
| `GetPublicKey` (cache miss) | 147,798 | 16,290 | 113 | `KeyStore.LoadKey` on cache eviction |
| `RotateKeys` | ~37,000,000 | ~550,000 | ~5,000 | RSA 2048-bit key generation + disk write (~37 ms) |
| `GetCurrentKeyInfo` — parallel | 168 | 504 | 5 | Metadata-only read, no private material |
| `GetJWKS` — parallel | 179 | 496 | 6 | JWKS serialization for `/.well-known/jwks.json` |

`RotateKeys` is intentionally expensive — it generates a fresh RSA 2048-bit key pair and
writes two files to disk. Key generation is a randomized prime search, so this figure varies
widely between runs (37–48 ms across recent measurements). In production, rotation happens at most once per
`KeyRotationInterval` (default 30 days). It never runs on the request path.

---

## Results: Token Manager

All token manager benchmarks use `MemoryRefreshStore` for deterministic crypto isolation.

### Pure Crypto (parallel)

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| `IssueAccessToken` | 62,411 | 6,631 | 70 |
| `IssueAccessToken` (WithAudience) | 64,337 | 6,820 | 73 |
| `IssueAccessTokenWithClaims` — Small (2 fields) | 66,921 | 8,380 | 89 |
| `IssueAccessTokenWithClaims` — Medium (5 fields) | 79,353 | 11,591 | 109 |
| `IssueAccessTokenWithClaims` — Large (15 fields) | 96,031 | 29,815 | 197 |
| `ValidateAccessToken` | 4,498 | 6,352 | 96 |
| `ValidateAccessTokenWithClaims` | 5,728 | 9,512 | 151 |
| `IssueTokenPair` | 58,803 | 8,968 | 91 |

These are throughput figures across 16 goroutines (see [Overview](#overview)). Issuance
(~62–96 µs per operation at full parallelism; ~0.7 ms for a single serial call) is dominated
by RSA 2048-bit signing. Validation (~4.5 µs) is PKCS#1 v1.5 verification — roughly 14× faster
than signing.

`WithAudience` adds no measurable overhead — the functional-option closure dispatch is
noise relative to RSA signing cost.

#### v0.5.0 Alloc Reduction — Issue #142

Three-phase structural fix targeting the `ValidateAccessToken` / `ValidateAccessTokenWithClaims`
hot path. All changes are in `pkg/tokens/manager.go`. No interface changes. Stdlib only.

| Method | Before (v0.4.0) | After (v0.5.0) | Alloc Δ |
|---|---|---|---|
| `ValidateAccessToken` | 5,580 ns / 7,384 B / 109 allocs | 5,067 ns / 6,633 B / 102 allocs | −7 allocs (−6%) |
| `ValidateAccessTokenWithClaims` | 7,116 ns / 11,752 B / 194 allocs | 6,140 ns / 9,840 B / 159 allocs | −35 allocs (−18%) |

**Phase 1 (PR #169):** Hoisted `reservedJWTClaims` from a per-call map literal to a package-level
`var`; changed `parseOpts` from an empty-slice literal to nil (saves a slice-header alloc when
`ClockSkew` is zero); removed two `Debug` log calls on the critical path.

**Phase 2 (PR #170):** Replaced `jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})` in
`ValidateAccessTokenWithClaims` with direct payload extraction — `strings.SplitN` +
`base64.RawURLEncoding.DecodeString` + `json.Unmarshal` into `map[string]json.RawMessage`. The
signature is already verified by the preceding `ParseWithClaims` call; the second parse existed
solely to extract raw claim values. Decoding into `json.RawMessage` defers per-value
deserialization so the seven reserved keys are skipped before any boxing occurs.

**Phase 3 (PR #171):** Added `validateCounterSuccessLabels` and `validateDurationLabels` fields to
`Manager`, initialized once in `NewManager`. The `ValidateAccessToken` defer reuses the pre-built
maps on the success path — fresh maps are allocated only on error paths, which are off the hot
path.

### Token Lifecycle

| Benchmark | ns/op | B/op | allocs/op | Notes |
|---|---|---|---|---|
| `RefreshAccessToken` | 719,066 | 10,943 | 120 | Store lookup + new access token + revoke presented refresh token |
| `RevokeRefreshToken` | 2,031 | 2,608 | 27 | Single-token revocation — in-memory store write |
| `IntrospectToken` — parallel | 382 | 2,752 | 32 | Metadata read — no JWT re-parse |

`RefreshAccessToken` retrieves the presented refresh token from the store, checks that it is
active and unexpired, issues a new RSA-signed access token, and revokes the presented refresh
token. It returns only the access token — no new refresh token is stored (see #278). The
benchmark issues a fresh token pair outside the timed section on every iteration, so it runs
serially and reports single-call latency: ~719 µs, almost all of it the one RSA-2048 signature
(~0.7 ms serially). The gap to `IssueAccessToken` above reflects serial latency versus parallel
throughput, not extra work.

### Bulk Revocation (N tokens per call, MemoryRefreshStore)

| Benchmark | N | ns/op | B/op | allocs/op |
|---|---|---|---|---|
| `RevokeAllUserTokens` | 10 | 3,823 | 4,688 | 70 |
| `RevokeAllUserTokens` | 100 | 22,568 | 26,288 | 520 |
| `RevokeAllUserTokens` | 1,000 | 178,958 | 242,304 | 5,021 |
| `RevokeAllForAudience` | 10 | 3,865 | 4,752 | 71 |
| `RevokeAllForAudience` | 100 | 22,876 | 26,352 | 521 |
| `RevokeAllForAudience` | 1,000 | 183,418 | 242,368 | 5,023 |
| `RevokeAllForUserAndAudience` | 10 | 4,166 | 5,360 | 85 |
| `RevokeAllForUserAndAudience` | 100 | 25,229 | 31,280 | 625 |
| `RevokeAllForUserAndAudience` | 1,000 | 199,261 | 290,496 | 6,027 |

These inherit the in-memory store's per-token `tokenref.Ref` cost described under
[Single-token operations](#single-token-operations) (#300).

### Audience-Scoped Listing (full scan, page size 100, MemoryRefreshStore)

| N tokens | ns/op | B/op | allocs/op |
|---|---|---|---|
| 100 | 5,183 | 17,040 | 218 |
| 1,000 | 62,594 | 174,460 | 2,279 |
| 10,000 | 684,487 | 1,748,741 | 22,889 |

---

## Rotation-Under-Load

Both rows are parallel.

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| `ValidateAccessToken` (steady state) | 4,498 | 6,352 | 96 |
| `ValidateAccessToken` (during rotation) | 7,996 | 6,431 | 96 |

`BenchmarkValidateAccessToken_DuringRotation` runs 16 parallel validator goroutines
against a token signed with the initial key while a background goroutine calls
`RotateKeys` every 50 ms. The key overlap window (5 minutes) keeps the original token
valid throughout the run. The ~1.8× slowdown (4.5 µs → 8.0 µs) reflects read-write mutex
contention during the brief window when a rotation updates the key cache.

This benchmark cannot be reproduced by single-key JWT libraries. It validates the
library's zero-downtime rotation guarantee under concurrent validation load.

---

## Observability Tax

All variants backed by `MemoryRefreshStore` and `DiskKeyStore`. OtelTracer uses
`tracing.NewOtelTracer("bench")` wired to Go's global no-op `TracerProvider` — zero
network calls. All rows are parallel.

### Issuance (`IssueAccessToken`)

| Variant | ns/op | B/op | allocs/op |
|---|---|---|---|
| NoOp (baseline) | 56,233 | 6,568 | 70 |
| PrometheusMetrics | 56,554 | 6,568 | 70 |
| OtelTracer | 56,267 | 7,048 | 79 |

### Validation (`ValidateAccessToken`)

| Variant | ns/op | B/op | allocs/op |
|---|---|---|---|
| NoOp (baseline) | 2,355 | 6,352 | 96 |
| OtelTracer | 2,427 | 6,832 | 105 |

Observability overhead is negligible — `PrometheusMetrics` adds < 1% to issuance because
counters and histograms use pre-built label maps allocated at construction time (ADR-007).
The `OtelTracer` span dispatch adds < 0.1% to issuance and ~3% (72 ns) to validation. Both are
noise relative to real Redis RTT in production.

---

## vs. golang-jwt/jwt Baseline

All rows are parallel.

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| `Sign` — raw `golang-jwt/jwt` | 56,500 | 3,384 | 30 |
| `IssueAccessToken` — jwtauth | 56,567 | 6,568 | 70 |
| `Verify` — raw `golang-jwt/jwt` | 2,107 | 4,288 | 62 |
| `ValidateAccessToken` — jwtauth | 2,379 | 6,352 | 96 |

jwtauth adds **< 1% overhead on signing** and **13% on validation** relative to raw
`golang-jwt/jwt`. The extra cost covers:

- Key manager cache lookup (read lock on the key map)
- Refresh token storage and correlation-ID propagation
- Logging, metrics, and tracing dispatch (no-op in these runs)
- Claims validation (issuer, audience, expiry enforcement)

The validation overhead in absolute terms is 272 ns — well within single-digit microsecond
territory for any real-world workload.

---

## Regression Detection

Use `benchstat` to compare two benchmark runs before releasing:

```bash
# Capture baseline (e.g., from current dev)
go test -bench=. -benchmem -run=^$ -count=3 ./pkg/storage/ ./pkg/keys/ ./pkg/tokens/ > old.txt

# Make changes, then capture new run
go test -bench=. -benchmem -run=^$ -count=3 ./pkg/storage/ ./pkg/keys/ ./pkg/tokens/ > new.txt

# Compare
benchstat old.txt new.txt
```

Install `benchstat`:
```bash
go install golang.org/x/perf/cmd/benchstat@latest
```

Thresholds — evaluated per operation against this document as the baseline:

- **< 15% regression** — soft gate: document in the PR and proceed.
- **≥ 15% regression** — hard stop: requires justification or optimization before merge.

Per-operation thresholds apply — a single operation regressing ≥ 15% blocks the PR even if
the geomean is flat.

---

## What These Numbers Don't Include

- **Real Redis network RTT.** Storage benchmarks use in-process miniredis. In production,
  add your observed Redis network RTT (typically 0.5–2 ms per round-trip on a local
  network) to all Redis `ns/op` figures. For the storage layer, the library's own overhead
  is the difference between the Memory and Redis columns.

- **Real Redis persistence and replication latency.** AOF fsync and replica propagation
  add latency beyond network RTT. These are deployment-specific and are the operator's
  responsibility to benchmark in their environment.

- **HTTP handler overhead.** The token manager is middleware — request parsing,
  response encoding, and transport cost sit outside this suite.

Real-Redis benchmarks against a known deployment will be published as a separate document
when a stable infrastructure baseline is available.
