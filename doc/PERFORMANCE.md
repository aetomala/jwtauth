# Performance

## Overview

This document covers library-level performance baselines for jwtauth. All measurements
isolate the library's own overhead — cryptographic cost, storage operations, and
observability dispatch. Real Redis network RTT is not included; see
[What These Numbers Don't Include](#what-these-numbers-dont-include).

---

## Reference Machine

| Field | Value |
|---|---|
| **Date** | 2026-06-03 (v1.0.0) |
| Hardware | Apple M4 Max |
| OS | macOS 25.5.0 (darwin/arm64) |
| Go | 1.26.2 |
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
| `Store` | 746 | 1,988 | 21 | 34,670 | 6,016 | 135 |
| `Store` (WithAudience) | 799 | 2,107 | 22 | 42,384 | 7,396 | 179 |
| `Retrieve` | 413 | 1,328 | 14 | 24,956 | 2,859 | 72 |
| `Revoke` | 977 | 1,136 | 11 | 51,180 | 2,091 | 52 |

### Bulk revocation (N tokens per call)

| Benchmark | N | Memory ns/op | Redis ns/op |
|---|---|---|---|
| `RevokeAllForUser` | 10 | 1,775 | 110,204 |
| `RevokeAllForUser` | 100 | 10,050 | 417,856 |
| `RevokeAllForUser` | 1,000 | 87,608 | 3,714,148 |
| `RevokeAllForAudience` | 10 | 2,230 | 94,776 |
| `RevokeAllForAudience` | 100 | 11,078 | 476,106 |
| `RevokeAllForAudience` | 1,000 | 93,164 | 5,568,471 |
| `RevokeAllForUserAndAudience` | 10 | 2,566 | 88,618 |
| `RevokeAllForUserAndAudience` | 100 | 13,488 | 419,715 |
| `RevokeAllForUserAndAudience` | 1,000 | 112,303 | 3,781,664 |

### Cursor-based listing (full scan, page size 100)

| Benchmark | N tokens | Memory ns/op | Redis ns/op |
|---|---|---|---|
| `ListTokens` | 100 | 6,852 | 554,958 |
| `ListTokens` | 1,000 | 680,359 | 4,984,003 |
| `ListTokens` | 10,000 | 79,988,533 | 49,922,752 |
| `ListTokensForUser` | 100 | 3,941 | 599,343 |
| `ListTokensForUser` | 1,000 | 44,405 | 7,046,524 |
| `ListTokensForUser` | 10,000 | 430,750 | 227,454,858 |
| `ListTokensForAudience` | 100 | 5,024 | 623,756 |
| `ListTokensForAudience` | 1,000 | 58,487 | 7,255,995 |
| `ListTokensForAudience` | 10,000 | 599,470 | 231,709,417 |

### Cleanup (scan and delete, N expired tokens)

| N | Memory ns/op | Redis ns/op |
|---|---|---|
| 100 | 1,056 | 2,543,289 |
| 1,000 | 6,934 | 25,609,035 |
| 10,000 | 59,640 | 261,540,490 |

Memory cleanup is O(N) with 13 allocations regardless of N — allocations do not scale because
the store reuses internal iteration state. Redis cleanup issues a `DEL` per expired entry via
a pipeline, so cost scales linearly.

---

## Results: Key Manager

| Benchmark | ns/op | B/op | allocs/op | Notes |
|---|---|---|---|---|
| `GetPublicKey` (cache hit) | 154 | 440 | 6 | In-memory read-lock path — overwhelmingly common |
| `GetPublicKey` (cache miss) | 143,837 | 16,130 | 113 | `KeyStore.LoadKey` on cache eviction |
| `RotateKeys` | ~46,000,000 | ~650,000 | ~6,000 | RSA 2048-bit key generation + disk write (~46 ms) |
| `GetCurrentKeyInfo` | 169 | 504 | 5 | Metadata-only read, no private material |
| `GetJWKS` | 176 | 496 | 6 | JWKS serialization for `/.well-known/jwks.json` |

`RotateKeys` is intentionally expensive — it generates a fresh RSA 2048-bit key pair and
writes two files to disk. In production, rotation happens at most once per
`KeyRotationInterval` (default 30 days). It never runs on the request path.

---

## Results: Token Manager

All token manager benchmarks use `MemoryRefreshStore` for deterministic crypto isolation.

### Pure Crypto

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| `IssueAccessToken` | 61,640 | 6,624 | 70 |
| `IssueAccessToken` (WithAudience) | 65,533 | 6,834 | 73 |
| `IssueAccessTokenWithClaims` — Small (2 fields) | 72,807 | 8,433 | 89 |
| `IssueAccessTokenWithClaims` — Medium (5 fields) | 78,542 | 11,577 | 109 |
| `IssueAccessTokenWithClaims` — Large (15 fields) | 97,736 | 30,013 | 198 |
| `ValidateAccessToken` | 4,184 | 6,352 | 96 |
| `ValidateAccessTokenWithClaims` | 5,311 | 9,512 | 151 |
| `IssueTokenPair` | 58,485 | 8,347 | 83 |

Issuance (~62–98 µs) is dominated by RSA 2048-bit signing. Validation (~4.2 µs) is PKCS#1
v1.5 verification — roughly 15× faster than signing.

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
| `RefreshAccessToken` | 702,740 | 10,414 | 111 | Full rotation: validate + new access token + new refresh token |
| `RevokeRefreshToken` | 1,525 | 2,256 | 21 | Single-token revocation — in-memory store write |
| `IntrospectToken` | 386 | 2,400 | 26 | Metadata read — no JWT re-parse |

`RefreshAccessToken` is expensive (~703 µs) because it validates the incoming refresh token,
generates a new RSA-signed access token, and stores a new opaque refresh token in a single call.

### Bulk Revocation (N tokens per call, MemoryRefreshStore)

| Benchmark | N | ns/op | B/op | allocs/op |
|---|---|---|---|---|
| `RevokeAllUserTokens` | 10 | 2,649 | 3,408 | 50 |
| `RevokeAllUserTokens` | 100 | 11,140 | 13,488 | 320 |
| `RevokeAllUserTokens` | 1,000 | 93,158 | 114,304 | 3,021 |
| `RevokeAllForAudience` | 10 | 2,792 | 3,472 | 51 |
| `RevokeAllForAudience` | 100 | 11,871 | 13,552 | 321 |
| `RevokeAllForAudience` | 1,000 | 102,654 | 114,368 | 3,023 |
| `RevokeAllForUserAndAudience` | 10 | 3,054 | 4,080 | 65 |
| `RevokeAllForUserAndAudience` | 100 | 13,935 | 18,480 | 425 |
| `RevokeAllForUserAndAudience` | 1,000 | 116,459 | 162,496 | 4,027 |

### Audience-Scoped Listing (full scan, page size 100, MemoryRefreshStore)

| N tokens | ns/op | B/op | allocs/op |
|---|---|---|---|
| 100 | 5,550 | 17,040 | 218 |
| 1,000 | 61,391 | 171,004 | 2,225 |
| 10,000 | 744,392 | 1,710,725 | 22,295 |

---

## Rotation-Under-Load

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| `ValidateAccessToken` (steady state) | 4,184 | 6,352 | 96 |
| `ValidateAccessToken` (during rotation) | 8,382 | 6,437 | 96 |

`BenchmarkValidateAccessToken_DuringRotation` runs 16 parallel validator goroutines
against a token signed with the initial key while a background goroutine calls
`RotateKeys` every 50 ms. The key overlap window (5 minutes) keeps the original token
valid throughout the run. The 2× slowdown (4.2 µs → 8.4 µs) reflects read-write mutex
contention during the brief window when a rotation updates the key cache.

This benchmark cannot be reproduced by single-key JWT libraries. It validates the
library's zero-downtime rotation guarantee under concurrent validation load.

---

## Observability Tax

All variants backed by `MemoryRefreshStore` and `DiskKeyStore`. OtelTracer uses
`tracing.NewOtelTracer("bench")` wired to Go's global no-op `TracerProvider` — zero
network calls.

### Issuance (`IssueAccessToken`)

| Variant | ns/op | B/op | allocs/op |
|---|---|---|---|
| NoOp (baseline) | 56,800 | 6,568 | 70 |
| PrometheusMetrics | 56,025 | 6,568 | 70 |
| OtelTracer | 57,061 | 7,048 | 79 |

### Validation (`ValidateAccessToken`)

| Variant | ns/op | B/op | allocs/op |
|---|---|---|---|
| NoOp (baseline) | 2,463 | 6,352 | 96 |
| OtelTracer | 2,504 | 6,832 | 105 |

Observability overhead is negligible — `PrometheusMetrics` adds < 0.2% to issuance because
counters and histograms use pre-built label maps allocated at construction time (ADR-007).
The `OtelTracer` span dispatch adds < 0.5% to issuance and ~1.7% to validation. Both are
noise relative to real Redis RTT in production.

---

## vs. golang-jwt/jwt Baseline

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| `Sign` — raw `golang-jwt/jwt` | 57,113 | 3,384 | 30 |
| `IssueAccessToken` — jwtauth | 56,653 | 6,568 | 70 |
| `Verify` — raw `golang-jwt/jwt` | 2,174 | 4,488 | 69 |
| `ValidateAccessToken` — jwtauth | 2,449 | 6,560 | 94 |

jwtauth adds **< 1% overhead on signing** and **13% on validation** relative to raw
`golang-jwt/jwt`. The extra cost covers:

- Key manager cache lookup (read lock on the key map)
- Refresh token storage and correlation-ID propagation
- Logging, metrics, and tracing dispatch (no-op in these runs)
- Claims validation (issuer, audience, expiry enforcement)

The validation overhead in absolute terms is 275 ns — well within single-digit microsecond
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
