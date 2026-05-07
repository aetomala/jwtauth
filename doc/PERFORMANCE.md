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
| Hardware | Apple M4 Max |
| OS | macOS 15.x (darwin/arm64) |
| Go | 1.26.2 |
| `GOMAXPROCS` | 16 |
| Redis (storage layer) | in-process miniredis (no network) |

Reproduction command:
```bash
go test -bench=. -benchmem -run=^$ ./pkg/storage/ ./pkg/keys/ ./pkg/tokens/
```

> **Note:** Passing `-count=1` is required when running only benchmarks (no Ginkgo specs).
> Ginkgo rejects `-count=N` for N > 1. Use `benchstat` with multiple `-count` runs if you
> need statistical confidence intervals (see [Regression Detection](#regression-detection)).

---

## Results: Storage Layer

All operations measured on `MemoryRefreshStore` and `RedisRefreshStore` (miniredis). The
`WithAudience` variants include the two additional `SAdd` calls added in PR #135.

### Single-token operations

| Benchmark | Memory ns/op | Memory B/op | Memory allocs | Redis ns/op | Redis B/op | Redis allocs |
|---|---|---|---|---|---|---|
| `Store` | 797 | 2,034 | 23 | 37,031 | 6,083 | 137 |
| `Store` (WithAudience) | 862 | 2,124 | 24 | 42,117 | 7,308 | 181 |
| `Retrieve` | 492 | 1,352 | 16 | 28,269 | 2,883 | 74 |
| `Revoke` | 1,147 | 1,160 | 13 | 52,430 | 2,119 | 54 |

### Bulk revocation (N tokens per call)

| Benchmark | N | Memory ns/op | Redis ns/op |
|---|---|---|---|
| `RevokeAllForUser` | 10 | 2,114 | 90,156 |
| `RevokeAllForUser` | 100 | 11,104 | 420,295 |
| `RevokeAllForUser` | 1,000 | 99,983 | 4,203,787 |
| `RevokeAllForAudience` | 10 | 2,307 | 96,923 |
| `RevokeAllForAudience` | 100 | 11,658 | 482,940 |
| `RevokeAllForAudience` | 1,000 | 165,791 | 6,212,172 |
| `RevokeAllForUserAndAudience` | 10 | 2,656 | 92,570 |
| `RevokeAllForUserAndAudience` | 100 | 14,161 | 435,261 |
| `RevokeAllForUserAndAudience` | 1,000 | 129,824 | 3,955,142 |

### Cursor-based listing (full scan, page size 100)

| Benchmark | N tokens | Memory ns/op | Redis ns/op |
|---|---|---|---|
| `ListTokens` | 100 | 8,165 | 569,111 |
| `ListTokens` | 1,000 | 827,597 | 5,071,786 |
| `ListTokens` | 10,000 | 92,270,139 | 49,281,907 |
| `ListTokensForUser` | 100 | 4,543 | 600,595 |
| `ListTokensForUser` | 1,000 | 50,824 | 7,588,131 |
| `ListTokensForUser` | 10,000 | 502,806 | 223,654,758 |
| `ListTokensForAudience` | 100 | 5,899 | 647,146 |
| `ListTokensForAudience` | 1,000 | 68,953 | 7,887,236 |
| `ListTokensForAudience` | 10,000 | 714,893 | 251,224,281 |

### Cleanup (scan only, no deletions, N live tokens)

| N | Memory ns/op | Redis ns/op |
|---|---|---|
| 100 | 1,275 | 2,553,852 |
| 1,000 | 9,094 | 26,172,139 |
| 10,000 | 82,225 | 269,240,656 |

---

## Results: Key Manager

| Benchmark | ns/op | B/op | allocs/op | Notes |
|---|---|---|---|---|
| `GetPublicKey` (cache hit) | 243 | 800 | 10 | In-memory read-lock path — overwhelmingly common |
| `GetPublicKey` (cache miss) | 188,334 | 16,659 | 119 | DiskKeyStore load on new instance startup |
| `RotateKeys` | 44,941,655 | 552,318 | 5,026 | RSA 2048-bit key generation + disk write (~45 ms) |
| `GetCurrentKeyInfo` | 193 | 528 | 7 | Metadata-only read, no private material |
| `GetJWKS` | 205 | 520 | 8 | JWKS serialization for `/.well-known/jwks.json` |

`RotateKeys` is intentionally expensive — it generates a fresh RSA 2048-bit key pair and
writes two files to disk. In production, rotation happens at most once per
`KeyRotationInterval` (default 30 days). It never runs on the request path.

---

## Results: Token Manager

All token manager benchmarks use `MemoryRefreshStore` for deterministic crypto isolation.

### Pure Crypto

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| `IssueAccessToken` | 78,775 | 6,893 | 75 |
| `IssueAccessToken` (WithAudience) | 71,341 | 6,991 | 78 |
| `IssueAccessTokenWithClaims` — Small (2 fields) | 68,787 | 8,660 | 94 |
| `IssueAccessTokenWithClaims` — Medium (10 fields) | 79,835 | 11,751 | 113 |
| `IssueAccessTokenWithClaims` — Large (50 fields) | 106,376 | 30,066 | 202 |
| `ValidateAccessToken` | 5,067 | 6,633 | 102 |
| `ValidateAccessTokenWithClaims` | 6,140 | 9,840 | 159 |
| `IssueTokenPair` | 69,436 | 8,612 | 90 |

Issuance (~70–80 µs) is dominated by RSA 2048-bit signing. Validation (~5.1 µs) is PKCS#1
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
| `RefreshAccessToken` | 867,641 | 9,497 | 109 | Full rotation: new access token + refresh token re-storage |
| `RevokeRefreshToken` | 2,268 | 2,304 | 25 | Single-token revocation — in-memory store write |
| `IntrospectToken` | 424 | 2,784 | 32 | Metadata read — no JWT re-parse |

`RefreshAccessToken` is expensive (~868 µs) because it generates a new RSA-signed access
token and a new opaque refresh token in a single call.

### Bulk Revocation (N tokens per call, MemoryRefreshStore)

| Benchmark | N | ns/op | B/op | allocs/op |
|---|---|---|---|---|
| `RevokeAllUserTokens` | 10 | 3,501 | 3,456 | 54 |
| `RevokeAllUserTokens` | 100 | 13,920 | 13,536 | 324 |
| `RevokeAllUserTokens` | 1,000 | 125,162 | 114,352 | 3,025 |
| `RevokeAllForAudience` | 10 | 3,583 | 3,520 | 55 |
| `RevokeAllForAudience` | 100 | 13,491 | 13,600 | 325 |
| `RevokeAllForAudience` | 1,000 | 134,578 | 114,416 | 3,027 |
| `RevokeAllForUserAndAudience` | 10 | 3,919 | 4,128 | 69 |
| `RevokeAllForUserAndAudience` | 100 | 16,184 | 18,528 | 429 |
| `RevokeAllForUserAndAudience` | 1,000 | 134,852 | 162,544 | 4,031 |

### Audience-Scoped Listing (full scan, page size 100, MemoryRefreshStore)

| N tokens | ns/op | B/op | allocs/op |
|---|---|---|---|
| 100 | 5,915 | 17,760 | 226 |
| 1,000 | 68,193 | 178,204 | 2,305 |
| 10,000 | 728,789 | 1,782,725 | 23,095 |

---

## Rotation-Under-Load

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| `ValidateAccessToken` (steady state) | 5,580 | 7,384 | 109 |
| `ValidateAccessToken` (during rotation) | 13,025 | 7,520 | 110 |

`BenchmarkValidateAccessToken_DuringRotation` runs 16 parallel validator goroutines
against a token signed with the initial key while a background goroutine calls
`RotateKeys` every 50 ms. The key overlap window (5 minutes) keeps the original token
valid throughout the run. The 2.3× slowdown (5.6 µs → 13.0 µs) reflects read-write mutex
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
| NoOp (baseline) | 57,951 | 6,800 | 75 |
| PrometheusMetrics | 57,979 | 6,800 | 75 |
| OtelTracer | 59,058 | 7,632 | 87 |

### Validation (`ValidateAccessToken`)

| Variant | ns/op | B/op | allocs/op |
|---|---|---|---|
| NoOp (baseline) | 2,536 | 7,384 | 109 |
| OtelTracer | 2,737 | 8,216 | 121 |

Observability overhead is negligible — PrometheusMetrics adds < 0.1% to issuance; the
OtelTracer dispatch (span start/end via the no-op provider) adds ~1.9% to issuance and
~8% to validation. Both are noise relative to real Redis RTT in production.

---

## vs. golang-jwt/jwt Baseline

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| `Sign` — raw `golang-jwt/jwt` | 56,472 | 3,384 | 30 |
| `IssueAccessToken` — jwtauth | 58,340 | 6,801 | 75 |
| `Verify` — raw `golang-jwt/jwt` | 2,271 | 4,288 | 62 |
| `ValidateAccessToken` — jwtauth | 2,642 | 7,384 | 109 |

jwtauth adds **3.3% overhead on signing** (58,340 vs 56,472 ns) and **16% on validation**
(2,642 vs 2,271 ns) relative to raw `golang-jwt/jwt`. The extra cost covers:

- Key manager cache lookup (read lock on the key map)
- Refresh token storage and correlation-ID propagation
- Logging, metrics, and tracing dispatch (no-op in these runs)
- Claims validation (issuer, audience, expiry enforcement)

The validation overhead in absolute terms is 371 ns — well within single-digit microsecond
territory for any real-world workload.

---

## Regression Detection

Use `benchstat` to compare two benchmark runs before releasing:

```bash
# Capture baseline (e.g., from current dev)
go test -bench=. -benchmem -run=^$ -count=5 ./pkg/storage/ ./pkg/keys/ ./pkg/tokens/ > old.txt

# Make changes, then capture new run
go test -bench=. -benchmem -run=^$ -count=5 ./pkg/storage/ ./pkg/keys/ ./pkg/tokens/ > new.txt

# Compare
benchstat old.txt new.txt
```

Install `benchstat`:
```bash
go install golang.org/x/perf/cmd/benchstat@latest
```

`benchstat` reports statistically significant regressions with a p-value threshold. Any
benchmark showing > 10% regression with p < 0.05 warrants investigation before merge.

> The suite is designed to run with `-count=1` for quick smoke checks and `-count=5` for
> release-gate comparisons.

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
when a stable infrastructure baseline is available (deferred from v0.5.0 — see
`CLAUDE.md` Cloud-Dependent Activities).
