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
| `GetPublicKey` (cache hit) | 177 | 440 | 6 | In-memory read-lock path — overwhelmingly common |
| `GetPublicKey` (cache miss) | 146,577 | 16,375 | 114 | DiskKeyStore load on new instance startup |
| `RotateKeys` | 41,091,208 | 583,374 | 5,300 | RSA 2048-bit key generation + disk write (~41 ms) |
| `GetCurrentKeyInfo` | 190 | 504 | 5 | Metadata-only read, no private material |
| `GetJWKS` | 198 | 496 | 6 | JWKS serialization for `/.well-known/jwks.json` |

`RotateKeys` is intentionally expensive — it generates a fresh RSA 2048-bit key pair and
writes two files to disk. In production, rotation happens at most once per
`KeyRotationInterval` (default 30 days). It never runs on the request path.

---

## Results: Token Manager

All token manager benchmarks use `MemoryRefreshStore` for deterministic crypto isolation.

### Pure Crypto

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| `IssueAccessToken` | 61,646 | 6,633 | 70 |
| `IssueAccessToken` (WithAudience) | 63,982 | 6,847 | 73 |
| `IssueAccessTokenWithClaims` — Small (2 fields) | 71,123 | 8,441 | 89 |
| `IssueAccessTokenWithClaims` — Medium (10 fields) | 79,138 | 11,592 | 109 |
| `IssueAccessTokenWithClaims` — Large (50 fields) | 95,422 | 29,985 | 198 |
| `ValidateAccessToken` | 4,199 | 6,352 | 96 |
| `ValidateAccessTokenWithClaims` | 5,287 | 9,512 | 151 |
| `IssueTokenPair` | 58,103 | 8,325 | 83 |

Issuance (~62–95 µs) is dominated by RSA 2048-bit signing. Validation (~4.2 µs) is PKCS#1
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
| `RefreshAccessToken` | 718,784 | 10,410 | 111 | Full rotation: new access token + refresh token re-storage |
| `RevokeRefreshToken` | 1,446 | 2,256 | 21 | Single-token revocation — in-memory store write |
| `IntrospectToken` | 382 | 2,400 | 26 | Metadata read — no JWT re-parse |

`RefreshAccessToken` is expensive (~719 µs) because it generates a new RSA-signed access
token and a new opaque refresh token in a single call.

### Bulk Revocation (N tokens per call, MemoryRefreshStore)

| Benchmark | N | ns/op | B/op | allocs/op |
|---|---|---|---|---|
| `RevokeAllUserTokens` | 10 | 2,278 | 3,408 | 50 |
| `RevokeAllUserTokens` | 100 | 10,622 | 13,488 | 320 |
| `RevokeAllUserTokens` | 1,000 | 91,055 | 114,304 | 3,021 |
| `RevokeAllForAudience` | 10 | 2,554 | 3,472 | 51 |
| `RevokeAllForAudience` | 100 | 11,341 | 13,552 | 321 |
| `RevokeAllForAudience` | 1,000 | 95,612 | 114,368 | 3,023 |
| `RevokeAllForUserAndAudience` | 10 | 2,890 | 4,080 | 65 |
| `RevokeAllForUserAndAudience` | 100 | 13,592 | 18,480 | 425 |
| `RevokeAllForUserAndAudience` | 1,000 | 112,805 | 162,496 | 4,027 |

### Audience-Scoped Listing (full scan, page size 100, MemoryRefreshStore)

| N tokens | ns/op | B/op | allocs/op |
|---|---|---|---|
| 100 | 4,877 | 17,040 | 218 |
| 1,000 | 54,099 | 171,004 | 2,225 |
| 10,000 | 567,105 | 1,710,726 | 22,295 |

---

## Rotation-Under-Load

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| `ValidateAccessToken` (steady state) | 4,199 | 6,352 | 96 |
| `ValidateAccessToken` (during rotation) | 10,335 | 6,464 | 97 |

`BenchmarkValidateAccessToken_DuringRotation` runs 16 parallel validator goroutines
against a token signed with the initial key while a background goroutine calls
`RotateKeys` every 50 ms. The key overlap window (5 minutes) keeps the original token
valid throughout the run. The 2.5× slowdown (4.2 µs → 10.3 µs) reflects read-write mutex
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
| NoOp (baseline) | 56,563 | 6,570 | 70 |
| PrometheusMetrics | 56,656 | 6,570 | 70 |
| OtelTracer | 56,704 | 7,050 | 79 |

### Validation (`ValidateAccessToken`)

| Variant | ns/op | B/op | allocs/op |
|---|---|---|---|
| NoOp (baseline) | 2,574 | 6,352 | 96 |
| OtelTracer | 2,642 | 6,832 | 105 |

Observability overhead is negligible — PrometheusMetrics adds < 0.2% to issuance; the
OtelTracer dispatch (span start/end via the no-op provider) adds < 0.3% to issuance and
~2.6% to validation. Both are noise relative to real Redis RTT in production.

---

## vs. golang-jwt/jwt Baseline

| Benchmark | ns/op | B/op | allocs/op |
|---|---|---|---|
| `Sign` — raw `golang-jwt/jwt` | 56,699 | 3,385 | 30 |
| `IssueAccessToken` — jwtauth | 57,471 | 6,571 | 70 |
| `Verify` — raw `golang-jwt/jwt` | 2,255 | 4,288 | 62 |
| `ValidateAccessToken` — jwtauth | 2,574 | 6,352 | 96 |

jwtauth adds **1.4% overhead on signing** (57,471 vs 56,699 ns) and **14% on validation**
(2,574 vs 2,255 ns) relative to raw `golang-jwt/jwt`. The extra cost covers:

- Key manager cache lookup (read lock on the key map)
- Refresh token storage and correlation-ID propagation
- Logging, metrics, and tracing dispatch (no-op in these runs)
- Claims validation (issuer, audience, expiry enforcement)

The validation overhead in absolute terms is 319 ns — well within single-digit microsecond
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
when a stable infrastructure baseline is available.
