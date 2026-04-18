# Changelog

All notable changes to this project will be documented in this file.

---

## [Unreleased] — v0.4.0

### Changed

- **`IssueAccessTokenWithClaims` parameter type changed** from `map[string]interface{}` to `CustomClaims` — update call sites: `map[string]interface{}{"k": v}` → `tokens.CustomClaims{"k": v}`.

- **`IssueRefreshTokenWithMetadata` renamed to `IssueRefreshTokenWithClaims`** — parameter renamed from `metadata` to `claims` with type `CustomClaims`; span name updated to match. Update all call sites.

- **`DiskKeyStore`, `RedisKeyStore`, `MemoryRefreshStore`, `RedisRefreshStore` constructors migrated to config-struct form** — positional parameter constructors removed; update call sites:
  - `keymanager.NewDiskKeyStore(dir, keySize, logger, metrics)` → `keymanager.NewDiskKeyStore(keymanager.DiskKeyStoreConfig{Dir: dir, KeySize: keySize, Logger: logger, Metrics: metrics})`
  - `keymanager.NewRedisKeyStore(client, logger, metrics)` → `keymanager.NewRedisKeyStore(keymanager.RedisKeyStoreConfig{Client: client, Logger: logger, Metrics: metrics})`
  - `storage.NewMemoryRefreshStore(logger, metrics)` → `storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{Logger: logger, Metrics: metrics})`
  - `storage.NewRedisRefreshStore(client, logger, metrics)` → `storage.NewRedisRefreshStore(storage.RedisRefreshStoreConfig{Client: client, Logger: logger, Metrics: metrics})`

- **`tokens.Service` → `tokens.Manager`** — The core token lifecycle type is renamed. Update all call sites:
  - `tokens.NewService(tokens.ServiceConfig{...})` → `tokens.NewManager(tokens.ManagerConfig{...})`
  - `tokens.ConfigDefault()` → `tokens.DefaultManagerConfig()`
  - `tokens.ErrServiceNotRunning` → `tokens.ErrManagerNotRunning`
  - `*tokens.Service` type references → `*tokens.Manager`

- **`AuthMiddleware` → `BearerMiddleware`** in all example middleware packages (`examples/gin-example/middleware`, `examples/chi-example/auth`, `examples/echo-example/middleware`). Rename call sites accordingly.

### Added

- **`CustomClaims` named type** (`map[string]interface{}`) in `pkg/tokens` — canonical type for caller-supplied custom claims across all `WithClaims` methods; reserved JWT field names (`sub`, `iss`, `aud`, `exp`, `nbf`, `iat`, `jti`) are silently dropped at issuance time to prevent caller-controlled claim injection.

- **`IssueTokenPairWithClaims(ctx, userID, accessClaims, refreshClaims CustomClaims)`** on `TokenManager` — issues an access+refresh pair with caller-supplied custom claims embedded in the access token and optional metadata stored with the refresh token; consistent with the established `IssueAccessToken` / `IssueAccessTokenWithClaims` pair pattern.

- **`RefreshAccessTokenWithClaims(ctx, refreshToken string, claims CustomClaims)`** on `TokenManager` — rotates a refresh token and issues a new access token with caller-supplied fresh claims; resolves the stale-claims-on-refresh problem (closes #76). `RefreshAccessToken` (no claims) is preserved unchanged — callers that do not need fresh claims have no migration cost.

- **Distributed tracing wired into all six components** via `pkg/tracing.Tracer` interface — every constructor accepts an optional `Tracer` field (defaults to `NoOpTracer`):
  - `DiskKeyStore` — spans for Load, Save, Delete, UpdateMetadata; attributes: `storage.backend = "disk"`, `key_id`
  - `RedisKeyStore` — same operations; `storage.backend = "redis"`
  - `MemoryRefreshStore` — spans for Store, Retrieve, Revoke, RevokeAllForUser, Cleanup; attribute: `token_id`
  - `RedisRefreshStore` — same operations; `storage.backend = "redis"`
  - `KeyManager` — spans for Start, Shutdown, and all key operations; attribute: `key_id`
  - `TokenManager` — spans for all 14 public methods; attributes: `user_id`, `token_id`, `active` (IntrospectToken), `deleted_count` (CleanupExpiredTokens)

- **`KeyInfo` struct** — public metadata type in `pkg/keymanager` exposing `KeyID`, `CreatedAt`, `RotateAt` (estimated, current key only), `ExpiresAt`, `KeySizeBits`, `Algorithm`, `IsCurrent`, and `IsValid`. Contains no private key material — safe to serve from health check or admin endpoints.

- **`GetKeyInfo(ctx, keyID)`** on `keymanager.Manager` — returns `*KeyInfo` for a specific key by ID. Pass an empty string to resolve the current signing key. Respects context cancellation. Returns `ErrManagerNotRunning` or `ErrKeyNotFound` as appropriate. `KeySizeBits` reflects the actual RSA modulus bit length of the key on disk, not the configured `KeySize`.

- **`GetCurrentKeyInfo(ctx)`** on `keymanager.Manager` — convenience wrapper around `GetKeyInfo(ctx, "")` for the common case of inspecting the active signing key.

- **`GetKeyInfo` and `GetCurrentKeyInfo` on `keymanager.KeyManager` interface** — both methods are now part of the `KeyManager` interface, enabling dependency injection and test doubles for any code that inspects key metadata. `internal/testutil/mock_keymanager.go` has been regenerated with corresponding stubs (`MockKeyManager.GetKeyInfo`, `MockKeyManager.GetCurrentKeyInfo`).

- **Integration tests for `GetCurrentKeyInfo` and `GetKeyInfo`** — three new cases added to `RunTokenManagerIntegrationTests` and run against all storage backends (DiskKeyStore+MemoryRefreshStore, RedisKeyStore+RedisRefreshStore): verifies accurate field values after `Start()`; verifies that `GetCurrentKeyInfo` reflects the new key after `RotateKeys()` while the old key remains accessible via `GetKeyInfo`; verifies that 20 concurrent `GetCurrentKeyInfo` calls during an active `RotateKeys()` produce no data races (real `Manager.mu` lock path exercised under `-race`).

### Fixed

- **`KeyInfo.KeySizeBits` now reports actual key size** — previously sourced from `ManagerConfig.KeySize` (caller-supplied), which could silently diverge from the actual RSA key on disk if the `DiskKeyStore` or `RedisKeyStore` was configured with a different key size. Now derived from `keyPair.PrivateKey.N.BitLen()` so the reported value always matches the real key material.

- **`pkg/tracing` package** — `Tracer` and `Span` interfaces defining the distributed tracing contract. `SpanOption` functional options pattern for span configuration. `StatusCode` (`Unset`, `Error`, `OK`) and `SpanKind` (`Internal`, `Server`, `Client`, `Producer`, `Consumer`) enumerations with `String()` methods. `WithAttributes` and `WithSpanKind` option constructors.

- **`NoOpTracer` / `NoOpSpan`** — zero-allocation no-op implementations; safe to use when tracing is disabled. 36 tests covering constructor, span creation, all span methods, concurrency, and edge cases; race-detection clean.

- **`MockTracer` / `MockSpan`** — gomock mocks generated via `go:generate` directive in `pkg/tracing/interface.go`; available in `internal/testutil/mock_tracing.go` for dependency injection in component tests.

- **`pkg/tracing` included in CI** — added to the unit test command in both `.github/workflows/CI.yml` and `run-ci-locally.sh`.

### Documentation

- **`README.md` — value proposition audit** — added elevator pitch above the fold (one sentence stating the problem jwtauth solves); moved "Why This Library?" from line ~892 to immediately after Overview; added "What Problem Does This Solve?" section framing the post-login token lifecycle gap; strengthened comparison matrix to include golang-jwt, gin-jwt, jwx, and Auth0; added "When NOT to Use This" section with four explicit anti-use-cases and recommended alternatives.

- **`README.md` — terminology** — replaced all "TokenManager" prose references with "TokenService" (concept) or `Manager` (Go type); added "stateful" qualifier consistently throughout; replaced "authentication" with "authorization" in post-login contexts to align with what jwtauth actually does.

- **`doc/ARCHITECTURE.md` — terminology and positioning** — updated title and overview to reflect stateful JWT authorization engine positioning; replaced all "TokenManager" occurrences with "TokenService" / `Manager`.

- **`doc/MIGRATION.md`** — new file; step-by-step migration guides from `golang-jwt/jwt` (manual token management → jwtauth), `gin-jwt` (framework lock-in → framework-agnostic middleware), and `lestrrat-go/jwx` (JOSE toolkit → focused engine). Covers common patterns (adding refresh tokens, adding revocation, zero-downtime key rotation), single-instance-to-distributed upgrade path, and a 10-item migration checklist.

- **`doc/adr/`** — new directory; three Architecture Decision Records:
  - `001-no-rate-limiting.md` — rate limiting belongs at the infrastructure layer (API Gateway, Ingress); jwtauth stays focused on token lifecycle.
  - `002-stateful-refresh-tokens.md` — refresh tokens are opaque UUIDs stored server-side for instant revocation; stateless refresh tokens were rejected because they cannot be revoked before expiry.
  - `003-rs256-only.md` — RS256 asserted unconditionally in `ValidateAccessToken` to prevent algorithm confusion attacks (CVE-2015-9235); ES256 and configurable algorithms were rejected.

- **`pkg/tokens` — package doc comment** — added `// Package tokens ...` comment with key capability list (access token issuance, refresh token rotation, instant revocation, distributed cleanup) and canonical usage example covering the full token lifecycle.

- **`pkg/keymanager` — package doc comment** — added `// Package keymanager ...` comment with rotation timeline ASCII diagram (Day 0 → Day 30 → Day 30+1h) and storage backend summary.

- **`README.md` — "Why This Library?" rewrite** — new positioning statement (authz layer, not authn), comparison vs. `golang-jwt/jwt` (build-vs-buy table), vs. framework JWT middleware (`gin-jwt`, `echo-jwt`) — previously missing entirely, vs. `lestrrat-go/jwx` / `go-jose/go-jose` JOSE toolkits, concrete security guarantees block (algorithm confusion, reserved claim protection, 10 sentinel errors, instant revocation), horizontal scale path table (`DiskKeyStore`+`MemoryRefreshStore` → `RedisKeyStore`+`RedisRefreshStore`), and "What jwtauth is not" closing paragraph.

- **`pkg/logging/README.md` — brought up to date** — corrected "3 log levels" to 4, added `Debug` level section with examples, updated Quick Start to recommend `NewCorrelationJSONLogger` as the production default, added full Correlation ID section (setup, HTTP middleware pattern, output examples, log aggregator filtering, and API reference table), fixed third-party adapter examples for Zap and Zerolog (both were missing the `Debug` method and would not satisfy the `Logger` interface), fixed broken `See Also` link.

- **`doc/ARCHITECTURE.md` — correlation ID and updated examples** — added `correlation-example/` to the project structure file tree, added Correlation ID subsection to the Logging section explaining the `ctx`-as-first-kwarg convention and `CorrelationIDHandler` wiring, updated the Integration Pattern code example to pass `ctx` as the first logger kwarg.

- **`examples/correlation-example/README.md`** — new file; full README matching the structure of Gin/Chi/Echo example READMEs. Covers setup, API testing with curl and expected JSON log output, implementation details (logger choice, `withCorrelation` middleware, `ctx`-as-first-kwarg convention, auto-generated IDs), and how to apply the same pattern to Gin, Chi, or Echo.

- **`examples/README.md`** — added Correlation ID Example entry, cross-reference note in the Common Pattern section, updated Framework Comparison table with a Correlation ID column, corrected title (jwtauth is an engine, not a framework).

---

## [v0.3.0] — 2026-04-14

### Added

- **`ManagerConfig.ClockSkew time.Duration`** — leeway applied to `exp` and `nbf` validation via `jwt.WithLeeway()`. Zero (the default) means strict validation. Negative values are rejected with `ErrInvalidConfig` at construction time.

- **`Manager.ValidateAccessTokenWithClaims(ctx, token)`** — validates an access token and returns both the registered claims (`*jwt.RegisteredClaims`) and application-defined custom claims (`map[string]interface{}`). Reserved JWT fields (`sub`, `exp`, `nbf`, `iat`, `jti`, `iss`, `aud`) are excluded from the custom map. Uses `ParseUnverified` after signature verification — no second key-manager round-trip.

- **`error_type` label on all counter metrics** — follows the OpenTelemetry `error.type` semantic convention. Value is `""` on success and mirrors the `status` label value on failure. Added to: `tokens_issued_total`, `tokens_validated_total`, `tokens_refreshed_total`, `storage_operations_total`, `keystore_operations_total`, `key_rotations_total`, `key_signing_operations_total`, `key_validation_operations_total`.

- **Context propagation in `KeyManager` interface** — `GetCurrentSigningKey(ctx context.Context)` and `GetPublicKey(ctx context.Context, kid string)` now accept a context. All call sites updated.

- **Specific JSON error codes in example middleware** — all three framework examples (Gin, Chi, Echo) now map library sentinel errors to structured JSON error codes (`token_expired`, `token_not_yet_valid`, `token_revoked`, `invalid_issuer`, `invalid_audience`, `invalid_token`, `missing_token`, `invalid_authorization_format`) via `errors.Is()` switch.

- **Prometheus metrics wired into all example `main.go` files** — all three examples now construct `metrics.NewPrometheusMetrics`, pass it to every constructor, and expose a `/metrics` endpoint.

- **Correlation ID logging** — `logging.WithCorrelationID(ctx, id)` and `logging.GetCorrelationID(ctx)` context helpers with an unexported key type that prevents collisions with external packages. `CorrelationIDHandler` wraps any `slog.Handler` and injects a `correlation_id` field into every log record when a correlation ID is present in the context. `SlogAdapter` now routes to slog's `*Context()` methods when `context.Context` is passed as the first variadic arg. `NewCorrelationJSONLogger` and `NewCorrelationTextLogger` convenience constructors pre-wire the handler. `examples/correlation-example/main.go` demonstrates end-to-end HTTP middleware usage.

- **All internal logging call sites pass `ctx`** — every `logger.Info/Debug/Warn/Error` call in `pkg/keymanager`, `pkg/tokens`, and `pkg/storage` now forwards the in-scope `context.Context` as the first variadic arg, enabling correlation ID injection at all component boundaries without any Logger interface changes.

- **Context cancellation guard in `GetJWKS`** — returns the context error immediately after the running check, before acquiring the read lock.

- **Context cancellation guard in `cleanupExpiredKeys`** — logs a warning and returns early when the context is already cancelled at sweep time.

- **Redis integration tests** — `pkg/tokens/integration` suite using miniredis covers distributed token refresh, revocation, and cleanup across all RefreshStore backends (closes #60).

### Changed

- **`ErrKeyNotFound` in `ValidateAccessToken` maps to `ErrInvalidToken`** — a token referencing an unknown `kid` now returns `ErrInvalidToken` (was `ErrInvalidSignature`, which was semantically incorrect for a missing-key condition).

- **`KeyManager` interface requires context on all read methods** — `GetCurrentSigningKey`, `GetPublicKey`, and `GetJWKS` signatures now all accept `context.Context`. Any custom `KeyManager` implementation must be updated.

### Removed

- **`ErrInvalidSignature`** — removed; was semantically misleading. The condition it covered (unknown `kid`) now maps to `ErrInvalidToken`. Update any `errors.Is(err, tokens.ErrInvalidSignature)` checks to `errors.Is(err, tokens.ErrInvalidToken)`.
