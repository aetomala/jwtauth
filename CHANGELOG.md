# Changelog

All notable changes to this project will be documented in this file.

---

> **License change:** Starting with v0.5.0, this project is licensed under the
> [Apache License 2.0](LICENSE). Releases v0.4.0 and earlier remain available
> under the MIT License.

---

## [Unreleased — v0.5.0]

### Breaking

- **`storage.RefreshStore.Store()` gains `audience []string` parameter** — all custom `RefreshStore` implementations must update their `Store()` method signature. `MemoryRefreshStore` and `RedisRefreshStore` are already updated. Add a compile-time assertion to catch the gap early: `var _ storage.RefreshStore = (*MyStore)(nil)`. See #124 and `UPGRADING.md`.

- **`storage.RefreshStore` gains `RevokeAllForAudience` and `RevokeAllForUserAndAudience`** — all custom `RefreshStore` implementations must add both methods or they will not compile. `MemoryRefreshStore` and `RedisRefreshStore` are already updated. See #135 and `UPGRADING.md`.

- **`jwtauth_tokens_revoked_total` label `operation` renamed to `revocation_scope`** — update any Prometheus alert rules, recording rules, or dashboards that filter or group by the old label name. Existing label values (`"single"`, `"all_user"`) are unchanged. See #124.

### Added

- **`IssueOption` type and `WithAudience` functional option** — all six issuance methods (`IssueAccessToken`, `IssueAccessTokenWithClaims`, `IssueRefreshToken`, `IssueRefreshTokenWithClaims`, `IssueTokenPair`, `IssueTokenPairWithClaims`) now accept a variadic `...tokens.IssueOption` parameter. All existing call sites compile unchanged — the parameter is optional and defaults to the manager's configured audience. Use `tokens.WithAudience("svc-payments")` to target a specific audience for a single call. See #124.

- **`RefreshToken.Audience []string`** — the stored refresh token record now carries the audience slice resolved at issuance time. `RefreshAccessToken` and `RefreshAccessTokenWithClaims` propagate this stored audience into the new access token so the refreshed token targets the same audience as the original. See #124.

- **`TokenMetadata.Audience []string`** — `IntrospectToken` now populates the `Audience` field on active, revoked, and expired paths. The not-found path leaves the field nil. See #124.

- **`tokens.Manager.RevokeAllForAudience(ctx, audience) error`** — revokes all non-expired refresh tokens targeting the given audience across all users. Multi-audience tokens are revoked globally — a token carrying the targeted audience is fully revoked regardless of its other audiences. Emits `revocation_scope="audience"` on `jwtauth_tokens_revoked_total`. See #135.

- **`tokens.Manager.RevokeAllForUserAndAudience(ctx, userID, audience) error`** — revokes all non-expired refresh tokens for a specific user and audience. Tokens for other users in the same audience are not affected. Emits `revocation_scope="user_audience"`. See #135.

- **`storage.ErrInvalidAudience`** — sentinel returned when an empty string is passed as the audience argument to the new revocation methods. See #135.

---

## [v0.4.0] — 2026-04-30

### Breaking

- **`logging.Logger` gains `With(keysAndValues ...interface{}) Logger`** — existing third-party adapter implementations (Zap, Zerolog, Logrus, etc.) must add this method. Built-in implementations (`SlogAdapter`, `NoOpLogger`) and `MockLogger` are already updated. `With` is additive — chained calls accumulate fields. `NoOpLogger` may return the receiver unchanged.

- **`keys.KeyStore` gains `Namespace() string`** — existing implementations must add this method. `RedisKeyStore` returns the configured `KeyPrefix`; `DiskKeyStore` returns `""`. `MockKeyStore` regenerated.

- **`storage.RefreshStore` gains `Namespace() string`** — existing implementations must add this method. `RedisRefreshStore` returns the configured `KeyPrefix`; `MemoryRefreshStore` returns `""`. `MockRefreshStore` regenerated.

- **`storage.RefreshStore` gains `ListTokens(ctx, cursor, count)` method** — existing third-party implementations must add this method. `MemoryRefreshStore` and `RedisRefreshStore` are already updated. See #105.

- **`storage.RefreshStore` gains `ListTokensForUser(ctx, userID, cursor, count)` method** — existing third-party implementations must add this method. `MemoryRefreshStore` and `RedisRefreshStore` are already updated. See #105.

### Security

- **`aud` added to reserved claims guard in `IssueAccessTokenWithClaims` and `IssueTokenPairWithClaims`** — callers can no longer override the manager's configured audience via custom claims. The warn-log path already covered this case; only the guard map needed updating. See #109 and ADR-008.

- **`kid` path traversal fix** — `DiskKeyStore` and `RedisKeyStore` now validate the
  `kid` header value against a UUID v4 format at every method boundary (`Save`,
  `UpdateMetadata`, `LoadKey`, `Delete`) before constructing any filesystem path or
  Redis key. Tokens with crafted `kid` values (e.g. `../../../etc/passwd`) are
  rejected with `ErrKeyStoreInvalidKeyID` before any I/O. See ADR-004 and ADR-005.

### Changed

- **Minimum Go version raised to 1.26.2** — `go.mod` (root and all example modules), CI workflow, and README badge updated from 1.25 to 1.26.2. Driven by stdlib vulnerability fixes available only in the 1.26 lineage.

- **`IssueAccessTokenWithClaims` parameter type changed** from `map[string]interface{}` to `CustomClaims` — update call sites: `map[string]interface{}{"k": v}` → `tokens.CustomClaims{"k": v}`.

- **`IssueRefreshTokenWithMetadata` renamed to `IssueRefreshTokenWithClaims`** — parameter renamed from `metadata` to `claims` with type `CustomClaims`; span name updated to match. Update all call sites.

- **`DiskKeyStore`, `RedisKeyStore`, `MemoryRefreshStore`, `RedisRefreshStore` constructors migrated to config-struct form** — positional parameter constructors removed; update call sites:
  - `keys.NewDiskKeyStore(dir, keySize, logger, metrics)` → `keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: dir, KeySize: keySize, Logger: logger, Metrics: metrics})`
  - `keys.NewRedisKeyStore(client, logger, metrics)` → `keys.NewRedisKeyStore(keys.RedisKeyStoreConfig{Client: client, Logger: logger, Metrics: metrics})`
  - `storage.NewMemoryRefreshStore(logger, metrics)` → `storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{Logger: logger, Metrics: metrics})`
  - `storage.NewRedisRefreshStore(client, logger, metrics)` → `storage.NewRedisRefreshStore(storage.RedisRefreshStoreConfig{Client: client, Logger: logger, Metrics: metrics})`

- **`tokens.Service` → `tokens.Manager`** — The core token lifecycle type is renamed. Update all call sites:
  - `tokens.NewService(tokens.ServiceConfig{...})` → `tokens.NewManager(tokens.TokenManagerConfig{...})`
  - `tokens.ConfigDefault()` → `tokens.DefaultTokenManagerConfig()`
  - `tokens.ErrServiceNotRunning` → `tokens.ErrManagerNotRunning`
  - `*tokens.Service` type references → `*tokens.Manager`

- **`AuthMiddleware` → `BearerMiddleware`** in all example middleware packages (`examples/gin-example/middleware`, `examples/chi-example/auth`, `examples/echo-example/middleware`). Rename call sites accordingly.

- **Nil logger/metrics guards eliminated** across all five components — `Logger` and `Metrics` fields are now assigned `&logging.NoOpLogger{}` / `metrics.NewNoOpMetrics()` at construction when `nil` is passed; every call site in `pkg/keys/`, `pkg/metrics/prometheus.go`, and `pkg/tokens/` invokes `m.logger` and `m.metrics` unconditionally. Passing `nil` continues to work — it silently activates the no-op. Previously 217 call-site guards were scattered across five files.

- **`pkg/keymanager` renamed to `pkg/keys`** — update all import paths from
  `github.com/aetomala/jwtauth/pkg/keymanager` → `github.com/aetomala/jwtauth/pkg/keys`;
  update qualifier `keymanager.` → `keys.` at all call sites.

- **`keys.ManagerConfig` → `keys.KeyManagerConfig`** — config struct renamed for
  unambiguous identification when both managers appear side by side.

- **`keys.ConfigDefault()` → `keys.DefaultKeyManagerConfig()`** — constructor
  renamed to match the config struct name.

- **`tokens.ManagerConfig` → `tokens.TokenManagerConfig`** — config struct renamed
  for consistency with `keys.KeyManagerConfig`; update all call sites.

- **`tokens.DefaultManagerConfig()` → `tokens.DefaultTokenManagerConfig()`** —
  constructor renamed to match the config struct name.

- **`pkg/logging` file renames** — `logger.go` → `interface.go`,
  `slog_adapter.go` → `slog.go`; file-level references in documentation updated
  accordingly. No API changes.

- **`TokenError` struct and `NewTokenError()` removed** — sentinel errors in
  `pkg/tokens` (`ErrTokenExpired`, `ErrTokenNotYetValid`, `ErrInvalidAudience`,
  `ErrInvalidIssuer`) are now plain `errors.New()` values. Any code that type-asserts
  to `*tokens.TokenError` must be updated; `errors.Is()` behavior is unchanged.

### Added

- **`CONTRIBUTING.md`** — new root-level contributor guide consolidating requirements, dev workflow (`run-ci-locally.sh`), branching/PR rules, and code standards. README Contributing section and ARCHITECTURE.md Testing Requirements block now point here instead of duplicating the content.

- **`govulncheck` added to CI and local pipeline** — runs as a lint-job step in `.github/workflows/CI.yml` and in `run-ci-locally.sh` after `golangci-lint`; checks all packages against the Go vulnerability database on every push.

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

- **`KeyInfo` struct** — public metadata type in `pkg/keys` exposing `KeyID`, `CreatedAt`, `RotateAt` (estimated, current key only), `ExpiresAt`, `KeySizeBits`, `Algorithm`, `IsCurrent`, and `IsValid`. Contains no private key material — safe to serve from health check or admin endpoints.

- **`GetKeyInfo(ctx, keyID)`** on `keys.Manager` — returns `*KeyInfo` for a specific key by ID. Pass an empty string to resolve the current signing key. Respects context cancellation. Returns `ErrManagerNotRunning` or `ErrKeyNotFound` as appropriate. `KeySizeBits` reflects the actual RSA modulus bit length of the key on disk, not the configured `KeySize`.

- **`GetCurrentKeyInfo(ctx)`** on `keys.Manager` — convenience wrapper around `GetKeyInfo(ctx, "")` for the common case of inspecting the active signing key.

- **`GetKeyInfo` and `GetCurrentKeyInfo` on `keys.KeyManager` interface** — both methods are now part of the `KeyManager` interface, enabling dependency injection and test doubles for any code that inspects key metadata. `internal/testutil/mock_keys.go` has been regenerated with corresponding stubs (`MockKeyManager.GetKeyInfo`, `MockKeyManager.GetCurrentKeyInfo`).

- **Integration tests for `GetCurrentKeyInfo` and `GetKeyInfo`** — three new cases added to `RunTokenManagerIntegrationTests` and run against all storage backends (DiskKeyStore+MemoryRefreshStore, RedisKeyStore+RedisRefreshStore): verifies accurate field values after `Start()`; verifies that `GetCurrentKeyInfo` reflects the new key after `RotateKeys()` while the old key remains accessible via `GetKeyInfo`; verifies that 20 concurrent `GetCurrentKeyInfo` calls during an active `RotateKeys()` produce no data races (real `Manager.mu` lock path exercised under `-race`).

- **`KeyPrefix` field added to `RedisKeyStoreConfig` and `RedisRefreshStoreConfig`** — optional string prepended to all Redis keys, enabling per-tenant namespace isolation when multiple `Manager` instances share a single Redis instance. Defaults to empty string — fully backward compatible. See #104.

- **`ListTokens(ctx, cursor, count)` added to `RefreshStore` interface and both implementations** — cursor-based token iteration for resumable reconciliation jobs, audit pipelines, and bulk operations. `MemoryRefreshStore` uses a sorted tokenID cursor; `RedisRefreshStore` uses Redis SCAN cursor passthrough. Pass an empty string for cursor to begin from the start; returns an empty cursor when iteration is exhausted. Count is a hint — actual page size may vary. All tokens are returned regardless of revocation or expiry status — caller is responsible for filtering. `MockRefreshStore` regenerated. See #105.

- **`Manager.ListTokens(ctx, cursor, count)` added to `tokens.Manager`** — thin delegation to the underlying `RefreshStore.ListTokens` following the established `CleanupExpiredTokens` pattern. Emits a `token.list_tokens` span (attrs: `token.namespace`, `token.cursor`, `token.count`, `token.result_count`), logs success and failure, and records `jwtauth_tokens_list_total` counter and `jwtauth_tokens_list_duration_seconds` histogram with `namespace` and `error_type` labels.

- **Compile-time `var _ RefreshStore` assertions added to `MemoryRefreshStore` and `RedisRefreshStore`** — interface compliance is now verified at compile time. Closes #106.

- **4 new Prometheus metrics registered in `PrometheusMetrics`** — storage-layer metrics (`jwtauth_storage_list_tokens_total`, `jwtauth_storage_list_tokens_duration_seconds`) and token-manager-layer metrics (`jwtauth_tokens_list_total`, `jwtauth_tokens_list_duration_seconds`); all carry `namespace` and `error_type` labels.

- **`ListTokensForUser(ctx, userID, cursor, count)` added to `RefreshStore` interface and both implementations** — user-scoped cursor-based token iteration. `MemoryRefreshStore` uses an integer offset cursor into the user's insertion-order token slice; `RedisRefreshStore` uses Redis SSCAN cursor passthrough on the user set key, hydrating tokens via the existing `fetchTokensByIDs` pipeline helper. Returns `ErrInvalidUserID` if `userID` is empty. All other cursor and filtering semantics are identical to `ListTokens`. `MockRefreshStore` regenerated. See #105.

- **`Manager.ListTokensForUser(ctx, userID, cursor, count)` added to `tokens.Manager`** — thin delegation to `RefreshStore.ListTokensForUser` following the same pattern as `Manager.ListTokens`. Emits a `token.list_tokens_for_user` span (attrs: `token.namespace`, `token.user_id`, `token.cursor`, `token.count`, `token.result_count`), logs success and failure, and records `jwtauth_tokens_list_for_user_total` counter and `jwtauth_tokens_list_for_user_duration_seconds` histogram with `namespace` and `error_type` labels.

- **4 additional Prometheus metrics registered in `PrometheusMetrics`** — storage-layer metrics (`jwtauth_storage_list_tokens_for_user_total`, `jwtauth_storage_list_tokens_for_user_duration_seconds`) and token-manager-layer metrics (`jwtauth_tokens_list_for_user_total`, `jwtauth_tokens_list_for_user_duration_seconds`); all carry `namespace` and `error_type` labels.

- **`Namespace string` added to `KeyManagerConfig` and `TokenManagerConfig`** — optional opaque label stored in both manager structs at construction time. Zero value preserves current behavior — no label is attached to observability output. Intended for multi-instance deployments where log lines, trace spans, and metric labels from different manager instances must be disambiguated. Decoupled from `KeyPrefix` — both fields may be set independently. See ADR-007.

- **`RedisKeyStore` and `RedisRefreshStore` emit namespace across all three signal types** — when `KeyPrefix` is non-empty, every span carries a `storage.namespace` attribute, every log line carries a `namespace` field (via `Logger.With` in the constructor — no per-call-site changes), and every Prometheus metric carries a `namespace` label. Zero-value `KeyPrefix` emits an empty string label, preserving backward compatibility. Closes #112 (Phase 3).

- **`KeyManager` emits namespace across all three signal types** — every span carries a `key.namespace` attribute, every log line carries a `namespace` field (via `Logger.With` in the constructor), and every Prometheus label on key management metrics (`key_rotations_total`, `key_signing_operations_total`, `key_validation_operations_total`, `key_operation_duration_seconds`, `key_active_versions_count`) includes `namespace`. Zero-value `Namespace` emits an empty string label, preserving backward compatibility. Closes #112 (Phase 4).

- **`TokenManager` emits namespace across all three signal types** — every span carries a `token.namespace` attribute, every log line carries a `namespace` field (via `Logger.With` in the constructor), and every Prometheus label on token management metrics (`tokens_issued_total`, `tokens_validated_total`, `tokens_refreshed_total`, `tokens_revoked_total`, `tokens_introspected_total`, `operations_total`, `operation_duration_seconds`, `active_tokens`) includes `namespace`. Zero-value `Namespace` emits an empty string label, preserving backward compatibility. Closes #112 (Phase 5).

- **`TokenMetadata.TokenID` (`jti`) populated by `IntrospectToken`** — callers can now revoke a token by ID directly from introspection results without parsing the JWT themselves (closes #108). Per RFC 7662 §2.2; set from `refreshToken.TokenID` for found tokens and from the caller-supplied token string for the not-found path.

### Fixed

- **`KeyInfo.KeySizeBits` now reports actual key size** — previously sourced from `KeyManagerConfig.KeySize` (caller-supplied), which could silently diverge from the actual RSA key on disk if the `DiskKeyStore` or `RedisKeyStore` was configured with a different key size. Now derived from `keyPair.PrivateKey.N.BitLen()` so the reported value always matches the real key material.

- **`pkg/tracing` package** — `Tracer` and `Span` interfaces defining the distributed tracing contract. `SpanOption` functional options pattern for span configuration. `StatusCode` (`Unset`, `Error`, `OK`) and `SpanKind` (`Internal`, `Server`, `Client`, `Producer`, `Consumer`) enumerations with `String()` methods. `WithAttributes` and `WithSpanKind` option constructors.

- **`NoOpTracer` / `NoOpSpan`** — zero-allocation no-op implementations; safe to use when tracing is disabled. 36 tests covering constructor, span creation, all span methods, concurrency, and edge cases; race-detection clean.

- **`MockTracer` / `MockSpan`** — gomock mocks generated via `go:generate` directive in `pkg/tracing/interface.go`; available in `internal/testutil/mock_tracing.go` for dependency injection in component tests.

- **`pkg/tracing` included in CI** — added to the unit test command in both `.github/workflows/CI.yml` and `run-ci-locally.sh`.

### Documentation

- **`README.md` — value proposition audit** — added elevator pitch above the fold (one sentence stating the problem jwtauth solves); moved "Why This Library?" from line ~892 to immediately after Overview; added "What Problem Does This Solve?" section framing the post-login token lifecycle gap; strengthened comparison matrix to include golang-jwt, gin-jwt, jwx, and Auth0; added "When NOT to Use This" section with four explicit anti-use-cases and recommended alternatives.

- **`README.md` — terminology** — replaced all "TokenManager" prose references with "TokenService" (concept) or `Manager` (Go type); added "stateful" qualifier consistently throughout; replaced "authentication" with "authorization" in post-login contexts to align with what jwtauth actually does.

- **`doc/ARCHITECTURE.md` — terminology and positioning** — updated title and overview to reflect stateful JWT authorization engine positioning; replaced all "TokenManager" occurrences with "TokenService" / `Manager`.

- **ADR-004 and ADR-005 cross-referenced in `README.md` and `doc/ARCHITECTURE.md`** — `004-kid-validation.md` and `005-security-boundaries.md` added to the `doc/adr/` directory tree and the Architecture Decision Records table in both files.

- **`doc/MIGRATION.md`** — new file; step-by-step migration guides from `golang-jwt/jwt` (manual token management → jwtauth), `gin-jwt` (framework lock-in → framework-agnostic middleware), and `lestrrat-go/jwx` (JOSE toolkit → focused engine). Covers common patterns (adding refresh tokens, adding revocation, zero-downtime key rotation), single-instance-to-distributed upgrade path, and a 10-item migration checklist.

- **`doc/adr/`** — new directory; three Architecture Decision Records:
  - `001-no-rate-limiting.md` — rate limiting belongs at the infrastructure layer (API Gateway, Ingress); jwtauth stays focused on token lifecycle.
  - `002-stateful-refresh-tokens.md` — refresh tokens are opaque UUIDs stored server-side for instant revocation; stateless refresh tokens were rejected because they cannot be revoked before expiry.
  - `003-rs256-only.md` — RS256 asserted unconditionally in `ValidateAccessToken` to prevent algorithm confusion attacks (CVE-2015-9235); ES256 and configurable algorithms were rejected.

- **`pkg/tokens` — package doc comment** — added `// Package tokens ...` comment with key capability list (access token issuance, refresh token rotation, instant revocation, distributed cleanup) and canonical usage example covering the full token lifecycle.

- **`pkg/keys` — package doc comment** — added `// Package keys ...` comment with rotation timeline ASCII diagram (Day 0 → Day 30 → Day 30+1h) and storage backend summary.

- **`README.md` — "Why This Library?" rewrite** — new positioning statement (authz layer, not authn), comparison vs. `golang-jwt/jwt` (build-vs-buy table), vs. framework JWT middleware (`gin-jwt`, `echo-jwt`) — previously missing entirely, vs. `lestrrat-go/jwx` / `go-jose/go-jose` JOSE toolkits, concrete security guarantees block (algorithm confusion, reserved claim protection, 10 sentinel errors, instant revocation), horizontal scale path table (`DiskKeyStore`+`MemoryRefreshStore` → `RedisKeyStore`+`RedisRefreshStore`), and "What jwtauth is not" closing paragraph.

- **`pkg/logging/README.md` — brought up to date** — corrected "3 log levels" to 4, added `Debug` level section with examples, updated Quick Start to recommend `NewCorrelationJSONLogger` as the production default, added full Correlation ID section (setup, HTTP middleware pattern, output examples, log aggregator filtering, and API reference table), fixed third-party adapter examples for Zap and Zerolog (both were missing the `Debug` method and would not satisfy the `Logger` interface), fixed broken `See Also` link.

- **`doc/ARCHITECTURE.md` — correlation ID and updated examples** — added `correlation-example/` to the project structure file tree, added Correlation ID subsection to the Logging section explaining the `ctx`-as-first-kwarg convention and `CorrelationIDHandler` wiring, updated the Integration Pattern code example to pass `ctx` as the first logger kwarg.

- **`examples/correlation-example/README.md`** — new file; full README matching the structure of Gin/Chi/Echo example READMEs. Covers setup, API testing with curl and expected JSON log output, implementation details (logger choice, `withCorrelation` middleware, `ctx`-as-first-kwarg convention, auto-generated IDs), and how to apply the same pattern to Gin, Chi, or Echo.

- **`examples/README.md`** — added Correlation ID Example entry, cross-reference note in the Common Pattern section, updated Framework Comparison table with a Correlation ID column, corrected title (jwtauth is an engine, not a framework).

- **`doc/UPGRADING.md`** — new file; step-by-step upgrade guide from v0.3.x → v0.4.0 covering all eight categories of breaking changes with Before/After code snippets, compile-time assertion guidance, and a dedicated section for interface additions that affect only custom implementations. Created in PR #121.

- **ADR-006, ADR-007, ADR-008** — three additional Architecture Decision Records:
  - `006-keyprefix-opaque-namespace.md` — `KeyPrefix` as an opaque Redis key namespace separator; empty string preserves existing layout; library does not interpret or validate the value.
  - `007-namespace-consistency-contract.md` — `Namespace` as a decoupled observability label on `KeyManagerConfig` and `TokenManagerConfig`; independent of `KeyPrefix`; zero value preserves existing behavior.
  - `008-reserved-claims-at-issuance.md` — reserved JWT claim protection at issuance; `CustomClaims` entries for `sub`, `iss`, `aud`, `exp`, `iat`, `nbf`, `jti` are silently dropped; per-call audience targeting deferred to a future `WithAudience` IssueOption (see #124).

- **`examples/token-audit/`** — new example demonstrating cursor-based token enumeration using `ListTokens` and `ListTokensForUser`; covers resumable pagination for audit and reconciliation pipelines. Created in PR #121.

- **`doc/DEPLOYMENT.md` additions** — four new operator-facing sections added in PRs #126–#129: namespace isolation (multi-instance `KeyPrefix` + `Namespace` wiring), token enumeration (cursor-based audit pattern), reserved claims (CustomClaims guard explanation with link to ADR-008), and corrected constructor snippets throughout.

### Bug Fixes

- **`TokenManager.Shutdown` — restart-safety**: `shutdownChan` is now recreated after a
  clean shutdown, matching `KeyManager`'s existing pattern. Previously, calling
  `Start → Shutdown → Start` would silently break the cleanup goroutine on the second start —
  `IsRunning()` returned `true` but background cleanup was dead.

- **`TokenManager.Shutdown` — pre-cancelled context drain**: Added a non-blocking ctx drain
  before the blocking goroutine-wait select, eliminating the same race condition fixed in
  `KeyManager.Shutdown` (PR #137). Prevents flaky behavior when both `done` and `ctx.Done()`
  are simultaneously ready.

- **`prometheus-metrics` example — graceful shutdown**: Replaced `http.ListenAndServe` with
  `http.Server.Shutdown` and `signal.NotifyContext` (SIGTERM/SIGINT). Background collection
  goroutine now exits cleanly on signal instead of only via `os.Exit`.

### Testing

- **`pkg/tokens` test DRY cleanup — shared `newTestManager` helper** — `createService` closure was independently defined in both `manager_test.go` and `manager_lifecycle_test.go`; extracted to `pkg/tokens/helpers_test.go` as `newTestManagerConfig` and `newTestManager` package-level helpers within the `tokens_test` package. 25 call sites updated across both files — no new dependency between packages. Fixes DRY violation M4.

- **`pkg/keys` test DRY cleanup — hoisted `ctrl` and `mockKS` to outer `Describe` scope** — `var ctrl *gomock.Controller` and `var mockKS *testutil.MockKeyStore` were independently declared, initialized in `BeforeEach`, and torn down with `ctrl.Finish()` in `AfterEach` inside each phase-level `Describe` block. Both vars moved to the outer `Describe("Manager")` var block with a single shared `BeforeEach`/`AfterEach` pair. Equivalent declarations removed from Phases 1, 3, 4, 5, 6, 7, 8, 9, 10, and 11 — 11 insertions, 98 deletions. The locally-scoped `ctrl2` in Phase 7 is untouched. Fixes DRY violation M5.

- **Integration test coverage extended — three new behavioral specs** added to `RunTokenManagerIntegrationTests` and run against both backends (DiskKeyStore+MemoryRefreshStore, RedisKeyStore+RedisRefreshStore): token listing and user-scoped filtering via `ListTokens` / `ListTokensForUser`; custom claims round-trip through `IssueAccessTokenWithClaims`, `IssueTokenPairWithClaims`, and `ValidateAccessTokenWithClaims`; individual token revocation via `RevokeRefreshToken` without disturbing other sessions for the same user.

- **`--fail-on-pending` added to integration test invocation** in both `.github/workflows/CI.yml` and `run-ci-locally.sh` — consistent with the existing unit test flags; prevents accidentally skipping pending specs from silently passing CI.

---

## [v0.3.0] — 2026-04-14

### Added

- **`TokenManagerConfig.ClockSkew time.Duration`** — leeway applied to `exp` and `nbf` validation via `jwt.WithLeeway()`. Zero (the default) means strict validation. Negative values are rejected with `ErrInvalidConfig` at construction time.

- **`Manager.ValidateAccessTokenWithClaims(ctx, token)`** — validates an access token and returns both the registered claims (`*jwt.RegisteredClaims`) and application-defined custom claims (`map[string]interface{}`). Reserved JWT fields (`sub`, `exp`, `nbf`, `iat`, `jti`, `iss`, `aud`) are excluded from the custom map. Uses `ParseUnverified` after signature verification — no second key-manager round-trip.

- **`error_type` label on all counter metrics** — follows the OpenTelemetry `error.type` semantic convention. Value is `""` on success and mirrors the `status` label value on failure. Added to: `tokens_issued_total`, `tokens_validated_total`, `tokens_refreshed_total`, `storage_operations_total`, `keystore_operations_total`, `key_rotations_total`, `key_signing_operations_total`, `key_validation_operations_total`.

- **Context propagation in `KeyManager` interface** — `GetCurrentSigningKey(ctx context.Context)` and `GetPublicKey(ctx context.Context, kid string)` now accept a context. All call sites updated.

- **Specific JSON error codes in example middleware** — all three framework examples (Gin, Chi, Echo) now map library sentinel errors to structured JSON error codes (`token_expired`, `token_not_yet_valid`, `token_revoked`, `invalid_issuer`, `invalid_audience`, `invalid_token`, `missing_token`, `invalid_authorization_format`) via `errors.Is()` switch.

- **Prometheus metrics wired into all example `main.go` files** — all three examples now construct `metrics.NewPrometheusMetrics`, pass it to every constructor, and expose a `/metrics` endpoint.

- **Correlation ID logging** — `logging.WithCorrelationID(ctx, id)` and `logging.GetCorrelationID(ctx)` context helpers with an unexported key type that prevents collisions with external packages. `CorrelationIDHandler` wraps any `slog.Handler` and injects a `correlation_id` field into every log record when a correlation ID is present in the context. `SlogAdapter` now routes to slog's `*Context()` methods when `context.Context` is passed as the first variadic arg. `NewCorrelationJSONLogger` and `NewCorrelationTextLogger` convenience constructors pre-wire the handler. `examples/correlation-example/main.go` demonstrates end-to-end HTTP middleware usage.

- **All internal logging call sites pass `ctx`** — every `logger.Info/Debug/Warn/Error` call in `pkg/keys`, `pkg/tokens`, and `pkg/storage` now forwards the in-scope `context.Context` as the first variadic arg, enabling correlation ID injection at all component boundaries without any Logger interface changes.

- **Context cancellation guard in `GetJWKS`** — returns the context error immediately after the running check, before acquiring the read lock.

- **Context cancellation guard in `cleanupExpiredKeys`** — logs a warning and returns early when the context is already cancelled at sweep time.

- **Redis integration tests** — `pkg/tokens/integration` suite using miniredis covers distributed token refresh, revocation, and cleanup across all RefreshStore backends (closes #60).

### Changed

- **`ErrKeyNotFound` in `ValidateAccessToken` maps to `ErrInvalidToken`** — a token referencing an unknown `kid` now returns `ErrInvalidToken` (was `ErrInvalidSignature`, which was semantically incorrect for a missing-key condition).

- **`KeyManager` interface requires context on all read methods** — `GetCurrentSigningKey`, `GetPublicKey`, and `GetJWKS` signatures now all accept `context.Context`. Any custom `KeyManager` implementation must be updated.

### Removed

- **`ErrInvalidSignature`** — removed; was semantically misleading. The condition it covered (unknown `kid`) now maps to `ErrInvalidToken`. Update any `errors.Is(err, tokens.ErrInvalidSignature)` checks to `errors.Is(err, tokens.ErrInvalidToken)`.
