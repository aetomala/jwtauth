# Changelog

All notable changes to this project will be documented in this file.

---

## [Unreleased] — v0.4.0

### Added

- **`pkg/tracing` package** — `Tracer` and `Span` interfaces defining the distributed tracing contract. `SpanOption` functional options pattern for span configuration. `StatusCode` (`Unset`, `Error`, `OK`) and `SpanKind` (`Internal`, `Server`, `Client`, `Producer`, `Consumer`) enumerations with `String()` methods. `WithAttributes` and `WithSpanKind` option constructors.

- **`NoOpTracer` / `NoOpSpan`** — zero-allocation no-op implementations; safe to use when tracing is disabled. 36 tests covering constructor, span creation, all span methods, concurrency, and edge cases; race-detection clean.

- **`MockTracer` / `MockSpan`** — gomock mocks generated via `go:generate` directive in `pkg/tracing/interface.go`; available in `internal/testutil/mock_tracing.go` for dependency injection in component tests.

- **`pkg/tracing` included in CI** — added to the unit test command in both `.github/workflows/CI.yml` and `run-ci-locally.sh`.

---

## [v0.3.0] — 2026-04-14

### Added

- **`ServiceConfig.ClockSkew time.Duration`** — leeway applied to `exp` and `nbf` validation via `jwt.WithLeeway()`. Zero (the default) means strict validation. Negative values are rejected with `ErrInvalidConfig` at construction time.

- **`Service.ValidateAccessTokenWithClaims(ctx, token)`** — validates an access token and returns both the registered claims (`*jwt.RegisteredClaims`) and application-defined custom claims (`map[string]interface{}`). Reserved JWT fields (`sub`, `exp`, `nbf`, `iat`, `jti`, `iss`, `aud`) are excluded from the custom map. Uses `ParseUnverified` after signature verification — no second key-manager round-trip.

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
