# Changelog

All notable changes to this project will be documented in this file.

---

## [Unreleased] — v0.2.x

### Added

- **`ServiceConfig.ClockSkew time.Duration`** — leeway applied to `exp` and `nbf` validation via `jwt.WithLeeway()`. Zero (the default) means strict validation. Negative values are rejected with `ErrInvalidConfig` at construction time.

- **`Service.ValidateAccessTokenWithClaims(ctx, token)`** — validates an access token and returns both the registered claims (`*jwt.RegisteredClaims`) and application-defined custom claims (`map[string]interface{}`). Reserved JWT fields (`sub`, `exp`, `nbf`, `iat`, `jti`, `iss`, `aud`) are excluded from the custom map. Uses `ParseUnverified` after signature verification — no second key-manager round-trip.

- **`error_type` label on all counter metrics** — follows the OpenTelemetry `error.type` semantic convention. Value is `""` on success and mirrors the `status` label value on failure. Added to: `tokens_issued_total`, `tokens_validated_total`, `tokens_refreshed_total`, `storage_operations_total`, `keystore_operations_total`, `key_rotations_total`, `key_signing_operations_total`, `key_validation_operations_total`.

- **Context propagation in `KeyManager` interface** — `GetCurrentSigningKey(ctx context.Context)` and `GetPublicKey(ctx context.Context, kid string)` now accept a context. All call sites updated.

- **Specific JSON error codes in example middleware** — all three framework examples (Gin, Chi, Echo) now map library sentinel errors to structured JSON error codes (`token_expired`, `token_not_yet_valid`, `token_revoked`, `invalid_issuer`, `invalid_audience`, `invalid_token`, `missing_token`, `invalid_authorization_format`) via `errors.Is()` switch.

- **Prometheus metrics wired into all example `main.go` files** — all three examples now construct `metrics.NewPrometheusMetrics`, pass it to every constructor, and expose a `/metrics` endpoint.

### Changed

- **`ErrKeyNotFound` in `ValidateAccessToken` maps to `ErrInvalidToken`** — a token referencing an unknown `kid` now returns `ErrInvalidToken` (was `ErrInvalidSignature`, which was semantically incorrect for a missing-key condition).

- **`KeyManager` interface requires context** — `GetCurrentSigningKey` and `GetPublicKey` signatures changed to accept `context.Context`. Any custom `KeyManager` implementation must be updated.

### Removed

- **`ErrInvalidSignature`** — removed; was semantically misleading. The condition it covered (unknown `kid`) now maps to `ErrInvalidToken`. Update any `errors.Is(err, tokens.ErrInvalidSignature)` checks to `errors.Is(err, tokens.ErrInvalidToken)`.
