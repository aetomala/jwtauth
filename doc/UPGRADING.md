# Upgrading jwtauth

This document describes breaking changes and the mechanical steps required to upgrade between versions.

---

## v0.6.x → v0.7.0

v0.7.0 reduces the PrometheusMetrics registered metric set from 34 to 18 high-signal
metrics. The `Metrics` interface is unchanged — all five methods (`IncrementCounter`,
`AddCounter`, `SetGauge`, `RecordHistogram`, `RecordDuration`) are unaffected. Prometheus
dashboards and alert rules that query removed metrics must be updated.

### Removed metrics

#### Phase 1 — lifecycle and admin metrics

| Metric | Type | Reason |
|---|---|---|
| `jwtauth_service_running` | Gauge | Derivable from scrape health — use `up{job="jwtauth"}` instead |
| `jwtauth_tokens_introspected_total` | Counter | Admin/debug use-case; low operational signal |
| `jwtauth_active_tokens` | Gauge | Zero production call sites; never populated |

**Action required:** Remove alert rules, recording rules, or dashboards referencing
these metrics. Replace `jwtauth_service_running` with `up{job="jwtauth"}` for
scrape-health alerting.

---

## v0.5.x → v0.6.0

v0.6.0 contains no breaking changes. All existing call sites compile and behave
correctly without modification. Two behavioral changes affect callers that relied
on specific edge-case semantics — review both items below before upgrading.

### 1. `RefreshAccessToken` and `RefreshAccessTokenWithClaims` now revoke the old refresh token

**Previous behavior:** The old refresh token remained valid (non-revoked) after a
successful refresh until its natural TTL expiry. A caller could reuse the same
refresh token to obtain multiple access tokens during the overlap window.

**New behavior:** The old refresh token is revoked immediately after the new
access token is issued. Any subsequent attempt to use the old token returns
`storage.ErrTokenRevoked`.

**Action required:** If your integration tests assert that the original refresh
token remains usable after a successful refresh call, update those tests to
expect `storage.ErrTokenRevoked` instead. Production code that follows the
standard rotate-on-use pattern requires no changes.

See ADR-002 for refresh token lifecycle semantics and #195 for the fix rationale.

### 2. `tokens.ErrTokenMissingKid` is now a distinct exported sentinel

**Previous behavior:** `ValidateAccessToken` returned an anonymous `errors.New`
value when the JWT header lacked a `kid` field. The error was only detectable as
a generic `ErrInvalidToken` via `errors.Is`.

**New behavior:** The same condition now returns `tokens.ErrTokenMissingKid`, a
named exported sentinel. `errors.Is(err, tokens.ErrInvalidToken)` continues to
return `true` — the sentinel wraps the generic error — so existing error-handling
code is unaffected.

**Action required:** None for existing code. Middleware that wants to distinguish
the missing-kid case specifically (e.g., to return a more targeted 401 payload)
can now use `errors.Is(err, tokens.ErrTokenMissingKid)`. See #178.

---

## v0.4.x → v0.5.0

v0.5.0 introduces breaking changes to `storage.RefreshStore` and the Prometheus metric
`jwtauth_tokens_revoked_total`. Code that only *calls* jwtauth is unaffected, except for
Prometheus consumers that query by the renamed label. Code that provides a custom
`RefreshStore` implementation must update the `Store()` method signature or it will not compile.

### 1. `storage.RefreshToken` — new `Audience` field

A new `Audience []string` field is added to `RefreshToken`. Custom serialization or
storage backends that persist `RefreshToken` structs must handle the new field.

```go
type RefreshToken struct {
    // ... existing fields unchanged ...
    Audience []string // NEW — audience resolved at issuance time
}
```

The value is populated from the per-call `WithAudience` IssueOption when provided,
or from the manager's configured `TokenManagerConfig.Audience` otherwise.

### 2. `storage.RefreshStore.Store()` — new `audience []string` parameter

The `Store()` method gains an `audience []string` parameter:

```go
// Before
Store(ctx context.Context, userID string, expiresAt time.Time) (*RefreshToken, error)

// After
Store(ctx context.Context, userID string, expiresAt time.Time, audience []string) (*RefreshToken, error)
```

All custom `RefreshStore` implementations must update this signature. Add a compile-time
assertion to catch the gap early:

```go
var _ storage.RefreshStore = (*MyRefreshStore)(nil)
```

### 3. `jwtauth_tokens_revoked_total` — label `operation` renamed to `revocation_scope`

The `operation` label on `jwtauth_tokens_revoked_total` is renamed to `revocation_scope`.
Update any Prometheus alert rules, recording rules, or dashboards that filter or group
by the old label name. Existing label values (`"single"`, `"all_user"`) are unchanged.

```promql
# Before
jwtauth_tokens_revoked_total{operation="single"}

# After
jwtauth_tokens_revoked_total{revocation_scope="single"}
```

### 4. `storage.RefreshStore` — two new revocation methods (#135)

Two new methods are added to the `RefreshStore` interface:

```go
RevokeAllForAudience(ctx context.Context, audience string) (int, error)
RevokeAllForUserAndAudience(ctx context.Context, userID, audience string) (int, error)
```

`MemoryRefreshStore` and `RedisRefreshStore` are already updated. All custom `RefreshStore`
implementations must add both methods or they will not compile. Add a compile-time assertion
to catch the gap early:

```go
var _ storage.RefreshStore = (*MyRefreshStore)(nil)
```

`tokens.Manager` exposes audience-scoped revocation at the manager level — callers use
`mgr.RevokeAllForAudience` and `mgr.RevokeAllForUserAndAudience` directly. Both manager
methods return `error` only; the storage-layer count is used internally for logging.

**Multi-audience revocation is global.** A token issued with `WithAudience("svc-payments",
"svc-reports")` is revoked completely when either audience is targeted — not partially. See
[ADR-009](adr/009-multi-audience-token-revocation.md) for the decision rationale and
[Audience-Scoped Revocation](DEPLOYMENT.md#audience-scoped-revocation) in `DEPLOYMENT.md`
for operational patterns and use cases.

### 5. `storage.RefreshStore` — one new enumeration method (#143)

One new method is added to the `RefreshStore` interface:

```go
ListTokensForAudience(ctx context.Context, audience string, cursor string, count int) ([]*RefreshToken, string, error)
```

`MemoryRefreshStore` and `RedisRefreshStore` are already updated. All custom `RefreshStore`
implementations must add this method or they will not compile. Add a compile-time assertion
to catch the gap early:

```go
var _ storage.RefreshStore = (*MyRefreshStore)(nil)
```

Returns a page of refresh tokens whose stored audience slice contains `audience`, starting
from `cursor`. Pass `""` to begin from the start; returns `""` as the next cursor when
iteration is exhausted. Returns `storage.ErrInvalidAudience` if `audience` is empty.
`count` is a hint — actual page size may vary.

`tokens.Manager` exposes audience-scoped enumeration at the manager level — callers use
`mgr.ListTokensForAudience` directly. The primary use case is the audit-before-revoke
workflow: enumerate tokens for an audience, log or validate them, then call
`mgr.RevokeAllForAudience`. See
[Audience-Scoped Revocation](../doc/DEPLOYMENT.md#audience-scoped-revocation) in
`DEPLOYMENT.md`.

**Multi-audience visibility** — a token issued with `WithAudience("svc-payments",
"svc-reports")` appears in the listing for **each** of its audiences. The same token will
appear once in the `svc-payments` listing and once in the `svc-reports` listing; it is not
double-counted within either listing.

---

### Additive changes (no action required)

`IssueOption` / `WithAudience` (#124) adds a variadic `...tokens.IssueOption` parameter
to all six issuance methods. All existing call sites compile and behave unchanged — the
parameter is optional and defaults to the manager's configured audience.

`storage.ErrInvalidAudience` is a new sentinel returned when an empty string is passed to
`RevokeAllForAudience`, `RevokeAllForUserAndAudience`, or `ListTokensForAudience`. Code that
only calls these methods via `tokens.Manager` does not need to import `storage` — the error
is wrapped by the manager and can be compared with `errors.Is`.

---

## v0.3.x → v0.4.0

v0.4.0 contains eight categories of breaking changes. Each section below lists the exact
mechanical update required. Changes that only affect code implementing a jwtauth interface
(not code that merely calls one) are grouped under
[Interface additions — custom implementations only](#7-interface-additions--custom-implementations-only).

### 1. Minimum Go version raised to 1.26.2

Go 1.26.2 is now required. Update `go.mod` and your toolchain:

```
go 1.26.2

toolchain go1.26.2
```

---

### 2. Package rename: `pkg/keymanager` → `pkg/keys`

The `keymanager` package is renamed to `keys`. Four call-site updates are required.

**Import path**

```go
// Before
import "github.com/aetomala/jwtauth/pkg/keymanager"

// After
import "github.com/aetomala/jwtauth/pkg/keys"
```

**Qualifier**

```go
// Before
km, err := keymanager.NewManager(cfg)

// After
km, err := keys.NewManager(cfg)
```

**Config struct: `ManagerConfig` → `KeyManagerConfig`**

```go
// Before
cfg := keymanager.ManagerConfig{KeySize: 2048}

// After
cfg := keys.KeyManagerConfig{KeySize: 2048}
```

**Default config constructor: `ConfigDefault()` → `DefaultKeyManagerConfig()`**

```go
// Before
cfg := keymanager.ConfigDefault()

// After
cfg := keys.DefaultKeyManagerConfig()
```

---

### 3. Token manager type rename: `tokens.Service` → `tokens.Manager`

Four mechanical changes are required together.

**Type reference**

```go
// Before
var svc *tokens.Service

// After
var mgr *tokens.Manager
```

**Constructor + config struct**

```go
// Before
svc, err := tokens.NewService(tokens.ServiceConfig{
    KeyManager:   km,
    RefreshStore: store,
})

// After
mgr, err := tokens.NewManager(tokens.TokenManagerConfig{
    KeyManager:   km,
    RefreshStore: store,
})
```

**Default config constructor**

```go
// Before
cfg := tokens.ConfigDefault()

// After
cfg := tokens.DefaultTokenManagerConfig()
```

**Error sentinel**

```go
// Before
if errors.Is(err, tokens.ErrServiceNotRunning) { ... }

// After
if errors.Is(err, tokens.ErrManagerNotRunning) { ... }
```

---

### 4. Storage constructors migrated to config-struct form

All four storage constructors replaced positional parameters with a single config struct.
Update each call site:

**`keys.NewDiskKeyStore`**

```go
// Before
store, err := keys.NewDiskKeyStore(dir, keySize, logger, metricsClient)

// After
store, err := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{
    Dir:     dir,
    KeySize: keySize,
    Logger:  logger,
    Metrics: metricsClient,
})
```

**`keys.NewRedisKeyStore`**

```go
// Before
store, err := keys.NewRedisKeyStore(redisClient, logger, metricsClient)

// After
store, err := keys.NewRedisKeyStore(keys.RedisKeyStoreConfig{
    Client:  redisClient,
    Logger:  logger,
    Metrics: metricsClient,
})
```

**`storage.NewMemoryRefreshStore`**

```go
// Before
store, err := storage.NewMemoryRefreshStore(logger, metricsClient)

// After
store, err := storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{
    Logger:  logger,
    Metrics: metricsClient,
})
```

**`storage.NewRedisRefreshStore`**

```go
// Before
store, err := storage.NewRedisRefreshStore(redisClient, logger, metricsClient)

// After
store, err := storage.NewRedisRefreshStore(storage.RedisRefreshStoreConfig{
    Client:  redisClient,
    Logger:  logger,
    Metrics: metricsClient,
})
```

`Logger` and `Metrics` default to no-op implementations when `nil` is passed — existing call sites
that pass `nil` continue to work.

---

### 5. Claims API: `WithMetadata` → `WithClaims` + `CustomClaims` type

**`IssueAccessTokenWithClaims` — parameter type changed**

The `claims` parameter type changed from `map[string]interface{}` to `tokens.CustomClaims`
(a named alias for `map[string]interface{}`).

```go
// Before
token, err := mgr.IssueAccessTokenWithClaims(ctx, userID, map[string]interface{}{
    "role": "admin",
})

// After
token, err := mgr.IssueAccessTokenWithClaims(ctx, userID, tokens.CustomClaims{
    "role": "admin",
})
```

**`IssueRefreshTokenWithMetadata` renamed to `IssueRefreshTokenWithClaims`**

```go
// Before
rt, err := mgr.IssueRefreshTokenWithMetadata(ctx, userID, metadata)

// After
rt, err := mgr.IssueRefreshTokenWithClaims(ctx, userID, claims)
```

**Reserved JWT fields are silently dropped**

The reserved field names `sub`, `iss`, `aud`, `exp`, `nbf`, `iat`, and `jti` are silently removed
from any `CustomClaims` map at issuance time. Do not rely on injecting them through custom claims.

---

### 6. `TokenError` struct removed

`tokens.TokenError` and `tokens.NewTokenError()` no longer exist. Replace any type assertion
against `*tokens.TokenError` with `errors.Is()` — sentinel behaviour is unchanged:

```go
// Before
if te, ok := err.(*tokens.TokenError); ok {
    log.Printf("token error: %s", te.Message)
}

// After — errors.Is works as before
if errors.Is(err, tokens.ErrTokenExpired) {
    log.Print("token has expired")
}
```

Available sentinels: `ErrTokenExpired`, `ErrTokenNotYetValid`, `ErrInvalidAudience`,
`ErrInvalidIssuer`, `ErrManagerNotRunning`.

---

### 7. Interface additions — custom implementations only

The following methods were added to three interfaces. Code that only *calls* jwtauth is unaffected.
Code that provides its own implementation of `logging.Logger`, `keys.KeyStore`, or
`storage.RefreshStore` must add the new methods or it will not compile.

#### `logging.Logger` — `With(keysAndValues ...interface{}) Logger`

Pre-binds structured fields for all subsequent log calls on the returned logger.

```go
// Add to your adapter
func (l *MyLogger) With(keysAndValues ...interface{}) logging.Logger {
    // Bind the key/value pairs to a new logger instance.
    // May return the receiver unchanged for no-op adapters.
    return l
}
```

`NoOpLogger` may return the receiver unchanged. Chained calls accumulate fields.

#### `keys.KeyStore` — `Namespace() string`

Returns the namespace label associated with this store instance, used in observability output.

```go
func (s *MyKeyStore) Namespace() string {
    return s.namespace // or return "" if not applicable
}
```

`DiskKeyStore` returns `""`. `RedisKeyStore` returns the configured `KeyPrefix`.

#### `storage.RefreshStore` — `Namespace() string`

Same contract as `keys.KeyStore.Namespace()`.

```go
func (s *MyRefreshStore) Namespace() string {
    return s.namespace // or return ""
}
```

`MemoryRefreshStore` returns `""`. `RedisRefreshStore` returns the configured `KeyPrefix`.

#### `storage.RefreshStore` — `ListTokens(ctx, cursor, count)`

Returns a page of all refresh tokens in the store, starting from `cursor`.
Pass `""` to begin from the start. Returns the next cursor and a `nil` error on success.
Returns `""` as the next cursor when iteration is exhausted.
`count` is a hint — the actual page size may vary.

All tokens are returned regardless of revocation or expiry status — the caller is responsible for
filtering. Cursor semantics are best-effort: tokens created or deleted between pages may appear,
disappear, or shift.

```go
func (s *MyStore) ListTokens(
    ctx context.Context,
    cursor string,
    count int,
) ([]*storage.RefreshToken, string, error) {
    // Return next cursor as "" when exhausted.
}
```

#### `storage.RefreshStore` — `ListTokensForUser(ctx, userID, cursor, count)`

Returns a page of refresh tokens belonging to `userID`, starting from `cursor`.
Returns `ErrInvalidUserID` if `userID` is empty or whitespace.
All other semantics are identical to `ListTokens`.

```go
func (s *MyStore) ListTokensForUser(
    ctx context.Context,
    userID string,
    cursor string,
    count int,
) ([]*storage.RefreshToken, string, error) {
    if strings.TrimSpace(userID) == "" {
        return nil, "", storage.ErrInvalidUserID
    }
    // Return next cursor as "" when exhausted.
}
```

#### Compile-time assertions

Add compile-time assertions to catch missed methods early:

```go
var _ storage.RefreshStore = (*MyRefreshStore)(nil)
var _ keys.KeyStore        = (*MyKeyStore)(nil)
```

---

### 8. Example middleware rename: `AuthMiddleware` → `BearerMiddleware`

`AuthMiddleware` is renamed to `BearerMiddleware` in all framework example packages
(`gin-example`, `chi-example`, `echo-example`). Update any call sites that reference
the example middleware by name:

```go
// Before
router.Use(middleware.AuthMiddleware(tokenManager))

// After
router.Use(middleware.BearerMiddleware(tokenManager))
```
