# Upgrading jwtauth

This document describes breaking changes and the mechanical steps required to upgrade between versions.

---

## Unreleased

No breaking changes documented yet.

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
