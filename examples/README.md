# jwtauth — Integration Examples

This directory contains complete, runnable examples showing how to integrate the `jwtauth` authorization token engine with different HTTP frameworks. Each example demonstrates:

- Setting up a `KeyManager` for zero-downtime key rotation
- Creating a `TokenManager` for token operations
- Writing framework-specific bearer token middleware
- Implementing login, refresh, logout flows
- Protecting endpoints with token validation

## Examples

### [Gin Example](gin-example/)

A simple and fast HTTP framework. Best for:
- High-performance APIs
- Microservices
- When you want a minimal, opinionated framework

**Features**:
- Framework-agnostic token validation
- Simple middleware using `gin.HandlerFunc`
- Built-in request binding and validation

**Run**:
```bash
cd gin-example
go run main.go
```

### [Chi Example](chi-example/)

A lightweight, idiomatic router. Best for:
- Custom routing patterns
- Applications that prefer `net/http` standard library
- When you want maximum flexibility

**Features**:
- Standard `http.Handler` pattern
- Route grouping with nested middleware
- Zero external dependencies beyond Chi

**Run**:
```bash
cd chi-example
go run main.go
```

### [Echo Example](echo-example/)

A high-performance, extensible framework. Best for:
- Complex applications
- When you want rich middleware ecosystem
- Applications that value developer experience

**Features**:
- Rich middleware composition
- Built-in request binding and validation
- Excellent error handling

**Run**:
```bash
cd echo-example
go run main.go
```

### [Correlation ID Example](correlation-example/)

End-to-end correlation ID tracing using only the standard library (`net/http`). Best for:
- Understanding how `correlation_id` flows through all jwtauth internal logs
- Adding per-request log tracing to any framework (the pattern is framework-agnostic)

**Features**:
- `NewCorrelationJSONLogger` with `CorrelationIDHandler` pre-wired
- `X-Correlation-ID` header extraction with auto-generation when absent
- `correlation_id` appears on every jwtauth log line for the request automatically
- No external framework dependencies — pure stdlib

**Run**:
```bash
cd correlation-example
go run main.go
```

### [Health Check Example](health-check/)

Key inspection via a `/health/keys` endpoint using only the standard library. Best for:
- Exposing signing key state in a health-check or readiness probe
- Understanding the `GetCurrentKeyInfo` API without a full token lifecycle
- Minimal setups where no HTTP framework is desired

**Features**:
- `GetCurrentKeyInfo` called per request — no background goroutine needed
- Returns `status: "healthy"` / `"degraded"` / `"unhealthy"` based on key validity
- Human-readable `time_until_rotation` and `key_age` fields
- No external framework dependencies — pure stdlib

**Run**:
```bash
cd health-check
go run main.go
```

### [Prometheus Metrics Example](prometheus-metrics/)

Custom Prometheus gauges driven by `GetCurrentKeyInfo` on a 30-second collection loop. Best for:
- Alerting on stalled key rotation or expired signing keys
- Adding time-based key health to an existing Prometheus/Grafana stack
- Understanding how to integrate `GetCurrentKeyInfo` into a background collection loop

**Features**:
- Three gauges: `jwtauth_key_age_seconds`, `jwtauth_rotation_scheduled_seconds`, `jwtauth_key_valid`
- Background goroutine with a 30-second tick — exits cleanly on shutdown
- `/metrics` endpoint via `promhttp.Handler()`
- Initial gauge population before the first scrape

**Run**:
```bash
cd prometheus-metrics
go run main.go
```

### [Token Audit Example](token-audit/)

Cursor-based token enumeration using `ListTokens` and `ListTokensForUser`. Best for:
- Understanding how to iterate all active refresh tokens for reconciliation or audit pipelines
- Implementing session management dashboards or bulk-revocation tooling
- Learning the cursor pagination pattern before integrating it into a production service

**Features**:
- Seeds tokens for multiple users, then iterates globally via `ListTokens` with a configurable page size
- Iterates a single user's tokens via `ListTokensForUser` — demonstrating user-scoped pagination
- Prints token metadata (tokenID prefix, userID, expiry, revocation state) per page
- No HTTP server — runs as a standalone command-line audit loop and exits

**Run**:
```bash
cd token-audit
go run main.go
```

### [Audience Revocation Example](audience-revocation/)

Multi-audience token issuance and audience-scoped revocation. Best for:
- Understanding `RevokeAllForAudience` and `RevokeAllForUserAndAudience`
- Learning the atomicity property: a refresh token is revoked as a unit regardless of how many audiences it covers
- Building service isolation patterns where different services share tokens

**Features**:
- Issues tokens with multiple audiences using `WithAudience("svc-payments", "svc-reports")`
- Lists tokens scoped to a specific audience via `ListTokensForAudience`
- Demonstrates `RevokeAllForAudience` and verifies that alice's token is revoked for both audiences
- Demonstrates `RevokeAllForUserAndAudience` for targeted user+audience revocation
- No HTTP server — runs as a standalone command-line demo and exits

**Run**:
```bash
cd audience-revocation
go run main.go
```

### [Redis Production Example](redis-production/)

Redis backend wiring for production multi-instance deployments. Best for:
- Understanding `RedisKeyStore` and `RedisRefreshStore` construction and wiring
- Learning how `KeyPrefix` (ADR-006) isolates storage keys across services
- Learning how `Namespace` (ADR-007) scopes observability labels
- Setting up graceful shutdown with `signal.NotifyContext`

**Features**:
- Builds a Redis client from environment variables — no hard-coded connection strings
- Wires `RedisKeyStore` and `RedisRefreshStore` with a shared `KeyPrefix`
- Sets `Namespace` on both `KeyManagerConfig` and `TokenManagerConfig`
- Issues and validates one token pair as a live wiring check
- Demonstrates graceful shutdown via `signal.NotifyContext`
- Optional TLS — enabled with `REDIS_TLS` env var

**Run**:
```bash
REDIS_ADDR=localhost:6379 go run .
```

## Common Pattern Across Examples

All framework examples (Gin, Chi, Echo) follow the same token lifecycle pattern — login, validate, refresh, revoke. The `correlation-example` extends this pattern with per-request log tracing.

The `health-check` and `prometheus-metrics` examples focus exclusively on the **Key Inspection API** (`GetCurrentKeyInfo`) and do not require a full `TokenManager` or refresh-token flow — they are useful as standalone observability integrations or as a reference for adding key-state monitoring to an existing service.

The `token-audit` example focuses on the **Token Enumeration API** (`ListTokens`, `ListTokensForUser`) — it demonstrates cursor-based pagination without an HTTP server and is useful as a reference for reconciliation jobs or session management tooling.

The `audience-revocation` example focuses on the **Audience-Scoped Revocation API** (`RevokeAllForAudience`, `RevokeAllForUserAndAudience`, `ListTokensForAudience`) — it demonstrates multi-audience token issuance, bulk revocation, and the atomicity property of refresh token revocation.

The `redis-production` example focuses on the **Redis Backend API** (`RedisKeyStore`, `RedisRefreshStore`) — it demonstrates production connection wiring, `KeyPrefix` (ADR-006), `Namespace` (ADR-007), and graceful shutdown without an HTTP server.

### 1. Setup Service Dependencies

```go
// Create KeyManager for key rotation
km, _ := keys.NewManager(config)
km.Start(ctx)

// Create RefreshStore for token persistence
store := storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{Logger: logger})

// Create TokenManager for token operations
mgr, _ := tokens.NewManager(config)
mgr.Start(ctx)
```

### 2. Write Framework Middleware

Each framework has a different middleware pattern, but they all:
- Extract token from `Authorization: Bearer <token>` header
- Validate with `mgr.ValidateAccessToken(ctx, token)`
- Attach user ID and claims to request context
- Proceed to the route handler

**Gin**:
```go
func BearerMiddleware(mgr *tokens.Manager) gin.HandlerFunc {
    return func(c *gin.Context) {
        claims, err := mgr.ValidateAccessToken(c, token)
        c.Set("userID", claims.Subject)
        c.Next()
    }
}
```

**Chi**:
```go
func BearerMiddleware(mgr *tokens.Manager) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            claims, err := mgr.ValidateAccessToken(r.Context(), token)
            ctx := context.WithValue(r.Context(), "userID", claims.Subject)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

**Echo**:
```go
func BearerMiddleware(mgr *tokens.Manager) echo.MiddlewareFunc {
    return func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            claims, err := mgr.ValidateAccessToken(c.Request().Context(), token)
            c.Set("userID", claims.Subject)
            return next(c)
        }
    }
}
```

### 3. Define Endpoints

Each example includes:
- `POST /login` - Issue access + refresh token pair (calls `issueTokensHandler`)
- `POST /refresh` - Issue new access token
- `GET /api/profile` - Protected endpoint
- `POST /api/logout` - Revoke all user tokens
- `GET /health` - Health check

## Testing an Example

1. Start the server:
   ```bash
   cd gin-example
   go run main.go
   ```

2. Login to get tokens:
   ```bash
   curl -X POST http://localhost:8080/login \
     -H "Content-Type: application/json" \
     -d '{"user_id": "user123"}'
   ```

3. Use the access token on protected endpoints:
   ```bash
   curl -X GET http://localhost:8080/api/profile \
     -H "Authorization: Bearer <access_token>"
   ```

4. Refresh the access token:
   ```bash
   curl -X POST http://localhost:8080/refresh \
     -H "Content-Type: application/json" \
     -d '{"refresh_token": "<refresh_token>"}'
   ```

5. Logout (revoke all tokens):
   ```bash
   curl -X POST http://localhost:8080/api/logout \
     -H "Authorization: Bearer <access_token>"
   ```

## Extending the Examples

### Add Custom Claims

All examples can issue tokens with custom claims:

```go
claims := map[string]interface{}{
    "role":   "admin",
    "tenant": "org-123",
}

token, err := mgr.IssueAccessTokenWithClaims(ctx, userID, claims)
```

### Add Database Integration

Replace the in-memory store with a database:

```go
// Implement your own RefreshStore
type PostgresRefreshStore struct {
    db *sql.DB
}

func (s *PostgresRefreshStore) Store(ctx context.Context, tokenID, userID string, expiresAt time.Time, metadata map[string]interface{}) error {
    // Store in database
}

// Use it in the manager
store := &PostgresRefreshStore{db: db}
mgr, _ := tokens.NewManager(tokens.TokenManagerConfig{
    RefreshStore: store,
})
```

### Add Authorization Middleware

Check custom claims in middleware:

```go
// Use ValidateAccessTokenWithClaims to get both registered and custom claims:
registered, custom, err := mgr.ValidateAccessTokenWithClaims(ctx, token)
// registered.Subject == userID
// custom["role"] == "admin"  (application-defined fields only)

// Store custom claims in context for downstream middleware:
c.Set("claims", custom) // map[string]interface{}

// Authorization middleware — check custom claims:
func RequireRole(role string) gin.HandlerFunc {
    return func(c *gin.Context) {
        custom, _ := c.Get("claims")
        claimsMap, _ := custom.(map[string]interface{})
        if claimsMap["role"] != role {
            c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "insufficient_permissions"})
            return
        }
        c.Next()
    }
}

// Usage
protected := r.Group("/admin")
protected.Use(RequireRole("admin"))
protected.GET("/stats", adminHandler)
```

## Design Philosophy

The `jwtauth` library itself is **framework-agnostic** — it only provides core token operations. This means:

✅ **Each framework gets its own idiomatic middleware**
✅ **No forced dependencies on Gin, Echo, or Chi**
✅ **Easy to integrate with your chosen framework**
✅ **Small library size and focused API**

The examples show how simple it is to write middleware for any framework that can use your `TokenManager`.

## Key Concepts

### Token Lifecycle

1. **Issue**: `IssueTokenPair()` creates access + refresh tokens
2. **Validate**: `ValidateAccessToken()` checks signature, expiration, claims
3. **Refresh**: `RefreshAccessToken()` issues new access token from refresh token
4. **Revoke**: `RevokeAllUserTokens()` invalidates all user tokens
5. **Introspect**: `IntrospectToken()` checks if token is active (RFC 7662)

### Token Types

- **Access Token**: Short-lived (15 minutes), used to access protected endpoints
- **Refresh Token**: Long-lived (7 days), used to get new access tokens
- **Both are signed with RS256** using keys managed by `KeyManager`

### Zero-Downtime Key Rotation

`KeyManager` handles automatic key rotation with overlap periods:
- Old key remains valid for the overlap period (default 1 hour)
- New key signs all new tokens
- Tokens signed with old key can still be validated
- No service disruption or token reissuance needed

## Related Documentation

- [Parent README](../README.md) - Library overview and features
- [ARCHITECTURE.md](../doc/ARCHITECTURE.md) - Design decisions and patterns
- [Quick Start](../README.md#quick-start) - Basic usage examples

## Example Comparison

### HTTP Framework Integration

These examples show the full token lifecycle (login, validate, refresh, logout) with
framework-specific middleware. Start here if you are integrating jwtauth into a web API.

| Feature | [Gin](gin-example/) | [Chi](chi-example/) | [Echo](echo-example/) |
|---------|---------------------|---------------------|----------------------|
| **Framework** | Gin | Chi | Echo |
| **Middleware** | `gin.HandlerFunc` | `func(Handler)Handler` | `MiddlewareFunc` |
| **Complexity** | Simple | Minimal | Rich features |
| **Ecosystem** | Large | Small | Large |
| **Best for** | Microservices | Simplicity | Feature-rich apps |

### Production Operations

These examples focus on running jwtauth in production — log tracing, key-state monitoring,
and Redis backend wiring. None require a framework; most run as standalone programs.

| Feature | [Correlation](correlation-example/) | [Health Check](health-check/) | [Prometheus Metrics](prometheus-metrics/) | [Redis Production](redis-production/) |
|---------|--------------------------------------|-------------------------------|-------------------------------------------|---------------------------------------|
| **Focus** | Per-request log tracing | Key inspection endpoint | Key state metrics | Redis backend wiring |
| **External deps** | None (stdlib) | None (stdlib) | Prometheus | Redis |
| **HTTP server** | Yes | Yes | Yes (`/metrics`) | No |
| **Best for** | Log tracing demo | Health / readiness probes | Alerting & dashboards | Multi-instance deployments |

### Token Operations

These examples demonstrate specialized token lifecycle operations — enumeration and
audience-scoped revocation. Both run as CLI tools without an HTTP server.

| Feature | [Token Audit](token-audit/) | [Audience Revocation](audience-revocation/) |
|---------|------------------------------|---------------------------------------------|
| **Focus** | Cursor-based token enumeration | Audience-scoped bulk revocation |
| **Key APIs** | `ListTokens`, `ListTokensForUser` | `RevokeAllForAudience`, `RevokeAllForUserAndAudience`, `ListTokensForAudience` |
| **Storage backend** | MemoryRefreshStore | MemoryRefreshStore |
| **Best for** | Audit / reconciliation pipelines | Multi-audience revocation |

## Next Steps

1. Pick your favorite framework and run its example
2. Read the example's README for detailed API documentation
3. Customize for your use case (database, custom claims, etc.)
4. Integrate into your application
5. Review [ARCHITECTURE.md](../doc/ARCHITECTURE.md) for design patterns

## Support

- 📖 **Documentation**: [ARCHITECTURE.md](../doc/ARCHITECTURE.md)
- 🐛 **Issues**: [GitHub Issues](https://github.com/aetomala/jwtauth/issues)
- 💬 **Questions**: [GitHub Discussions](https://github.com/aetomala/jwtauth/discussions)
