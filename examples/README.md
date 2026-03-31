# jwtauth Framework Examples

This directory contains complete, runnable examples of using `jwtauth` with different HTTP frameworks. Each example demonstrates:

- Setting up a `KeyManager` for zero-downtime key rotation
- Creating a `TokenService` for token operations
- Writing framework-specific authentication middleware
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

## Common Pattern Across Examples

All examples follow the same pattern:

### 1. Setup Service Dependencies

```go
// Create KeyManager for key rotation
km, _ := keymanager.NewManager(config)
km.Start(ctx)

// Create RefreshStore for token persistence
store := storage.NewMemoryRefreshStore(logger)

// Create TokenService for token operations
svc, _ := tokens.NewService(config)
svc.Start(ctx)
```

### 2. Write Framework Middleware

Each framework has a different middleware pattern, but they all:
- Extract token from `Authorization: Bearer <token>` header
- Validate with `svc.ValidateAccessToken(ctx, token)`
- Attach user ID and claims to request context
- Proceed to the route handler

**Gin**:
```go
func AuthMiddleware(svc *tokens.Service) gin.HandlerFunc {
    return func(c *gin.Context) {
        claims, err := svc.ValidateAccessToken(c, token)
        c.Set("userID", claims.Subject)
        c.Next()
    }
}
```

**Chi**:
```go
func AuthMiddleware(svc *tokens.Service) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            claims, err := svc.ValidateAccessToken(r.Context(), token)
            ctx := context.WithValue(r.Context(), "userID", claims.Subject)
            next.ServeHTTP(w, r.WithContext(ctx))
        })
    }
}
```

**Echo**:
```go
func AuthMiddleware(svc *tokens.Service) echo.MiddlewareFunc {
    return func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            claims, err := svc.ValidateAccessToken(c.Request().Context(), token)
            c.Set("userID", claims.Subject)
            return next(c)
        }
    }
}
```

### 3. Define Endpoints

Each example includes:
- `POST /login` - Issue access + refresh token pair
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

token, err := svc.IssueAccessTokenWithClaims(ctx, userID, claims)
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

// Use it in the service
store := &PostgresRefreshStore{db: db}
svc, _ := tokens.NewService(tokens.ServiceConfig{
    RefreshStore: store,
})
```

### Add Authorization Middleware

Check custom claims in middleware:

```go
// Gin example
func RequireRole(role string) gin.HandlerFunc {
    return func(c *gin.Context) {
        claims := c.Get("claims").(*tokens.Claims)
        if claims.Custom["role"] != role {
            c.AbortWithStatusJSON(403, gin.H{"error": "insufficient permissions"})
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

The examples show how simple it is to write middleware for any framework that can use your `TokenService`.

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

## Framework Comparison

| Feature | Gin | Chi | Echo |
|---------|-----|-----|------|
| **Speed** | Very fast | Fast | Very fast |
| **Middleware** | `gin.HandlerFunc` | `func(Handler)Handler` | `MiddlewareFunc` |
| **Complexity** | Simple | Minimal | Rich features |
| **Learning curve** | Easy | Very easy | Medium |
| **Ecosystem** | Large | Small | Large |
| **Best for** | Microservices | Simplicity | Feature-rich apps |

All examples achieve the same authentication goals — choose based on your framework preference!

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
