# Gin Framework Example

This example demonstrates how to use `jwtauth` with [Gin](https://github.com/gin-gonic/gin), a popular lightweight HTTP web framework.

## Overview

The example shows:
- Creating and starting a `TokenService` with `KeyManager` and `RefreshStore`
- Writing a custom authentication middleware for Gin
- Public endpoints for login and token refresh
- Protected endpoints that require a valid JWT token
- Token revocation (logout)

## Project Structure

```
gin-example/
├── main.go              # Server setup and route handlers
├── middleware/
│   └── auth.go          # Custom Gin authentication middleware
└── README.md            # This file
```

## Setup

### Prerequisites

- Go 1.21+
- The parent `jwtauth` library (from the parent directory)

### Install Dependencies

```bash
go mod tidy
```

This will:
- Download `github.com/gin-gonic/gin`
- Link to the parent `jwtauth` module
- Pull test dependencies (Ginkgo, Gomega, etc.)

## Running the Example

```bash
go run main.go
```

You'll see output like:

```
2026-03-30T12:34:56.123Z	info	KeyManager started	{"active_keys": 1, "current_key_id": "..."}
2026-03-30T12:34:56.124Z	info	TokenService started	{"issuer": "gin-example"}
Starting server on :8080
```

## Testing the API

### 1. Login (Get Tokens)

```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"user_id": "user123"}'
```

Response:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjIwMjYwMzMwXzEyMzQ1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjIwMjYwMzMwXzEyMzQ1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 900
}
```

Save the `access_token` for the next request.

### 2. Access Protected Endpoint

```bash
curl -X GET http://localhost:8080/api/profile \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

Response:
```json
{
  "user_id": "user123",
  "message": "This is a protected endpoint"
}
```

### 3. Refresh Token

```bash
curl -X POST http://localhost:8080/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "YOUR_REFRESH_TOKEN"}'
```

Response:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjIwMjYwMzMwXzEyMzQ1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 900
}
```

### 4. Logout (Revoke Tokens)

```bash
curl -X POST http://localhost:8080/api/logout \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

Response:
```json
{
  "message": "logged out successfully"
}
```

After logout, attempting to use the same refresh token will fail:

```bash
curl -X POST http://localhost:8080/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "YOUR_REFRESH_TOKEN"}'
```

Response (401 Unauthorized):
```json
{
  "error": "failed to refresh token"
}
```

### 5. Health Check

```bash
curl http://localhost:8080/health
```

Response:
```json
{
  "status": "healthy"
}
```

## Key Implementation Details

### Middleware Pattern

The custom middleware in `middleware/auth.go`:

1. **Extracts** the token from the `Authorization: Bearer <token>` header
2. **Validates** the token using `svc.ValidateAccessToken()`
3. **Attaches** the claims to the Gin context with `c.Set()`
4. **Proceeds** to the next handler or **aborts** with 401 if validation fails

This pattern is simple, composable, and follows Gin conventions.

### Service Lifecycle

The example demonstrates proper `jwtauth` lifecycle management:

```go
// Start
km.Start(ctx)
svc.Start(ctx)

// Use
svc.IssueTokenPair(ctx, userID)
svc.ValidateAccessToken(ctx, token)
svc.RefreshAccessToken(ctx, refreshToken)
svc.RevokeAllUserTokens(ctx, userID)

// Shutdown
svc.Shutdown(shutdownCtx)
km.Shutdown(shutdownCtx)
```

### Token Claims

Access tokens issued by `jwtauth` contain standard JWT claims:

```json
{
  "iss": "gin-example",              // Issuer
  "sub": "user123",                  // Subject (user ID)
  "aud": ["gin-example-api"],        // Audience
  "exp": 1234567890,                 // Expiration time
  "iat": 1234566990,                 // Issued at
  "jti": "token-id-12345"            // JWT ID (unique per token)
}
```

You can decode these tokens at [jwt.io](https://jwt.io/) to inspect the claims.

## Extending the Example

### Add Custom Claims

```go
claims := map[string]interface{}{
    "role":   "admin",
    "tenant": "org-123",
}

token, err := svc.IssueAccessTokenWithClaims(ctx, userID, claims)
```

### Add Custom Middleware

Extend `middleware/auth.go` to check custom claims:

```go
func RequireRole(role string) gin.HandlerFunc {
    return func(c *gin.Context) {
        claims, exists := c.Get("claims")
        if !exists {
            c.AbortWithStatusJSON(401, gin.H{"error": "no claims"})
            return
        }

        tokenClaims := claims.(*tokens.Claims)
        if tokenClaims.Custom["role"] != role {
            c.AbortWithStatusJSON(403, gin.H{"error": "insufficient permissions"})
            return
        }

        c.Next()
    }
}

// Usage
admin := protected.Group("/admin")
admin.Use(RequireRole("admin"))
admin.GET("/stats", adminStatsHandler)
```

### Add Database Integration

Replace the in-memory `RefreshStore` with your own implementation:

```go
// Create custom store
store := database.NewPostgresRefreshStore(db, logger)

svc, _ := tokens.NewService(tokens.ServiceConfig{
    RefreshStore: store,
    // ... other config
})
```

## Debugging

Enable debug logging:

```go
logger := logging.NewTextLogger(slog.LevelDebug)

km, _ := keymanager.NewManager(keymanager.ManagerConfig{
    Logger: logger,
})

svc, _ := tokens.NewService(tokens.ServiceConfig{
    Logger: logger,
})
```

This will print detailed logs for:
- Token issuance
- Token validation
- Token refresh
- Token revocation
- Service lifecycle

## Next Steps

- Read [ARCHITECTURE.md](../../doc/ARCHITECTURE.md) for design details
- Explore other examples (Chi, Echo)
- Implement a Redis `RefreshStore` for distributed deployments
- Add custom claims and authorization logic
