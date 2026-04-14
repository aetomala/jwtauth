# Echo Framework Example

This example demonstrates how to use `jwtauth` with [Echo](https://echo.labstack.com/), a high-performance, extensible HTTP web framework.

## Overview

The example shows:
- Creating and starting a `TokenService` with `KeyManager` and `RefreshStore`
- Writing a custom authentication middleware for Echo
- Public endpoints for login and token refresh
- Protected endpoints that require a valid JWT token
- Token revocation (logout)
- Echo middleware composition

## Project Structure

```
echo-example/
├── main.go              # Server setup and route handlers
├── middleware/
│   └── auth.go          # Custom Echo authentication middleware
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
- Download `github.com/labstack/echo/v4`
- Link to the parent `jwtauth` module
- Pull test dependencies (Ginkgo, Gomega, etc.)

## Running the Example

```bash
go run main.go
```

You'll see output like:

```
2026-03-30T12:34:56.123Z	info	KeyManager started	{"active_keys": 1, "current_key_id": "..."}
2026-03-30T12:34:56.124Z	info	TokenService started	{"issuer": "echo-example"}
⇨ http server started on [::]:8080
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

Echo middleware follows the `func(HandlerFunc) HandlerFunc` pattern. The custom middleware in `middleware/auth.go`:

1. **Extracts** the token from the `Authorization: Bearer <token>` header
2. **Validates** the token using `svc.ValidateAccessToken()`
3. **Attaches** the claims to the Echo context with `c.Set()`
4. **Proceeds** to the next handler or **aborts** with 401 if validation fails

This pattern is composable and idiomatic for Echo.

### Route Organization

Echo allows organizing routes hierarchically with groups:

```go
protected := e.Group("/api")
protected.Use(middleware.AuthMiddleware(svc))
protected.GET("/profile", profileHandler)
protected.POST("/logout", logoutHandler)
```

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
  "iss": "echo-example",             // Issuer
  "sub": "user123",                  // Subject (user ID)
  "aud": ["echo-example-api"],       // Audience
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

### Add Authorization Middleware

Use `ValidateAccessTokenWithClaims` in your middleware to surface custom claims, then store them in context:

```go
// In auth middleware — replace ValidateAccessToken with ValidateAccessTokenWithClaims
registered, custom, err := svc.ValidateAccessTokenWithClaims(c.Request().Context(), token)
if err != nil {
    return c.JSON(http.StatusUnauthorized, map[string]string{"error": tokenErrorCode(err)})
}
c.Set("userID", registered.Subject)
c.Set("claims", custom) // map[string]interface{}
return next(c)

// In downstream middleware — check custom claims
func RequireRole(role string) echo.MiddlewareFunc {
    return func(next echo.HandlerFunc) echo.HandlerFunc {
        return func(c echo.Context) error {
            custom, _ := c.Get("claims").(map[string]interface{})
            if custom["role"] != role {
                return c.JSON(http.StatusForbidden, map[string]string{
                    "error": "insufficient_permissions",
                })
            }
            return next(c)
        }
    }
}

// Usage
admin := e.Group("/admin")
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

ks, _ := keymanager.NewDiskKeyStore("./keys", 2048, logger, nil)
km, _ := keymanager.NewManager(keymanager.ManagerConfig{
    KeyStore: ks,
    Logger:   logger,
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
- Explore other examples (Gin, Chi)
- Implement a Redis `RefreshStore` for distributed deployments
- Add custom claims and authorization logic
