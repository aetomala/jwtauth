# Chi Framework Example

This example demonstrates how to use `jwtauth` with [Chi](https://github.com/go-chi/chi), a lightweight HTTP router and middleware framework.

## Overview

The example shows:
- Creating and starting a `TokenService` with `KeyManager` and `RefreshStore`
- Writing a custom authentication middleware for Chi
- Public endpoints for login and token refresh
- Protected endpoints that require a valid JWT token
- Token revocation (logout)
- Chi middleware stack (request ID, logging, recovery)

## Project Structure

```
chi-example/
├── main.go              # Server setup and route handlers
├── auth/
│   └── middleware.go    # Custom Chi authentication middleware
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
- Download `github.com/go-chi/chi/v5`
- Link to the parent `jwtauth` module
- Pull test dependencies (Ginkgo, Gomega, etc.)

## Running the Example

```bash
go run main.go
```

You'll see output like:

```
2026-03-30T12:34:56.123Z	info	KeyManager started	{"active_keys": 1, "current_key_id": "..."}
2026-03-30T12:34:56.124Z	info	TokenService started	{"issuer": "chi-example"}
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
Error: failed to refresh token
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

Chi middleware uses the standard `func(http.Handler) http.Handler` pattern. The custom middleware in `auth/middleware.go`:

1. **Extracts** the token from the `Authorization: Bearer <token>` header
2. **Validates** the token using `mgr.ValidateAccessToken()`
3. **Attaches** the claims to the request context with `context.WithValue()`
4. **Proceeds** to the next handler or **writes** 401 if validation fails

This pattern is composable and follows Chi conventions.

### Router Organization

Chi allows organizing routes hierarchically:

```go
r.Route("/api", func(r chi.Router) {
    r.Use(auth.BearerMiddleware(mgr))  // Only applied to /api routes
    r.Get("/profile", profileHandler)
    r.Post("/logout", logoutHandler)
})
```

### Service Lifecycle

The example demonstrates proper `jwtauth` lifecycle management:

```go
// Start
km.Start(ctx)
mgr.Start(ctx)

// Use
mgr.IssueTokenPair(ctx, userID)
mgr.ValidateAccessToken(ctx, token)
mgr.RefreshAccessToken(ctx, refreshToken)
mgr.RevokeAllUserTokens(ctx, userID)

// Shutdown
mgr.Shutdown(shutdownCtx)
km.Shutdown(shutdownCtx)
```

### Token Claims

Access tokens issued by `jwtauth` contain standard JWT claims:

```json
{
  "iss": "chi-example",              // Issuer
  "sub": "user123",                  // Subject (user ID)
  "aud": ["chi-example-api"],        // Audience
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

token, err := mgr.IssueAccessTokenWithClaims(ctx, userID, claims)
```

### Add Authorization Middleware

Use `ValidateAccessTokenWithClaims` in your middleware to surface custom claims, then store them in context:

```go
// In auth middleware — replace ValidateAccessToken with ValidateAccessTokenWithClaims
registered, custom, err := mgr.ValidateAccessTokenWithClaims(r.Context(), token)
if err != nil {
    writeJSONError(w, tokenErrorCode(err), http.StatusUnauthorized)
    return
}
ctx := context.WithValue(r.Context(), "userID", registered.Subject)
ctx = context.WithValue(ctx, "claims", custom) // map[string]interface{}
next.ServeHTTP(w, r.WithContext(ctx))

// In downstream middleware — check custom claims
func RequireRole(role string) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            custom, _ := r.Context().Value("claims").(map[string]interface{})
            if custom["role"] != role {
                http.Error(w, `{"error":"insufficient_permissions"}`, http.StatusForbidden)
                return
            }
            next.ServeHTTP(w, r)
        })
    }
}

// Usage
r.Route("/admin", func(r chi.Router) {
    r.Use(RequireRole("admin"))
    r.Get("/stats", adminStatsHandler)
})
```

### Add Database Integration

Replace the in-memory `RefreshStore` with your own implementation:

```go
// Create custom store
store := database.NewPostgresRefreshStore(db, logger)

mgr, _ := tokens.NewManager(tokens.ManagerConfig{
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

mgr, _ := tokens.NewManager(tokens.ManagerConfig{
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
- Explore other examples (Gin, Echo)
- Implement a Redis `RefreshStore` for distributed deployments
- Add custom claims and authorization logic
