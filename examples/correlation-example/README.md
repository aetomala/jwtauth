# Correlation ID Example

This example demonstrates end-to-end correlation ID tracing using only the Go standard library (`net/http`). Every log line produced by jwtauth during a request carries the same `correlation_id`, making production log filtering trivial.

## Overview

The example shows:
- Wiring `NewCorrelationJSONLogger` so all jwtauth internal logs carry `correlation_id`
- An `X-Correlation-ID` HTTP middleware that injects or generates the ID per request
- How passing the enriched context to jwtauth operations propagates the ID automatically
- Filtering the resulting logs by `correlation_id` in a log aggregator

## Project Structure

```
correlation-example/
├── main.go     # Server setup, middleware, and route handlers
└── README.md   # This file
```

## Setup

### Prerequisites

- Go 1.21+
- The parent `jwtauth` library (from the parent directory)

### Install Dependencies

```bash
go mod tidy
```

## Running the Example

```bash
go run main.go
```

You'll see output like:

```
{"time":"2026-04-14T10:30:00Z","level":"INFO","msg":"correlation-example server starting","addr":":8080"}
{"time":"2026-04-14T10:30:00Z","level":"INFO","msg":"key manager started","active_keys":1,"current_key_id":"20260414_103000"}
{"time":"2026-04-14T10:30:00Z","level":"INFO","msg":"token manager started","issuer":"correlation-example"}
```

## Testing the API

### 1. Login — supply a correlation ID

```bash
curl -s -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -H "X-Correlation-ID: req-001" \
  -d '{"user_id": "alice"}'
```

Response:
```json
{
  "access_token": "eyJhbGci...",
  "refresh_token": "eyJhbGci..."
}
```

Every log line the server emits while handling this request includes `"correlation_id":"req-001"`:

```json
{"time":"...","level":"INFO","msg":"token pair issued","userID":"alice","correlation_id":"req-001"}
{"time":"...","level":"DEBUG","msg":"refresh token stored","tokenID":"tok-xyz","correlation_id":"req-001"}
```

### 2. Login — no correlation ID supplied

```bash
curl -s -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"user_id": "bob"}'
```

The server generates an ID automatically and echoes it back in the `X-Correlation-ID` response header:

```
X-Correlation-ID: 3f2a1b0c-4d5e
```

### 3. Refresh Token

```bash
curl -s -X POST http://localhost:8080/refresh \
  -H "Content-Type: application/json" \
  -H "X-Correlation-ID: req-002" \
  -d '{"refresh_token": "YOUR_REFRESH_TOKEN"}'
```

Response:
```json
{
  "access_token": "eyJhbGci..."
}
```

### 4. Validate Token

```bash
curl -s -X GET http://localhost:8080/validate \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
  -H "X-Correlation-ID: req-003"
```

Response:
```json
{
  "subject": "alice",
  "issuer": "correlation-example"
}
```

### 5. Filter Logs by Correlation ID

With JSON logging, every line is filterable. To isolate all log lines for a single request:

```bash
go run main.go 2>&1 | jq 'select(.correlation_id=="req-001")'
```

## Key Implementation Details

### Logger: `NewCorrelationJSONLogger`

The example uses `logging.NewCorrelationJSONLogger` instead of `logging.NewJSONLogger`:

```go
logger := logging.NewCorrelationJSONLogger(slog.LevelDebug)
```

`NewCorrelationJSONLogger` wraps `slog.NewJSONHandler` with `CorrelationIDHandler`. When any jwtauth component logs a line, `CorrelationIDHandler` extracts the correlation ID from the context and appends it to the record. Switching back to `NewJSONLogger` would produce identical logs minus the `correlation_id` field.

### The `withCorrelation` Middleware

```go
withCorrelation := func(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        id := r.Header.Get("X-Correlation-ID")
        if id == "" {
            id = newCorrelationID() // auto-generate if absent
        }
        ctx := logging.WithCorrelationID(r.Context(), id)
        w.Header().Set("X-Correlation-ID", id)
        next(w, r.WithContext(ctx))
    }
}
```

This is the only place the correlation ID enters the system. The enriched context is then passed to every jwtauth call (`IssueTokenPair`, `RefreshAccessToken`, `ValidateAccessToken`), and jwtauth threads it through all internal operations.

### The Context-as-First-Kwarg Convention

jwtauth components pass `ctx` as the first element of key-value pairs when calling the logger:

```go
logger.Info("token pair issued", ctx, "userID", userID)
```

`SlogAdapter` detects this and routes the call through `slog.InfoContext(ctx, ...)`. The `CorrelationIDHandler` then sees the context in its `Handle(ctx, r)` method and appends `correlation_id` automatically. No changes to the `Logger` interface or to component call sites are needed.

### Auto-Generated IDs

For requests that arrive without `X-Correlation-ID`, the middleware generates a short pseudo-random hex ID:

```go
func newCorrelationID() string {
    return fmt.Sprintf("%08x-%04x", rand.Uint32(), rand.Uint32()&0xffff)
}
```

For production use, replace this with a UUID library (e.g. `github.com/google/uuid`) to guarantee global uniqueness.

## Adding Correlation ID to Gin, Chi, or Echo

The pattern is framework-agnostic. For Gin:

```go
// 1. Swap the logger
logger := logging.NewCorrelationJSONLogger(slog.LevelInfo)

// 2. Add a correlation ID middleware
r.Use(func(c *gin.Context) {
    id := c.GetHeader("X-Correlation-ID")
    if id == "" {
        id = uuid.New().String()
    }
    ctx := logging.WithCorrelationID(c.Request.Context(), id)
    c.Request = c.Request.WithContext(ctx)
    c.Header("X-Correlation-ID", id)
    c.Next()
})

// 3. Handlers already pass c.Request.Context() to jwtauth — no other changes needed.
```

Chi and Echo follow the same two-step pattern: swap the logger constructor, add one middleware.

## Next Steps

- Read [pkg/logging/README.md](../../pkg/logging/README.md) for the full correlation ID API reference
- Read [ARCHITECTURE.md](../../doc/ARCHITECTURE.md) for how the context-as-first-kwarg convention works internally
- Explore the [Gin](../gin-example/), [Chi](../chi-example/), and [Echo](../echo-example/) examples for framework-specific patterns
- Implement a Redis `RefreshStore` for distributed deployments
