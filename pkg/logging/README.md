# Logging Package

Shared logging interface for the JWT authorization token engine.

## Overview

The `logging` package provides a simple, structured logging interface that all components use. This ensures consistent log format across the entire system and allows flexible logger implementations.

## Design Principles

- **Simple**: Only 4 log levels (Debug, Info, Warn, Error)
- **Structured**: Key-value pairs for machine-readable logs
- **Flexible**: Works with any logging library via adapters
- **Optional**: Pass `nil` to default to `NoOpLogger` — components call unconditionally

## Quick Start

### Production (JSON for Kubernetes, with correlation ID)

```go
import (
    "log/slog"
    "github.com/aetomala/jwtauth/pkg/logging"
    "github.com/aetomala/jwtauth/pkg/keymanager"
)

func main() {
    // Recommended: JSON logger with CorrelationIDHandler pre-wired.
    // When a request context carries a correlation ID, every jwtauth log
    // line for that request will include "correlation_id" automatically.
    logger := logging.NewCorrelationJSONLogger(slog.LevelInfo)

    // Without correlation ID support (simpler, no X-Correlation-ID tracing):
    // logger := logging.NewJSONLogger(slog.LevelInfo)

    // Use with KeyManager
    ks, _ := keymanager.NewDiskKeyStore("/keys", 2048, logger, nil)
    manager, _ := keymanager.NewManager(keymanager.ManagerConfig{
        KeyStore: ks,
        Logger:   logger,
    })

    manager.Start(context.Background())
    // Logs: {"time":"2025-01-07T10:30:00Z","level":"INFO","msg":"key manager started"}
    // With a correlation ID in ctx:
    // {"time":"...","level":"INFO","msg":"token pair issued","correlation_id":"req-001","userID":"alice"}
}
```

### Development (Human-Readable)

```go
// Create text logger for development
handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
    Level: slog.LevelInfo,
})
logger := logging.NewSlogAdapter(slog.New(handler))

// Or use helper:
// logger := logging.NewTextLogger(slog.LevelInfo)

// Logs: time=2025-01-07T10:30:00.000Z level=INFO msg="key manager started"
```

### No Logging (Testing)

```go
// Option 1: Use NoOpLogger
config := keymanager.ManagerConfig{
    Logger: &logging.NoOpLogger{},
}

// Option 2: Use nil (components handle nil gracefully)
config := keymanager.ManagerConfig{
    Logger: nil,
}
```

## Log Levels

### Info
Use for normal operations and important milestones:
- Successful operations
- State changes
- Component startup/shutdown
- Key rotations

```go
logger.Info("key rotation successful",
    "oldKeyID", "abc-123",
    "newKeyID", "xyz-789",
    "duration", 150*time.Millisecond)
```

### Warn
Use for recoverable issues:
- Degraded operation
- Retries
- Skipped/corrupted items
- Fallback behavior

```go
logger.Warn("failed to load key file",
    "file", "corrupted.pem",
    "error", err,
    "action", "skipped")
```

### Error
Use for critical failures:
- Operation failures
- Unrecoverable errors
- System issues

```go
logger.Error("key rotation failed",
    "error", err,
    "keyID", keyID,
    "attempt", 3)
```

### Debug

Use for development and troubleshooting. Suppressed at Info level and above — safe to leave in production code and enable only when needed:

- Internal state, cache hits/misses
- Entry points on high-frequency read paths
- Intermediate steps inside loops
- No-op outcomes ("nothing to do")

```go
logger.Debug("public key cache hit", "keyID", keyID)
logger.Debug("revoking token for user", "tokenID", tokenID, "userID", userID)
logger.Debug("no expired keys found during cleanup")
```

## Structured Logging

Always provide context as key-value pairs:

```go
// ✅ Good: Structured with context
logger.Info("token issued",
    "userID", "user-123",
    "expiresIn", "15m",
    "scopes", []string{"read", "write"})

// ❌ Bad: Unstructured, hard to query
logger.Info("Token issued for user-123 expires in 15m")
```

## Log Output Formats

### JSON (Production)
```json
{
  "time": "2025-01-07T10:30:00.123Z",
  "level": "INFO",
  "msg": "key rotation successful",
  "oldKeyID": "abc-123",
  "newKeyID": "xyz-789",
  "duration": "150ms"
}
```

**Advantages**:
- Machine-readable
- Easy to parse in log aggregators (ELK, Loki, Splunk)
- Preserves types (numbers, booleans, arrays)
- Efficient querying in log systems

### Text (Development)
```
time=2025-01-07T10:30:00.123Z level=INFO msg="key rotation successful" oldKeyID=abc-123 newKeyID=xyz-789 duration=150ms
```

**Advantages**:
- Human-readable
- Easier to scan visually
- Good for local development
- Works well with grep/tail

## Integration with Kubernetes

In Kubernetes, write JSON logs to **stdout**. The container runtime captures them automatically:

```go
// main.go
func setupLogger() logging.Logger {
    // Read from environment variables
    logLevel := os.Getenv("LOG_LEVEL") // "info", "warn", "error"
    
    level := slog.LevelInfo
    switch logLevel {
    case "warn":
        level = slog.LevelWarn
    case "error":
        level = slog.LevelError
    }
    
    // Always use JSON in production/K8s
    handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
        Level: level,
    })
    
    return logging.NewSlogAdapter(slog.New(handler))
}
```

Your logs flow through:
```
App → stdout (JSON) → Container runtime → K8s logs → Log collector → Aggregator
```

## Custom Implementations

### For Zap (uber-go/zap)

```go
package myapp

import (
    "go.uber.org/zap"
    "github.com/aetomala/jwtauth/pkg/logging"
)

type ZapAdapter struct {
    logger *zap.SugaredLogger
}

func NewZapAdapter(logger *zap.SugaredLogger) *ZapAdapter {
    return &ZapAdapter{logger: logger}
}

func (z *ZapAdapter) Debug(msg string, keysAndValues ...interface{}) {
    z.logger.Debugw(msg, keysAndValues...)
}

func (z *ZapAdapter) Info(msg string, keysAndValues ...interface{}) {
    z.logger.Infow(msg, keysAndValues...)
}

func (z *ZapAdapter) Warn(msg string, keysAndValues ...interface{}) {
    z.logger.Warnw(msg, keysAndValues...)
}

func (z *ZapAdapter) Error(msg string, keysAndValues ...interface{}) {
    z.logger.Errorw(msg, keysAndValues...)
}

// Usage
zapLogger, _ := zap.NewProduction()
logger := NewZapAdapter(zapLogger.Sugar())
```

### For Zerolog

```go
package myapp

import (
    "github.com/rs/zerolog"
    "github.com/aetomala/jwtauth/pkg/logging"
)

type ZerologAdapter struct {
    logger zerolog.Logger
}

func NewZerologAdapter(logger zerolog.Logger) *ZerologAdapter {
    return &ZerologAdapter{logger: logger}
}

func (z *ZerologAdapter) Debug(msg string, keysAndValues ...interface{}) {
    event := z.logger.Debug()
    z.addFields(event, keysAndValues)
    event.Msg(msg)
}

func (z *ZerologAdapter) Info(msg string, keysAndValues ...interface{}) {
    event := z.logger.Info()
    z.addFields(event, keysAndValues)
    event.Msg(msg)
}

func (z *ZerologAdapter) Warn(msg string, keysAndValues ...interface{}) {
    event := z.logger.Warn()
    z.addFields(event, keysAndValues)
    event.Msg(msg)
}

func (z *ZerologAdapter) Error(msg string, keysAndValues ...interface{}) {
    event := z.logger.Error()
    z.addFields(event, keysAndValues)
    event.Msg(msg)
}

func (z *ZerologAdapter) addFields(event *zerolog.Event, keysAndValues []interface{}) {
    for i := 0; i < len(keysAndValues); i += 2 {
        if i+1 < len(keysAndValues) {
            key := keysAndValues[i].(string)
            value := keysAndValues[i+1]
            event.Interface(key, value)
        }
    }
}
```

## Correlation ID

Every jwtauth component passes `context.Context` through all operations. When you wire `CorrelationIDHandler` into your logger and inject a correlation ID at the request boundary, **every internal log line for that request automatically carries `correlation_id`** — from token validation to refresh store lookups — with no changes to component code.

### How It Works

`SlogAdapter` checks whether the first element of `keysAndValues` is a `context.Context`. If it is, the adapter routes the call through `slog.*Context()` instead of `slog.*()`, which lets `CorrelationIDHandler` extract the ID and append it to every record:

```go
// This is how jwtauth components log internally — ctx as the first kwarg:
logger.Info("token pair issued", ctx, "userID", userID)

// SlogAdapter detects ctx and calls:
s.logger.InfoContext(ctx, "token pair issued", "userID", userID)

// CorrelationIDHandler.Handle extracts and injects the field:
// → {"msg":"token pair issued","userID":"alice","correlation_id":"req-001"}
```

### Setup

```go
// Recommended for production — CorrelationIDHandler pre-wired:
logger := logging.NewCorrelationJSONLogger(slog.LevelInfo)

// For local development:
// logger := logging.NewCorrelationTextLogger(slog.LevelDebug)

mgr, _ := tokens.NewManager(tokens.ManagerConfig{
    Logger: logger,
    // ...
})
```

### HTTP Middleware

Inject a correlation ID once at the request boundary — jwtauth propagates it from there:

```go
func withCorrelation(next http.HandlerFunc) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        id := r.Header.Get("X-Correlation-ID")
        if id == "" {
            id = uuid.New().String() // generate if client did not supply one
        }
        ctx := logging.WithCorrelationID(r.Context(), id)
        w.Header().Set("X-Correlation-ID", id) // echo back to client
        next(w, r.WithContext(ctx))
    }
}

// Handler — pass r.Context() (which now carries the ID) to all jwtauth calls:
func loginHandler(w http.ResponseWriter, r *http.Request) {
    accessToken, refreshToken, err := mgr.IssueTokenPair(r.Context(), userID)
    // All jwtauth log lines for this call will include correlation_id automatically.
}
```

### Output

```json
{"time":"2026-04-14T10:30:00Z","level":"INFO","msg":"token pair issued","userID":"alice","correlation_id":"req-001"}
{"time":"2026-04-14T10:30:00Z","level":"DEBUG","msg":"refresh token stored","tokenID":"tok-xyz","correlation_id":"req-001"}
```

Every line for the same request carries the same `correlation_id`. Filter in any log aggregator:

```bash
jq 'select(.correlation_id=="req-001")' app.log
```

### API Reference

| Symbol | Description |
|--------|-------------|
| `WithCorrelationID(ctx, id)` | Returns a copy of ctx with the correlation ID attached |
| `GetCorrelationID(ctx)` | Extracts the correlation ID from ctx; returns `""` if not set |
| `NewCorrelationIDHandler(h)` | Wraps any `slog.Handler` to inject `correlation_id` on every record |
| `NewCorrelationJSONLogger(level)` | JSON logger with `CorrelationIDHandler` pre-wired — recommended for production |
| `NewCorrelationTextLogger(level)` | Text logger with `CorrelationIDHandler` pre-wired — recommended for development |

See [examples/correlation-example/](../../examples/correlation-example/) for a complete runnable demonstration.

## Testing

Use the shared `MockLogger` from `internal/testutil`:

```go
import "github.com/aetomala/jwtauth/internal/testutil"

func TestMyComponent(t *testing.T) {
    mockLogger := testutil.NewMockLogger()
    
    component := NewComponent(Config{
        Logger: mockLogger,
    })
    
    component.DoSomething()
    
    // Verify logs
    if !mockLogger.HasLog("info", "operation successful") {
        t.Error("Expected success log")
    }
}
```

## Best Practices

### DO ✅

- **Use structured logging** with key-value pairs
- **Include context** in every log (IDs, durations, errors)
- **Log at appropriate levels** (Info for success, Warn for issues, Error for failures)
- **Use JSON in production** for log aggregators
- **Assign no-op at construction** — default to `&logging.NoOpLogger{}` when caller passes `nil`; call sites are then unconditional

```go
if config.Logger == nil {
    config.Logger = &logging.NoOpLogger{}
}
// Now call unconditionally everywhere:
m.logger.Info("operation complete", ctx, "duration", elapsed)
```

### DON'T ❌

- **Don't log sensitive data** (passwords, tokens, PII)
- **Don't use string formatting in messages** (use key-value pairs instead)
- **Don't log excessively** (avoid noisy logs)
- **Don't guard every call site** — assign `NoOpLogger` at construction instead of repeating `if m.logger != nil` throughout method bodies

## Future: OpenTelemetry

The Logger interface is designed to be compatible with OpenTelemetry for unified observability (logs + metrics + traces). Integration guide will be provided when OpenTelemetry support is added.

## See Also

- [Metrics Package](../metrics/README.md) - For metrics/monitoring
- [Architecture Docs](../../doc/ARCHITECTURE.md) - Overall design decisions
- [KeyManager Example](../../examples/keymanager/) - Complete usage examples
