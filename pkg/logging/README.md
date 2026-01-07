# Logging Package

Shared logging interface for the JWT authentication system.

## Overview

The `logging` package provides a simple, structured logging interface that all components use. This ensures consistent log format across the entire system and allows flexible logger implementations.

## Design Principles

- **Simple**: Only 3 log levels (Info, Warn, Error)
- **Structured**: Key-value pairs for machine-readable logs
- **Flexible**: Works with any logging library via adapters
- **Optional**: Components work without a logger (nil-safe)

## Quick Start

### Production (JSON for Kubernetes)

```go
import (
    "log/slog"
    "os"
    "github.com/aetomala/jwtauth/pkg/logging"
    "github.com/aetomala/jwtauth/pkg/keymanager"
)

func main() {
    // Create JSON logger for production
    handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
        Level: slog.LevelInfo,
    })
    logger := logging.NewSlogAdapter(slog.New(handler))
    
    // Or use helper:
    // logger := logging.NewJSONLogger(slog.LevelInfo)
    
    // Use with KeyManager
    manager, _ := keymanager.NewManager(keymanager.ManagerConfig{
        KeyDirectory: "/keys",
        Logger:       logger,
    })
    
    manager.Start(context.Background())
    // Logs: {"time":"2025-01-07T10:30:00Z","level":"INFO","msg":"key manager started"}
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
- **Make logger optional** (handle nil gracefully)

```go
if m.config.Logger != nil {
    m.config.Logger.Info("operation complete", "duration", elapsed)
}
```

### DON'T ❌

- **Don't log sensitive data** (passwords, tokens, PII)
- **Don't use string formatting in messages** (use key-value pairs instead)
- **Don't log excessively** (avoid noisy logs)
- **Don't assume logger is not nil** (always check or use helper)

## Future: OpenTelemetry

The Logger interface is designed to be compatible with OpenTelemetry for unified observability (logs + metrics + traces). Integration guide will be provided when OpenTelemetry support is added.

## See Also

- [Metrics Package](../metrics/README.md) - For metrics/monitoring
- [Architecture Docs](../../docs/ARCHITECTURE.md) - Overall design decisions
- [KeyManager Example](../../examples/keymanager/) - Complete usage examples
