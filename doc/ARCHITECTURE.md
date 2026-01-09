# JWT Authentication System - Architecture

This document explains the design decisions, patterns, and principles used in the JWT authentication system.

## Table of Contents

- [Overview](#overview)
- [Design Principles](#design-principles)
- [Project Structure](#project-structure)
- [Observability Architecture](#observability-architecture)
- [Dependency Inversion](#dependency-inversion)
- [Component Architecture](#component-architecture)
- [Testing Strategy](#testing-strategy)
- [Future Roadmap](#future-roadmap)

---

## Overview

The JWT authentication system is designed as a **production-ready, highly observable, and testable** authentication solution for Go applications.

### Key Features

- **Zero-downtime key rotation** with configurable overlap periods
- **Automatic background rotation** with cleanup
- **Structured logging** for log aggregation (ELK, Loki, Splunk)
- **Domain-specific metrics** for monitoring and alerting
- **Thread-safe** concurrent operations
- **Graceful shutdown** with proper resource cleanup
- **Comprehensive test coverage** with race detection

---

## Design Principles

### 1. Dependency Inversion Principle (SOLID)

> High-level modules should not depend on low-level modules. Both should depend on abstractions.

**Applied**:
- Components depend on `logging.Logger` interface, not specific loggers
- Components depend on `metrics.Metrics` interface, not specific metrics systems
- Easy to swap implementations without changing component code

**Example**:
```go
// KeyManager depends on abstractions, not concrete implementations
type ManagerConfig struct {
    Logger  logging.Logger   // Interface, not *slog.Logger
    Metrics metrics.Metrics  // Interface, not *PrometheusMetrics
}
```

### 2. Single Responsibility Principle

Each package has one clear responsibility:
- `pkg/keymanager` - RSA key generation, rotation, and management
- `pkg/logging` - Logging abstraction and adapters
- `pkg/metrics` - Metrics abstraction and implementations
- `pkg/tokens` (future) - JWT token creation and validation
- `pkg/middleware` (future) - HTTP middleware for token validation

### 3. Interface Segregation

Interfaces are small and focused:
- `Logger` - Only 3 methods (Info, Warn, Error)
- `Metrics` - Domain-specific methods, not generic
- Easy to implement, test, and maintain

### 4. Don't Repeat Yourself (DRY)

Shared interfaces prevent duplication:
- One `Logger` interface for all components
- One `MockLogger` for all tests
- One set of adapters reused everywhere

### 5. YAGNI (You Aren't Gonna Need It)

Build what's needed now:
- No interfaces until multiple implementations exist
- Metrics interface defined, but implementations added as needed
- Simple Logger interface (no Debug level initially)

---

## Project Structure

```
github.com/aetomala/jwtauth/
├── pkg/                           # Public API packages
│   ├── logging/                   # Logging abstraction
│   │   ├── logger.go              # Logger interface
│   │   ├── noop.go                # NoOp implementation
│   │   ├── slog_adapter.go        # Standard library adapter
│   │   └── README.md              # Usage documentation
│   ├── metrics/                   # Metrics abstraction
│   │   ├── metrics.go             # Metrics interface
│   │   ├── noop.go                # NoOp implementation
│   │   └── README.md              # Usage documentation
│   ├── keymanager/                # Key rotation and management
│   │   ├── manager.go             # Core implementation
│   │   ├── persistence.go         # Disk operations
│   │   └── keymanager_test.go    # Comprehensive tests
│   ├── tokens/                    # JWT token operations (future)
│   ├── middleware/                # HTTP middleware (future)
│   └── storage/                   # Refresh token storage (future)
├── internal/                      # Private packages
│   └── testutil/                  # Shared test utilities
│       └── mock_logger.go         # Reusable mock logger
├── docs/                          # Documentation
│   └── ARCHITECTURE.md            # This file
├── examples/                      # Usage examples
│   └── keymanager/                # KeyManager examples
│       ├── basic.go               # Basic usage
│       └── with_logging.go        # With logging and metrics
└── go.mod
```

### Package Organization

**`pkg/` (Public API)**
- Code users import and use directly
- Stable interfaces
- Semantic versioning applies

**`internal/` (Private)**
- Implementation details
- Test utilities
- Not importable by external code

**`docs/` (Documentation)**
- Architecture decisions
- Design patterns
- Best practices

**`examples/` (Usage Examples)**
- Complete runnable examples
- Real-world patterns
- Copy-paste ready code

---

## Observability Architecture

### Design Goal

**Unified observability across all components with zero coupling to specific implementations.**

### Three Pillars

```
┌─────────────────────────────────────────────┐
│           JWT Auth System                    │
├─────────────────────────────────────────────┤
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  │
│  │ Logging  │  │ Metrics  │  │ Tracing  │  │
│  │Interface │  │Interface │  │(Future)  │  │
│  └──────────┘  └──────────┘  └──────────┘  │
├─────────────────────────────────────────────┤
│         Component Layer                      │
│  ┌───────────┐ ┌─────────┐ ┌────────────┐  │
│  │KeyManager │ │  Tokens │ │ Middleware │  │
│  └───────────┘ └─────────┘ └────────────┘  │
└─────────────────────────────────────────────┘
           ↓ Observability Signals
┌─────────────────────────────────────────────┐
│     User's Observability Stack               │
│  ┌─────────┐  ┌────────────┐  ┌──────────┐ │
│  │  slog   │  │Prometheus  │  │   OTel   │ │
│  │  Zap    │  │  StatsD    │  │  (Future)│ │
│  │ Zerolog │  │CloudWatch  │  │          │ │
│  └─────────┘  └────────────┘  └──────────┘ │
└─────────────────────────────────────────────┘
```

### Logging

**Interface**: `pkg/logging/Logger`

**Design Decisions**:
- **3 levels only** (Info, Warn, Error) - simple and sufficient
- **Structured** (key-value pairs) - machine-readable
- **Optional** (nil-safe) - works without logger
- **stdlib adapter** (slog) - no external dependencies

**Flow**:
```go
KeyManager → logging.Logger interface → SlogAdapter → os.Stdout → K8s logs
```

**Why this design**:
- ✅ Kubernetes logs picked up automatically (stdout/stderr)
- ✅ JSON format for log aggregators (ELK, Loki, Splunk)
- ✅ Flexible (swap logger without changing code)
- ✅ Testable (MockLogger)

### Metrics

**Interface**: `pkg/metrics/Metrics`

**Design Decisions**:
- **Domain-specific** methods (not generic counters)
- **Type-safe** (prevents errors)
- **Optional** (nil-safe) - works without metrics
- **Future implementations** (Prometheus, StatsD, CloudWatch)

**Why domain-specific**:
```go
// ✅ Good: Clear intent, type-safe
metrics.RecordRotation(true, 150*time.Millisecond)

// ❌ Alternative: Generic, error-prone
metrics.IncrementCounter("key.rotation.success", 1)
metrics.RecordDuration("key.rotation.duration", 150)
```

### Integration Pattern

Every component accepts optional observability:

```go
type ManagerConfig struct {
    // Core configuration
    KeyDirectory        string
    KeyRotationInterval time.Duration
    
    // Observability (optional)
    Logger  logging.Logger   // Can be nil
    Metrics metrics.Metrics  // Can be nil
}

// Usage
func (m *Manager) RotateKeys(ctx context.Context) error {
    start := time.Now()
    
    // Rotate logic...
    
    // Optional logging
    if m.config.Logger != nil {
        m.config.Logger.Info("key rotation successful",
            "keyID", newKeyID,
            "duration", time.Since(start))
    }
    
    // Optional metrics
    if m.config.Metrics != nil {
        m.config.Metrics.RecordRotation(true, time.Since(start))
    }
    
    return nil
}
```

---

## Dependency Inversion

### Problem Without Dependency Inversion

```go
// ❌ Bad: Direct coupling to concrete implementation
import "github.com/uber-go/zap"

type Manager struct {
    logger *zap.Logger  // Tightly coupled!
}

// Issues:
// - Can't swap logger without changing Manager
// - Hard to test (real logger in tests)
// - Forces all users to use Zap
```

### Solution With Dependency Inversion

```go
// ✅ Good: Depends on abstraction
import "github.com/aetomala/jwtauth/pkg/logging"

type Manager struct {
    logger logging.Logger  // Interface!
}

// Benefits:
// - Easy to swap (slog, Zap, Zerolog, NoOp)
// - Easy to test (MockLogger)
// - Users choose their logger
```

### Dependency Flow

```
High-Level Module (KeyManager)
        ↓ depends on
    Abstraction (logging.Logger interface)
        ↑ implements
Low-Level Module (SlogAdapter, ZapAdapter, etc.)
```

**Key Insight**: The dependency points **upward** (adapter implements interface), not downward (KeyManager doesn't import adapter).

---

## Component Architecture

### KeyManager

**Responsibilities**:
- Generate RSA key pairs
- Rotate keys on schedule
- Maintain overlap period (old + new keys valid simultaneously)
- Cleanup expired keys
- Persist keys to disk
- Provide JWKS endpoint

**State Machine**:
```
Created → Start() → Running → Shutdown() → Stopped
                      ↓
                   Rotating (concurrent with Running)
                      ↓
                   Cleanup (concurrent with Running)
```

**Concurrency Model**:
- **Main goroutine**: User requests (GetCurrentSigningKey, RotateKeys, etc.)
- **Rotation goroutine**: Background scheduler, fires every N days
- **Cleanup goroutine**: Separate ticker, checks every N minutes
- **Synchronization**: RWMutex for key map, atomic for state

**Key Rotation Timeline**:
```
Day 0:    Key A (current)
Day 30:   Rotate → Key A (expires in 1 hour), Key B (current)
Day 30+1h: Key A deleted, Key B (current)
Day 60:   Rotate → Key B (expires in 1 hour), Key C (current)
```

**Persistence**:
- **PEM files**: `{keyID}.pem` - RSA private keys
- **Metadata files**: `{keyID}.json` - CreatedAt, ExpiresAt timestamps
- **Load on restart**: All valid keys loaded, most recent becomes current

### TokenService (Future)

**Responsibilities**:
- Issue access tokens (short-lived, e.g., 15 minutes)
- Issue refresh tokens (long-lived, e.g., 30 days)
- Validate tokens (signature, expiration, claims)
- Sign tokens with current key from KeyManager

### Middleware (Future)

**Responsibilities**:
- Extract token from HTTP request (Authorization header)
- Validate token using TokenService
- Inject user context into request
- Return 401 Unauthorized on invalid token

### RefreshTokenStore (Future)

**Responsibilities**:
- Store refresh tokens (in-memory or Redis)
- Revoke refresh tokens
- Track refresh token usage

---

## Testing Strategy

### Test Organization

Tests organized by **concern**, not **chronology**:

```go
Describe("KeyManager", func() {
    // Phase 1: Constructor
    // Phase 2: Start
    // Phase 3: Core Operations
    // ...
})

Describe("KeyManager Shutdown", func() {
    // Separate suite for shutdown behavior
})

Describe("KeyManager Persistence", func() {
    // Separate suite for disk operations
})

Describe("KeyManager Logging", func() {
    // Separate suite for logging behavior
})
```

### Progressive Phase-Based Testing

Each phase builds on the previous:

```
Phase 1: Constructor
  ↓ Test passes
Phase 2: Start/Initialization  
  ↓ Test passes
Phase 3: Core Operations
  ↓ Test passes
Phase 4: JWKS
  ↓ Test passes
Phase 5: Manual Rotation
  ↓ Test passes
Phase 6: Automatic Rotation
  ↓ Test passes
Phase 7: Concurrency
```

**Benefits**:
- Small increments (easy to debug)
- Always have working code
- Clear checkpoints

### Test Utilities

**Shared MockLogger** (`internal/testutil/mock_logger.go`):
- Thread-safe log recording
- Query helpers (HasLog, CountLogs, etc.)
- Reusable across all component tests

**Usage**:
```go
mockLogger := testutil.NewMockLogger()

manager := keymanager.NewManager(keymanager.ManagerConfig{
    Logger: mockLogger,
})

manager.Start(ctx)

// Verify
Expect(mockLogger.HasLog("info", "key manager started")).To(BeTrue())
```

### Race Detection

All tests run with race detector:
```bash
ginkgo -race ./...
```

Catches:
- Concurrent map access
- Unsynchronized atomic operations
- Channel races

---

## Future Roadmap

### Phase 1: Logging (Current)
- ✅ Logger interface defined
- ✅ Slog adapter implemented
- ✅ KeyManager integrated
- ✅ Tests comprehensive

### Phase 2: Metrics (Next)
- ✅ Metrics interface defined
- ⏳ Prometheus implementation
- ⏳ KeyManager integration
- ⏳ Tests added

### Phase 3: TokenService
- ⏳ Interface design
- ⏳ JWT creation/validation
- ⏳ Integration with KeyManager
- ⏳ Logging and metrics

### Phase 4: Middleware
- ⏳ HTTP middleware
- ⏳ Token extraction
- ⏳ Validation pipeline
- ⏳ User context injection

### Phase 5: RefreshTokenStore
- ⏳ Interface design
- ⏳ Memory implementation
- ⏳ Redis implementation
- ⏳ Revocation logic

### Phase 6: RateLimiter
- ⏳ Interface design
- ⏳ Token bucket algorithm
- ⏳ Per-user limits
- ⏳ Per-IP limits

### Phase 7: OpenTelemetry
- ⏳ Unified observability
- ⏳ Distributed tracing
- ⏳ Span creation
- ⏳ Context propagation

---

## Design Patterns Used

### 1. Dependency Injection
Configuration structs accept interfaces:
```go
type ManagerConfig struct {
    Logger logging.Logger  // Injected
}
```

### 2. Strategy Pattern
Swap implementations via interfaces:
```go
// Development
logger := logging.NewTextLogger(slog.LevelInfo)

// Production
logger := logging.NewJSONLogger(slog.LevelInfo)
```

### 3. Adapter Pattern
Adapt external libraries to our interfaces:
```go
type SlogAdapter struct {
    logger *slog.Logger
}

func (s *SlogAdapter) Info(msg string, args ...interface{}) {
    s.logger.Info(msg, args...)
}
```

### 4. Null Object Pattern
NoOp implementations for optional features:
```go
type NoOpLogger struct{}
func (n *NoOpLogger) Info(msg string, args ...interface{}) {}
```

### 5. Template Method
Consistent patterns for all components:
```go
func (c *Component) Operation() error {
    // 1. Check state
    // 2. Acquire lock
    // 3. Do work
    // 4. Log result (if logger present)
    // 5. Record metric (if metrics present)
}
```

---

## Contributing Guidelines

### Adding New Components

1. Define interfaces in `pkg/` following existing patterns
2. Implement core functionality
3. Add logging at appropriate points
4. Add metrics for monitoring
5. Write comprehensive tests (Ginkgo)
6. Document in README.md
7. Update ARCHITECTURE.md

### Adding Observability

1. Identify what to log/measure
2. Add calls at appropriate points
3. Always check for nil (optional feature)
4. Write tests verifying logs/metrics
5. Update documentation

### Testing Requirements

- ✅ All new code must have tests
- ✅ Tests must pass race detector
- ✅ Coverage >80% for critical paths
- ✅ Integration tests for complex flows
- ✅ Examples for new features

---

## References

- [SOLID Principles](https://en.wikipedia.org/wiki/SOLID)
- [Dependency Inversion Principle](https://en.wikipedia.org/wiki/Dependency_inversion_principle)
- [Go Concurrency Patterns](https://go.dev/blog/pipelines)
- [Structured Logging Best Practices](https://go.dev/blog/slog)
- [Kubernetes Logging Architecture](https://kubernetes.io/docs/concepts/cluster-administration/logging/)

---

**Last Updated**: January 2026  
**Version**: 1.0.0-alpha  
**Status**: Active Development
