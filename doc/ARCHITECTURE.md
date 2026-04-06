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
- `pkg/tokens` - JWT token creation, validation, and lifecycle management
- `pkg/storage` - Refresh token persistence (memory, Redis, extensible)

### 3. Interface Segregation

Interfaces are small and focused:
- `Logger` - Only 4 methods (Debug, Info, Warn, Error)
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
- Logger interface evolved from Info/Warn/Error to include Debug for development tracing

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
│   ├── metrics/                   # Metrics abstraction and implementations
│   │   ├── interface.go           # Metrics interface
│   │   ├── noop.go                # NoOp implementation
│   │   ├── prometheus.go          # Prometheus implementation
│   │   ├── metrics_suite_test.go  # Ginkgo bootstrap
│   │   ├── prometheus_test.go     # 9-phase Prometheus test suite (73 specs)
│   │   └── noop_test.go           # NoOp tests
│   ├── keymanager/                # Key rotation and management
│   │   ├── manager.go             # Core implementation
│   │   ├── persistence.go         # Disk operations
│   │   └── keymanager_test.go    # Comprehensive tests
│   ├── tokens/                    # JWT token operations (Beta)
│   │   ├── service.go             # TokenService implementation
│   │   ├── service_test.go        # Token operations tests
│   │   ├── service_lifecycle_test.go  # Lifecycle management tests
│   │   └── claims.go              # Claims management
│   └── storage/                   # Refresh token storage ✅
│       ├── interface.go           # RefreshStore interface
│       ├── memory.go              # In-memory implementation
│       ├── redis.go               # Redis implementation
│       └── suite_test.go          # Shared test suite
├── internal/                      # Private packages
│   └── testutil/                  # Shared test utilities
│       ├── mock_logger.go         # Reusable MockLogger
│       └── mock_metrics.go        # gomock-generated MockMetrics
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
│  │KeyManager │ │  Tokens │ │  Storage   │  │
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
- **4 levels** (Debug, Info, Warn, Error) - stratified by use case
- **Structured** (key-value pairs) - machine-readable
- **Optional** (nil-safe) - works without logger
- **stdlib adapter** (slog) - no external dependencies

**Log Levels by Purpose**:

| Level | Use Case | Examples |
|-------|----------|----------|
| **Debug** | Development & troubleshooting | Entry points, cache hits/misses, intermediate state, "no-op" outcomes |
| **Info** | Terminal outcomes | Token issued, key rotated, cleanup completed |
| **Warn** | Expected but notable conditions | Empty inputs, missing tokens, expired items, context cancellation |
| **Error** | Failures requiring attention | I/O errors, invalid state, operation failures |

**Debug Usage Pattern**:
```go
// High-frequency read operations (cache lookups, token validation entry)
if m.config.Logger != nil {
    m.config.Logger.Debug("public key cache hit", "keyID", keyID)
}

// Intermediate steps in loops (per-token operations)
if m.logger != nil {
    m.logger.Debug("revoking token for user",
        "tokenID", tokenID,
        "userID", userID)
}

// No-op outcomes (nothing to do during cleanup)
if m.logger != nil {
    m.logger.Debug("no expired keys found during cleanup")
}
```

**Flow**:
```go
KeyManager → logging.Logger interface → SlogAdapter → os.Stdout → K8s logs
```

**Why this design**:
- ✅ Kubernetes logs picked up automatically (stdout/stderr)
- ✅ JSON format for log aggregators (ELK, Loki, Splunk)
- ✅ Flexible (swap logger without changing code)
- ✅ Testable (MockLogger)
- ✅ Debug level disableable in production (disable at handler, not in code)

### Metrics

**Interface**: `pkg/metrics/Metrics`

**Design Decisions**:
- **Generic primitives** (counters, gauges, histograms, durations) with label maps — backend-agnostic
- **Optional** (nil-safe) — works without metrics
- **Pre-registration at construction** — naming conflicts caught early, not at observation time
- **Graceful label handling** — wrong or missing labels log a warning and skip rather than panic

**Interface**:
```go
type Metrics interface {
    IncrementCounter(name string, labels map[string]string)
    AddCounter(name string, value float64, labels map[string]string)
    SetGauge(name string, value float64, labels map[string]string)
    RecordHistogram(name string, value float64, labels map[string]string)
    RecordDuration(name string, duration time.Duration, labels map[string]string)
}
```

**Implementations**:
- `PrometheusMetrics` — Prometheus client, isolated registry, OpenMetrics `/metrics` handler, 100% test coverage
- `NoOpMetrics` — zero overhead no-op for when metrics are disabled

**PrometheusMetrics pre-registered metrics** (grouped by component):

| Metric | Type | Labels |
|--------|------|--------|
| `jwtauth_tokens_issued_total` | Counter | status, error_type |
| `jwtauth_tokens_validated_total` | Counter | status, error_type |
| `jwtauth_tokens_refreshed_total` | Counter | status, error_type |
| `jwtauth_tokens_revoked_total` | Counter | operation, status |
| `jwtauth_tokens_introspected_total` | Counter | status |
| `jwtauth_operations_total` | Counter | operation, status |
| `jwtauth_operation_duration_seconds` | Histogram | operation |
| `jwtauth_active_tokens` | Gauge | storage_backend |
| `jwtauth_service_running` | Gauge | — |
| `jwtauth_storage_operations_total` | Counter | operation, status, storage_backend |
| `jwtauth_storage_cleanup_tokens_removed_total` | Counter | storage_backend |
| `jwtauth_storage_operation_duration_seconds` | Histogram | operation, storage_backend |
| `jwtauth_storage_tokens_count` | Gauge | storage_backend |
| `jwtauth_key_rotations_total` | Counter | status |
| `jwtauth_key_signing_operations_total` | Counter | status |
| `jwtauth_key_validation_operations_total` | Counter | status |
| `jwtauth_key_operation_duration_seconds` | Histogram | operation |
| `jwtauth_key_current_version` | Gauge | — |
| `jwtauth_key_active_versions_count` | Gauge | — |

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
        m.config.Metrics.IncrementCounter("jwtauth_key_rotations_total",
            map[string]string{"status": "success"})
        m.config.Metrics.RecordDuration("jwtauth_key_operation_duration_seconds",
            time.Since(start), map[string]string{"operation": "rotate"})
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

### TokenService (Beta)

**Responsibilities**:
- Issue access tokens (short-lived, e.g., 15 minutes) with optional custom claims
- Issue refresh tokens (long-lived, e.g., 30 days) with optional metadata
- Issue coordinated token pairs (access + refresh in one call)
- Validate access tokens (signature, expiration, issuer, audience)
- Rotate tokens via refresh flow with expiration and revocation checks
- Revoke single or all tokens for a user
- Introspect token status per RFC 7662
- Sign tokens with current key from KeyManager

**State Machine**:
```
Created → Start() → Running → Shutdown() → Stopped
                      ↓
                   Background cleanup goroutine (configurable interval)
```

**Concurrency Model**:
- **User goroutines**: Token operations (IssueAccessToken, ValidateAccessToken, etc.)
- **Cleanup goroutine**: Background ticker deletes expired refresh tokens from store
- **Synchronization**: `atomic.Bool` for running state; cleanup uses channel signaling and `sync.WaitGroup` for graceful shutdown

**Key Design Decisions**:
- Rate limiting is intentionally **not** in TokenService — it belongs at the infrastructure layer (API Gateway, Ingress, Load Balancer) where per-route and per-IP policies apply globally
- All storage operations accept `context.Context` for cancellation propagation
- Reserved JWT claims (`sub`, `iss`, `aud`, `exp`, `iat`, `jti`) cannot be overridden by custom claims

### RefreshTokenStore

**Responsibilities**:
- Store refresh tokens with expiration and revocation tracking
- Retrieve tokens with validation checks (expiry, revocation)
- Revoke individual or bulk tokens (by userID)
- Clean up expired tokens
- Maintain lookups optimized for each implementation

**Implementations**:

#### MemoryRefreshStore (In-Process, Testing & Single-Instance) ✅

**Design**:
```go
type MemoryRefreshStore struct {
    mu         sync.RWMutex             // Thread safety
    tokens     map[string]*RefreshToken // tokenID → token
    userTokens map[string][]string      // userID → []tokenID (for bulk ops)
    logger     logging.Logger           // Optional logging
}
```

**Key Features**:
- **Dual-index data structure**: `tokens` map for O(1) lookup, `userTokens` set for O(1) bulk revocation
- **Defensive copying**: Metadata and token structs isolated from caller mutations
- **RWMutex locking**: RLock for Retrieve (concurrent reads), Lock for mutations
- **Idempotent operations**: Revoke returns nil if token doesn't exist
- **Expiration/Revocation checks**: Retrieve validates expiry and revocation at request time
- **Cleanup**: Removes expired tokens from both maps and userTokens index
- **Context propagation**: All operations respect context.Context cancellation
- **Structured logging**: Warn for validation failures, Info for successful ops
- **Thread-safe**: Read operations concurrent, write operations exclusive

#### RedisRefreshStore (Distributed, Multi-Instance) ✅

**Design**:
```go
type RedisRefreshStore struct {
    client *redis.Client  // go-redis/v9 client (internally thread-safe)
    logger logging.Logger // Optional logging
}
```

**Redis Data Structure**:
```
tokens:{tokenID}        → Hash with fields: userID, expiresAt, createdAt, revoked, metadata
user_tokens:{userID}    → Set of tokenIDs for that user
```

**Key Features**:
- **Distributed**: Works across multiple instances (Redis is the shared backend)
- **Pipeline atomicity**: Multi-operation transactions via Redis pipelines
- **Millisecond-precision timestamps**: Stored as UnixMilli (preserves precision across serialization)
- **Efficient cleanup**: SCAN-based key iteration for expired token sweeps
- **TTL management**: Token keys automatically expire via Redis EXPIRE
- **Context propagation**: All operations respect context.Context cancellation
- **Structured logging**: Same error/info patterns as MemoryRefreshStore
- **Thread-safe**: go-redis/v9 client is internally thread-safe
- **Error handling**: Proper error wrapping with context

**Why Redis?**:
- ✅ Shared state across service instances (no distributed consensus issues)
- ✅ TTL-based automatic cleanup (keys expire automatically)
- ✅ Atomic transactions via pipelines
- ✅ Familiar operations (HSet, SAdd, SRem, Scan)
- ✅ Production-proven (widely used in Go services)

**Common Features** (Both Implementations):

| Aspect | Details |
|--------|---------|
| **Error Handling** | `ErrInvalidTokenID` / `ErrInvalidUserID`, `ErrTokenNotFound`, `ErrTokenExpired`, `ErrTokenRevoked` |
| **Validation** | Empty/whitespace input rejection, expiry checks, revocation checks |
| **Idempotence** | Revoke returns nil if token doesn't exist (safe to call multiple times) |
| **Context** | Full support for context.Context cancellation propagation |
| **Logging** | Structured key-value logs with operation names and fields |
| **Testing** | Identical comprehensive test suite (51 tests per implementation) |

#### Shared Test Suite Pattern

**Problem Solved**: Without shared testing, maintaining two implementations risks:
- Test divergence (Memory tests differ from Redis tests)
- Duplicate test code (800+ lines of duplication)
- Inconsistent semantics (implementations evolve differently)

**Solution**: Single parameterized test suite runs against all implementations:

```go
// suite_test.go defines 51 comprehensive tests
func RunRefreshStoreTests(description string, factory StoreFactory, cleanup CleanupFunc) bool {
    Describe(description, func() {
        // All 51 tests run here
        // Verify all error conditions, edge cases, context handling
    })
}

// memory_test.go uses the suite
var _ = RunRefreshStoreTests(
    "MemoryRefreshStore",
    func(logger) storage.RefreshStore { return storage.NewMemoryRefreshStore(logger) },
    nil,  // No cleanup needed
)

// redis_test.go uses the same suite
var _ = RunRefreshStoreTests(
    "RedisRefreshStore",
    func(logger) storage.RefreshStore {
        mini := miniredis.Run()
        return storage.NewRedisRefreshStore(redis.NewClient(...), logger)
    },
    func() { mini.FlushAll() },  // Cleanup after each test
)
```

**Benefits**:
- ✅ Both implementations pass identical tests (semantic equivalence)
- ✅ No duplication (single suite shared by all)
- ✅ Easy to add new implementations (just add a new test file calling RunRefreshStoreTests)
- ✅ Same behavior guaranteed (same test code)
- ✅ Reduces maintenance burden (update tests once, benefits both)

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

Describe("MemoryRefreshStore", func() {
    // Phase 1: Constructor
    // Phase 2: Happy paths (Store, Retrieve)
    // Phase 2.5: Context cancellation
    // Phase 3: Input validation
    // Phase 4: Defensive programming
    // Phase 5: Contract compliance
    // Phase 6: Concurrency safety
    // Phase 7: Core methods
    // Phase 8: Edge cases
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

## Roadmap

### Phase 1: Logging ✅
- ✅ Logger interface defined
- ✅ Slog adapter implemented
- ✅ KeyManager integrated
- ✅ Tests comprehensive

### Phase 2: Metrics ✅
- ✅ Metrics interface defined
- ✅ Prometheus implementation (`PrometheusMetrics`) with 19 pre-registered metrics, 100% test coverage
- ✅ NoOp implementation
- ✅ gomock `MockMetrics` for dependency injection in tests
- ⏳ Wire into KeyManager, TokenService, and RefreshStore

### Phase 3: TokenService ✅ (Beta)
- ✅ JWT creation with RS256 signing and custom claims
- ✅ Access token validation (signature, expiration, issuer, audience)
- ✅ Refresh token rotation with revocation checks
- ✅ Single and bulk token revocation
- ✅ Token introspection per RFC 7662
- ✅ Lifecycle management (Start/Shutdown/IsRunning)
- ✅ Background cleanup goroutine with configurable interval
- ✅ Comprehensive test coverage (126 tests, ~87% coverage, race-detection clean)
- ✅ RefreshStore interface with context propagation

### Phase 4: RefreshToken Storage Implementations ✅
- ✅ RefreshStore interface defined (pkg/storage)
- ✅ MemoryRefreshStore (in-process, testing + single-instance deployments)
  - Dual-index design for O(1) lookups and bulk operations
  - Defensive copying for metadata isolation
  - 51 comprehensive tests with 100% statement coverage
- ✅ RedisRefreshStore (distributed, multi-instance deployments)
  - Pipeline-based atomic operations
  - Millisecond-precision timestamp handling
  - Efficient SCAN-based cleanup
  - 51 comprehensive tests (identical suite as Memory)
- ✅ Shared test suite pattern (eliminates 800+ lines of duplication)
  - Single parameterized suite runs against all implementations
  - Ensures semantic equivalence across backends
  - Easy to add new implementations

### Phase 5: Metrics Wiring (In Progress)
- ✅ Prometheus adapter with `/metrics` endpoint (`PrometheusMetrics`)
- ⏳ Wire `PrometheusMetrics` into KeyManager, TokenService, and RefreshStore
- ⏳ StatsD integration (Datadog, Graphite compatible)
- ⏳ CloudWatch metrics for AWS environments

### Phase 6: OpenTelemetry (Future)
- ⏳ Distributed tracing
- ⏳ Span creation across token operations
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

**Last Updated**: April 6, 2026
**Version**: 0.2.0-beta
**Status**: Active Development (TokenService + RefreshStore [Memory + Redis] + Metrics [Prometheus] stable, wiring metrics into components in progress)
