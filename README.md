# jwtauth

![Tests](https://github.com/aetomala/jwtauth/actions/workflows/CI.yml/badge.svg?branch=main)
![Go Version](https://img.shields.io/badge/go-1.21+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

**Production-ready JWT authentication library for distributed Go applications**

> ⚠️ **Beta Status**: KeyManager and RefreshStore are production-ready and fully tested. TokenService is in beta — core operations are complete with comprehensive test coverage. API may change before v1.0.0.

## Overview

`jwtauth` is a JWT authentication library built from the ground up with **observability, testability, and production operations** as first-class concerns. Unlike traditional JWT libraries that focus solely on token operations, jwtauth provides complete lifecycle management including zero-downtime key rotation, structured logging, metrics integration, and graceful shutdown patterns.

### Design Philosophy

- **Dependency Inversion**: All components depend on interfaces, not concrete implementations
- **Observability-First**: Structured logging and metrics built into every operation
- **Production-Ready**: Graceful shutdown, persistence, concurrent operations, comprehensive error handling
- **SOLID Principles**: Clean architecture that's easy to test, extend, and maintain
- **Zero External Dependencies**: Core functionality uses only Go standard library

## Key Features

### ✅ Currently Available

**KeyManager**
- **Zero-downtime key rotation** with configurable overlap periods
- **Automatic background rotation** with cleanup
- **RSA key pair generation** and management
- **JWKS (JSON Web Key Set)** endpoint support
- **Persistence** to disk with atomic file operations
- **Thread-safe** concurrent operations with proper locking
- **Graceful shutdown** with in-flight operation completion
- **Structured logging** (slog adapter included, bring your own logger)
- **Domain-specific metrics** interface (Prometheus adapter coming)
- **Comprehensive test coverage** with race detection

**TokenService** (Beta)
- **Access token issuance** (IssueAccessToken, IssueAccessTokenWithClaims, IssueTokenPair)
- **Refresh token issuance** (IssueRefreshToken, IssueRefreshTokenWithMetadata)
- **Access token validation** with claims extraction (ValidateAccessToken)
- **Token refresh flow** (RefreshAccessToken) with expiration and revocation checks
- **Token revocation** (RevokeRefreshToken, RevokeAllUserTokens) for logout and security scenarios
- **Token introspection** (IntrospectToken) per RFC 7662 — returns active/inactive status with metadata
- **Manual token cleanup** (CleanupExpiredTokens) for on-demand expiration sweeps
- **RS256 signing** with custom claims support and reserved claim protection
- **Lifecycle management** (Start/Shutdown/IsRunning) with graceful operations
- **Background cleanup goroutines** with configurable interval and proper synchronization
- **Service state management** ensuring tokens only issue when service is running
- **Comprehensive BDD test coverage** (126 tests covering lifecycle, issuance, validation, refresh, revocation, and introspection; ~87% statement coverage)

**RefreshTokenStore** ✅
- **Two implementations**: Memory (in-process) and Redis (distributed)
- **MemoryRefreshStore**: In-memory storage with thread-safe RWMutex locking
  - Perfect for single-instance deployments and testing
  - Dual-index lookups (tokenID → token, userID → []tokenID) for O(1) retrieval
  - Defensive copying for isolation from caller mutations
  - 61 comprehensive tests with 100% statement coverage
- **RedisRefreshStore**: Distributed storage for multi-instance deployments
  - Uses go-redis/v9 with pipeline support for atomic operations
  - Millisecond-precision timestamp storage
  - Efficient SCAN-based cleanup for expired tokens
  - Production-ready error handling and logging
  - 61 comprehensive tests (identical test suite as Memory implementation)
- **Shared test suite** pattern: Single suite (61 tests) runs against both implementations
- **Common features** (both implementations):
  - Token lifecycle management (Store, Retrieve, Revoke, RevokeAllForUser, Cleanup)
  - Expiration and revocation checks with per-request validation
  - Idempotent revocation (safe to call multiple times)
  - Comprehensive context handling with cancellation propagation
  - Structured logging for audit trail
  - **122 total storage tests** (61 × 2 implementations)

### 🚧 In Development

- **Metrics Wiring**: Wire `PrometheusMetrics` into TokenService and RefreshStore (KeyManager already wired via DiskKeyStore)
- **OpenTelemetry**: Distributed tracing integration

## Architecture Highlights

### Observability as a Core Design Principle

Every component accepts optional logging and metrics interfaces:

```go
import (
    "github.com/aetomala/jwtauth/pkg/keymanager"
    "github.com/aetomala/jwtauth/pkg/logging"
    "github.com/aetomala/jwtauth/pkg/metrics"
)

ks, _ := keymanager.NewDiskKeyStore("/var/keys", 2048, nil, nil)
config := keymanager.ManagerConfig{
    KeyStore:            ks,
    KeyRotationInterval: 30 * 24 * time.Hour, // 30 days
    KeyOverlapDuration:  1 * time.Hour,        // 1 hour overlap

    // Optional: Bring your own logger
    Logger: logging.NewJSONLogger(slog.LevelInfo),

    // Optional: Bring your own metrics
    Metrics: metrics.NewPrometheusMetrics(metrics.PrometheusConfig{
        Namespace: "myapp",
    }),
}
```

### Key Rotation with Zero Downtime

```
Day 0:    Key A (current, signs new tokens)
          ↓
Day 30:   Rotate → Key A (validates old tokens), Key B (current, signs new tokens)
          ↓ [1 hour overlap period]
Day 30+1h: Key B (current, only valid key)
```

**Why this matters**: Services can validate tokens signed with old keys during the overlap period, ensuring zero service disruption during rotation.

### Dependency Inversion Pattern

Components depend on abstractions, not concrete implementations:

```go
// ✅ KeyManager depends on interfaces
type ManagerConfig struct {
    KeyStore KeyStore         // Interface, not *DiskKeyStore
    Logger   logging.Logger  // Interface, not *slog.Logger
    Metrics  metrics.Metrics // Interface, not *PrometheusMetrics
}

// Easy to swap implementations:
logger := logging.NewJSONLogger(slog.LevelInfo)      // Production
logger := logging.NewTextLogger(slog.LevelDebug)     // Development
logger := logging.NewNoOpLogger()                     // Disable logging
logger := yourCustomAdapter{}                         // Your own logger
```

**Benefits**:
- Easy to test (mock implementations)
- Easy to integrate (adapt your existing logging/metrics)
- No forced dependencies (optional observability)
- Follows SOLID principles (open for extension, closed for modification)

## Installation

```bash
# Will be available as:
go get github.com/aetomala/jwtauth
```

**Current Status**: Beta development. Not recommended for production use until v1.0.0 release.

## Quick Start

### Basic KeyManager Usage

```go
package main

import (
    "context"
    "log"
    "time"
    
    "github.com/aetomala/jwtauth/pkg/keymanager"
)

func main() {
    // Create DiskKeyStore for key persistence
    ks, err := keymanager.NewDiskKeyStore("./keys", 2048, nil, nil)
    if err != nil {
        log.Fatal(err)
    }

    // Create KeyManager
    manager, err := keymanager.NewManager(keymanager.ManagerConfig{
        KeyStore:            ks,
        KeyRotationInterval: 30 * 24 * time.Hour,
        KeyOverlapDuration:  1 * time.Hour,
    })
    if err != nil {
        log.Fatal(err)
    }
    
    // Start background rotation
    ctx := context.Background()
    if err := manager.Start(ctx); err != nil {
        log.Fatal(err)
    }
    defer manager.Shutdown(ctx)
    
    // Get current signing key
    _, keyID, err := manager.GetCurrentSigningKey()
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Current key ID: %s", keyID)
    
    // Get JWKS for token validation
    jwks, err := manager.GetJWKS()
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("Available keys: %d", len(jwks.Keys))
}
```

### With Observability

```go
import (
    "log/slog"
    "os"
    
    "github.com/aetomala/jwtauth/pkg/keymanager"
    "github.com/aetomala/jwtauth/pkg/logging"
)

func main() {
    // Configure structured logging (JSON for production)
    logger := logging.NewJSONLogger(slog.LevelInfo)
    pm := metrics.NewPrometheusMetrics(metrics.PrometheusConfig{})

    ks, err := keymanager.NewDiskKeyStore("./keys", 2048, logger, pm)
    if err != nil {
        log.Fatal(err)
    }

    manager, err := keymanager.NewManager(keymanager.ManagerConfig{
        KeyStore:            ks,
        KeyRotationInterval: 30 * 24 * time.Hour,
        KeyOverlapDuration:  1 * time.Hour,
        Logger:              logger,
        Metrics:             pm,
    })
    if err != nil {
        log.Fatal(err)
    }
    
    ctx := context.Background()
    manager.Start(ctx)
    defer manager.Shutdown(ctx)
    
    // All operations are logged with structured fields
    // Example log output:
    // {"time":"2026-02-07T12:00:00Z","level":"INFO","msg":"key manager started","active_keys":2}
    // {"time":"2026-02-07T12:30:00Z","level":"INFO","msg":"key rotation successful","key_id":"key_20260207_120000","duration":"150ms"}

    // Metrics are available at /metrics (Prometheus text format)
    http.Handle("/metrics", pm.Handler())
}
```

### TokenService Usage (Beta)

```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/aetomala/jwtauth/pkg/tokens"
    // ... other imports
)

func main() {
    // Create TokenService with storage
    config := tokens.ServiceConfig{
        KeyManager:           keyManager,      // from KeyManager above
        RefreshStore:         refreshStore,    // RefreshStore implementation
        Logger:               logger,          // Optional
        AccessTokenDuration:  15 * time.Minute,
        RefreshTokenDuration: 30 * 24 * time.Hour,
        CleanupInterval:      1 * time.Hour,   // Auto-cleanup of expired tokens
        Issuer:               "my-app",
        Audience:             []string{"my-app-api"},
    }

    service, err := tokens.NewService(config)
    if err != nil {
        log.Fatal(err)
    }

    // Start service lifecycle
    ctx := context.Background()
    if err := service.Start(ctx); err != nil {
        log.Fatal(err)
    }
    defer service.Shutdown(ctx)

    // Issue access token with custom claims
    token, err := service.IssueAccessTokenWithClaims(ctx, "user-123", map[string]interface{}{
        "role": "admin",
        "tenant": "org-456",
    })
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Access token issued: %s", token)
}
```

**Key Features**:
- ✅ Automatic lifecycle management (Start/Shutdown)
- ✅ Service state checking (IsRunning) ensures tokens only issue when running
- ✅ Custom claims support with reserved claim protection
- ✅ Background cleanup of expired refresh tokens
- ✅ Structured logging integration

## Configuration

### ManagerConfig

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `KeyStore` | `KeyStore` | Yes | - | Key persistence backend — use `NewDiskKeyStore` for single-instance or a custom implementation for distributed deployments |
| `KeyRotationInterval` | `time.Duration` | Yes | - | How often to rotate keys (e.g., 30 days) |
| `KeyOverlapDuration` | `time.Duration` | Yes | - | Overlap period for zero-downtime rotation |
| `Logger` | `logging.Logger` | No | `nil` | Optional structured logger |
| `Metrics` | `metrics.Metrics` | No | `nil` | Optional metrics collector |

### Recommended Settings

**Production**:
```go
ks, _ := keymanager.NewDiskKeyStore("./keys", 2048, nil, nil)
config := keymanager.ManagerConfig{
    KeyStore:            ks,
    KeyRotationInterval: 30 * 24 * time.Hour,  // 30 days
    KeyOverlapDuration:  1 * time.Hour,         // 1 hour
    Logger:              logging.NewJSONLogger(slog.LevelInfo),
}
```

**Development**:
```go
ks, _ := keymanager.NewDiskKeyStore("./keys", 2048, nil, nil)
config := keymanager.ManagerConfig{
    KeyStore:            ks,
    KeyRotationInterval: 24 * time.Hour,        // 1 day (faster testing)
    KeyOverlapDuration:  5 * time.Minute,        // 5 minutes
    Logger:              logging.NewTextLogger(slog.LevelDebug),
}
```

## Observability Integration

### Logging

**Built-in adapters**:
- `logging.NewJSONLogger()` - JSON output for log aggregators (ELK, Loki, Splunk)
- `logging.NewTextLogger()` - Human-readable text for development
- `logging.NewNoOpLogger()` - Disable logging

**Bring your own logger**:
```go
// Implement the simple Logger interface
type Logger interface {
    Debug(msg string, args ...interface{})
    Info(msg string, args ...interface{})
    Warn(msg string, args ...interface{})
    Error(msg string, args ...interface{})
}

// Adapt your existing logger
type MyZapAdapter struct {
    logger *zap.Logger
}

func (m *MyZapAdapter) Debug(msg string, args ...interface{}) {
    m.logger.Sugar().Debugw(msg, args...)
}
func (m *MyZapAdapter) Info(msg string, args ...interface{}) {
    m.logger.Sugar().Infow(msg, args...)
}
// ... implement Warn, Error
```

### Metrics

**Interface** (`pkg/metrics/Metrics`):
```go
type Metrics interface {
    IncrementCounter(name string, labels map[string]string)
    AddCounter(name string, value float64, labels map[string]string)
    SetGauge(name string, value float64, labels map[string]string)
    RecordHistogram(name string, value float64, labels map[string]string)
    RecordDuration(name string, duration time.Duration, labels map[string]string)
}
```

**Available implementations**:
- `metrics.NewPrometheusMetrics()` — Prometheus with `/metrics` endpoint, pre-registers all jwtauth metrics at construction time
- `metrics.NewNoOpMetrics()` — no-op, zero overhead, for when metrics are disabled

**Prometheus quick start**:
```go
pm := metrics.NewPrometheusMetrics(metrics.PrometheusConfig{
    Namespace: "myapp",   // defaults to "jwtauth"
})

// Serve metrics endpoint
http.Handle("/metrics", pm.Handler())

// Pass to components
ks, _ := keymanager.NewDiskKeyStore("./keys", 2048, nil, pm)
config := keymanager.ManagerConfig{
    KeyStore: ks,
    Metrics:  pm,
}
```

**Planned implementations**:
- StatsD (for Datadog, Graphite)
- CloudWatch (for AWS environments)

## Project Structure

```
github.com/aetomala/jwtauth/
├── pkg/                          # Public API packages
│   ├── logging/                  # Logging abstraction
│   │   ├── logger.go             # Logger interface (4 methods: Debug, Info, Warn, Error)
│   │   ├── slog_adapter.go       # Standard library adapter
│   │   └── noop.go               # NoOp implementation
│   ├── metrics/                  # Metrics abstraction and implementations
│   │   ├── interface.go          # Metrics interface
│   │   ├── noop.go               # NoOp implementation
│   │   ├── prometheus.go         # Prometheus implementation
│   │   ├── metrics_suite_test.go # Ginkgo bootstrap
│   │   ├── prometheus_test.go    # 9-phase Prometheus test suite
│   │   └── noop_test.go          # NoOp tests
│   ├── keymanager/               # Key rotation and management ✅
│   │   ├── keymanager.go         # Manager: lifecycle, rotation, JWKS generation
│   │   ├── interface.go          # Manager interface
│   │   ├── keystore.go           # KeyStore interface, StoredKey type, sentinel errors
│   │   ├── disk.go               # DiskKeyStore — filesystem-backed KeyStore
│   │   ├── observability.go      # Metric name constants
│   │   ├── keymanager_test.go    # 8-phase Manager tests (44 specs, MockKeyStore)
│   │   └── disk_test.go          # 9-phase DiskKeyStore tests (38 specs)
│   ├── tokens/                   # JWT operations (Beta) 🟡
│   │   ├── service.go            # TokenService implementation
│   │   ├── service_test.go       # Token operations tests
│   │   ├── service_lifecycle_test.go  # Lifecycle management tests
│   │   └── claims.go             # Claims management
│   ├── storage/                  # Refresh token storage ✅
│   │   ├── interface.go          # RefreshStore interface
│   │   ├── errors.go             # Sentinel error types
│   │   ├── memory.go             # In-memory implementation (~287 lines, production-ready)
│   │   ├── memory_test.go        # Test runner for MemoryRefreshStore (26 lines)
│   │   ├── redis.go              # Redis implementation (~497 lines, production-ready)
│   │   ├── redis_test.go         # Test runner for RedisRefreshStore (60 lines)
│   │   └── suite_test.go         # Shared test suite (642 lines, 51 tests run against both implementations)
├── internal/                     # Private packages
│   └── testutil/                 # Shared test utilities
│       ├── mock_logger.go        # Reusable MockLogger
│       ├── mock_metrics.go       # gomock-generated MockMetrics
│       └── mock_keystore.go      # gomock-generated MockKeyStore
├── doc/                          # Documentation
│   └── ARCHITECTURE.md           # Design decisions and patterns
└── examples/                     # Usage examples (coming)
```

## Testing

### Test Coverage

**Current**: 472 comprehensive tests across KeyManager, TokenService, RefreshStore, Metrics, and Logging, all passing with race detection (KeyManager ~90%, TokenService ~87%, RefreshStore 100%, Metrics 100%, Logging 100%)

**KeyManager** (2 test suites — 82 total specs):
- **8-phase Manager tests** (44 specs, MockKeyStore — no filesystem I/O):
  - Constructor validation, config defaults, ErrInvalidKeyStore
  - Start: loads from store, generates key on empty store, error paths
  - GetCurrentSigningKey, GetPublicKey (cache hit/miss), GetJWKS
  - RotateKeys: Save + UpdateMetadata calls, currentKeyID update
  - Shutdown: scheduler stop, idempotency, context timeout
- **9-phase DiskKeyStore tests** (38 specs, real tmp directory):
  - Constructor, Save (0600 permissions, companion JSON), LoadAll
  - LoadKey (key size validation), UpdateMetadata, Delete (idempotent)
  - Error handling, concurrency, metrics recording

**TokenService** (7 test suites, 126 total tests):
- **Lifecycle Management Tests** (20 tests):
  - Start: idempotency, logging, background cleanup, failure handling, context cancellation
  - Shutdown: logging, cleanup termination, goroutine coordination, timeout respect, idempotency
  - IsRunning: state tracking and thread-safety verification
  - Complete Lifecycle: integration test of start → use → shutdown cycle
- **Token Issuance Tests**:
  - IssueAccessToken / IssueAccessTokenWithClaims: successful issuance, custom claims, reserved claim protection, guard conditions
  - IssueRefreshToken: successful issuance, storage, metadata handling, guard conditions
  - IssueTokenPair: coordinated access and refresh token issuance, guard conditions
- **Validation & Refresh Tests**:
  - ValidateAccessToken: signature verification, claims extraction, expiration, audience/issuer enforcement, wrong signing method, missing kid header, guard conditions
  - RefreshAccessToken: token rotation, revocation checks, expiration handling, error propagation, guard conditions
- **Revocation & Introspection Tests**:
  - RevokeRefreshToken / RevokeAllUserTokens: single and bulk revocation flows
  - IntrospectToken: active/inactive/revoked/expired status per RFC 7662
  - CleanupExpiredTokens: manual sweep with error handling
- **Concurrent Operations**: parallel token issuance and service state safety

**RefreshStore** (170 total tests: 51 MemoryRefreshStore + 51 RedisRefreshStore + shared test suite):
- **Shared Test Suite** (51 tests, runs against both Memory and Redis):
  - **Phase 1**: Constructor initialization
  - **Phase 2**: Happy paths (Store, Retrieve) with metadata preservation
  - **Phase 3**: Input validation (empty/whitespace tokenID/userID, expired tokens, metadata defensive copy)
  - **Phase 4**: Defensive programming (metadata isolation between calls, defensive copying)
  - **Phase 5**: Retrieve validation and state checks (revocation, expiration)
  - **Phase 6**: Revoke idempotency and state-changing operations
  - **Phase 7**: RevokeAllForUser bulk operations with user isolation
  - **Phase 8**: Cleanup (expired token removal, mixed expiration states)
  - **Phase 8.5**: Edge cases (unicode characters, large-scale operations, far-future timestamps)
  - **Phase 9**: Context cancellation handling across all operations
- **Test Suite Architecture**: Single parameterized suite eliminates 800+ lines of duplication, ensures both implementations have identical semantics

**Test Organization**:
- Separate test files for logical concerns (`service_test.go`, `service_lifecycle_test.go`)
- Ginkgo/Gomega BDD-style test organization
- gomock for dependency injection testing
- Shared test utilities and fixtures

**All tests pass with race detection**:
```bash
go test -race ./...
# or
ginkgo -race ./...
```

### Running Tests

```bash
# Standard Go test runner
go test -v -race ./...

# With Ginkgo (BDD-style output)
go install github.com/onsi/ginkgo/v2/ginkgo@latest
ginkgo -v -race ./...

# Specific package
go test -v -race ./pkg/keymanager
```

### Test Philosophy

Tests follow **progressive phase-based development**:
1. Constructor → Start → Operations → Shutdown (incremental validation)
2. Organized by concern (not chronology) for clarity
3. Shared test utilities in `internal/testutil` (MockLogger, etc.)
4. Race detection on all tests (catches concurrency bugs)

## Why This Library?

### vs. golang-jwt/jwt

**golang-jwt/jwt** focuses on token operations (create/validate). **jwtauth** provides:
- ✅ Complete lifecycle management (key rotation, persistence)
- ✅ Zero-downtime operations (overlap periods)
- ✅ Production observability (structured logging, metrics)
- ✅ Clean architecture (SOLID principles, dependency inversion)

### vs. lestrrat-go/jwx

**lestrrat-go/jwx** is comprehensive but complex. **jwtauth** provides:
- ✅ Simpler API focused on common use cases
- ✅ Built-in key rotation and management
- ✅ Observability as a first-class feature
- ✅ Clear separation of concerns (KeyManager, TokenService, Storage)

### Unique Features

1. **Zero-downtime key rotation** - Most libraries require service restart
2. **Observability-first design** - Structured logging and metrics built into every operation
3. **Dependency inversion** - Bring your own logger/metrics, no forced dependencies
4. **Distributed token storage** - Memory for testing, Redis for production (multi-instance)
5. **Production patterns** - Graceful shutdown, persistence, error recovery, defensive copying
6. **SOLID architecture** - Easy to test, extend, and maintain

## Roadmap

### v0.1.0 (Current - Pre-Alpha)
- ✅ KeyManager fully implemented
- ✅ Logging abstraction and slog adapter
- ✅ Metrics interface defined
- ✅ Comprehensive test coverage with race detection
- ✅ Architecture documentation

### v0.2.0 (Current - Beta)
- ✅ TokenService: JWT creation with RS256 signing
- ✅ TokenService: Lifecycle management (Start/Shutdown/IsRunning)
- ✅ TokenService: Claims management with custom claims support and reserved claim protection
- ✅ TokenService: Access token validation with issuer/audience enforcement (ValidateAccessToken)
- ✅ TokenService: Refresh token rotation with expiration and revocation checks (RefreshAccessToken)
- ✅ TokenService: Token revocation — single and bulk (RevokeRefreshToken, RevokeAllUserTokens)
- ✅ TokenService: Token introspection per RFC 7662 (IntrospectToken)
- ✅ TokenService: Manual cleanup sweep (CleanupExpiredTokens)
- ✅ TokenService: Comprehensive test coverage (126 tests, ~87% statement coverage, all passing with race detection)
- ✅ RefreshStore: Shared test suite pattern (51 tests, eliminates duplication, runs against all implementations)
- ✅ RefreshStore: MemoryRefreshStore with defensive copying and concurrent safety
- ✅ RefreshStore: RedisRefreshStore for distributed deployments with go-redis/v9
- ✅ RefreshStore: Comprehensive test coverage (170 tests across 9 phases, 100% statement coverage, race-detection clean)
- ✅ Prometheus metrics adapter (`metrics.NewPrometheusMetrics`) with pre-registered jwtauth metrics, 100% test coverage
- ✅ KeyStore interface extracted from KeyManager — `DiskKeyStore` for single-instance, interface seam for distributed backends
- ✅ Wire metrics into KeyManager (DiskKeyStore operations via `jwtauth_keystore_*` metrics)
- 🚧 Wire metrics into TokenService and RefreshStore

### v0.3.0 (Beta)
- 🚧 Wire Prometheus metrics into all components
- 🚧 StatsD and CloudWatch metrics adapters
- 🚧 Example applications

### v1.0.0 (Stable)
- API stability guarantee
- Production-ready for all components
- Comprehensive documentation
- OpenTelemetry integration
- Performance benchmarks

## Architecture

This library follows SOLID principles and clean architecture patterns. For detailed design decisions, dependency inversion patterns, and component architecture, see:

📖 **[ARCHITECTURE.md](doc/ARCHITECTURE.md)** - Comprehensive architecture documentation

**Key architectural highlights**:
- Dependency Inversion Principle (components depend on abstractions)
- Single Responsibility (each package has one clear purpose)
- Interface Segregation (small, focused interfaces)
- Strategy Pattern (swap implementations via interfaces)
- Template Method (consistent patterns across components)

## Rate Limiting

`jwtauth` does not provide rate limiting. Rate limiting is a deployment concern — the right layer depends on your environment, scale, and infrastructure.

**Recommended approach: API Gateway (distributed deployments)**

Enforce rate limits at the API Gateway before requests reach your service. This is the only approach that works correctly across multiple instances:

- **Kong**: `rate-limiting` plugin, configurable per route
- **AWS API Gateway**: `ThrottlingRateLimit` / `ThrottlingBurstLimit` per method
- **Kubernetes Ingress (NGINX)**: `nginx.ingress.kubernetes.io/limit-rps` annotation
- **Cloudflare**: Zone-level rate limiting rules

**Alternative: Application-Level Rate Limiting**

If you prefer application-level rate limiting (outside jwtauth), several well-maintained Go libraries exist:

- [`golang.org/x/time/rate`](https://pkg.go.dev/golang.org/x/time/rate) — standard library token bucket
- [`github.com/ulule/limiter`](https://github.com/ulule/limiter) — Redis-backed, works across instances
- [`github.com/throttled/throttled`](https://github.com/throttled/throttled) — flexible, GCRA algorithm

See [doc/DEPLOYMENT.md](doc/DEPLOYMENT.md) for architecture guidance and configuration examples.

## Contributing

Contributions welcome! This library follows strict quality standards:

**Requirements**:
- ✅ All code must have tests
- ✅ Tests must pass with race detector (`-race` flag)
- ✅ Coverage >80% for critical paths
- ✅ Follow existing architecture patterns (see ARCHITECTURE.md)
- ✅ Use Ginkgo/Gomega for BDD-style tests
- ✅ Update documentation for new features

**Development workflow**:
```bash
# Clone and setup
git clone https://github.com/aetomala/jwtauth.git
cd jwtauth

# Run tests
ginkgo -v -race ./...

# Check for issues
go vet ./...
```

See [ARCHITECTURE.md](doc/ARCHITECTURE.md) for contribution guidelines and architectural patterns.

## Requirements

- **Go 1.21+**
- No external dependencies for core functionality
- Optional: Ginkgo/Gomega for running tests

## License

MIT License - see [LICENSE](LICENSE) for details

## Support

- 📖 **Documentation**: [doc/ARCHITECTURE.md](doc/ARCHITECTURE.md)
- 🐛 **Issues**: [GitHub Issues](https://github.com/aetomala/jwtauth/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/aetomala/jwtauth/discussions)

## Background

Built by a Senior Platform Engineer with 28 years of experience in distributed systems. This library represents production-grade patterns learned from building authentication systems at scale, with a focus on operational excellence, observability, and maintainability.

**Design Philosophy**: Software should be observable, testable, and maintainable. Good architecture makes these properties natural, not afterthoughts.

---

**Status**: Beta (Active Development)
**Version**: 0.2.0-beta
**Components**: KeyManager ✅ | TokenService (Beta) 🟡 | RefreshStore (Memory + Redis) ✅ | Metrics (Prometheus) ✅
**Test Coverage**: 472 tests (KeyManager ~90%, TokenService ~87%, RefreshStore 100%, Metrics 100%, Logging 100%), all passing, race-detection enabled
**Last Updated**: April 6, 2026