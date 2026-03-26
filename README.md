# jwtauth

**Production-ready JWT authentication library for distributed Go applications**

> ⚠️ **Beta Status**: KeyManager is production-ready and fully tested. TokenService is in beta — core operations are complete with comprehensive test coverage. Middleware and storage implementations are under active development. API may change before v1.0.0.

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
- **Rate limiting** integration at token issuance boundary
- **Background cleanup goroutines** with configurable interval and proper synchronization
- **Service state management** ensuring tokens only issue when service is running
- **Comprehensive BDD test coverage** (144 tests covering lifecycle, issuance, validation, refresh, revocation, and introspection; 88% statement coverage)

### 🚧 In Development

- **HTTP Middleware**: Request authentication and user context injection
- **Refresh Token Storage**: Memory and Redis implementations (RefreshStore interface ready)
- **Metrics Implementations**: Prometheus, StatsD, CloudWatch adapters
- **OpenTelemetry**: Distributed tracing integration
- **Rate Limiter Implementations**: Token bucket, sliding window, Redis-backed limiters

## Architecture Highlights

### Observability as a Core Design Principle

Every component accepts optional logging and metrics interfaces:

```go
import (
    "github.com/aetomala/jwtauth/pkg/keymanager"
    "github.com/aetomala/jwtauth/pkg/logging"
    "github.com/aetomala/jwtauth/pkg/metrics"
)

config := keymanager.ManagerConfig{
    KeyDirectory:        "/var/keys",
    KeyRotationInterval: 30 * 24 * time.Hour, // 30 days
    KeyOverlapPeriod:    1 * time.Hour,        // 1 hour overlap
    
    // Optional: Bring your own logger
    Logger: logging.NewJSONLogger(slog.LevelInfo),
    
    // Optional: Bring your own metrics (interface defined, impl coming)
    Metrics: nil, // metrics.NewPrometheusMetrics() // Coming soon
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
    Logger  logging.Logger   // Interface, not *slog.Logger
    Metrics metrics.Metrics  // Interface, not *PrometheusMetrics
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
    // Create KeyManager
    config := keymanager.ManagerConfig{
        KeyDirectory:        "./keys",
        KeyRotationInterval: 30 * 24 * time.Hour,
        KeyOverlapPeriod:    1 * time.Hour,
    }
    
    manager, err := keymanager.NewManager(config)
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
    key, err := manager.GetCurrentSigningKey()
    if err != nil {
        log.Fatal(err)
    }
    
    // Use key to sign tokens (TokenService coming soon)
    log.Printf("Current key ID: %s", key.KeyID)
    
    // Get JWKS for token validation
    jwks := manager.GetJWKS()
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
    
    config := keymanager.ManagerConfig{
        KeyDirectory:        "./keys",
        KeyRotationInterval: 30 * 24 * time.Hour,
        KeyOverlapPeriod:    1 * time.Hour,
        Logger:              logger,
        // Metrics: metrics.NewPrometheusMetrics(), // Coming soon
    }
    
    manager, err := keymanager.NewManager(config)
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
    // Create TokenService with rate limiting and storage
    config := tokens.ServiceConfig{
        KeyManager:           keyManager,      // from KeyManager above
        RefreshStore:         refreshStore,    // RefreshStore implementation
        RateLimiter:          rateLimiter,     // RateLimiter implementation
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
- ✅ Rate limiting enforced at token issuance
- ✅ Custom claims support with reserved claim protection
- ✅ Background cleanup of expired refresh tokens
- ✅ Structured logging integration

## Configuration

### ManagerConfig

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `KeyDirectory` | `string` | Yes | - | Directory for key persistence |
| `KeyRotationInterval` | `time.Duration` | Yes | - | How often to rotate keys (e.g., 30 days) |
| `KeyOverlapPeriod` | `time.Duration` | Yes | - | Overlap period for zero-downtime rotation |
| `Logger` | `logging.Logger` | No | `nil` | Optional structured logger |
| `Metrics` | `metrics.Metrics` | No | `nil` | Optional metrics collector |

### Recommended Settings

**Production**:
```go
config := keymanager.ManagerConfig{
    KeyRotationInterval: 30 * 24 * time.Hour,  // 30 days
    KeyOverlapPeriod:    1 * time.Hour,         // 1 hour
    Logger:              logging.NewJSONLogger(slog.LevelInfo),
}
```

**Development**:
```go
config := keymanager.ManagerConfig{
    KeyRotationInterval: 24 * time.Hour,        // 1 day (faster testing)
    KeyOverlapPeriod:    5 * time.Minute,       // 5 minutes
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
    Info(msg string, args ...interface{})
    Warn(msg string, args ...interface{})
    Error(msg string, args ...interface{})
}

// Adapt your existing logger
type MyZapAdapter struct {
    logger *zap.Logger
}

func (m *MyZapAdapter) Info(msg string, args ...interface{}) {
    m.logger.Sugar().Infow(msg, args...)
}
// ... implement Warn, Error
```

### Metrics (Coming Soon)

**Planned interface**:
```go
type Metrics interface {
    RecordRotation(success bool, duration time.Duration)
    RecordKeyGeneration(duration time.Duration)
    RecordSigningOperation(success bool, duration time.Duration)
    RecordValidationOperation(success bool, duration time.Duration)
}
```

**Planned implementations**:
- Prometheus (with `/metrics` endpoint)
- StatsD (for Datadog, Graphite)
- CloudWatch (for AWS environments)

## Project Structure

```
github.com/aetomala/jwtauth/
├── pkg/                          # Public API packages
│   ├── logging/                  # Logging abstraction
│   │   ├── logger.go             # Logger interface (3 methods)
│   │   ├── slog_adapter.go       # Standard library adapter
│   │   └── noop.go               # NoOp implementation
│   ├── metrics/                  # Metrics abstraction
│   │   ├── metrics.go            # Metrics interface
│   │   └── noop.go               # NoOp implementation
│   ├── keymanager/               # Key rotation and management ✅
│   │   ├── manager.go            # Core implementation
│   │   ├── persistence.go        # Disk operations
│   │   └── keymanager_test.go   # Comprehensive tests
│   ├── tokens/                   # JWT operations (Beta) 🟡
│   │   ├── service.go            # TokenService implementation
│   │   ├── service_test.go       # Token operations tests
│   │   ├── service_lifecycle_test.go  # Lifecycle management tests
│   │   └── claims.go             # Claims management
│   ├── middleware/               # HTTP middleware 🚧
│   └── storage/                  # Refresh token storage 🚧
├── internal/                     # Private packages
│   └── testutil/                 # Shared test utilities
├── doc/                          # Documentation
│   └── ARCHITECTURE.md           # Design decisions and patterns
└── examples/                     # Usage examples (coming)
```

## Testing

### Test Coverage

**Current**: 144 comprehensive tests across KeyManager and TokenService, all passing with race detection; 88% statement coverage on TokenService

**KeyManager** (3 test suites):
- Constructor validation and defaults
- Lifecycle management (Start/Stop/Shutdown)
- Core operations (key generation, rotation, retrieval)
- JWKS endpoint data generation
- Manual and automatic rotation
- Persistence (load/save from disk)
- Concurrency and race conditions
- Graceful shutdown with in-flight operations
- Logging integration and verification

**TokenService** (7 test suites, 144 total tests):
- **Lifecycle Management Tests** (20 tests):
  - Start: idempotency, logging, background cleanup, failure handling, context cancellation
  - Shutdown: logging, cleanup termination, goroutine coordination, timeout respect, idempotency
  - IsRunning: state tracking and thread-safety verification
  - Complete Lifecycle: integration test of start → use → shutdown cycle
- **Token Issuance Tests**:
  - IssueAccessToken / IssueAccessTokenWithClaims: successful issuance, rate limiting, custom claims, reserved claim protection, guard conditions
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
- ✅ Clear separation of concerns (KeyManager, TokenService, Middleware)

### Unique Features

1. **Zero-downtime key rotation** - Most libraries require service restart
2. **Observability-first design** - Logging and metrics built into every operation
3. **Dependency inversion** - Bring your own logger/metrics, no forced dependencies
4. **Production patterns** - Graceful shutdown, persistence, error recovery
5. **SOLID architecture** - Easy to test, extend, and maintain

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
- ✅ TokenService: Rate limiting integration
- ✅ TokenService: Claims management with custom claims support and reserved claim protection
- ✅ TokenService: Access token validation with issuer/audience enforcement (ValidateAccessToken)
- ✅ TokenService: Refresh token rotation with expiration and revocation checks (RefreshAccessToken)
- ✅ TokenService: Token revocation — single and bulk (RevokeRefreshToken, RevokeAllUserTokens)
- ✅ TokenService: Token introspection per RFC 7662 (IntrospectToken)
- ✅ TokenService: Manual cleanup sweep (CleanupExpiredTokens)
- ✅ TokenService: Comprehensive test coverage (144 tests, 88% statement coverage, all passing with race detection)
- 🚧 Prometheus metrics adapter

### v0.3.0 (Beta)
- 🚧 HTTP Middleware
- 🚧 Request authentication
- 🚧 User context injection
- 🚧 Example applications

### v0.4.0 (Beta)
- 🚧 Refresh token storage (memory + Redis)
- 🚧 Token revocation
- 🚧 Rate limiting

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
**Components**: KeyManager ✅ | TokenService (Beta) 🟡 | Middleware 🚧
**Test Coverage**: 144 tests, 88% statement coverage, all passing, race-detection enabled
**Last Updated**: March 2026