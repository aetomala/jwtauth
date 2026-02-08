# jwtauth

**Production-ready JWT authentication library for distributed Go applications**

> ⚠️ **Pre-Alpha Status**: KeyManager component is production-ready and fully tested. TokenService, Middleware, and other components are under active development. API may change before v1.0.0 release.

## Overview

`jwtauth` is a JWT authentication library built from the ground up with **observability, testability, and production operations** as first-class concerns. Unlike traditional JWT libraries that focus solely on token operations, jwtauth provides complete lifecycle management including zero-downtime key rotation, structured logging, metrics integration, and graceful shutdown patterns.

### Design Philosophy

- **Dependency Inversion**: All components depend on interfaces, not concrete implementations
- **Observability-First**: Structured logging and metrics built into every operation
- **Production-Ready**: Graceful shutdown, persistence, concurrent operations, comprehensive error handling
- **SOLID Principles**: Clean architecture that's easy to test, extend, and maintain
- **Zero External Dependencies**: Core functionality uses only Go standard library

## Key Features

### ✅ Currently Available (KeyManager)

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

### 🚧 In Development

- **TokenService**: JWT creation, validation, and claims management
- **HTTP Middleware**: Request authentication and user context injection
- **Refresh Token Storage**: Memory and Redis implementations
- **Rate Limiting**: Token bucket algorithm with per-user/IP limits
- **Metrics Implementations**: Prometheus, StatsD, CloudWatch adapters
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
# Not yet available - pre-alpha
# Will be available as:
go get github.com/aetomala/jwtauth
```

**Current Status**: Pre-alpha development. Not recommended for production use until v1.0.0 release.

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
│   ├── tokens/                   # JWT operations 🚧
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

**Current**: 3 comprehensive test suites covering KeyManager

**Test Organization**:
- Constructor validation and defaults
- Lifecycle management (Start/Stop/Shutdown)
- Core operations (key generation, rotation, retrieval)
- JWKS endpoint data generation
- Manual and automatic rotation
- Persistence (load/save from disk)
- Concurrency and race conditions
- Graceful shutdown with in-flight operations
- Logging integration and verification

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

### v0.2.0 (Next - Alpha)
- 🚧 TokenService implementation
- 🚧 JWT creation and validation
- 🚧 Claims management
- 🚧 Integration tests with KeyManager
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

**Status**: Pre-Alpha (Active Development)  
**Version**: 0.1.0-pre-alpha  
**Last Updated**: February 2026