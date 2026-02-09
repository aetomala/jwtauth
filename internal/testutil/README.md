# Test Utilities

Comprehensive mock implementations for testing components that depend on external interfaces. These mocks enable isolated, deterministic testing without external dependencies.

## Available Mocks

| Mock | Purpose | Type | Key Features |
|------|---------|------|--------------|
| **MockKeyManager** | RSA key operations | Auto-generated (gomock) | EXPECT() pattern, call verification, error injection |
| **MockRateLimiter** | Request throttling | Auto-generated (gomock) | EXPECT() pattern, call verification, error injection |
| **MockLogger** | Structured logging | Custom implementation | Capture logs, assert on messages, verify fields |
| **MockRefreshStore** | Token persistence | Auto-generated (gomock) | EXPECT() pattern, call verification, error injection |

### Mock Types

- **Auto-generated (gomock)**: `MockKeyManager`, `MockRateLimiter`, and `MockRefreshStore` are generated from their respective interfaces using mockgen. They use the record/replay pattern with `EXPECT()`.
- **Custom implementations**: `MockLogger` and error types (`MockError`, `MockErrorWithContext` in errors.go) are hand-written test utilities with special behaviors for specific testing scenarios.

## Quick Start Examples

### MockKeyManager (Auto-generated with gomock)

```go
import (
	"crypto/rsa"

	"github.com/aetomala/jwtauth/internal/testutil"
	"go.uber.org/mock/gomock"
)

ctrl := gomock.NewController(t)
mockKM := testutil.NewMockKeyManager(ctrl)

// Set up expectations for method calls
mockKM.EXPECT().
	GetCurrentSigningKey().
	Return(privateKey, "test-key-id", nil).
	Times(1)

// Set up error behavior
mockKM.EXPECT().
	GetPublicKey("invalid-key").
	Return(nil, errors.New("key not found")).
	Times(1)

// Execute code under test that uses mockKM
// Assertions are automatic - gomock verifies expectations after test
```

**Note**: `MockKeyManager` is auto-generated from the `KeyManager` interface using mockgen. It uses gomock's record/replay pattern. See [gomock documentation](https://github.com/golang/mock) for detailed usage patterns.

### MockLogger

```go
mockLogger := testutil.NewMockLogger()

// Use in component under test
component := myapp.NewComponent(myapp.Config{
    Logger: mockLogger,
})

// Verify logs
Expect(mockLogger.HasLog("info", "component started")).To(BeTrue())
Expect(mockLogger.HasLogWithField("info", "request processed", "requestID")).To(BeTrue())

// Check log count
Expect(mockLogger.CountLogs("error")).To(Equal(0))
```

### MockRateLimiter (Auto-generated with gomock)

```go
import (
	"github.com/aetomala/jwtauth/internal/testutil"
	"go.uber.org/mock/gomock"
)

ctrl := gomock.NewController(t)
mockRL := testutil.NewMockRateLimiter(ctrl)

// Set up expectations
mockRL.EXPECT().
	Allow("user-123", 1).
	Return(true, nil).
	Times(1)

mockRL.EXPECT().
	Allow("user-456", 1).
	Return(false, errors.New("rate limit exceeded")).
	Times(1)

// Code under test uses mockRL
// Assertions are verified automatically by gomock
```

### MockRefreshStore (Auto-generated with gomock)

```go
import (
	"github.com/aetomala/jwtauth/internal/testutil"
	"go.uber.org/mock/gomock"
)

ctrl := gomock.NewController(t)
mockStore := testutil.NewMockRefreshStore(ctrl)

// Set up expectations
mockStore.EXPECT().
	Store("token-123", "user-456", gomock.Any(), nil).
	Return(nil).
	Times(1)

mockStore.EXPECT().
	Retrieve("token-123").
	Return(&ratelimit.RefreshToken{UserID: "user-456"}, nil).
	Times(1)

// Code under test uses mockStore
// Assertions are verified automatically by gomock
```

## Key Features

### Thread Safety

All mocks are **thread-safe** and can be used in concurrent tests:

```go
var wg sync.WaitGroup
for i := 0; i < 10; i++ {
    wg.Add(1)
    go func() {
        defer wg.Done()
        mockRL.Allow("concurrent-user", 1)
    }()
}
wg.Wait()
Expect(mockRL.GetCallCount("Allow")).To(Equal(10))
```

### Error Injection

Configure mocks to return errors for testing error handling:

```go
// Logger
mockLogger.Disable()  // Stop recording logs

// RateLimiter
mockRL.SetAllowError(testutil.NewMockError("rate limit service down"))

// RefreshStore
mockStore.SetStoreError(testutil.NewMockError("database offline"))
```

### State Reset

Reset mocks between test phases:

```go
mockKM.Reset()              // Reset all call counters
mockLogger.Clear()          // Clear all recorded logs
mockRL.ResetCounters()      // Reset call counts
mockRL.ResetState()         // Reset per-identifier state
mockStore.Reset()           // Reset entire store state
```

## Error Types

Custom error types for testing:

```go
// Create mock error
err := testutil.NewMockError("custom error message")

// Check error type
if testutil.IsMockError(err) {
    // Handle mock error
}

// Wrap with context
wrapped := testutil.WrapMockError(err, "operation context")
```

## Testing Patterns

### MockKeyManager - Verify Expected Calls (gomock)

```go
ctrl := gomock.NewController(t)
mockKM := testutil.NewMockKeyManager(ctrl)

// Set up expectations
mockKM.EXPECT().
	GetPublicKey("key-1").
	Return(&rsaPublicKey1, nil)

mockKM.EXPECT().
	GetPublicKey("key-2").
	Return(&rsaPublicKey2, nil)

// Code under test calls these methods
myComponent.GetKeys(mockKM)

// Assertions are verified automatically by gomock
```

### Assert Log Fields

```go
log := mockLogger.GetLogWithField("info", "operation complete", "duration")
Expect(log).NotTo(BeNil())
duration := log.Fields["duration"].(time.Duration)
Expect(duration).To(BeNumerically(">", 0))
```

### Verify Multiple Calls (gomock)

```go
ctrl := gomock.NewController(t)
mockRL := testutil.NewMockRateLimiter(ctrl)

// Set up expectations for multiple calls
mockRL.EXPECT().
	Allow("alice", 5).
	Return(true, nil).
	Times(1)

mockRL.EXPECT().
	Allow("bob", 3).
	Return(true, nil).
	Times(1)

// Code under test makes these calls
myComponent.CheckRateLimit(mockRL)

// Assertions verified automatically by gomock
```

## API Reference

### Auto-generated Mocks (gomock)

Auto-generated from interface definitions using mockgen. See [gomock documentation](https://github.com/golang/mock) for detailed usage patterns.

- **[mock_keymanager.go](./mock_keymanager.go)** - Auto-generated from `KeyManager` interface
- **[mock_ratelimiter.go](./mock_ratelimiter.go)** - Auto-generated from `RateLimiter` interface
- **[mock_refreshstore.go](./mock_refreshstore.go)** - Auto-generated from `RefreshStore` interface

### Custom Mock Implementations

For complete API documentation, see the docstrings in:
- **[mock_logger.go](./mock_logger.go)** - Custom implementation for capturing and asserting on structured logs

### Shared Utilities

- **[errors.go](./errors.go)** - `MockError` and `MockErrorWithContext` for test error handling
- **[README.md](./README.md)** - This file

## Mock Type Comparison

### Auto-generated Mocks (MockKeyManager, MockRateLimiter, MockRefreshStore)

Auto-generated using [mockgen](https://github.com/golang/mock), these mocks use gomock's record/replay pattern:

**Use when:**
- Testing components that depend on an interface
- You want strict call verification
- You need to set up complex call sequences
- Testing interface methods that may change

**API:**
```go
ctrl := gomock.NewController(t)
mock := testutil.NewMockKeyManager(ctrl)

mock.EXPECT().MethodName(args...).Return(values...).Times(n)
```

**Regeneration:**
```bash
go generate ./...
```

### Custom Mocks (MockLogger)

Hand-written implementation with special behavior for logging capture:

**Use when:**
- You need to capture and verify logs from components
- You need custom helper methods for asserting log state
- You need more control over mock behavior than gomock provides

**API:**
```go
mock := testutil.NewMockLogger()
mock.HasLog("info", "message")
mock.HasLogWithField("info", "message", "fieldName")
mock.Clear()
```

---

## Testing Best Practices

1. **Reset between tests** - Use `Reset()` or `Clear()` in `AfterEach`
2. **Configure errors early** - Set error behavior before test execution
3. **Verify behavior, not implementation** - Assert on mock method calls, not internal state
4. **Use concurrent tests** - All mocks support parallel test execution
5. **Document mock configuration** - Comment on why specific mock behavior is configured

## Example Test Suite

```go
var _ = Describe("MyComponent", func() {
    var (
        ctrl    *gomock.Controller
        mockKM  *testutil.MockKeyManager
        mockLog *testutil.MockLogger
    )

    BeforeEach(func() {
        ctrl = gomock.NewController(GinkgoT())
        mockKM = testutil.NewMockKeyManager(ctrl)
        mockLog = testutil.NewMockLogger()
    })

    AfterEach(func() {
        ctrl.Finish()  // Verify all expectations were met
    })

    Describe("key signing", func() {
        It("should retrieve signing key on startup", func() {
            privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

            // Set up expectations
            mockKM.EXPECT().
                GetCurrentSigningKey().
                Return(privateKey, "test-key-id", nil).
                Times(1)

            component := myapp.New(myapp.Config{
                KeyManager: mockKM,
                Logger:     mockLog,
            })

            Expect(mockLog.HasLog("info", "loaded current key")).To(BeTrue())
        })
    })
})
```
