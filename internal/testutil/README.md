# Test Utilities

Comprehensive mock implementations for testing components that depend on external interfaces. These mocks enable isolated, deterministic testing without external dependencies.

## Available Mocks

| Mock | Purpose | Key Features |
|------|---------|--------------|
| **MockKeyManager** | RSA key operations | Generate/rotate keys, get public keys, JWKS support |
| **MockLogger** | Structured logging | Capture logs, assert on messages, verify fields |
| **MockRateLimiter** | Request throttling | Allow/block behavior, per-identifier state, cost tracking |
| **MockRefreshStore** | Token persistence | Store/retrieve tokens, revocation, expiration handling |

## Quick Start Examples

### MockKeyManager

```go
import "github.com/aetomala/jwtauth/internal/testutil"

mockKM := testutil.NewMockKeyManager()

// Generate a new key pair
mockKM.RotateKeys()

// Configure error behavior
mockKM.SetGetPublicKeyError(testutil.NewMockError("key not found"))

// Verify calls were made
Expect(mockKM.GetCallCount("GetPublicKey")).To(Equal(1))
```

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

### MockRateLimiter

```go
mockRL := testutil.NewMockRateLimiter()

// Allow requests
allowed, err := mockRL.Allow("user-123", 1)
Expect(allowed).To(BeTrue())

// Simulate rate limit exceeded
mockRL.SimulateRateLimitExceeded("user-456")
Expect(mockRL.IsIdentifierBlocked("user-456")).To(BeTrue())

// Verify behavior
Expect(mockRL.GetCallCount("Allow")).To(Equal(1))
```

### MockRefreshStore

```go
mockStore := testutil.NewMockRefreshStore()

// Store token
err := mockStore.Store("token-123", "user-456", time.Now().Add(24*time.Hour), nil)
Expect(err).NotTo(HaveOccurred())

// Retrieve token
token, err := mockStore.Retrieve("token-123")
Expect(token.UserID).To(Equal("user-456"))

// Revoke token
mockStore.Revoke("token-123")
Expect(mockStore.IsTokenRevoked("token-123")).To(BeTrue())
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

### Verify Call Arguments

```go
mockKM.GetPublicKey("key-1")
mockKM.GetPublicKey("key-2")
Expect(mockKM.WasPublicKeyRequested("key-1")).To(BeTrue())
```

### Assert Log Fields

```go
log := mockLogger.GetLogWithField("info", "operation complete", "duration")
Expect(log).NotTo(BeNil())
duration := log.Fields["duration"].(time.Duration)
Expect(duration).To(BeNumerically(">", 0))
```

### Track Per-User State

```go
mockRL.Allow("alice", 5)
mockRL.Allow("bob", 3)
Expect(mockRL.GetIdentifierCallCount("alice")).To(Equal(1))
Expect(mockRL.GetTotalCost("alice")).To(Equal(5))
```

## API Reference

For complete API documentation, see the docstrings in:
- [mock_keymanager.go](./mock_keymanager.go)
- [mock_logger.go](./mock_logger.go)
- [mock_ratelimiter.go](./mock_ratelimiter.go)
- [mock_refreshstore.go](./mock_refreshstore.go)

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
        mockKM  *testutil.MockKeyManager
        mockLog *testutil.MockLogger
    )

    BeforeEach(func() {
        mockKM = testutil.NewMockKeyManager()
        mockLog = testutil.NewMockLogger()
    })

    Describe("initialization", func() {
        It("should load current key on startup", func() {
            component := myapp.New(myapp.Config{
                KeyManager: mockKM,
                Logger:     mockLog,
            })

            Expect(mockLog.HasLog("info", "loaded current key")).To(BeTrue())
        })
    })
})
```
