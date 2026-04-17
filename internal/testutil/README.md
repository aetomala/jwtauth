# Test Utilities

Mock implementations for testing components that depend on external interfaces. All auto-generated mocks use gomock's record/replay pattern; `MockLogger` is a hand-written capture implementation.

## Available Mocks

| Mock | Source interface | File | Generation |
|------|-----------------|------|------------|
| **MockKeyManager** | `keymanager.KeyManager` | mock_keymanager.go | Auto-generated (mockgen) |
| **MockKeyStore** | `keymanager.KeyStore` | mock_keystore.go | Auto-generated (mockgen) |
| **MockRefreshStore** | `storage.RefreshStore` | mock_refreshstore.go | Auto-generated (mockgen) |
| **MockMetrics** | `metrics.Metrics` | mock_metrics.go | Auto-generated (mockgen) |
| **MockLogger** | `logging.Logger` | mock_logger.go | Custom implementation |

Shared error helpers live in `errors.go`.

## Quick Start

### Auto-generated mocks (MockKeyManager, MockKeyStore, MockRefreshStore, MockMetrics)

```go
ctrl := gomock.NewController(GinkgoT())
defer ctrl.Finish()

mockKM := testutil.NewMockKeyManager(ctrl)

// Expect a call and specify the return value
mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(privateKey, "key-1", nil)

// Expect a call that should not happen — omit EXPECT entirely;
// any unexpected call causes the test to fail automatically.

// Expect a call any number of times
mockKM.EXPECT().Start(gomock.Any()).Return(nil).AnyTimes()
```

### MockLogger

```go
mockLog := testutil.NewMockLogger()

// Pass to the component under test
mgr := myapp.NewManager(myapp.Config{Logger: mockLog})

// Assert on captured output
Expect(mockLog.HasLog("info", "manager started")).To(BeTrue())
Expect(mockLog.HasLogWithField("warn", "token expired", "tokenID")).To(BeTrue())
Expect(mockLog.CountLogs("error")).To(Equal(0))

// Clear between phases
mockLog.Clear()
```

### MockMetrics

```go
ctrl := gomock.NewController(GinkgoT())
mockM := testutil.NewMockMetrics(ctrl)

mockM.EXPECT().IncrementCounter("jwtauth_tokens_issued_total", map[string]string{
    "status":     "success",
    "error_type": "",
})
mockM.EXPECT().RecordDuration("jwtauth_operation_duration_seconds", gomock.Any(), map[string]string{
    "operation": "issue_access_token",
})

// Use gomock.Any() for duration values — exact timing is non-deterministic.
// Use exact label maps — label correctness is what the test verifies.
```

### MockKeyStore

```go
ctrl := gomock.NewController(GinkgoT())
mockKS := testutil.NewMockKeyStore(ctrl)

mockKS.EXPECT().LoadAll(gomock.Any()).Return([]*keymanager.StoredKey{}, nil)
mockKS.EXPECT().Save(gomock.Any(), "key-1", gomock.Any(), gomock.Any()).Return(nil)
```

### MockRefreshStore

```go
ctrl := gomock.NewController(GinkgoT())
mockStore := testutil.NewMockRefreshStore(ctrl)

mockStore.EXPECT().
    Store(gomock.Any(), "token-abc", "user-1", gomock.Any(), gomock.Any()).
    Return(nil)

mockStore.EXPECT().
    Retrieve(gomock.Any(), "token-abc").
    Return(&storage.RefreshToken{UserID: "user-1", ExpiresAt: time.Now().Add(time.Hour)}, nil)
```

## Error Helpers (`errors.go`)

```go
// Simple sentinel error
err := testutil.NewMockError("database offline")

// Wrapped error with context
wrapped := testutil.NewMockErrorWithContext("operation failed", err)
```

## Regenerating Auto-generated Mocks

```bash
go generate ./...
```

Each mock file contains the exact `mockgen` command used to generate it in its header comment.

## Files

- **[mock_keymanager.go](./mock_keymanager.go)** — `KeyManager` interface (key signing, rotation, lifecycle)
- **[mock_keystore.go](./mock_keystore.go)** — `KeyStore` interface (key persistence: LoadAll, Save, UpdateMetadata, LoadKey, Delete)
- **[mock_refreshstore.go](./mock_refreshstore.go)** — `RefreshStore` interface (token persistence: Store, Retrieve, Revoke, Cleanup)
- **[mock_metrics.go](./mock_metrics.go)** — `Metrics` interface (counters, gauges, histograms, durations)
- **[mock_logger.go](./mock_logger.go)** — custom `Logger` capture implementation
- **[errors.go](./errors.go)** — `MockError` and `MockErrorWithContext` test error types
