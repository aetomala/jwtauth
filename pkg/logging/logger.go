package logging

// Logger is the standard logging interface for the JWT authentication system.
// All components (KeyManager, TokenService, Middleware, RefreshTokenStore, etc.)
// use this interface for structured logging.
//
// Implementations must support structured logging with key-value pairs where
// keys are strings and values can be any type.
//
// Design Philosophy:
//   - Simple: Only 3 log levels (Info, Warn, Error)
//   - Structured: Key-value pairs for machine-readable logs
//   - Flexible: Works with any logging library via adapters
//   - Optional: Components work without a logger (nil-safe)
//
// Example Usage:
//
//	logger.Info("key rotation successful",
//	    "keyID", "abc-123",
//	    "duration", 150*time.Millisecond,
//	    "oldKeyID", "xyz-789")
//
//	logger.Warn("failed to load key file",
//	    "file", "corrupted.pem",
//	    "error", err)
//
//	logger.Error("rotation failed",
//	    "error", err,
//	    "keyID", keyID)
//
// Standard Implementations:
//   - SlogAdapter: Uses Go's standard library log/slog (Go 1.21+)
//   - NoOpLogger: Discards all logs (useful for testing)
//
// Third-Party Adapters (implement yourself):
//   - Zap: github.com/uber-go/zap
//   - Zerolog: github.com/rs/zerolog
//   - Logrus: github.com/sirupsen/logrus
type Logger interface {
	// Info logs informational messages for normal operations.
	// Use for: successful operations, state changes, important milestones
	//
	// keysAndValues must be alternating keys (string) and values (any type).
	//
	// Example:
	//   Info("manager started", "keyCount", 5, "currentKeyID", id)
	Info(msg string, keysAndValues ...interface{})

	// Warn logs warning messages for recoverable issues.
	// Use for: degraded operation, retries, skipped items, fallback behavior
	//
	// keysAndValues must be alternating keys (string) and values (any type).
	//
	// Example:
	//   Warn("failed to load key file", "file", filename, "error", err)
	Warn(msg string, keysAndValues ...interface{})

	// Error logs error messages for critical failures.
	// Use for: operation failures, unrecoverable errors, system issues
	//
	// keysAndValues must be alternating keys (string) and values (any type).
	//
	// Example:
	//   Error("rotation failed", "error", err, "keyID", keyID)
	Error(msg string, keysAndValues ...interface{})
}

// Ensure interfaces are implemented at compile time
var (
	_ Logger = (*NoOpLogger)(nil)
	_ Logger = (*SlogAdapter)(nil)
)
