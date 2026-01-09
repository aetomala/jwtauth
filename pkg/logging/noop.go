package logging

// NoOpLogger is a Logger implementation that discards all log messages.
// Useful for testing when you don't want log output, or as a default
// when no logger is configured.
//
// Example Usage:
//
//	config := keymanager.ManagerConfig{
//	    Logger: &logging.NoOpLogger{}, // Silent operation
//	}
//
// Or simply use nil (components handle nil loggers gracefully):
//
//	config := keymanager.ManagerConfig{
//	    Logger: nil, // No logging
//	}
type NoOpLogger struct{}

// Info discards the log message.
func (n *NoOpLogger) Info(msg string, keysAndValues ...interface{}) {}

// Warn discards the log message.
func (n *NoOpLogger) Warn(msg string, keysAndValues ...interface{}) {}

// Error discards the log message.
func (n *NoOpLogger) Error(msg string, keysAndValues ...interface{}) {}
