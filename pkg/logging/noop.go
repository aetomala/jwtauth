// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package logging

// NoOpLogger is a Logger implementation that discards all log messages.
// Useful for testing when you don't want log output, or as a default
// when no logger is configured.
//
// Example Usage:
//
//	config := keys.KeyManagerConfig{
//	    Logger: &logging.NoOpLogger{}, // Silent operation
//	}
//
// Or simply use nil (components handle nil loggers gracefully):
//
//	config := keys.KeyManagerConfig{
//	    Logger: nil, // No logging
//	}
type NoOpLogger struct{}

// Debug discards the log message.
func (n *NoOpLogger) Debug(msg string, keysAndValues ...interface{}) {}

// Info discards the log message.
func (n *NoOpLogger) Info(msg string, keysAndValues ...interface{}) {}

// Warn discards the log message.
func (n *NoOpLogger) Warn(msg string, keysAndValues ...interface{}) {}

// Error discards the log message.
func (n *NoOpLogger) Error(msg string, keysAndValues ...interface{}) {}

// With returns the receiver unchanged — NoOpLogger discards all output so there
// are no fields to bind.
func (n *NoOpLogger) With(keysAndValues ...interface{}) Logger { return n }
