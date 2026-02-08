package logging

import (
	"log/slog"
	"os"
)

// SlogAdapter adapts Go's standard library log/slog to the Logger interface.
// This is the recommended logger for production use as it has no external
// dependencies and performs well.
//
// Example Usage (JSON for production/Kubernetes):
//
//	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
//	    Level: slog.LevelInfo,
//	})
//	logger := logging.NewSlogAdapter(slog.New(handler))
//
//	config := keymanager.ManagerConfig{
//	    Logger: logger,
//	}
//
// Example Usage (Text for development):
//
//	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
//	    Level: slog.LevelInfo,
//	})
//	logger := logging.NewSlogAdapter(slog.New(handler))
//
// JSON output (for log aggregators like ELK, Loki):
//
//	{"time":"2025-01-07T10:30:00Z","level":"INFO","msg":"key rotation successful","keyID":"abc-123"}
//
// Text output (human-readable for development):
//
//	time=2025-01-07T10:30:00.000Z level=INFO msg="key rotation successful" keyID=abc-123
type SlogAdapter struct {
	logger *slog.Logger
}

// NewSlogAdapter creates a new Logger that wraps slog.Logger.
//
// Example:
//
//	slogger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
//	logger := logging.NewSlogAdapter(slogger)
func NewSlogAdapter(logger *slog.Logger) *SlogAdapter {
	return &SlogAdapter{logger: logger}
}

// Info logs an informational message with structured key-value pairs.
func (s *SlogAdapter) Info(msg string, keysAndValues ...interface{}) {
	s.logger.Info(msg, keysAndValues...)
}

// Warn logs a warning message with structured key-value pairs.
func (s *SlogAdapter) Warn(msg string, keysAndValues ...interface{}) {
	s.logger.Warn(msg, keysAndValues...)
}

// Error logs an error message with structured key-value pairs.
func (s *SlogAdapter) Error(msg string, keysAndValues ...interface{}) {
	s.logger.Error(msg, keysAndValues...)
}

// Helper functions for common slog configurations

// NewJSONLogger creates a production-ready JSON logger that writes to stdout.
// Suitable for Kubernetes deployments where logs are collected by log aggregators.
//
// Example:
//
//	logger := logging.NewJSONLogger(slog.LevelInfo)
//	// Output: {"time":"...","level":"INFO","msg":"...","key":"value"}
func NewJSONLogger(level slog.Level) *SlogAdapter {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})
	return NewSlogAdapter(slog.New(handler))
}

// NewTextLogger creates a development-friendly text logger that writes to stdout.
// Suitable for local development and debugging.
//
// Example:
//
//	logger := logging.NewTextLogger(slog.LevelInfo)
//	// Output: time=... level=INFO msg=... key=value
func NewTextLogger(level slog.Level) *SlogAdapter {
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})
	return NewSlogAdapter(slog.New(handler))
}
