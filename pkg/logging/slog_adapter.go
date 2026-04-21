package logging

import (
	"context"
	"log/slog"
	"os"
)

// SlogAdapter adapts Go's standard library log/slog to the Logger interface.
// This is the recommended logger for production use as it has no external
// dependencies and performs well.
//
// Context-aware logging: if the first element of keysAndValues is a
// context.Context, the adapter calls the corresponding *Context method on the
// underlying slog.Logger so that any handler wrapping (e.g. CorrelationIDHandler)
// can extract request-scoped values from the context.
//
// Example Usage (JSON for production/Kubernetes):
//
//	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
//	    Level: slog.LevelInfo,
//	})
//	logger := logging.NewSlogAdapter(slog.New(handler))
//
//	config := keys.KeyManagerConfig{
//	    Logger: logger,
//	}
//
// Example Usage (with correlation ID support):
//
//	logger := logging.NewCorrelationJSONLogger(slog.LevelInfo)
//	// In your HTTP handler:
//	ctx = logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-ID"))
//	tokenService.RefreshAccessToken(ctx, refreshToken) // logs include correlation_id
//
// JSON output (for log aggregators like ELK, Loki):
//
//	{"time":"2025-01-07T10:30:00Z","level":"INFO","msg":"key rotation successful","keyID":"abc-123","correlation_id":"req-xyz"}
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

// Debug logs a verbose diagnostic message with structured key-value pairs.
// If the first element of keysAndValues is a context.Context, it is used to
// propagate request-scoped values (e.g. correlation ID) to the handler.
func (s *SlogAdapter) Debug(msg string, keysAndValues ...interface{}) {
	if len(keysAndValues) > 0 {
		if ctx, ok := keysAndValues[0].(context.Context); ok {
			s.logger.DebugContext(ctx, msg, keysAndValues[1:]...)
			return
		}
	}
	s.logger.Debug(msg, keysAndValues...)
}

// Info logs an informational message with structured key-value pairs.
// If the first element of keysAndValues is a context.Context, it is used to
// propagate request-scoped values (e.g. correlation ID) to the handler.
func (s *SlogAdapter) Info(msg string, keysAndValues ...interface{}) {
	if len(keysAndValues) > 0 {
		if ctx, ok := keysAndValues[0].(context.Context); ok {
			s.logger.InfoContext(ctx, msg, keysAndValues[1:]...)
			return
		}
	}
	s.logger.Info(msg, keysAndValues...)
}

// Warn logs a warning message with structured key-value pairs.
// If the first element of keysAndValues is a context.Context, it is used to
// propagate request-scoped values (e.g. correlation ID) to the handler.
func (s *SlogAdapter) Warn(msg string, keysAndValues ...interface{}) {
	if len(keysAndValues) > 0 {
		if ctx, ok := keysAndValues[0].(context.Context); ok {
			s.logger.WarnContext(ctx, msg, keysAndValues[1:]...)
			return
		}
	}
	s.logger.Warn(msg, keysAndValues...)
}

// Error logs an error message with structured key-value pairs.
// If the first element of keysAndValues is a context.Context, it is used to
// propagate request-scoped values (e.g. correlation ID) to the handler.
func (s *SlogAdapter) Error(msg string, keysAndValues ...interface{}) {
	if len(keysAndValues) > 0 {
		if ctx, ok := keysAndValues[0].(context.Context); ok {
			s.logger.ErrorContext(ctx, msg, keysAndValues[1:]...)
			return
		}
	}
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

// NewCorrelationJSONLogger creates a production-ready JSON logger with
// CorrelationIDHandler pre-wired. When component methods pass a context as the
// first logging arg, correlation_id is automatically injected into each record.
//
// Example:
//
//	logger := logging.NewCorrelationJSONLogger(slog.LevelInfo)
//	ctx = logging.WithCorrelationID(r.Context(), r.Header.Get("X-Correlation-ID"))
//	// Output: {"time":"...","level":"INFO","msg":"...","correlation_id":"req-xyz","key":"value"}
func NewCorrelationJSONLogger(level slog.Level) *SlogAdapter {
	inner := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})
	return NewSlogAdapter(slog.New(NewCorrelationIDHandler(inner)))
}

// NewCorrelationTextLogger creates a development-friendly text logger with
// CorrelationIDHandler pre-wired. When component methods pass a context as the
// first logging arg, correlation_id is automatically injected into each record.
//
// Example:
//
//	logger := logging.NewCorrelationTextLogger(slog.LevelDebug)
//	// Output: time=... level=INFO msg=... correlation_id=req-xyz key=value
func NewCorrelationTextLogger(level slog.Level) *SlogAdapter {
	inner := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: level,
	})
	return NewSlogAdapter(slog.New(NewCorrelationIDHandler(inner)))
}
