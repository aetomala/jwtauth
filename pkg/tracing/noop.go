// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package tracing

import "context"

// NoOpTracer is a Tracer implementation that does nothing.
//
// Use this when tracing is disabled to avoid nil checks throughout
// the codebase. All operations are no-ops with zero overhead.
//
// Safe for concurrent use by multiple goroutines.
type NoOpTracer struct{}

// NoOpSpan is a Span implementation that does nothing.
//
// Returned by NoOpTracer.Start(). All operations are no-ops.
type NoOpSpan struct{}

// NewNoOpTracer creates a new no-op tracer.
//
// Example:
//
//	tracer := tracing.NewNoOpTracer()
//	service, _ := tokens.NewService(tokens.ServiceConfig{
//	    Tracer: tracer, // Tracing disabled
//	    // ...
//	})
func NewNoOpTracer() *NoOpTracer {
	return &NoOpTracer{}
}

// Start returns the context unchanged and a no-op span.
//
// The returned span's methods are all no-ops.
func (t *NoOpTracer) Start(ctx context.Context, name string, opts ...SpanOption) (context.Context, Span) {
	return ctx, &NoOpSpan{}
}

// End does nothing.
func (s *NoOpSpan) End() {}

// SetAttribute does nothing.
func (s *NoOpSpan) SetAttribute(key string, value interface{}) {}

// SetAttributes does nothing.
func (s *NoOpSpan) SetAttributes(attrs map[string]interface{}) {}

// RecordError does nothing.
func (s *NoOpSpan) RecordError(err error) {}

// SetStatus does nothing.
func (s *NoOpSpan) SetStatus(code StatusCode, description string) {}
