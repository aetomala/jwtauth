// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

// Package tracing provides distributed tracing abstractions for the JWT authentication system.
//
// All components (KeyManager, TokenService, RefreshStore, KeyStore) accept optional
// tracing interfaces, enabling users to bring their own tracer implementation or disable
// tracing entirely with NoOpTracer.
//
// Design Philosophy:
//   - Simple: Only 2 core interfaces (Tracer + Span)
//   - Flexible: Works with any tracing backend via adapters
//   - Optional: Components work without tracing (nil-safe)
//   - Compatible: Pre-built OpenTelemetry adapter included
//
// Example Usage:
//
//	import (
//	    "github.com/aetomala/jwtauth/pkg/tracing"
//	    "go.opentelemetry.io/otel"
//	)
//
//	// OpenTelemetry
//	tracer := tracing.NewOtelTracer("jwtauth")
//
//	// Or disable tracing
//	tracer := tracing.NewNoOpTracer()
//
//	// Pass to components
//	service, _ := tokens.NewService(tokens.ServiceConfig{
//	    Tracer: tracer,
//	    // ... other config
//	})
//go:generate mockgen -source=interface.go -destination=../../internal/testutil/mock_tracing.go -package=testutil -mock_names=Tracer=MockTracer,Span=MockSpan

package tracing

import (
	"context"
)

// Tracer creates and manages spans for distributed tracing.
//
// Implementations must be safe for concurrent use by multiple goroutines.
type Tracer interface {
	// Start creates a new span from the given context.
	//
	// The returned context contains the new span and should be used for
	// all subsequent operations within this span's scope.
	//
	// The returned Span must be ended by calling span.End() when the
	// operation completes, typically via defer:
	//
	//     ctx, span := tracer.Start(ctx, "operation_name")
	//     defer span.End()
	//
	// SpanOptions can customize span creation (kind, attributes, etc.).
	Start(ctx context.Context, name string, opts ...SpanOption) (context.Context, Span)
}

// Span represents a single operation in a distributed trace.
//
// Spans form a tree structure, with parent-child relationships defined
// by the context passed to Tracer.Start().
//
// A Span is complete once End() is called. Implementations should ignore
// all method calls after End().
type Span interface {
	// End completes the span, recording its duration.
	//
	// Calling End multiple times has no effect.
	// Should typically be called via defer immediately after span creation.
	End()

	// SetAttribute adds a key-value attribute to the span.
	//
	// Attributes provide additional context about the operation.
	// Common examples: user_id, token_id, operation type, etc.
	//
	// The value can be string, int, int64, float64, or bool.
	// Other types are converted to string via fmt.Sprintf.
	SetAttribute(key string, value interface{})

	// SetAttributes adds multiple attributes at once.
	//
	// Equivalent to calling SetAttribute multiple times but may be
	// more efficient in some implementations.
	SetAttributes(attrs map[string]interface{})

	// RecordError records an error that occurred during this span.
	//
	// The span's status is set to Error automatically.
	// Does nothing if err is nil.
	RecordError(err error)

	// SetStatus explicitly sets the span's final status.
	//
	// Most spans should use StatusOK (success) or StatusError (failure).
	// StatusUnset is the default if neither is called.
	//
	// The description provides additional context for error statuses.
	// For StatusOK and StatusUnset, description is typically empty.
	SetStatus(code StatusCode, description string)
}

// StatusCode represents the final status of a span.
type StatusCode int

const (
	// StatusUnset is the default span status.
	// Used when the outcome is not explicitly set.
	StatusUnset StatusCode = iota

	// StatusError indicates the span represents a failed operation.
	// Typically set automatically by RecordError or explicitly via SetStatus.
	StatusError

	// StatusOK indicates the span represents a successful operation.
	// Explicitly set via SetStatus when an operation completes successfully.
	StatusOK
)

// String returns a human-readable representation of the status code.
func (s StatusCode) String() string {
	switch s {
	case StatusOK:
		return "OK"
	case StatusError:
		return "ERROR"
	case StatusUnset:
		return "UNSET"
	default:
		return "UNKNOWN"
	}
}

// SpanOption configures span creation.
//
// Options are applied in order during Tracer.Start().
type SpanOption func(*SpanConfig)

// SpanConfig holds configuration for span creation.
//
// Not typically used directly; configured via SpanOption functions.
type SpanConfig struct {
	// Attributes to add to the span at creation time.
	Attributes map[string]interface{}

	// Kind indicates the span's role in the trace (internal, server, client, etc.).
	Kind SpanKind
}

// SpanKind categorizes a span's role in a trace.
type SpanKind int

const (
	// SpanKindInternal represents an internal operation within a service.
	// Used for operations that don't cross service boundaries.
	// Default kind if not specified.
	SpanKindInternal SpanKind = iota

	// SpanKindServer represents a server handling a request.
	// Used for HTTP handlers, gRPC server methods, message consumers, etc.
	SpanKindServer

	// SpanKindClient represents a client making a request.
	// Used for HTTP clients, gRPC client calls, database queries, etc.
	SpanKindClient

	// SpanKindProducer represents a message producer.
	// Used when sending messages to a queue.
	SpanKindProducer

	// SpanKindConsumer represents a message consumer.
	// Used when receiving messages from a queue.
	SpanKindConsumer
)

// String returns a human-readable representation of the span kind.
func (k SpanKind) String() string {
	switch k {
	case SpanKindInternal:
		return "INTERNAL"
	case SpanKindServer:
		return "SERVER"
	case SpanKindClient:
		return "CLIENT"
	case SpanKindProducer:
		return "PRODUCER"
	case SpanKindConsumer:
		return "CONSUMER"
	default:
		return "UNKNOWN"
	}
}

// WithAttributes adds attributes to the span at creation time.
//
// Example:
//
//	ctx, span := tracer.Start(ctx, "operation",
//	    tracing.WithAttributes(map[string]interface{}{
//	        "user_id": "user-123",
//	        "operation": "token_refresh",
//	    }),
//	)
func WithAttributes(attrs map[string]interface{}) SpanOption {
	return func(c *SpanConfig) {
		if c.Attributes == nil {
			c.Attributes = make(map[string]interface{})
		}
		for k, v := range attrs {
			c.Attributes[k] = v
		}
	}
}

// WithSpanKind sets the span's kind.
//
// Example:
//
//	ctx, span := tracer.Start(ctx, "RefreshAccessToken",
//	    tracing.WithSpanKind(tracing.SpanKindServer),
//	)
func WithSpanKind(kind SpanKind) SpanOption {
	return func(c *SpanConfig) {
		c.Kind = kind
	}
}
