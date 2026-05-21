// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package tracing

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// OtelTracer is a Tracer implementation backed by the OpenTelemetry SDK, suitable for
// production use with any OTel-compatible backend (Jaeger, Zipkin, OTLP, etc.).
// It delegates to the global OTel provider configured by the caller. All methods are safe for concurrent use.
type OtelTracer struct {
	tracer trace.Tracer // underlying OTel tracer from the global provider
}

// OtelSpan is a Span implementation wrapping an OpenTelemetry trace.Span.
// All methods are safe for concurrent use.
type OtelSpan struct {
	span trace.Span // underlying OTel span
}

// NewOtelTracer creates a new OpenTelemetry tracer.
//
// The serviceName identifies this service in distributed traces and should
// be unique across your system (e.g., "jwtauth-service", "api-gateway").
//
// Requires OpenTelemetry to be configured globally via otel.SetTracerProvider().
// If no provider is set, spans will be no-ops.
//
// Example:
//
//	import (
//	    "go.opentelemetry.io/otel"
//	    "go.opentelemetry.io/otel/exporters/jaeger"
//	    sdktrace "go.opentelemetry.io/otel/sdk/trace"
//	)
//
//	// Setup (typically in main())
//	exporter, _ := jaeger.New(jaeger.WithCollectorEndpoint(...))
//	provider := sdktrace.NewTracerProvider(
//	    sdktrace.WithBatcher(exporter),
//	)
//	otel.SetTracerProvider(provider)
//
//	// Create tracer
//	tracer := tracing.NewOtelTracer("jwtauth")
//	service, _ := tokens.NewService(tokens.ServiceConfig{
//	    Tracer: tracer,
//	    // ...
//	})
func NewOtelTracer(scopeName string) *OtelTracer {
	return &OtelTracer{
		tracer: otel.Tracer(scopeName),
	}
}

// Start creates a new OpenTelemetry span and returns a context containing it.
// All library spans use SpanKindInternal — span kind is not configurable.
func (t *OtelTracer) Start(ctx context.Context, name string) (context.Context, Span) {
	ctx, otelSpan := t.tracer.Start(ctx, name, trace.WithSpanKind(trace.SpanKindInternal))
	return ctx, &OtelSpan{span: otelSpan}
}

// End completes the OpenTelemetry span, recording its duration.
func (s *OtelSpan) End() {
	s.span.End()
}

// SetAttribute adds a key-value attribute to the OpenTelemetry span.
func (s *OtelSpan) SetAttribute(key string, value interface{}) {
	s.span.SetAttributes(toOtelAttribute(key, value))
}

// SetAttributes adds multiple attributes to the OpenTelemetry span.
func (s *OtelSpan) SetAttributes(attrs map[string]interface{}) {
	otelAttrs := make([]attribute.KeyValue, 0, len(attrs))
	for k, v := range attrs {
		otelAttrs = append(otelAttrs, toOtelAttribute(k, v))
	}
	s.span.SetAttributes(otelAttrs...)
}

// RecordError records an error on the OpenTelemetry span and sets its status to Error.
// Does nothing if err is nil.
func (s *OtelSpan) RecordError(err error) {
	if err != nil {
		s.span.RecordError(err)
		s.span.SetStatus(codes.Error, err.Error())
	}
}

// SetStatus maps a StatusCode to the equivalent OpenTelemetry status and applies it to the span.
func (s *OtelSpan) SetStatus(code StatusCode, description string) {
	var otelCode codes.Code
	switch code {
	case StatusError:
		otelCode = codes.Error
	case StatusOK:
		otelCode = codes.Ok
	default:
		otelCode = codes.Unset
	}
	s.span.SetStatus(otelCode, description)
}

// toOtelAttribute converts a key-value pair to an OTel attribute.KeyValue.
// Handles string, int, int64, float64, and bool natively; all other types fall back to fmt.Sprintf.
func toOtelAttribute(key string, value interface{}) attribute.KeyValue {
	switch v := value.(type) {
	case string:
		return attribute.String(key, v)
	case int:
		return attribute.Int(key, v)
	case int64:
		return attribute.Int64(key, v)
	case float64:
		return attribute.Float64(key, v)
	case bool:
		return attribute.Bool(key, v)
	default:
		return attribute.String(key, fmt.Sprintf("%v", v))
	}
}
