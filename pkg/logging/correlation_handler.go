// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package logging

import (
	"context"
	"log/slog"
)

// CorrelationIDHandler is a slog.Handler wrapper that injects the correlation_id
// field from context into every log record. It is suitable for production use
// with any slog.Handler backend (JSON, text, custom). All methods are safe for
// concurrent use.
type CorrelationIDHandler struct {
	// handler is the inner slog.Handler that receives the enriched records.
	handler slog.Handler
}

// Compile-time check that CorrelationIDHandler implements slog.Handler.
var _ slog.Handler = (*CorrelationIDHandler)(nil)

// NewCorrelationIDHandler returns a CorrelationIDHandler that wraps h.
// When Handle is called, correlation_id is extracted from the context via
// GetCorrelationID and appended to the record before delegating to h.
// If no correlation ID is present in the context, the field is omitted.
func NewCorrelationIDHandler(h slog.Handler) *CorrelationIDHandler {
	return &CorrelationIDHandler{handler: h}
}

// Enabled reports whether the inner handler is enabled for the given level.
func (h *CorrelationIDHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}

// Handle extracts the correlation_id from ctx and appends it to a clone of r
// before forwarding to the inner handler. If the context carries no correlation
// ID, the record is forwarded unchanged.
func (h *CorrelationIDHandler) Handle(ctx context.Context, r slog.Record) error {
	if id := GetCorrelationID(ctx); id != "" {
		r = r.Clone()
		r.AddAttrs(slog.String("correlation_id", id))
	}
	return h.handler.Handle(ctx, r)
}

// WithAttrs returns a new CorrelationIDHandler whose inner handler has the
// given attributes pre-applied. The returned handler continues to inject
// correlation_id on every record.
func (h *CorrelationIDHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &CorrelationIDHandler{handler: h.handler.WithAttrs(attrs)}
}

// WithGroup returns a new CorrelationIDHandler whose inner handler scopes
// subsequent attributes under the given group name. The returned handler
// continues to inject correlation_id on every record.
func (h *CorrelationIDHandler) WithGroup(name string) slog.Handler {
	return &CorrelationIDHandler{handler: h.handler.WithGroup(name)}
}
