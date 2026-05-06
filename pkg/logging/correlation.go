// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package logging

import "context"

// contextKey is an unexported type for context keys in this package.
// Using a package-local type prevents key collisions with other packages.
type contextKey string

const correlationIDKey contextKey = "correlation_id"

// WithCorrelationID returns a copy of ctx with the given correlation ID attached.
// The ID is later extracted by GetCorrelationID and injected into log records
// by CorrelationIDHandler.
func WithCorrelationID(ctx context.Context, correlationID string) context.Context {
	return context.WithValue(ctx, correlationIDKey, correlationID)
}

// GetCorrelationID extracts the correlation ID from ctx.
// Returns "" if no correlation ID has been set.
func GetCorrelationID(ctx context.Context) string {
	if id, ok := ctx.Value(correlationIDKey).(string); ok {
		return id
	}
	return ""
}
