// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

// Generate mock from this interface using mockgen
//go:generate mockgen -source=interface.go -destination=../../internal/testutil/mock_metrics.go -package=testutil -mock_names=Metrics=MockMetrics

// Package metrics provides interfaces and implementations for recording application metrics.
// This package supports multiple metrics backends while maintaining a consistent interface
// across all components.
package metrics

import "time"

// Metrics defines the interface for recording application metrics.
// All implementations must be thread-safe as they will be called concurrently
// from multiple goroutines.
//
// The interface supports four types of metrics:
//   - Counters: Monotonically increasing values (e.g., total requests, errors)
//   - Gauges: Point-in-time values that can go up or down (e.g., active connections, queue size)
//   - Histograms: Distribution of values (e.g., request latencies, response sizes)
//   - Durations: Convenience wrapper for recording time-based histograms
type Metrics interface {
	// IncrementCounter increments a counter metric by 1.
	// Counters are monotonically increasing values used for counting events.
	//
	// Example:
	//   metrics.IncrementCounter("jwtauth_tokens_issued_total", map[string]string{
	//       "status": "success",
	//   })
	IncrementCounter(name string, labels map[string]string)

	// AddCounter increments a counter metric by the given value.
	// The value should be positive. Use this when you need to increment by more than 1.
	//
	// Example:
	//   metrics.AddCounter("jwtauth_tokens_processed_total", 10, map[string]string{
	//       "batch_id": "batch_123",
	//   })
	AddCounter(name string, value float64, labels map[string]string)

	// SetGauge sets a gauge metric to the given value.
	// Gauges represent point-in-time values that can increase or decrease.
	//
	// Example:
	//   metrics.SetGauge("jwtauth_active_tokens", 150, map[string]string{
	//       "storage_backend": "redis",
	//   })
	SetGauge(name string, value float64, labels map[string]string)

	// RecordHistogram records a value in a histogram metric.
	// Histograms track the distribution of values, typically used for sizes or counts.
	//
	// Example:
	//   metrics.RecordHistogram("jwtauth_token_size_bytes", 1024, map[string]string{
	//       "token_type": "access",
	//   })
	RecordHistogram(name string, value float64, labels map[string]string)

	// RecordDuration records a duration in a histogram metric.
	// This is a convenience method for recording latencies. The duration is automatically
	// converted to seconds (as a float64) before being recorded in the histogram.
	//
	// Example:
	//   start := time.Now()
	//   // ... operation ...
	//   metrics.RecordDuration("jwtauth_operation_duration_seconds", time.Since(start), map[string]string{
	//       "operation": "validate",
	//   })
	RecordDuration(name string, duration time.Duration, labels map[string]string)
}
