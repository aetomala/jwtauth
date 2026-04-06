package metrics

import "time"

// NoOpMetrics is a Metrics implementation that does nothing.
// Use this when you want to disable metrics collection without changing your code.
// All methods are no-ops and have zero runtime overhead.
//
// Example usage:
//
//	var m metrics.Metrics
//	if metricsEnabled {
//	    m = metrics.NewPrometheusMetrics()
//	} else {
//	    m = metrics.NewNoOpMetrics()
//	}
type NoOpMetrics struct{}

// NewNoOpMetrics creates a new NoOpMetrics instance.
func NewNoOpMetrics() *NoOpMetrics {
	return &NoOpMetrics{}
}

// IncrementCounter does nothing.
func (n *NoOpMetrics) IncrementCounter(name string, labels map[string]string) {}

// AddCounter does nothing.
func (n *NoOpMetrics) AddCounter(name string, value float64, labels map[string]string) {}

// SetGauge does nothing.
func (n *NoOpMetrics) SetGauge(name string, value float64, labels map[string]string) {}

// RecordHistogram does nothing.
func (n *NoOpMetrics) RecordHistogram(name string, value float64, labels map[string]string) {}

// RecordDuration does nothing.
func (n *NoOpMetrics) RecordDuration(name string, duration time.Duration, labels map[string]string) {}
