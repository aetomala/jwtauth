// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"net/http"
	"sync"
	"time"

	"github.com/aetomala/jwtauth/pkg/logging"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// PrometheusMetrics is a thread-safe implementation of the Metrics interface
// backed by the Prometheus client library. All metrics are pre-registered at
// construction time so naming conflicts are caught early rather than at
// observation time. All methods are safe for concurrent use.
type PrometheusMetrics struct {
	// ===== Observability =====
	registry *prometheus.Registry
	logger   logging.Logger // never nil; defaults to NoOpLogger

	// ===== Counters =====
	counters   map[string]*prometheus.CounterVec
	countersMu sync.RWMutex

	// ===== Gauges =====
	gauges   map[string]*prometheus.GaugeVec
	gaugesMu sync.RWMutex

	// ===== Histograms =====
	histograms   map[string]*prometheus.HistogramVec
	histogramsMu sync.RWMutex

	// ===== Metric Names =====
	names map[string]string // name → help string; written once at construction, read-only after
}

// PrometheusConfig holds configuration for a PrometheusMetrics instance.
// All fields have sensible defaults and may be left at their zero values.
type PrometheusConfig struct {
	Namespace string               // Prepended to all metric names. Defaults to "jwtauth".
	Registry  *prometheus.Registry // Registry to register metrics into. If nil, a new isolated registry is created.
	Logger    logging.Logger       // Optional; nil defaults to NoOpLogger.
}

// NewPrometheusMetrics returns a new PrometheusMetrics with all metrics
// pre-registered. If config.Namespace is empty it defaults to "jwtauth". If
// config.Registry is nil a new isolated registry is created so metrics do not
// collide with the default Prometheus process registry.
func NewPrometheusMetrics(config PrometheusConfig) *PrometheusMetrics {
	// ===== STEP 1: Apply Defaults =====
	if config.Namespace == "" {
		config.Namespace = "jwtauth"
	}
	if config.Registry == nil {
		config.Registry = prometheus.NewRegistry()
	}
	if config.Logger == nil {
		config.Logger = &logging.NoOpLogger{}
	}

	// ===== STEP 2: Construct =====
	pm := &PrometheusMetrics{
		registry:   config.Registry,
		logger:     config.Logger,
		counters:   make(map[string]*prometheus.CounterVec),
		gauges:     make(map[string]*prometheus.GaugeVec),
		histograms: make(map[string]*prometheus.HistogramVec),
		names:      make(map[string]string),
	}

	// ===== STEP 3: Pre-register All Metrics =====
	pm.registerAllMetrics(config.Namespace)
	return pm
}

// registerAllMetrics registers every metric this package exposes, grouped by
// the component that owns each metric.
func (pm *PrometheusMetrics) registerAllMetrics(namespace string) {
	// ===== TokenManager Metrics =====

	pm.registerCounter(namespace, "tokens_issued_total",
		"Total number of tokens issued",
		[]string{"status", "error_type", "namespace"})

	pm.registerCounter(namespace, "tokens_validated_total",
		"Total number of tokens validated",
		[]string{"status", "error_type", "namespace"})

	pm.registerCounter(namespace, "tokens_refreshed_total",
		"Total number of tokens refreshed",
		[]string{"status", "error_type", "namespace"})

	pm.registerCounter(namespace, "tokens_revoked_total",
		"Total number of tokens revoked",
		[]string{"revocation_scope", "status", "namespace"})

	pm.registerCounter(namespace, "tokens_cleanup_total",
		"Total number of cleanup operations",
		[]string{"status", "namespace"})

	pm.registerHistogram(namespace, "operation_duration_seconds",
		"Duration of operations in seconds",
		[]string{"operation", "namespace"},
		[]float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10})

	pm.registerCounter(namespace, "tokens_list_total",
		"Total number of list-tokens operations on the token manager",
		[]string{"scope", "namespace", "error_type"})

	pm.registerHistogram(namespace, "tokens_list_duration_seconds",
		"Duration of list-tokens operations on the token manager in seconds",
		[]string{"scope", "namespace"},
		[]float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10})

	// ===== RefreshStore Metrics =====

	pm.registerCounter(namespace, "storage_operations_total",
		"Total number of storage operations",
		[]string{"operation", "status", "error_type", "storage_backend", "namespace"})

	pm.registerCounter(namespace, "storage_cleanup_tokens_removed_total",
		"Total number of tokens removed during cleanup",
		[]string{"storage_backend", "namespace"})

	pm.registerHistogram(namespace, "storage_operation_duration_seconds",
		"Duration of storage operations in seconds",
		[]string{"operation", "storage_backend", "namespace"},
		[]float64{.0001, .0005, .001, .0025, .005, .01, .025, .05, .1, .25})

	pm.registerGauge(namespace, "storage_tokens_count",
		"Number of tokens in storage",
		[]string{"storage_backend", "namespace"})

	// ===== KeyStore Metrics =====

	pm.registerCounter(namespace, "keystore_operations_total",
		"Total number of key store operations",
		[]string{"operation", "status", "error_type", "storage_backend", "namespace"})

	pm.registerHistogram(namespace, "keystore_operation_duration_seconds",
		"Duration of key store operations in seconds",
		[]string{"operation", "storage_backend", "namespace"},
		[]float64{.0001, .0005, .001, .0025, .005, .01, .025, .05, .1, .25})

	pm.registerGauge(namespace, "keystore_keys_count",
		"Number of keys in the key store",
		[]string{"storage_backend", "namespace"})

	// ===== KeyManager Metrics =====

	pm.registerCounter(namespace, "key_rotations_total",
		"Total number of key rotations",
		[]string{"status", "error_type", "namespace"})

	pm.registerHistogram(namespace, "key_operation_duration_seconds",
		"Duration of key operations in seconds",
		[]string{"operation", "namespace"},
		[]float64{.0001, .0005, .001, .0025, .005, .01, .025, .05})

	pm.registerGauge(namespace, "key_active_versions_count",
		"Number of active key versions",
		[]string{"namespace"})
}

// registerCounter creates a CounterVec with the given namespace, name, help
// string, and label names, registers it in the registry, and stores it for
// lookup by fully-qualified name.
func (pm *PrometheusMetrics) registerCounter(namespace, name, help string, labels []string) {
	counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Name:      name,
			Help:      help,
		},
		labels,
	)
	pm.registry.MustRegister(counter)
	pm.counters[namespace+"_"+name] = counter
	pm.names[namespace+"_"+name] = help
}

// registerGauge creates a GaugeVec with the given namespace, name, help
// string, and label names, registers it in the registry, and stores it for
// lookup by fully-qualified name.
func (pm *PrometheusMetrics) registerGauge(namespace, name, help string, labels []string) {
	gauge := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Name:      name,
			Help:      help,
		},
		labels,
	)
	pm.registry.MustRegister(gauge)
	pm.gauges[namespace+"_"+name] = gauge
	pm.names[namespace+"_"+name] = help
}

// registerHistogram creates a HistogramVec with the given namespace, name,
// help string, label names, and bucket boundaries, registers it in the
// registry, and stores it for lookup by fully-qualified name.
func (pm *PrometheusMetrics) registerHistogram(namespace, name, help string, labels []string, buckets []float64) {
	histogram := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      name,
			Help:      help,
			Buckets:   buckets,
		},
		labels,
	)
	pm.registry.MustRegister(histogram)
	pm.histograms[namespace+"_"+name] = histogram
	pm.names[namespace+"_"+name] = help
}

// IncrementCounter increments the named counter by 1. It is a convenience
// wrapper around AddCounter. If the metric is not registered or the labels do
// not match the registered label names, the call is silently skipped and a
// warning is logged if a logger is configured.
func (pm *PrometheusMetrics) IncrementCounter(name string, labels map[string]string) {
	pm.AddCounter(name, 1, labels)
}

// AddCounter adds value to the named counter. If the metric is not registered,
// the call is silently skipped and a warning is logged with the metric name and
// value. If the provided labels do not match the label names declared at
// registration, the call is silently skipped and a warning is logged with the
// metric name and error.
func (pm *PrometheusMetrics) AddCounter(name string, value float64, labels map[string]string) {
	// ===== STEP 1: Look Up Metric =====
	pm.countersMu.RLock()
	counter, exists := pm.counters[name]
	pm.countersMu.RUnlock()

	if !exists {
		pm.logger.Warn("counter metric not registered - skipping", "metric", name, "value", value)
		return
	}

	// ===== STEP 2: Resolve Label Set =====
	c, err := counter.GetMetricWith(labels)
	if err != nil {
		pm.logger.Warn("invalid labels for counter - skipping", "metric", name, "error", err)
		return
	}

	// ===== STEP 3: Record =====
	c.Add(value)
}

// SetGauge sets the named gauge to value. If the metric is not registered, the
// call is silently skipped and a warning is logged. If the provided labels do
// not match the label names declared at registration, the call is silently
// skipped and a warning is logged with the metric name and error.
func (pm *PrometheusMetrics) SetGauge(name string, value float64, labels map[string]string) {
	// ===== STEP 1: Look Up Metric =====
	pm.gaugesMu.RLock()
	gauge, exists := pm.gauges[name]
	pm.gaugesMu.RUnlock()

	if !exists {
		pm.logger.Warn("gauge metric not registered - skipping", "metric", name)
		return
	}

	// ===== STEP 2: Resolve Label Set =====
	g, err := gauge.GetMetricWith(labels)
	if err != nil {
		pm.logger.Warn("invalid labels for gauge - skipping", "metric", name, "error", err)
		return
	}

	// ===== STEP 3: Record =====
	g.Set(value)
}

// RecordHistogram records value in the named histogram. If the metric is not
// registered, the call is silently skipped and a warning is logged. If the
// provided labels do not match the label names declared at registration, the
// call is silently skipped and a warning is logged with the metric name and
// error.
func (pm *PrometheusMetrics) RecordHistogram(name string, value float64, labels map[string]string) {
	// ===== STEP 1: Look Up Metric =====
	pm.histogramsMu.RLock()
	histogram, exists := pm.histograms[name]
	pm.histogramsMu.RUnlock()

	if !exists {
		pm.logger.Warn("histogram metric not registered - skipping", "metric", name)
		return
	}

	// ===== STEP 2: Resolve Label Set =====
	h, err := histogram.GetMetricWith(labels)
	if err != nil {
		pm.logger.Warn("invalid labels for histogram - skipping", "metric", name, "error", err)
		return
	}

	// ===== STEP 3: Record =====
	h.Observe(value)
}

// RecordDuration records duration in the named histogram by converting it to
// seconds before observation. It delegates to RecordHistogram and inherits its
// skip-on-unregistered and skip-on-label-mismatch behaviour.
func (pm *PrometheusMetrics) RecordDuration(name string, duration time.Duration, labels map[string]string) {
	pm.RecordHistogram(name, duration.Seconds(), labels)
}

// Handler returns an HTTP handler that serves all registered metrics in
// OpenMetrics text format. Mount it at /metrics in your HTTP server.
func (pm *PrometheusMetrics) Handler() http.Handler {
	return promhttp.HandlerFor(pm.registry, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	})
}

// Registry returns the underlying Prometheus registry. This is intended for
// advanced use cases such as registering custom collectors or inspecting metric
// families in tests.
func (pm *PrometheusMetrics) Registry() *prometheus.Registry {
	return pm.registry
}

// MetricNames returns a map of every registered metric name to its help string.
// Returns a defensive copy — mutations do not affect the registry.
func (pm *PrometheusMetrics) MetricNames() map[string]string {
	result := make(map[string]string, len(pm.names))
	for k, v := range pm.names {
		result[k] = v
	}
	return result
}
