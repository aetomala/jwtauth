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
	logger   logging.Logger // Optional; nil disables logging

	// ===== Counters =====
	counters   map[string]*prometheus.CounterVec
	countersMu sync.RWMutex

	// ===== Gauges =====
	gauges   map[string]*prometheus.GaugeVec
	gaugesMu sync.RWMutex

	// ===== Histograms =====
	histograms   map[string]*prometheus.HistogramVec
	histogramsMu sync.RWMutex
}

// PrometheusConfig holds configuration for a PrometheusMetrics instance.
// All fields have sensible defaults and may be left at their zero values.
type PrometheusConfig struct {
	Namespace string             // Prepended to all metric names. Defaults to "jwtauth".
	Registry  *prometheus.Registry // Registry to register metrics into. If nil, a new isolated registry is created.
	Logger    logging.Logger     // Optional; nil disables logging.
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

	// ===== STEP 2: Construct =====
	pm := &PrometheusMetrics{
		registry:   config.Registry,
		logger:     config.Logger,
		counters:   make(map[string]*prometheus.CounterVec),
		gauges:     make(map[string]*prometheus.GaugeVec),
		histograms: make(map[string]*prometheus.HistogramVec),
	}

	// ===== STEP 3: Pre-register All Metrics =====
	pm.registerAllMetrics(config.Namespace)
	return pm
}

// registerAllMetrics registers every metric this package exposes, grouped by
// the component that owns each metric.
func (pm *PrometheusMetrics) registerAllMetrics(namespace string) {
	// ===== TokenService Metrics =====

	pm.registerCounter(namespace, "tokens_issued_total",
		"Total number of tokens issued",
		[]string{"status", "error_type"})

	pm.registerCounter(namespace, "tokens_validated_total",
		"Total number of tokens validated",
		[]string{"status", "error_type"})

	pm.registerCounter(namespace, "tokens_refreshed_total",
		"Total number of tokens refreshed",
		[]string{"status", "error_type"})

	pm.registerCounter(namespace, "tokens_revoked_total",
		"Total number of tokens revoked",
		[]string{"operation", "status"})

	pm.registerCounter(namespace, "tokens_introspected_total",
		"Total number of token introspections",
		[]string{"status"})

	pm.registerCounter(namespace, "operations_total",
		"Total number of operations",
		[]string{"operation", "status"})

	pm.registerHistogram(namespace, "operation_duration_seconds",
		"Duration of operations in seconds",
		[]string{"operation"},
		[]float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10})

	pm.registerGauge(namespace, "active_tokens",
		"Number of active tokens",
		[]string{"storage_backend"})

	pm.registerGauge(namespace, "service_running",
		"Whether the service is running (1) or stopped (0)",
		[]string{})

	// ===== RefreshStore Metrics =====

	pm.registerCounter(namespace, "storage_operations_total",
		"Total number of storage operations",
		[]string{"operation", "status", "storage_backend"})

	pm.registerCounter(namespace, "storage_cleanup_tokens_removed_total",
		"Total number of tokens removed during cleanup",
		[]string{"storage_backend"})

	pm.registerHistogram(namespace, "storage_operation_duration_seconds",
		"Duration of storage operations in seconds",
		[]string{"operation", "storage_backend"},
		[]float64{.0001, .0005, .001, .0025, .005, .01, .025, .05, .1, .25})

	pm.registerGauge(namespace, "storage_tokens_count",
		"Number of tokens in storage",
		[]string{"storage_backend"})

	// ===== KeyStore Metrics =====

	pm.registerCounter(namespace, "keystore_operations_total",
		"Total number of key store operations",
		[]string{"operation", "status", "storage_backend"})

	pm.registerHistogram(namespace, "keystore_operation_duration_seconds",
		"Duration of key store operations in seconds",
		[]string{"operation", "storage_backend"},
		[]float64{.0001, .0005, .001, .0025, .005, .01, .025, .05, .1, .25})

	pm.registerGauge(namespace, "keystore_keys_count",
		"Number of keys in the key store",
		[]string{"storage_backend"})

	// ===== KeyManager Metrics =====

	pm.registerCounter(namespace, "key_rotations_total",
		"Total number of key rotations",
		[]string{"status"})

	pm.registerCounter(namespace, "key_signing_operations_total",
		"Total number of key signing operations",
		[]string{"status"})

	pm.registerCounter(namespace, "key_validation_operations_total",
		"Total number of key validation operations",
		[]string{"status"})

	pm.registerHistogram(namespace, "key_operation_duration_seconds",
		"Duration of key operations in seconds",
		[]string{"operation"},
		[]float64{.0001, .0005, .001, .0025, .005, .01, .025, .05})

	pm.registerGauge(namespace, "key_current_version",
		"Current active key version",
		[]string{})

	pm.registerGauge(namespace, "key_active_versions_count",
		"Number of active key versions",
		[]string{})
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
		if pm.logger != nil {
			pm.logger.Warn("counter metric not registered - skipping", "metric", name, "value", value)
		}
		return
	}

	// ===== STEP 2: Resolve Label Set =====
	c, err := counter.GetMetricWith(labels)
	if err != nil {
		if pm.logger != nil {
			pm.logger.Warn("invalid labels for counter - skipping", "metric", name, "error", err)
		}
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
		if pm.logger != nil {
			pm.logger.Warn("gauge metric not registered - skipping", "metric", name)
		}
		return
	}

	// ===== STEP 2: Resolve Label Set =====
	g, err := gauge.GetMetricWith(labels)
	if err != nil {
		if pm.logger != nil {
			pm.logger.Warn("invalid labels for gauge - skipping", "metric", name, "error", err)
		}
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
		if pm.logger != nil {
			pm.logger.Warn("histogram metric not registered - skipping", "metric", name)
		}
		return
	}

	// ===== STEP 2: Resolve Label Set =====
	h, err := histogram.GetMetricWith(labels)
	if err != nil {
		if pm.logger != nil {
			pm.logger.Warn("invalid labels for histogram - skipping", "metric", name, "error", err)
		}
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
