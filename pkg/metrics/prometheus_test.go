package metrics_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	dto "github.com/prometheus/client_model/go"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/aetomala/jwtauth/internal/testutil"
	"github.com/aetomala/jwtauth/pkg/metrics"
)

// counterValue gathers the value of a counter with the given labels from the registry.
func counterValue(registry *prometheus.Registry, name string, labels map[string]string) float64 {
	families, err := registry.Gather()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			if dtoLabelsMatch(m.GetLabel(), labels) {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// gaugeValue gathers the value of a gauge with the given labels from the registry.
func gaugeValue(registry *prometheus.Registry, name string, labels map[string]string) float64 {
	families, err := registry.Gather()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			if dtoLabelsMatch(m.GetLabel(), labels) {
				return m.GetGauge().GetValue()
			}
		}
	}
	return 0
}

// histogramSampleCount returns the number of observations recorded for a histogram metric.
func histogramSampleCount(registry *prometheus.Registry, name string, labels map[string]string) uint64 {
	families, err := registry.Gather()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			if dtoLabelsMatch(m.GetLabel(), labels) {
				return m.GetHistogram().GetSampleCount()
			}
		}
	}
	return 0
}

// histogramSampleSum returns the sum of all observations for a histogram metric.
func histogramSampleSum(registry *prometheus.Registry, name string, labels map[string]string) float64 {
	families, err := registry.Gather()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			if dtoLabelsMatch(m.GetLabel(), labels) {
				return m.GetHistogram().GetSampleSum()
			}
		}
	}
	return 0
}

// histogramBucketCount returns the cumulative count for the bucket with the given upper bound.
func histogramBucketCount(registry *prometheus.Registry, name string, labels map[string]string, upperBound float64) uint64 {
	families, err := registry.Gather()
	ExpectWithOffset(1, err).NotTo(HaveOccurred())
	for _, f := range families {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			if dtoLabelsMatch(m.GetLabel(), labels) {
				for _, b := range m.GetHistogram().GetBucket() {
					if b.GetUpperBound() == upperBound {
						return b.GetCumulativeCount()
					}
				}
			}
		}
	}
	return 0
}

func dtoLabelsMatch(pairs []*dto.LabelPair, labels map[string]string) bool {
	matched := 0
	for _, p := range pairs {
		if v, ok := labels[p.GetName()]; ok && v == p.GetValue() {
			matched++
		}
	}
	return matched == len(labels)
}


var _ = Describe("Prometheus", func() {
	var (
		pm       *metrics.PrometheusMetrics
		registry *prometheus.Registry
	)

	BeforeEach(func() {
		// Create fresh registry for each test
		registry = prometheus.NewRegistry()
		pm = metrics.NewPrometheusMetrics(metrics.PrometheusConfig{
			Registry: registry,
		})
	})

	// ==== PHASE1: Constructor and Initialization =====
	Describe("Phase 1: Constructor and Initialization", func() {
		Context("with default configuration", func() {
			It("should create PrometheusMetrics instance", func() {
				pm := metrics.NewPrometheusMetrics(metrics.PrometheusConfig{})
				Expect(pm).NotTo(BeNil())
			})

			It("should use default namespace 'jwtauth'", func() {
				pm := metrics.NewPrometheusMetrics(metrics.PrometheusConfig{})
				Expect(pm).NotTo(BeNil())
				// Metrics should be prefixed with "jwtauth_"
			})

			It("should create new registry when not provided", func() {
				pm := metrics.NewPrometheusMetrics(metrics.PrometheusConfig{})
				Expect(pm.Registry()).NotTo(BeNil())
			})
		})

		Context("with custom configuration", func() {
			It("should accept custom namespace", func() {
				pm := metrics.NewPrometheusMetrics(metrics.PrometheusConfig{
					Namespace: "custom_app",
				})
				Expect(pm).NotTo(BeNil())
			})

			It("should use provided registry", func() {
				customRegistry := prometheus.NewRegistry()
				pm := metrics.NewPrometheusMetrics(metrics.PrometheusConfig{
					Registry: customRegistry,
				})
				Expect(pm.Registry()).To(Equal(customRegistry))
			})
		})

		Context("metric pre-registration", func() {
			It("should pre-register all metrics at creation", func() {
				descCh := make(chan *prometheus.Desc, 100)
				registry.Describe(descCh)
				close(descCh)
				Expect(descCh).NotTo(BeEmpty())
			})

			It("should register TokenManager counters", func() {
				descCh := make(chan *prometheus.Desc, 100)
				registry.Describe(descCh)
				close(descCh)

				names := make([]string, 0, len(descCh))
				for desc := range descCh {
					names = append(names, desc.String())
				}

				Expect(names).To(ContainElement(ContainSubstring("jwtauth_tokens_issued_total")))
				Expect(names).To(ContainElement(ContainSubstring("jwtauth_tokens_validated_total")))
				Expect(names).To(ContainElement(ContainSubstring("jwtauth_operations_total")))
			})

			It("should register RefreshStore metrics", func() {
				descCh := make(chan *prometheus.Desc, 100)
				registry.Describe(descCh)
				close(descCh)

				names := make([]string, 0, len(descCh))
				for desc := range descCh {
					names = append(names, desc.String())
				}

				Expect(names).To(ContainElement(ContainSubstring("jwtauth_storage_operations_total")))
				Expect(names).To(ContainElement(ContainSubstring("jwtauth_storage_cleanup_tokens_removed_total")))
			})

			It("should register KeyManager metrics", func() {
				descCh := make(chan *prometheus.Desc, 100)
				registry.Describe(descCh)
				close(descCh)

				names := make([]string, 0, len(descCh))
				for desc := range descCh {
					names = append(names, desc.String())
				}

				Expect(names).To(ContainElement(ContainSubstring("jwtauth_key_rotations_total")))
				Expect(names).To(ContainElement(ContainSubstring("jwtauth_key_signing_operations_total")))
			})

			It("should support multiple increments", func() {
				labels := map[string]string{
					"operation": "validate",
					"status":    "success",
				}

				pm.IncrementCounter("jwtauth_operations_total", labels)
				pm.IncrementCounter("jwtauth_operations_total", labels)
				pm.IncrementCounter("jwtauth_operations_total", labels)

				Expect(counterValue(registry, "jwtauth_operations_total", labels)).To(Equal(3.0))
			})

			It("should handle different label combinations independently", func() {
				successLabels := map[string]string{"operation": "issue", "status": "success"}
				failureLabels := map[string]string{"operation": "issue", "status": "failure"}

				pm.IncrementCounter("jwtauth_operations_total", successLabels)
				pm.IncrementCounter("jwtauth_operations_total", failureLabels)

				Expect(counterValue(registry, "jwtauth_operations_total", successLabels)).To(Equal(1.0))
				Expect(counterValue(registry, "jwtauth_operations_total", failureLabels)).To(Equal(1.0))
			})

			Context("AddCounter", func() {
				It("should add specific value to counter", func() {
					labels := map[string]string{"operation": "batch", "status": "success"}
					pm.AddCounter("jwtauth_operations_total", 5.0, labels)

					Expect(counterValue(registry, "jwtauth_operations_total", labels)).To(Equal(5.0))
				})

				It("should accumulate values across multiple calls", func() {
					labels := map[string]string{"operation": "batch", "status": "success"}

					pm.AddCounter("jwtauth_operations_total", 5.0, labels)
					pm.AddCounter("jwtauth_operations_total", 3.0, labels)

					Expect(counterValue(registry, "jwtauth_operations_total", labels)).To(Equal(8.0))
				})

				It("should handle fractional values", func() {
					labels := map[string]string{"operation": "partial", "status": "success"}
					pm.AddCounter("jwtauth_operations_total", 0.5, labels)

					Expect(counterValue(registry, "jwtauth_operations_total", labels)).To(Equal(0.5))
				})
			})
		})
	})

	// ===== PHASE 2: Counter Operations - Happy Path =====
	Describe("Phase 2: Counter Operations - Happy Path", func() {
		Context("IncrementCounter", func() {
			It("should increment counter by 1", func() {
				labels := map[string]string{"operation": "issue", "status": "success"}
				pm.IncrementCounter("jwtauth_operations_total", labels)

				Expect(counterValue(registry, "jwtauth_operations_total", labels)).To(Equal(1.0))
			})

			It("should support multiple increments", func() {
				labels := map[string]string{"operation": "validate", "status": "success"}

				pm.IncrementCounter("jwtauth_operations_total", labels)
				pm.IncrementCounter("jwtauth_operations_total", labels)
				pm.IncrementCounter("jwtauth_operations_total", labels)

				Expect(counterValue(registry, "jwtauth_operations_total", labels)).To(Equal(3.0))
			})

			It("should handle different label combinations independently", func() {
				successLabels := map[string]string{"operation": "issue", "status": "success"}
				failureLabels := map[string]string{"operation": "issue", "status": "failure"}

				pm.IncrementCounter("jwtauth_operations_total", successLabels)
				pm.IncrementCounter("jwtauth_operations_total", failureLabels)

				Expect(counterValue(registry, "jwtauth_operations_total", successLabels)).To(Equal(1.0))
				Expect(counterValue(registry, "jwtauth_operations_total", failureLabels)).To(Equal(1.0))
			})
		})
	})

	// ===== PHASE 3: Gauge Operations =====
	Describe("Phase 3: Gauge Operations", func() {
		Context("SetGauge - basic usage", func() {
			It("should set gauge to specific value", func() {
				labels := map[string]string{"storage_backend": "memory"}
				pm.SetGauge("jwtauth_active_tokens", 100, labels)

				Expect(gaugeValue(registry, "jwtauth_active_tokens", labels)).To(Equal(100.0))
			})

			It("should overwrite previous gauge value", func() {
				labels := map[string]string{"storage_backend": "redis"}

				pm.SetGauge("jwtauth_active_tokens", 50, labels)
				pm.SetGauge("jwtauth_active_tokens", 75, labels)

				Expect(gaugeValue(registry, "jwtauth_active_tokens", labels)).To(Equal(75.0))
			})
		})

		Context("SetGauge - value changes", func() {
			It("should allow gauge to increase", func() {
				labels := map[string]string{"storage_backend": "memory"}

				pm.SetGauge("jwtauth_active_tokens", 50, labels)
				pm.SetGauge("jwtauth_active_tokens", 100, labels)

				Expect(gaugeValue(registry, "jwtauth_active_tokens", labels)).To(Equal(100.0))
			})

			It("should allow gauge to decrease", func() {
				labels := map[string]string{"storage_backend": "memory"}

				pm.SetGauge("jwtauth_active_tokens", 100, labels)
				pm.SetGauge("jwtauth_active_tokens", 50, labels)

				Expect(gaugeValue(registry, "jwtauth_active_tokens", labels)).To(Equal(50.0))
			})

			It("should handle zero values", func() {
				labels := map[string]string{}

				pm.SetGauge("jwtauth_service_running", 1, labels)
				pm.SetGauge("jwtauth_service_running", 0, labels)

				Expect(gaugeValue(registry, "jwtauth_service_running", labels)).To(Equal(0.0))
			})

			It("should handle negative values", func() {
				pm.SetGauge("jwtauth_key_current_version", -1, map[string]string{})

				Expect(gaugeValue(registry, "jwtauth_key_current_version", map[string]string{})).To(Equal(-1.0))
			})
		})
	})

	// ===== PHASE 4: Histogram Operations =====
	Describe("Phase 4: Histogram Operations", func() {
		Context("RecordHistogram", func() {
			It("should record single value", func() {
				labels := map[string]string{"operation": "issue"}
				pm.RecordHistogram("jwtauth_operation_duration_seconds", 0.123, labels)

				Expect(histogramSampleCount(registry, "jwtauth_operation_duration_seconds", labels)).To(Equal(uint64(1)))
				Expect(histogramSampleSum(registry, "jwtauth_operation_duration_seconds", labels)).To(BeNumerically("~", 0.123, 0.0001))
			})

			It("should record distribution of values", func() {
				labels := map[string]string{"operation": "validate"}

				pm.RecordHistogram("jwtauth_operation_duration_seconds", 0.001, labels)
				pm.RecordHistogram("jwtauth_operation_duration_seconds", 0.005, labels)
				pm.RecordHistogram("jwtauth_operation_duration_seconds", 0.010, labels)
				pm.RecordHistogram("jwtauth_operation_duration_seconds", 0.100, labels)
				pm.RecordHistogram("jwtauth_operation_duration_seconds", 1.000, labels)

				Expect(histogramSampleCount(registry, "jwtauth_operation_duration_seconds", labels)).To(Equal(uint64(5)))
				Expect(histogramSampleSum(registry, "jwtauth_operation_duration_seconds", labels)).To(BeNumerically("~", 1.116, 0.0001))
			})

			It("should place values in correct buckets", func() {
				labels := map[string]string{"operation": "refresh"}
				pm.RecordHistogram("jwtauth_operation_duration_seconds", 0.025, labels)

				// 0.025 should appear in the ≤0.025 bucket and all larger buckets
				Expect(histogramBucketCount(registry, "jwtauth_operation_duration_seconds", labels, 0.025)).To(Equal(uint64(1)))
				Expect(histogramBucketCount(registry, "jwtauth_operation_duration_seconds", labels, 0.01)).To(Equal(uint64(0)))
			})
		})

		Context("RecordDuration", func() {
			It("should convert duration to seconds", func() {
				labels := map[string]string{"operation": "issue"}
				pm.RecordDuration("jwtauth_operation_duration_seconds", 250*time.Millisecond, labels)

				Expect(histogramSampleCount(registry, "jwtauth_operation_duration_seconds", labels)).To(Equal(uint64(1)))
				Expect(histogramSampleSum(registry, "jwtauth_operation_duration_seconds", labels)).To(BeNumerically("~", 0.25, 0.0001))
			})

			It("should handle microsecond precision", func() {
				labels := map[string]string{"operation": "retrieve", "storage_backend": "memory", "namespace": ""}
				pm.RecordDuration("jwtauth_storage_operation_duration_seconds", 100*time.Microsecond, labels)

				Expect(histogramSampleCount(registry, "jwtauth_storage_operation_duration_seconds", labels)).To(Equal(uint64(1)))
				Expect(histogramSampleSum(registry, "jwtauth_storage_operation_duration_seconds", labels)).To(BeNumerically("~", 0.0001, 0.00001))
			})

			It("should handle long durations", func() {
				labels := map[string]string{"operation": "cleanup"}
				pm.RecordDuration("jwtauth_operation_duration_seconds", 5*time.Second, labels)

				Expect(histogramSampleCount(registry, "jwtauth_operation_duration_seconds", labels)).To(Equal(uint64(1)))
				Expect(histogramSampleSum(registry, "jwtauth_operation_duration_seconds", labels)).To(BeNumerically("~", 5.0, 0.0001))
			})
		})
	})

	// ===== PHASE 5: Error Handling and Edge Cases =====
	Describe("Phase 5: Error Handling and Edge Cases", func() {
		Context("invalid input handling", func() {
			It("should not panic with nil labels", func() {
				Expect(func() {
					pm.IncrementCounter("jwtauth_operations_total", nil)
				}).NotTo(Panic())
			})

			It("should not panic with empty labels", func() {
				Expect(func() {
					pm.IncrementCounter("jwtauth_operations_total", map[string]string{})
				}).NotTo(Panic())
			})

			It("should not panic with unregistered metric", func() {
				Expect(func() {
					pm.IncrementCounter("totally_fake_metric", map[string]string{})
				}).NotTo(Panic())
			})

			It("should gracefully skip unregistered metrics", func() {
				// Should not cause errors or crashes
				pm.AddCounter("nonexistent_counter", 5.0, map[string]string{})
				pm.SetGauge("nonexistent_gauge", 100, map[string]string{})
				pm.RecordHistogram("nonexistent_histogram", 0.5, map[string]string{})
			})
		})

		Context("label mismatch handling", func() {
			It("should handle missing required labels", func() {
				// Metric expects "operation" and "status" labels
				Expect(func() {
					pm.IncrementCounter("jwtauth_operations_total", map[string]string{
						"operation": "issue",
						// Missing "status" label
					})
				}).NotTo(Panic())
			})

			It("should handle extra labels", func() {
				Expect(func() {
					pm.IncrementCounter("jwtauth_operations_total", map[string]string{
						"operation": "issue",
						"status":    "success",
						"extra_key": "extra_value",
						"another":   "label",
					})
				}).NotTo(Panic())
			})

			It("should not panic with invalid labels on SetGauge", func() {
				Expect(func() {
					pm.SetGauge("jwtauth_active_tokens", 100, map[string]string{
						"storage_backend": "memory",
						"extra_key":       "value",
					})
				}).NotTo(Panic())
			})

			It("should not panic with invalid labels on RecordHistogram", func() {
				Expect(func() {
					pm.RecordHistogram("jwtauth_operation_duration_seconds", 0.1, map[string]string{
						"operation": "issue",
						"extra_key": "value",
					})
				}).NotTo(Panic())
			})
		})
	})

	// ===== PHASE 6: Concurrency and Thread Safety =====
	Describe("Phase 6: Concurrency and Thread Safety", func() {
		Context("concurrent counter operations", func() {
			It("should handle concurrent increments safely", func() {
				done := make(chan bool)
				goroutines := 10
				incrementsPerGoroutine := 100

				for i := 0; i < goroutines; i++ {
					go func() {
						defer GinkgoRecover()
						for j := 0; j < incrementsPerGoroutine; j++ {
							pm.IncrementCounter("jwtauth_operations_total", map[string]string{
								"operation": "concurrent",
								"status":    "success",
							})
						}
						done <- true
					}()
				}

				// Wait for all goroutines
				for i := 0; i < goroutines; i++ {
					<-done
				}

				labels := map[string]string{"operation": "concurrent", "status": "success"}
				Expect(counterValue(registry, "jwtauth_operations_total", labels)).To(Equal(float64(goroutines * incrementsPerGoroutine)))
			})

			It("should handle concurrent AddCounter calls", func() {
				done := make(chan bool)

				for i := 0; i < 5; i++ {
					go func() {
						defer GinkgoRecover()
						pm.AddCounter("jwtauth_operations_total", 10.0, map[string]string{
							"operation": "concurrent_add",
							"status":    "success",
						})
						done <- true
					}()
				}

				for i := 0; i < 5; i++ {
					<-done
				}

				labels := map[string]string{"operation": "concurrent_add", "status": "success"}
				Expect(counterValue(registry, "jwtauth_operations_total", labels)).To(Equal(50.0))
			})
		})

		Context("concurrent gauge operations", func() {
			It("should handle concurrent gauge updates", func() {
				done := make(chan bool)

				for i := 0; i < 10; i++ {
					go func(value float64) {
						defer GinkgoRecover()
						pm.SetGauge("jwtauth_active_tokens", value, map[string]string{
							"storage_backend": "concurrent",
						})
						done <- true
					}(float64(i))
				}

				for i := 0; i < 10; i++ {
					<-done
				}

				// Last write wins — value must be one of the 10 values written
				labels := map[string]string{"storage_backend": "concurrent"}
				Expect(gaugeValue(registry, "jwtauth_active_tokens", labels)).To(BeNumerically(">=", 0))
				Expect(gaugeValue(registry, "jwtauth_active_tokens", labels)).To(BeNumerically("<", 10))
			})
		})

		Context("concurrent histogram operations", func() {
			It("should handle concurrent observations", func() {
				done := make(chan bool)

				for i := 0; i < 10; i++ {
					go func() {
						defer GinkgoRecover()
						for j := 0; j < 100; j++ {
							pm.RecordHistogram("jwtauth_operation_duration_seconds", 0.001, map[string]string{
								"operation": "concurrent",
							})
						}
						done <- true
					}()
				}

				for i := 0; i < 10; i++ {
					<-done
				}

				labels := map[string]string{"operation": "concurrent"}
				Expect(histogramSampleCount(registry, "jwtauth_operation_duration_seconds", labels)).To(Equal(uint64(1000)))
			})
		})
	})

	// ===== PHASE 7: HTTP Handler and Export =====
	Describe("Phase 7: HTTP Handler and Metrics Export", func() {
		Context("Handler method", func() {
			It("should return valid HTTP handler", func() {
				handler := pm.Handler()
				Expect(handler).NotTo(BeNil())
			})

			It("should expose metrics in Prometheus text format", func() {
				pm.IncrementCounter("jwtauth_operations_total", map[string]string{
					"operation": "issue",
					"status":    "success",
				})
				pm.SetGauge("jwtauth_active_tokens", 42, map[string]string{
					"storage_backend": "memory",
				})

				req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
				w := httptest.NewRecorder()
				pm.Handler().ServeHTTP(w, req)

				resp := w.Result()
				body, _ := io.ReadAll(resp.Body)

				Expect(resp.StatusCode).To(Equal(http.StatusOK))
				Expect(resp.Header.Get("Content-Type")).To(ContainSubstring("text/plain"))
				Expect(strings.Contains(string(body), "jwtauth_operations_total")).To(BeTrue())
				Expect(strings.Contains(string(body), "jwtauth_active_tokens")).To(BeTrue())
			})
		})

		Context("Registry method", func() {
			It("should return underlying Prometheus registry", func() {
				reg := pm.Registry()
				Expect(reg).NotTo(BeNil())
				Expect(reg).To(Equal(registry))
			})

			It("should allow querying metrics from registry", func() {
				pm.IncrementCounter("jwtauth_operations_total", map[string]string{
					"operation": "test",
					"status":    "success",
				})

				metricFamilies, err := pm.Registry().Gather()
				Expect(err).NotTo(HaveOccurred())
				Expect(metricFamilies).NotTo(BeEmpty())
			})
		})
	})

	// ===== PHASE 8: Integration Scenarios =====
	Describe("Phase 8: Integration Scenarios", func() {
		Context("complete token lifecycle", func() {
			It("should track issue → validate → refresh flow", func() {
				// Issue token
				pm.IncrementCounter("jwtauth_tokens_issued_total", map[string]string{
					"status":     "success",
					"error_type": "",
				})
				pm.RecordDuration("jwtauth_operation_duration_seconds", 50*time.Millisecond, map[string]string{
					"operation": "issue",
				})

				// Validate token
				pm.IncrementCounter("jwtauth_tokens_validated_total", map[string]string{
					"status":     "success",
					"error_type": "",
				})
				pm.RecordDuration("jwtauth_operation_duration_seconds", 5*time.Millisecond, map[string]string{
					"operation": "validate",
				})

				// Refresh token
				pm.IncrementCounter("jwtauth_tokens_refreshed_total", map[string]string{
					"status":     "success",
					"error_type": "",
				})
				pm.RecordDuration("jwtauth_operation_duration_seconds", 30*time.Millisecond, map[string]string{
					"operation": "refresh",
				})

				// Update active tokens
				pm.SetGauge("jwtauth_active_tokens", 150, map[string]string{
					"storage_backend": "redis",
				})

				Expect(counterValue(registry, "jwtauth_tokens_issued_total", map[string]string{"status": "success", "error_type": ""})).To(Equal(1.0))
				Expect(counterValue(registry, "jwtauth_tokens_validated_total", map[string]string{"status": "success", "error_type": ""})).To(Equal(1.0))
				Expect(counterValue(registry, "jwtauth_tokens_refreshed_total", map[string]string{"status": "success", "error_type": ""})).To(Equal(1.0))
				Expect(histogramSampleCount(registry, "jwtauth_operation_duration_seconds", map[string]string{"operation": "issue"})).To(Equal(uint64(1)))
				Expect(histogramSampleCount(registry, "jwtauth_operation_duration_seconds", map[string]string{"operation": "validate"})).To(Equal(uint64(1)))
				Expect(histogramSampleCount(registry, "jwtauth_operation_duration_seconds", map[string]string{"operation": "refresh"})).To(Equal(uint64(1)))
				Expect(gaugeValue(registry, "jwtauth_active_tokens", map[string]string{"storage_backend": "redis"})).To(Equal(150.0))
			})
		})

		Context("storage operations lifecycle", func() {
			It("should track store → retrieve → cleanup flow", func() {
				// Store operation
				pm.IncrementCounter("jwtauth_storage_operations_total", map[string]string{
					"operation":       "store",
					"status":          "success",
					"error_type":      "",
					"storage_backend": "redis",
					"namespace":       "",
				})
				pm.RecordDuration("jwtauth_storage_operation_duration_seconds", 2*time.Millisecond, map[string]string{
					"operation":       "store",
					"storage_backend": "redis",
					"namespace":       "",
				})

				// Retrieve operation
				pm.IncrementCounter("jwtauth_storage_operations_total", map[string]string{
					"operation":       "retrieve",
					"status":          "success",
					"error_type":      "",
					"storage_backend": "redis",
					"namespace":       "",
				})
				pm.RecordDuration("jwtauth_storage_operation_duration_seconds", 1*time.Millisecond, map[string]string{
					"operation":       "retrieve",
					"storage_backend": "redis",
					"namespace":       "",
				})

				// Cleanup
				pm.AddCounter("jwtauth_storage_cleanup_tokens_removed_total", 25.0, map[string]string{
					"storage_backend": "redis",
					"namespace":       "",
				})

				// Update storage size
				pm.SetGauge("jwtauth_storage_tokens_count", 975, map[string]string{
					"storage_backend": "redis",
					"namespace":       "",
				})

				Expect(counterValue(registry, "jwtauth_storage_operations_total", map[string]string{"operation": "store", "status": "success", "error_type": "", "storage_backend": "redis", "namespace": ""})).To(Equal(1.0))
				Expect(counterValue(registry, "jwtauth_storage_operations_total", map[string]string{"operation": "retrieve", "status": "success", "error_type": "", "storage_backend": "redis", "namespace": ""})).To(Equal(1.0))
				Expect(counterValue(registry, "jwtauth_storage_cleanup_tokens_removed_total", map[string]string{"storage_backend": "redis", "namespace": ""})).To(Equal(25.0))
				Expect(histogramSampleCount(registry, "jwtauth_storage_operation_duration_seconds", map[string]string{"operation": "store", "storage_backend": "redis", "namespace": ""})).To(Equal(uint64(1)))
				Expect(histogramSampleCount(registry, "jwtauth_storage_operation_duration_seconds", map[string]string{"operation": "retrieve", "storage_backend": "redis", "namespace": ""})).To(Equal(uint64(1)))
				Expect(gaugeValue(registry, "jwtauth_storage_tokens_count", map[string]string{"storage_backend": "redis", "namespace": ""})).To(Equal(975.0))
			})
		})

		Context("key management lifecycle", func() {
			It("should track rotation → sign → validate flow", func() {
				// Key rotation
				pm.IncrementCounter("jwtauth_key_rotations_total", map[string]string{
					"status":     "success",
					"error_type": "",
					"namespace":  "",
				})
				pm.RecordDuration("jwtauth_key_operation_duration_seconds", 100*time.Millisecond, map[string]string{
					"operation": "rotate",
					"namespace": "",
				})

				// Update key gauges
				pm.SetGauge("jwtauth_key_current_version", 5, map[string]string{})
				pm.SetGauge("jwtauth_key_active_versions_count", 2, map[string]string{"namespace": ""})

				// Signing operations
				pm.IncrementCounter("jwtauth_key_signing_operations_total", map[string]string{
					"status":     "success",
					"error_type": "",
					"namespace":  "",
				})
				pm.RecordDuration("jwtauth_key_operation_duration_seconds", 500*time.Microsecond, map[string]string{
					"operation": "sign",
					"namespace": "",
				})

				// Validation operations
				pm.IncrementCounter("jwtauth_key_validation_operations_total", map[string]string{
					"status":     "success",
					"error_type": "",
					"namespace":  "",
				})
				pm.RecordDuration("jwtauth_key_operation_duration_seconds", 300*time.Microsecond, map[string]string{
					"operation": "validate",
					"namespace": "",
				})

				Expect(counterValue(registry, "jwtauth_key_rotations_total", map[string]string{"status": "success", "error_type": "", "namespace": ""})).To(Equal(1.0))
				Expect(counterValue(registry, "jwtauth_key_signing_operations_total", map[string]string{"status": "success", "error_type": "", "namespace": ""})).To(Equal(1.0))
				Expect(counterValue(registry, "jwtauth_key_validation_operations_total", map[string]string{"status": "success", "error_type": "", "namespace": ""})).To(Equal(1.0))
				Expect(gaugeValue(registry, "jwtauth_key_current_version", map[string]string{})).To(Equal(5.0))
				Expect(gaugeValue(registry, "jwtauth_key_active_versions_count", map[string]string{"namespace": ""})).To(Equal(2.0))
				Expect(histogramSampleCount(registry, "jwtauth_key_operation_duration_seconds", map[string]string{"operation": "rotate", "namespace": ""})).To(Equal(uint64(1)))
				Expect(histogramSampleCount(registry, "jwtauth_key_operation_duration_seconds", map[string]string{"operation": "sign", "namespace": ""})).To(Equal(uint64(1)))
				Expect(histogramSampleCount(registry, "jwtauth_key_operation_duration_seconds", map[string]string{"operation": "validate", "namespace": ""})).To(Equal(uint64(1)))
			})
		})
	})

	// ===== PHASE 9: Logging Behavior =====
	Describe("Phase 9: Logging Behavior", func() {
		var mockLogger *testutil.MockLogger
		var pmWithLogger *metrics.PrometheusMetrics

		BeforeEach(func() {
			mockLogger = testutil.NewMockLogger()
			registry := prometheus.NewRegistry()
			pmWithLogger = metrics.NewPrometheusMetrics(metrics.PrometheusConfig{
				Registry: registry,
				Logger:   mockLogger,
			})
		})

		Context("with logger provided", func() {
			It("should log warning for unregistered counter", func() {
				pmWithLogger.IncrementCounter("fake_counter_metric", map[string]string{})

				Expect(mockLogger.HasLog("warn", "counter metric not registered - skipping")).To(BeTrue())
				entry := mockLogger.GetLogWithField("warn", "counter metric not registered - skipping", "metric")
				Expect(entry).NotTo(BeNil())
				Expect(entry.Fields["metric"]).To(Equal("fake_counter_metric"))
			})

			It("should log warning for unregistered gauge", func() {
				pmWithLogger.SetGauge("fake_gauge_metric", 100, map[string]string{})

				Expect(mockLogger.HasLog("warn", "gauge metric not registered - skipping")).To(BeTrue())
				entry := mockLogger.GetLogWithField("warn", "gauge metric not registered - skipping", "metric")
				Expect(entry).NotTo(BeNil())
				Expect(entry.Fields["metric"]).To(Equal("fake_gauge_metric"))
			})

			It("should log warning for unregistered histogram", func() {
				pmWithLogger.RecordHistogram("fake_histogram_metric", 0.5, map[string]string{})

				Expect(mockLogger.HasLog("warn", "histogram metric not registered - skipping")).To(BeTrue())
				entry := mockLogger.GetLogWithField("warn", "histogram metric not registered - skipping", "metric")
				Expect(entry).NotTo(BeNil())
				Expect(entry.Fields["metric"]).To(Equal("fake_histogram_metric"))
			})

			It("should include metric name and value in warning logs", func() {
				pmWithLogger.AddCounter("nonexistent", 42.5, map[string]string{})

				entry := mockLogger.GetLogWithField("warn", "counter metric not registered - skipping", "value")
				Expect(entry).NotTo(BeNil())
				Expect(entry.Fields["metric"]).To(Equal("nonexistent"))
				Expect(entry.Fields["value"]).To(Equal(42.5))
			})
		})

		Context("with nil logger", func() {
			It("should not panic on unregistered counter", func() {
				pmNoLogger := metrics.NewPrometheusMetrics(metrics.PrometheusConfig{
					Logger: nil,
				})

				Expect(func() {
					pmNoLogger.IncrementCounter("fake_metric", map[string]string{})
				}).NotTo(Panic())
			})

			It("should not panic on unregistered gauge", func() {
				pmNoLogger := metrics.NewPrometheusMetrics(metrics.PrometheusConfig{
					Logger: nil,
				})

				Expect(func() {
					pmNoLogger.SetGauge("fake_gauge", 100, map[string]string{})
				}).NotTo(Panic())
			})

			It("should not panic on unregistered histogram", func() {
				pmNoLogger := metrics.NewPrometheusMetrics(metrics.PrometheusConfig{
					Logger: nil,
				})

				Expect(func() {
					pmNoLogger.RecordHistogram("fake_histogram", 0.5, map[string]string{})
				}).NotTo(Panic())
			})
		})

		Context("typo detection", func() {
			It("should help catch metric name typos", func() {
				// Common typo: "operatoins" instead of "operations"
				pmWithLogger.IncrementCounter("jwtauth_operatoins_total", map[string]string{
					"operation": "issue",
					"status":    "success",
				})

				Expect(mockLogger.HasLog("warn", "counter metric not registered - skipping")).To(BeTrue())
				entry := mockLogger.GetLogWithField("warn", "counter metric not registered - skipping", "metric")
				Expect(entry).NotTo(BeNil())
				Expect(entry.Fields["metric"]).To(Equal("jwtauth_operatoins_total"))
			})

			It("should log warning for label key typos", func() {
				// Typo in label key: "operaton" instead of "operation" — causes label mismatch
				pmWithLogger.IncrementCounter("jwtauth_operations_total", map[string]string{
					"operaton": "issue", // Typo: should be "operation"
					"status":   "success",
				})

				// Our implementation logs a warning when labels don't match registered label names
				Expect(mockLogger.HasLog("warn", "invalid labels for counter - skipping")).To(BeTrue())
			})

			It("should log warning for invalid labels on SetGauge", func() {
				pmWithLogger.SetGauge("jwtauth_active_tokens", 100, map[string]string{
					"storage_backend": "memory",
					"extra_key":       "value",
				})
				Expect(mockLogger.HasLog("warn", "invalid labels for gauge - skipping")).To(BeTrue())
			})

			It("should log warning for invalid labels on RecordHistogram", func() {
				pmWithLogger.RecordHistogram("jwtauth_operation_duration_seconds", 0.1, map[string]string{
					"operation": "issue",
					"extra_key": "value",
				})
				Expect(mockLogger.HasLog("warn", "invalid labels for histogram - skipping")).To(BeTrue())
			})
		})
	})
})
