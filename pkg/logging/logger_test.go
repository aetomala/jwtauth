package logging_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aetomala/jwtauth/pkg/logging"
)

func TestLogging(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Logging Suite")
}

var _ = Describe("Logger Interface", func() {
	Describe("Interface Compliance", func() {
		It("should be implemented by SlogAdapter", func() {
			var _ logging.Logger = (*logging.SlogAdapter)(nil)
		})

		It("should be implemented by NoOpLogger", func() {
			var _ logging.Logger = (*logging.NoOpLogger)(nil)
		})
	})
})

// ============================================================================
// SlogAdapter Tests
// ============================================================================

var _ = Describe("SlogAdapter", func() {
	var (
		buf    *bytes.Buffer
		logger logging.Logger
	)

	BeforeEach(func() {
		buf = &bytes.Buffer{}
	})

	// === CONSTRUCTOR ===
	Describe("NewSlogAdapter", func() {
		It("should create adapter with valid slog.Logger", func() {
			slogger := slog.New(slog.NewTextHandler(buf, nil))
			adapter := logging.NewSlogAdapter(slogger)

			Expect(adapter).NotTo(BeNil())
		})

		It("should accept nil handler options", func() {
			slogger := slog.New(slog.NewJSONHandler(buf, nil))
			adapter := logging.NewSlogAdapter(slogger)

			Expect(adapter).NotTo(BeNil())
		})

		It("should accept custom handler options", func() {
			opts := &slog.HandlerOptions{
				Level: slog.LevelWarn,
			}
			slogger := slog.New(slog.NewJSONHandler(buf, opts))
			adapter := logging.NewSlogAdapter(slogger)

			Expect(adapter).NotTo(BeNil())
		})
	})

	// === INFO LEVEL ===
	Describe("Info", func() {
		BeforeEach(func() {
			handler := slog.NewTextHandler(buf, &slog.HandlerOptions{
				Level: slog.LevelInfo,
			})
			logger = logging.NewSlogAdapter(slog.New(handler))
		})

		It("should log info message without fields", func() {
			logger.Info("test message")

			output := buf.String()
			Expect(output).To(ContainSubstring("level=INFO"))
			Expect(output).To(ContainSubstring("msg=\"test message\""))
		})

		It("should log info message with single key-value pair", func() {
			logger.Info("operation complete", "duration", 150)

			output := buf.String()
			Expect(output).To(ContainSubstring("level=INFO"))
			Expect(output).To(ContainSubstring("msg=\"operation complete\""))
			Expect(output).To(ContainSubstring("duration=150"))
		})

		It("should log info message with multiple key-value pairs", func() {
			logger.Info("key rotation successful",
				"oldKeyID", "abc-123",
				"newKeyID", "xyz-789",
				"duration", 150)

			output := buf.String()
			Expect(output).To(ContainSubstring("level=INFO"))
			Expect(output).To(ContainSubstring("oldKeyID=abc-123"))
			Expect(output).To(ContainSubstring("newKeyID=xyz-789"))
			Expect(output).To(ContainSubstring("duration=150"))
		})

		It("should handle string values", func() {
			logger.Info("test", "key", "value")

			output := buf.String()
			Expect(output).To(ContainSubstring("key=value"))
		})

		It("should handle integer values", func() {
			logger.Info("test", "count", 42)

			output := buf.String()
			Expect(output).To(ContainSubstring("count=42"))
		})

		It("should handle boolean values", func() {
			logger.Info("test", "success", true, "failed", false)

			output := buf.String()
			Expect(output).To(ContainSubstring("success=true"))
			Expect(output).To(ContainSubstring("failed=false"))
		})

		It("should handle float values", func() {
			logger.Info("test", "percentage", 99.5)

			output := buf.String()
			Expect(output).To(ContainSubstring("percentage=99.5"))
		})

		It("should handle time.Duration values", func() {
			logger.Info("test", "duration", 150*time.Millisecond)

			output := buf.String()
			Expect(output).To(ContainSubstring("duration="))
			Expect(output).To(ContainSubstring("ms"))
		})

		It("should handle time.Time values", func() {
			now := time.Now()
			logger.Info("test", "timestamp", now)

			output := buf.String()
			Expect(output).To(ContainSubstring("timestamp="))
		})

		It("should handle nil values", func() {
			logger.Info("test", "nullable", nil)

			output := buf.String()
			Expect(output).To(ContainSubstring("nullable"))
		})

		It("should handle array values", func() {
			logger.Info("test", "items", []string{"a", "b", "c"})

			output := buf.String()
			Expect(output).To(ContainSubstring("items="))
		})

		It("should handle map values", func() {
			logger.Info("test", "data", map[string]int{"count": 5})

			output := buf.String()
			Expect(output).To(ContainSubstring("data="))
		})

		It("should handle empty message", func() {
			logger.Info("", "key", "value")

			output := buf.String()
			Expect(output).To(ContainSubstring("level=INFO"))
			Expect(output).To(ContainSubstring("key=value"))
		})

		It("should handle message with special characters", func() {
			logger.Info("test: success! (100%)", "key", "value")

			output := buf.String()
			Expect(output).To(ContainSubstring("level=INFO"))
		})

		It("should handle odd number of key-value pairs gracefully", func() {
			// This is technically invalid, but shouldn't crash
			logger.Info("test", "key1", "value1", "key2")

			output := buf.String()
			Expect(output).To(ContainSubstring("level=INFO"))
			Expect(output).To(ContainSubstring("key1=value1"))
		})
	})

	// === WARN LEVEL ===
	Describe("Warn", func() {
		BeforeEach(func() {
			handler := slog.NewTextHandler(buf, &slog.HandlerOptions{
				Level: slog.LevelWarn,
			})
			logger = logging.NewSlogAdapter(slog.New(handler))
		})

		It("should log warn message without fields", func() {
			logger.Warn("warning message")

			output := buf.String()
			Expect(output).To(ContainSubstring("level=WARN"))
			Expect(output).To(ContainSubstring("msg=\"warning message\""))
		})

		It("should log warn message with key-value pairs", func() {
			logger.Warn("failed to load key file",
				"file", "corrupted.pem",
				"error", "invalid PEM format")

			output := buf.String()
			Expect(output).To(ContainSubstring("level=WARN"))
			Expect(output).To(ContainSubstring("file=corrupted.pem"))
			Expect(output).To(ContainSubstring("error=\"invalid PEM format\""))
		})

		It("should handle error values", func() {
			testErr := errors.New("permission denied")
			logger.Warn("operation failed", "error", testErr)

			output := buf.String()
			Expect(output).To(ContainSubstring("level=WARN"))
			Expect(output).To(ContainSubstring("error"))
			Expect(output).To(ContainSubstring("permission denied"))
		})

		It("should not log info messages when level is Warn", func() {
			logger.Info("this should not appear")

			output := buf.String()
			Expect(output).To(BeEmpty())
		})
	})

	// === ERROR LEVEL ===
	Describe("Error", func() {
		BeforeEach(func() {
			handler := slog.NewTextHandler(buf, &slog.HandlerOptions{
				Level: slog.LevelError,
			})
			logger = logging.NewSlogAdapter(slog.New(handler))
		})

		It("should log error message without fields", func() {
			logger.Error("critical failure")

			output := buf.String()
			Expect(output).To(ContainSubstring("level=ERROR"))
			Expect(output).To(ContainSubstring("msg=\"critical failure\""))
		})

		It("should log error message with key-value pairs", func() {
			logger.Error("key rotation failed",
				"error", "disk full",
				"keyID", "abc-123",
				"attempt", 3)

			output := buf.String()
			Expect(output).To(ContainSubstring("level=ERROR"))
			Expect(output).To(ContainSubstring("error=\"disk full\""))
			Expect(output).To(ContainSubstring("keyID=abc-123"))
			Expect(output).To(ContainSubstring("attempt=3"))
		})

		It("should not log info or warn messages when level is Error", func() {
			logger.Info("this should not appear")
			logger.Warn("this should not appear either")

			output := buf.String()
			Expect(output).To(BeEmpty())
		})
	})

	// === JSON OUTPUT ===
	Describe("JSON Output", func() {
		BeforeEach(func() {
			handler := slog.NewJSONHandler(buf, &slog.HandlerOptions{
				Level: slog.LevelInfo,
			})
			logger = logging.NewSlogAdapter(slog.New(handler))
		})

		It("should produce valid JSON for info logs", func() {
			logger.Info("test message", "key", "value")

			var logEntry map[string]interface{}
			err := json.Unmarshal(buf.Bytes(), &logEntry)
			Expect(err).NotTo(HaveOccurred())

			Expect(logEntry["level"]).To(Equal("INFO"))
			Expect(logEntry["msg"]).To(Equal("test message"))
			Expect(logEntry["key"]).To(Equal("value"))
		})

		It("should produce valid JSON for warn logs", func() {
			logger.Warn("warning", "file", "test.pem")

			var logEntry map[string]interface{}
			err := json.Unmarshal(buf.Bytes(), &logEntry)
			Expect(err).NotTo(HaveOccurred())

			Expect(logEntry["level"]).To(Equal("WARN"))
			Expect(logEntry["msg"]).To(Equal("warning"))
			Expect(logEntry["file"]).To(Equal("test.pem"))
		})

		It("should produce valid JSON for error logs", func() {
			logger.Error("failure", "error", "test error")

			var logEntry map[string]interface{}
			err := json.Unmarshal(buf.Bytes(), &logEntry)
			Expect(err).NotTo(HaveOccurred())

			Expect(logEntry["level"]).To(Equal("ERROR"))
			Expect(logEntry["msg"]).To(Equal("failure"))
			Expect(logEntry["error"]).To(Equal("test error"))
		})

		It("should include timestamp in JSON", func() {
			logger.Info("test")

			var logEntry map[string]interface{}
			err := json.Unmarshal(buf.Bytes(), &logEntry)
			Expect(err).NotTo(HaveOccurred())

			Expect(logEntry).To(HaveKey("time"))
		})

		It("should handle nested structures in JSON", func() {
			logger.Info("test", "data", map[string]interface{}{
				"nested": "value",
				"count":  42,
			})

			var logEntry map[string]interface{}
			err := json.Unmarshal(buf.Bytes(), &logEntry)
			Expect(err).NotTo(HaveOccurred())

			Expect(logEntry).To(HaveKey("data"))
		})
	})

	// === LEVEL FILTERING ===
	Describe("Log Level Filtering", func() {
		Context("when level is Info", func() {
			BeforeEach(func() {
				handler := slog.NewTextHandler(buf, &slog.HandlerOptions{
					Level: slog.LevelInfo,
				})
				logger = logging.NewSlogAdapter(slog.New(handler))
			})

			It("should log all levels", func() {
				logger.Info("info message")
				logger.Warn("warn message")
				logger.Error("error message")

				output := buf.String()
				Expect(strings.Count(output, "level=INFO")).To(Equal(1))
				Expect(strings.Count(output, "level=WARN")).To(Equal(1))
				Expect(strings.Count(output, "level=ERROR")).To(Equal(1))
			})
		})

		Context("when level is Warn", func() {
			BeforeEach(func() {
				handler := slog.NewTextHandler(buf, &slog.HandlerOptions{
					Level: slog.LevelWarn,
				})
				logger = logging.NewSlogAdapter(slog.New(handler))
			})

			It("should only log Warn and Error", func() {
				logger.Info("info message")
				logger.Warn("warn message")
				logger.Error("error message")

				output := buf.String()
				Expect(output).NotTo(ContainSubstring("level=INFO"))
				Expect(output).To(ContainSubstring("level=WARN"))
				Expect(output).To(ContainSubstring("level=ERROR"))
			})
		})

		Context("when level is Error", func() {
			BeforeEach(func() {
				handler := slog.NewTextHandler(buf, &slog.HandlerOptions{
					Level: slog.LevelError,
				})
				logger = logging.NewSlogAdapter(slog.New(handler))
			})

			It("should only log Error", func() {
				logger.Info("info message")
				logger.Warn("warn message")
				logger.Error("error message")

				output := buf.String()
				Expect(output).NotTo(ContainSubstring("level=INFO"))
				Expect(output).NotTo(ContainSubstring("level=WARN"))
				Expect(output).To(ContainSubstring("level=ERROR"))
			})
		})
	})
})

// ============================================================================
// NoOpLogger Tests
// ============================================================================

var _ = Describe("NoOpLogger", func() {
	var logger logging.Logger

	BeforeEach(func() {
		logger = &logging.NoOpLogger{}
	})

	Describe("Info", func() {
		It("should not panic with no arguments", func() {
			Expect(func() {
				logger.Info("test message")
			}).NotTo(Panic())
		})

		It("should not panic with key-value pairs", func() {
			Expect(func() {
				logger.Info("test message", "key", "value", "count", 42)
			}).NotTo(Panic())
		})

		It("should not panic with nil values", func() {
			Expect(func() {
				logger.Info("test", "nullable", nil)
			}).NotTo(Panic())
		})

		It("should not panic with empty message", func() {
			Expect(func() {
				logger.Info("")
			}).NotTo(Panic())
		})

		It("should not panic with many fields", func() {
			Expect(func() {
				logger.Info("test",
					"field1", "value1",
					"field2", "value2",
					"field3", "value3",
					"field4", "value4",
					"field5", "value5")
			}).NotTo(Panic())
		})

		It("should handle rapid successive calls", func() {
			Expect(func() {
				for i := 0; i < 1000; i++ {
					logger.Info("message", "iteration", i)
				}
			}).NotTo(Panic())
		})
	})

	Describe("Warn", func() {
		It("should not panic with no arguments", func() {
			Expect(func() {
				logger.Warn("warning message")
			}).NotTo(Panic())
		})

		It("should not panic with key-value pairs", func() {
			Expect(func() {
				logger.Warn("warning", "file", "test.pem", "error", "corrupted")
			}).NotTo(Panic())
		})

		It("should not panic with complex values", func() {
			Expect(func() {
				logger.Warn("test",
					"array", []string{"a", "b"},
					"map", map[string]int{"count": 5},
					"duration", 150*time.Millisecond)
			}).NotTo(Panic())
		})
	})

	Describe("Error", func() {
		It("should not panic with no arguments", func() {
			Expect(func() {
				logger.Error("error message")
			}).NotTo(Panic())
		})

		It("should not panic with key-value pairs", func() {
			Expect(func() {
				logger.Error("failure", "error", "test error", "keyID", "abc-123")
			}).NotTo(Panic())
		})

		It("should not panic with error values", func() {
			Expect(func() {
				logger.Error("operation failed", "error", "some error")
			}).NotTo(Panic())
		})
	})

	Describe("Silent Operation", func() {
		It("should produce no output", func() {
			// NoOpLogger doesn't write anywhere, so we just verify it doesn't panic
			// In a real scenario, you'd verify no side effects occurred
			Expect(func() {
				logger.Info("info")
				logger.Warn("warn")
				logger.Error("error")
			}).NotTo(Panic())
		})

		It("should handle all log levels silently", func() {
			Expect(func() {
				for i := 0; i < 100; i++ {
					logger.Info("info", "iteration", i)
					logger.Warn("warn", "iteration", i)
					logger.Error("error", "iteration", i)
				}
			}).NotTo(Panic())
		})
	})

	Describe("Concurrent Usage", func() {
		It("should be safe for concurrent use", func() {
			done := make(chan bool, 10)

			for i := 0; i < 10; i++ {
				go func(id int) {
					defer GinkgoRecover()
					for j := 0; j < 100; j++ {
						logger.Info("message", "goroutine", id, "iteration", j)
						logger.Warn("warning", "goroutine", id)
						logger.Error("error", "goroutine", id)
					}
					done <- true
				}(i)
			}

			// Wait for all goroutines
			for i := 0; i < 10; i++ {
				Eventually(done).Should(Receive())
			}
		})
	})
})

// ============================================================================
// Helper Functions Tests
// ============================================================================

var _ = Describe("Helper Functions", func() {
	Describe("NewJSONLogger", func() {
		It("should create logger with JSON handler", func() {
			logger := logging.NewJSONLogger(slog.LevelInfo)

			Expect(logger).NotTo(BeNil())
		})

		It("should accept Info level", func() {
			logger := logging.NewJSONLogger(slog.LevelInfo)

			Expect(logger).NotTo(BeNil())
		})

		It("should accept Warn level", func() {
			logger := logging.NewJSONLogger(slog.LevelWarn)

			Expect(logger).NotTo(BeNil())
		})

		It("should accept Error level", func() {
			logger := logging.NewJSONLogger(slog.LevelError)

			Expect(logger).NotTo(BeNil())
		})

		It("should produce JSON output", func() {
			// We can't easily capture stdout here, but we can verify it doesn't panic
			logger := logging.NewJSONLogger(slog.LevelInfo)

			Expect(func() {
				logger.Info("test message", "key", "value")
			}).NotTo(Panic())
		})
	})

	Describe("NewTextLogger", func() {
		It("should create logger with text handler", func() {
			logger := logging.NewTextLogger(slog.LevelInfo)

			Expect(logger).NotTo(BeNil())
		})

		It("should accept Info level", func() {
			logger := logging.NewTextLogger(slog.LevelInfo)

			Expect(logger).NotTo(BeNil())
		})

		It("should accept Warn level", func() {
			logger := logging.NewTextLogger(slog.LevelWarn)

			Expect(logger).NotTo(BeNil())
		})

		It("should accept Error level", func() {
			logger := logging.NewTextLogger(slog.LevelError)

			Expect(logger).NotTo(BeNil())
		})

		It("should produce text output", func() {
			// We can't easily capture stdout here, but we can verify it doesn't panic
			logger := logging.NewTextLogger(slog.LevelInfo)

			Expect(func() {
				logger.Info("test message", "key", "value")
			}).NotTo(Panic())
		})
	})
})

// ============================================================================
// Integration Tests
// ============================================================================

var _ = Describe("Integration", func() {
	Describe("Real-World Usage Patterns", func() {
		var (
			buf    *bytes.Buffer
			logger logging.Logger
		)

		BeforeEach(func() {
			buf = &bytes.Buffer{}
			handler := slog.NewJSONHandler(buf, &slog.HandlerOptions{
				Level: slog.LevelInfo,
			})
			logger = logging.NewSlogAdapter(slog.New(handler))
		})

		It("should handle KeyManager startup log pattern", func() {
			logger.Info("key manager started",
				"keyDirectory", "/keys",
				"rotationInterval", 30*24*time.Hour,
				"keySize", 2048)

			var logEntry map[string]interface{}
			err := json.Unmarshal(buf.Bytes(), &logEntry)
			Expect(err).NotTo(HaveOccurred())

			Expect(logEntry["msg"]).To(Equal("key manager started"))
			Expect(logEntry["keyDirectory"]).To(Equal("/keys"))
			Expect(logEntry["keySize"]).To(Equal(float64(2048)))
		})

		It("should handle key rotation log pattern", func() {
			logger.Info("key rotation successful",
				"oldKeyID", "abc-123",
				"newKeyID", "xyz-789",
				"duration", 150*time.Millisecond)

			output := buf.String()
			Expect(output).To(ContainSubstring("key rotation successful"))
			Expect(output).To(ContainSubstring("abc-123"))
			Expect(output).To(ContainSubstring("xyz-789"))
		})

		It("should handle error with context pattern", func() {
			logger.Error("key rotation failed",
				"error", "disk full",
				"keyID", "abc-123",
				"attempt", 3,
				"timestamp", time.Now())

			var logEntry map[string]interface{}
			err := json.Unmarshal(buf.Bytes(), &logEntry)
			Expect(err).NotTo(HaveOccurred())

			Expect(logEntry["level"]).To(Equal("ERROR"))
			Expect(logEntry["error"]).To(Equal("disk full"))
			Expect(logEntry["keyID"]).To(Equal("abc-123"))
			Expect(logEntry["attempt"]).To(Equal(float64(3)))
		})

		It("should handle warning with file info pattern", func() {
			logger.Warn("failed to load key file",
				"file", "corrupted.pem",
				"error", "invalid PEM format",
				"action", "skipped")

			var logEntry map[string]interface{}
			err := json.Unmarshal(buf.Bytes(), &logEntry)
			Expect(err).NotTo(HaveOccurred())

			Expect(logEntry["level"]).To(Equal("WARN"))
			Expect(logEntry["file"]).To(Equal("corrupted.pem"))
			Expect(logEntry["action"]).To(Equal("skipped"))
		})
	})

	Describe("Performance", func() {
		var logger logging.Logger

		BeforeEach(func() {
			buf := &bytes.Buffer{}
			handler := slog.NewJSONHandler(buf, nil)
			logger = logging.NewSlogAdapter(slog.New(handler))
		})

		It("should handle rapid logging without blocking", func() {
			start := time.Now()

			for i := 0; i < 1000; i++ {
				logger.Info("test message", "iteration", i)
			}

			duration := time.Since(start)
			// Should complete quickly (< 100ms for 1000 logs)
			Expect(duration).To(BeNumerically("<", 100*time.Millisecond))
		})

		It("should handle concurrent logging", func() {
			done := make(chan bool, 10)

			for i := 0; i < 10; i++ {
				go func(id int) {
					defer GinkgoRecover()
					for j := 0; j < 100; j++ {
						logger.Info("message", "goroutine", id, "iteration", j)
					}
					done <- true
				}(i)
			}

			// All should complete
			for i := 0; i < 10; i++ {
				Eventually(done).Should(Receive())
			}
		})
	})
})
