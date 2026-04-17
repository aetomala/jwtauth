package tracing_test

import (
	"context"
	"fmt"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aetomala/jwtauth/pkg/tracing"
)

func TestTracing(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Tracing Suite")
}

var _ = Describe("NoOpTracer", func() {
	var (
		tracer tracing.Tracer
		ctx    context.Context
	)

	BeforeEach(func() {
		tracer = tracing.NewNoOpTracer()
		ctx = context.Background()
	})

	// ===== PHASE 1: Constructor and Initialization =====
	Describe("Constructor", func() {
		It("should create a non-nil tracer", func() {
			Expect(tracer).NotTo(BeNil())
		})

		It("should return a NoOpTracer type", func() {
			_, ok := tracer.(*tracing.NoOpTracer)
			Expect(ok).To(BeTrue())
		})
	})

	// ===== PHASE 2: Span Creation =====
	Describe("Start", func() {
		Context("basic span creation", func() {
			It("should return the same context unchanged", func() {
				newCtx, span := tracer.Start(ctx, "test.operation")

				Expect(newCtx).To(Equal(ctx))
				Expect(span).NotTo(BeNil())
			})

			It("should return a NoOpSpan type", func() {
				_, span := tracer.Start(ctx, "test.operation")

				_, ok := span.(*tracing.NoOpSpan)
				Expect(ok).To(BeTrue())
			})
		})

		Context("with span options", func() {
			It("should accept WithSpanKind option without error", func() {
				_, span := tracer.Start(ctx, "test.operation",
					tracing.WithSpanKind(tracing.SpanKindServer),
				)

				Expect(span).NotTo(BeNil())
			})

			It("should accept WithAttributes option without error", func() {
				_, span := tracer.Start(ctx, "test.operation",
					tracing.WithAttributes(map[string]any{
						"user_id": "user-123",
						"count":   42,
					}),
				)

				Expect(span).NotTo(BeNil())
			})

			It("should accept multiple options without error", func() {
				_, span := tracer.Start(ctx, "test.operation",
					tracing.WithSpanKind(tracing.SpanKindClient),
					tracing.WithAttributes(map[string]any{
						"endpoint": "/api/users",
					}),
				)

				Expect(span).NotTo(BeNil())
			})
		})

		Context("with different operation names", func() {
			It("should handle empty operation name", func() {
				_, span := tracer.Start(ctx, "")

				Expect(span).NotTo(BeNil())
			})

			It("should handle long operation name", func() {
				longName := "very.long.operation.name.with.many.segments.TokenService.RefreshAccessToken.WithMetadata"
				_, span := tracer.Start(ctx, longName)

				Expect(span).NotTo(BeNil())
			})

			It("should handle special characters in operation name", func() {
				_, span := tracer.Start(ctx, "test/operation:with-special.chars_123")

				Expect(span).NotTo(BeNil())
			})
		})
	})

	// ===== PHASE 3: Span Operations (No-Ops) =====
	Describe("NoOpSpan Operations", func() {
		var span tracing.Span

		BeforeEach(func() {
			_, span = tracer.Start(ctx, "test.operation")
		})

		Context("End", func() {
			It("should not panic when called", func() {
				Expect(func() {
					span.End()
				}).NotTo(Panic())
			})

			It("should not panic when called multiple times", func() {
				Expect(func() {
					span.End()
					span.End()
					span.End()
				}).NotTo(Panic())
			})
		})

		Context("SetAttribute", func() {
			It("should not panic with string value", func() {
				Expect(func() {
					span.SetAttribute("key", "value")
				}).NotTo(Panic())
			})

			It("should not panic with int value", func() {
				Expect(func() {
					span.SetAttribute("count", 42)
				}).NotTo(Panic())
			})

			It("should not panic with int64 value", func() {
				Expect(func() {
					span.SetAttribute("timestamp", int64(1234567890))
				}).NotTo(Panic())
			})

			It("should not panic with float64 value", func() {
				Expect(func() {
					span.SetAttribute("duration", 3.14)
				}).NotTo(Panic())
			})

			It("should not panic with bool value", func() {
				Expect(func() {
					span.SetAttribute("success", true)
				}).NotTo(Panic())
			})

			It("should not panic with nil value", func() {
				Expect(func() {
					span.SetAttribute("nullable", nil)
				}).NotTo(Panic())
			})

			It("should not panic with empty key", func() {
				Expect(func() {
					span.SetAttribute("", "value")
				}).NotTo(Panic())
			})
		})

		Context("SetAttributes", func() {
			It("should not panic with empty map", func() {
				Expect(func() {
					span.SetAttributes(map[string]any{})
				}).NotTo(Panic())
			})

			It("should not panic with nil map", func() {
				Expect(func() {
					span.SetAttributes(nil)
				}).NotTo(Panic())
			})

			It("should not panic with multiple attributes", func() {
				Expect(func() {
					span.SetAttributes(map[string]any{
						"user_id":  "user-123",
						"count":    42,
						"duration": 3.14,
						"success":  true,
					})
				}).NotTo(Panic())
			})
		})

		Context("RecordError", func() {
			It("should not panic with error", func() {
				Expect(func() {
					span.RecordError(context.DeadlineExceeded)
				}).NotTo(Panic())
			})

			It("should not panic with nil error", func() {
				Expect(func() {
					span.RecordError(nil)
				}).NotTo(Panic())
			})
		})

		Context("SetStatus", func() {
			It("should not panic with StatusOK", func() {
				Expect(func() {
					span.SetStatus(tracing.StatusOK, "")
				}).NotTo(Panic())
			})

			It("should not panic with StatusError", func() {
				Expect(func() {
					span.SetStatus(tracing.StatusError, "something failed")
				}).NotTo(Panic())
			})

			It("should not panic with StatusUnset", func() {
				Expect(func() {
					span.SetStatus(tracing.StatusUnset, "")
				}).NotTo(Panic())
			})

			It("should not panic with empty description", func() {
				Expect(func() {
					span.SetStatus(tracing.StatusError, "")
				}).NotTo(Panic())
			})
		})
	})

	// ===== PHASE 4: Typical Usage Pattern =====
	Describe("Typical Usage Pattern", func() {
		It("should support defer pattern without panic", func() {
			Expect(func() {
				_, span := tracer.Start(ctx, "operation")
				defer span.End()

				span.SetAttribute("user_id", "user-123")
				span.SetStatus(tracing.StatusOK, "")
			}).NotTo(Panic())
		})

		It("should support error handling pattern without panic", func() {
			Expect(func() {
				_, span := tracer.Start(ctx, "operation")
				defer span.End()

				err := context.DeadlineExceeded
				if err != nil {
					span.RecordError(err)
					span.SetStatus(tracing.StatusError, "operation failed")
				}
			}).NotTo(Panic())
		})

		It("should support nested spans without panic", func() {
			Expect(func() {
				ctx, span1 := tracer.Start(ctx, "parent")
				defer span1.End()

				ctx, span2 := tracer.Start(ctx, "child1")
				defer span2.End()

				_, span3 := tracer.Start(ctx, "child2")
				defer span3.End()
			}).NotTo(Panic())
		})
	})

	// ===== PHASE 5: Thread Safety =====
	Describe("Concurrent Usage", func() {
		It("should be safe for concurrent span creation", func() {
			const goroutines = 100

			done := make(chan bool, goroutines)

			for i := range goroutines {
				go func(i int) {
					defer GinkgoRecover()
					_, span := tracer.Start(ctx, "concurrent.operation")
					defer span.End()

					span.SetAttribute("iteration", i)
					span.SetStatus(tracing.StatusOK, "")

					done <- true
				}(i)
			}

			for range goroutines {
				Eventually(done).Should(Receive())
			}
		})

		It("should be safe for concurrent operations on same span", func() {
			_, span := tracer.Start(ctx, "concurrent.span")
			defer span.End()

			const goroutines = 50
			done := make(chan bool, goroutines)

			for i := range goroutines {
				go func(id int) {
					defer GinkgoRecover()
					span.SetAttribute("goroutine", id)
					done <- true
				}(i)
			}

			for range goroutines {
				Eventually(done).Should(Receive())
			}
		})
	})

	// ===== PHASE 6: Edge Cases =====
	Describe("Edge Cases", func() {
		It("should handle very large attribute values", func() {
			_, span := tracer.Start(ctx, "large.data")
			defer span.End()

			largeString := make([]byte, 1024*1024) // 1MB string
			for i := range largeString {
				largeString[i] = 'x'
			}

			Expect(func() {
				span.SetAttribute("large_data", string(largeString))
			}).NotTo(Panic())
		})

		It("should handle many attributes", func() {
			_, span := tracer.Start(ctx, "many.attributes")
			defer span.End()

			attrs := make(map[string]any)
			for i := range 1000 {
				attrs[fmt.Sprintf("attr_%d", i)] = i
			}

			Expect(func() {
				span.SetAttributes(attrs)
			}).NotTo(Panic())
		})

		It("should handle rapid span creation and destruction", func() {
			Expect(func() {
				for range 1000 {
					_, span := tracer.Start(ctx, "rapid.span")
					span.End()
				}
			}).NotTo(Panic())
		})
	})
})
