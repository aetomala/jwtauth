// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package tracing_test

import (
	"context"
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/aetomala/jwtauth/pkg/tracing"
)

var _ = Describe("OtelTracer", func() {
	var (
		exporter *tracetest.InMemoryExporter
		otracer  *tracing.OtelTracer
		ctx      context.Context
		cancel   context.CancelFunc
	)

	BeforeEach(func() {
		exporter = tracetest.NewInMemoryExporter()
		provider := sdktrace.NewTracerProvider(
			sdktrace.WithSyncer(exporter),
		)
		otel.SetTracerProvider(provider)
		otracer = tracing.NewOtelTracer("test-scope")
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	})

	AfterEach(func() {
		cancel()
		otel.SetTracerProvider(noop.NewTracerProvider())
		exporter.Reset()
	})

	latestSpan := func() tracetest.SpanStub {
		spans := exporter.GetSpans()
		Expect(spans).NotTo(BeEmpty())
		return spans[len(spans)-1]
	}

	findAttr := func(attrs []attribute.KeyValue, key string) (attribute.Value, bool) {
		for _, kv := range attrs {
			if string(kv.Key) == key {
				return kv.Value, true
			}
		}
		return attribute.Value{}, false
	}

	// ===== PHASE 1: Constructor and Initialization =====
	Describe("Phase 1: Constructor and Initialization", func() {
		It("should return a non-nil OtelTracer", func() {
			Expect(otracer).NotTo(BeNil())
		})

		It("should satisfy the Tracer interface", func() {
			var _ tracing.Tracer = otracer
			Expect(otracer).To(BeAssignableToTypeOf(&tracing.OtelTracer{}))
		})

		It("should accept different scope names without error", func() {
			t1 := tracing.NewOtelTracer("scope-a")
			t2 := tracing.NewOtelTracer("scope-b")
			Expect(t1).NotTo(BeNil())
			Expect(t2).NotTo(BeNil())
		})
	})

	// ===== PHASE 2: Start — Context and Span Creation =====
	Describe("Phase 2: Start — Context and Span Creation", func() {
		It("should return a non-nil context", func() {
			newCtx, span := otracer.Start(ctx, "test.operation")
			defer span.End()
			Expect(newCtx).NotTo(BeNil())
		})

		It("should return a context distinct from the input context", func() {
			newCtx, span := otracer.Start(ctx, "test.operation")
			defer span.End()
			Expect(newCtx).NotTo(Equal(ctx))
		})

		It("should return a non-nil Span", func() {
			_, span := otracer.Start(ctx, "test.operation")
			defer span.End()
			Expect(span).NotTo(BeNil())
		})

		It("should satisfy the Span interface", func() {
			_, span := otracer.Start(ctx, "test.operation")
			defer span.End()
			Expect(span).To(BeAssignableToTypeOf(&tracing.OtelSpan{}))
		})

		It("should record the span name correctly", func() {
			_, span := otracer.Start(ctx, "my.operation.name")
			span.End()
			Expect(latestSpan().Name).To(Equal("my.operation.name"))
		})
	})

	// ===== PHASE 3: Span Operations =====
	Describe("Phase 3: Span Operations", func() {
		var span tracing.Span

		BeforeEach(func() {
			_, span = otracer.Start(ctx, "test.operation")
		})

		Context("End", func() {
			It("should not panic when called", func() {
				Expect(func() { span.End() }).NotTo(Panic())
			})

			It("should not panic when called multiple times", func() {
				Expect(func() {
					span.End()
					span.End()
				}).NotTo(Panic())
			})
		})

		Context("SetAttribute", func() {
			It("should record a string attribute", func() {
				span.SetAttribute("key", "hello")
				span.End()
				val, found := findAttr(latestSpan().Attributes, "key")
				Expect(found).To(BeTrue())
				Expect(val.AsString()).To(Equal("hello"))
			})

			It("should record an int attribute", func() {
				span.SetAttribute("count", 42)
				span.End()
				val, found := findAttr(latestSpan().Attributes, "count")
				Expect(found).To(BeTrue())
				Expect(val.AsInt64()).To(Equal(int64(42)))
			})

			It("should record an int64 attribute", func() {
				span.SetAttribute("ts", int64(9876543210))
				span.End()
				val, found := findAttr(latestSpan().Attributes, "ts")
				Expect(found).To(BeTrue())
				Expect(val.AsInt64()).To(Equal(int64(9876543210)))
			})

			It("should record a float64 attribute", func() {
				span.SetAttribute("ratio", 3.14)
				span.End()
				val, found := findAttr(latestSpan().Attributes, "ratio")
				Expect(found).To(BeTrue())
				Expect(val.AsFloat64()).To(BeNumerically("~", 3.14, 0.001))
			})

			It("should record a bool attribute", func() {
				span.SetAttribute("ok", true)
				span.End()
				val, found := findAttr(latestSpan().Attributes, "ok")
				Expect(found).To(BeTrue())
				Expect(val.AsBool()).To(BeTrue())
			})
		})

		Context("SetAttributes", func() {
			It("should record all provided attributes", func() {
				span.SetAttributes(map[string]any{
					"a": "alpha",
					"b": 99,
					"c": false,
				})
				span.End()
				attrs := latestSpan().Attributes
				_, foundA := findAttr(attrs, "a")
				_, foundB := findAttr(attrs, "b")
				_, foundC := findAttr(attrs, "c")
				Expect(foundA).To(BeTrue())
				Expect(foundB).To(BeTrue())
				Expect(foundC).To(BeTrue())
			})

			It("should not panic with an empty map", func() {
				Expect(func() {
					span.SetAttributes(map[string]any{})
					span.End()
				}).NotTo(Panic())
			})
		})

		Context("RecordError", func() {
			It("should record an error event on the span", func() {
				span.RecordError(errors.New("something failed"))
				span.End()
				events := latestSpan().Events
				Expect(events).NotTo(BeEmpty())
				Expect(events[0].Name).To(Equal("exception"))
			})

			It("should set the span status to Error", func() {
				span.RecordError(errors.New("boom"))
				span.End()
				Expect(latestSpan().Status.Code).To(Equal(codes.Error))
			})

			It("should be a no-op when err is nil", func() {
				span.RecordError(nil)
				span.End()
				Expect(latestSpan().Events).To(BeEmpty())
				Expect(latestSpan().Status.Code).To(Equal(codes.Unset))
			})
		})

		Context("SetStatus", func() {
			It("should set StatusOK", func() {
				span.SetStatus(tracing.StatusOK, "")
				span.End()
				Expect(latestSpan().Status.Code).To(Equal(codes.Ok))
			})

			It("should set StatusError with description", func() {
				span.SetStatus(tracing.StatusError, "operation failed")
				span.End()
				s := latestSpan().Status
				Expect(s.Code).To(Equal(codes.Error))
				Expect(s.Description).To(Equal("operation failed"))
			})

			It("should set StatusUnset", func() {
				span.SetStatus(tracing.StatusUnset, "")
				span.End()
				Expect(latestSpan().Status.Code).To(Equal(codes.Unset))
			})
		})
	})

	// ===== PHASE 4: toOtelAttribute Type Dispatch =====
	Describe("Phase 4: toOtelAttribute Type Dispatch", func() {
		var span tracing.Span

		BeforeEach(func() {
			_, span = otracer.Start(ctx, "type.dispatch")
		})

		DescribeTable("maps Go types to OTel attribute types",
			func(value any, expectedType attribute.Type) {
				span.SetAttribute("key", value)
				span.End()
				val, found := findAttr(latestSpan().Attributes, "key")
				Expect(found).To(BeTrue())
				Expect(val.Type()).To(Equal(expectedType))
			},
			Entry("string → STRING", "hello", attribute.STRING),
			Entry("int → INT64", 42, attribute.INT64),
			Entry("int64 → INT64", int64(99), attribute.INT64),
			Entry("float64 → FLOAT64", 1.5, attribute.FLOAT64),
			Entry("bool → BOOL", true, attribute.BOOL),
			Entry("unknown type → STRING (Sprintf fallback)", struct{}{}, attribute.STRING),
		)
	})

	// ===== PHASE 5: Typical Usage Pattern =====
	Describe("Phase 5: Typical Usage Pattern", func() {
		It("should record the span when using the defer End pattern", func() {
			func() {
				_, span := otracer.Start(ctx, "deferred.op")
				defer span.End()
				span.SetAttribute("user_id", "u-1")
				span.SetStatus(tracing.StatusOK, "")
			}()
			Expect(latestSpan().Name).To(Equal("deferred.op"))
		})

		It("should record a valid parent span ID for a nested span", func() {
			parentCtx, parentSpan := otracer.Start(ctx, "parent")
			_, childSpan := otracer.Start(parentCtx, "child")
			childSpan.End()
			parentSpan.End()

			spans := exporter.GetSpans()
			Expect(spans).To(HaveLen(2))

			child := spans[0]
			parent := spans[1]
			Expect(child.Parent.SpanID()).To(Equal(parent.SpanContext.SpanID()))
		})

		It("should reflect both RecordError and SetStatus on the span", func() {
			_, span := otracer.Start(ctx, "error.op")
			err := errors.New("service unavailable")
			span.RecordError(err)
			span.SetStatus(tracing.StatusError, "service unavailable")
			span.End()

			s := latestSpan()
			Expect(s.Status.Code).To(Equal(codes.Error))
			Expect(s.Events).NotTo(BeEmpty())
		})
	})

	// ===== PHASE 6: Concurrent Usage =====
	Describe("Phase 6: Concurrent Usage", func() {
		It("should be safe for concurrent span creation and ending", func() {
			const goroutines = 100
			done := make(chan bool, goroutines)

			for i := range goroutines {
				go func(i int) {
					defer GinkgoRecover()
					_, span := otracer.Start(ctx, "concurrent.op")
					span.SetAttribute("iteration", i)
					span.End()
					done <- true
				}(i)
			}

			for range goroutines {
				Eventually(done).Should(Receive())
			}
		})

		It("should be safe for concurrent SetAttribute calls on the same span", func() {
			_, span := otracer.Start(ctx, "concurrent.span")
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
})
