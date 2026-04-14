package logging_test

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aetomala/jwtauth/pkg/logging"
)

var _ = Describe("Correlation ID context helpers", func() {
	// Phase 1: WithCorrelationID and GetCorrelationID round-trip
	It("should store and retrieve the correlation ID", func() {
		ctx := logging.WithCorrelationID(context.Background(), "req-abc-123")

		Expect(logging.GetCorrelationID(ctx)).To(Equal("req-abc-123"))
	})

	// Phase 2: missing ID returns empty string
	It("should return empty string when no correlation ID is set", func() {
		Expect(logging.GetCorrelationID(context.Background())).To(Equal(""))
	})

	// Phase 3: key isolation — external packages cannot accidentally read or overwrite our key
	It("should not collide with keys set by other packages", func() {
		type externalKey string
		const externalCorrelationKey externalKey = "correlation_id"

		ctx := context.WithValue(context.Background(), externalCorrelationKey, "external-value")

		// Our helper must return "" because the key type is different
		Expect(logging.GetCorrelationID(ctx)).To(Equal(""))
	})

	// Phase 4: later value overwrites earlier value
	It("should return the most recently set correlation ID", func() {
		ctx := logging.WithCorrelationID(context.Background(), "first-id")
		ctx = logging.WithCorrelationID(ctx, "second-id")

		Expect(logging.GetCorrelationID(ctx)).To(Equal("second-id"))
	})

	// Phase 5: child context inherits the correlation ID from parent
	It("should be inherited by child contexts", func() {
		parent := logging.WithCorrelationID(context.Background(), "parent-corr-id")
		child, cancel := context.WithCancel(parent)
		defer cancel()

		Expect(logging.GetCorrelationID(child)).To(Equal("parent-corr-id"))
	})
})
