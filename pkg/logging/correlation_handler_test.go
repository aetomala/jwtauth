package logging_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aetomala/jwtauth/pkg/logging"
)

var _ = Describe("CorrelationIDHandler", func() {
	var (
		buf         *bytes.Buffer
		innerHandler slog.Handler
		corrHandler  *logging.CorrelationIDHandler
		adapter      logging.Logger
	)

	BeforeEach(func() {
		buf = &bytes.Buffer{}
		innerHandler = slog.NewJSONHandler(buf, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})
		corrHandler = logging.NewCorrelationIDHandler(innerHandler)
		adapter = logging.NewSlogAdapter(slog.New(corrHandler))
	})

	// Phase 1: Handle injects correlation_id when present in ctx
	It("should inject correlation_id into the log record when set in context", func() {
		ctx := logging.WithCorrelationID(context.Background(), "req-abc-123")

		adapter.Info("token refreshed", ctx, "user_id", "user-456")

		var entry map[string]interface{}
		Expect(json.Unmarshal(buf.Bytes(), &entry)).To(Succeed())
		Expect(entry["correlation_id"]).To(Equal("req-abc-123"))
		Expect(entry["user_id"]).To(Equal("user-456"))
		Expect(entry["msg"]).To(Equal("token refreshed"))
	})

	// Phase 2: Handle omits field when ctx has no correlation ID
	It("should not emit correlation_id when the context carries none", func() {
		adapter.Info("background operation", context.Background(), "task", "cleanup")

		var entry map[string]interface{}
		Expect(json.Unmarshal(buf.Bytes(), &entry)).To(Succeed())
		Expect(entry).NotTo(HaveKey("correlation_id"))
		Expect(entry["task"]).To(Equal("cleanup"))
	})

	// Phase 3: WithAttrs preserves the CorrelationIDHandler wrapper
	It("should return a CorrelationIDHandler from WithAttrs", func() {
		enriched := corrHandler.WithAttrs([]slog.Attr{slog.String("service", "auth")})

		_, ok := enriched.(*logging.CorrelationIDHandler)
		Expect(ok).To(BeTrue())
	})

	It("should still inject correlation_id after WithAttrs", func() {
		enriched := corrHandler.WithAttrs([]slog.Attr{slog.String("service", "auth")})
		enrichedAdapter := logging.NewSlogAdapter(slog.New(enriched))

		ctx := logging.WithCorrelationID(context.Background(), "enriched-corr-id")
		enrichedAdapter.Info("test", ctx)

		var entry map[string]interface{}
		Expect(json.Unmarshal(buf.Bytes(), &entry)).To(Succeed())
		Expect(entry["correlation_id"]).To(Equal("enriched-corr-id"))
		Expect(entry["service"]).To(Equal("auth"))
	})

	// Phase 4: WithGroup preserves the CorrelationIDHandler wrapper
	It("should return a CorrelationIDHandler from WithGroup", func() {
		grouped := corrHandler.WithGroup("request")

		_, ok := grouped.(*logging.CorrelationIDHandler)
		Expect(ok).To(BeTrue())
	})

	// Phase 5: Enabled delegates to inner handler
	It("should delegate Enabled to the inner handler", func() {
		warnHandler := slog.NewJSONHandler(&bytes.Buffer{}, &slog.HandlerOptions{
			Level: slog.LevelWarn,
		})
		warnCorrHandler := logging.NewCorrelationIDHandler(warnHandler)

		Expect(warnCorrHandler.Enabled(context.Background(), slog.LevelDebug)).To(BeFalse())
		Expect(warnCorrHandler.Enabled(context.Background(), slog.LevelInfo)).To(BeFalse())
		Expect(warnCorrHandler.Enabled(context.Background(), slog.LevelWarn)).To(BeTrue())
		Expect(warnCorrHandler.Enabled(context.Background(), slog.LevelError)).To(BeTrue())
	})
})
