package storage_test

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"github.com/aetomala/jwtauth/internal/testutil"
	"github.com/aetomala/jwtauth/pkg/metrics"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/aetomala/jwtauth/pkg/tracing"
)

var _ = RunRefreshStoreTests(
	"MemoryRefreshStore", "memory",
	// Factory: creates MemoryRefreshStore
	func(logger *testutil.MockLogger, m metrics.Metrics) storage.RefreshStore {
		return storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{Logger: logger, Metrics: m})
	},
	// Cleanup: nil (memory needs no cleanup)
	nil,
)

var _ = Describe("MemoryRefreshStore — Constructor", func() {
	ctx := context.Background()

	It("should apply defaults from MemoryRefreshStoreConfigDefault when optional fields are nil", func() {
		store := storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{})
		tokenID := "defaults-token"
		userID := "defaults-user"
		Expect(store.Store(ctx, tokenID, userID, nil, time.Now().Add(time.Hour), nil)).To(Succeed())
		_, err := store.Retrieve(ctx, tokenID)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should accept an explicit Tracer without error", func() {
		ctrl := gomock.NewController(GinkgoT())
		defer ctrl.Finish()
		mockTracer := testutil.NewMockTracer(ctrl)
		mockSpan := testutil.NewMockSpan(ctrl)
		mockTracer.EXPECT().Start(gomock.Any(), gomock.Any(), gomock.Any()).Return(ctx, mockSpan).AnyTimes()
		mockSpan.EXPECT().End().AnyTimes()
		mockSpan.EXPECT().SetAttribute(gomock.Any(), gomock.Any()).AnyTimes()
		mockSpan.EXPECT().SetStatus(gomock.Any(), gomock.Any()).AnyTimes()

		store := storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{Tracer: mockTracer})
		tokenID := "tracer-token"
		userID := "tracer-user"
		Expect(store.Store(ctx, tokenID, userID, nil, time.Now().Add(time.Hour), nil)).To(Succeed())
	})
})

// PHASE 16: ListTokensForAudience — Memory-only specs.
//
// These specs cover the MemoryRefreshStore implementation. The shared suite
// (suite_test.go Phase 16) is promoted here once the Redis implementation
// ships in Phase 2.
var _ = Describe("MemoryRefreshStore — Phase 16: ListTokensForAudience", func() {
	var (
		store     *storage.MemoryRefreshStore
		ctx       context.Context
		expiresAt time.Time
	)

	BeforeEach(func() {
		ctx = context.Background()
		expiresAt = time.Now().Add(24 * time.Hour)
		store = storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{})
	})

	It("should return empty result for an audience with no tokens", func() {
		tokens, next, err := store.ListTokensForAudience(ctx, "svc-ghost", "", 10)
		Expect(err).NotTo(HaveOccurred())
		Expect(tokens).To(BeEmpty())
		Expect(next).To(BeEmpty())
	})

	It("should return all tokens for an audience in a single page", func() {
		aud := "svc-payments-single"
		ids := []string{"aud-tok-a", "aud-tok-b", "aud-tok-c"}
		for _, id := range ids {
			Expect(store.Store(ctx, id, "user-aud", []string{aud}, expiresAt, nil)).To(Succeed())
		}

		tokens, next, err := store.ListTokensForAudience(ctx, aud, "", 100)
		Expect(err).NotTo(HaveOccurred())
		Expect(next).To(BeEmpty())
		got := make(map[string]bool)
		for _, t := range tokens {
			got[t.TokenID] = true
		}
		for _, id := range ids {
			Expect(got[id]).To(BeTrue(), "expected token %s in result", id)
		}
	})

	It("should paginate across multiple pages and exhaust the set", func() {
		aud := "svc-paginate-aud"
		total := 7
		for i := 0; i < total; i++ {
			Expect(store.Store(ctx, fmt.Sprintf("aud-page-tok-%d", i), "user-p", []string{aud}, expiresAt, nil)).To(Succeed())
		}

		var all []*storage.RefreshToken
		cursor := ""
		for {
			page, next, err := store.ListTokensForAudience(ctx, aud, cursor, 3)
			Expect(err).NotTo(HaveOccurred())
			all = append(all, page...)
			cursor = next
			if cursor == "" {
				break
			}
		}
		Expect(all).To(HaveLen(total))
	})

	It("should not include tokens from a different audience", func() {
		audA := "svc-iso-aud-a"
		audB := "svc-iso-aud-b"
		Expect(store.Store(ctx, "aud-iso-tok-a1", "user-ia", []string{audA}, expiresAt, nil)).To(Succeed())
		Expect(store.Store(ctx, "aud-iso-tok-a2", "user-ia", []string{audA}, expiresAt, nil)).To(Succeed())
		Expect(store.Store(ctx, "aud-iso-tok-b1", "user-ib", []string{audB}, expiresAt, nil)).To(Succeed())

		tokensA, _, err := store.ListTokensForAudience(ctx, audA, "", 100)
		Expect(err).NotTo(HaveOccurred())
		Expect(tokensA).To(HaveLen(2))
		for _, t := range tokensA {
			Expect(t.Audience).To(ContainElement(audA))
		}

		tokensB, _, err := store.ListTokensForAudience(ctx, audB, "", 100)
		Expect(err).NotTo(HaveOccurred())
		Expect(tokensB).To(HaveLen(1))
		Expect(tokensB[0].TokenID).To(Equal("aud-iso-tok-b1"))
	})

	It("should return ErrInvalidAudience for empty audience", func() {
		_, _, err := store.ListTokensForAudience(ctx, "", "", 10)
		Expect(err).To(MatchError(storage.ErrInvalidAudience))
	})

	It("should return empty next cursor when iteration is exhausted", func() {
		aud := "svc-exhaust-aud"
		Expect(store.Store(ctx, "aud-exhaust-1", "user-e", []string{aud}, expiresAt, nil)).To(Succeed())
		Expect(store.Store(ctx, "aud-exhaust-2", "user-e", []string{aud}, expiresAt, nil)).To(Succeed())

		_, finalCursor, err := store.ListTokensForAudience(ctx, aud, "", 100)
		Expect(err).NotTo(HaveOccurred())
		Expect(finalCursor).To(BeEmpty())
	})

	It("should return context error on cancelled context", func() {
		cancelledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		_, _, err := store.ListTokensForAudience(cancelledCtx, "svc-payments", "", 10)
		Expect(err).To(MatchError(context.Canceled))
	})

	It("should return revoked and active tokens for the audience", func() {
		aud := "svc-mixed-aud"
		active := "aud-tok-active"
		revoked := "aud-tok-revoked"

		Expect(store.Store(ctx, active, "user-m", []string{aud}, expiresAt, nil)).To(Succeed())
		Expect(store.Store(ctx, revoked, "user-m", []string{aud}, expiresAt, nil)).To(Succeed())
		Expect(store.Revoke(ctx, revoked)).To(Succeed())

		var all []*storage.RefreshToken
		cursor := ""
		for {
			page, next, err := store.ListTokensForAudience(ctx, aud, cursor, 100)
			Expect(err).NotTo(HaveOccurred())
			all = append(all, page...)
			cursor = next
			if cursor == "" {
				break
			}
		}

		tokenIDs := map[string]bool{}
		for _, t := range all {
			tokenIDs[t.TokenID] = true
		}
		Expect(tokenIDs[active]).To(BeTrue(), "active token missing from ListTokensForAudience")
		Expect(tokenIDs[revoked]).To(BeTrue(), "revoked token missing from ListTokensForAudience")
	})

	It("should return a multi-audience token in listings for each of its audiences", func() {
		audA := "svc-multi-a"
		audB := "svc-multi-b"
		Expect(store.Store(ctx, "aud-multi-tok", "user-multi", []string{audA, audB}, expiresAt, nil)).To(Succeed())

		tokensA, _, err := store.ListTokensForAudience(ctx, audA, "", 100)
		Expect(err).NotTo(HaveOccurred())
		Expect(tokensA).To(HaveLen(1))
		Expect(tokensA[0].TokenID).To(Equal("aud-multi-tok"))

		tokensB, _, err := store.ListTokensForAudience(ctx, audB, "", 100)
		Expect(err).NotTo(HaveOccurred())
		Expect(tokensB).To(HaveLen(1))
		Expect(tokensB[0].TokenID).To(Equal("aud-multi-tok"))
	})
})

// ===== PHASE 10: Tracing =====
var _ = Describe("MemoryRefreshStore — Phase 10: Tracing", func() {
	var (
		ctrl         *gomock.Controller
		mockTracer   *testutil.MockTracer
		mockSpan     *testutil.MockSpan
		tracingStore *storage.MemoryRefreshStore
		ctx          context.Context
	)

	BeforeEach(func() {
		ctx = context.Background()
		ctrl = gomock.NewController(GinkgoT())
		mockTracer = testutil.NewMockTracer(ctrl)
		mockSpan = testutil.NewMockSpan(ctrl)
		tracingStore = storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{Tracer: mockTracer})
	})

	AfterEach(func() { ctrl.Finish() })

	Context("Store — success path", func() {
		It("should start a span named MemoryRefreshStore.Store with storage.backend, token_id and StatusOK", func() {
			mockTracer.EXPECT().Start(gomock.Any(), "MemoryRefreshStore.Store", gomock.Any()).Return(ctx, mockSpan)
			mockSpan.EXPECT().SetAttribute("token_id", "trace-store-token")
			mockSpan.EXPECT().SetStatus(tracing.StatusOK, "")
			mockSpan.EXPECT().End()

			Expect(tracingStore.Store(ctx, "trace-store-token", "trace-user", nil, time.Now().Add(time.Hour), nil)).To(Succeed())
		})
	})

	Context("Retrieve — error path", func() {
		It("should call RecordError and StatusError when token is not found", func() {
			mockTracer.EXPECT().Start(gomock.Any(), "MemoryRefreshStore.Retrieve", gomock.Any()).Return(ctx, mockSpan)
			mockSpan.EXPECT().SetAttribute("token_id", "missing-trace-token")
			mockSpan.EXPECT().RecordError(storage.ErrTokenNotFound)
			mockSpan.EXPECT().SetStatus(tracing.StatusError, gomock.Any())
			mockSpan.EXPECT().End()

			_, err := tracingStore.Retrieve(ctx, "missing-trace-token")
			Expect(err).To(MatchError(storage.ErrTokenNotFound))
		})
	})
})

