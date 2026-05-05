package storage_test

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"github.com/aetomala/jwtauth/internal/testutil"
	"github.com/aetomala/jwtauth/pkg/metrics"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/aetomala/jwtauth/pkg/tracing"
)

// newMemStore returns a bare MemoryRefreshStore for audience revocation tests.
func newMemStore() *storage.MemoryRefreshStore {
	return storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{})
}

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

// ===== PHASE 14: RevokeAllForAudience =====
var _ = Describe("MemoryRefreshStore — Phase 14: RevokeAllForAudience", func() {
	var (
		store     *storage.MemoryRefreshStore
		ctx       context.Context
		cancel    context.CancelFunc
		userID    string
		expiresAt time.Time
	)

	BeforeEach(func() {
		store = newMemStore()
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		userID = "user-aud-test"
		expiresAt = time.Now().Add(24 * time.Hour)
	})

	AfterEach(func() { cancel() })

	It("should revoke all tokens for the target audience and return the count", func() {
		aud := []string{"svc-payments"}
		Expect(store.Store(ctx, "tok-pay-1", userID, aud, expiresAt, nil)).To(Succeed())
		Expect(store.Store(ctx, "tok-pay-2", userID, aud, expiresAt, nil)).To(Succeed())

		n, err := store.RevokeAllForAudience(ctx, "svc-payments")
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal(2))

		_, err = store.Retrieve(ctx, "tok-pay-1")
		Expect(err).To(MatchError(storage.ErrTokenRevoked))
		_, err = store.Retrieve(ctx, "tok-pay-2")
		Expect(err).To(MatchError(storage.ErrTokenRevoked))
	})

	It("should not affect tokens issued for a different audience", func() {
		Expect(store.Store(ctx, "tok-pay", userID, []string{"svc-payments"}, expiresAt, nil)).To(Succeed())
		Expect(store.Store(ctx, "tok-rep", userID, []string{"svc-reports"}, expiresAt, nil)).To(Succeed())

		_, err := store.RevokeAllForAudience(ctx, "svc-payments")
		Expect(err).NotTo(HaveOccurred())

		_, err = store.Retrieve(ctx, "tok-pay")
		Expect(err).To(MatchError(storage.ErrTokenRevoked))

		tok, err := store.Retrieve(ctx, "tok-rep")
		Expect(err).NotTo(HaveOccurred())
		Expect(tok.Revoked).To(BeFalse())
	})

	It("should not affect tokens issued with no audience", func() {
		Expect(store.Store(ctx, "tok-noaud", userID, nil, expiresAt, nil)).To(Succeed())

		_, err := store.RevokeAllForAudience(ctx, "svc-payments")
		Expect(err).NotTo(HaveOccurred())

		tok, err := store.Retrieve(ctx, "tok-noaud")
		Expect(err).NotTo(HaveOccurred())
		Expect(tok.Revoked).To(BeFalse())
	})

	It("should revoke a multi-audience token when either audience is targeted", func() {
		Expect(store.Store(ctx, "tok-multi", userID, []string{"svc-payments", "svc-reports"}, expiresAt, nil)).To(Succeed())

		n, err := store.RevokeAllForAudience(ctx, "svc-payments")
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal(1))

		_, err = store.Retrieve(ctx, "tok-multi")
		Expect(err).To(MatchError(storage.ErrTokenRevoked))
	})

	It("should count already-revoked tokens and not error (idempotent)", func() {
		Expect(store.Store(ctx, "tok-pre-rev", userID, []string{"svc-payments"}, expiresAt, nil)).To(Succeed())
		Expect(store.Revoke(ctx, "tok-pre-rev")).To(Succeed())

		n, err := store.RevokeAllForAudience(ctx, "svc-payments")
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal(1))
	})

	It("should return zero count and no error when audience has no tokens", func() {
		n, err := store.RevokeAllForAudience(ctx, "svc-nonexistent")
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal(0))
	})

	It("should return ErrInvalidAudience for empty audience", func() {
		_, err := store.RevokeAllForAudience(ctx, "")
		Expect(err).To(MatchError(storage.ErrInvalidAudience))
	})

	It("should return ErrInvalidAudience for whitespace-only audience", func() {
		_, err := store.RevokeAllForAudience(ctx, "   ")
		Expect(err).To(MatchError(storage.ErrInvalidAudience))
	})

	It("should return context error on cancelled context", func() {
		cancelledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := store.RevokeAllForAudience(cancelledCtx, "svc-payments")
		Expect(err).To(MatchError(context.Canceled))
	})

	It("should prune stale audience index entries after Cleanup", func() {
		shortExp := time.Now().Add(50 * time.Millisecond)
		Expect(store.Store(ctx, "tok-expire", userID, []string{"svc-payments"}, shortExp, nil)).To(Succeed())

		time.Sleep(100 * time.Millisecond)
		_, err := store.Cleanup(ctx)
		Expect(err).NotTo(HaveOccurred())

		// Revoking now should return 0 — stale ID was pruned by Cleanup
		n, err := store.RevokeAllForAudience(ctx, "svc-payments")
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal(0))
	})
})

// ===== PHASE 15: RevokeAllForUserAndAudience =====
var _ = Describe("MemoryRefreshStore — Phase 15: RevokeAllForUserAndAudience", func() {
	var (
		store     *storage.MemoryRefreshStore
		ctx       context.Context
		cancel    context.CancelFunc
		userID    string
		expiresAt time.Time
	)

	BeforeEach(func() {
		store = newMemStore()
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		userID = "user-ua-test"
		expiresAt = time.Now().Add(24 * time.Hour)
	})

	AfterEach(func() { cancel() })

	It("should revoke only the specified user's tokens for that audience", func() {
		user1 := "user-aud-1"
		user2 := "user-aud-2"
		aud := []string{"svc-payments"}

		Expect(store.Store(ctx, "tok-u1-pay", user1, aud, expiresAt, nil)).To(Succeed())
		Expect(store.Store(ctx, "tok-u2-pay", user2, aud, expiresAt, nil)).To(Succeed())

		n, err := store.RevokeAllForUserAndAudience(ctx, user1, "svc-payments")
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal(1))

		_, err = store.Retrieve(ctx, "tok-u1-pay")
		Expect(err).To(MatchError(storage.ErrTokenRevoked))

		tok, err := store.Retrieve(ctx, "tok-u2-pay")
		Expect(err).NotTo(HaveOccurred())
		Expect(tok.Revoked).To(BeFalse())
	})

	It("should not affect the same user's tokens for a different audience", func() {
		Expect(store.Store(ctx, "tok-pay", userID, []string{"svc-payments"}, expiresAt, nil)).To(Succeed())
		Expect(store.Store(ctx, "tok-rep", userID, []string{"svc-reports"}, expiresAt, nil)).To(Succeed())

		_, err := store.RevokeAllForUserAndAudience(ctx, userID, "svc-payments")
		Expect(err).NotTo(HaveOccurred())

		_, err = store.Retrieve(ctx, "tok-pay")
		Expect(err).To(MatchError(storage.ErrTokenRevoked))

		tok, err := store.Retrieve(ctx, "tok-rep")
		Expect(err).NotTo(HaveOccurred())
		Expect(tok.Revoked).To(BeFalse())
	})

	It("should return zero count and no error when user has no tokens for that audience", func() {
		n, err := store.RevokeAllForUserAndAudience(ctx, userID, "svc-nonexistent")
		Expect(err).NotTo(HaveOccurred())
		Expect(n).To(Equal(0))
	})

	It("should return ErrInvalidUserID for empty userID", func() {
		_, err := store.RevokeAllForUserAndAudience(ctx, "", "svc-payments")
		Expect(err).To(MatchError(storage.ErrInvalidUserID))
	})

	It("should return ErrInvalidAudience for empty audience", func() {
		_, err := store.RevokeAllForUserAndAudience(ctx, userID, "")
		Expect(err).To(MatchError(storage.ErrInvalidAudience))
	})

	It("should return context error on cancelled context", func() {
		cancelledCtx, cancel := context.WithCancel(context.Background())
		cancel()

		_, err := store.RevokeAllForUserAndAudience(cancelledCtx, userID, "svc-payments")
		Expect(err).To(MatchError(context.Canceled))
	})
})
