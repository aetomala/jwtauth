// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

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
		mockTracer.EXPECT().Start(gomock.Any(), gomock.Any()).Return(ctx, mockSpan).AnyTimes()
		mockSpan.EXPECT().End().AnyTimes()
		mockSpan.EXPECT().SetAttribute(gomock.Any(), gomock.Any()).AnyTimes()
		mockSpan.EXPECT().SetAttributes(gomock.Any()).AnyTimes()
		mockSpan.EXPECT().SetStatus(gomock.Any(), gomock.Any()).AnyTimes()

		store := storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{Tracer: mockTracer})
		tokenID := "tracer-token"
		userID := "tracer-user"
		Expect(store.Store(ctx, tokenID, userID, nil, time.Now().Add(time.Hour), nil)).To(Succeed())
	})
})

var _ = Describe("MemoryRefreshStore — Cleanup Expiry Heap Edge Cases", func() {
	ctx := context.Background()

	It("should not remove a token whose tokenID was re-stored under a later expiry", func() {
		store := storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{})
		tokenID := "reused-token-id"
		userID := "reuse-user"

		shortLived := time.Now().Add(50 * time.Millisecond)
		err := store.Store(ctx, tokenID, userID, nil, shortLived, nil)
		if err != nil {
			Skip("Store rejected short-lived token")
		}

		// Re-store the same tokenID with a much later expiry before the
		// first entry's expiry has passed. The heap now holds two entries
		// for this tokenID — the earlier (stale) one and the live one.
		laterExpiry := time.Now().Add(1 * time.Hour)
		Expect(store.Store(ctx, tokenID, userID, nil, laterExpiry, nil)).To(Succeed())

		// Wait past the first (stale) entry's expiry, but well before the
		// second (live) one.
		time.Sleep(100 * time.Millisecond)

		count, err := store.Cleanup(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(count).To(Equal(0))

		token, err := store.Retrieve(ctx, tokenID)
		Expect(err).NotTo(HaveOccurred())
		Expect(token.ExpiresAt).To(BeTemporally("~", laterExpiry, time.Second))
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
			mockTracer.EXPECT().Start(gomock.Any(), "MemoryRefreshStore.Store").Return(ctx, mockSpan)
			mockSpan.EXPECT().SetAttributes(map[string]any{"storage_backend": "memory"})
			mockSpan.EXPECT().SetAttribute("token_id", "trace-store-token")
			mockSpan.EXPECT().SetStatus(tracing.StatusOK, "")
			mockSpan.EXPECT().End()

			Expect(tracingStore.Store(ctx, "trace-store-token", "trace-user", nil, time.Now().Add(time.Hour), nil)).To(Succeed())
		})
	})

	Context("Retrieve — error path", func() {
		It("should call RecordError and StatusError when token is not found", func() {
			mockTracer.EXPECT().Start(gomock.Any(), "MemoryRefreshStore.Retrieve").Return(ctx, mockSpan)
			mockSpan.EXPECT().SetAttributes(map[string]any{"storage_backend": "memory"})
			mockSpan.EXPECT().SetAttribute("token_id", "missing-trace-token")
			mockSpan.EXPECT().RecordError(storage.ErrTokenNotFound)
			mockSpan.EXPECT().SetStatus(tracing.StatusError, gomock.Any())
			mockSpan.EXPECT().End()

			_, err := tracingStore.Retrieve(ctx, "missing-trace-token")
			Expect(err).To(MatchError(storage.ErrTokenNotFound))
		})
	})
})

