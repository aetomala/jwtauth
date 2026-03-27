package storage_test

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aetomala/jwtauth/internal/testutil"
	"github.com/aetomala/jwtauth/pkg/storage"
)

var _ = Describe("MemoryRefreshStore", func() {
	var (
		store      storage.RefreshStore
		mockLogger *testutil.MockLogger
		ctx        context.Context
		cancel     context.CancelFunc
		tokenID    string
		userID     string
		expiresAt  time.Time
		metadata   map[string]interface{}
	)

	BeforeEach(func() {
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		mockLogger = testutil.NewMockLogger()
		store = storage.NewMemoryRefreshStore(mockLogger)

		tokenID = "token-12345"
		userID = "user-67890"
		expiresAt = time.Now().Add(24 * time.Hour)
		metadata = map[string]interface{}{
			"ip":        "192.168.1.1",
			"userAgent": "Mozilla/5.0",
			"device":    "iPhone",
		}
	})

	AfterEach(func() {
		if cancel != nil {
			cancel()
		}
	})

	// ============================================================
	// PHASE 1: Constructor (Day 1)
	// Checkpoint: Can create the struct
	// ============================================================
	Describe("Phase 1: Constructor", func() {
		It("should create store with logger", func() {
			Expect(store).NotTo(BeNil())
		})

		It("should create store with nil logger", func() {
			storeWithoutLogger := storage.NewMemoryRefreshStore(nil)
			Expect(storeWithoutLogger).NotTo(BeNil())
		})

		It("should initialize empty", func() {
			token, err := store.Retrieve(ctx, "nonexistent")
			Expect(err).To(HaveOccurred())
			Expect(token).To(BeNil())
		})
	})

	// ============================================================
	// PHASE 2: Core Operations - Happy Path (Day 1-2)
	// Checkpoint: Basic store/retrieve cycle works
	// ============================================================
	Describe("Phase 2: Store - Happy Path", func() {
		It("should store token successfully", func() {
			err := store.Store(ctx, tokenID, userID, expiresAt, metadata)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should allow retrieval after storing", func() {
			err := store.Store(ctx, tokenID, userID, expiresAt, metadata)
			Expect(err).NotTo(HaveOccurred())

			token, err := store.Retrieve(ctx, tokenID)
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeNil())
			Expect(token.TokenID).To(Equal(tokenID))
			Expect(token.UserID).To(Equal(userID))
		})

		It("should store metadata correctly", func() {
			err := store.Store(ctx, tokenID, userID, expiresAt, metadata)
			Expect(err).NotTo(HaveOccurred())

			token, err := store.Retrieve(ctx, tokenID)
			Expect(err).NotTo(HaveOccurred())
			Expect(token.Metadata).To(Equal(metadata))
		})

		It("should store expiration time correctly", func() {
			err := store.Store(ctx, tokenID, userID, expiresAt, metadata)
			Expect(err).NotTo(HaveOccurred())

			token, err := store.Retrieve(ctx, tokenID)
			Expect(err).NotTo(HaveOccurred())
			Expect(token.ExpiresAt).To(BeTemporally("~", expiresAt, time.Second))
		})

		It("should set CreatedAt to current time", func() {
			now := time.Now()
			err := store.Store(ctx, tokenID, userID, expiresAt, metadata)
			Expect(err).NotTo(HaveOccurred())

			token, err := store.Retrieve(ctx, tokenID)
			Expect(err).NotTo(HaveOccurred())
			Expect(token.CreatedAt).To(BeTemporally("~", now, time.Second))
		})

		It("should set Revoked to false initially", func() {
			err := store.Store(ctx, tokenID, userID, expiresAt, metadata)
			Expect(err).NotTo(HaveOccurred())

			token, err := store.Retrieve(ctx, tokenID)
			Expect(err).NotTo(HaveOccurred())
			Expect(token.Revoked).To(BeFalse())
		})

		It("should store multiple tokens for same user", func() {
			err := store.Store(ctx, "token-1", userID, expiresAt, metadata)
			Expect(err).NotTo(HaveOccurred())

			err = store.Store(ctx, "token-2", userID, expiresAt, metadata)
			Expect(err).NotTo(HaveOccurred())

			token1, err := store.Retrieve(ctx, "token-1")
			Expect(err).NotTo(HaveOccurred())
			Expect(token1.UserID).To(Equal(userID))

			token2, err := store.Retrieve(ctx, "token-2")
			Expect(err).NotTo(HaveOccurred())
			Expect(token2.UserID).To(Equal(userID))
		})

		It("should store tokens for different users", func() {
			err := store.Store(ctx, "token-1", "user-1", expiresAt, metadata)
			Expect(err).NotTo(HaveOccurred())

			err = store.Store(ctx, "token-2", "user-2", expiresAt, metadata)
			Expect(err).NotTo(HaveOccurred())

			token1, err := store.Retrieve(ctx, "token-1")
			Expect(err).NotTo(HaveOccurred())
			Expect(token1.UserID).To(Equal("user-1"))

			token2, err := store.Retrieve(ctx, "token-2")
			Expect(err).NotTo(HaveOccurred())
			Expect(token2.UserID).To(Equal("user-2"))
		})
	})

	Describe("Phase 2: Retrieve - Happy Path", func() {
		BeforeEach(func() {
			err := store.Store(ctx, tokenID, userID, expiresAt, metadata)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should retrieve stored token", func() {
			token, err := store.Retrieve(ctx, tokenID)
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeNil())
		})

		It("should return correct token data", func() {
			token, err := store.Retrieve(ctx, tokenID)
			Expect(err).NotTo(HaveOccurred())
			Expect(token.TokenID).To(Equal(tokenID))
			Expect(token.UserID).To(Equal(userID))
			Expect(token.Revoked).To(BeFalse())
		})

		It("should return token with metadata", func() {
			token, err := store.Retrieve(ctx, tokenID)
			Expect(err).NotTo(HaveOccurred())
			Expect(token.Metadata).To(Equal(metadata))
		})
	})

	// ============================================================
	// PHASE 3: Critical Input Validation (Day 2-3)
	// Checkpoint: Rejects obviously bad input
	// CATCHES: BUG #1 (empty IDs), BUG #2 (expired tokens), BUG #3 (metadata mutation)
	// ============================================================
	Describe("Phase 3: Store - Input Validation", func() {
		It("should reject empty tokenID", func() {
			err := store.Store(ctx, "", userID, expiresAt, metadata)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(storage.ErrInvalidTokenID))
		})

		It("should reject whitespace-only tokenID", func() {
			err := store.Store(ctx, "   ", userID, expiresAt, metadata)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(storage.ErrInvalidTokenID))
		})

		It("should reject empty userID", func() {
			err := store.Store(ctx, tokenID, "", expiresAt, metadata)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(storage.ErrInvalidUserID))
		})

		It("should reject whitespace-only userID", func() {
			err := store.Store(ctx, tokenID, "   ", expiresAt, metadata)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(storage.ErrInvalidUserID))
		})

		It("should reject already-expired token (1 hour ago)", func() {
			expiredTime := time.Now().Add(-1 * time.Hour)
			err := store.Store(ctx, tokenID, userID, expiredTime, metadata)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(storage.ErrTokenExpired))
		})

		It("should reject token expiring 1 millisecond ago", func() {
			justExpired := time.Now().Add(-1 * time.Millisecond)
			err := store.Store(ctx, tokenID, userID, justExpired, metadata)
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(storage.ErrTokenExpired))
		})

		It("should accept token expiring 1 second in future", func() {
			soonExpires := time.Now().Add(1 * time.Second)
			err := store.Store(ctx, tokenID, userID, soonExpires, metadata)
			Expect(err).NotTo(HaveOccurred())
		})

	})
})
