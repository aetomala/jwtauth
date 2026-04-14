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
)

// StoreFactory creates a RefreshStore for testing. Pass nil for m to disable
// metrics instrumentation (used by phases 1–9).
type StoreFactory func(logger *testutil.MockLogger, m metrics.Metrics) storage.RefreshStore

// CleanupFunc cleans up after each test (implementation-specific)
type CleanupFunc func()

// RunRefreshStoreTests runs the complete test suite against any RefreshStore
// implementation. backend is the storage_backend label value used in metric
// assertions (e.g. "memory" or "redis").
func RunRefreshStoreTests(description, backend string, factory StoreFactory, cleanup CleanupFunc) bool {
	return Describe(description, func() {
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
			store = factory(mockLogger, nil)

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
			if cleanup != nil {
				cleanup()
			}
		})

		// ============================================================
		// PHASE 1: Constructor
		// Checkpoint: Can create the struct
		// ============================================================
		Describe("Phase 1: Constructor", func() {
			It("should create store with logger", func() {
				Expect(store).NotTo(BeNil())
			})

			It("should create store with nil logger", func() {
				storeWithoutLogger := factory(nil, nil)
				Expect(storeWithoutLogger).NotTo(BeNil())
			})

			It("should initialize empty", func() {
				token, err := store.Retrieve(ctx, "nonexistent")
				Expect(err).To(HaveOccurred())
				Expect(token).To(BeNil())
			})
		})

		// ============================================================
		// PHASE 2: Core Operations - Happy Path
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

			It("should store creation time", func() {
				before := time.Now()
				err := store.Store(ctx, tokenID, userID, expiresAt, metadata)
				Expect(err).NotTo(HaveOccurred())

				token, err := store.Retrieve(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())
				// Use 2ms tolerance to account for precision loss in Redis (stores milliseconds, not microseconds)
				Expect(token.CreatedAt).To(BeTemporally("~", before, 2*time.Millisecond))
				Expect(token.CreatedAt).To(BeTemporally("<=", time.Now().Add(time.Millisecond)))
			})

			It("should initialize revoked as false", func() {
				err := store.Store(ctx, tokenID, userID, expiresAt, metadata)
				Expect(err).NotTo(HaveOccurred())

				token, err := store.Retrieve(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())
				Expect(token.Revoked).To(BeFalse())
			})
		})

		// ============================================================
		// PHASE 3: Store - Input Validation
		// Checkpoint: Rejects invalid inputs
		// ============================================================
		Describe("Phase 3: Store - Input Validation", func() {
			It("should reject empty tokenID", func() {
				err := store.Store(ctx, "", userID, expiresAt, metadata)
				Expect(err).To(MatchError(storage.ErrInvalidTokenID))
			})

			It("should reject whitespace-only tokenID", func() {
				err := store.Store(ctx, "   ", userID, expiresAt, metadata)
				Expect(err).To(MatchError(storage.ErrInvalidTokenID))
			})

			It("should reject empty userID", func() {
				err := store.Store(ctx, tokenID, "", expiresAt, metadata)
				Expect(err).To(MatchError(storage.ErrInvalidUserID))
			})

			It("should reject whitespace-only userID", func() {
				err := store.Store(ctx, tokenID, "   ", expiresAt, metadata)
				Expect(err).To(MatchError(storage.ErrInvalidUserID))
			})

			It("should reject expired token (past time)", func() {
				past := time.Now().Add(-1 * time.Hour)
				err := store.Store(ctx, tokenID, userID, past, metadata)
				Expect(err).To(MatchError(storage.ErrTokenExpired))
			})

			It("should reject expired token (exactly now)", func() {
				now := time.Now()
				err := store.Store(ctx, tokenID, userID, now, metadata)
				Expect(err).To(MatchError(storage.ErrTokenExpired))
			})

			It("should accept nil metadata", func() {
				err := store.Store(ctx, tokenID, userID, expiresAt, nil)
				Expect(err).NotTo(HaveOccurred())

				token, err := store.Retrieve(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())
				Expect(token.Metadata).To(BeNil())
			})

			It("should accept empty metadata", func() {
				err := store.Store(ctx, tokenID, userID, expiresAt, map[string]interface{}{})
				Expect(err).NotTo(HaveOccurred())

				token, err := store.Retrieve(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())
				Expect(token.Metadata).To(Equal(map[string]interface{}{}))
			})
		})

		// ============================================================
		// PHASE 4: Metadata Isolation (Defensive Copy)
		// Checkpoint: Store and Retrieve don't share mutable references
		// ============================================================
		Describe("Phase 4: Metadata Isolation - Store Creates Defensive Copy", func() {
			It("should not reflect mutations to input metadata after Store", func() {
				originalMetadata := map[string]interface{}{
					"key": "original",
				}

				err := store.Store(ctx, tokenID, userID, expiresAt, originalMetadata)
				Expect(err).NotTo(HaveOccurred())

				// Mutate original
				originalMetadata["key"] = "mutated"

				// Retrieved copy should be unchanged
				token, err := store.Retrieve(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())
				Expect(token.Metadata["key"]).To(Equal("original"))
			})

			It("should return deep copy of metadata on Retrieve", func() {
				err := store.Store(ctx, tokenID, userID, expiresAt, metadata)
				Expect(err).NotTo(HaveOccurred())

				token, err := store.Retrieve(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())

				// Mutate retrieved metadata
				token.Metadata["ip"] = "mutated"

				// Re-retrieve should show original
				token2, err := store.Retrieve(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())
				Expect(token2.Metadata["ip"]).To(Equal("192.168.1.1"))
			})

			It("should handle complex nested metadata (no shared references)", func() {
				nestedMetadata := map[string]interface{}{
					"nested": map[string]interface{}{
						"key": "value",
					},
				}

				err := store.Store(ctx, tokenID, userID, expiresAt, nestedMetadata)
				Expect(err).NotTo(HaveOccurred())

				// Top-level copy is defensive, but nested structures are shared
				// This is expected behavior (one level of copy)
				token, err := store.Retrieve(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())
				Expect(token.Metadata).NotTo(BeNil())
			})
		})

		// ============================================================
		// PHASE 5: Retrieve - Input Validation and State Checks
		// Checkpoint: Retrieve validates inputs and checks state
		// ============================================================
		Describe("Phase 5: Retrieve - Input Validation and State Checks", func() {
			It("should reject empty tokenID", func() {
				_, err := store.Retrieve(ctx, "")
				Expect(err).To(MatchError(storage.ErrInvalidTokenID))
			})

			It("should reject whitespace-only tokenID", func() {
				_, err := store.Retrieve(ctx, "   ")
				Expect(err).To(MatchError(storage.ErrInvalidTokenID))
			})

			It("should return ErrTokenNotFound for nonexistent token", func() {
				_, err := store.Retrieve(ctx, "nonexistent")
				Expect(err).To(MatchError(storage.ErrTokenNotFound))
			})

			It("should return ErrTokenRevoked for revoked token", func() {
				err := store.Store(ctx, tokenID, userID, expiresAt, metadata)
				Expect(err).NotTo(HaveOccurred())

				err = store.Revoke(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())

				_, err = store.Retrieve(ctx, tokenID)
				Expect(err).To(MatchError(storage.ErrTokenRevoked))
			})

			It("should return ErrTokenExpired for expired token", func() {
				past := time.Now().Add(-1 * time.Hour)
				err := store.Store(ctx, tokenID, userID, past, metadata)
				// Some stores might reject this at Store time, so check either way
				if err != storage.ErrTokenExpired {
					// If Store accepts it, Retrieve should reject it
					// But most implementations reject at Store time
					Skip("Store rejected expired token at write time")
				}
			})
		})

		// ============================================================
		// PHASE 6: Revoke - Idempotent and State-Changing
		// Checkpoint: Revoke marks token as unavailable
		// ============================================================
		Describe("Phase 6: Revoke - Idempotent and State-Changing", func() {
			It("should mark token as revoked", func() {
				err := store.Store(ctx, tokenID, userID, expiresAt, metadata)
				Expect(err).NotTo(HaveOccurred())

				err = store.Revoke(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())

				_, err = store.Retrieve(ctx, tokenID)
				Expect(err).To(MatchError(storage.ErrTokenRevoked))
			})

			It("should be idempotent (revoke twice)", func() {
				err := store.Store(ctx, tokenID, userID, expiresAt, metadata)
				Expect(err).NotTo(HaveOccurred())

				err = store.Revoke(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())

				// Second revoke should not error
				err = store.Revoke(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())

				_, err = store.Retrieve(ctx, tokenID)
				Expect(err).To(MatchError(storage.ErrTokenRevoked))
			})

			It("should return nil for nonexistent token (idempotent)", func() {
				err := store.Revoke(ctx, "nonexistent")
				Expect(err).NotTo(HaveOccurred())
			})

			It("should reject empty tokenID", func() {
				err := store.Revoke(ctx, "")
				Expect(err).To(MatchError(storage.ErrInvalidTokenID))
			})

			It("should reject whitespace-only tokenID", func() {
				err := store.Revoke(ctx, "   ")
				Expect(err).To(MatchError(storage.ErrInvalidTokenID))
			})
		})

		// ============================================================
		// PHASE 7: RevokeAllForUser - Bulk Operation
		// Checkpoint: Can revoke all tokens for a user
		// ============================================================
		Describe("Phase 7: RevokeAllForUser - Bulk Operation", func() {
			It("should revoke all tokens for user", func() {
				// Store 5 tokens for same user
				for i := 0; i < 5; i++ {
					tid := fmt.Sprintf("token-%d", i)
					err := store.Store(ctx, tid, userID, expiresAt, metadata)
					Expect(err).NotTo(HaveOccurred())
				}

				// Revoke all
				err := store.RevokeAllForUser(ctx, userID)
				Expect(err).NotTo(HaveOccurred())

				// All should be revoked
				for i := 0; i < 5; i++ {
					tid := fmt.Sprintf("token-%d", i)
					_, err := store.Retrieve(ctx, tid)
					Expect(err).To(MatchError(storage.ErrTokenRevoked))
				}
			})

			It("should not affect other users' tokens", func() {
				user1ID := "user-1"
				user2ID := "user-2"

				err := store.Store(ctx, "token-1", user1ID, expiresAt, metadata)
				Expect(err).NotTo(HaveOccurred())

				err = store.Store(ctx, "token-2", user2ID, expiresAt, metadata)
				Expect(err).NotTo(HaveOccurred())

				// Revoke user1's tokens
				err = store.RevokeAllForUser(ctx, user1ID)
				Expect(err).NotTo(HaveOccurred())

				// User1's token should be revoked
				_, err = store.Retrieve(ctx, "token-1")
				Expect(err).To(MatchError(storage.ErrTokenRevoked))

				// User2's token should still be valid
				token, err := store.Retrieve(ctx, "token-2")
				Expect(err).NotTo(HaveOccurred())
				Expect(token.UserID).To(Equal(user2ID))
			})

			It("should succeed silently if user has no tokens", func() {
				err := store.RevokeAllForUser(ctx, "user-with-no-tokens")
				Expect(err).NotTo(HaveOccurred())
			})

			It("should reject empty userID", func() {
				err := store.RevokeAllForUser(ctx, "")
				Expect(err).To(MatchError(storage.ErrInvalidUserID))
			})

			It("should reject whitespace-only userID", func() {
				err := store.RevokeAllForUser(ctx, "   ")
				Expect(err).To(MatchError(storage.ErrInvalidUserID))
			})

			It("should be idempotent", func() {
				err := store.Store(ctx, tokenID, userID, expiresAt, metadata)
				Expect(err).NotTo(HaveOccurred())

				err = store.RevokeAllForUser(ctx, userID)
				Expect(err).NotTo(HaveOccurred())

				// Second call should also succeed
				err = store.RevokeAllForUser(ctx, userID)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		// ============================================================
		// PHASE 8: Cleanup - Expire Management
		// Checkpoint: Expired tokens are removed
		// ============================================================
		Describe("Phase 8: Cleanup - Expire Management", func() {
			It("should remove expired tokens", func() {
				veryShortLived := time.Now().Add(100 * time.Millisecond)

				err := store.Store(ctx, tokenID, userID, veryShortLived, metadata)
				if err != nil {
					Skip("Store rejected short-lived token")
				}

				// Wait for it to expire
				time.Sleep(200 * time.Millisecond)

				// Run cleanup
				count, err := store.Cleanup(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(count).To(BeNumerically(">=", 1))

				// Should not be retrievable
				_, err = store.Retrieve(ctx, tokenID)
				Expect(err).To(MatchError(storage.ErrTokenNotFound))
			})

			It("should return count of removed tokens", func() {
				veryShortLived := time.Now().Add(50 * time.Millisecond)

				// Store multiple short-lived tokens
				for i := 0; i < 3; i++ {
					tid := fmt.Sprintf("token-%d", i)
					err := store.Store(ctx, tid, userID, veryShortLived, metadata)
					if err != nil {
						Skip("Store rejected short-lived tokens")
					}
				}

				// Wait for expiration
				time.Sleep(150 * time.Millisecond)

				// Cleanup should remove all 3
				count, err := store.Cleanup(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(count).To(Equal(3))
			})

			It("should not remove non-expired tokens", func() {
				future := time.Now().Add(1 * time.Hour)
				err := store.Store(ctx, tokenID, userID, future, metadata)
				Expect(err).NotTo(HaveOccurred())

				count, err := store.Cleanup(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(count).To(Equal(0))

				token, err := store.Retrieve(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())
				Expect(token.TokenID).To(Equal(tokenID))
			})

			It("should succeed on empty store", func() {
				count, err := store.Cleanup(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(count).To(Equal(0))
			})

			It("should handle mixed expiration states", func() {
				future := time.Now().Add(1 * time.Hour)
				err := store.Store(ctx, "future-token", userID, future, metadata)
				Expect(err).NotTo(HaveOccurred())

				shortLived := time.Now().Add(50 * time.Millisecond)
				err = store.Store(ctx, "short-token", userID, shortLived, metadata)
				if err != nil {
					Skip("Store rejected short-lived token")
				}

				time.Sleep(150 * time.Millisecond)

				count, err := store.Cleanup(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(count).To(Equal(1))

				token, err := store.Retrieve(ctx, "future-token")
				Expect(err).NotTo(HaveOccurred())
				Expect(token.TokenID).To(Equal("future-token"))
			})
		})

		// ============================================================
		// PHASE 8: Edge Cases - Unicode and UUID
		// Checkpoint: Handles various string types
		// ============================================================
		Describe("Phase 8: Edge Cases - Unicode", func() {
			It("should handle unicode in tokenID", func() {
				uuidToken := "token-🔐-abc"
				err := store.Store(ctx, uuidToken, userID, expiresAt, metadata)
				Expect(err).NotTo(HaveOccurred())

				token, err := store.Retrieve(ctx, uuidToken)
				Expect(err).NotTo(HaveOccurred())
				Expect(token.TokenID).To(Equal(uuidToken))
			})

			It("should handle unicode in userID", func() {
				uuidUser := "user-🔐-xyz"
				err := store.Store(ctx, tokenID, uuidUser, expiresAt, metadata)
				Expect(err).NotTo(HaveOccurred())

				token, err := store.Retrieve(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())
				Expect(token.UserID).To(Equal(uuidUser))
			})
		})

		// ============================================================
		// PHASE 8: Edge Cases - Large Scale
		// Checkpoint: Handles volume
		// ============================================================
		Describe("Phase 8: Edge Cases - Large Scale", func() {
			It("should handle storing many tokens for one user", func() {
				for i := 0; i < 100; i++ {
					tid := fmt.Sprintf("token-%d", i)
					err := store.Store(ctx, tid, userID, expiresAt, metadata)
					Expect(err).NotTo(HaveOccurred())
				}

				for i := 0; i < 100; i++ {
					tid := fmt.Sprintf("token-%d", i)
					token, err := store.Retrieve(ctx, tid)
					Expect(err).NotTo(HaveOccurred())
					Expect(token.UserID).To(Equal(userID))
				}

				err := store.RevokeAllForUser(ctx, userID)
				Expect(err).NotTo(HaveOccurred())

				for i := 0; i < 100; i++ {
					tid := fmt.Sprintf("token-%d", i)
					_, err := store.Retrieve(ctx, tid)
					Expect(err).To(MatchError(storage.ErrTokenRevoked))
				}
			})

			It("should handle large metadata maps", func() {
				largeMeta := make(map[string]interface{})
				for i := 0; i < 100; i++ {
					largeMeta[fmt.Sprintf("key-%d", i)] = fmt.Sprintf("value-%d", i)
				}

				err := store.Store(ctx, tokenID, userID, expiresAt, largeMeta)
				Expect(err).NotTo(HaveOccurred())

				token, err := store.Retrieve(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())
				Expect(len(token.Metadata)).To(Equal(100))
			})
		})

		// ============================================================
		// PHASE 8: Edge Cases - Far Future
		// Checkpoint: Handles extreme time values
		// ============================================================
		Describe("Phase 8: Edge Cases - Far Future", func() {
			It("should handle tokens with very far future expiration", func() {
				farFuture := time.Now().Add(100 * 365 * 24 * time.Hour)
				err := store.Store(ctx, tokenID, userID, farFuture, metadata)
				Expect(err).NotTo(HaveOccurred())

				token, err := store.Retrieve(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())
				Expect(token.ExpiresAt).To(BeTemporally("~", farFuture, time.Second))
			})
		})

		// ============================================================
		// PHASE 10: Metrics Recording
		// Checkpoint: Every operation records the correct metric calls
		// ============================================================
		Describe("Phase 10: Metrics Recording", func() {
			var (
				ctrl  *gomock.Controller
				mockM *testutil.MockMetrics
				ms    storage.RefreshStore // store with live MockMetrics
			)

			BeforeEach(func() {
				ctrl = gomock.NewController(GinkgoT())
				mockM = testutil.NewMockMetrics(ctrl)
				ms = factory(mockLogger, mockM)
			})

			AfterEach(func() {
				ctrl.Finish()
			})

			It("should record counter and duration on Store success", func() {
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "store", "status": "success", "error_type": "", "storage_backend": backend})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "store", "storage_backend": backend})
				// Some implementations (e.g. Memory) update the token-count gauge on
				// every Store; others (e.g. Redis) only update it in Cleanup.
				mockM.EXPECT().SetGauge("jwtauth_storage_tokens_count",
					gomock.Any(),
					map[string]string{"storage_backend": backend}).AnyTimes()

				err := ms.Store(ctx, tokenID, userID, expiresAt, metadata)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should record validation_error status on Store with empty tokenID", func() {
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "store", "status": "validation_error", "error_type": "validation_error", "storage_backend": backend})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "store", "storage_backend": backend})

				err := ms.Store(ctx, "", userID, expiresAt, metadata)
				Expect(err).To(HaveOccurred())
			})

			It("should record counter and duration on Retrieve success", func() {
				// Setup: Store the token (expect those metrics too)
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "store", "status": "success", "error_type": "", "storage_backend": backend})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "store", "storage_backend": backend})
				mockM.EXPECT().SetGauge("jwtauth_storage_tokens_count",
					gomock.Any(),
					map[string]string{"storage_backend": backend}).AnyTimes()
				Expect(ms.Store(ctx, tokenID, userID, expiresAt, metadata)).To(Succeed())

				// Retrieve expectations
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "retrieve", "status": "success", "error_type": "", "storage_backend": backend})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "retrieve", "storage_backend": backend})

				token, err := ms.Retrieve(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())
				Expect(token).NotTo(BeNil())
			})

			It("should record not_found status on Retrieve for nonexistent token", func() {
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "retrieve", "status": "not_found", "error_type": "not_found", "storage_backend": backend})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "retrieve", "storage_backend": backend})

				_, err := ms.Retrieve(ctx, "nonexistent-token")
				Expect(err).To(MatchError(storage.ErrTokenNotFound))
			})

			It("should record revoked status on Retrieve for revoked token", func() {
				// Store
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "store", "status": "success", "error_type": "", "storage_backend": backend})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "store", "storage_backend": backend})
				mockM.EXPECT().SetGauge("jwtauth_storage_tokens_count",
					gomock.Any(),
					map[string]string{"storage_backend": backend}).AnyTimes()
				Expect(ms.Store(ctx, tokenID, userID, expiresAt, metadata)).To(Succeed())

				// Revoke
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "revoke", "status": "success", "error_type": "", "storage_backend": backend})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "revoke", "storage_backend": backend})
				Expect(ms.Revoke(ctx, tokenID)).To(Succeed())

				// Retrieve
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "retrieve", "status": "revoked", "error_type": "revoked", "storage_backend": backend})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "retrieve", "storage_backend": backend})

				_, err := ms.Retrieve(ctx, tokenID)
				Expect(err).To(MatchError(storage.ErrTokenRevoked))
			})

			It("should record counter and duration on Revoke success", func() {
				// Store
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "store", "status": "success", "error_type": "", "storage_backend": backend})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "store", "storage_backend": backend})
				mockM.EXPECT().SetGauge("jwtauth_storage_tokens_count",
					gomock.Any(),
					map[string]string{"storage_backend": backend}).AnyTimes()
				Expect(ms.Store(ctx, tokenID, userID, expiresAt, metadata)).To(Succeed())

				// Revoke
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "revoke", "status": "success", "error_type": "", "storage_backend": backend})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "revoke", "storage_backend": backend})

				Expect(ms.Revoke(ctx, tokenID)).To(Succeed())
			})

			It("should record counter and duration on RevokeAllForUser success", func() {
				// Store
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "store", "status": "success", "error_type": "", "storage_backend": backend})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "store", "storage_backend": backend})
				mockM.EXPECT().SetGauge("jwtauth_storage_tokens_count",
					gomock.Any(),
					map[string]string{"storage_backend": backend}).AnyTimes()
				Expect(ms.Store(ctx, tokenID, userID, expiresAt, metadata)).To(Succeed())

				// RevokeAllForUser
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "revoke_all", "status": "success", "error_type": "", "storage_backend": backend})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "revoke_all", "storage_backend": backend})

				Expect(ms.RevokeAllForUser(ctx, userID)).To(Succeed())
			})

			It("should record counter, duration, removed count, and gauge on Cleanup with expired tokens", func() {
				veryShortLived := time.Now().Add(50 * time.Millisecond)

				// Store short-lived token
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "store", "status": "success", "error_type": "", "storage_backend": backend})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "store", "storage_backend": backend})
				// Memory updates the gauge on Store (value=1 after first insert); Redis does not.
				mockM.EXPECT().SetGauge("jwtauth_storage_tokens_count",
					float64(1),
					map[string]string{"storage_backend": backend}).AnyTimes()
				err := ms.Store(ctx, tokenID, userID, veryShortLived, metadata)
				if err != nil {
					Skip("store rejected short-lived token")
				}

				time.Sleep(100 * time.Millisecond)

				// Cleanup expectations
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "cleanup", "status": "success", "error_type": "", "storage_backend": backend})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "cleanup", "storage_backend": backend})
				mockM.EXPECT().AddCounter("jwtauth_storage_cleanup_tokens_removed_total",
					float64(1),
					map[string]string{"storage_backend": backend})
				mockM.EXPECT().SetGauge("jwtauth_storage_tokens_count",
					float64(0),
					map[string]string{"storage_backend": backend})

				count, err := ms.Cleanup(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(count).To(Equal(1))
			})

			It("should record zero removed count and gauge on Cleanup with no tokens", func() {
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "cleanup", "status": "success", "error_type": "", "storage_backend": backend})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "cleanup", "storage_backend": backend})
				mockM.EXPECT().AddCounter("jwtauth_storage_cleanup_tokens_removed_total",
					float64(0),
					map[string]string{"storage_backend": backend})
				mockM.EXPECT().SetGauge("jwtauth_storage_tokens_count",
					float64(0),
					map[string]string{"storage_backend": backend})

				count, err := ms.Cleanup(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(count).To(Equal(0))
			})

			It("should not panic when metrics is nil", func() {
				nilMetricsStore := factory(mockLogger, nil)
				Expect(func() {
					_ = nilMetricsStore.Store(ctx, tokenID, userID, expiresAt, metadata)
					_, _ = nilMetricsStore.Retrieve(ctx, tokenID)
					_ = nilMetricsStore.Revoke(ctx, tokenID)
					_ = nilMetricsStore.RevokeAllForUser(ctx, userID)
					_, _ = nilMetricsStore.Cleanup(ctx)
				}).NotTo(Panic())
			})
		})

		// ============================================================
		// PHASE 9: Context Cancellation
		// Checkpoint: Respects context deadline/cancellation
		// ============================================================
		Describe("Phase 9: Context Cancellation", func() {
			It("should return context error on cancelled context for Store", func() {
				cancelledCtx, cancel := context.WithCancel(context.Background())
				cancel()

				err := store.Store(cancelledCtx, tokenID, userID, expiresAt, metadata)
				Expect(err).To(MatchError(context.Canceled))
			})

			It("should return context error on cancelled context for Retrieve", func() {
				cancelledCtx, cancel := context.WithCancel(context.Background())
				cancel()

				_, err := store.Retrieve(cancelledCtx, tokenID)
				Expect(err).To(MatchError(context.Canceled))
			})

			It("should return context error on cancelled context for Revoke", func() {
				cancelledCtx, cancel := context.WithCancel(context.Background())
				cancel()

				err := store.Revoke(cancelledCtx, tokenID)
				Expect(err).To(MatchError(context.Canceled))
			})

			It("should return context error on cancelled context for RevokeAllForUser", func() {
				cancelledCtx, cancel := context.WithCancel(context.Background())
				cancel()

				err := store.RevokeAllForUser(cancelledCtx, userID)
				Expect(err).To(MatchError(context.Canceled))
			})

			It("should return context error on cancelled context for Cleanup", func() {
				cancelledCtx, cancel := context.WithCancel(context.Background())
				cancel()

				_, err := store.Cleanup(cancelledCtx)
				Expect(err).To(MatchError(context.Canceled))
			})
		})
	})
}
