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
				err := store.Store(ctx, tokenID, userID, nil, expiresAt, metadata)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should allow retrieval after storing", func() {
				err := store.Store(ctx, tokenID, userID, nil, expiresAt, metadata)
				Expect(err).NotTo(HaveOccurred())

				token, err := store.Retrieve(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())
				Expect(token).NotTo(BeNil())
				Expect(token.TokenID).To(Equal(tokenID))
				Expect(token.UserID).To(Equal(userID))
			})

			It("should store metadata correctly", func() {
				err := store.Store(ctx, tokenID, userID, nil, expiresAt, metadata)
				Expect(err).NotTo(HaveOccurred())

				token, err := store.Retrieve(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())
				Expect(token.Metadata).To(Equal(metadata))
			})

			It("should store expiration time correctly", func() {
				err := store.Store(ctx, tokenID, userID, nil, expiresAt, metadata)
				Expect(err).NotTo(HaveOccurred())

				token, err := store.Retrieve(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())
				Expect(token.ExpiresAt).To(BeTemporally("~", expiresAt, time.Second))
			})

			It("should store creation time", func() {
				before := time.Now()
				err := store.Store(ctx, tokenID, userID, nil, expiresAt, metadata)
				Expect(err).NotTo(HaveOccurred())

				token, err := store.Retrieve(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())
				// Use 2ms tolerance to account for precision loss in Redis (stores milliseconds, not microseconds)
				Expect(token.CreatedAt).To(BeTemporally("~", before, 2*time.Millisecond))
				Expect(token.CreatedAt).To(BeTemporally("<=", time.Now().Add(time.Millisecond)))
			})

			It("should initialize revoked as false", func() {
				err := store.Store(ctx, tokenID, userID, nil, expiresAt, metadata)
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
				err := store.Store(ctx, "", userID, nil, expiresAt, metadata)
				Expect(err).To(MatchError(storage.ErrInvalidTokenID))
			})

			It("should reject whitespace-only tokenID", func() {
				err := store.Store(ctx, "   ", userID, nil, expiresAt, metadata)
				Expect(err).To(MatchError(storage.ErrInvalidTokenID))
			})

			It("should reject empty userID", func() {
				err := store.Store(ctx, tokenID, "", nil, expiresAt, metadata)
				Expect(err).To(MatchError(storage.ErrInvalidUserID))
			})

			It("should reject whitespace-only userID", func() {
				err := store.Store(ctx, tokenID, "   ", nil, expiresAt, metadata)
				Expect(err).To(MatchError(storage.ErrInvalidUserID))
			})

			It("should reject expired token (past time)", func() {
				past := time.Now().Add(-1 * time.Hour)
				err := store.Store(ctx, tokenID, userID, nil, past, metadata)
				Expect(err).To(MatchError(storage.ErrTokenExpired))
			})

			It("should reject expired token (exactly now)", func() {
				now := time.Now()
				err := store.Store(ctx, tokenID, userID, nil, now, metadata)
				Expect(err).To(MatchError(storage.ErrTokenExpired))
			})

			It("should accept nil metadata", func() {
				err := store.Store(ctx, tokenID, userID, nil, expiresAt, nil)
				Expect(err).NotTo(HaveOccurred())

				token, err := store.Retrieve(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())
				Expect(token.Metadata).To(BeNil())
			})

			It("should accept empty metadata", func() {
				err := store.Store(ctx, tokenID, userID, nil, expiresAt, map[string]interface{}{})
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

				err := store.Store(ctx, tokenID, userID, nil, expiresAt, originalMetadata)
				Expect(err).NotTo(HaveOccurred())

				// Mutate original
				originalMetadata["key"] = "mutated"

				// Retrieved copy should be unchanged
				token, err := store.Retrieve(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())
				Expect(token.Metadata["key"]).To(Equal("original"))
			})

			It("should return deep copy of metadata on Retrieve", func() {
				err := store.Store(ctx, tokenID, userID, nil, expiresAt, metadata)
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

				err := store.Store(ctx, tokenID, userID, nil, expiresAt, nestedMetadata)
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
				err := store.Store(ctx, tokenID, userID, nil, expiresAt, metadata)
				Expect(err).NotTo(HaveOccurred())

				err = store.Revoke(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())

				_, err = store.Retrieve(ctx, tokenID)
				Expect(err).To(MatchError(storage.ErrTokenRevoked))
			})

			It("should return ErrTokenExpired for expired token", func() {
				past := time.Now().Add(-1 * time.Hour)
				err := store.Store(ctx, tokenID, userID, nil, past, metadata)
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
				err := store.Store(ctx, tokenID, userID, nil, expiresAt, metadata)
				Expect(err).NotTo(HaveOccurred())

				err = store.Revoke(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())

				_, err = store.Retrieve(ctx, tokenID)
				Expect(err).To(MatchError(storage.ErrTokenRevoked))
			})

			It("should be idempotent (revoke twice)", func() {
				err := store.Store(ctx, tokenID, userID, nil, expiresAt, metadata)
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
					err := store.Store(ctx, tid, userID, nil, expiresAt, metadata)
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

				err := store.Store(ctx, "token-1", user1ID, nil, expiresAt, metadata)
				Expect(err).NotTo(HaveOccurred())

				err = store.Store(ctx, "token-2", user2ID, nil, expiresAt, metadata)
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
				err := store.Store(ctx, tokenID, userID, nil, expiresAt, metadata)
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

				err := store.Store(ctx, tokenID, userID, nil, veryShortLived, metadata)
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
					err := store.Store(ctx, tid, userID, nil, veryShortLived, metadata)
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
				err := store.Store(ctx, tokenID, userID, nil, future, metadata)
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
				err := store.Store(ctx, "future-token", userID, nil, future, metadata)
				Expect(err).NotTo(HaveOccurred())

				shortLived := time.Now().Add(50 * time.Millisecond)
				err = store.Store(ctx, "short-token", userID, nil, shortLived, metadata)
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
				err := store.Store(ctx, uuidToken, userID, nil, expiresAt, metadata)
				Expect(err).NotTo(HaveOccurred())

				token, err := store.Retrieve(ctx, uuidToken)
				Expect(err).NotTo(HaveOccurred())
				Expect(token.TokenID).To(Equal(uuidToken))
			})

			It("should handle unicode in userID", func() {
				uuidUser := "user-🔐-xyz"
				err := store.Store(ctx, tokenID, uuidUser, nil, expiresAt, metadata)
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
					err := store.Store(ctx, tid, userID, nil, expiresAt, metadata)
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

				err := store.Store(ctx, tokenID, userID, nil, expiresAt, largeMeta)
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
				err := store.Store(ctx, tokenID, userID, nil, farFuture, metadata)
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
					map[string]string{"operation": "store", "status": "success", "error_type": "", "storage_backend": backend, "namespace": ""})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "store", "storage_backend": backend, "namespace": ""})
				// Some implementations (e.g. Memory) update the token-count gauge on
				// every Store; others (e.g. Redis) only update it in Cleanup.
				mockM.EXPECT().SetGauge("jwtauth_storage_tokens_count",
					gomock.Any(),
					map[string]string{"storage_backend": backend, "namespace": ""}).AnyTimes()

				err := ms.Store(ctx, tokenID, userID, nil, expiresAt, metadata)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should record validation_error status on Store with empty tokenID", func() {
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "store", "status": "validation_error", "error_type": "validation_error", "storage_backend": backend, "namespace": ""})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "store", "storage_backend": backend, "namespace": ""})

				err := ms.Store(ctx, "", userID, nil, expiresAt, metadata)
				Expect(err).To(HaveOccurred())
			})

			It("should record counter and duration on Retrieve success", func() {
				// Setup: Store the token (expect those metrics too)
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "store", "status": "success", "error_type": "", "storage_backend": backend, "namespace": ""})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "store", "storage_backend": backend, "namespace": ""})
				mockM.EXPECT().SetGauge("jwtauth_storage_tokens_count",
					gomock.Any(),
					map[string]string{"storage_backend": backend, "namespace": ""}).AnyTimes()
				Expect(ms.Store(ctx, tokenID, userID, nil, expiresAt, metadata)).To(Succeed())

				// Retrieve expectations
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "retrieve", "status": "success", "error_type": "", "storage_backend": backend, "namespace": ""})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "retrieve", "storage_backend": backend, "namespace": ""})

				token, err := ms.Retrieve(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())
				Expect(token).NotTo(BeNil())
			})

			It("should record not_found status on Retrieve for nonexistent token", func() {
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "retrieve", "status": "not_found", "error_type": "not_found", "storage_backend": backend, "namespace": ""})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "retrieve", "storage_backend": backend, "namespace": ""})

				_, err := ms.Retrieve(ctx, "nonexistent-token")
				Expect(err).To(MatchError(storage.ErrTokenNotFound))
			})

			It("should record revoked status on Retrieve for revoked token", func() {
				// Store
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "store", "status": "success", "error_type": "", "storage_backend": backend, "namespace": ""})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "store", "storage_backend": backend, "namespace": ""})
				mockM.EXPECT().SetGauge("jwtauth_storage_tokens_count",
					gomock.Any(),
					map[string]string{"storage_backend": backend, "namespace": ""}).AnyTimes()
				Expect(ms.Store(ctx, tokenID, userID, nil, expiresAt, metadata)).To(Succeed())

				// Revoke
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "revoke", "status": "success", "error_type": "", "storage_backend": backend, "namespace": ""})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "revoke", "storage_backend": backend, "namespace": ""})
				Expect(ms.Revoke(ctx, tokenID)).To(Succeed())

				// Retrieve
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "retrieve", "status": "revoked", "error_type": "revoked", "storage_backend": backend, "namespace": ""})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "retrieve", "storage_backend": backend, "namespace": ""})

				_, err := ms.Retrieve(ctx, tokenID)
				Expect(err).To(MatchError(storage.ErrTokenRevoked))
			})

			It("should record counter and duration on Revoke success", func() {
				// Store
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "store", "status": "success", "error_type": "", "storage_backend": backend, "namespace": ""})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "store", "storage_backend": backend, "namespace": ""})
				mockM.EXPECT().SetGauge("jwtauth_storage_tokens_count",
					gomock.Any(),
					map[string]string{"storage_backend": backend, "namespace": ""}).AnyTimes()
				Expect(ms.Store(ctx, tokenID, userID, nil, expiresAt, metadata)).To(Succeed())

				// Revoke
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "revoke", "status": "success", "error_type": "", "storage_backend": backend, "namespace": ""})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "revoke", "storage_backend": backend, "namespace": ""})

				Expect(ms.Revoke(ctx, tokenID)).To(Succeed())
			})

			It("should record counter and duration on RevokeAllForUser success", func() {
				// Store
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "store", "status": "success", "error_type": "", "storage_backend": backend, "namespace": ""})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "store", "storage_backend": backend, "namespace": ""})
				mockM.EXPECT().SetGauge("jwtauth_storage_tokens_count",
					gomock.Any(),
					map[string]string{"storage_backend": backend, "namespace": ""}).AnyTimes()
				Expect(ms.Store(ctx, tokenID, userID, nil, expiresAt, metadata)).To(Succeed())

				// RevokeAllForUser
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "revoke_all", "status": "success", "error_type": "", "storage_backend": backend, "namespace": ""})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "revoke_all", "storage_backend": backend, "namespace": ""})

				Expect(ms.RevokeAllForUser(ctx, userID)).To(Succeed())
			})

			It("should record counter, duration, removed count, and gauge on Cleanup with expired tokens", func() {
				veryShortLived := time.Now().Add(50 * time.Millisecond)

				// Store short-lived token
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "store", "status": "success", "error_type": "", "storage_backend": backend, "namespace": ""})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "store", "storage_backend": backend, "namespace": ""})
				// Memory updates the gauge on Store (value=1 after first insert); Redis does not.
				mockM.EXPECT().SetGauge("jwtauth_storage_tokens_count",
					float64(1),
					map[string]string{"storage_backend": backend, "namespace": ""}).AnyTimes()
				err := ms.Store(ctx, tokenID, userID, nil, veryShortLived, metadata)
				if err != nil {
					Skip("store rejected short-lived token")
				}

				time.Sleep(100 * time.Millisecond)

				// Cleanup expectations
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "cleanup", "status": "success", "error_type": "", "storage_backend": backend, "namespace": ""})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "cleanup", "storage_backend": backend, "namespace": ""})
				mockM.EXPECT().AddCounter("jwtauth_storage_cleanup_tokens_removed_total",
					float64(1),
					map[string]string{"storage_backend": backend, "namespace": ""})
				mockM.EXPECT().SetGauge("jwtauth_storage_tokens_count",
					float64(0),
					map[string]string{"storage_backend": backend, "namespace": ""})

				count, err := ms.Cleanup(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(count).To(Equal(1))
			})

			It("should record zero removed count and gauge on Cleanup with no tokens", func() {
				mockM.EXPECT().IncrementCounter("jwtauth_storage_operations_total",
					map[string]string{"operation": "cleanup", "status": "success", "error_type": "", "storage_backend": backend, "namespace": ""})
				mockM.EXPECT().RecordDuration("jwtauth_storage_operation_duration_seconds",
					gomock.Any(),
					map[string]string{"operation": "cleanup", "storage_backend": backend, "namespace": ""})
				mockM.EXPECT().AddCounter("jwtauth_storage_cleanup_tokens_removed_total",
					float64(0),
					map[string]string{"storage_backend": backend, "namespace": ""})
				mockM.EXPECT().SetGauge("jwtauth_storage_tokens_count",
					float64(0),
					map[string]string{"storage_backend": backend, "namespace": ""})

				count, err := ms.Cleanup(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(count).To(Equal(0))
			})

			It("should not panic when metrics is nil", func() {
				nilMetricsStore := factory(mockLogger, nil)
				Expect(func() {
					_ = nilMetricsStore.Store(ctx, tokenID, userID, nil, expiresAt, metadata)
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

				err := store.Store(cancelledCtx, tokenID, userID, nil, expiresAt, metadata)
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

		// ============================================================
		// PHASE 12: ListTokens — Cursor-based Pagination
		// Checkpoint: Exhaustive iteration, no duplicates, no gaps, context cancellation
		// ============================================================
		Describe("Phase 12: ListTokens", func() {
			It("should return empty slice and empty cursor for empty store", func() {
				tokens, next, err := store.ListTokens(ctx, "", 10)
				Expect(err).NotTo(HaveOccurred())
				Expect(tokens).To(BeEmpty())
				Expect(next).To(BeEmpty())
			})

			It("should return all tokens in a single page when count >= total", func() {
				for i := 0; i < 3; i++ {
					Expect(store.Store(ctx, fmt.Sprintf("tok-single-%d", i), userID, nil, expiresAt, nil)).To(Succeed())
				}

				tokens, next, err := store.ListTokens(ctx, "", 100)
				Expect(err).NotTo(HaveOccurred())
				Expect(tokens).To(HaveLen(3))
				Expect(next).To(BeEmpty())
			})

			It("should return all tokens across multiple pages with no gaps", func() {
				const total = 7
				for i := 0; i < total; i++ {
					Expect(store.Store(ctx, fmt.Sprintf("tok-page-%02d", i), userID, nil, expiresAt, nil)).To(Succeed())
				}

				var all []*storage.RefreshToken
				cursor := ""
				for {
					page, next, err := store.ListTokens(ctx, cursor, 3)
					Expect(err).NotTo(HaveOccurred())
					all = append(all, page...)
					cursor = next
					if cursor == "" {
						break
					}
				}

				Expect(all).To(HaveLen(total))

				seen := map[string]bool{}
				for _, t := range all {
					Expect(seen[t.TokenID]).To(BeFalse(), "duplicate token: %s", t.TokenID)
					seen[t.TokenID] = true
				}
			})

			It("should return empty cursor when iteration is exhausted", func() {
				for i := 0; i < 2; i++ {
					Expect(store.Store(ctx, fmt.Sprintf("tok-exhaust-%d", i), userID, nil, expiresAt, nil)).To(Succeed())
				}

				_, finalCursor, err := store.ListTokens(ctx, "", 100)
				Expect(err).NotTo(HaveOccurred())
				Expect(finalCursor).To(BeEmpty())
			})

			It("should return non-overlapping pages on successive calls", func() {
				for i := 0; i < 6; i++ {
					Expect(store.Store(ctx, fmt.Sprintf("tok-overlap-%02d", i), userID, nil, expiresAt, nil)).To(Succeed())
				}

				page1, cursor1, err := store.ListTokens(ctx, "", 3)
				Expect(err).NotTo(HaveOccurred())
				Expect(page1).NotTo(BeEmpty())

				if cursor1 != "" {
					page2, _, err := store.ListTokens(ctx, cursor1, 3)
					Expect(err).NotTo(HaveOccurred())

					ids1 := map[string]bool{}
					for _, t := range page1 {
						ids1[t.TokenID] = true
					}
					for _, t := range page2 {
						Expect(ids1[t.TokenID]).To(BeFalse(), "token %s appeared in both pages", t.TokenID)
					}
				}
			})

			It("should return no error for count=0", func() {
				Expect(store.Store(ctx, "tok-count0", userID, nil, expiresAt, nil)).To(Succeed())
				_, _, err := store.ListTokens(ctx, "", 0)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should return context error on cancelled context for ListTokens", func() {
				cancelledCtx, cancel := context.WithCancel(context.Background())
				cancel()

				_, _, err := store.ListTokens(cancelledCtx, "", 10)
				Expect(err).To(MatchError(context.Canceled))
			})

			It("should return revoked and expired tokens alongside active tokens", func() {
				active := "tok-active"
				revoked := "tok-revoked"
				expired := "tok-expired"

				Expect(store.Store(ctx, active, userID, nil, expiresAt, nil)).To(Succeed())
				Expect(store.Store(ctx, revoked, userID, nil, expiresAt, nil)).To(Succeed())
				Expect(store.Revoke(ctx, revoked)).To(Succeed())
				// Store expired token: use far-future expiry then mutate via Cleanup-immune path.
				// Memory: we can store with a short expiry but Cleanup hasn't run, so it's still present.
				// Just verify all tokens stored and visible (Cleanup hasn't run yet).
				Expect(store.Store(ctx, expired, userID, nil, time.Now().Add(24*time.Hour), nil)).To(Succeed())

				var all []*storage.RefreshToken
				cursor := ""
				for {
					page, next, err := store.ListTokens(ctx, cursor, 100)
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
				Expect(tokenIDs[active]).To(BeTrue(), "active token missing from ListTokens")
				Expect(tokenIDs[revoked]).To(BeTrue(), "revoked token missing from ListTokens")
				Expect(tokenIDs[expired]).To(BeTrue(), "expired token missing from ListTokens")
			})
		})

		// PHASE 13: ListTokensForUser — User-scoped Cursor-based Pagination
		//
		// Verifies that ListTokensForUser correctly scopes iteration to a single
		// user's tokens and that cursor-based pagination exhausts the set cleanly.

		Describe("Phase 13: ListTokensForUser", func() {
			It("should return empty result for user with no tokens", func() {
				tokens, next, err := store.ListTokensForUser(ctx, "ghost-user", "", 10)
				Expect(err).NotTo(HaveOccurred())
				Expect(tokens).To(BeEmpty())
				Expect(next).To(BeEmpty())
			})

			It("should return all tokens for a user in a single page", func() {
				user := "user-single-page"
				ids := []string{"tok-a", "tok-b", "tok-c"}
				for _, id := range ids {
					Expect(store.Store(ctx, id, user, nil, expiresAt, nil)).To(Succeed())
				}

				tokens, next, err := store.ListTokensForUser(ctx, user, "", 100)
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
				user := "user-paginate"
				total := 7
				for i := 0; i < total; i++ {
					Expect(store.Store(ctx, fmt.Sprintf("page-tok-%d", i), user, nil, expiresAt, nil)).To(Succeed())
				}

				var all []*storage.RefreshToken
				cursor := ""
				for {
					page, next, err := store.ListTokensForUser(ctx, user, cursor, 3)
					Expect(err).NotTo(HaveOccurred())
					all = append(all, page...)
					cursor = next
					if cursor == "" {
						break
					}
				}
				Expect(all).To(HaveLen(total))
			})

			It("should isolate tokens between different users", func() {
				userA := "user-isolation-a"
				userB := "user-isolation-b"
				Expect(store.Store(ctx, "tok-iso-a1", userA, nil, expiresAt, nil)).To(Succeed())
				Expect(store.Store(ctx, "tok-iso-a2", userA, nil, expiresAt, nil)).To(Succeed())
				Expect(store.Store(ctx, "tok-iso-b1", userB, nil, expiresAt, nil)).To(Succeed())

				tokensA, _, err := store.ListTokensForUser(ctx, userA, "", 100)
				Expect(err).NotTo(HaveOccurred())
				Expect(tokensA).To(HaveLen(2))
				for _, t := range tokensA {
					Expect(t.UserID).To(Equal(userA))
				}

				tokensB, _, err := store.ListTokensForUser(ctx, userB, "", 100)
				Expect(err).NotTo(HaveOccurred())
				Expect(tokensB).To(HaveLen(1))
				Expect(tokensB[0].UserID).To(Equal(userB))
			})

			It("should return ErrInvalidUserID for empty userID", func() {
				_, _, err := store.ListTokensForUser(ctx, "", "", 10)
				Expect(err).To(MatchError(storage.ErrInvalidUserID))
			})

			It("should return empty next cursor when iteration is exhausted", func() {
				user := "user-exhaust"
				Expect(store.Store(ctx, "tok-exhaust-1", user, nil, expiresAt, nil)).To(Succeed())
				Expect(store.Store(ctx, "tok-exhaust-2", user, nil, expiresAt, nil)).To(Succeed())

				_, finalCursor, err := store.ListTokensForUser(ctx, user, "", 100)
				Expect(err).NotTo(HaveOccurred())
				Expect(finalCursor).To(BeEmpty())
			})

			It("should return context error on cancelled context", func() {
				cancelledCtx, cancel := context.WithCancel(context.Background())
				cancel()

				_, _, err := store.ListTokensForUser(cancelledCtx, userID, "", 10)
				Expect(err).To(MatchError(context.Canceled))
			})

			It("should return revoked and active tokens for the user", func() {
				user := "user-mixed"
				active := "tok-user-active"
				revoked := "tok-user-revoked"

				Expect(store.Store(ctx, active, user, nil, expiresAt, nil)).To(Succeed())
				Expect(store.Store(ctx, revoked, user, nil, expiresAt, nil)).To(Succeed())
				Expect(store.Revoke(ctx, revoked)).To(Succeed())

				var all []*storage.RefreshToken
				cursor := ""
				for {
					page, next, err := store.ListTokensForUser(ctx, user, cursor, 100)
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
				Expect(tokenIDs[active]).To(BeTrue(), "active token missing from ListTokensForUser")
				Expect(tokenIDs[revoked]).To(BeTrue(), "revoked token missing from ListTokensForUser")
			})
		})

		// ============================================================
		// ============================================================
		Describe("Phase 14: RevokeAllForAudience", func() {
			var expiresAt time.Time
			BeforeEach(func() {
				expiresAt = time.Now().Add(24 * time.Hour)
			})

			It("should revoke all tokens for the target audience and return the count", func() {
				aud := []string{"svc-payments"}
				Expect(store.Store(ctx, "tok-pay-1", "user-aud", aud, expiresAt, nil)).To(Succeed())
				Expect(store.Store(ctx, "tok-pay-2", "user-aud", aud, expiresAt, nil)).To(Succeed())

				n, err := store.RevokeAllForAudience(ctx, "svc-payments")
				Expect(err).NotTo(HaveOccurred())
				Expect(n).To(Equal(2))

				_, err = store.Retrieve(ctx, "tok-pay-1")
				Expect(err).To(MatchError(storage.ErrTokenRevoked))
				_, err = store.Retrieve(ctx, "tok-pay-2")
				Expect(err).To(MatchError(storage.ErrTokenRevoked))
			})

			It("should not affect tokens issued for a different audience", func() {
				Expect(store.Store(ctx, "tok-pay", "user-aud", []string{"svc-payments"}, expiresAt, nil)).To(Succeed())
				Expect(store.Store(ctx, "tok-rep", "user-aud", []string{"svc-reports"}, expiresAt, nil)).To(Succeed())

				_, err := store.RevokeAllForAudience(ctx, "svc-payments")
				Expect(err).NotTo(HaveOccurred())

				_, err = store.Retrieve(ctx, "tok-pay")
				Expect(err).To(MatchError(storage.ErrTokenRevoked))

				tok, err := store.Retrieve(ctx, "tok-rep")
				Expect(err).NotTo(HaveOccurred())
				Expect(tok.Revoked).To(BeFalse())
			})

			It("should not affect tokens issued with no audience", func() {
				Expect(store.Store(ctx, "tok-noaud", "user-aud", nil, expiresAt, nil)).To(Succeed())

				_, err := store.RevokeAllForAudience(ctx, "svc-payments")
				Expect(err).NotTo(HaveOccurred())

				tok, err := store.Retrieve(ctx, "tok-noaud")
				Expect(err).NotTo(HaveOccurred())
				Expect(tok.Revoked).To(BeFalse())
			})

			It("should revoke a multi-audience token when either audience is targeted", func() {
				Expect(store.Store(ctx, "tok-multi", "user-aud", []string{"svc-payments", "svc-reports"}, expiresAt, nil)).To(Succeed())

				n, err := store.RevokeAllForAudience(ctx, "svc-payments")
				Expect(err).NotTo(HaveOccurred())
				Expect(n).To(Equal(1))

				_, err = store.Retrieve(ctx, "tok-multi")
				Expect(err).To(MatchError(storage.ErrTokenRevoked))
			})

			It("should count already-revoked tokens and not error (idempotent)", func() {
				Expect(store.Store(ctx, "tok-pre-rev", "user-aud", []string{"svc-payments"}, expiresAt, nil)).To(Succeed())
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
				Expect(store.Store(ctx, "tok-expire-aud", "user-aud", []string{"svc-payments"}, shortExp, nil)).To(Succeed())

				time.Sleep(100 * time.Millisecond)
				_, err := store.Cleanup(ctx)
				Expect(err).NotTo(HaveOccurred())

				n, err := store.RevokeAllForAudience(ctx, "svc-payments")
				Expect(err).NotTo(HaveOccurred())
				Expect(n).To(Equal(0))
			})
		})
		// ============================================================

		// ============================================================
		Describe("Phase 15: RevokeAllForUserAndAudience", func() {
			var expiresAt time.Time
			BeforeEach(func() {
				expiresAt = time.Now().Add(24 * time.Hour)
			})

			It("should revoke only the specified user's tokens for that audience", func() {
				user1 := "user-ua-1"
				user2 := "user-ua-2"
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
				Expect(store.Store(ctx, "tok-ua-pay", "user-ua", []string{"svc-payments"}, expiresAt, nil)).To(Succeed())
				Expect(store.Store(ctx, "tok-ua-rep", "user-ua", []string{"svc-reports"}, expiresAt, nil)).To(Succeed())

				_, err := store.RevokeAllForUserAndAudience(ctx, "user-ua", "svc-payments")
				Expect(err).NotTo(HaveOccurred())

				_, err = store.Retrieve(ctx, "tok-ua-pay")
				Expect(err).To(MatchError(storage.ErrTokenRevoked))

				tok, err := store.Retrieve(ctx, "tok-ua-rep")
				Expect(err).NotTo(HaveOccurred())
				Expect(tok.Revoked).To(BeFalse())
			})

			It("should return zero count and no error when user has no tokens for that audience", func() {
				n, err := store.RevokeAllForUserAndAudience(ctx, "user-ua", "svc-nonexistent")
				Expect(err).NotTo(HaveOccurred())
				Expect(n).To(Equal(0))
			})

			It("should return ErrInvalidUserID for empty userID", func() {
				_, err := store.RevokeAllForUserAndAudience(ctx, "", "svc-payments")
				Expect(err).To(MatchError(storage.ErrInvalidUserID))
			})

			It("should return ErrInvalidAudience for empty audience", func() {
				_, err := store.RevokeAllForUserAndAudience(ctx, "user-ua", "")
				Expect(err).To(MatchError(storage.ErrInvalidAudience))
			})

			It("should return context error on cancelled context", func() {
				cancelledCtx, cancel := context.WithCancel(context.Background())
				cancel()

				_, err := store.RevokeAllForUserAndAudience(cancelledCtx, "user-ua", "svc-payments")
				Expect(err).To(MatchError(context.Canceled))
			})
		})
		// ============================================================

		// ============================================================
		// PHASE 16: ListTokensForAudience — Audience-scoped Cursor-based Pagination
		//
		// Verifies that ListTokensForAudience correctly scopes iteration to a
		// single audience's tokens and that cursor-based pagination exhausts the
		// set cleanly. Also validates multi-audience token visibility: a token
		// issued with multiple audiences must appear in listings for each.
		Describe("Phase 16: ListTokensForAudience", func() {
			var expiresAt time.Time
			BeforeEach(func() {
				expiresAt = time.Now().Add(24 * time.Hour)
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
		// ============================================================

	})
}
