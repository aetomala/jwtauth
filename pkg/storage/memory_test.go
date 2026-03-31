package storage_test

import (
	"context"
	"fmt"
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
	// PHASE 1: Constructor
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
	// PHASE 2.5: Context Handling - Cancellation Coverage
	// Checkpoint: Context cancellation properly logged and propagated
	// ============================================================
	Describe("Phase 2.5: Store - Context Cancellation", func() {
		It("should abort with cancelled context and log warning", func() {
			cancelledCtx, cancel := context.WithCancel(context.Background())
			cancel()

			mockLogger.Clear()
			err := store.Store(cancelledCtx, tokenID, userID, expiresAt, metadata)

			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(context.Canceled))

			// Should log at Warn level
			warnCount := mockLogger.CountLogs("warn")
			Expect(warnCount).To(BeNumerically(">", 0))
		})
	})

	Describe("Phase 2.5: Retrieve - Context Cancellation", func() {
		BeforeEach(func() {
			err := store.Store(ctx, tokenID, userID, expiresAt, metadata)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should abort with cancelled context and log warning", func() {
			cancelledCtx, cancel := context.WithCancel(context.Background())
			cancel()

			mockLogger.Clear()
			token, err := store.Retrieve(cancelledCtx, tokenID)

			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(context.Canceled))
			Expect(token).To(BeNil())

			// Should log at Warn level
			warnCount := mockLogger.CountLogs("warn")
			Expect(warnCount).To(BeNumerically(">", 0))
		})
	})

	// ============================================================
	// PHASE 3: Critical Input Validation
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

		It("should make defensive copy of metadata (prevent caller mutation)", func() {
			originalMeta := map[string]interface{}{
				"ip":     "192.168.1.1",
				"device": "phone",
			}

			err := store.Store(ctx, tokenID, userID, expiresAt, originalMeta)
			Expect(err).NotTo(HaveOccurred())

			// Mutate the original metadata after storing
			originalMeta["ip"] = "10.0.0.1"
			originalMeta["newKey"] = "hacked"
			delete(originalMeta, "device")

			// Retrieve token should have ORIGINAL values
			token, err := store.Retrieve(ctx, tokenID)
			Expect(err).NotTo(HaveOccurred())
			Expect(token.Metadata["ip"]).To(Equal("192.168.1.1"))
			Expect(token.Metadata["device"]).To(Equal("phone"))
			Expect(token.Metadata).NotTo(HaveKey("newKey"))
		})

		It("should accept nil metadata", func() {
			err := store.Store(ctx, tokenID, userID, expiresAt, nil)
			Expect(err).NotTo(HaveOccurred())

			token, err := store.Retrieve(ctx, tokenID)
			Expect(err).NotTo(HaveOccurred())
			Expect(token.Metadata).To(BeNil())
		})

		It("should accept empty metadata map", func() {
			emptyMeta := map[string]interface{}{}
			err := store.Store(ctx, tokenID, userID, expiresAt, emptyMeta)
			Expect(err).NotTo(HaveOccurred())

			token, err := store.Retrieve(ctx, tokenID)
			Expect(err).NotTo(HaveOccurred())
			Expect(token.Metadata).To(BeEmpty())
		})
	})

	Describe("Phase 3: Retrieve - Input Validation", func() {
		It("should reject empty tokenID", func() {
			token, err := store.Retrieve(ctx, "")
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(storage.ErrInvalidTokenID))
			Expect(token).To(BeNil())
		})

		It("should reject whitespace-only tokenID", func() {
			token, err := store.Retrieve(ctx, "   ")
			Expect(err).To(HaveOccurred())
			Expect(err).To(MatchError(storage.ErrInvalidTokenID))
			Expect(token).To(BeNil())
		})

		It("should return ErrTokenNotFound for non-existent token", func() {
			token, err := store.Retrieve(ctx, "does-not-exist")
			Expect(err).To(MatchError(storage.ErrTokenNotFound))
			Expect(token).To(BeNil())
		})
	})

	// ============================================================
	// PHASE 4: Defensive Programming
	// Checkpoint: Internal data structures protected
	// CATCHES: BUG #4 (userTokens dangling pointers)
	// ============================================================
	Describe("Phase 4: Store = userTokens Cleanup", func() {
		It("should clean up old userTokens entry when tokenID changes owner", func() {
			// store token for user-1
			err := store.Store(ctx, tokenID, "user-1", expiresAt, metadata)
			Expect(err).NotTo(HaveOccurred())

			// Overwrite same tokenID for user-2
			err = store.Store(ctx, tokenID, "user-2", expiresAt, metadata)
			Expect(err).NotTo(HaveOccurred())

			// Token should still be retrievable (belongs to user-2 now)
			token, err := store.Retrieve(ctx, tokenID)
			Expect(err).NotTo(HaveOccurred())
			Expect(token.UserID).To(Equal("user-2"))
			Expect(token.Revoked).To(BeFalse())
		})

		It("should not create duplicate entires in userTokens", func() {
			// Store same tokenID multiple time for same user
			err := store.Store(ctx, tokenID, userID, expiresAt, metadata)
			Expect(err).NotTo(HaveOccurred())

			err = store.Store(ctx, tokenID, userID, expiresAt, metadata)
			Expect(err).NotTo(HaveOccurred())

			err = store.Store(ctx, tokenID, userID, expiresAt, metadata)
			Expect(err).NotTo(HaveOccurred())

			// RevokeAllForUser should work correctly (no duplicates)
			err = store.RevokeAllForUser(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			_, err = store.Retrieve(ctx, tokenID)
			Expect(err).To(MatchError(storage.ErrTokenRevoked))

		})

		It("should allow overwrite with new data for same user", func() {
			newMetadata := map[string]interface{}{"ip": "10.0.0.1"}
			newExpiresAt := time.Now().Add(48 * time.Hour)

			err := store.Store(ctx, tokenID, userID, expiresAt, metadata)
			Expect(err).NotTo(HaveOccurred())

			// Overwrite
			err = store.Store(ctx, tokenID, userID, newExpiresAt, newMetadata)
			Expect(err).NotTo(HaveOccurred())

			token, err := store.Retrieve(ctx, tokenID)
			Expect(err).NotTo(HaveOccurred())
			Expect(token.Metadata["ip"]).To(Equal("10.0.0.1"))
			Expect(token.ExpiresAt).To(BeTemporally("~", newExpiresAt, time.Second))
		})
	})

	Describe("Phase 4: Retrieve - Defensive Copy", func() {
		BeforeEach(func() {
			err := store.Store(ctx, tokenID, userID, expiresAt, metadata)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return defensive copy (caller cannot mutate stored token)", func() {
			token1, err := store.Retrieve(ctx, tokenID)
			Expect(err).NotTo(HaveOccurred())

			// Mutate returned token
			token1.Revoked = true
			token1.UserID = "hacker"
			token1.Metadata["hacked"] = "true"

			// Retrieve again - should be unchanged
			token2, err := store.Retrieve(ctx, tokenID)
			Expect(err).NotTo(HaveOccurred())
			Expect(token2.Revoked).To(BeFalse())
			Expect(token2.UserID).To(Equal(userID))
			Expect(token2.Metadata).NotTo(HaveKey("hacked"))
		})

		It("should isolate metadata between successive retrievals", func() {
			token1, err := store.Retrieve(ctx, tokenID)
			Expect(err).NotTo(HaveOccurred())

			// Mutate only the metadata on the first retrieved copy
			originalIP := token1.Metadata["ip"]
			token1.Metadata["ip"] = "10.0.0.1"

			// Second retrieval should still have the original value
			token2, err := store.Retrieve(ctx, tokenID)
			Expect(err).NotTo(HaveOccurred())
			Expect(token2.Metadata["ip"]).To(Equal(originalIP))
		})
	})

	// ============================================================
	// PHASE 5: Contract Compliance - Retrieve
	// Checkpoint: Retrieve honors its contract
	// CATCHES: BUG #7 (expiry check), BUG #8 (revocation check), BUG #10 (logging)
	// ============================================================
	Describe("Phase 5: Retrieve - Expiry Check", func() {
		It("should reject token that expired 1 second ago", func() {
			// Store token that expires soon
			soonExpires := time.Now().Add(100 * time.Millisecond)
			err := store.Store(ctx, "expiring-token", userID, soonExpires, metadata)
			Expect(err).NotTo(HaveOccurred())

			// Wait for expiration
			time.Sleep(200 * time.Millisecond)

			// Should now be expired
			token, err := store.Retrieve(ctx, "expiring-token")
			Expect(err).To(MatchError(storage.ErrTokenExpired))
			Expect(token).To(BeNil())
		})

		It("should reject token expiring at boundary (exactly now)", func() {
			now := time.Now()
			futureTime := now.Add(50 * time.Millisecond)
			err := store.Store(ctx, "boundary-token", userID, futureTime, metadata)
			Expect(err).NotTo(HaveOccurred())

			time.Sleep(60 * time.Millisecond)

			token, err := store.Retrieve(ctx, "boundary-token")
			Expect(err).To(MatchError(storage.ErrTokenExpired))
			Expect(token).To(BeNil())
		})
	})

	Describe("Phase 5: Retrieve - Revocation Check", func() {
		BeforeEach(func() {
			err := store.Store(ctx, tokenID, userID, expiresAt, metadata)
			Expect(err).NotTo(HaveOccurred())

			err = store.Revoke(ctx, tokenID)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should reject revoked token", func() {
			token, err := store.Retrieve(ctx, tokenID)
			Expect(err).To(MatchError(storage.ErrTokenRevoked))
			Expect(token).To(BeNil())
		})

		It("should log at appropriate level (not error) for revoked token", func() {
			mockLogger.Clear()
			store.Retrieve(ctx, tokenID)

			// Revoked token retrieval is normal flow, not system error
			errorCount := mockLogger.CountLogs("error")
			Expect(errorCount).To(Equal(0))

			// Should log as warn or info
			warnOrInfoCount := mockLogger.CountLogs("warn") + mockLogger.CountLogs("info")
			Expect(warnOrInfoCount).To(BeNumerically(">", 0))
		})
	})

	Describe("Phase 5: Retrieve - Logging Levels", func() {
		It("should log at warn/info level for token not found (not error)", func() {
			mockLogger.Clear()
			store.Retrieve(ctx, "does-not-exists")

			// "Token not found" is normal flow, NOT an error
			errorCount := mockLogger.CountLogs("error")
			Expect(errorCount).To(Equal(0))
		})

		It("should log successful retrieve at appropriate level (not error)", func() {
			err := store.Store(ctx, tokenID, userID, expiresAt, metadata)
			Expect(err).NotTo(HaveOccurred())

			mockLogger.Clear()
			_, err = store.Retrieve(ctx, tokenID)
			Expect(err).NotTo(HaveOccurred())

			// Should NOT log as error
			errorCount := mockLogger.CountLogs("error")
			Expect(errorCount).To(Equal(0))
		})
	})

	// ============================================================
	// PHASE 6: Concurrency Safety
	// Checkpoint: Thread-safe, race detector passes
	// CATCHES: BUG #5 (Lock instead of RLock)
	// ============================================================
	Describe("Phase 6: Concurrency - RLock Usage", func() {
		BeforeEach(func() {
			err := store.Store(ctx, tokenID, userID, expiresAt, metadata)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should use RLock for concurrent reads (not Lock)", func() {
			// This test verifies Retrieve uses RLock, not Lock
			// Multiple concurrent reads should succeed without blocking
			done := make(chan bool, 10)

			for i := 0; i < 10; i++ {
				go func() {
					defer GinkgoRecover()
					token, err := store.Retrieve(ctx, tokenID)
					Expect(err).NotTo(HaveOccurred())
					Expect(token).NotTo(BeNil())
					done <- true
				}()
			}

			// All should complete quickly (no blocking from Lock)
			for i := 0; i < 10; i++ {
				select {
				case <-done:
					// Success
				case <-time.After(1 * time.Second):
					Fail("Retrieve operations blocked - may be using Lock instead of RLock")
				}
			}
		})

		It("should handle concurrent Store operations", func() {
			done := make(chan bool, 10)

			for i := 0; i < 10; i++ {
				go func(index int) {
					defer GinkgoRecover()
					tid := fmt.Sprintf("token-%d", index)
					err := store.Store(ctx, tid, userID, expiresAt, metadata)
					Expect(err).NotTo(HaveOccurred())
					done <- true
				}(i)
			}

			for i := 0; i < 10; i++ {
				<-done
			}
		})

		It("should handle mixed Store and Retrieve operations", func() {
			done := make(chan bool, 10)

			// Concurrent stores
			for i := 0; i < 5; i++ {
				go func(index int) {
					defer GinkgoRecover()
					tid := fmt.Sprintf("token-%d", index)
					store.Store(ctx, tid, userID, expiresAt, metadata)
					done <- true
				}(i)
			}

			// Concurrent retrieves
			for i := 0; i < 5; i++ {
				go func(index int) {
					defer GinkgoRecover()
					tid := fmt.Sprintf("token-%d", index)
					store.Retrieve(ctx, tid)
					done <- true
				}(i)
			}

			for i := 0; i < 10; i++ {
				<-done
			}
		})
	})

	// ============================================================
	// PHASE 7: Remaining Methods
	// Checkpoint: All RefreshStore methods implemented
	// ============================================================
	Describe("Phase 7: Revoke", func() {
		Context("input validation", func() {
			It("should reject empty tokenID", func() {
				err := store.Revoke(ctx, "")
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError(storage.ErrInvalidTokenID))
			})

			It("should reject whitespace-only tokenID", func() {
				err := store.Revoke(ctx, "   ")
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError(storage.ErrInvalidTokenID))
			})
		})

		Context("with existing token", func() {
			BeforeEach(func() {
				err := store.Store(ctx, tokenID, userID, expiresAt, metadata)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should revoke token successfully", func() {
				err := store.Revoke(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should make token unretrievable after revocation", func() {
				err := store.Revoke(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())

				_, err = store.Retrieve(ctx, tokenID)
				Expect(err).To(MatchError(storage.ErrTokenRevoked))
			})

			It("should be idempotent (can revoke twice)", func() {
				err := store.Revoke(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())

				err = store.Revoke(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should only revoke specified token", func() {
				err := store.Store(ctx, "token-2", userID, expiresAt, metadata)
				Expect(err).NotTo(HaveOccurred())

				err = store.Revoke(ctx, tokenID)
				Expect(err).NotTo(HaveOccurred())

				// tokenID should be revoked
				_, err = store.Retrieve(ctx, tokenID)
				Expect(err).To(MatchError(storage.ErrTokenRevoked))

				// token-2 should still be valid
				token2, err := store.Retrieve(ctx, "token-2")
				Expect(err).NotTo(HaveOccurred())
				Expect(token2).NotTo(BeNil())
			})
		})

		Context("with non-existent token", func() {
			It("should not error (idempotent)", func() {
				err := store.Revoke(ctx, "does-not-exist")
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("context handling", func() {
			BeforeEach(func() {
				err := store.Store(ctx, tokenID, userID, expiresAt, metadata)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should respect context cancellation", func() {
				cancelledCtx, cancel := context.WithCancel(context.Background())
				cancel()

				err := store.Revoke(cancelledCtx, tokenID)
				Expect(err).To(MatchError(context.Canceled))
			})
		})

		Describe("Phase 7: RevokeAllForUser", func() {
			Context("input validation", func() {
				It("should reject empty userID", func() {
					err := store.RevokeAllForUser(ctx, "")
					Expect(err).To(HaveOccurred())
					Expect(err).To(MatchError(storage.ErrInvalidUserID))
				})

				It("should reject whitespace-only userID", func() {
					err := store.RevokeAllForUser(ctx, "   ")
					Expect(err).To(HaveOccurred())
					Expect(err).To(MatchError(storage.ErrInvalidUserID))
				})
			})

			Context("with multiple tokens for user", func() {
				BeforeEach(func() {
					err := store.Store(ctx, "token-1", userID, expiresAt, metadata)
					Expect(err).NotTo(HaveOccurred())

					err = store.Store(ctx, "token-2", userID, expiresAt, metadata)
					Expect(err).NotTo(HaveOccurred())

					err = store.Store(ctx, "token-3", userID, expiresAt, metadata)
					Expect(err).NotTo(HaveOccurred())

					err = store.Store(ctx, "other-token", "other-user", expiresAt, metadata)
					Expect(err).NotTo(HaveOccurred())
				})

				It("should revoke all token for specified user", func() {
					err := store.RevokeAllForUser(ctx, userID)
					Expect(err).NotTo(HaveOccurred())

					_, err = store.Retrieve(ctx, "token-1")
					Expect(err).To(MatchError(storage.ErrTokenRevoked))

					_, err = store.Retrieve(ctx, "token-2")
					Expect(err).To(MatchError(storage.ErrTokenRevoked))

					_, err = store.Retrieve(ctx, "token-3")
					Expect(err).To(MatchError(storage.ErrTokenRevoked))
				})

				It("should not affect other users' tokens", func() {
					err := store.RevokeAllForUser(ctx, userID)
					Expect(err).NotTo(HaveOccurred())

					token, err := store.Retrieve(ctx, "other-token")
					Expect(err).NotTo(HaveOccurred())
					Expect(token.UserID).To(Equal("other-user"))
				})
			})

			Context("idempotency", func() {
				BeforeEach(func() {
					err := store.Store(ctx, tokenID, userID, expiresAt, metadata)
					Expect(err).NotTo(HaveOccurred())
				})

				It("should be idempotent (cal call multiple times)", func() {
					err := store.RevokeAllForUser(ctx, userID)
					Expect(err).NotTo(HaveOccurred())

					err = store.RevokeAllForUser(ctx, userID)
					Expect(err).NotTo(HaveOccurred())

					err = store.RevokeAllForUser(ctx, userID)
					Expect(err).NotTo(HaveOccurred())
				})
			})

			Context("context handling", func() {
				BeforeEach(func() {
					err := store.Store(ctx, tokenID, userID, expiresAt, metadata)
					Expect(err).NotTo(HaveOccurred())
				})

				It("should respect context cancellation", func() {
					cancelledCtx, cancel := context.WithCancel(context.Background())
					cancel()

					err := store.RevokeAllForUser(cancelledCtx, userID)
					Expect(err).To(MatchError(context.Canceled))
				})
			})
		})
	})

	Describe("Phase 7: Cleanup", func() {
		Context("with expired tokens", func() {
			BeforeEach(func() {
				// Store tokens that expire soon
				soonExpires := time.Now().Add(50 * time.Millisecond)
				err := store.Store(ctx, "expired-1", userID, soonExpires, metadata)
				Expect(err).NotTo(HaveOccurred())

				soonExpires2 := time.Now().Add(60 * time.Millisecond)
				err = store.Store(ctx, "expired-2", "other-user", soonExpires2, metadata)

				// Store valid token
				validTime := time.Now().Add(24 * time.Hour)
				err = store.Store(ctx, "valid-1", userID, validTime, metadata)
				Expect(err).NotTo(HaveOccurred())

				//wait for tokens to expire
				time.Sleep(100 * time.Millisecond)
			})

			It("should remove expired tokens", func() {
				count, err := store.Cleanup(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(count).To(Equal(2))
			})

			It("should not remove valid tokens", func() {
				_, err := store.Cleanup(ctx)
				Expect(err).NotTo(HaveOccurred())

				token, err := store.Retrieve(ctx, "valid-1")
				Expect(err).NotTo(HaveOccurred())
				Expect(token).NotTo(BeNil())
			})

			It("should make expired tokens unretrievable", func() {
				_, err := store.Cleanup(ctx)
				Expect(err).NotTo(HaveOccurred())

				_, err = store.Retrieve(ctx, "expired-1")
				Expect(err).To(MatchError(storage.ErrTokenNotFound))
			})
		})

		Context("with no expired tokens", func() {
			BeforeEach(func() {
				validTime := time.Now().Add(24 * time.Hour)
				err := store.Store(ctx, "valid-1", userID, validTime, metadata)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should return zero count", func() {
				count, err := store.Cleanup(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(count).To(Equal(0))
			})
		})

		Context("with empty store", func() {
			It("should return zero count", func() {
				count, err := store.Cleanup(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(count).To(Equal(0))
			})
		})

		Context("with revoked but not expired tokens", func() {
			BeforeEach(func() {
				validTime := time.Now().Add(24 * time.Hour)
				err := store.Store(ctx, "revoked-but-valid", userID, validTime, metadata)
				Expect(err).NotTo(HaveOccurred())

				err = store.Revoke(ctx, "revoked-but-valid")
				Expect(err).NotTo(HaveOccurred())
			})

			It("should NOT remove revoked tokens that haven't expired", func() {
				count, err := store.Cleanup(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(count).To(Equal(0))

				// Token should still exist (but revoked)
				_, err = store.Retrieve(ctx, "revoked-but-valid")
				Expect(err).To(MatchError(storage.ErrTokenRevoked))
			})
		})

		Context("idempotency", func() {
			BeforeEach(func() {
				soonExpires := time.Now().Add(50 * time.Millisecond)
				err := store.Store(ctx, "expired-1", userID, soonExpires, metadata)
				Expect(err).NotTo(HaveOccurred())

				time.Sleep(100 * time.Millisecond)
			})

			It("should be idempotent (subsequent cleanups return zero)", func() {
				count, err := store.Cleanup(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(count).To(Equal(1))

				count, err = store.Cleanup(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(count).To(Equal(0))

				count, err = store.Cleanup(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(count).To(Equal(0))
			})
		})

		Context("context handling", func() {
			BeforeEach(func() {
				soonExpires := time.Now().Add(50 * time.Millisecond)
				err := store.Store(ctx, "expired-1", userID, soonExpires, metadata)
				Expect(err).NotTo(HaveOccurred())

				time.Sleep(100 * time.Millisecond)
			})

			It("should respect context cancellation", func() {
				cancelledCtx, cancel := context.WithCancel(context.Background())
				cancel()

				_, err := store.Cleanup(cancelledCtx)
				Expect(err).To(MatchError(context.Canceled))
			})
		})
	})

	// ============================================================
	// PHASE 8: Edge Cases
	// Checkpoint: Handles unusual but valid inputs
	// Can skip this phase if time-constrained
	// ============================================================
	Describe("Phase 8: Edge Cases - Special Characters", func() {
		It("should handle special characters in tokenID", func() {
			specialTokenID := "token-!@#$%^&*()_+-={}[]|:;<>?,."
			err := store.Store(ctx, specialTokenID, userID, expiresAt, metadata)
			Expect(err).NotTo(HaveOccurred())

			token, err := store.Retrieve(ctx, specialTokenID)
			Expect(err).NotTo(HaveOccurred())
			Expect(token.TokenID).To(Equal(specialTokenID))
		})

		It("should handle special characters in userID", func() {
			specialUserID := "user@example.com"
			err := store.Store(ctx, tokenID, specialUserID, expiresAt, metadata)
			Expect(err).NotTo(HaveOccurred())

			token, err := store.Retrieve(ctx, tokenID)
			Expect(err).NotTo(HaveOccurred())
			Expect(token.UserID).To(Equal(specialUserID))
		})

		It("should handle UUID-format IDs", func() {
			uuidToken := "550e8400-e29b-41d4-a716-446655440000"
			uuidUser := "7c9e6679-7425-40de-944b-e07fc1f90ae7"

			err := store.Store(ctx, uuidToken, uuidUser, expiresAt, metadata)
			Expect(err).NotTo(HaveOccurred())

			token, err := store.Retrieve(ctx, uuidToken)
			Expect(err).NotTo(HaveOccurred())
			Expect(token.UserID).To(Equal(uuidUser))
		})
	})

	Describe("Phase 8: Edge Cases - Large Scale", func() {
		It("should handle storing many tokens for one user", func() {
			// Store 100 tokens for same user
			for i := 0; i < 100; i++ {
				tid := fmt.Sprintf("token-%d", i)
				err := store.Store(ctx, tid, userID, expiresAt, metadata)
				Expect(err).NotTo(HaveOccurred())
			}

			// All should be retrievable
			for i := 0; i < 100; i++ {
				tid := fmt.Sprintf("token-%d", i)
				token, err := store.Retrieve(ctx, tid)
				Expect(err).NotTo(HaveOccurred())
				Expect(token.UserID).To(Equal(userID))
			}

			// RevokeAllForUser should revoke all 100
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

	Describe("Phase 8: Edge Cases - Far Future", func() {
		It("should handle tokens with very far future expiration", func() {
			farFuture := time.Now().Add(100 * 365 * 24 * time.Hour) // 100 years
			err := store.Store(ctx, tokenID, userID, farFuture, metadata)
			Expect(err).NotTo(HaveOccurred())

			token, err := store.Retrieve(ctx, tokenID)
			Expect(err).NotTo(HaveOccurred())
			Expect(token.ExpiresAt).To(BeTemporally("~", farFuture, time.Second))
		})
	})
})
