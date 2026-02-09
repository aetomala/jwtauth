package testutil_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aetomala/jwtauth/internal/testutil"
)

func TestTestutil(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Testutil Suite")
}

// ============================================================================
// MockKeyManager Tests
// ============================================================================

var _ = Describe("MockKeyManager", func() {
	var mockKM *testutil.MockKeyManager

	BeforeEach(func() {
		mockKM = testutil.NewMockKeyManager()
	})

	Describe("Constructor", func() {
		It("should create with default key pair", func() {
			Expect(mockKM).NotTo(BeNil())

			privateKey, keyID, err := mockKM.GetCurrentSigningKey()
			Expect(err).NotTo(HaveOccurred())
			Expect(privateKey).NotTo(BeNil())
			Expect(keyID).NotTo(BeEmpty())
		})

		It("should start as running", func() {
			Expect(mockKM.IsRunning()).To(BeTrue())
		})

		It("should have one default public key", func() {
			Expect(mockKM.GetPublicKeyCount()).To(Equal(1))
		})
	})

	Describe("GetCurrentSigningKey", func() {
		It("should return current key", func() {
			privateKey, keyID, err := mockKM.GetCurrentSigningKey()

			Expect(err).NotTo(HaveOccurred())
			Expect(privateKey).NotTo(BeNil())
			Expect(keyID).NotTo(BeEmpty())
			Expect(mockKM.GetCallCount("GetCurrentSigningKey")).To(Equal(1))
		})

		It("should return configured error", func() {
			testErr := testutil.NewMockError("test error")
			mockKM.SetGetCurrentSigningKeyError(testErr)

			_, _, err := mockKM.GetCurrentSigningKey()

			Expect(err).To(Equal(testErr))
			Expect(mockKM.GetCallCount("GetCurrentSigningKey")).To(Equal(1))
		})

		It("should track multiple calls", func() {
			mockKM.GetCurrentSigningKey()
			mockKM.GetCurrentSigningKey()
			mockKM.GetCurrentSigningKey()

			Expect(mockKM.GetCallCount("GetCurrentSigningKey")).To(Equal(3))
		})
	})

	Describe("GetPublicKey", func() {
		It("should return public key for valid key ID", func() {
			_, keyID, _ := mockKM.GetCurrentSigningKey()

			publicKey, err := mockKM.GetPublicKey(keyID)

			Expect(err).NotTo(HaveOccurred())
			Expect(publicKey).NotTo(BeNil())
			Expect(mockKM.GetCallCount("GetPublicKey")).To(Equal(1))
		})

		It("should track which key IDs were requested", func() {
			_, keyID, _ := mockKM.GetCurrentSigningKey()

			mockKM.GetPublicKey(keyID)

			Expect(mockKM.WasPublicKeyRequested(keyID)).To(BeTrue())
			Expect(mockKM.WasPublicKeyRequested("non-existent")).To(BeFalse())
		})

		It("should return error for non-existent key", func() {
			_, err := mockKM.GetPublicKey("non-existent-key")

			Expect(err).To(HaveOccurred())
			Expect(err).To(Equal(testutil.ErrMockKeyNotFound))
		})

		It("should return configured error", func() {
			testErr := testutil.NewMockError("test error")
			mockKM.SetGetPublicKeyError(testErr)

			_, err := mockKM.GetPublicKey("any-key")

			Expect(err).To(Equal(testErr))
		})
	})

	Describe("GetJWKS", func() {
		It("should return JWKS", func() {
			jwks, err := mockKM.GetJWKS()

			Expect(err).NotTo(HaveOccurred())
			Expect(jwks).NotTo(BeNil())
			Expect(len(jwks.Keys)).To(BeNumerically(">", 0))
			Expect(mockKM.GetCallCount("GetJWKS")).To(Equal(1))
		})

		It("should return configured error", func() {
			testErr := testutil.NewMockError("test error")
			mockKM.SetGetJWKSError(testErr)

			_, err := mockKM.GetJWKS()

			Expect(err).To(Equal(testErr))
		})
	})

	Describe("RotateKeys", func() {
		It("should rotate to new key", func() {
			_, oldKeyID, _ := mockKM.GetCurrentSigningKey()
			oldKeyCount := mockKM.GetPublicKeyCount()

			err := mockKM.RotateKeys()

			Expect(err).NotTo(HaveOccurred())
			Expect(mockKM.GetCallCount("RotateKeys")).To(Equal(1))

			_, newKeyID, _ := mockKM.GetCurrentSigningKey()
			Expect(newKeyID).NotTo(Equal(oldKeyID))
			Expect(mockKM.GetPublicKeyCount()).To(Equal(oldKeyCount + 1))
		})

		It("should keep old key accessible", func() {
			_, oldKeyID, _ := mockKM.GetCurrentSigningKey()

			mockKM.RotateKeys()

			// Old key should still be accessible
			oldPublicKey, err := mockKM.GetPublicKey(oldKeyID)
			Expect(err).NotTo(HaveOccurred())
			Expect(oldPublicKey).NotTo(BeNil())
		})

		It("should return configured error", func() {
			testErr := testutil.NewMockError("rotation failed")
			mockKM.SetRotateKeysError(testErr)

			err := mockKM.RotateKeys()

			Expect(err).To(Equal(testErr))
		})
	})

	Describe("Start and Shutdown", func() {
		It("should track start calls", func() {
			mockKM.Start()

			Expect(mockKM.GetCallCount("Start")).To(Equal(1))
			Expect(mockKM.IsRunning()).To(BeTrue())
		})

		It("should track shutdown calls", func() {
			mockKM.Shutdown()

			Expect(mockKM.GetCallCount("Shutdown")).To(Equal(1))
			Expect(mockKM.IsRunning()).To(BeFalse())
		})
	})

	Describe("Behavior Control", func() {
		It("should allow setting custom key", func() {
			// Create custom key
			customKey, _ := rsa.GenerateKey(rand.Reader, 2048)
			customKeyID := "custom-key-123"

			mockKM.SetCurrentKey(customKey, customKeyID)

			privateKey, keyID, _ := mockKM.GetCurrentSigningKey()
			Expect(keyID).To(Equal(customKeyID))
			Expect(privateKey).To(Equal(customKey))
		})

		It("should allow adding public keys", func() {
			customKey, _ := rsa.GenerateKey(rand.Reader, 2048)
			customKeyID := "custom-public-key"

			mockKM.AddPublicKey(customKeyID, &customKey.PublicKey)

			publicKey, err := mockKM.GetPublicKey(customKeyID)
			Expect(err).NotTo(HaveOccurred())
			Expect(publicKey).To(Equal(&customKey.PublicKey))
		})

		It("should allow removing public keys", func() {
			_, keyID, _ := mockKM.GetCurrentSigningKey()

			mockKM.RemovePublicKey(keyID)

			_, err := mockKM.GetPublicKey(keyID)
			Expect(err).To(HaveOccurred())
		})
	})

	Describe("Reset", func() {
		It("should reset call counters", func() {
			mockKM.GetCurrentSigningKey()
			mockKM.GetPublicKey("test")
			mockKM.RotateKeys()

			mockKM.Reset()

			Expect(mockKM.GetCallCount("GetCurrentSigningKey")).To(Equal(0))
			Expect(mockKM.GetCallCount("GetPublicKey")).To(Equal(0))
			Expect(mockKM.GetCallCount("RotateKeys")).To(Equal(0))
		})

		It("should reset errors", func() {
			testErr := testutil.NewMockError("test")
			mockKM.SetGetCurrentSigningKeyError(testErr)

			mockKM.ResetErrors()

			_, _, err := mockKM.GetCurrentSigningKey()
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Describe("Concurrent Usage", func() {
		It("should be thread-safe", func() {
			done := make(chan bool, 10)

			for i := 0; i < 10; i++ {
				go func() {
					defer GinkgoRecover()
					mockKM.GetCurrentSigningKey()
					mockKM.RotateKeys()
					done <- true
				}()
			}

			for i := 0; i < 10; i++ {
				Eventually(done).Should(Receive())
			}
		})
	})
})

// ============================================================================
// MockRefreshStore Tests
// ============================================================================

var _ = Describe("MockRefreshStore", func() {
	var mockStore *testutil.MockRefreshStore

	BeforeEach(func() {
		mockStore = testutil.NewMockRefreshStore()
	})

	Describe("Constructor", func() {
		It("should create empty store", func() {
			Expect(mockStore).NotTo(BeNil())
			Expect(mockStore.GetTokenCount()).To(Equal(0))
		})
	})

	Describe("Store", func() {
		It("should store token", func() {
			err := mockStore.Store("token-123", "user-456", time.Now().Add(24*time.Hour), nil)

			Expect(err).NotTo(HaveOccurred())
			Expect(mockStore.GetCallCount("Store")).To(Equal(1))
			Expect(mockStore.GetTokenCount()).To(Equal(1))
		})

		It("should track store arguments", func() {
			tokenID := "token-123"
			userID := "user-456"
			expiresAt := time.Now().Add(24 * time.Hour)
			metadata := map[string]interface{}{"key": "value"}

			mockStore.Store(tokenID, userID, expiresAt, metadata)

			Expect(mockStore.WasTokenStored(tokenID)).To(BeTrue())
		})

		It("should return configured error", func() {
			testErr := testutil.NewMockError("storage failed")
			mockStore.SetStoreError(testErr)

			err := mockStore.Store("token-123", "user-456", time.Now().Add(24*time.Hour), nil)

			Expect(err).To(Equal(testErr))
		})
	})

	Describe("Retrieve", func() {
		BeforeEach(func() {
			mockStore.Store("token-123", "user-456", time.Now().Add(24*time.Hour), nil)
		})

		It("should retrieve stored token", func() {
			token, err := mockStore.Retrieve("token-123")

			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeNil())
			Expect(token.TokenID).To(Equal("token-123"))
			Expect(token.UserID).To(Equal("user-456"))
			Expect(mockStore.GetCallCount("Retrieve")).To(Equal(1))
		})

		It("should track retrieve attempts", func() {
			mockStore.Retrieve("token-123")

			Expect(mockStore.WasTokenRetrieved("token-123")).To(BeTrue())
		})

		It("should return error for non-existent token", func() {
			_, err := mockStore.Retrieve("non-existent")

			Expect(err).To(Equal(testutil.ErrMockTokenNotFound))
		})

		It("should return error for revoked token", func() {
			mockStore.Revoke("token-123")

			_, err := mockStore.Retrieve("token-123")

			Expect(err).To(Equal(testutil.ErrMockTokenRevoked))
		})

		It("should return error for expired token", func() {
			mockStore.AddExpiredToken("expired-token", "user-456")

			_, err := mockStore.Retrieve("expired-token")

			Expect(err).To(Equal(testutil.ErrMockTokenExpired))
		})

		It("should return configured error", func() {
			testErr := testutil.NewMockError("retrieval failed")
			mockStore.SetRetrieveError(testErr)

			_, err := mockStore.Retrieve("token-123")

			Expect(err).To(Equal(testErr))
		})
	})

	Describe("Revoke", func() {
		BeforeEach(func() {
			mockStore.Store("token-123", "user-456", time.Now().Add(24*time.Hour), nil)
		})

		It("should revoke token", func() {
			err := mockStore.Revoke("token-123")

			Expect(err).NotTo(HaveOccurred())
			Expect(mockStore.GetCallCount("Revoke")).To(Equal(1))
			Expect(mockStore.IsTokenRevoked("token-123")).To(BeTrue())
		})

		It("should track revoke attempts", func() {
			mockStore.Revoke("token-123")

			Expect(mockStore.WasTokenRevoked("token-123")).To(BeTrue())
		})

		It("should return error for non-existent token", func() {
			err := mockStore.Revoke("non-existent")

			Expect(err).To(Equal(testutil.ErrMockTokenNotFound))
		})

		It("should return configured error", func() {
			testErr := testutil.NewMockError("revoke failed")
			mockStore.SetRevokeError(testErr)

			err := mockStore.Revoke("token-123")

			Expect(err).To(Equal(testErr))
		})
	})

	Describe("RevokeAllForUser", func() {
		BeforeEach(func() {
			mockStore.Store("token-1", "user-456", time.Now().Add(24*time.Hour), nil)
			mockStore.Store("token-2", "user-456", time.Now().Add(24*time.Hour), nil)
			mockStore.Store("token-3", "user-789", time.Now().Add(24*time.Hour), nil)
		})

		It("should revoke all tokens for user", func() {
			err := mockStore.RevokeAllForUser("user-456")

			Expect(err).NotTo(HaveOccurred())
			Expect(mockStore.IsTokenRevoked("token-1")).To(BeTrue())
			Expect(mockStore.IsTokenRevoked("token-2")).To(BeTrue())
			Expect(mockStore.IsTokenRevoked("token-3")).To(BeFalse())
		})

		It("should return error when no tokens found", func() {
			err := mockStore.RevokeAllForUser("non-existent-user")

			Expect(err).To(Equal(testutil.ErrMockNoTokensForUser))
		})
	})

	Describe("Cleanup", func() {
		It("should remove expired tokens", func() {
			mockStore.Store("active", "user-1", time.Now().Add(24*time.Hour), nil)
			mockStore.AddExpiredToken("expired", "user-2")

			count, err := mockStore.Cleanup()

			Expect(err).NotTo(HaveOccurred())
			Expect(count).To(Equal(1))
			Expect(mockStore.GetTokenCount()).To(Equal(1))
			Expect(mockStore.GetCallCount("Cleanup")).To(Equal(1))
		})

		It("should remove revoked tokens", func() {
			mockStore.Store("token-1", "user-1", time.Now().Add(24*time.Hour), nil)
			mockStore.AddRevokedToken("revoked", "user-2")

			count, err := mockStore.Cleanup()

			Expect(err).NotTo(HaveOccurred())
			Expect(count).To(Equal(1))
		})

		It("should return configured error", func() {
			testErr := testutil.NewMockError("cleanup failed")
			mockStore.SetCleanupError(testErr)

			_, err := mockStore.Cleanup()

			Expect(err).To(Equal(testErr))
		})
	})

	Describe("Query Methods", func() {
		BeforeEach(func() {
			mockStore.Store("token-1", "user-456", time.Now().Add(24*time.Hour), nil)
			mockStore.Store("token-2", "user-456", time.Now().Add(24*time.Hour), nil)
			mockStore.AddExpiredToken("expired", "user-456")
		})

		It("should count total tokens", func() {
			Expect(mockStore.GetTokenCount()).To(Equal(3))
		})

		It("should count active tokens only", func() {
			Expect(mockStore.GetActiveTokenCount()).To(Equal(2))
		})

		It("should get tokens for user", func() {
			tokens := mockStore.GetTokensForUser("user-456")

			Expect(len(tokens)).To(Equal(3))
		})

		It("should check token existence", func() {
			Expect(mockStore.HasToken("token-1")).To(BeTrue())
			Expect(mockStore.HasToken("non-existent")).To(BeFalse())
		})
	})

	Describe("Reset", func() {
		It("should reset everything", func() {
			mockStore.Store("token-1", "user-1", time.Now().Add(24*time.Hour), nil)
			mockStore.Retrieve("token-1")

			mockStore.Reset()

			Expect(mockStore.GetCallCount("Store")).To(Equal(0))
			Expect(mockStore.GetCallCount("Retrieve")).To(Equal(0))
			Expect(mockStore.GetTokenCount()).To(Equal(0))
		})
	})

	Describe("Concurrent Usage", func() {
		It("should be thread-safe", func() {
			done := make(chan bool, 10)

			for i := 0; i < 10; i++ {
				go func(id int) {
					defer GinkgoRecover()
					tokenID := time.Now().String() + string(rune(id))
					mockStore.Store(tokenID, "user-1", time.Now().Add(24*time.Hour), nil)
					mockStore.Retrieve(tokenID)
					done <- true
				}(i)
			}

			for i := 0; i < 10; i++ {
				Eventually(done).Should(Receive())
			}
		})
	})
})

// ============================================================================
// MockRateLimiter Tests
// ============================================================================

var _ = Describe("MockRateLimiter", func() {
	var mockRL *testutil.MockRateLimiter

	BeforeEach(func() {
		mockRL = testutil.NewMockRateLimiter()
	})

	Describe("Constructor", func() {
		It("should create with allow-all default", func() {
			Expect(mockRL).NotTo(BeNil())

			allowed, err := mockRL.Allow("test-identifier", 1)
			Expect(err).NotTo(HaveOccurred())
			Expect(allowed).To(BeTrue())
		})
	})

	Describe("Allow", func() {
		It("should allow request by default", func() {
			allowed, err := mockRL.Allow("user-123", 1)

			Expect(err).NotTo(HaveOccurred())
			Expect(allowed).To(BeTrue())
			Expect(mockRL.GetCallCount("Allow")).To(Equal(1))
		})

		It("should track identifiers checked", func() {
			mockRL.Allow("user-123", 1)

			Expect(mockRL.WasIdentifierChecked("user-123")).To(BeTrue())
			Expect(mockRL.WasIdentifierChecked("user-456")).To(BeFalse())
		})

		It("should track request costs", func() {
			mockRL.Allow("user-123", 5)
			mockRL.Allow("user-123", 3)

			Expect(mockRL.GetTotalCost("user-123")).To(Equal(8))
		})

		It("should block when configured", func() {
			mockRL.SetAllowResult(false)

			allowed, err := mockRL.Allow("user-123", 1)

			Expect(err).NotTo(HaveOccurred())
			Expect(allowed).To(BeFalse())
		})

		It("should return configured error", func() {
			testErr := testutil.NewMockError("rate limit check failed")
			mockRL.SetAllowError(testErr)

			_, err := mockRL.Allow("user-123", 1)

			Expect(err).To(Equal(testErr))
		})

		It("should decrement remaining requests", func() {
			mockRL.SetRemainingRequests(10)

			mockRL.Allow("user-123", 3)

			Expect(mockRL.GetRemainingForIdentifier("user-123")).To(Equal(7))
		})
	})

	Describe("Reset", func() {
		It("should reset rate limit for identifier", func() {
			mockRL.SimulateRateLimitExceeded("user-123")

			err := mockRL.Reset("user-123")

			Expect(err).NotTo(HaveOccurred())
			Expect(mockRL.GetCallCount("Reset")).To(Equal(1))
		})
	})

	Describe("GetStatus", func() {
		It("should return status", func() {
			mockRL.SetRemainingRequests(50)

			status, err := mockRL.GetStatus("user-123")

			Expect(err).NotTo(HaveOccurred())
			Expect(status).NotTo(BeNil())
			Expect(status.Remaining).To(Equal(50))
			Expect(mockRL.GetCallCount("GetStatus")).To(Equal(1))
		})
	})

	Describe("Behavior Control", func() {
		It("should block specific identifier", func() {
			mockRL.BlockIdentifier("blocked-user")

			Expect(mockRL.IsIdentifierBlocked("blocked-user")).To(BeTrue())
		})

		It("should unblock specific identifier", func() {
			mockRL.BlockIdentifier("user-123")
			mockRL.UnblockIdentifier("user-123")

			Expect(mockRL.IsIdentifierBlocked("user-123")).To(BeFalse())
		})

		It("should simulate rate limit exceeded", func() {
			mockRL.SimulateRateLimitExceeded("user-123")

			Expect(mockRL.IsIdentifierBlocked("user-123")).To(BeTrue())
			Expect(mockRL.GetRemainingForIdentifier("user-123")).To(Equal(0))
		})

		It("should simulate near limit", func() {
			mockRL.SimulateNearLimit("user-123", 2)

			Expect(mockRL.GetRemainingForIdentifier("user-123")).To(Equal(2))
		})
	})

	Describe("Query Methods", func() {
		BeforeEach(func() {
			mockRL.Allow("user-1", 1)
			mockRL.Allow("user-1", 1)
			mockRL.Allow("user-2", 1)
		})

		It("should count calls per identifier", func() {
			Expect(mockRL.GetIdentifierCallCount("user-1")).To(Equal(2))
			Expect(mockRL.GetIdentifierCallCount("user-2")).To(Equal(1))
		})

		It("should list all identifiers", func() {
			identifiers := mockRL.GetAllIdentifiers()

			Expect(len(identifiers)).To(Equal(2))
		})
	})

	Describe("Reset", func() {
		It("should reset counters", func() {
			mockRL.Allow("user-1", 1)

			mockRL.ResetCounters()

			Expect(mockRL.GetCallCount("Allow")).To(Equal(0))
		})

		It("should reset state", func() {
			mockRL.Allow("user-1", 1)

			mockRL.ResetCounters()
			mockRL.ResetState()

			Expect(len(mockRL.GetAllIdentifiers())).To(Equal(0))
		})

		It("should reset all", func() {
			mockRL.SetAllowResult(false)
			mockRL.Allow("user-1", 1)

			mockRL.ResetAll()

			Expect(mockRL.GetCallCount("Allow")).To(Equal(0))
			allowed, _ := mockRL.Allow("user-2", 1)
			Expect(allowed).To(BeTrue())
		})
	})

	Describe("Concurrent Usage", func() {
		It("should be thread-safe", func() {
			done := make(chan bool, 10)

			for i := 0; i < 10; i++ {
				go func(id int) {
					defer GinkgoRecover()
					identifier := time.Now().String() + string(rune(id))
					mockRL.Allow(identifier, 1)
					mockRL.GetStatus(identifier)
					done <- true
				}(i)
			}

			for i := 0; i < 10; i++ {
				Eventually(done).Should(Receive())
			}
		})
	})
})
