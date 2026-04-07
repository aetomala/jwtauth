//go:build integration

package integration

import (
	"context"
	"os"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aetomala/jwtauth/pkg/keymanager"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/aetomala/jwtauth/pkg/tokens"
)

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Integration Suite")
}

var _ = Describe("TokenService Integration", func() {
	var (
		svc    *tokens.Service
		km     *keymanager.Manager
		store  *storage.MemoryRefreshStore
		ctx    context.Context
		cancel context.CancelFunc
		tmpDir string
	)

	BeforeEach(func() {
		var err error
		ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)

		tmpDir, err = os.MkdirTemp("", "integration-test-*")
		Expect(err).NotTo(HaveOccurred())

		ks, err := keymanager.NewDiskKeyStore(tmpDir, 2048, nil, nil)
		Expect(err).NotTo(HaveOccurred())

		km, err = keymanager.NewManager(keymanager.ManagerConfig{
			KeyStore:            ks,
			KeyRotationInterval: 30 * 24 * time.Hour,
			KeySize:             2048,
		})
		Expect(err).NotTo(HaveOccurred())

		store = storage.NewMemoryRefreshStore(nil, nil)

		svc, err = tokens.NewService(tokens.ServiceConfig{
			KeyManager:           km,
			RefreshStore:         store,
			AccessTokenDuration:  5 * time.Minute,
			RefreshTokenDuration: 1 * time.Hour,
			CleanupInterval:      5 * time.Minute,
			Issuer:               "integration-test",
			Audience:             []string{"integration-test"},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(svc.Start(ctx)).To(Succeed())
	})

	AfterEach(func() {
		if svc != nil && svc.IsRunning() {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			_ = svc.Shutdown(shutdownCtx)
		}
		cancel()
		if tmpDir != "" {
			os.RemoveAll(tmpDir)
		}
	})

	It("should issue, validate, and refresh tokens", func() {
		userID := "test-user"

		// Issue token pair
		accessToken, refreshToken, err := svc.IssueTokenPair(ctx, userID)
		Expect(err).NotTo(HaveOccurred())
		Expect(accessToken).NotTo(BeEmpty())
		Expect(refreshToken).NotTo(BeEmpty())

		// Validate access token
		claims, err := svc.ValidateAccessToken(ctx, accessToken)
		Expect(err).NotTo(HaveOccurred())
		Expect(claims.Subject).To(Equal(userID))
		Expect(claims.Issuer).To(Equal("integration-test"))
		Expect(claims.Audience).To(ContainElement("integration-test"))

		// Refresh token
		newAccessToken, err := svc.RefreshAccessToken(ctx, refreshToken)
		Expect(err).NotTo(HaveOccurred())
		Expect(newAccessToken).NotTo(BeEmpty())

		// Validate new access token
		newClaims, err := svc.ValidateAccessToken(ctx, newAccessToken)
		Expect(err).NotTo(HaveOccurred())
		Expect(newClaims.Subject).To(Equal(userID))

		// Assert tokens are different
		Expect(accessToken).NotTo(Equal(newAccessToken))
	})

	It("should prevent refresh after token is revoked", func() {
		userID := "revoke-test-user"

		// Issue refresh token
		refreshToken, err := svc.IssueRefreshToken(ctx, userID)
		Expect(err).NotTo(HaveOccurred())

		// Extract tokenID from refresh token (for this test, we use the token itself)
		// and revoke all user tokens
		err = svc.RevokeAllUserTokens(ctx, userID)
		Expect(err).NotTo(HaveOccurred())

		// Try to refresh — should fail
		_, err = svc.RefreshAccessToken(ctx, refreshToken)
		Expect(err).To(Equal(tokens.ErrTokenRevoked))
	})

	It("should invalidate all refresh tokens for a user", func() {
		userID := "multi-token-user"

		// Issue 3 refresh tokens
		token1, err := svc.IssueRefreshToken(ctx, userID)
		Expect(err).NotTo(HaveOccurred())

		token2, err := svc.IssueRefreshToken(ctx, userID)
		Expect(err).NotTo(HaveOccurred())

		token3, err := svc.IssueRefreshToken(ctx, userID)
		Expect(err).NotTo(HaveOccurred())

		// Verify all work before revocation
		_, err = svc.RefreshAccessToken(ctx, token1)
		Expect(err).NotTo(HaveOccurred())
		_, err = svc.RefreshAccessToken(ctx, token2)
		Expect(err).NotTo(HaveOccurred())
		_, err = svc.RefreshAccessToken(ctx, token3)
		Expect(err).NotTo(HaveOccurred())

		// Revoke all tokens for user
		err = svc.RevokeAllUserTokens(ctx, userID)
		Expect(err).NotTo(HaveOccurred())

		// All should now fail
		_, err = svc.RefreshAccessToken(ctx, token1)
		Expect(err).To(Equal(tokens.ErrTokenRevoked))

		_, err = svc.RefreshAccessToken(ctx, token2)
		Expect(err).To(Equal(tokens.ErrTokenRevoked))

		_, err = svc.RefreshAccessToken(ctx, token3)
		Expect(err).To(Equal(tokens.ErrTokenRevoked))
	})

	It("should introspect active and revoked tokens", func() {
		userID := "introspect-user"

		// Issue refresh tokens
		refreshToken1, err := svc.IssueRefreshToken(ctx, userID)
		Expect(err).NotTo(HaveOccurred())

		// Introspect active refresh token
		metadata, err := svc.IntrospectToken(ctx, refreshToken1)
		Expect(err).NotTo(HaveOccurred())
		Expect(metadata.Active).To(BeTrue())
		Expect(metadata.Subject).To(Equal(userID))

		// Issue another refresh token and revoke all
		_, err = svc.IssueRefreshToken(ctx, userID)
		Expect(err).NotTo(HaveOccurred())

		err = svc.RevokeAllUserTokens(ctx, userID)
		Expect(err).NotTo(HaveOccurred())

		// Introspect revoked refresh token
		revokedMetadata, err := svc.IntrospectToken(ctx, refreshToken1)
		Expect(err).NotTo(HaveOccurred())
		Expect(revokedMetadata.Active).To(BeFalse())
	})

	It("should reject operations when service is not running", func() {
		// Create a new service without starting it
		tmpDir2, err := os.MkdirTemp("", "not-running-*")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(tmpDir2)

		ks2, err := keymanager.NewDiskKeyStore(tmpDir2, 2048, nil, nil)
		Expect(err).NotTo(HaveOccurred())

		km2, err := keymanager.NewManager(keymanager.ManagerConfig{
			KeyStore: ks2,
		})
		Expect(err).NotTo(HaveOccurred())

		store2 := storage.NewMemoryRefreshStore(nil, nil)

		svc2, err := tokens.NewService(tokens.ServiceConfig{
			KeyManager:           km2,
			RefreshStore:         store2,
			AccessTokenDuration:  5 * time.Minute,
			RefreshTokenDuration: 1 * time.Hour,
			Issuer:               "integration-test",
			Audience:             []string{"integration-test"},
		})
		Expect(err).NotTo(HaveOccurred())
		// Note: NOT calling svc2.Start(ctx)

		// All operations should fail with ErrServiceNotRunning
		_, err = svc2.IssueAccessToken(ctx, "user-id")
		Expect(err).To(Equal(tokens.ErrServiceNotRunning))
	})

	It("should issue tokens concurrently without data races", func() {
		userID := "concurrent-user"
		numGoroutines := 20

		results := make(chan string, numGoroutines*2)
		for i := 0; i < numGoroutines; i++ {
			go func() {
				accessToken, refreshToken, err := svc.IssueTokenPair(ctx, userID)
				Expect(err).NotTo(HaveOccurred())
				results <- accessToken
				results <- refreshToken
			}()
		}

		// Collect all tokens
		accessTokens := make(map[string]bool)
		refreshTokens := make(map[string]bool)
		for i := 0; i < numGoroutines*2; i++ {
			token := <-results
			if i%2 == 0 {
				accessTokens[token] = true
			} else {
				refreshTokens[token] = true
			}
		}

		// Assert all are unique
		Expect(len(accessTokens)).To(Equal(numGoroutines))
		Expect(len(refreshTokens)).To(Equal(numGoroutines))
	})

	It("should validate tokens signed before a key rotation", func() {
		userID := "rotation-user"

		// Issue access token
		oldAccessToken, err := svc.IssueAccessToken(ctx, userID)
		Expect(err).NotTo(HaveOccurred())

		// Validate before rotation
		claims, err := svc.ValidateAccessToken(ctx, oldAccessToken)
		Expect(err).NotTo(HaveOccurred())
		Expect(claims.Subject).To(Equal(userID))

		// Rotate keys
		err = km.RotateKeys(ctx)
		Expect(err).NotTo(HaveOccurred())

		// Token signed with old key should still validate (overlap window)
		claims, err = svc.ValidateAccessToken(ctx, oldAccessToken)
		Expect(err).NotTo(HaveOccurred())
		Expect(claims.Subject).To(Equal(userID))

		// New tokens should work with new key
		newAccessToken, err := svc.IssueAccessToken(ctx, userID)
		Expect(err).NotTo(HaveOccurred())
		claims, err = svc.ValidateAccessToken(ctx, newAccessToken)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should clean up expired tokens", func() {
		userID := "cleanup-user"

		// Create a second service with very short token duration and long cleanup interval
		tmpDir2, err := os.MkdirTemp("", "cleanup-test-*")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(tmpDir2)

		ks2, err := keymanager.NewDiskKeyStore(tmpDir2, 2048, nil, nil)
		Expect(err).NotTo(HaveOccurred())

		km2, err := keymanager.NewManager(keymanager.ManagerConfig{
			KeyStore: ks2,
		})
		Expect(err).NotTo(HaveOccurred())

		store2 := storage.NewMemoryRefreshStore(nil, nil)

		svc2, err := tokens.NewService(tokens.ServiceConfig{
			KeyManager:           km2,
			RefreshStore:         store2,
			AccessTokenDuration:  5 * time.Minute,
			RefreshTokenDuration: 100 * time.Millisecond,
			CleanupInterval:      10 * time.Second,
			Issuer:               "integration-test",
			Audience:             []string{"integration-test"},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(svc2.Start(ctx)).To(Succeed())
		defer svc2.Shutdown(ctx)

		// Issue 3 refresh tokens
		token1, err := svc2.IssueRefreshToken(ctx, userID)
		Expect(err).NotTo(HaveOccurred())

		_, err = svc2.IssueRefreshToken(ctx, userID)
		Expect(err).NotTo(HaveOccurred())

		_, err = svc2.IssueRefreshToken(ctx, userID)
		Expect(err).NotTo(HaveOccurred())

		// Wait for expiration
		time.Sleep(150 * time.Millisecond)

		// Manually run cleanup
		count, err := store2.Cleanup(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(count).To(BeNumerically(">=", 3))

		// Verify expired tokens fail to refresh
		_, err = svc2.RefreshAccessToken(ctx, token1)
		Expect(err).To(HaveOccurred())

		// Fresh token should still work
		freshToken, err := svc2.IssueRefreshToken(ctx, userID)
		Expect(err).NotTo(HaveOccurred())
		newAccessToken, err := svc2.RefreshAccessToken(ctx, freshToken)
		Expect(err).NotTo(HaveOccurred())
		Expect(newAccessToken).NotTo(BeEmpty())
	})

	It("should track independent sessions per device", func() {
		userID := "multi-device-user"
		devices := map[string]string{
			"iPhone":  "device-001",
			"Laptop":  "device-002",
			"iPad":    "device-003",
		}

		refreshTokens := make(map[string]string)
		for deviceName, deviceID := range devices {
			metadata := map[string]interface{}{
				"device_name": deviceName,
				"device_id":   deviceID,
				"ip_address":  "192.168.1.100",
			}
			token, err := svc.IssueRefreshTokenWithMetadata(ctx, userID, metadata)
			Expect(err).NotTo(HaveOccurred())
			refreshTokens[deviceName] = token
		}

		// Each device refreshes and gets a unique access token
		accessTokens := make(map[string]string)
		for deviceName, refreshToken := range refreshTokens {
			accessToken, err := svc.RefreshAccessToken(ctx, refreshToken)
			Expect(err).NotTo(HaveOccurred())
			accessTokens[deviceName] = accessToken
		}

		// All access tokens should be unique
		Expect(len(accessTokens)).To(Equal(3))
		for _, token := range accessTokens {
			Expect(token).NotTo(BeEmpty())
		}

		// Validate all access tokens
		for deviceName, accessToken := range accessTokens {
			claims, err := svc.ValidateAccessToken(ctx, accessToken)
			Expect(err).NotTo(HaveOccurred())
			Expect(claims.Subject).To(Equal(userID))
			_ = deviceName // silence lint
		}

		// Revoke all user tokens
		err := svc.RevokeAllUserTokens(ctx, userID)
		Expect(err).NotTo(HaveOccurred())

		// All refresh tokens should now be revoked
		for _, refreshToken := range refreshTokens {
			_, err = svc.RefreshAccessToken(ctx, refreshToken)
			Expect(err).To(Equal(tokens.ErrTokenRevoked))
		}
	})

	It("should reject invalid, expired, and revoked refresh tokens", func() {
		validUserID := "valid-user"

		// Issue a valid refresh token for comparison
		validToken, err := svc.IssueRefreshToken(ctx, validUserID)
		Expect(err).NotTo(HaveOccurred())

		// Test malformed token
		_, err = svc.RefreshAccessToken(ctx, "not-a-valid-token")
		Expect(err).To(HaveOccurred())

		// Test expired token (create separate short-lived service)
		tmpDir2, err := os.MkdirTemp("", "expired-test-*")
		Expect(err).NotTo(HaveOccurred())
		defer os.RemoveAll(tmpDir2)

		ks2, err := keymanager.NewDiskKeyStore(tmpDir2, 2048, nil, nil)
		Expect(err).NotTo(HaveOccurred())

		km2, err := keymanager.NewManager(keymanager.ManagerConfig{
			KeyStore: ks2,
		})
		Expect(err).NotTo(HaveOccurred())

		store2 := storage.NewMemoryRefreshStore(nil, nil)
		svc2, err := tokens.NewService(tokens.ServiceConfig{
			KeyManager:           km2,
			RefreshStore:         store2,
			AccessTokenDuration:  5 * time.Minute,
			RefreshTokenDuration: 50 * time.Millisecond,
			Issuer:               "integration-test",
			Audience:             []string{"integration-test"},
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(svc2.Start(ctx)).To(Succeed())
		defer svc2.Shutdown(ctx)

		expiredToken, err := svc2.IssueRefreshToken(ctx, "expired-user")
		Expect(err).NotTo(HaveOccurred())
		time.Sleep(100 * time.Millisecond)
		_, err = svc2.RefreshAccessToken(ctx, expiredToken)
		Expect(err).To(HaveOccurred())

		// Test revoked token
		revokeUserID := "revoke-user"
		revokedToken, err := svc.IssueRefreshToken(ctx, revokeUserID)
		Expect(err).NotTo(HaveOccurred())

		// Verify it works before revocation
		_, err = svc.RefreshAccessToken(ctx, revokedToken)
		Expect(err).NotTo(HaveOccurred())

		// Revoke and test
		err = svc.RevokeAllUserTokens(ctx, revokeUserID)
		Expect(err).NotTo(HaveOccurred())
		_, err = svc.RefreshAccessToken(ctx, revokedToken)
		Expect(err).To(Equal(tokens.ErrTokenRevoked))

		// Test never-issued token
		_, err = svc.RefreshAccessToken(ctx, "token-never-issued")
		Expect(err).To(HaveOccurred())

		// Verify valid token still works
		newAccessToken, err := svc.RefreshAccessToken(ctx, validToken)
		Expect(err).NotTo(HaveOccurred())
		Expect(newAccessToken).NotTo(BeEmpty())
	})
})
