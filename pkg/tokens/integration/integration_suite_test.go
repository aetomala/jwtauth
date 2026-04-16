//go:build integration

package integration

import (
	"context"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aetomala/jwtauth/pkg/keymanager"
	"github.com/aetomala/jwtauth/pkg/tokens"
)

func TestIntegration(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Integration Suite")
}

// ManagerFactory creates a configured but not-yet-started TokenManager along with its
// KeyManager and a cleanup function. The caller is responsible for calling Start and
// Shutdown on the returned manager, and calling cleanup after Shutdown.
type ManagerFactory func(cfg tokens.ManagerConfig) (mgr *tokens.Manager, km *keymanager.Manager, cleanup func())

// RunTokenManagerIntegrationTests runs the full TokenManager behavioral contract suite
// against the storage backend provided by factory. It is called once per backend
// (DiskKeyStore+Memory, RedisKeyStore+Redis) and produces 10 specs each.
func RunTokenManagerIntegrationTests(description string, factory ManagerFactory) {
	Describe(description, func() {
		var (
			mgr    *tokens.Manager
			km     *keymanager.Manager
			ctx    context.Context
			cancel context.CancelFunc
		)

		BeforeEach(func() {
			ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)

			var cleanup func()
			mgr, km, cleanup = factory(tokens.ManagerConfig{
				AccessTokenDuration:  5 * time.Minute,
				RefreshTokenDuration: 1 * time.Hour,
				CleanupInterval:      5 * time.Minute,
				Issuer:               "integration-test",
				Audience:             []string{"integration-test"},
			})
			Expect(mgr.Start(ctx)).To(Succeed())

			DeferCleanup(func() {
				if mgr != nil && mgr.IsRunning() {
					shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer shutdownCancel()
					_ = mgr.Shutdown(shutdownCtx)
				}
				cancel()
				if cleanup != nil {
					cleanup()
				}
			})
		})

		It("should issue, validate, and refresh tokens", func() {
			userID := "test-user"

			accessToken, refreshToken, err := mgr.IssueTokenPair(ctx, userID)
			Expect(err).NotTo(HaveOccurred())
			Expect(accessToken).NotTo(BeEmpty())
			Expect(refreshToken).NotTo(BeEmpty())

			claims, err := mgr.ValidateAccessToken(ctx, accessToken)
			Expect(err).NotTo(HaveOccurred())
			Expect(claims.Subject).To(Equal(userID))
			Expect(claims.Issuer).To(Equal("integration-test"))
			Expect(claims.Audience).To(ContainElement("integration-test"))

			newAccessToken, err := mgr.RefreshAccessToken(ctx, refreshToken)
			Expect(err).NotTo(HaveOccurred())
			Expect(newAccessToken).NotTo(BeEmpty())

			newClaims, err := mgr.ValidateAccessToken(ctx, newAccessToken)
			Expect(err).NotTo(HaveOccurred())
			Expect(newClaims.Subject).To(Equal(userID))

			Expect(accessToken).NotTo(Equal(newAccessToken))
		})

		It("should prevent refresh after token is revoked", func() {
			userID := "revoke-test-user"

			refreshToken, err := mgr.IssueRefreshToken(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			err = mgr.RevokeAllUserTokens(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			_, err = mgr.RefreshAccessToken(ctx, refreshToken)
			Expect(err).To(Equal(tokens.ErrTokenRevoked))
		})

		It("should invalidate all refresh tokens for a user", func() {
			userID := "multi-token-user"

			token1, err := mgr.IssueRefreshToken(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			token2, err := mgr.IssueRefreshToken(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			token3, err := mgr.IssueRefreshToken(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			_, err = mgr.RefreshAccessToken(ctx, token1)
			Expect(err).NotTo(HaveOccurred())
			_, err = mgr.RefreshAccessToken(ctx, token2)
			Expect(err).NotTo(HaveOccurred())
			_, err = mgr.RefreshAccessToken(ctx, token3)
			Expect(err).NotTo(HaveOccurred())

			err = mgr.RevokeAllUserTokens(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			_, err = mgr.RefreshAccessToken(ctx, token1)
			Expect(err).To(Equal(tokens.ErrTokenRevoked))

			_, err = mgr.RefreshAccessToken(ctx, token2)
			Expect(err).To(Equal(tokens.ErrTokenRevoked))

			_, err = mgr.RefreshAccessToken(ctx, token3)
			Expect(err).To(Equal(tokens.ErrTokenRevoked))
		})

		It("should introspect active and revoked tokens", func() {
			userID := "introspect-user"

			refreshToken1, err := mgr.IssueRefreshToken(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			metadata, err := mgr.IntrospectToken(ctx, refreshToken1)
			Expect(err).NotTo(HaveOccurred())
			Expect(metadata.Active).To(BeTrue())
			Expect(metadata.Subject).To(Equal(userID))

			_, err = mgr.IssueRefreshToken(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			err = mgr.RevokeAllUserTokens(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			revokedMetadata, err := mgr.IntrospectToken(ctx, refreshToken1)
			Expect(err).NotTo(HaveOccurred())
			Expect(revokedMetadata.Active).To(BeFalse())
		})

		It("should reject operations when service is not running", func() {
			mgr2, _, cleanup2 := factory(tokens.ManagerConfig{
				AccessTokenDuration:  5 * time.Minute,
				RefreshTokenDuration: 1 * time.Hour,
				Issuer:               "integration-test",
				Audience:             []string{"integration-test"},
			})
			DeferCleanup(cleanup2)
			// Note: NOT calling mgr2.Start(ctx)

			_, err := mgr2.IssueAccessToken(ctx, "user-id")
			Expect(err).To(Equal(tokens.ErrManagerNotRunning))
		})

		It("should issue tokens concurrently without data races", func() {
			userID := "concurrent-user"
			numGoroutines := 20

			results := make(chan string, numGoroutines*2)
			for i := 0; i < numGoroutines; i++ {
				go func() {
					accessToken, refreshToken, err := mgr.IssueTokenPair(ctx, userID)
					Expect(err).NotTo(HaveOccurred())
					results <- accessToken
					results <- refreshToken
				}()
			}

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

			Expect(len(accessTokens)).To(Equal(numGoroutines))
			Expect(len(refreshTokens)).To(Equal(numGoroutines))
		})

		It("should validate tokens signed before a key rotation", func() {
			userID := "rotation-user"

			oldAccessToken, err := mgr.IssueAccessToken(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			claims, err := mgr.ValidateAccessToken(ctx, oldAccessToken)
			Expect(err).NotTo(HaveOccurred())
			Expect(claims.Subject).To(Equal(userID))

			err = km.RotateKeys(ctx)
			Expect(err).NotTo(HaveOccurred())

			claims, err = mgr.ValidateAccessToken(ctx, oldAccessToken)
			Expect(err).NotTo(HaveOccurred())
			Expect(claims.Subject).To(Equal(userID))

			newAccessToken, err := mgr.IssueAccessToken(ctx, userID)
			Expect(err).NotTo(HaveOccurred())
			claims, err = mgr.ValidateAccessToken(ctx, newAccessToken)
			Expect(err).NotTo(HaveOccurred())
			Expect(claims.Subject).To(Equal(userID))
		})

		It("should clean up expired tokens", func() {
			userID := "cleanup-user"

			mgr2, _, cleanup2 := factory(tokens.ManagerConfig{
				AccessTokenDuration:  5 * time.Minute,
				RefreshTokenDuration: 100 * time.Millisecond,
				CleanupInterval:      10 * time.Second,
				Issuer:               "integration-test",
				Audience:             []string{"integration-test"},
			})
			Expect(mgr2.Start(ctx)).To(Succeed())
			DeferCleanup(func() {
				shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
				defer c()
				_ = mgr2.Shutdown(shutdownCtx)
				cleanup2()
			})

			token1, err := mgr2.IssueRefreshToken(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			_, err = mgr2.IssueRefreshToken(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			_, err = mgr2.IssueRefreshToken(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			time.Sleep(150 * time.Millisecond)

			count, err := mgr2.CleanupExpiredTokens(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(count).To(BeNumerically(">=", 3))

			_, err = mgr2.RefreshAccessToken(ctx, token1)
			Expect(err).To(HaveOccurred())

			freshToken, err := mgr2.IssueRefreshToken(ctx, userID)
			Expect(err).NotTo(HaveOccurred())
			newAccessToken, err := mgr2.RefreshAccessToken(ctx, freshToken)
			Expect(err).NotTo(HaveOccurred())
			Expect(newAccessToken).NotTo(BeEmpty())
		})

		It("should track independent sessions per device", func() {
			userID := "multi-device-user"
			devices := map[string]string{
				"iPhone": "device-001",
				"Laptop": "device-002",
				"iPad":   "device-003",
			}

			deviceRefreshTokens := make(map[string]string)
			for deviceName, deviceID := range devices {
				metadata := map[string]interface{}{
					"device_name": deviceName,
					"device_id":   deviceID,
					"ip_address":  "192.168.1.100",
				}
				token, err := mgr.IssueRefreshTokenWithMetadata(ctx, userID, metadata)
				Expect(err).NotTo(HaveOccurred())
				deviceRefreshTokens[deviceName] = token
			}

			accessTokens := make(map[string]string)
			for deviceName, refreshToken := range deviceRefreshTokens {
				accessToken, err := mgr.RefreshAccessToken(ctx, refreshToken)
				Expect(err).NotTo(HaveOccurred())
				accessTokens[deviceName] = accessToken
			}

			Expect(len(accessTokens)).To(Equal(3))
			for _, token := range accessTokens {
				Expect(token).NotTo(BeEmpty())
			}

			for deviceName, accessToken := range accessTokens {
				claims, err := mgr.ValidateAccessToken(ctx, accessToken)
				Expect(err).NotTo(HaveOccurred())
				Expect(claims.Subject).To(Equal(userID))
				_ = deviceName
			}

			err := mgr.RevokeAllUserTokens(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			for _, refreshToken := range deviceRefreshTokens {
				_, err = mgr.RefreshAccessToken(ctx, refreshToken)
				Expect(err).To(Equal(tokens.ErrTokenRevoked))
			}
		})

		It("should return accurate key info after Start", func() {
			info, err := km.GetCurrentKeyInfo(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(info.KeyID).NotTo(BeEmpty())
			Expect(info.IsCurrent).To(BeTrue())
			Expect(info.IsValid).To(BeTrue())
			Expect(info.Algorithm).To(Equal("RS256"))
			Expect(info.KeySizeBits).To(Equal(2048))
			Expect(info.CreatedAt).To(BeTemporally("<=", time.Now()))
			Expect(info.RotateAt).To(BeTemporally(">", time.Now()))
		})

		It("should reflect the new key after rotation and keep old key accessible via GetKeyInfo", func() {
			before, err := km.GetCurrentKeyInfo(ctx)
			Expect(err).NotTo(HaveOccurred())

			Expect(km.RotateKeys(ctx)).To(Succeed())

			after, err := km.GetCurrentKeyInfo(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(after.KeyID).NotTo(Equal(before.KeyID))
			Expect(after.IsCurrent).To(BeTrue())
			Expect(after.IsValid).To(BeTrue())

			old, err := km.GetKeyInfo(ctx, before.KeyID)
			Expect(err).NotTo(HaveOccurred())
			Expect(old.KeyID).To(Equal(before.KeyID))
			Expect(old.IsCurrent).To(BeFalse())
		})

		It("should allow concurrent GetCurrentKeyInfo calls during rotation without data races", func() {
			const numReaders = 20
			var wg sync.WaitGroup

			for i := 0; i < numReaders; i++ {
				wg.Add(1)
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					info, err := km.GetCurrentKeyInfo(ctx)
					Expect(err).NotTo(HaveOccurred())
					Expect(info.KeyID).NotTo(BeEmpty())
					Expect(info.IsCurrent).To(BeTrue())
				}()
			}

			wg.Add(1)
			go func() {
				defer GinkgoRecover()
				defer wg.Done()
				Expect(km.RotateKeys(ctx)).To(Succeed())
			}()

			wg.Wait()
		})

		It("should reject invalid, expired, and revoked refresh tokens", func() {
			validUserID := "valid-user"

			validToken, err := mgr.IssueRefreshToken(ctx, validUserID)
			Expect(err).NotTo(HaveOccurred())

			_, err = mgr.RefreshAccessToken(ctx, "not-a-valid-token")
			Expect(err).To(HaveOccurred())

			mgr2, _, cleanup2 := factory(tokens.ManagerConfig{
				AccessTokenDuration:  5 * time.Minute,
				RefreshTokenDuration: 50 * time.Millisecond,
				Issuer:               "integration-test",
				Audience:             []string{"integration-test"},
			})
			Expect(mgr2.Start(ctx)).To(Succeed())
			DeferCleanup(func() {
				shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
				defer c()
				_ = mgr2.Shutdown(shutdownCtx)
				cleanup2()
			})

			expiredToken, err := mgr2.IssueRefreshToken(ctx, "expired-user")
			Expect(err).NotTo(HaveOccurred())
			time.Sleep(100 * time.Millisecond)
			_, err = mgr2.RefreshAccessToken(ctx, expiredToken)
			Expect(err).To(HaveOccurred())

			revokeUserID := "revoke-user"
			revokedToken, err := mgr.IssueRefreshToken(ctx, revokeUserID)
			Expect(err).NotTo(HaveOccurred())

			_, err = mgr.RefreshAccessToken(ctx, revokedToken)
			Expect(err).NotTo(HaveOccurred())

			err = mgr.RevokeAllUserTokens(ctx, revokeUserID)
			Expect(err).NotTo(HaveOccurred())
			_, err = mgr.RefreshAccessToken(ctx, revokedToken)
			Expect(err).To(Equal(tokens.ErrTokenRevoked))

			_, err = mgr.RefreshAccessToken(ctx, "token-never-issued")
			Expect(err).To(HaveOccurred())

			newAccessToken, err := mgr.RefreshAccessToken(ctx, validToken)
			Expect(err).NotTo(HaveOccurred())
			Expect(newAccessToken).NotTo(BeEmpty())
		})
	})
}
