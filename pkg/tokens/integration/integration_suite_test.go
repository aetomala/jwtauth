//go:build integration

package integration

import (
	"context"
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

// ServiceFactory creates a configured but not-yet-started TokenService along with its
// KeyManager and a cleanup function. The caller is responsible for calling Start and
// Shutdown on the returned service, and calling cleanup after Shutdown.
type ServiceFactory func(cfg tokens.ServiceConfig) (svc *tokens.Service, km *keymanager.Manager, cleanup func())

// RunTokenServiceIntegrationTests runs the full TokenService behavioral contract suite
// against the storage backend provided by factory. It is called once per backend
// (DiskKeyStore+Memory, RedisKeyStore+Redis) and produces 10 specs each.
func RunTokenServiceIntegrationTests(description string, factory ServiceFactory) {
	Describe(description, func() {
		var (
			svc    *tokens.Service
			km     *keymanager.Manager
			ctx    context.Context
			cancel context.CancelFunc
		)

		BeforeEach(func() {
			ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)

			var cleanup func()
			svc, km, cleanup = factory(tokens.ServiceConfig{
				AccessTokenDuration:  5 * time.Minute,
				RefreshTokenDuration: 1 * time.Hour,
				CleanupInterval:      5 * time.Minute,
				Issuer:               "integration-test",
				Audience:             []string{"integration-test"},
			})
			Expect(svc.Start(ctx)).To(Succeed())

			DeferCleanup(func() {
				if svc != nil && svc.IsRunning() {
					shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer shutdownCancel()
					_ = svc.Shutdown(shutdownCtx)
				}
				cancel()
				if cleanup != nil {
					cleanup()
				}
			})
		})

		It("should issue, validate, and refresh tokens", func() {
			userID := "test-user"

			accessToken, refreshToken, err := svc.IssueTokenPair(ctx, userID)
			Expect(err).NotTo(HaveOccurred())
			Expect(accessToken).NotTo(BeEmpty())
			Expect(refreshToken).NotTo(BeEmpty())

			claims, err := svc.ValidateAccessToken(ctx, accessToken)
			Expect(err).NotTo(HaveOccurred())
			Expect(claims.Subject).To(Equal(userID))
			Expect(claims.Issuer).To(Equal("integration-test"))
			Expect(claims.Audience).To(ContainElement("integration-test"))

			newAccessToken, err := svc.RefreshAccessToken(ctx, refreshToken)
			Expect(err).NotTo(HaveOccurred())
			Expect(newAccessToken).NotTo(BeEmpty())

			newClaims, err := svc.ValidateAccessToken(ctx, newAccessToken)
			Expect(err).NotTo(HaveOccurred())
			Expect(newClaims.Subject).To(Equal(userID))

			Expect(accessToken).NotTo(Equal(newAccessToken))
		})

		It("should prevent refresh after token is revoked", func() {
			userID := "revoke-test-user"

			refreshToken, err := svc.IssueRefreshToken(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			err = svc.RevokeAllUserTokens(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			_, err = svc.RefreshAccessToken(ctx, refreshToken)
			Expect(err).To(Equal(tokens.ErrTokenRevoked))
		})

		It("should invalidate all refresh tokens for a user", func() {
			userID := "multi-token-user"

			token1, err := svc.IssueRefreshToken(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			token2, err := svc.IssueRefreshToken(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			token3, err := svc.IssueRefreshToken(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			_, err = svc.RefreshAccessToken(ctx, token1)
			Expect(err).NotTo(HaveOccurred())
			_, err = svc.RefreshAccessToken(ctx, token2)
			Expect(err).NotTo(HaveOccurred())
			_, err = svc.RefreshAccessToken(ctx, token3)
			Expect(err).NotTo(HaveOccurred())

			err = svc.RevokeAllUserTokens(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			_, err = svc.RefreshAccessToken(ctx, token1)
			Expect(err).To(Equal(tokens.ErrTokenRevoked))

			_, err = svc.RefreshAccessToken(ctx, token2)
			Expect(err).To(Equal(tokens.ErrTokenRevoked))

			_, err = svc.RefreshAccessToken(ctx, token3)
			Expect(err).To(Equal(tokens.ErrTokenRevoked))
		})

		It("should introspect active and revoked tokens", func() {
			userID := "introspect-user"

			refreshToken1, err := svc.IssueRefreshToken(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			metadata, err := svc.IntrospectToken(ctx, refreshToken1)
			Expect(err).NotTo(HaveOccurred())
			Expect(metadata.Active).To(BeTrue())
			Expect(metadata.Subject).To(Equal(userID))

			_, err = svc.IssueRefreshToken(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			err = svc.RevokeAllUserTokens(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			revokedMetadata, err := svc.IntrospectToken(ctx, refreshToken1)
			Expect(err).NotTo(HaveOccurred())
			Expect(revokedMetadata.Active).To(BeFalse())
		})

		It("should reject operations when service is not running", func() {
			svc2, _, cleanup2 := factory(tokens.ServiceConfig{
				AccessTokenDuration:  5 * time.Minute,
				RefreshTokenDuration: 1 * time.Hour,
				Issuer:               "integration-test",
				Audience:             []string{"integration-test"},
			})
			DeferCleanup(cleanup2)
			// Note: NOT calling svc2.Start(ctx)

			_, err := svc2.IssueAccessToken(ctx, "user-id")
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

			oldAccessToken, err := svc.IssueAccessToken(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			claims, err := svc.ValidateAccessToken(ctx, oldAccessToken)
			Expect(err).NotTo(HaveOccurred())
			Expect(claims.Subject).To(Equal(userID))

			err = km.RotateKeys(ctx)
			Expect(err).NotTo(HaveOccurred())

			claims, err = svc.ValidateAccessToken(ctx, oldAccessToken)
			Expect(err).NotTo(HaveOccurred())
			Expect(claims.Subject).To(Equal(userID))

			newAccessToken, err := svc.IssueAccessToken(ctx, userID)
			Expect(err).NotTo(HaveOccurred())
			claims, err = svc.ValidateAccessToken(ctx, newAccessToken)
			Expect(err).NotTo(HaveOccurred())
			Expect(claims.Subject).To(Equal(userID))
		})

		It("should clean up expired tokens", func() {
			userID := "cleanup-user"

			svc2, _, cleanup2 := factory(tokens.ServiceConfig{
				AccessTokenDuration:  5 * time.Minute,
				RefreshTokenDuration: 100 * time.Millisecond,
				CleanupInterval:      10 * time.Second,
				Issuer:               "integration-test",
				Audience:             []string{"integration-test"},
			})
			Expect(svc2.Start(ctx)).To(Succeed())
			DeferCleanup(func() {
				shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
				defer c()
				_ = svc2.Shutdown(shutdownCtx)
				cleanup2()
			})

			token1, err := svc2.IssueRefreshToken(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			_, err = svc2.IssueRefreshToken(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			_, err = svc2.IssueRefreshToken(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			time.Sleep(150 * time.Millisecond)

			count, err := svc2.CleanupExpiredTokens(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(count).To(BeNumerically(">=", 3))

			_, err = svc2.RefreshAccessToken(ctx, token1)
			Expect(err).To(HaveOccurred())

			freshToken, err := svc2.IssueRefreshToken(ctx, userID)
			Expect(err).NotTo(HaveOccurred())
			newAccessToken, err := svc2.RefreshAccessToken(ctx, freshToken)
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
				token, err := svc.IssueRefreshTokenWithMetadata(ctx, userID, metadata)
				Expect(err).NotTo(HaveOccurred())
				deviceRefreshTokens[deviceName] = token
			}

			accessTokens := make(map[string]string)
			for deviceName, refreshToken := range deviceRefreshTokens {
				accessToken, err := svc.RefreshAccessToken(ctx, refreshToken)
				Expect(err).NotTo(HaveOccurred())
				accessTokens[deviceName] = accessToken
			}

			Expect(len(accessTokens)).To(Equal(3))
			for _, token := range accessTokens {
				Expect(token).NotTo(BeEmpty())
			}

			for deviceName, accessToken := range accessTokens {
				claims, err := svc.ValidateAccessToken(ctx, accessToken)
				Expect(err).NotTo(HaveOccurred())
				Expect(claims.Subject).To(Equal(userID))
				_ = deviceName
			}

			err := svc.RevokeAllUserTokens(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			for _, refreshToken := range deviceRefreshTokens {
				_, err = svc.RefreshAccessToken(ctx, refreshToken)
				Expect(err).To(Equal(tokens.ErrTokenRevoked))
			}
		})

		It("should reject invalid, expired, and revoked refresh tokens", func() {
			validUserID := "valid-user"

			validToken, err := svc.IssueRefreshToken(ctx, validUserID)
			Expect(err).NotTo(HaveOccurred())

			_, err = svc.RefreshAccessToken(ctx, "not-a-valid-token")
			Expect(err).To(HaveOccurred())

			svc2, _, cleanup2 := factory(tokens.ServiceConfig{
				AccessTokenDuration:  5 * time.Minute,
				RefreshTokenDuration: 50 * time.Millisecond,
				Issuer:               "integration-test",
				Audience:             []string{"integration-test"},
			})
			Expect(svc2.Start(ctx)).To(Succeed())
			DeferCleanup(func() {
				shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
				defer c()
				_ = svc2.Shutdown(shutdownCtx)
				cleanup2()
			})

			expiredToken, err := svc2.IssueRefreshToken(ctx, "expired-user")
			Expect(err).NotTo(HaveOccurred())
			time.Sleep(100 * time.Millisecond)
			_, err = svc2.RefreshAccessToken(ctx, expiredToken)
			Expect(err).To(HaveOccurred())

			revokeUserID := "revoke-user"
			revokedToken, err := svc.IssueRefreshToken(ctx, revokeUserID)
			Expect(err).NotTo(HaveOccurred())

			_, err = svc.RefreshAccessToken(ctx, revokedToken)
			Expect(err).NotTo(HaveOccurred())

			err = svc.RevokeAllUserTokens(ctx, revokeUserID)
			Expect(err).NotTo(HaveOccurred())
			_, err = svc.RefreshAccessToken(ctx, revokedToken)
			Expect(err).To(Equal(tokens.ErrTokenRevoked))

			_, err = svc.RefreshAccessToken(ctx, "token-never-issued")
			Expect(err).To(HaveOccurred())

			newAccessToken, err := svc.RefreshAccessToken(ctx, validToken)
			Expect(err).NotTo(HaveOccurred())
			Expect(newAccessToken).NotTo(BeEmpty())
		})
	})
}
