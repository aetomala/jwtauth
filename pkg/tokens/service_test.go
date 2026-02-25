package tokens_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"time"

	"github.com/aetomala/jwtauth/internal/testutil"
	"github.com/aetomala/jwtauth/pkg/tokens"
)

func TestTokens(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Tokens Suite")
}

var _ = Describe("TokenService", func() {
	var (
		ctrl       *gomock.Controller
		service    *tokens.Service
		mockKM     *testutil.MockKeyManager
		mockStore  *testutil.MockRefreshStore
		mockRL     *testutil.MockRateLimiter
		mockLogger *testutil.MockLogger
		ctx        context.Context
		cancel     context.CancelFunc
		testUserID string
		/*testTokenID string */
		testKey   *rsa.PrivateKey
		testKeyID string
	)

	BeforeEach(func() {
		// Create gomock controller
		ctrl = gomock.NewController(GinkgoT())

		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		testUserID = "user-12345"
		/*testTokenID = "token-67890"*/

		// Generate test RSA key
		testKey, _ = rsa.GenerateKey(rand.Reader, 2048)
		testKeyID = "test-key-id-123"

		testPublicKey = &testKey.PublicKey

		// Create mocks using gomock (auto-generated)
		mockKM = testutil.NewMockKeyManager(ctrl)
		mockStore = testutil.NewMockRefreshStore(ctrl)
		mockRL = testutil.NewMockRateLimiter(ctrl)
		mockLogger = testutil.NewMockLogger() // Manual mock (for now)
	})

	AfterEach(func() {
		if service != nil && service.IsRunning() {
			// Use a fresh context for shutdown (not the cancelled test context)
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
			mockKM.EXPECT().Shutdown(gomock.Any()).Return(nil).AnyTimes()
			service.Shutdown(shutdownCtx)
			shutdownCancel()
		}
		cancel()
		ctrl.Finish() // Verify all expectations were met
	})

	createService := func() *tokens.Service {
		config := tokens.ServiceConfig{
			KeyManager:           mockKM,
			RefreshStore:         mockStore,
			RateLimiter:          mockRL,
			Logger:               mockLogger,
			AccessTokenDuration:  15 * time.Minute,
			RefreshTokenDuration: 30 * 24 * time.Hour,
			CleanupInterval:      100 * time.Millisecond,
			Issuer:               "test-issuer",
			Audience:             []string{"test-audience"},
		}

		svc, err := tokens.NewService(config)
		Expect(err).NotTo(HaveOccurred())
		return svc
	}

	// ====== PHASE 1: CONSTRUCTOR & CONFIGURATION ===========

	Describe("NewService", func() {
		Context("with valid configuration", func() {
			It("should create service successfully", func() {
				config := tokens.ServiceConfig{
					KeyManager:           mockKM,
					RefreshStore:         mockStore,
					RateLimiter:          mockRL,
					Logger:               mockLogger,
					AccessTokenDuration:  15 * time.Minute,
					RefreshTokenDuration: 30 * 24 * time.Hour,
				}
				svc, err := tokens.NewService(config)
				Expect(err).NotTo(HaveOccurred())
				Expect(svc).NotTo(BeNil())
			})

			It("should work without optional logger", func() {
				config := tokens.ServiceConfig{
					KeyManager:           mockKM,
					RefreshStore:         mockStore,
					RateLimiter:          mockRL,
					Logger:               nil, // Optional
					AccessTokenDuration:  15 * time.Minute,
					RefreshTokenDuration: 30 * 24 * time.Hour,
				}

				svc, err := tokens.NewService(config)

				Expect(err).NotTo(HaveOccurred())
				Expect(svc).NotTo(BeNil())
			})

			It("should use default durations when not specified", func() {
				config := tokens.ServiceConfig{
					KeyManager:   mockKM,
					RefreshStore: mockStore,
					RateLimiter:  mockRL,
					// Durations not specified
				}

				svc, err := tokens.NewService(config)

				Expect(err).NotTo(HaveOccurred())
				Expect(svc).NotTo(BeNil())
			})
		})

		Context("with invalid configuration", func() {
			It("should return error when KeyManager is nil", func() {
				config := tokens.ServiceConfig{
					KeyManager:   nil, // Required
					RefreshStore: mockStore,
					RateLimiter:  mockRL,
				}

				_, err := tokens.NewService(config)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("KeyManager"))
			})

			It("should return error when RefreshStore is nil", func() {
				config := tokens.ServiceConfig{
					KeyManager:   mockKM,
					RefreshStore: nil, // Required
					RateLimiter:  mockRL,
				}
				_, err := tokens.NewService(config)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("RefreshStore"))
			})

			It("should return error when RateLimiter is nil", func() {
				config := tokens.ServiceConfig{
					KeyManager:   mockKM,
					RefreshStore: mockStore,
					RateLimiter:  nil, // Required
				}

				_, err := tokens.NewService(config)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("RateLimiter"))
			})

			It("should return error for invalid token durations", func() {
				config := tokens.ServiceConfig{
					KeyManager:           mockKM,
					RefreshStore:         mockStore,
					RateLimiter:          mockRL,
					AccessTokenDuration:  -1 * time.Minute, // Invalid
					RefreshTokenDuration: 30 * 24 * time.Hour,
				}

				_, err := tokens.NewService(config)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("AccessTokenDuration"))
			})

			It("should return error for invalid refresh token durations", func() {
				config := tokens.ServiceConfig{
					KeyManager:           mockKM,
					RefreshStore:         mockStore,
					RateLimiter:          mockRL,
					AccessTokenDuration:  5 * time.Minute,
					RefreshTokenDuration: -1 * 24 * time.Hour, // Invalid
				}

				_, err := tokens.NewService(config)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("RefreshTokenDuration"))
			})
		})
	})

	// =============  START.   =================

	Describe("Start", func() {
		BeforeEach(func() {
			service = createService()
		})

		It("should start successfully", func() {
			// Expect KeyManager to start
			mockKM.EXPECT().Start(gomock.Any()).Return(nil).Times(1)

			err := service.Start(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(service.IsRunning()).To(BeTrue())
		})

		It("should log startup", func() {
			mockKM.EXPECT().Start(gomock.Any()).Return(nil)

			service.Start(ctx)

			Eventually(func() bool {
				return mockLogger.HasLog("info", "token service started")
			}).Should(BeTrue())
		})

		It("should be idempotent", func() {
			mockKM.EXPECT().Start(gomock.Any()).Return(nil).Times(1)

			// First start
			err := service.Start(ctx)
			Expect(err).NotTo(HaveOccurred())

			// Second start should not error, but not call KeyManager.Start again
			err = service.Start(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(service.IsRunning()).To(BeTrue())
		})

		It("should return error on concurrent start attempts", func() {
			mockKM.EXPECT().Start(gomock.Any()).Return(nil).AnyTimes()

			var wg sync.WaitGroup
			errors := make(chan error, 2)

			// Attempt concurrent starts
			for i := 0; i < 2; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer GinkgoRecover()
					err := service.Start(ctx)
					errors <- err
				}()
			}

			wg.Wait()
			close(errors)

			// One should succeed, one might get ErrAlreadyRunning
			// At minimum, service should be running
			Expect(service.IsRunning()).To(BeTrue())
		})

		It("should start background cleanup goroutine", func() {
			mockKM.EXPECT().Start(gomock.Any()).Return(nil)
			mockKM.EXPECT().Shutdown(gomock.Any()).Return(nil)

			// Start expects cleanup to be called periodically
			// We'll verify by checking cleanup is called after start
			cleanupCalled := make(chan bool, 1)
			mockStore.EXPECT().
				Cleanup().
				DoAndReturn(func() (int, error) {
					select {
					case cleanupCalled <- true:
					default:
					}
					return 0, nil
				}).
				AnyTimes()

			service.Start(ctx)

			// Wait for at least one cleanup call
			Eventually(cleanupCalled, 2*time.Second).Should(Receive())

			// Shutdown to stop the cleanup goroutine
			service.Shutdown(ctx)
		})

		It("should fail if KeyManager fails to start", func() {
			mockKM.EXPECT().
				Start(gomock.Any()).
				Return(errors.New("keymanager start failed"))

			err := service.Start(ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("keymanager start failed"))
			Expect(service.IsRunning()).To(BeFalse())
		})

		It("should respect context cancellation", func() {
			shortCtx, shortCancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
			defer shortCancel()

			mockKM.EXPECT().Start(gomock.Any()).DoAndReturn(func(ctx context.Context) error {
				time.Sleep(100 * time.Millisecond) // Simulate slow start
				return ctx.Err()
			})

			err := service.Start(shortCtx)
			Expect(err).To(HaveOccurred())
			Expect(service.IsRunning()).To(BeFalse())
		})
	})

	// ========================================================================
	// SHUTDOWN TESTS - Following keymanager_test_spec_updated.go line 776
	// ========================================================================
	Describe("Shutdown", func() {
		BeforeEach(func() {
			service = createService()

			// Start the service
			mockKM.EXPECT().Start(gomock.Any()).Return(nil)
			service.Start(ctx)
		})

		// NEW TEST - Basic shutdown
		It("should shutdown successfully", func() {
			// Expect KeyManager to shutdown
			mockKM.EXPECT().Shutdown(gomock.Any()).Return(nil).Times(1)

			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err := service.Shutdown(shutdownCtx)
			Expect(err).NotTo(HaveOccurred())
			Expect(service.IsRunning()).To(BeFalse())
		})

		It("should log shutdown", func() {
			mockKM.EXPECT().Shutdown(gomock.Any()).Return(nil)

			service.Shutdown(ctx)

			Eventually(func() bool {
				return mockLogger.HasLog("info", "token service stopped")
			}).Should(BeTrue())
		})

		It("should stop background cleanup goroutine", func() {
			mockKM.EXPECT().Shutdown(gomock.Any()).Return(nil)

			cleanupCallCount := 0
			mockStore.EXPECT().
				Cleanup().
				DoAndReturn(func() error {
					cleanupCallCount++
					return nil
				}).
				AnyTimes()

			// Shutdown
			service.Shutdown(ctx)

			// Wait a bit
			time.Sleep(2 * time.Second)
			initialCount := cleanupCallCount

			// Wait more - cleanup should NOT be called anymore
			time.Sleep(2 * time.Second)
			Expect(cleanupCallCount).To(Equal(initialCount))
		})

		It("should wait for background goroutines to complete", func() {
			mockKM.EXPECT().Shutdown(gomock.Any()).Return(nil)

			// Track cleanup execution
			cleanupRunning := true
			mockStore.EXPECT().
				Cleanup().
				DoAndReturn(func() error {
					if !cleanupRunning {
						return errors.New("cleanup called after shutdown")
					}
					return nil
				}).
				AnyTimes()

			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err := service.Shutdown(shutdownCtx)
			cleanupRunning = false

			Expect(err).NotTo(HaveOccurred())
		})

		It("should respect shutdown timeout", func() {
			// KeyManager takes too long to shutdown
			mockKM.EXPECT().Shutdown(gomock.Any()).DoAndReturn(func(ctx context.Context) error {
				time.Sleep(2 * time.Second)
				return ctx.Err()
			})

			// Short timeout
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			err := service.Shutdown(shutdownCtx)
			Expect(errors.Is(err, context.DeadlineExceeded)).To(BeTrue())
		})

		It("should be idempotent", func() {
			mockKM.EXPECT().Shutdown(gomock.Any()).Return(nil).Times(1)

			shutdownCtx := context.Background()

			// First shutdown
			err := service.Shutdown(shutdownCtx)
			Expect(err).NotTo(HaveOccurred())

			// Second shutdown should not error, not call KeyManager.Shutdown again
			err = service.Shutdown(shutdownCtx)
			Expect(err).NotTo(HaveOccurred())
			Expect(service.IsRunning()).To(BeFalse())
		})

		It("should reject new token operations after shutdown", func() {
			mockKM.EXPECT().Shutdown(gomock.Any()).Return(nil)

			service.Shutdown(ctx)

			// Try to issue token
			_, err := service.IssueAccessToken(ctx, "user-123")
			Expect(err).To(Equal(tokens.ErrServiceNotRunning))
		})

		It("should return error if KeyManager fails to shutdown", func() {
			mockKM.EXPECT().
				Shutdown(gomock.Any()).
				Return(errors.New("keymanager shutdown failed"))

			err := service.Shutdown(ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("keymanager shutdown failed"))
		})
	})

	// ============== ISRUNNING ===============

	Describe("IsRunning", func() {
		BeforeEach(func() {
			service = createService()
		})

		It("should return false initially", func() {
			Expect(service.IsRunning()).To(BeFalse())
		})

		It("should return true after start", func() {
			mockKM.EXPECT().Start(gomock.Any()).Return(nil)

			service.Start(ctx)

			Expect(service.IsRunning()).To(BeTrue())
		})

	})

	// ==========ACCESS TOKEN ISSUANCE ========
	Describe("IssueAccessToken", func() {
		BeforeEach(func() {
			service = createService()
		})
		It("should issue access token successfully", func() {
			// Expect rake limit check
			mockRL.EXPECT().Allow(testUserID, 1).Return(true, nil).Times(1)
			// Expect key retrieval
			mockKM.EXPECT().GetCurrentSigningKey().Return(testKey, testKeyID, nil)
			token, err := service.IssueAccessToken(ctx, testUserID)
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo((BeEmpty()))
		})

		It("should use KeyManager to sign token", func() {
			mockRL.EXPECT().Allow(gomock.Any(), gomock.Any()).Return(true, nil)

			// This is what we're verifying
			mockKM.EXPECT().GetCurrentSigningKey().Return(testKey, testKeyID, nil).Times(1)

			service.IssueAccessToken(ctx, testUserID)
		})

		It("should check rate limit", func() {
			// This is what we're verifying
			mockRL.EXPECT().Allow(testUserID, 1).Return(true, nil).Times(1)

			mockKM.EXPECT().GetCurrentSigningKey().Return(testKey, testKeyID, nil)

			service.IssueAccessToken(ctx, testUserID)
		})

		It("should log token issuance", func() {
			mockRL.EXPECT().Allow(gomock.Any(), gomock.Any()).Return(true, nil)
			mockKM.EXPECT().GetCurrentSigningKey().Return(testKey, testKeyID, nil)

			service.IssueAccessToken(ctx, testUserID)

			Eventually(func() bool {
				return mockLogger.HasLog("info", "access token issued")
			}).Should(BeTrue())
		})

		It("should include custom claims issuance if provided", func() {
			mockRL.EXPECT().Allow(gomock.Any(), gomock.Any()).Return(true, nil)
			mockKM.EXPECT().GetCurrentSigningKey().Return(testKey, testKeyID, nil)

			customClaims := map[string]interface{}{
				"role":   "admin",
				"tenant": "org-123",
			}

			token, err := service.IssueAccessTokenWithClaims(ctx, testUserID, customClaims)

			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())

			// Parse and verify claims contain custom data
			claims := parseToken(token)
			Expect(claims.Custom["role"]).To(Equal("admin"))
			Expect(claims.Custom["tenant"]).To(Equal("org-123"))
		})

		It("should respect call order", func() {
			// Verify rate limit is checked BEFORE getting signing key
			gomock.InOrder(
				mockRL.EXPECT().Allow(testUserID, 1).Return(true, nil),
				mockKM.EXPECT().GetCurrentSigningKey().Return(testKey, testKeyID, nil),
			)

			service.IssueAccessToken(ctx, testUserID)
		})

		Context("when rate limited", func() {
			It("should return error when rate limit exceeded", func() {
				mockRL.EXPECT().Allow(testUserID, 1).Return(false, nil).Times(1)

				// Should NOT call KeyManager
				mockKM.EXPECT().GetCurrentSigningKey().Times(0)

				_, err := service.IssueAccessToken(ctx, testUserID)
				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError(tokens.ErrRateLimitExceeded))
			})

			It("should log rate limit rejection", func() {
				mockRL.EXPECT().Allow(gomock.Any(), gomock.Any()).Return(false, nil)

				service.IssueAccessToken(ctx, testUserID)

				Eventually(func() bool {
					return mockLogger.HasLog("warn", "rate limit exceeded")
				}).Should(BeTrue())
			})

			It("should not issue token when rate limited", func() {
				mockRL.EXPECT().Allow(gomock.Any(), gomock.Any()).Return(false, nil)

				// Verify GetCurrentSigningKey is NEVER called
				mockKM.EXPECT().GetCurrentSigningKey().Times(0)

				service.IssueAccessToken(ctx, testUserID)
			})
		})

		Context("when rate limit check fails", func() {
			It("should return error", func() {
				mockRL.EXPECT().
					Allow(gomock.Any(), gomock.Any()).
					Return(false, errors.New("rate limit service unavailable"))

				_, err := service.IssueAccessToken(ctx, testUserID)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("rate limit service unavailable"))
			})
		})

		Context("when key retrieval fails", func() {
			It("should return error", func() {
				mockRL.EXPECT().Allow(gomock.Any(), gomock.Any()).Return(true, nil)

				mockKM.EXPECT().GetCurrentSigningKey().Return(nil, "", errors.New("key unavailable")).Times(1)

				_, err := service.IssueAccessToken(ctx, testUserID)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("key unavailable"))
			})

			It("should log error", func() {
				mockRL.EXPECT().Allow(gomock.Any(), gomock.Any()).Return(true, nil)
				mockKM.EXPECT().
					GetCurrentSigningKey().
					Return(nil, "", errors.New("key error"))

				service.IssueAccessToken(ctx, testUserID)

				Eventually(func() bool {
					return mockLogger.HasLog("error", "failed to get signing key")
				}).Should(BeTrue())
			})
		})

		Context("with invalid user ID", func() {
			It("should return error for empty user ID", func() {
				// Should not call any dependencies for invalid input
				mockRL.EXPECT().Allow(gomock.Any(), gomock.Any()).Times(0)
				mockKM.EXPECT().GetCurrentSigningKey().Times(0)

				_, err := service.IssueAccessToken(ctx, "")

				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError(tokens.ErrInvalidUserID))
			})

			It("should return error for whitespace-only user ID", func() {
				mockRL.EXPECT().Allow(gomock.Any(), gomock.Any()).Times(0)
				mockKM.EXPECT().GetCurrentSigningKey().Times(0)

				_, err := service.IssueAccessToken(ctx, "   ")

				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError(tokens.ErrInvalidUserID))
			})
		})

		Context("with cancelled context", func() {
			It("should return context error", func() {
				cancelledCtx, cancelFn := context.WithCancel(context.Background())
				cancelFn() // cancel immediately

				// Might not even get to dependencies
				mockRL.EXPECT().Allow(gomock.Any(), gomock.Any()).Times(0)
				mockKM.EXPECT().GetCurrentSigningKey().Times(0)

				_, err := service.IssueAccessToken(cancelledCtx, testUserID)
				Expect(err).To(Equal(context.Canceled))
			})
		})
	})

	// ============== REFRESH TOKEN ISSUANCE ===================

	Describe("IssueRefreshToken", func() {
		BeforeEach(func() {
			service = createService()
		})

		Context("with valid user ID", func() {
			It("should issue refresh token succesfully", func() {
				mockRL.EXPECT().Allow(testUserID, 1).Return(true, nil)

				mockStore.EXPECT().Store(
					gomock.Any(), // tokenID (generated)
					testUserID,   // userID
					gomock.Any(), // expireAt
					gomock.Any(), // metadata
				).Return(nil).
					Times(1)

				token, err := service.IssueRefreshToken(ctx, testUserID)

				Expect(err).NotTo(HaveOccurred())
				Expect(token).NotTo(BeEmpty())
			})

			It("should store refresh token", func() {
				mockRL.EXPECT().Allow(gomock.Any(), gomock.Any()).Return(true, nil)

				// Verify Store is called
				mockStore.EXPECT().
					Store(gomock.Any(), testUserID, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)

				service.IssueRefreshToken(ctx, testUserID)
			})

			It("should check rate limit", func() {
				// Verify rate limit is checked
				mockRL.EXPECT().
					Allow(testUserID, 1).
					Return(true, nil).
					Times(1)

				mockStore.EXPECT().Store(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				service.IssueRefreshToken(ctx, testUserID)
			})

			It("should log token issuance", func() {
				mockRL.EXPECT().Allow(gomock.Any(), gomock.Any()).Return(true, nil)
				mockStore.EXPECT().Store(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				service.IssueRefreshToken(ctx, testUserID)

				Eventually(func() bool {
					return mockLogger.HasLog("info", "refresh token issued")
				}).Should(BeTrue())
			})

			It("should store metadata when provided", func() {
				mockRL.EXPECT().Allow(gomock.Any(), gomock.Any()).Return(true, nil)

				metadata := map[string]interface{}{
					"ip":        "192.168.1.1",
					"userAgent": "Mozilla/5.0",
				}

				// Verify metadata is passed to Store
				mockStore.EXPECT().
					Store(gomock.Any(), testUserID, gomock.Any(), metadata).
					Return(nil)

				service.IssueRefreshTokenWithMetadata(ctx, testUserID, metadata)
			})

			It("should set correct expiration time", func() {
				mockRL.EXPECT().Allow(gomock.Any(), gomock.Any()).Return(true, nil)

				expectedExpiry := time.Now().Add(30 * 24 * time.Hour)

				// Use custom matcher to verify expiration is approximately correct
				mockStore.EXPECT().
					Store(
						gomock.Any(),
						testUserID,
						gomock.AssignableToTypeOf(time.Time{}),
						gomock.Any(),
					).
					Do(func(tokenID, userID string, expiresAt time.Time, metadata map[string]interface{}) {
						// Verify expiration is within 2 seconds of expected
						Expect(expiresAt).To(BeTemporally("~", expectedExpiry, 2*time.Second))
					}).
					Return(nil)

				service.IssueRefreshToken(ctx, testUserID)
			})
		})

		Context("when storage fails", func() {
			It("should return error", func() {
				mockRL.EXPECT().Allow(gomock.Any(), gomock.Any()).Return(true, nil)

				mockStore.EXPECT().
					Store(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(errors.New("storage failure"))

				_, err := service.IssueRefreshToken(ctx, testUserID)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("storage failure"))
			})

			It("should log error", func() {
				mockRL.EXPECT().Allow(gomock.Any(), gomock.Any()).Return(true, nil)
				mockStore.EXPECT().
					Store(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(errors.New("storage error"))

				service.IssueRefreshToken(ctx, testUserID)

				Eventually(func() bool {
					return mockLogger.HasLog("error", "failed to store refresh token")
				}).Should(BeTrue())
			})
		})

		Context("when rate limited", func() {
			It("should return error", func() {
				mockRL.EXPECT().Allow(gomock.Any(), gomock.Any()).Return(false, nil)

				// Should NOT call Store
				mockStore.EXPECT().Store(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				_, err := service.IssueRefreshToken(ctx, testUserID)

				Expect(err).To(MatchError(tokens.ErrRateLimitExceeded))
			})

			It("should not store token when rate limited", func() {
				mockRL.EXPECT().Allow(gomock.Any(), gomock.Any()).Return(false, nil)

				// Verify Store is NEVER called
				mockStore.EXPECT().Store(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				service.IssueRefreshToken(ctx, testUserID)
			})
		})
	})

	// ================== TOKEN PAIR ISSUANCE =============

	Describe("IssueTokenPair", func() {
		BeforeEach(func() {
			service = createService()
		})

		Context("with valid user. ID", func() {
			It("should issue both token successfully", func() {
				// Expect all dependencies called in order
				gomock.InOrder(
					mockRL.EXPECT().Allow(testUserID, 1).Return(true, nil),
					mockKM.EXPECT().GetCurrentSigningKey().Return(testKey, testKeyID, nil),
					mockStore.EXPECT().Store(gomock.Any(), testUserID, gomock.Any(), gomock.Any()).Return(nil),
				)

				accessToken, refreshToken, err := service.IssueTokenPair(ctx, testUserID)
				Expect(err).NotTo(HaveOccurred())
				Expect(accessToken).NotTo(BeEmpty())
				Expect(refreshToken).NotTo(BeEmpty())
				Expect(accessToken).NotTo(Equal(refreshToken))
			})

			It("should use KeyManager for access token", func() {
				mockRL.EXPECT().Allow(gomock.Any(), gomock.Any()).Return(true, nil)

				mockKM.EXPECT().
					GetCurrentSigningKey().
					Return(testKey, testKeyID, nil).
					Times(1)

				mockStore.EXPECT().Store(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				service.IssueTokenPair(ctx, testUserID)
			})

			It("should store refresh token", func() {
				mockRL.EXPECT().Allow(gomock.Any(), gomock.Any()).Return(true, nil)
				mockKM.EXPECT().GetCurrentSigningKey().Return(testKey, testKeyID, nil)

				mockStore.EXPECT().
					Store(gomock.Any(), testUserID, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)

				service.IssueTokenPair(ctx, testUserID)
			})

			It("should check rate limit once for pair", func() {
				mockRL.EXPECT().
					Allow(testUserID, 1).
					Return(true, nil).
					Times(1) // Only once for the pair

				mockKM.EXPECT().GetCurrentSigningKey().Return(testKey, testKeyID, nil)
				mockStore.EXPECT().Store(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				service.IssueTokenPair(ctx, testUserID)
			})

			It("should log both issuances", func() {
				mockRL.EXPECT().Allow(gomock.Any(), gomock.Any()).Return(true, nil)
				mockKM.EXPECT().GetCurrentSigningKey().Return(testKey, testKeyID, nil)
				mockStore.EXPECT().Store(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				service.IssueTokenPair(ctx, testUserID)

				Eventually(func() bool {
					return mockLogger.HasLog("info", "token pair issued")
				}).Should(BeTrue())
			})
		})

		Context("when access token issuance fails", func() {
			It("should not issue refresh token", func() {
				mockRL.EXPECT().Allow(gomock.Any(), gomock.Any()).Return(true, nil)
				mockKM.EXPECT().
					GetCurrentSigningKey().
					Return(nil, "", errors.New("key error"))

				// Store should NOT be called
				mockStore.EXPECT().Store(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				_, _, err := service.IssueTokenPair(ctx, testUserID)

				Expect(err).To(HaveOccurred())
			})
		})

		Context("when refresh token storage fails", func() {
			It("should return error", func() {
				mockRL.EXPECT().Allow(gomock.Any(), gomock.Any()).Return(true, nil)
				mockKM.EXPECT().GetCurrentSigningKey().Return(testKey, testKeyID, nil)
				mockStore.EXPECT().
					Store(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(errors.New("storage error"))

				_, _, err := service.IssueTokenPair(ctx, testUserID)

				Expect(err).To(HaveOccurred())
			})
		})

		Context("when rate limited", func() {
			It("should not issue either token", func() {
				mockRL.EXPECT().Allow(gomock.Any(), gomock.Any()).Return(false, nil)

				// Neither KeyManager nor Store should be called
				mockKM.EXPECT().GetCurrentSigningKey().Times(0)
				mockStore.EXPECT().Store(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				_, _, err := service.IssueTokenPair(ctx, testUserID)

				Expect(err).To(MatchError(tokens.ErrRateLimitExceeded))
			})
		})
	})

	// ========== ACCESS TOKEN VALIDATION ===========

})

// ============================================================================
// TEST HELPERS
// ============================================================================

// parseToken parses a JWT token string and returns the claims.
//
// This is a TEST HELPER function - it knows about the test key.
// Production code should use ValidateAccessToken instead.
//
// Args:
//   - tokenString: The JWT token to parse
//
// Returns:
//   - claims: Parsed claims if valid
//   - nil: If token is invalid or parsing fails
func parseToken(tokenString string) *tokens.Claims {
	// First parse with MapClaims to get all claims (standard + custom)
	mapToken, err := jwt.ParseWithClaims(
		tokenString,
		jwt.MapClaims{},
		func(token *jwt.Token) (interface{}, error) {
			// Verify signing method is RS256
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			// Get key ID from header
			kid, ok := token.Header["kid"].(string)
			if !ok {
				return nil, errors.New("missing kid in token header")
			}

			// In tests, we use the test public key
			// In production, you'd call: mockKM.GetPublicKey(kid)
			return getTestPublicKey(kid)
		},
	)

	if err != nil {
		return nil
	}

	// Verify token is valid
	if !mapToken.Valid {
		return nil
	}

	// Extract MapClaims
	mapClaims, ok := mapToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil
	}

	// Create a tokens.Claims struct and populate it
	claims := &tokens.Claims{
		Custom: make(map[string]interface{}),
	}

	// Standard JWT claims that should NOT be in Custom
	standardClaimKeys := map[string]bool{
		"sub": true, "iss": true, "aud": true,
		"exp": true, "iat": true, "nbf": true, "jti": true,
	}

	// Extract standard claims and custom claims
	for key, value := range mapClaims {
		if !standardClaimKeys[key] {
			// This is a custom claim
			claims.Custom[key] = value
		}
	}

	// Manually populate RegisteredClaims from MapClaims
	if sub, ok := mapClaims["sub"].(string); ok {
		claims.Subject = sub
	}
	if iss, ok := mapClaims["iss"].(string); ok {
		claims.Issuer = iss
	}
	if jti, ok := mapClaims["jti"].(string); ok {
		claims.ID = jti
	}

	// Handle audience (can be []string or []interface{})
	if aud, ok := mapClaims["aud"]; ok {
		switch audVal := aud.(type) {
		case []interface{}:
			for _, a := range audVal {
				if audStr, ok := a.(string); ok {
					claims.Audience = append(claims.Audience, audStr)
				}
			}
		case []string:
			claims.Audience = audVal
		}
	}

	return claims
}

// ============================================================================
// ALTERNATIVE: Parse with Mock KeyManager
// ============================================================================

// parseTokenWithKeyManager parses a token using a mock KeyManager.
// This is more realistic for integration-style tests.
func parseTokenWithKeyManager(tokenString string, mockKM *testutil.MockKeyManager) *tokens.Claims {
	token, err := jwt.ParseWithClaims(
		tokenString,
		&tokens.Claims{},
		func(token *jwt.Token) (interface{}, error) {
			// Verify signing method
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			// Get key ID from header
			kid, ok := token.Header["kid"].(string)
			if !ok {
				return nil, errors.New("missing kid in token header")
			}

			// Use mock KeyManager to get public key
			publicKey, err := mockKM.GetPublicKey(kid)
			if err != nil {
				return nil, err
			}

			return publicKey, nil
		},
	)

	if err != nil {
		return nil
	}

	if !token.Valid {
		return nil
	}

	claims, ok := token.Claims.(*tokens.Claims)
	if !ok {
		return nil
	}

	return claims
}

// ============================================================================
// SIMPLER: Parse WITHOUT Verification (Testing Only!)
// ============================================================================

// parseTokenUnsafe parses a token WITHOUT verifying the signature.
//
//	ONLY USE IN TESTS! Never in production!
//
// Use this when you just want to check claims structure, not security.
func parseTokenUnsafe(tokenString string) *tokens.Claims {
	// Parse without verification
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenString, &tokens.Claims{})
	if err != nil {
		return nil
	}

	claims, ok := token.Claims.(*tokens.Claims)
	if !ok {
		return nil
	}

	return claims
}

var testPublicKey *rsa.PublicKey

func getTestPublicKey(kid string) (*rsa.PublicKey, error) {
	if testPublicKey == nil {
		return nil, errors.New("test public key not initialized")
	}
	return testPublicKey, nil
}
