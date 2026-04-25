package tokens_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"github.com/aetomala/jwtauth/internal/testutil"
	"github.com/aetomala/jwtauth/pkg/keys"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/aetomala/jwtauth/pkg/tokens"
	"github.com/aetomala/jwtauth/pkg/tracing"
)

func TestTokens(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Tokens Suite")
}

var _ = Describe("TokenManager", func() {
	var (
		ctrl        *gomock.Controller
		service     *tokens.Manager
		mockKM      *testutil.MockKeyManager
		mockStore   *testutil.MockRefreshStore
		mockLogger  *testutil.MockLogger
		ctx         context.Context
		cancel      context.CancelFunc
		testUserID  string
		testTokenID string
		testKey     *rsa.PrivateKey
		testKeyID   string
	)

	BeforeEach(func() {
		// Create gomock controller
		ctrl = gomock.NewController(GinkgoT())

		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		testUserID = "user-12345"
		testTokenID = "token-67890"

		// Generate test RSA key
		testKey, _ = rsa.GenerateKey(rand.Reader, 2048)
		testKeyID = "test-key-id-123"

		testPublicKey = &testKey.PublicKey

		// Create mocks using gomock (auto-generated)
		mockKM = testutil.NewMockKeyManager(ctrl)
		mockStore = testutil.NewMockRefreshStore(ctrl)
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

	// ========================================================================
	// NEWSERVICE TESTS
	// ========================================================================
	Describe("NewManager", func() {
		Context("with valid configuration", func() {
			It("should create service successfully", func() {
				config := tokens.TokenManagerConfig{
					KeyManager:           mockKM,
					RefreshStore:         mockStore,
							Logger:               mockLogger,
					AccessTokenDuration:  15 * time.Minute,
					RefreshTokenDuration: 30 * 24 * time.Hour,
				}
				mgr, err := tokens.NewManager(config)
				Expect(err).NotTo(HaveOccurred())
				Expect(mgr).NotTo(BeNil())
			})

			It("should work without optional logger", func() {
				config := tokens.TokenManagerConfig{
					KeyManager:           mockKM,
					RefreshStore:         mockStore,
							Logger:               nil, // Optional
					AccessTokenDuration:  15 * time.Minute,
					RefreshTokenDuration: 30 * 24 * time.Hour,
				}

				mgr, err := tokens.NewManager(config)

				Expect(err).NotTo(HaveOccurred())
				Expect(mgr).NotTo(BeNil())
			})

			It("should use default durations when not specified", func() {
				config := tokens.TokenManagerConfig{
					KeyManager:   mockKM,
					RefreshStore: mockStore,
						// Durations not specified
				}

				mgr, err := tokens.NewManager(config)

				Expect(err).NotTo(HaveOccurred())
				Expect(mgr).NotTo(BeNil())
			})
		})

		Context("with invalid configuration", func() {
			It("should return error when KeyManager is nil", func() {
				config := tokens.TokenManagerConfig{
					KeyManager:   nil, // Required
					RefreshStore: mockStore,
					}

				_, err := tokens.NewManager(config)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("KeyManager"))
			})

			It("should return error when RefreshStore is nil", func() {
				config := tokens.TokenManagerConfig{
					KeyManager:   mockKM,
					RefreshStore: nil, // Required
					}
				_, err := tokens.NewManager(config)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("RefreshStore"))
			})


			It("should return error for invalid token durations", func() {
				config := tokens.TokenManagerConfig{
					KeyManager:           mockKM,
					RefreshStore:         mockStore,
							AccessTokenDuration:  -1 * time.Minute, // Invalid
					RefreshTokenDuration: 30 * 24 * time.Hour,
				}

				_, err := tokens.NewManager(config)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("AccessTokenDuration"))
			})

			It("should return error for invalid refresh token durations", func() {
				config := tokens.TokenManagerConfig{
					KeyManager:           mockKM,
					RefreshStore:         mockStore,
							AccessTokenDuration:  5 * time.Minute,
					RefreshTokenDuration: -1 * 24 * time.Hour, // Invalid
				}

				_, err := tokens.NewManager(config)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("RefreshTokenDuration"))
			})

			It("should return error for negative ClockSkew", func() {
				config := tokens.TokenManagerConfig{
					KeyManager: mockKM,
					RefreshStore: mockStore,
					ClockSkew:  -1 * time.Second,
				}

				_, err := tokens.NewManager(config)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("ClockSkew"))
			})
		})

		Context("tracer defaults and acceptance", func() {
			It("should apply default Tracer from DefaultTokenManagerConfig when Tracer is nil", func() {
				mgr, err := tokens.NewManager(tokens.TokenManagerConfig{
					KeyManager:   mockKM,
					RefreshStore: mockStore,
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(mgr).NotTo(BeNil())
			})

			It("should accept an explicit Tracer without error", func() {
				ctrl2 := gomock.NewController(GinkgoT())
				defer ctrl2.Finish()
				mockT := testutil.NewMockTracer(ctrl2)
				mockSp := testutil.NewMockSpan(ctrl2)
				mockT.EXPECT().Start(gomock.Any(), gomock.Any(), gomock.Any()).Return(context.Background(), mockSp).AnyTimes()
				mockSp.EXPECT().End().AnyTimes()
				mockSp.EXPECT().SetAttribute(gomock.Any(), gomock.Any()).AnyTimes()
				mockSp.EXPECT().SetStatus(gomock.Any(), gomock.Any()).AnyTimes()
				mockSp.EXPECT().RecordError(gomock.Any()).AnyTimes()

				mgr, err := tokens.NewManager(tokens.TokenManagerConfig{
					KeyManager:   mockKM,
					RefreshStore: mockStore,
					Tracer:       mockT,
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(mgr).NotTo(BeNil())
			})
		})
	})

	// Lifecycle tests (Start, Shutdown, IsRunning, Complete Lifecycle) have been moved to service_lifecycle_test.go

	// ========================================================================
	// ISSUE ACCESS TOKEN TESTS
	// ========================================================================
	Describe("IssueAccessToken", func() {
		BeforeEach(func() {
			service = newTestManager(mockKM, mockStore, mockLogger)
			mockKM.EXPECT().Start(gomock.Any()).Return(nil)
			err := service.Start(ctx)
			Expect(err).NotTo(HaveOccurred())
		})
		It("should issue access token successfully", func() {
			// Expect key retrieval
			mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)
			token, err := service.IssueAccessToken(ctx, testUserID)
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo((BeEmpty()))
		})

		It("should use KeyManager to sign token", func() {
			// This is what we're verifying
			mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil).Times(1)

			service.IssueAccessToken(ctx, testUserID)
		})

		It("should log token issuance", func() {
			mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)

			service.IssueAccessToken(ctx, testUserID)

			Eventually(func() bool {
				return mockLogger.HasLog("info", "access token issued")
			}).Should(BeTrue())
		})

		It("should include custom claims issuance if provided", func() {
			mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)

			customClaims := tokens.CustomClaims{
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
			mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)

			service.IssueAccessToken(ctx, testUserID)
		})

		Context("when key retrieval fails", func() {
			It("should return error", func() {
				mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(nil, "", errors.New("key unavailable")).Times(1)

				_, err := service.IssueAccessToken(ctx, testUserID)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("key unavailable"))
			})

			It("should log error", func() {
				mockKM.EXPECT().
					GetCurrentSigningKey(gomock.Any()).
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
				mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Times(0)

				_, err := service.IssueAccessToken(ctx, "")

				Expect(err).To(HaveOccurred())
				Expect(err).To(Equal(tokens.ErrInvalidUserID))
			})

			It("should return error for whitespace-only user ID", func() {
				mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Times(0)

				_, err := service.IssueAccessToken(ctx, "   ")

				Expect(err).To(HaveOccurred())
				Expect(err).To(Equal(tokens.ErrInvalidUserID))
			})
		})

		Context("with cancelled context", func() {
			It("should return context error", func() {
				cancelledCtx, cancelFn := context.WithCancel(context.Background())
				cancelFn() // cancel immediately

				// Might not even get to dependencies
				mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Times(0)

				_, err := service.IssueAccessToken(cancelledCtx, testUserID)
				Expect(err).To(Equal(context.Canceled))
			})
		})

		Context("IssueAccessTokenWithClaims guard conditions", func() {
			It("should return ErrManagerNotRunning", func() {
				mgr := newTestManager(mockKM, mockStore, mockLogger)
				_, err := mgr.IssueAccessTokenWithClaims(ctx, testUserID, nil)
				Expect(err).To(Equal(tokens.ErrManagerNotRunning))
			})

			It("should return context error when context is cancelled", func() {
				cancelledCtx, cancel := context.WithCancel(ctx)
				cancel()
				_, err := service.IssueAccessTokenWithClaims(cancelledCtx, testUserID, nil)
				Expect(err).To(Equal(context.Canceled))
			})

			It("should return ErrInvalidUserID for empty userID", func() {
				_, err := service.IssueAccessTokenWithClaims(ctx, "", nil)
				Expect(err).To(Equal(tokens.ErrInvalidUserID))
			})

			It("should return ErrInvalidUserID for whitespace-only userID", func() {
				_, err := service.IssueAccessTokenWithClaims(ctx, "   ", nil)
				Expect(err).To(Equal(tokens.ErrInvalidUserID))
			})

			It("should not override reserved claim sub", func() {
				mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)
				customClaims := tokens.CustomClaims{"sub": "hacker", "role": "admin"}
				tokenStr, err := service.IssueAccessTokenWithClaims(ctx, testUserID, customClaims)
				Expect(err).NotTo(HaveOccurred())
				parsed, _ := jwt.ParseWithClaims(tokenStr, &jwt.MapClaims{}, func(t *jwt.Token) (interface{}, error) {
					return &testKey.PublicKey, nil
				})
				claims := *parsed.Claims.(*jwt.MapClaims)
				Expect(claims["sub"]).To(Equal(testUserID))
				Expect(claims["role"]).To(Equal("admin"))
			})
		})
	})

	// ========================================================================
	// ISSUE REFRESH TOKEN TESTS
	// ========================================================================
	Describe("IssueRefreshToken", func() {
		BeforeEach(func() {
			service = newTestManager(mockKM, mockStore, mockLogger)
			mockKM.EXPECT().Start(gomock.Any()).Return(nil)
			err := service.Start(ctx)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("with valid user ID", func() {
			It("should issue refresh token succesfully", func() {
				mockStore.EXPECT().Store(
					gomock.Any(), // ctx
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
					// Verify Store is called
				mockStore.EXPECT().
					Store(gomock.Any(), gomock.Any(), testUserID, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)

				service.IssueRefreshToken(ctx, testUserID)
			})

			It("should log token issuance", func() {
				mockStore.EXPECT().Store(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				service.IssueRefreshToken(ctx, testUserID)

				Eventually(func() bool {
					return mockLogger.HasLog("info", "refresh token issued")
				}).Should(BeTrue())
			})

			It("should store claims when provided", func() {
				claims := tokens.CustomClaims{
					"ip":        "192.168.1.1",
					"userAgent": "Mozilla/5.0",
				}

				// Verify claims are passed to Store
				mockStore.EXPECT().
					Store(gomock.Any(), gomock.Any(), testUserID, gomock.Any(), claims).
					Return(nil)

				service.IssueRefreshTokenWithClaims(ctx, testUserID, claims)
			})

			It("should set correct expiration time", func() {
				expectedExpiry := time.Now().Add(30 * 24 * time.Hour)

				// Use custom matcher to verify expiration is approximately correct
				mockStore.EXPECT().
					Store(
						gomock.Any(),
						gomock.Any(),
						testUserID,
						gomock.AssignableToTypeOf(time.Time{}),
						gomock.Any(),
					).
					Do(func(_ context.Context, tokenID, userID string, expiresAt time.Time, metadata map[string]interface{}) {
						// Verify expiration is within 2 seconds of expected
						Expect(expiresAt).To(BeTemporally("~", expectedExpiry, 2*time.Second))
					}).
					Return(nil)

				service.IssueRefreshToken(ctx, testUserID)
			})
		})

		Context("when storage fails", func() {
			It("should return error", func() {
				mockStore.EXPECT().
					Store(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(errors.New("storage failure"))

				_, err := service.IssueRefreshToken(ctx, testUserID)

				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("storage failure"))
			})

			It("should log error", func() {
				mockStore.EXPECT().
					Store(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(errors.New("storage error"))

				service.IssueRefreshToken(ctx, testUserID)

				Eventually(func() bool {
					return mockLogger.HasLog("error", "failed to store refresh token")
				}).Should(BeTrue())
			})
		})

		Context("guard conditions", func() {
			It("should return ErrManagerNotRunning", func() {
				mgr := newTestManager(mockKM, mockStore, mockLogger)
				_, err := mgr.IssueRefreshToken(ctx, "user-123")
				Expect(err).To(Equal(tokens.ErrManagerNotRunning))
			})

			It("should return context error when context is cancelled", func() {
				cancelledCtx, cancel := context.WithCancel(ctx)
				cancel()
				_, err := service.IssueRefreshToken(cancelledCtx, "user-123")
				Expect(err).To(Equal(context.Canceled))
			})

			It("should return ErrInvalidUserID for whitespace-only userID", func() {
				_, err := service.IssueRefreshToken(ctx, "   ")
				Expect(err).To(Equal(tokens.ErrInvalidUserID))
			})
		})

		Context("IssueRefreshTokenWithClaims guards", func() {
			It("should return error when service is not running", func() {
				stoppedService := newTestManager(mockKM, mockStore, mockLogger)

				_, err := stoppedService.IssueRefreshTokenWithClaims(ctx, testUserID, nil)

				Expect(err).To(MatchError(tokens.ErrManagerNotRunning))
			})

			It("should return error when context is cancelled", func() {
				cancelledCtx, cancel := context.WithCancel(ctx)
				cancel()

				_, err := service.IssueRefreshTokenWithClaims(cancelledCtx, testUserID, nil)

				Expect(err).To(MatchError(context.Canceled))
			})

			It("should return error when storage fails", func() {
				mockStore.EXPECT().Store(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(errors.New("storage failure"))

				_, err := service.IssueRefreshTokenWithClaims(ctx, testUserID, nil)

				Expect(err).To(HaveOccurred())
			})
		})
	})

	// ========================================================================
	// ISSUE TOKEN PAIR TESTS
	// ========================================================================
	Describe("IssueTokenPair", func() {
		BeforeEach(func() {
			service = newTestManager(mockKM, mockStore, mockLogger)
			mockKM.EXPECT().Start(gomock.Any()).Return(nil)
			err := service.Start(ctx)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("with valid user. ID", func() {
			It("should issue both token successfully", func() {
				// Expect all dependencies called in order
				gomock.InOrder(
					mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil),
					mockStore.EXPECT().Store(gomock.Any(), gomock.Any(), testUserID, gomock.Any(), gomock.Any()).Return(nil),
				)

				accessToken, refreshToken, err := service.IssueTokenPair(ctx, testUserID)
				Expect(err).NotTo(HaveOccurred())
				Expect(accessToken).NotTo(BeEmpty())
				Expect(refreshToken).NotTo(BeEmpty())
				Expect(accessToken).NotTo(Equal(refreshToken))
			})

			It("should use KeyManager for access token", func() {
				mockKM.EXPECT().
					GetCurrentSigningKey(gomock.Any()).
					Return(testKey, testKeyID, nil).
					Times(1)

				mockStore.EXPECT().Store(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				service.IssueTokenPair(ctx, testUserID)
			})

			It("should store refresh token", func() {
				mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)

				mockStore.EXPECT().
					Store(gomock.Any(), gomock.Any(), testUserID, gomock.Any(), gomock.Any()).
					Return(nil).
					Times(1)

				service.IssueTokenPair(ctx, testUserID)
			})

			It("should log both issuances", func() {
				mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)
				mockStore.EXPECT().Store(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				service.IssueTokenPair(ctx, testUserID)

				Eventually(func() bool {
					return mockLogger.HasLog("info", "token pair issued")
				}).Should(BeTrue())
			})
		})

		Context("when access token issuance fails", func() {
			It("should not issue refresh token", func() {
				mockKM.EXPECT().
					GetCurrentSigningKey(gomock.Any()).
					Return(nil, "", errors.New("key error"))

				// Store should NOT be called
				mockStore.EXPECT().Store(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				_, _, err := service.IssueTokenPair(ctx, testUserID)

				Expect(err).To(HaveOccurred())
			})
		})

		Context("when refresh token storage fails", func() {
			It("should return error", func() {
				mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)
				mockStore.EXPECT().
					Store(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(errors.New("storage error"))

				_, _, err := service.IssueTokenPair(ctx, testUserID)

				Expect(err).To(HaveOccurred())
			})
		})

		Context("guard conditions", func() {
			It("should return ErrManagerNotRunning", func() {
				mgr := newTestManager(mockKM, mockStore, mockLogger)
				_, _, err := mgr.IssueTokenPair(ctx, "user-123")
				Expect(err).To(Equal(tokens.ErrManagerNotRunning))
			})

			It("should return context error when context is cancelled", func() {
				cancelledCtx, cancel := context.WithCancel(ctx)
				cancel()
				_, _, err := service.IssueTokenPair(cancelledCtx, "user-123")
				Expect(err).To(Equal(context.Canceled))
			})

			It("should return ErrInvalidUserID for whitespace-only userID", func() {
				_, _, err := service.IssueTokenPair(ctx, "   ")
				Expect(err).To(Equal(tokens.ErrInvalidUserID))
			})
		})
	})

	// ========================================================================
	// ISSUE TOKEN PAIR WITH CLAIMS TESTS
	// ========================================================================

	Describe("IssueTokenPairWithClaims", func() {
		BeforeEach(func() {
			service = newTestManager(mockKM, mockStore, mockLogger)
			mockKM.EXPECT().Start(gomock.Any()).Return(nil)
			err := service.Start(ctx)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("with valid user ID and claims", func() {
			It("should issue both tokens successfully", func() {
				accessClaims := tokens.CustomClaims{"role": "admin"}
				refreshClaims := tokens.CustomClaims{"ip": "192.168.1.1"}

				gomock.InOrder(
					mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil),
					mockStore.EXPECT().Store(gomock.Any(), gomock.Any(), testUserID, gomock.Any(), refreshClaims).Return(nil),
				)

				accessToken, refreshToken, err := service.IssueTokenPairWithClaims(ctx, testUserID, accessClaims, refreshClaims)
				Expect(err).NotTo(HaveOccurred())
				Expect(accessToken).NotTo(BeEmpty())
				Expect(refreshToken).NotTo(BeEmpty())
				Expect(accessToken).NotTo(Equal(refreshToken))
			})

			It("should embed access claims into the access token", func() {
				accessClaims := tokens.CustomClaims{"role": "editor", "tenant": "org-456"}
				mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)
				mockStore.EXPECT().Store(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				accessToken, _, err := service.IssueTokenPairWithClaims(ctx, testUserID, accessClaims, nil)
				Expect(err).NotTo(HaveOccurred())

				parsed := parseToken(accessToken)
				Expect(parsed.Custom["role"]).To(Equal("editor"))
				Expect(parsed.Custom["tenant"]).To(Equal("org-456"))
			})

			It("should pass refresh claims to the store", func() {
				refreshClaims := tokens.CustomClaims{"device_id": "device-001"}
				mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)
				mockStore.EXPECT().
					Store(gomock.Any(), gomock.Any(), testUserID, gomock.Any(), refreshClaims).
					Return(nil)

				service.IssueTokenPairWithClaims(ctx, testUserID, nil, refreshClaims)
			})

			It("should not override reserved claims in the access token", func() {
				accessClaims := tokens.CustomClaims{"sub": "hacker", "role": "admin"}
				mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)
				mockStore.EXPECT().Store(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				accessToken, _, err := service.IssueTokenPairWithClaims(ctx, testUserID, accessClaims, nil)
				Expect(err).NotTo(HaveOccurred())

				parsed, _ := jwt.ParseWithClaims(accessToken, &jwt.MapClaims{}, func(t *jwt.Token) (interface{}, error) {
					return &testKey.PublicKey, nil
				})
				claims := *parsed.Claims.(*jwt.MapClaims)
				Expect(claims["sub"]).To(Equal(testUserID))
				Expect(claims["role"]).To(Equal("admin"))
			})

			It("should behave like IssueTokenPair when both claims are nil", func() {
				mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)
				mockStore.EXPECT().Store(gomock.Any(), gomock.Any(), testUserID, gomock.Any(), nil).Return(nil)

				accessToken, refreshToken, err := service.IssueTokenPairWithClaims(ctx, testUserID, nil, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(accessToken).NotTo(BeEmpty())
				Expect(refreshToken).NotTo(BeEmpty())
			})

			It("should log token pair issuance", func() {
				mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)
				mockStore.EXPECT().Store(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				service.IssueTokenPairWithClaims(ctx, testUserID, nil, nil)

				Eventually(func() bool {
					return mockLogger.HasLog("info", "token pair with claims issued")
				}).Should(BeTrue())
			})
		})

		Context("when access token signing fails", func() {
			It("should not store refresh token", func() {
				mockKM.EXPECT().
					GetCurrentSigningKey(gomock.Any()).
					Return(nil, "", errors.New("key error"))

				mockStore.EXPECT().Store(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Times(0)

				_, _, err := service.IssueTokenPairWithClaims(ctx, testUserID, nil, nil)

				Expect(err).To(HaveOccurred())
			})
		})

		Context("when refresh token storage fails", func() {
			It("should return error", func() {
				mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)
				mockStore.EXPECT().
					Store(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
					Return(errors.New("storage error"))

				_, _, err := service.IssueTokenPairWithClaims(ctx, testUserID, nil, nil)

				Expect(err).To(HaveOccurred())
			})
		})

		Context("guard conditions", func() {
			It("should return ErrManagerNotRunning", func() {
				mgr := newTestManager(mockKM, mockStore, mockLogger)
				_, _, err := mgr.IssueTokenPairWithClaims(ctx, "user-123", nil, nil)
				Expect(err).To(Equal(tokens.ErrManagerNotRunning))
			})

			It("should return context error when context is cancelled", func() {
				cancelledCtx, cancel := context.WithCancel(ctx)
				cancel()
				_, _, err := service.IssueTokenPairWithClaims(cancelledCtx, "user-123", nil, nil)
				Expect(err).To(Equal(context.Canceled))
			})

			It("should return ErrInvalidUserID for whitespace-only userID", func() {
				_, _, err := service.IssueTokenPairWithClaims(ctx, "   ", nil, nil)
				Expect(err).To(Equal(tokens.ErrInvalidUserID))
			})
		})
	})

	// ========================================================================
	// ACCESS TOKEN VALIDATION
	// ========================================================================

	Describe("ValidationAccessToken", func() {
		var validToken string

		BeforeEach(func() {
			service = newTestManager(mockKM, mockStore, mockLogger)

			// Start service first (required before token operations)
			mockKM.EXPECT().Start(gomock.Any()).Return(nil)
			// Cleanup goroutine expects periodic cleanup calls
			mockStore.EXPECT().Cleanup(gomock.Any()).Return(0, nil).AnyTimes()
			err := service.Start(ctx)
			Expect(err).NotTo(HaveOccurred())

			// Then issue a valid token
			mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)
			validToken, _ = service.IssueAccessToken(ctx, testUserID)
		})

		Context("with valid token", func() {
			It("should validate successfully", func() {
				// Expect public key retrieval
				mockKM.EXPECT().GetPublicKey(gomock.Any(), testKeyID).
					Return(&testKey.PublicKey, nil).
					Times(1)

				claims, err := service.ValidateAccessToken(ctx, validToken)

				Expect(err).NotTo(HaveOccurred())
				Expect(claims).NotTo(BeNil())
				Expect(claims.Subject).To(Equal(testUserID))
			})

			It("should use KeyManager to get public key", func() {
				mockKM.EXPECT().
					GetPublicKey(gomock.Any(), gomock.Any()).
					Return(&testKey.PublicKey, nil).
					Times(1)

				service.ValidateAccessToken(ctx, validToken)
			})

			It("should verify correct key ID from header", func() {
				mockKM.EXPECT().
					GetPublicKey(gomock.Any(), testKeyID). // Exact key ID
					Return(&testKey.PublicKey, nil)

				service.ValidateAccessToken(ctx, validToken)
			})

			It("should log successful validation", func() {
				mockKM.EXPECT().GetPublicKey(gomock.Any(), gomock.Any()).Return(&testKey.PublicKey, nil)

				service.ValidateAccessToken(ctx, validToken)

				Eventually(func() bool {
					return mockLogger.HasLog("info", "access token validated")
				}).Should(BeTrue())
			})
		})

		Context("with invalid token format", func() {
			It("should return error for malformed token", func() {
				// Should not call KeyManager for invalid format
				mockKM.EXPECT().GetPublicKey(gomock.Any(), gomock.Any()).Times(0)

				_, err := service.ValidateAccessToken(ctx, "not-a-jwt-token")

				Expect(err).To(HaveOccurred())
				Expect(err).To(Equal(tokens.ErrInvalidToken))
			})

			It("should return error for empty token", func() {
				mockKM.EXPECT().GetPublicKey(gomock.Any(), gomock.Any()).Times(0)

				_, err := service.ValidateAccessToken(ctx, "")

				Expect(err).To(HaveOccurred())
				Expect(err).To(Equal(tokens.ErrInvalidToken))
			})

			It("should log validation failure", func() {
				service.ValidateAccessToken(ctx, "malformed")

				Eventually(func() bool {
					return mockLogger.HasLog("warn", "token parsing failed")
				}).Should(BeTrue())
			})
		})

		Context("with expired token", func() {
			It("should return error", func() {
				expiredToken := createExpiredToken(testKey, testKeyID, testUserID)

				mockKM.EXPECT().GetPublicKey(gomock.Any(), gomock.Any()).Return(&testKey.PublicKey, nil).AnyTimes()

				_, err := service.ValidateAccessToken(ctx, expiredToken)

				Expect(err).To(HaveOccurred())
				Expect(err).To(Equal(tokens.ErrTokenExpired))
			})

			It("should log expiration", func() {
				expiredToken := createExpiredToken(testKey, testKeyID, testUserID)
				mockKM.EXPECT().GetPublicKey(gomock.Any(), gomock.Any()).Return(&testKey.PublicKey, nil).AnyTimes()

				service.ValidateAccessToken(ctx, expiredToken)

				Eventually(func() bool {
					return mockLogger.HasLog("warn", "token expired")
				}).Should(BeTrue())
			})

		})

		Context("with clock skew leeway configured", func() {
			var leewayService *tokens.Manager

			BeforeEach(func() {
				config := tokens.TokenManagerConfig{
					KeyManager:          mockKM,
					RefreshStore:        mockStore,
					Logger:              mockLogger,
					AccessTokenDuration: 15 * time.Minute,
					CleanupInterval:     100 * time.Millisecond,
					Issuer:              "test-issuer",
					Audience:            []string{"test-audience"},
					ClockSkew:           30 * time.Second,
				}
				var err error
				leewayService, err = tokens.NewManager(config)
				Expect(err).NotTo(HaveOccurred())

				mockKM.EXPECT().Start(gomock.Any()).Return(nil)
				mockStore.EXPECT().Cleanup(gomock.Any()).Return(0, nil).AnyTimes()
				Expect(leewayService.Start(ctx)).To(Succeed())
			})

			AfterEach(func() {
				mockKM.EXPECT().Shutdown(gomock.Any()).Return(nil).AnyTimes()
				leewayService.Shutdown(context.Background())
			})

			It("should accept a token expired within the leeway window", func() {
				// Token expired 10 seconds ago — within the 30s leeway
				recentToken := createRecentlyExpiredToken(testKey, testKeyID, testUserID, 10*time.Second)
				mockKM.EXPECT().GetPublicKey(gomock.Any(), testKeyID).Return(&testKey.PublicKey, nil)

				_, err := leewayService.ValidateAccessToken(ctx, recentToken)

				Expect(err).NotTo(HaveOccurred())
			})

			It("should reject a token expired beyond the leeway window", func() {
				// Token expired 60 seconds ago — exceeds the 30s leeway
				oldToken := createRecentlyExpiredToken(testKey, testKeyID, testUserID, 60*time.Second)
				mockKM.EXPECT().GetPublicKey(gomock.Any(), testKeyID).Return(&testKey.PublicKey, nil)

				_, err := leewayService.ValidateAccessToken(ctx, oldToken)

				Expect(err).To(Equal(tokens.ErrTokenExpired))
			})

			It("should reject a token with zero clock skew that expired 10 seconds ago", func() {
				// Same token, but strict service (no leeway) must reject it
				recentToken := createRecentlyExpiredToken(testKey, testKeyID, testUserID, 10*time.Second)
				mockKM.EXPECT().GetPublicKey(gomock.Any(), testKeyID).Return(&testKey.PublicKey, nil)

				_, err := service.ValidateAccessToken(ctx, recentToken)

				Expect(err).To(Equal(tokens.ErrTokenExpired))
			})
		})

		// ======================================================================
		// ValidateAccessTokenWithClaims
		// ======================================================================

		Describe("ValidateAccessTokenWithClaims", func() {
			Context("with custom claims embedded at issuance", func() {
				It("should return custom claims alongside registered claims", func() {
					mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)
					customClaims := tokens.CustomClaims{
						"role":   "admin",
						"tenant": "org-123",
					}
					tokenStr, err := service.IssueAccessTokenWithClaims(ctx, testUserID, customClaims)
					Expect(err).NotTo(HaveOccurred())

					mockKM.EXPECT().GetPublicKey(gomock.Any(), testKeyID).Return(&testKey.PublicKey, nil)

					registered, custom, err := service.ValidateAccessTokenWithClaims(ctx, tokenStr)

					Expect(err).NotTo(HaveOccurred())
					Expect(registered).NotTo(BeNil())
					Expect(registered.Subject).To(Equal(testUserID))
					Expect(custom["role"]).To(Equal("admin"))
					Expect(custom["tenant"]).To(Equal("org-123"))
				})

				It("should exclude reserved claim keys from custom claims map", func() {
					mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)
					tokenStr, err := service.IssueAccessToken(ctx, testUserID)
					Expect(err).NotTo(HaveOccurred())

					mockKM.EXPECT().GetPublicKey(gomock.Any(), testKeyID).Return(&testKey.PublicKey, nil)

					_, custom, err := service.ValidateAccessTokenWithClaims(ctx, tokenStr)

					Expect(err).NotTo(HaveOccurred())
					for _, reserved := range []string{"sub", "exp", "nbf", "iat", "jti", "iss", "aud"} {
						Expect(custom).NotTo(HaveKey(reserved))
					}
				})

				It("should return empty map when no custom claims were embedded", func() {
					mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)
					tokenStr, err := service.IssueAccessToken(ctx, testUserID)
					Expect(err).NotTo(HaveOccurred())

					mockKM.EXPECT().GetPublicKey(gomock.Any(), testKeyID).Return(&testKey.PublicKey, nil)

					_, custom, err := service.ValidateAccessTokenWithClaims(ctx, tokenStr)

					Expect(err).NotTo(HaveOccurred())
					Expect(custom).NotTo(BeNil())
					Expect(custom).To(BeEmpty())
				})
			})

			Context("when validation fails", func() {
				It("should propagate errors from ValidateAccessToken", func() {
					_, _, err := service.ValidateAccessTokenWithClaims(ctx, "not-a-jwt")

					Expect(err).To(Equal(tokens.ErrInvalidToken))
				})

				It("should return nil claims and nil map on error", func() {
					registered, custom, err := service.ValidateAccessTokenWithClaims(ctx, "malformed")

					Expect(err).To(HaveOccurred())
					Expect(registered).To(BeNil())
					Expect(custom).To(BeNil())
				})
			})
		})

		Context("when public key retrieval fails", func() {
			It("should return error", func() {
				mockKM.EXPECT().
					GetPublicKey(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("key unavailable"))

				_, err := service.ValidateAccessToken(ctx, validToken)

				Expect(err).To(HaveOccurred())
			})

			It("should log error", func() {
				mockKM.EXPECT().
					GetPublicKey(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("key error"))

				service.ValidateAccessToken(ctx, validToken)

				Eventually(func() bool {
					return mockLogger.HasLog("error", "failed to get public key")
				}).Should(BeTrue())
			})
		})

		Context("with key not found", func() {
			It("should return ErrInvalidToken", func() {
				mockKM.EXPECT().
					GetPublicKey(gomock.Any(), gomock.Any()).
					Return(nil, keys.ErrKeyNotFound)

				_, err := service.ValidateAccessToken(ctx, validToken)

				Expect(err).To(Equal(tokens.ErrInvalidToken))
			})
		})

		Context("guard conditions", func() {
			It("should return ErrManagerNotRunning", func() {
				mgr := newTestManager(mockKM, mockStore, mockLogger)
				_, err := mgr.ValidateAccessToken(ctx, validToken)
				Expect(err).To(Equal(tokens.ErrManagerNotRunning))
			})

			It("should return context error when context is cancelled", func() {
				cancelledCtx, cancel := context.WithCancel(ctx)
				cancel()
				_, err := service.ValidateAccessToken(cancelledCtx, validToken)
				Expect(err).To(Equal(context.Canceled))
			})
		})

		Context("with wrong signing method", func() {
			It("should return ErrInvalidToken for HS256-signed token", func() {
				hs256Token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
					Subject:   "user-123",
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
				}).SignedString([]byte("secret"))
				_, err := service.ValidateAccessToken(ctx, hs256Token)
				Expect(err).To(Equal(tokens.ErrInvalidToken))
			})
		})

		Context("with missing kid header", func() {
			It("should return ErrInvalidToken", func() {
				token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.RegisteredClaims{
					Subject:   "user-123",
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
				})
				// kid deliberately NOT set
				signed, _ := token.SignedString(testKey)
				_, err := service.ValidateAccessToken(ctx, signed)
				Expect(err).To(Equal(tokens.ErrInvalidToken))
			})
		})

		Context("with issuer mismatch", func() {
			It("should return ErrInvalidIssuer", func() {
				mismatchToken := createTokenWithIssuer(testKey, testKeyID, "wrong-issuer")
				mockKM.EXPECT().GetPublicKey(gomock.Any(), testKeyID).Return(&testKey.PublicKey, nil)
				_, err := service.ValidateAccessToken(ctx, mismatchToken)
				Expect(err).To(Equal(tokens.ErrInvalidIssuer))
			})
		})

		Context("with audience mismatch", func() {
			It("should return ErrInvalidAudience", func() {
				mismatchToken := createTokenWithAudience(testKey, testKeyID, []string{"wrong-audience"})
				mockKM.EXPECT().GetPublicKey(gomock.Any(), testKeyID).Return(&testKey.PublicKey, nil)
				_, err := service.ValidateAccessToken(ctx, mismatchToken)
				Expect(err).To(Equal(tokens.ErrInvalidAudience))
			})
		})
	})

	Describe("RefreshAccessToken", func() {
		var validRefreshToken string

		BeforeEach(func() {
			service = newTestManager(mockKM, mockStore, mockLogger)

			// Start the service first (required before token operations)
			mockKM.EXPECT().Start(gomock.Any()).Return(nil)
			mockStore.EXPECT().Cleanup(gomock.Any()).Return(0, nil).AnyTimes()
			err := service.Start(ctx)
			Expect(err).NotTo(HaveOccurred())

			// Then issue a refresh token
			mockStore.EXPECT().Store(gomock.Any(), gomock.Any(), testUserID, gomock.Any(), gomock.Any()).Return(nil)
			validRefreshToken, _ = service.IssueRefreshToken(ctx, testUserID)
		})

		Context("with valid refresh token", func() {
			It("should issue new access token", func() {
				// Expect retrieval from store
				mockStore.EXPECT().
					Retrieve(gomock.Any(), validRefreshToken).
					Return(&storage.RefreshToken{
						TokenID:   validRefreshToken,
						UserID:    testUserID,
						Revoked:   false,
						ExpiresAt: time.Now().Add(24 * time.Hour),
					}, nil)

				// Expect new access token signed
				mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)

				accessToken, err := service.RefreshAccessToken(ctx, validRefreshToken)

				Expect(err).NotTo(HaveOccurred())
				Expect(accessToken).NotTo(BeEmpty())
			})

			It("should retrieve refresh token from store", func() {
				mockStore.EXPECT().
					Retrieve(gomock.Any(), validRefreshToken).
					Return(&storage.RefreshToken{UserID: testUserID, ExpiresAt: time.Now().Add(1 * time.Hour)}, nil).
					Times(1)

				mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)

				service.RefreshAccessToken(ctx, validRefreshToken)
			})

			It("should preserve user ID from refresh token", func() {
				mockStore.EXPECT().Retrieve(gomock.Any(), gomock.Any()).Return(&storage.RefreshToken{UserID: testUserID, ExpiresAt: time.Now().Add(1 * time.Hour)}, nil)
				mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)

				accessToken, _ := service.RefreshAccessToken(ctx, validRefreshToken)

				claims := parseToken(accessToken)
				Expect(claims.Subject).To(Equal(testUserID))
			})

			It("should log refresh operation", func() {
				mockStore.EXPECT().Retrieve(gomock.Any(), gomock.Any()).Return(&storage.RefreshToken{UserID: testUserID, ExpiresAt: time.Now().Add(1 * time.Hour)}, nil)
				mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)

				service.RefreshAccessToken(ctx, validRefreshToken)

				Eventually(func() bool {
					return mockLogger.HasLog("info", "access token refreshed")
				}).Should(BeTrue())
			})
		})

		Context("with invalid refresh token", func() {
			It("should return error for non-existent token", func() {
				mockStore.EXPECT().
					Retrieve(gomock.Any(), "non-existent-token").
					Return(nil, errors.New("token not found"))

				_, err := service.RefreshAccessToken(ctx, "non-existent-token")

				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError(tokens.ErrInvalidRefreshToken))
			})

			It("should return error for revoked token", func() {
				mockStore.EXPECT().
					Retrieve(gomock.Any(), validRefreshToken).
					Return(nil, storage.ErrTokenRevoked)

				_, err := service.RefreshAccessToken(ctx, validRefreshToken)

				Expect(err).To(HaveOccurred())
				Expect(err).To(MatchError(tokens.ErrTokenRevoked))
			})

			It("should return error for expired token", func() {
				mockStore.EXPECT().
					Retrieve(gomock.Any(), validRefreshToken).
					Return(&storage.RefreshToken{
						UserID:    testUserID,
						ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
					}, nil)

				mockStore.EXPECT().Revoke(gomock.Any(), validRefreshToken).Return(nil)
				_, err := service.RefreshAccessToken(ctx, validRefreshToken)

				Expect(err).To(HaveOccurred())
				Expect(err).To(Equal(tokens.ErrRefreshTokenExpired))
			})
		})

		Context("when IssueAccessToken fails", func() {
			It("should propagate the error", func() {
				mockStore.EXPECT().Retrieve(gomock.Any(), gomock.Any()).Return(&storage.RefreshToken{
					UserID: testUserID, ExpiresAt: time.Now().Add(time.Hour),
				}, nil)
				mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(nil, "", errors.New("key unavailable"))
				_, err := service.RefreshAccessToken(ctx, validRefreshToken)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("key unavailable"))
			})
		})

		Context("when storage retrieval fails", func() {
			It("should return error", func() {
				mockStore.EXPECT().
					Retrieve(gomock.Any(), gomock.Any()).
					Return(nil, errors.New("storage error"))

				_, err := service.RefreshAccessToken(ctx, validRefreshToken)

				Expect(err).To(HaveOccurred())
			})
		})

		Context("guard conditions", func() {
			It("should return ErrManagerNotRunning when manager is not running", func() {
				mgr := newTestManager(mockKM, mockStore, mockLogger)
				_, err := mgr.RefreshAccessToken(ctx, "any-token")
				Expect(err).To(Equal(tokens.ErrManagerNotRunning))
			})

			It("should return context error when context is cancelled", func() {
				cancelledCtx, cancel := context.WithCancel(ctx)
				cancel()
				_, err := service.RefreshAccessToken(cancelledCtx, "any-token")
				Expect(err).To(Equal(context.Canceled))
			})

			It("should return ErrInvalidRefreshToken for empty token", func() {
				_, err := service.RefreshAccessToken(ctx, "")
				Expect(err).To(Equal(tokens.ErrInvalidRefreshToken))
			})
		})
	})

	Describe("RefreshAccessTokenWithClaims", func() {
		var validRefreshToken string

		BeforeEach(func() {
			service = newTestManager(mockKM, mockStore, mockLogger)

			mockKM.EXPECT().Start(gomock.Any()).Return(nil)
			mockStore.EXPECT().Cleanup(gomock.Any()).Return(0, nil).AnyTimes()
			err := service.Start(ctx)
			Expect(err).NotTo(HaveOccurred())

			mockStore.EXPECT().Store(gomock.Any(), gomock.Any(), testUserID, gomock.Any(), gomock.Any()).Return(nil)
			validRefreshToken, _ = service.IssueRefreshToken(ctx, testUserID)
		})

		Context("with valid refresh token and claims", func() {
			It("should issue new access token with claims embedded", func() {
				claims := tokens.CustomClaims{"role": "admin", "tenant": "org-123"}

				mockStore.EXPECT().
					Retrieve(gomock.Any(), validRefreshToken).
					Return(&storage.RefreshToken{
						TokenID:   validRefreshToken,
						UserID:    testUserID,
						ExpiresAt: time.Now().Add(time.Hour),
					}, nil)
				mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)

				accessToken, err := service.RefreshAccessTokenWithClaims(ctx, validRefreshToken, claims)
				Expect(err).NotTo(HaveOccurred())
				Expect(accessToken).NotTo(BeEmpty())

				parsed := parseToken(accessToken)
				Expect(parsed.Subject).To(Equal(testUserID))
				Expect(parsed.Custom["role"]).To(Equal("admin"))
				Expect(parsed.Custom["tenant"]).To(Equal("org-123"))
			})

			It("should behave like RefreshAccessToken when claims are nil", func() {
				mockStore.EXPECT().
					Retrieve(gomock.Any(), validRefreshToken).
					Return(&storage.RefreshToken{
						TokenID:   validRefreshToken,
						UserID:    testUserID,
						ExpiresAt: time.Now().Add(time.Hour),
					}, nil)
				mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)

				accessToken, err := service.RefreshAccessTokenWithClaims(ctx, validRefreshToken, nil)
				Expect(err).NotTo(HaveOccurred())
				Expect(accessToken).NotTo(BeEmpty())

				parsed := parseToken(accessToken)
				Expect(parsed.Subject).To(Equal(testUserID))
			})

			It("should log access token refreshed with claims", func() {
				mockStore.EXPECT().Retrieve(gomock.Any(), gomock.Any()).Return(&storage.RefreshToken{
					UserID:    testUserID,
					ExpiresAt: time.Now().Add(time.Hour),
				}, nil)
				mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)

				service.RefreshAccessTokenWithClaims(ctx, validRefreshToken, nil)

				Eventually(func() bool {
					return mockLogger.HasLog("info", "access token refreshed with claims")
				}).Should(BeTrue())
			})
		})

		Context("with invalid refresh token", func() {
			It("should return error for non-existent token", func() {
				mockStore.EXPECT().
					Retrieve(gomock.Any(), "non-existent-token").
					Return(nil, errors.New("token not found"))

				_, err := service.RefreshAccessTokenWithClaims(ctx, "non-existent-token", nil)

				Expect(err).To(MatchError(tokens.ErrInvalidRefreshToken))
			})

			It("should return error for revoked token", func() {
				mockStore.EXPECT().
					Retrieve(gomock.Any(), validRefreshToken).
					Return(nil, storage.ErrTokenRevoked)

				_, err := service.RefreshAccessTokenWithClaims(ctx, validRefreshToken, nil)

				Expect(err).To(MatchError(tokens.ErrTokenRevoked))
			})

			It("should return error for expired token", func() {
				mockStore.EXPECT().
					Retrieve(gomock.Any(), validRefreshToken).
					Return(&storage.RefreshToken{
						UserID:    testUserID,
						ExpiresAt: time.Now().Add(-time.Hour),
					}, nil)
				mockStore.EXPECT().Revoke(gomock.Any(), validRefreshToken).Return(nil)

				_, err := service.RefreshAccessTokenWithClaims(ctx, validRefreshToken, nil)

				Expect(err).To(Equal(tokens.ErrRefreshTokenExpired))
			})
		})

		Context("when IssueAccessTokenWithClaims fails", func() {
			It("should propagate the error", func() {
				mockStore.EXPECT().Retrieve(gomock.Any(), gomock.Any()).Return(&storage.RefreshToken{
					UserID: testUserID, ExpiresAt: time.Now().Add(time.Hour),
				}, nil)
				mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(nil, "", errors.New("key unavailable"))

				_, err := service.RefreshAccessTokenWithClaims(ctx, validRefreshToken, nil)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring("key unavailable"))
			})
		})

		Context("guard conditions", func() {
			It("should return ErrManagerNotRunning when manager is not running", func() {
				mgr := newTestManager(mockKM, mockStore, mockLogger)
				_, err := mgr.RefreshAccessTokenWithClaims(ctx, "any-token", nil)
				Expect(err).To(Equal(tokens.ErrManagerNotRunning))
			})

			It("should return context error when context is cancelled", func() {
				cancelledCtx, cancel := context.WithCancel(ctx)
				cancel()
				_, err := service.RefreshAccessTokenWithClaims(cancelledCtx, "any-token", nil)
				Expect(err).To(Equal(context.Canceled))
			})

			It("should return ErrInvalidRefreshToken for empty token", func() {
				_, err := service.RefreshAccessTokenWithClaims(ctx, "", nil)
				Expect(err).To(Equal(tokens.ErrInvalidRefreshToken))
			})
		})
	})

	// ========================================================================
	// TOKEN REVOCATION
	// ========================================================================

	Describe("RevokeRefreshToken", func() {
		BeforeEach(func() {
			service = newTestManager(mockKM, mockStore, mockLogger)

			// Start the service first (required before token operations)
			mockKM.EXPECT().Start(gomock.Any()).Return(nil)
			mockStore.EXPECT().Cleanup(gomock.Any()).Return(0, nil).AnyTimes()
			err := service.Start(ctx)
			Expect(err).NotTo(HaveOccurred())
		})

		Context("with valid token ID", func() {
			It("should revoke token successfully", func() {
				mockStore.EXPECT().
					Revoke(gomock.Any(), testTokenID).
					Return(nil).
					Times(1)

				err := service.RevokeRefreshToken(ctx, testTokenID)

				Expect(err).NotTo(HaveOccurred())
			})

			It("should call store revoke", func() {
				mockStore.EXPECT().
					Revoke(gomock.Any(), testTokenID).
					Return(nil).
					Times(1)

				service.RevokeRefreshToken(ctx, testTokenID)
			})

			It("should log revocation", func() {
				mockStore.EXPECT().Revoke(gomock.Any(), gomock.Any()).Return(nil)

				service.RevokeRefreshToken(ctx, testTokenID)

				Eventually(func() bool {
					return mockLogger.HasLog("info", "refresh token revoked")
				}).Should(BeTrue())
			})
		})

		Context("with non-existent token", func() {
			It("should return error", func() {
				mockStore.EXPECT().
					Revoke(gomock.Any(), "non-existent").
					Return(errors.New("token not found"))

				err := service.RevokeRefreshToken(ctx, "non-existent")

				Expect(err).To(HaveOccurred())
			})
		})

		Context("when storage revocation fails", func() {
			It("should return error", func() {
				mockStore.EXPECT().
					Revoke(gomock.Any(), gomock.Any()).
					Return(errors.New("revocation failed"))

				err := service.RevokeRefreshToken(ctx, testTokenID)

				Expect(err).To(HaveOccurred())
			})

			It("should log error", func() {
				mockStore.EXPECT().
					Revoke(gomock.Any(), gomock.Any()).
					Return(errors.New("error"))

				service.RevokeRefreshToken(ctx, testTokenID)

				Eventually(func() bool {
					return mockLogger.HasLog("error", "failed to revoke refresh token")
				}).Should(BeTrue())
			})
		})

		Context("guard conditions", func() {
			It("should return ErrManagerNotRunning when manager is not running", func() {
				mgr := newTestManager(mockKM, mockStore, mockLogger)
				err := mgr.RevokeRefreshToken(ctx, "any-token")
				Expect(err).To(Equal(tokens.ErrManagerNotRunning))
			})

			It("should return context error when context is cancelled", func() {
				cancelledCtx, cancel := context.WithCancel(ctx)
				cancel()
				err := service.RevokeRefreshToken(cancelledCtx, "any-token")
				Expect(err).To(Equal(context.Canceled))
			})

			It("should return ErrInvalidRefreshToken for empty tokenID", func() {
				err := service.RevokeRefreshToken(ctx, "")
				Expect(err).To(Equal(tokens.ErrInvalidRefreshToken))
			})
		})
	})

	Describe("RevokeAllUserTokens", func() {
		BeforeEach(func() {
			service = newTestManager(mockKM, mockStore, mockLogger)

			// Start the service first (required before token operations)
			mockKM.EXPECT().Start(gomock.Any()).Return(nil)
			mockStore.EXPECT().Cleanup(gomock.Any()).Return(0, nil).AnyTimes()
			err := service.Start(ctx)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should revoke all tokens for user", func() {
			mockStore.EXPECT().
				RevokeAllForUser(gomock.Any(), testUserID).
				Return(nil).
				Times(1)

			err := service.RevokeAllUserTokens(ctx, testUserID)

			Expect(err).NotTo(HaveOccurred())
		})

		It("should log bulk revocation", func() {
			mockStore.EXPECT().RevokeAllForUser(gomock.Any(), gomock.Any()).Return(nil)

			service.RevokeAllUserTokens(ctx, testUserID)

			Eventually(func() bool {
				return mockLogger.HasLog("info", "all refresh tokens revoked for user")
			}).Should(BeTrue())
		})

		It("should return wrapped error when store fails", func() {
			mockStore.EXPECT().RevokeAllForUser(gomock.Any(), "user-123").Return(errors.New("db error"))
			err := service.RevokeAllUserTokens(ctx, "user-123")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("db error"))
		})

		Context("guard conditions", func() {
			It("should return ErrManagerNotRunning when manager is not running", func() {
				mgr := newTestManager(mockKM, mockStore, mockLogger)
				err := mgr.RevokeAllUserTokens(ctx, "user-123")
				Expect(err).To(Equal(tokens.ErrManagerNotRunning))
			})

			It("should return context error when context is cancelled", func() {
				cancelledCtx, cancel := context.WithCancel(ctx)
				cancel()
				err := service.RevokeAllUserTokens(cancelledCtx, "user-123")
				Expect(err).To(Equal(context.Canceled))
			})

			It("should return ErrInvalidUserID for empty userID", func() {
				err := service.RevokeAllUserTokens(ctx, "")
				Expect(err).To(Equal(tokens.ErrInvalidUserID))
			})
		})
	})

	// ==================
	// TOKEN INTROSPECTION
	// ===================

	Describe("IntrospectToken", func() {
		var refreshToken string

		BeforeEach(func() {
			service = newTestManager(mockKM, mockStore, mockLogger)

			// Start the service first (required before token operations)
			mockKM.EXPECT().Start(gomock.Any()).Return(nil)
			Expect(service.Start(ctx)).To(Succeed())

			mockStore.EXPECT().Store(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			refreshToken, _ = service.IssueRefreshToken(ctx, testUserID)
		})

		Context("with valid refresh token", func() {
			It("should return token metadata", func() {
				mockStore.EXPECT().Retrieve(gomock.Any(), refreshToken).Return(&storage.RefreshToken{
					UserID:    testUserID,
					ExpiresAt: time.Now().Add(1 * time.Hour),
					CreatedAt: time.Now(),
					Revoked:   false,
				}, nil)

				metadata, err := service.IntrospectToken(ctx, refreshToken)

				Expect(err).NotTo(HaveOccurred())
				Expect(metadata.Active).To(BeTrue())
				Expect(metadata.Subject).To(Equal(testUserID))
				Expect(metadata.TokenType).To(Equal("refresh_token"))
			})

			It("should include expiration info", func() {
				mockStore.EXPECT().Retrieve(gomock.Any(), refreshToken).Return(&storage.RefreshToken{
					UserID:    testUserID,
					ExpiresAt: time.Now().Add(1 * time.Hour),
					CreatedAt: time.Now(),
					Revoked:   false,
				}, nil)

				metadata, _ := service.IntrospectToken(ctx, refreshToken)

				Expect(metadata.ExpiresAt).To(BeTemporally(">", time.Now()))
				Expect(metadata.IssuedAt).To(BeTemporally("<=", time.Now()))
			})
		})

		Context("with expired token", func() {
			It("should return inactive status", func() {
				mockStore.EXPECT().Retrieve(gomock.Any(), refreshToken).Return(&storage.RefreshToken{
					UserID:    testUserID,
					ExpiresAt: time.Now().Add(-1 * time.Hour),
					CreatedAt: time.Now().Add(-25 * time.Hour),
					Revoked:   false,
				}, nil)

				metadata, err := service.IntrospectToken(ctx, refreshToken)

				Expect(err).NotTo(HaveOccurred())
				Expect(metadata.Active).To(BeFalse())
			})
		})

		Context("with invalid token", func() {
			It("should return inactive with no error", func() {
				mockStore.EXPECT().Retrieve(gomock.Any(), "invalid-token").Return(nil, errors.New("token not found"))

				metadata, err := service.IntrospectToken(ctx, "invalid-token")

				Expect(err).NotTo(HaveOccurred())
				Expect(metadata.Active).To(BeFalse())
				Expect(metadata.Subject).To(BeEmpty())
			})
		})

		Context("with revoked token", func() {
			It("should return inactive status", func() {
				mockStore.EXPECT().Retrieve(gomock.Any(), refreshToken).Return(&storage.RefreshToken{
					UserID:    testUserID,
					ExpiresAt: time.Now().Add(1 * time.Hour),
					CreatedAt: time.Now(),
					Revoked:   true,
				}, nil)

				metadata, err := service.IntrospectToken(ctx, refreshToken)

				Expect(err).NotTo(HaveOccurred())
				Expect(metadata.Active).To(BeFalse())
				Expect(metadata.Subject).To(Equal(testUserID))
			})
		})

		Context("with empty token", func() {
			It("should return error", func() {
				_, err := service.IntrospectToken(ctx, "")

				Expect(err).To(MatchError(tokens.ErrInvalidRefreshToken))
			})
		})

		Context("when service is not running", func() {
			It("should return error", func() {
				stoppedService := newTestManager(mockKM, mockStore, mockLogger)

				_, err := stoppedService.IntrospectToken(ctx, refreshToken)

				Expect(err).To(MatchError(tokens.ErrManagerNotRunning))
			})
		})

		Context("when context is cancelled", func() {
			It("should return context error", func() {
				cancelledCtx, cancel := context.WithCancel(ctx)
				cancel()

				_, err := service.IntrospectToken(cancelledCtx, refreshToken)

				Expect(err).To(MatchError(context.Canceled))
			})
		})
	})

	// ===========
	// CLEANUP & MAINTENANCE
	// ===========

	Describe("CleanupExpiredTokens", func() {
		BeforeEach(func() {
			service = newTestManager(mockKM, mockStore, mockLogger)
			// Start the service first (required before token operations)
			mockKM.EXPECT().Start(gomock.Any()).Return(nil)
			Expect(service.Start(ctx)).To(Succeed())
		})

		It("should cleanup expired tokens", func() {
			mockStore.EXPECT().
				Cleanup(gomock.Any()).
				Return(5, nil). // 5 tokens deleted
				Times(1)

			count, err := service.CleanupExpiredTokens(ctx)

			Expect(err).NotTo(HaveOccurred())
			Expect(count).To(Equal(5))
		})

		It("should log cleanup operation", func() {
			mockStore.EXPECT().Cleanup(gomock.Any()).Return(2, nil)

			service.CleanupExpiredTokens(ctx)

			Eventually(func() bool {
				return mockLogger.HasLog("info", "expired tokens cleaned up")
			}).Should(BeTrue())
		})

		It("should call store cleanup", func() {
			mockStore.EXPECT().
				Cleanup(gomock.Any()).
				Return(0, nil).
				Times(1)

			service.CleanupExpiredTokens(ctx)
		})

		Context("when cleanup fails", func() {
			It("should return error", func() {
				mockStore.EXPECT().
					Cleanup(gomock.Any()).
					Return(0, errors.New("cleanup failed"))

				_, err := service.CleanupExpiredTokens(ctx)

				Expect(err).To(HaveOccurred())
			})
		})

		Context("when service is not running", func() {
			It("should return error", func() {
				stoppedService := newTestManager(mockKM, mockStore, mockLogger)

				_, err := stoppedService.CleanupExpiredTokens(ctx)

				Expect(err).To(MatchError(tokens.ErrManagerNotRunning))
			})
		})

		Context("when context is cancelled", func() {
			It("should return context error", func() {
				cancelledCtx, cancel := context.WithCancel(ctx)
				cancel()

				_, err := service.CleanupExpiredTokens(cancelledCtx)

				Expect(err).To(MatchError(context.Canceled))
			})
		})
	})

	// ========================================================================
	// CONCURRENT OPERATIONS
	// ========================================================================

	// NOTE: These tests verify concurrent access does not cause panics or data races.
	// Run with the race detector for full coverage: ginkgo --race ./pkg/tokens/
	// TODO: Add concurrent lifecycle tests (Start/Shutdown races) when lifecycle work is complete.
	Describe("Concurrent Operations", func() {
		BeforeEach(func() {
			service = newTestManager(mockKM, mockStore, mockLogger)
			mockKM.EXPECT().Start(gomock.Any()).Return(nil)
			Expect(service.Start(ctx)).To(Succeed())
		})

		It("should handle concurrent token issuance", func() {
			// Allow many concurrent calls
			mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil).Times(10)

			done := make(chan bool, 10)

			for i := 0; i < 10; i++ {
				go func(id int) {
					defer GinkgoRecover()
					userID := testUserID + "-" + fmt.Sprintf("%d", id)
					_, err := service.IssueAccessToken(ctx, userID)
					Expect(err).NotTo(HaveOccurred())
					done <- true
				}(i)
			}

			for i := 0; i < 10; i++ {
				Eventually(done).Should(Receive())
			}
		})

		It("should handle concurrent validation", func() {
			// Issue token first (service is running from BeforeEach)
			mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)
			token, err := service.IssueAccessToken(ctx, testUserID)
			Expect(err).NotTo(HaveOccurred())

			// Allow many concurrent validations
			mockKM.EXPECT().GetPublicKey(gomock.Any(), gomock.Any()).Return(&testKey.PublicKey, nil).Times(10)

			done := make(chan bool, 10)

			for i := 0; i < 10; i++ {
				go func() {
					defer GinkgoRecover()
					_, err := service.ValidateAccessToken(ctx, token)
					Expect(err).NotTo(HaveOccurred())
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

var testPublicKey *rsa.PublicKey

func getTestPublicKey(kid string) (*rsa.PublicKey, error) {
	if testPublicKey == nil {
		return nil, errors.New("test public key not initialized")
	}
	return testPublicKey, nil
}

func createTokenWithIssuer(key *rsa.PrivateKey, keyID, issuer string) string {
	claims := jwt.RegisteredClaims{
		Subject:   "user-123",
		Issuer:    issuer,
		Audience:  jwt.ClaimStrings{"test-audience"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID
	signed, _ := token.SignedString(key)
	return signed
}

func createTokenWithAudience(key *rsa.PrivateKey, keyID string, audience []string) string {
	claims := jwt.RegisteredClaims{
		Subject:   "user-123",
		Issuer:    "test-issuer",
		Audience:  jwt.ClaimStrings(audience),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID
	signed, _ := token.SignedString(key)
	return signed
}

// createRecentlyExpiredToken creates a token that expired the given duration ago.
func createRecentlyExpiredToken(key *rsa.PrivateKey, keyID, userID string, expiredAgo time.Duration) string {
	now := time.Now()
	expiresAt := now.Add(-expiredAgo)

	claims := jwt.RegisteredClaims{
		Subject:   userID,
		Issuer:    "test-issuer",
		Audience:  jwt.ClaimStrings{"test-audience"},
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		IssuedAt:  jwt.NewNumericDate(now.Add(-expiredAgo - time.Minute)),
		NotBefore: jwt.NewNumericDate(now.Add(-expiredAgo - time.Minute)),
		ID:        "test-recently-expired-jti",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID

	signedToken, err := token.SignedString(key)
	if err != nil {
		return ""
	}

	return signedToken
}

// ============================================================================
// Phase N: Tracing
// ============================================================================

var _ = Describe("TokenManager — Phase N: Tracing", func() {
	var (
		ctrl       *gomock.Controller
		mockTracer *testutil.MockTracer
		setupSpan  *testutil.MockSpan
		testSpan   *testutil.MockSpan
		mockKM     *testutil.MockKeyManager
		mockStore  *testutil.MockRefreshStore
		manager    *tokens.Manager
		ctx        context.Context
		testKey    *rsa.PrivateKey
		testKeyID  string
	)

	newTracingManager := func() {
		var err error
		testKey, err = rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		testKeyID = "tracing-key-id"

		manager, err = tokens.NewManager(tokens.TokenManagerConfig{
			KeyManager:           mockKM,
			RefreshStore:         mockStore,
			Tracer:               mockTracer,
			AccessTokenDuration:  15 * time.Minute,
			RefreshTokenDuration: 30 * 24 * time.Hour,
			CleanupInterval:      100 * time.Millisecond,
			Issuer:               "test-issuer",
			Audience:             []string{"test-audience"},
		})
		Expect(err).NotTo(HaveOccurred())

		// Route Start/Shutdown spans to setupSpan; all other spans go to testSpan.
		mockTracer.EXPECT().Start(gomock.Any(), gomock.Eq("TokenManager.Start"), gomock.Any()).Return(ctx, setupSpan).AnyTimes()
		mockTracer.EXPECT().Start(gomock.Any(), gomock.Eq("TokenManager.Shutdown"), gomock.Any()).Return(ctx, setupSpan).AnyTimes()
		setupSpan.EXPECT().End().AnyTimes()
		setupSpan.EXPECT().SetAttribute(gomock.Any(), gomock.Any()).AnyTimes()
		setupSpan.EXPECT().SetStatus(gomock.Any(), gomock.Any()).AnyTimes()
		setupSpan.EXPECT().RecordError(gomock.Any()).AnyTimes()

		mockKM.EXPECT().Start(gomock.Any()).Return(nil)
		Expect(manager.Start(ctx)).To(Succeed())
	}

	BeforeEach(func() {
		ctx = context.Background()
		ctrl = gomock.NewController(GinkgoT())
		mockTracer = testutil.NewMockTracer(ctrl)
		setupSpan = testutil.NewMockSpan(ctrl)
		testSpan = testutil.NewMockSpan(ctrl)
		mockKM = testutil.NewMockKeyManager(ctrl)
		mockStore = testutil.NewMockRefreshStore(ctrl)
	})

	AfterEach(func() {
		if manager != nil && manager.IsRunning() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			mockKM.EXPECT().Shutdown(gomock.Any()).Return(nil).AnyTimes()
			_ = manager.Shutdown(shutdownCtx)
		}
		ctrl.Finish()
	})

	Context("IssueAccessToken — success path", func() {
		It("should start a span named TokenManager.IssueAccessToken with user_id and StatusOK", func() {
			newTracingManager()

			mockTracer.EXPECT().Start(gomock.Any(), gomock.Eq("TokenManager.IssueAccessToken"), gomock.Any()).Return(ctx, testSpan)
			testSpan.EXPECT().SetAttribute("user_id", "tracing-user")
			testSpan.EXPECT().SetAttribute("token_id", gomock.Any())
			testSpan.EXPECT().SetStatus(tracing.StatusOK, "")
			testSpan.EXPECT().End()

			mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)
			_, err := manager.IssueAccessToken(ctx, "tracing-user")
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("IssueAccessToken — error path (not running)", func() {
		It("should call RecordError and StatusError when service is not running", func() {
			newTracingManager()

			// Stop the manager first; AfterEach will see it stopped and skip.
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			mockKM.EXPECT().Shutdown(gomock.Any()).Return(nil)
			Expect(manager.Shutdown(shutdownCtx)).To(Succeed())

			mockTracer.EXPECT().Start(gomock.Any(), gomock.Eq("TokenManager.IssueAccessToken"), gomock.Any()).Return(ctx, testSpan)
			testSpan.EXPECT().SetAttribute("user_id", "stopped-user")
			testSpan.EXPECT().RecordError(tokens.ErrManagerNotRunning)
			testSpan.EXPECT().SetStatus(tracing.StatusError, gomock.Any())
			testSpan.EXPECT().End()

			_, err := manager.IssueAccessToken(ctx, "stopped-user")
			Expect(err).To(MatchError(tokens.ErrManagerNotRunning))
		})
	})

	Context("RefreshAccessToken — success path", func() {
		It("should start a span with token_id attribute and StatusOK", func() {
			newTracingManager()

			refreshTok := "refresh-token-xyz"
			record := &storage.RefreshToken{
				TokenID:   refreshTok,
				UserID:    "refresh-user",
				ExpiresAt: time.Now().Add(time.Hour),
				Revoked:   false,
			}
			mockStore.EXPECT().Retrieve(gomock.Any(), refreshTok).Return(record, nil)
			mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)

			mockTracer.EXPECT().Start(gomock.Any(), gomock.Eq("TokenManager.RefreshAccessToken"), gomock.Any()).Return(ctx, testSpan)
			// IssueAccessToken is called internally — route to setupSpan to avoid expectation conflicts.
			mockTracer.EXPECT().Start(gomock.Any(), gomock.Eq("TokenManager.IssueAccessToken"), gomock.Any()).Return(ctx, setupSpan)
			testSpan.EXPECT().SetAttribute("token_id", refreshTok)
			testSpan.EXPECT().SetStatus(tracing.StatusOK, "")
			testSpan.EXPECT().End()

			_, err := manager.RefreshAccessToken(ctx, refreshTok)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("ValidateAccessToken — error path", func() {
		It("should call RecordError and StatusError for an invalid token", func() {
			newTracingManager()

			mockTracer.EXPECT().Start(gomock.Any(), gomock.Eq("TokenManager.ValidateAccessToken"), gomock.Any()).Return(ctx, testSpan)
			testSpan.EXPECT().RecordError(tokens.ErrInvalidToken)
			testSpan.EXPECT().SetStatus(tracing.StatusError, gomock.Any())
			testSpan.EXPECT().End()

			_, err := manager.ValidateAccessToken(ctx, "not-a-valid-jwt")
			Expect(err).To(MatchError(tokens.ErrInvalidToken))
		})
	})

	Context("IssueTokenPairWithClaims — success path", func() {
		It("should start a span with user_id and token_id attributes and StatusOK", func() {
			newTracingManager()

			mockTracer.EXPECT().Start(gomock.Any(), gomock.Eq("TokenManager.IssueTokenPairWithClaims"), gomock.Any()).Return(ctx, testSpan)
			testSpan.EXPECT().SetAttribute("user_id", "tracing-user")
			testSpan.EXPECT().SetAttribute("token_id", gomock.Any())
			testSpan.EXPECT().SetStatus(tracing.StatusOK, "")
			testSpan.EXPECT().End()

			mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)
			mockStore.EXPECT().Store(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

			_, _, err := manager.IssueTokenPairWithClaims(ctx, "tracing-user", nil, nil)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("IssueTokenPairWithClaims — error path (not running)", func() {
		It("should call RecordError and StatusError when service is not running", func() {
			newTracingManager()

			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			mockKM.EXPECT().Shutdown(gomock.Any()).Return(nil)
			Expect(manager.Shutdown(shutdownCtx)).To(Succeed())

			mockTracer.EXPECT().Start(gomock.Any(), gomock.Eq("TokenManager.IssueTokenPairWithClaims"), gomock.Any()).Return(ctx, testSpan)
			testSpan.EXPECT().SetAttribute("user_id", "stopped-user")
			testSpan.EXPECT().RecordError(tokens.ErrManagerNotRunning)
			testSpan.EXPECT().SetStatus(tracing.StatusError, gomock.Any())
			testSpan.EXPECT().End()

			_, _, err := manager.IssueTokenPairWithClaims(ctx, "stopped-user", nil, nil)
			Expect(err).To(MatchError(tokens.ErrManagerNotRunning))
		})
	})

	Context("RefreshAccessTokenWithClaims — success path", func() {
		It("should start a span with token_id attribute and StatusOK", func() {
			newTracingManager()

			refreshTok := "refresh-claims-xyz"
			record := &storage.RefreshToken{
				TokenID:   refreshTok,
				UserID:    "refresh-claims-user",
				ExpiresAt: time.Now().Add(time.Hour),
				Revoked:   false,
			}
			mockStore.EXPECT().Retrieve(gomock.Any(), refreshTok).Return(record, nil)
			mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)

			mockTracer.EXPECT().Start(gomock.Any(), gomock.Eq("TokenManager.RefreshAccessTokenWithClaims"), gomock.Any()).Return(ctx, testSpan)
			// IssueAccessTokenWithClaims is called internally — route to setupSpan to avoid expectation conflicts.
			mockTracer.EXPECT().Start(gomock.Any(), gomock.Eq("TokenManager.IssueAccessTokenWithClaims"), gomock.Any()).Return(ctx, setupSpan)
			testSpan.EXPECT().SetAttribute("token_id", refreshTok)
			testSpan.EXPECT().SetStatus(tracing.StatusOK, "")
			testSpan.EXPECT().End()

			_, err := manager.RefreshAccessTokenWithClaims(ctx, refreshTok, nil)
			Expect(err).NotTo(HaveOccurred())
		})
	})

	Context("RefreshAccessTokenWithClaims — error path (not running)", func() {
		It("should call RecordError and StatusError when service is not running", func() {
			newTracingManager()

			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			mockKM.EXPECT().Shutdown(gomock.Any()).Return(nil)
			Expect(manager.Shutdown(shutdownCtx)).To(Succeed())

			mockTracer.EXPECT().Start(gomock.Any(), gomock.Eq("TokenManager.RefreshAccessTokenWithClaims"), gomock.Any()).Return(ctx, testSpan)
			testSpan.EXPECT().RecordError(tokens.ErrManagerNotRunning)
			testSpan.EXPECT().SetStatus(tracing.StatusError, gomock.Any())
			testSpan.EXPECT().End()

			_, err := manager.RefreshAccessTokenWithClaims(ctx, "any-token", nil)
			Expect(err).To(MatchError(tokens.ErrManagerNotRunning))
		})
	})
})

func createExpiredToken(key *rsa.PrivateKey, keyID, userID string) string {
	// Create a token with past expiration
	now := time.Now()
	expiresAt := now.Add(-1 * time.Hour) // Expired 1 hour ago

	claims := jwt.RegisteredClaims{
		Subject:   userID,
		Issuer:    "test-issuer",
		Audience:  jwt.ClaimStrings{"test-audience"},
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		ID:        "test-expired-jti",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID

	signedToken, err := token.SignedString(key)
	if err != nil {
		return ""
	}

	return signedToken
}
