package tokens_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
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
		cancel()
		/*if service != nil && service.IsRunning() {
			service.Shutdown(ctx)
		}*/
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
// ⚠️ ONLY USE IN TESTS! Never in production!
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
