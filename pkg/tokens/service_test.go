package tokens_test

import (
	"testing"

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
		ctrl *gomock.Controller
		//service     *tokens.Service
		mockKM     *testutil.MockKeyManager
		mockStore  *testutil.MockRefreshStore
		mockRL     *testutil.MockRateLimiter
		mockLogger *testutil.MockLogger
		/*ctx         context.Context
		cancel      context.CancelFunc
		testUserID  string
		testTokenID string
		testKey     *rsa.PrivateKey
		testKeyID   string*/
	)

	BeforeEach(func() {
		// Create gomock controller
		ctrl = gomock.NewController(GinkgoT())

		/*ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		testUserID = "user-12345"
		testTokenID = "token-67890"

		// Generate test RSA key
		testKey, _ = rsa.GenerateKey(rand.Reader, 2048)
		testKeyID = "test-key-id-123"*/

		// Create mocks using gomock (auto-generated)
		mockKM = testutil.NewMockKeyManager(ctrl)
		mockStore = testutil.NewMockRefreshStore(ctrl)
		mockRL = testutil.NewMockRateLimiter(ctrl)
		mockLogger = testutil.NewMockLogger() // Manual mock (for now)
	})
	/*
			AfterEach(func() {
				cancel()
				if service != nil && service.IsRunning() {
					service.Shutdown(ctx)
				}
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
		}*/

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
})
