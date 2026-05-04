package tokens_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"github.com/aetomala/jwtauth/internal/testutil"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/aetomala/jwtauth/pkg/tokens"
)

var _ = Describe("TokenManager Metrics", func() {
	var (
		ctrl      *gomock.Controller
		mockKM    *testutil.MockKeyManager
		mockStore *testutil.MockRefreshStore
		mockM     *testutil.MockMetrics
		service   *tokens.Manager
		ctx       context.Context
		cancel    context.CancelFunc
		testKey   *rsa.PrivateKey
		testKeyID string
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)

		var err error
		testKey, err = rsa.GenerateKey(rand.Reader, 2048)
		Expect(err).NotTo(HaveOccurred())
		testKeyID = "test-key-id"

		mockKM = testutil.NewMockKeyManager(ctrl)
		mockStore = testutil.NewMockRefreshStore(ctrl)
		mockM = testutil.NewMockMetrics(ctrl)

		service, err = tokens.NewManager(tokens.TokenManagerConfig{
			KeyManager:           mockKM,
			RefreshStore:         mockStore,
			Metrics:              mockM,
			AccessTokenDuration:  15 * time.Minute,
			RefreshTokenDuration: 30 * 24 * time.Hour,
			CleanupInterval:      100 * time.Millisecond,
		})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		if service != nil && service.IsRunning() {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer shutdownCancel()
			mockKM.EXPECT().Shutdown(gomock.Any()).Return(nil).AnyTimes()
			mockM.EXPECT().SetGauge(gomock.Any(), gomock.Any(), gomock.Any()).AnyTimes()
			service.Shutdown(shutdownCtx) //nolint:errcheck
		}
		cancel()
		ctrl.Finish()
	})

	// startService starts the service and expects the correct Start metrics.
	startService := func() {
		mockKM.EXPECT().Start(gomock.Any()).Return(nil)
		mockM.EXPECT().SetGauge("jwtauth_service_running", 1.0, map[string]string{})
		Expect(service.Start(ctx)).To(Succeed())
	}

	// ====================================================================
	// Phase 1: Lifecycle Metrics
	// ====================================================================

	Describe("Start", func() {
		It("records service_running=1.0 on successful start", func() {
			mockKM.EXPECT().Start(gomock.Any()).Return(nil)
			mockM.EXPECT().SetGauge("jwtauth_service_running", 1.0, map[string]string{})
			Expect(service.Start(ctx)).To(Succeed())
		})
	})

	Describe("Shutdown", func() {
		It("records service_running=0.0 on successful shutdown", func() {
			startService()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer shutdownCancel()
			mockKM.EXPECT().Shutdown(gomock.Any()).Return(nil)
			mockM.EXPECT().SetGauge("jwtauth_service_running", 0.0, map[string]string{})
			Expect(service.Shutdown(shutdownCtx)).To(Succeed())
		})
	})

	// ====================================================================
	// Phase 2: IssueAccessToken Metrics
	// ====================================================================

	Describe("IssueAccessToken", func() {
		It("records success counter and duration on successful issuance", func() {
			startService()
			mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)
			mockM.EXPECT().IncrementCounter("jwtauth_tokens_issued_total", map[string]string{
				"status":     "success",
				"error_type": "",
				"namespace":  "",
			})
			mockM.EXPECT().RecordDuration("jwtauth_operation_duration_seconds", gomock.Any(), map[string]string{
				"operation": "issue_access_token",
				"namespace": "",
			})
			_, err := service.IssueAccessToken(ctx, "user-1")
			Expect(err).NotTo(HaveOccurred())
		})

		It("records not_running counter when service is stopped", func() {
			mockM.EXPECT().IncrementCounter("jwtauth_tokens_issued_total", map[string]string{
				"status":     "not_running",
				"error_type": "not_running",
				"namespace":  "",
			})
			mockM.EXPECT().RecordDuration("jwtauth_operation_duration_seconds", gomock.Any(), map[string]string{
				"operation": "issue_access_token",
				"namespace": "",
			})
			_, err := service.IssueAccessToken(ctx, "user-1")
			Expect(err).To(MatchError(tokens.ErrManagerNotRunning))
		})

		It("records invalid_input counter for empty user ID", func() {
			startService()
			mockM.EXPECT().IncrementCounter("jwtauth_tokens_issued_total", map[string]string{
				"status":     "invalid_input",
				"error_type": "invalid_input",
				"namespace":  "",
			})
			mockM.EXPECT().RecordDuration("jwtauth_operation_duration_seconds", gomock.Any(), map[string]string{
				"operation": "issue_access_token",
				"namespace": "",
			})
			_, err := service.IssueAccessToken(ctx, "")
			Expect(err).To(MatchError(tokens.ErrInvalidUserID))
		})

		It("records invalid_input counter for whitespace-only user ID", func() {
			startService()
			mockM.EXPECT().IncrementCounter("jwtauth_tokens_issued_total", map[string]string{
				"status":     "invalid_input",
				"error_type": "invalid_input",
				"namespace":  "",
			})
			mockM.EXPECT().RecordDuration("jwtauth_operation_duration_seconds", gomock.Any(), map[string]string{
				"operation": "issue_access_token",
				"namespace": "",
			})
			_, err := service.IssueAccessToken(ctx, "   ")
			Expect(err).To(MatchError(tokens.ErrInvalidUserID))
		})
	})

	// ====================================================================
	// Phase 3: IssueRefreshToken Metrics
	// ====================================================================

	Describe("IssueRefreshToken", func() {
		It("records success counter and duration on successful issuance", func() {
			startService()
			mockStore.EXPECT().Store(gomock.Any(), gomock.Any(), "user-1", gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			mockM.EXPECT().IncrementCounter("jwtauth_tokens_issued_total", map[string]string{
				"status":     "success",
				"error_type": "",
				"namespace":  "",
			})
			mockM.EXPECT().RecordDuration("jwtauth_operation_duration_seconds", gomock.Any(), map[string]string{
				"operation": "issue_refresh_token",
				"namespace": "",
			})
			_, err := service.IssueRefreshToken(ctx, "user-1")
			Expect(err).NotTo(HaveOccurred())
		})
	})

	// ====================================================================
	// Phase 4: ValidateAccessToken Metrics
	// ====================================================================

	Describe("ValidateAccessToken", func() {
		It("records success counter and duration on valid token", func() {
			startService()
			// Issue a real token first so we have a valid string to validate
			mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)
			mockM.EXPECT().IncrementCounter("jwtauth_tokens_issued_total", gomock.Any())
			mockM.EXPECT().RecordDuration("jwtauth_operation_duration_seconds", gomock.Any(), map[string]string{
				"operation": "issue_access_token",
				"namespace": "",
			})
			tokenStr, err := service.IssueAccessToken(ctx, "user-1")
			Expect(err).NotTo(HaveOccurred())

			// Now validate
			mockKM.EXPECT().GetPublicKey(gomock.Any(), testKeyID).Return(&testKey.PublicKey, nil)
			mockM.EXPECT().IncrementCounter("jwtauth_tokens_validated_total", map[string]string{
				"status":     "success",
				"error_type": "",
				"namespace":  "",
			})
			mockM.EXPECT().RecordDuration("jwtauth_operation_duration_seconds", gomock.Any(), map[string]string{
				"operation": "validate_access_token",
				"namespace": "",
			})
			_, err = service.ValidateAccessToken(ctx, tokenStr)
			Expect(err).NotTo(HaveOccurred())
		})

		It("records not_running counter when service is stopped", func() {
			mockM.EXPECT().IncrementCounter("jwtauth_tokens_validated_total", map[string]string{
				"status":     "not_running",
				"error_type": "not_running",
				"namespace":  "",
			})
			mockM.EXPECT().RecordDuration("jwtauth_operation_duration_seconds", gomock.Any(), map[string]string{
				"operation": "validate_access_token",
				"namespace": "",
			})
			_, err := service.ValidateAccessToken(ctx, "some-token")
			Expect(err).To(MatchError(tokens.ErrManagerNotRunning))
		})
	})

	// ====================================================================
	// Phase 5: RefreshAccessToken Metrics
	// ====================================================================

	Describe("RefreshAccessToken", func() {
		It("records success counter on successful refresh", func() {
			startService()
			storedToken := &storage.RefreshToken{
				TokenID:   "rt-1",
				UserID:    "user-1",
				ExpiresAt: time.Now().Add(time.Hour),
				Revoked:   false,
			}
			mockStore.EXPECT().Retrieve(gomock.Any(), "rt-1").Return(storedToken, nil)
			mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)
			// IssueAccessToken metrics (called internally by RefreshAccessToken)
			mockM.EXPECT().IncrementCounter("jwtauth_tokens_issued_total", gomock.Any())
			mockM.EXPECT().RecordDuration("jwtauth_operation_duration_seconds", gomock.Any(), map[string]string{
				"operation": "issue_access_token",
				"namespace": "",
			})
			// RefreshAccessToken metrics
			mockM.EXPECT().IncrementCounter("jwtauth_tokens_refreshed_total", map[string]string{
				"status":     "success",
				"error_type": "",
				"namespace":  "",
			})
			mockM.EXPECT().RecordDuration("jwtauth_operation_duration_seconds", gomock.Any(), map[string]string{
				"operation": "refresh_access_token",
				"namespace": "",
			})
			_, err := service.RefreshAccessToken(ctx, "rt-1")
			Expect(err).NotTo(HaveOccurred())
		})

		It("records expired counter when refresh token is expired", func() {
			startService()
			storedToken := &storage.RefreshToken{
				TokenID:   "rt-expired",
				UserID:    "user-1",
				ExpiresAt: time.Now().Add(-time.Hour), // expired
				Revoked:   false,
			}
			mockStore.EXPECT().Retrieve(gomock.Any(), "rt-expired").Return(storedToken, nil)
			mockStore.EXPECT().Revoke(gomock.Any(), "rt-expired").Return(nil).AnyTimes()
			mockM.EXPECT().IncrementCounter("jwtauth_tokens_refreshed_total", map[string]string{
				"status":     "expired",
				"error_type": "expired",
				"namespace":  "",
			})
			mockM.EXPECT().RecordDuration("jwtauth_operation_duration_seconds", gomock.Any(), map[string]string{
				"operation": "refresh_access_token",
				"namespace": "",
			})
			_, err := service.RefreshAccessToken(ctx, "rt-expired")
			Expect(err).To(MatchError(tokens.ErrRefreshTokenExpired))
		})
	})

	// ====================================================================
	// Phase 6: RevokeRefreshToken Metrics
	// ====================================================================

	Describe("RevokeRefreshToken", func() {
		It("records success counter with operation=single on successful revocation", func() {
			startService()
			mockStore.EXPECT().Revoke(gomock.Any(), "rt-1").Return(nil)
			mockM.EXPECT().IncrementCounter("jwtauth_tokens_revoked_total", map[string]string{
				"operation": "single",
				"status":    "success",
				"namespace": "",
			})
			mockM.EXPECT().RecordDuration("jwtauth_operation_duration_seconds", gomock.Any(), map[string]string{
				"operation": "revoke_token",
				"namespace": "",
			})
			Expect(service.RevokeRefreshToken(ctx, "rt-1")).To(Succeed())
		})

		It("records invalid_input counter for empty token ID", func() {
			startService()
			mockM.EXPECT().IncrementCounter("jwtauth_tokens_revoked_total", map[string]string{
				"operation": "single",
				"status":    "invalid_input",
				"namespace": "",
			})
			mockM.EXPECT().RecordDuration("jwtauth_operation_duration_seconds", gomock.Any(), map[string]string{
				"operation": "revoke_token",
				"namespace": "",
			})
			Expect(service.RevokeRefreshToken(ctx, "")).To(MatchError(tokens.ErrInvalidRefreshToken))
		})
	})

	// ====================================================================
	// Phase 7: RevokeAllUserTokens Metrics
	// ====================================================================

	Describe("RevokeAllUserTokens", func() {
		It("records success counter with operation=all_user on successful bulk revocation", func() {
			startService()
			mockStore.EXPECT().RevokeAllForUser(gomock.Any(), "user-1").Return(nil)
			mockM.EXPECT().IncrementCounter("jwtauth_tokens_revoked_total", map[string]string{
				"operation": "all_user",
				"status":    "success",
				"namespace": "",
			})
			mockM.EXPECT().RecordDuration("jwtauth_operation_duration_seconds", gomock.Any(), map[string]string{
				"operation": "revoke_all_user_tokens",
				"namespace": "",
			})
			Expect(service.RevokeAllUserTokens(ctx, "user-1")).To(Succeed())
		})
	})

	// ====================================================================
	// Phase 8: IntrospectToken Metrics
	// ====================================================================

	Describe("IntrospectToken", func() {
		It("records success counter for an active token", func() {
			startService()
			storedToken := &storage.RefreshToken{
				TokenID:   "rt-1",
				UserID:    "user-1",
				ExpiresAt: time.Now().Add(time.Hour),
				Revoked:   false,
			}
			mockStore.EXPECT().Retrieve(gomock.Any(), "rt-1").Return(storedToken, nil)
			mockM.EXPECT().IncrementCounter("jwtauth_tokens_introspected_total", map[string]string{
				"status":    "success",
				"namespace": "",
			})
			mockM.EXPECT().RecordDuration("jwtauth_operation_duration_seconds", gomock.Any(), map[string]string{
				"operation": "introspect_token",
				"namespace": "",
			})
			meta, err := service.IntrospectToken(ctx, "rt-1")
			Expect(err).NotTo(HaveOccurred())
			Expect(meta.Active).To(BeTrue())
		})

		It("records success counter even when token is not found (returns inactive)", func() {
			startService()
			mockStore.EXPECT().Retrieve(gomock.Any(), "unknown-rt").Return(nil, storage.ErrTokenNotFound)
			mockM.EXPECT().IncrementCounter("jwtauth_tokens_introspected_total", map[string]string{
				"status":    "success",
				"namespace": "",
			})
			mockM.EXPECT().RecordDuration("jwtauth_operation_duration_seconds", gomock.Any(), map[string]string{
				"operation": "introspect_token",
				"namespace": "",
			})
			meta, err := service.IntrospectToken(ctx, "unknown-rt")
			Expect(err).NotTo(HaveOccurred())
			Expect(meta.Active).To(BeFalse())
		})
	})

	// ====================================================================
	// Phase 9: CleanupExpiredTokens Metrics
	// ====================================================================

	Describe("CleanupExpiredTokens", func() {
		It("records success counter and duration on successful cleanup", func() {
			startService()
			mockStore.EXPECT().Cleanup(gomock.Any()).Return(3, nil)
			mockM.EXPECT().IncrementCounter("jwtauth_operations_total", map[string]string{
				"operation": "cleanup",
				"status":    "success",
				"namespace": "",
			})
			mockM.EXPECT().RecordDuration("jwtauth_operation_duration_seconds", gomock.Any(), map[string]string{
				"operation": "cleanup",
				"namespace": "",
			})
			count, err := service.CleanupExpiredTokens(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(count).To(Equal(3))
		})
	})

	// ====================================================================
	// Phase 10: Nil Metrics Safety
	// ====================================================================

	Describe("nil metrics", func() {
		It("does not panic when Metrics is nil", func() {
			nilService, nilMetricsErr := tokens.NewManager(tokens.TokenManagerConfig{
				KeyManager:          mockKM,
				RefreshStore:        mockStore,
				Metrics:             nil,
				AccessTokenDuration: 15 * time.Minute,
				CleanupInterval:     100 * time.Millisecond,
			})
			Expect(nilMetricsErr).NotTo(HaveOccurred())

			// Start without metrics (no SetGauge call expected)
			mockKM.EXPECT().Start(gomock.Any()).Return(nil)
			Expect(nilService.Start(ctx)).To(Succeed())

			// IssueAccessToken should not panic
			mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil)
			_, err := nilService.IssueAccessToken(ctx, "user-1")
			Expect(err).NotTo(HaveOccurred())

			// Shutdown without metrics
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer shutdownCancel()
			mockKM.EXPECT().Shutdown(gomock.Any()).Return(nil)
			Expect(nilService.Shutdown(shutdownCtx)).To(Succeed())
		})
	})
})
