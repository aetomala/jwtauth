package tokens_test

import (
	"context"
	"errors"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"github.com/aetomala/jwtauth/internal/testutil"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/aetomala/jwtauth/pkg/tokens"
)

var _ = Describe("TokenManager ListTokens", func() {
	var (
		ctrl       *gomock.Controller
		mockKM     *testutil.MockKeyManager
		mockStore  *testutil.MockRefreshStore
		mockLogger *testutil.MockLogger
		service    *tokens.Manager
		ctx        context.Context
		cancel     context.CancelFunc
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)

		mockKM = testutil.NewMockKeyManager(ctrl)
		mockStore = testutil.NewMockRefreshStore(ctrl)
		mockLogger = testutil.NewMockLogger()

		service = newTestManager(mockKM, mockStore, mockLogger)

		mockStore.EXPECT().Cleanup(gomock.Any()).Return(0, nil).AnyTimes()
		mockKM.EXPECT().Start(gomock.Any()).Return(nil)
		Expect(service.Start(ctx)).To(Succeed())
	})

	AfterEach(func() {
		if service != nil && service.IsRunning() {
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer shutdownCancel()
			mockKM.EXPECT().Shutdown(gomock.Any()).Return(nil).AnyTimes()
			service.Shutdown(shutdownCtx)
		}
		cancel()
		ctrl.Finish()
	})

	Describe("ListTokens", func() {
		It("should return page from store on success", func() {
			expected := []*storage.RefreshToken{
				{TokenID: "tok-1", UserID: "user-1"},
				{TokenID: "tok-2", UserID: "user-1"},
			}
			mockStore.EXPECT().
				ListTokens(gomock.Any(), "", 10).
				Return(expected, "", nil)

			page, next, err := service.ListTokens(ctx, "", 10)

			Expect(err).NotTo(HaveOccurred())
			Expect(page).To(Equal(expected))
			Expect(next).To(BeEmpty())
		})

		It("should propagate cursor and count to store", func() {
			mockStore.EXPECT().
				ListTokens(gomock.Any(), "cursor-abc", 5).
				Return(nil, "", nil)

			service.ListTokens(ctx, "cursor-abc", 5)
		})

		It("should return next cursor from store", func() {
			mockStore.EXPECT().
				ListTokens(gomock.Any(), "", 2).
				Return([]*storage.RefreshToken{{TokenID: "tok-1"}}, "cursor-xyz", nil)

			_, next, err := service.ListTokens(ctx, "", 2)

			Expect(err).NotTo(HaveOccurred())
			Expect(next).To(Equal("cursor-xyz"))
		})

		It("should log success with result count and next cursor", func() {
			mockStore.EXPECT().
				ListTokens(gomock.Any(), "", 10).
				Return([]*storage.RefreshToken{{TokenID: "tok-1"}}, "next", nil)

			service.ListTokens(ctx, "", 10)

			Eventually(func() bool {
				return mockLogger.HasLog("info", "tokens listed")
			}).Should(BeTrue())
		})

		Context("when store returns an error", func() {
			It("should return wrapped error", func() {
				storeErr := errors.New("redis unavailable")
				mockStore.EXPECT().
					ListTokens(gomock.Any(), "", 10).
					Return(nil, "", storeErr)

				_, _, err := service.ListTokens(ctx, "", 10)

				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, storeErr)).To(BeTrue())
			})

			It("should log the error", func() {
				mockStore.EXPECT().
					ListTokens(gomock.Any(), "", 10).
					Return(nil, "", errors.New("store error"))

				service.ListTokens(ctx, "", 10)

				Eventually(func() bool {
					return mockLogger.HasLog("error", "failed to list tokens")
				}).Should(BeTrue())
			})
		})

		Context("when service is not running", func() {
			It("should return ErrManagerNotRunning", func() {
				stoppedService := newTestManager(mockKM, mockStore, mockLogger)

				_, _, err := stoppedService.ListTokens(ctx, "", 10)

				Expect(err).To(MatchError(tokens.ErrManagerNotRunning))
			})
		})

		Context("when context is cancelled", func() {
			It("should return context error", func() {
				cancelledCtx, cancel := context.WithCancel(ctx)
				cancel()

				_, _, err := service.ListTokens(cancelledCtx, "", 10)

				Expect(err).To(MatchError(context.Canceled))
			})
		})
	})
})
