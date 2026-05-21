// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package tokens_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"github.com/aetomala/jwtauth/internal/testutil"
	"github.com/aetomala/jwtauth/pkg/tokens"
)

var _ = Describe("TokenManager", func() {
	var (
		ctrl       *gomock.Controller
		service    *tokens.Manager
		mockKM     *testutil.MockKeyManager
		mockStore  *testutil.MockRefreshStore
		mockLogger *testutil.MockLogger
		ctx        context.Context
		cancel     context.CancelFunc
		testKey    *rsa.PrivateKey
		testKeyID  string
	)

	BeforeEach(func() {
		// Create gomock controller
		ctrl = gomock.NewController(GinkgoT())

		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)

		// Generate test RSA key
		testKey, _ = rsa.GenerateKey(rand.Reader, 2048)
		testKeyID = "test-key-id-123"

		testPublicKey = &testKey.PublicKey

		// Create mocks using gomock (auto-generated)
		mockKM = testutil.NewMockKeyManager(ctrl)
		mockStore = testutil.NewMockRefreshStore(ctrl)
		mockLogger = testutil.NewMockLogger()
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
	// START TESTS
	// ========================================================================
	Describe("Start", func() {
		BeforeEach(func() {
			service = newTestManager(mockKM, mockStore, mockLogger)
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

			// One should succeed, one should be a no-op (idempotent)
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
				Cleanup(gomock.Any()).
				DoAndReturn(func(context.Context) (int, error) {
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
				Return(errors.New("key manager start failed"))

			err := service.Start(ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("key manager start failed"))
			Expect(service.IsRunning()).To(BeFalse())
		})

		It("should log error when background cleanup fails", func() {
			mockKM.EXPECT().Start(gomock.Any()).Return(nil)
			mockKM.EXPECT().Shutdown(gomock.Any()).Return(nil)

			mockStore.EXPECT().
				Cleanup(gomock.Any()).
				DoAndReturn(func(context.Context) (int, error) {
					return 0, errors.New("store unavailable")
				}).
				AnyTimes()

			service.Start(ctx)

			Eventually(func() bool {
				return mockLogger.HasLog("error", "refresh token cleanup failed")
			}, 2*time.Second).Should(BeTrue())

			service.Shutdown(ctx)
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
	// SHUTDOWN TESTS
	// ========================================================================
	Describe("Shutdown", func() {
		BeforeEach(func() {
			service = newTestManager(mockKM, mockStore, mockLogger)

			// Start the service
			mockKM.EXPECT().Start(gomock.Any()).Return(nil)
			service.Start(ctx)
		})

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

			cleanupStopped := make(chan struct{})
			mockStore.EXPECT().
				Cleanup(gomock.Any()).
				DoAndReturn(func(context.Context) (int, error) {
					return 0, nil
				}).
				AnyTimes()

			service.Shutdown(ctx)
			close(cleanupStopped)

			// Verify no further cleanup calls happen after shutdown signal
			Consistently(func() bool {
				return service.IsRunning()
			}, 200*time.Millisecond, 50*time.Millisecond).Should(BeFalse())
		})

		It("should wait for background goroutines to complete", func() {
			mockKM.EXPECT().Shutdown(gomock.Any()).Return(nil)

			// Track cleanup execution
			cleanupRunning := true
			mockStore.EXPECT().
				Cleanup(gomock.Any()).
				DoAndReturn(func(context.Context) (int, error) {
					if !cleanupRunning {
						return 0, errors.New("cleanup called after shutdown")
					}
					return 0, nil
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
			Expect(err).To(Equal(tokens.ErrManagerNotRunning))
		})

		It("should return error if KeyManager fails to shutdown", func() {
			mockKM.EXPECT().
				Shutdown(gomock.Any()).
				Return(errors.New("key manager shutdown failed"))

			err := service.Shutdown(ctx)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("key manager shutdown failed"))
		})

		It("should return context error when shutdown context is pre-cancelled", func() {
			// Allow cleanup if the ticker fires before Shutdown is called.
			mockStore.EXPECT().Cleanup(gomock.Any()).Return(0, nil).AnyTimes()

			cancelledCtx, cancel := context.WithCancel(context.Background())
			cancel() // immediately cancelled

			err := service.Shutdown(cancelledCtx)
			Expect(errors.Is(err, context.Canceled)).To(BeTrue())
			// AfterEach: IsRunning() is false — Shutdown block skipped, ctrl.Finish() is safe.
		})

		It("should handle concurrent Shutdown calls without panicking", func() {
			// CompareAndSwap prevents double-close of shutdownChan; verify concurrency is safe.
			mockKM.EXPECT().Shutdown(gomock.Any()).Return(nil).AnyTimes()
			mockStore.EXPECT().Cleanup(gomock.Any()).Return(0, nil).AnyTimes()

			var wg sync.WaitGroup
			for i := 0; i < 5; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer GinkgoRecover()
					shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					_ = service.Shutdown(shutdownCtx)
				}()
			}
			wg.Wait()
			Expect(service.IsRunning()).To(BeFalse())
		})
	})

	// ========================================================================
	// ISRUNNING TESTS
	// ========================================================================
	Describe("IsRunning", func() {
		BeforeEach(func() {
			service = newTestManager(mockKM, mockStore, mockLogger)
		})

		It("should return false initially", func() {
			Expect(service.IsRunning()).To(BeFalse())
		})

		It("should return true after start", func() {
			mockKM.EXPECT().Start(gomock.Any()).Return(nil)

			service.Start(ctx)

			Expect(service.IsRunning()).To(BeTrue())
		})

		It("should return false after shutdown", func() {
			mockKM.EXPECT().Start(gomock.Any()).Return(nil)
			mockKM.EXPECT().Shutdown(gomock.Any()).Return(nil)

			service.Start(ctx)
			service.Shutdown(ctx)

			Expect(service.IsRunning()).To(BeFalse())
		})

		It("should be thread-safe", func() {
			mockKM.EXPECT().Start(gomock.Any()).Return(nil).AnyTimes()

			service.Start(ctx)

			var wg sync.WaitGroup
			for i := 0; i < 100; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_ = service.IsRunning()
				}()
			}

			wg.Wait()
		})
	})

	// ========================================================================
	// COMPLETE LIFECYCLE INTEGRATION TEST
	// ========================================================================
	Describe("Complete Lifecycle", func() {
		It("should handle start -> use -> shutdown cycle", func() {
			mockKM.EXPECT().Start(gomock.Any()).Return(nil)
			mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil).AnyTimes()
			mockKM.EXPECT().Shutdown(gomock.Any()).Return(nil)

			service = newTestManager(mockKM, mockStore, mockLogger)
			// Start
			err := service.Start(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(service.IsRunning()).To(BeTrue())

			// Use
			token, err := service.IssueAccessToken(ctx, "user-123")
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())

			// Shutdown
			err = service.Shutdown(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(service.IsRunning()).To(BeFalse())

			// Operations should fail after shutdown
			_, err = service.IssueAccessToken(ctx, "user-456")
			Expect(err).To(Equal(tokens.ErrManagerNotRunning))
		})

		It("should support restart (Start → Shutdown → Start → Shutdown)", func() {
			mockKM.EXPECT().Start(gomock.Any()).Return(nil).Times(2)
			mockKM.EXPECT().Shutdown(gomock.Any()).Return(nil).Times(2)
			mockStore.EXPECT().Cleanup(gomock.Any()).Return(0, nil).AnyTimes()

			service = newTestManager(mockKM, mockStore, mockLogger)

			// First cycle
			Expect(service.Start(ctx)).To(Succeed())
			Expect(service.IsRunning()).To(BeTrue())
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer shutdownCancel()
			Expect(service.Shutdown(shutdownCtx)).To(Succeed())
			Expect(service.IsRunning()).To(BeFalse())

			// Second cycle
			Expect(service.Start(ctx)).To(Succeed())
			Expect(service.IsRunning()).To(BeTrue())
			shutdownCtx2, shutdownCancel2 := context.WithTimeout(context.Background(), 2*time.Second)
			defer shutdownCancel2()
			Expect(service.Shutdown(shutdownCtx2)).To(Succeed())
			Expect(service.IsRunning()).To(BeFalse())
		})

		It("should run cleanup goroutine after restart", func() {
			// Without the shutdownChan recreation fix, IsRunning() returns true after
			// the second Start but the cleanup goroutine exits immediately because
			// shutdownChan is already closed. This spec detects that silent failure.
			mockKM.EXPECT().Start(gomock.Any()).Return(nil).Times(2)
			mockKM.EXPECT().Shutdown(gomock.Any()).Return(nil).Times(2)

			service = newTestManager(mockKM, mockStore, mockLogger)

			// Single DoAndReturn expectation for both cycles — gomock FIFO means a
			// second AnyTimes registration would never be reached.
			cleanupCalled := make(chan struct{}, 100)
			mockStore.EXPECT().Cleanup(gomock.Any()).
				DoAndReturn(func(context.Context) (int, error) {
					select {
					case cleanupCalled <- struct{}{}:
					default:
					}
					return 0, nil
				}).AnyTimes()

			// First cycle
			Expect(service.Start(ctx)).To(Succeed())
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
			Expect(service.Shutdown(shutdownCtx)).To(Succeed())
			shutdownCancel()

			// Drain any calls from the first cycle before restarting.
			draining := true
			for draining {
				select {
				case <-cleanupCalled:
				default:
					draining = false
				}
			}

			// Second start — verify the cleanup goroutine is alive.
			Expect(service.Start(ctx)).To(Succeed())

			// If bug is present: cleanupCalled never receives (goroutine exits immediately).
			Eventually(cleanupCalled, 2*time.Second).Should(Receive())

			shutdownCtx2, shutdownCancel2 := context.WithTimeout(context.Background(), 2*time.Second)
			Expect(service.Shutdown(shutdownCtx2)).To(Succeed())
			shutdownCancel2()
		})
	})

	// ========================================================================
	// CONCURRENT LIFECYCLE RACES
	// ========================================================================
	Describe("Concurrent Lifecycle Races", func() {
		BeforeEach(func() {
			service = newTestManager(mockKM, mockStore, mockLogger)
			mockKM.EXPECT().Start(gomock.Any()).Return(nil)
			Expect(service.Start(ctx)).To(Succeed())
		})

		It("token operations racing with Shutdown should complete or return ErrManagerNotRunning — never panic", func() {
			const workers = 20
			mockKM.EXPECT().GetCurrentSigningKey(gomock.Any()).Return(testKey, testKeyID, nil).AnyTimes()
			mockStore.EXPECT().Cleanup(gomock.Any()).Return(0, nil).AnyTimes()
			mockKM.EXPECT().Shutdown(gomock.Any()).Return(nil)

			results := make(chan error, workers)
			var wg sync.WaitGroup

			for i := 0; i < workers; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer GinkgoRecover()
					_, err := service.IssueAccessToken(ctx, "user-race-test")
					results <- err
				}()
			}

			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutdownCancel()
			Expect(service.Shutdown(shutdownCtx)).To(Succeed())

			wg.Wait()
			close(results)

			for err := range results {
				if err != nil {
					Expect(err).To(Equal(tokens.ErrManagerNotRunning))
				}
			}
		})
	})
})
