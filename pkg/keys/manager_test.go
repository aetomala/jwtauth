package keys_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"github.com/aetomala/jwtauth/internal/testutil"
	"github.com/aetomala/jwtauth/pkg/keys"
	"github.com/aetomala/jwtauth/pkg/tracing"
)

func TestKeyManager(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Key Manager Suite")
}

// newTestKey generates a 2048-bit RSA key for use in tests.
func newTestKey() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	Expect(err).NotTo(HaveOccurred())
	return key
}

// newTestConfig returns a KeyManagerConfig wired to the given MockKeyStore with
// short rotation/overlap durations suitable for tests.
func newTestConfig(mockKS *testutil.MockKeyStore) keys.KeyManagerConfig {
	return keys.KeyManagerConfig{
		KeyStore:            mockKS,
		KeySize:             2048,
		KeyRotationInterval: 24 * time.Hour,
		KeyOverlapDuration:  100 * time.Millisecond,
	}
}

var _ = Describe("Manager", func() {
	var (
		ctx    context.Context
		cancel context.CancelFunc
		ctrl   *gomock.Controller
		mockKS *testutil.MockKeyStore
	)

	BeforeEach(func() {
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		ctrl = gomock.NewController(GinkgoT())
		mockKS = testutil.NewMockKeyStore(ctrl)
	})

	AfterEach(func() {
		cancel()
		ctrl.Finish()
	})

	// ===== PHASE 1: Constructor and Initialization =====
	Describe("Phase 1: Constructor and Initialization", func() {

		Context("with valid configuration", func() {
			It("should create manager successfully", func() {
				cfg := newTestConfig(mockKS)
				m, err := keys.NewManager(cfg)
				Expect(err).NotTo(HaveOccurred())
				Expect(m).NotTo(BeNil())
			})

			It("should apply default KeySize when zero", func() {
				cfg := keys.KeyManagerConfig{
					KeyStore: mockKS,
					KeySize:  0,
				}
				m, err := keys.NewManager(cfg)
				Expect(err).NotTo(HaveOccurred())
				Expect(m).NotTo(BeNil())
			})

			It("should apply default KeyRotationInterval when zero", func() {
				cfg := keys.KeyManagerConfig{
					KeyStore:            mockKS,
					KeyRotationInterval: 0,
				}
				m, err := keys.NewManager(cfg)
				Expect(err).NotTo(HaveOccurred())
				Expect(m).NotTo(BeNil())
			})

			It("should apply default KeyOverlapDuration when zero", func() {
				cfg := keys.KeyManagerConfig{
					KeyStore:           mockKS,
					KeyOverlapDuration: 0,
				}
				m, err := keys.NewManager(cfg)
				Expect(err).NotTo(HaveOccurred())
				Expect(m).NotTo(BeNil())
			})
		})

		Context("tracer defaults and acceptance", func() {
			It("should apply default Tracer from ConfigDefault when Tracer is nil", func() {
				cfg := newTestConfig(mockKS)
				cfg.Tracer = nil
				m, err := keys.NewManager(cfg)
				Expect(err).NotTo(HaveOccurred())
				Expect(m).NotTo(BeNil())
				// Verify the manager is usable without panicking (NoOp tracer installed)
				mockKS.EXPECT().LoadAll(gomock.Any()).Return([]*keys.StoredKey{}, nil)
				mockKS.EXPECT().Save(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				startCtx, startCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer startCancel()
				Expect(m.Start(startCtx)).To(Succeed())
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer shutdownCancel()
				Expect(m.Shutdown(shutdownCtx)).To(Succeed())
			})

			It("should accept an explicit Tracer without error", func() {
				mockTracer := testutil.NewMockTracer(ctrl)
				mockSpan := testutil.NewMockSpan(ctrl)
				mockTracer.EXPECT().Start(gomock.Any(), gomock.Any(), gomock.Any()).Return(ctx, mockSpan).AnyTimes()
				mockSpan.EXPECT().End().AnyTimes()
				mockSpan.EXPECT().SetStatus(gomock.Any(), gomock.Any()).AnyTimes()
				mockSpan.EXPECT().SetAttribute(gomock.Any(), gomock.Any()).AnyTimes()
				mockSpan.EXPECT().RecordError(gomock.Any()).AnyTimes()

				cfg := newTestConfig(mockKS)
				cfg.Tracer = mockTracer
				m, err := keys.NewManager(cfg)
				Expect(err).NotTo(HaveOccurred())
				Expect(m).NotTo(BeNil())

				mockKS.EXPECT().LoadAll(gomock.Any()).Return([]*keys.StoredKey{}, nil)
				mockKS.EXPECT().Save(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				startCtx, startCancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer startCancel()
				Expect(m.Start(startCtx)).To(Succeed())
				shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer shutdownCancel()
				Expect(m.Shutdown(shutdownCtx)).To(Succeed())
			})
		})

		Context("with invalid configuration", func() {
			It("should return ErrInvalidKeyStore when KeyStore is nil", func() {
				_, err := keys.NewManager(keys.KeyManagerConfig{})
				Expect(err).To(MatchError(keys.ErrInvalidKeyStore))
			})

			It("should return ErrInvalidKeySize when KeySize is negative", func() {
				_, err := keys.NewManager(keys.KeyManagerConfig{
					KeyStore: mockKS,
					KeySize:  -1,
				})
				Expect(err).To(MatchError(keys.ErrInvalidKeySize))
			})

			It("should return ErrInvalidKeySize when KeySize is below 2048", func() {
				_, err := keys.NewManager(keys.KeyManagerConfig{
					KeyStore: mockKS,
					KeySize:  1024,
				})
				Expect(err).To(MatchError(keys.ErrInvalidKeySize))
			})

			It("should return ErrInvalidKeyRotationInterval when negative", func() {
				_, err := keys.NewManager(keys.KeyManagerConfig{
					KeyStore:            mockKS,
					KeyRotationInterval: -1,
				})
				Expect(err).To(MatchError(keys.ErrInvalidKeyRotationInterval))
			})

			It("should return ErrInvalidKeyOverlapDuration when negative", func() {
				_, err := keys.NewManager(keys.KeyManagerConfig{
					KeyStore:           mockKS,
					KeyOverlapDuration: -1,
				})
				Expect(err).To(MatchError(keys.ErrInvalidKeyOverlapDuration))
			})
		})
	})

	// ===== PHASE 2: ConfigDefault =====
	Describe("Phase 2: ConfigDefault", func() {
		It("should return the correct default key size", func() {
			d := keys.DefaultKeyManagerConfig()
			Expect(d.KeySize).To(Equal(2048))
		})

		It("should return the correct default rotation interval", func() {
			d := keys.DefaultKeyManagerConfig()
			Expect(d.KeyRotationInterval).To(Equal(30 * 24 * time.Hour))
		})

		It("should return the correct default overlap duration", func() {
			d := keys.DefaultKeyManagerConfig()
			Expect(d.KeyOverlapDuration).To(Equal(1 * time.Hour))
		})

		It("should leave KeyStore nil", func() {
			d := keys.DefaultKeyManagerConfig()
			Expect(d.KeyStore).To(BeNil())
		})
	})

	// ===== PHASE 3: Start =====
	Describe("Phase 3: Start", func() {
		var manager *keys.Manager

		BeforeEach(func() {
			var err error
			manager, err = keys.NewManager(newTestConfig(mockKS))
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			if manager.IsRunning() {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				manager.Shutdown(shutdownCtx)
			}
		})

		Context("when the store has existing keys", func() {
			It("should load keys from the store and set IsRunning", func() {
				key := newTestKey()
				storedKeys := []*keys.StoredKey{
					{
						KeyID:      "existing-key-id",
						PrivateKey: key,
						Metadata:   keys.KeyMetadata{ID: "existing-key-id", CreatedAt: time.Now()},
					},
				}
				mockKS.EXPECT().LoadAll(gomock.Any()).Return(storedKeys, nil)

				err := manager.Start(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(manager.IsRunning()).To(BeTrue())
			})
		})

		Context("when the store is empty", func() {
			It("should generate a new key pair, save it, and set IsRunning", func() {
				mockKS.EXPECT().LoadAll(gomock.Any()).Return([]*keys.StoredKey{}, nil)
				mockKS.EXPECT().Save(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				err := manager.Start(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(manager.IsRunning()).To(BeTrue())
			})
		})

		Context("error cases", func() {
			It("should return ErrAlreadyRunning on double Start", func() {
				mockKS.EXPECT().LoadAll(gomock.Any()).Return([]*keys.StoredKey{}, nil)
				mockKS.EXPECT().Save(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				Expect(manager.Start(ctx)).To(Succeed())
				Expect(manager.Start(ctx)).To(MatchError(keys.ErrAlreadyRunning))
			})

			It("should return context error when context is cancelled before Start", func() {
				cancelCtx, cancel := context.WithCancel(context.Background())
				cancel()

				err := manager.Start(cancelCtx)
				Expect(err).To(MatchError(context.Canceled))
			})

			It("should return error when LoadAll fails", func() {
				mockKS.EXPECT().LoadAll(gomock.Any()).Return(nil, testutil.NewMockError("store unavailable"))

				err := manager.Start(ctx)
				Expect(err).To(HaveOccurred())
				Expect(manager.IsRunning()).To(BeFalse())
			})

			It("should return error when Save fails on empty store", func() {
				mockKS.EXPECT().LoadAll(gomock.Any()).Return([]*keys.StoredKey{}, nil)
				mockKS.EXPECT().Save(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(testutil.NewMockError("disk full"))

				err := manager.Start(ctx)
				Expect(err).To(HaveOccurred())
				Expect(manager.IsRunning()).To(BeFalse())
			})
		})
	})

	// ===== PHASE 4: GetCurrentSigningKey =====
	Describe("Phase 4: GetCurrentSigningKey", func() {
		var manager *keys.Manager

		BeforeEach(func() {
			var err error
			manager, err = keys.NewManager(newTestConfig(mockKS))
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			if manager.IsRunning() {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				manager.Shutdown(shutdownCtx)
			}
		})

		Context("when the manager is running", func() {
			BeforeEach(func() {
				mockKS.EXPECT().LoadAll(gomock.Any()).Return([]*keys.StoredKey{}, nil)
				mockKS.EXPECT().Save(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				Expect(manager.Start(ctx)).To(Succeed())
			})

			It("should return a valid private key and non-empty key ID", func() {
				key, keyID, err := manager.GetCurrentSigningKey(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(key).NotTo(BeNil())
				Expect(keyID).NotTo(BeEmpty())
			})

			It("should return consistent key ID across multiple calls", func() {
				_, id1, _ := manager.GetCurrentSigningKey(ctx)
				_, id2, _ := manager.GetCurrentSigningKey(ctx)
				Expect(id1).To(Equal(id2))
			})

			It("should return a key of the configured size", func() {
				key, _, err := manager.GetCurrentSigningKey(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(key.N.BitLen()).To(Equal(2048))
			})
		})

		Context("when the manager is not running", func() {
			It("should return ErrManagerNotRunning", func() {
				_, _, err := manager.GetCurrentSigningKey(ctx)
				Expect(err).To(MatchError(keys.ErrManagerNotRunning))
			})
		})

		Context("context cancellation", func() {
			BeforeEach(func() {
				mockKS.EXPECT().LoadAll(gomock.Any()).Return([]*keys.StoredKey{}, nil)
				mockKS.EXPECT().Save(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				Expect(manager.Start(ctx)).To(Succeed())
			})

			It("should return context error when context is already cancelled", func() {
				cancelledCtx, cancelFn := context.WithCancel(context.Background())
				cancelFn()

				_, _, err := manager.GetCurrentSigningKey(cancelledCtx)
				Expect(err).To(MatchError(context.Canceled))
			})
		})
	})

	// ===== PHASE 5: GetPublicKey =====
	Describe("Phase 5: GetPublicKey", func() {
		var (
			manager   *keys.Manager
			testKey   *rsa.PrivateKey
			testKeyID string
		)

		BeforeEach(func() {
			testKey = newTestKey()
			testKeyID = "test-key-id"

			storedKeys := []*keys.StoredKey{
				{
					KeyID:      testKeyID,
					PrivateKey: testKey,
					Metadata:   keys.KeyMetadata{ID: testKeyID, CreatedAt: time.Now()},
				},
			}
			mockKS.EXPECT().LoadAll(gomock.Any()).Return(storedKeys, nil)

			var err error
			manager, err = keys.NewManager(newTestConfig(mockKS))
			Expect(err).NotTo(HaveOccurred())
			Expect(manager.Start(ctx)).To(Succeed())
		})

		AfterEach(func() {
			if manager.IsRunning() {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				manager.Shutdown(shutdownCtx)
			}
		})

		Context("cache hit", func() {
			It("should return the public key for a cached key ID", func() {
				pub, err := manager.GetPublicKey(ctx, testKeyID)
				Expect(err).NotTo(HaveOccurred())
				Expect(pub).NotTo(BeNil())
				Expect(pub).To(Equal(&testKey.PublicKey))
			})
		})

		Context("cache miss", func() {
			It("should call LoadKey on the store for an uncached key ID", func() {
				uncachedKey := newTestKey()
				uncachedID := "uncached-key-id"
				meta := &keys.KeyMetadata{ID: uncachedID, CreatedAt: time.Now()}

				mockKS.EXPECT().LoadKey(gomock.Any(), uncachedID).Return(uncachedKey, meta, nil)

				pub, err := manager.GetPublicKey(ctx, uncachedID)
				Expect(err).NotTo(HaveOccurred())
				Expect(pub).To(Equal(&uncachedKey.PublicKey))
			})

			It("should return ErrKeyNotFound when store returns ErrKeyStoreKeyNotFound", func() {
				mockKS.EXPECT().LoadKey(gomock.Any(), "missing-id").Return(nil, nil, keys.ErrKeyStoreKeyNotFound)

				_, err := manager.GetPublicKey(ctx, "missing-id")
				Expect(err).To(MatchError(keys.ErrKeyNotFound))
			})

			It("should return ErrKeyNotFound for an expired key from the store", func() {
				expiredKey := newTestKey()
				expiredID := "expired-key-id"
				expiredMeta := &keys.KeyMetadata{
					ID:        expiredID,
					CreatedAt: time.Now().Add(-2 * time.Hour),
					ExpiresAt: time.Now().Add(-1 * time.Hour),
				}

				mockKS.EXPECT().LoadKey(gomock.Any(), expiredID).Return(expiredKey, expiredMeta, nil)

				_, err := manager.GetPublicKey(ctx, expiredID)
				Expect(err).To(MatchError(keys.ErrKeyNotFound))
			})
		})

		Context("input validation", func() {
			It("should return ErrInvalidKeyID for an empty key ID", func() {
				_, err := manager.GetPublicKey(ctx, "")
				Expect(err).To(MatchError(keys.ErrInvalidKeyID))
			})

			It("should return ErrInvalidKeyID for a whitespace-only key ID", func() {
				_, err := manager.GetPublicKey(ctx, "   ")
				Expect(err).To(MatchError(keys.ErrInvalidKeyID))
			})

			It("should trim whitespace from keyID and succeed", func() {
				pub, err := manager.GetPublicKey(ctx, "  "+testKeyID+"  ")
				Expect(err).NotTo(HaveOccurred())
				Expect(pub).NotTo(BeNil())
			})
		})

		Context("concurrent access", func() {
			It("should return correct keys under concurrent reads", func() {
				const numReaders = 20
				results := make(chan error, numReaders)

				for i := 0; i < numReaders; i++ {
					go func() {
						_, err := manager.GetPublicKey(ctx, testKeyID)
						results <- err
					}()
				}

				for i := 0; i < numReaders; i++ {
					Expect(<-results).NotTo(HaveOccurred())
				}
			})
		})

		Context("context cancellation", func() {
			It("should return context error when context is already cancelled", func() {
				cancelledCtx, cancelFn := context.WithCancel(context.Background())
				cancelFn()

				_, err := manager.GetPublicKey(cancelledCtx, testKeyID)
				Expect(err).To(MatchError(context.Canceled))
			})
		})
	})

	// ===== PHASE 6: GetJWKS =====
	Describe("Phase 6: GetJWKS", func() {
		var manager *keys.Manager

		AfterEach(func() {
			if manager != nil && manager.IsRunning() {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				manager.Shutdown(shutdownCtx)
			}
		})

		Context("when the manager is not running", func() {
			BeforeEach(func() {
				var err error
				manager, err = keys.NewManager(newTestConfig(mockKS))
				Expect(err).NotTo(HaveOccurred())
			})

			It("should return ErrManagerNotRunning", func() {
				_, err := manager.GetJWKS(ctx)
				Expect(err).To(MatchError(keys.ErrManagerNotRunning))
			})
		})

		Context("when the context is already cancelled", func() {
			BeforeEach(func() {
				activeKey := newTestKey()
				storedKeys := []*keys.StoredKey{
					{
						KeyID:      "active-key",
						PrivateKey: activeKey,
						Metadata:   keys.KeyMetadata{ID: "active-key", CreatedAt: time.Now()},
					},
				}
				mockKS.EXPECT().LoadAll(gomock.Any()).Return(storedKeys, nil)

				var err error
				manager, err = keys.NewManager(newTestConfig(mockKS))
				Expect(err).NotTo(HaveOccurred())
				Expect(manager.Start(ctx)).To(Succeed())
			})

			It("should return the context error", func() {
				cancelledCtx, cancel := context.WithCancel(context.Background())
				cancel()

				_, err := manager.GetJWKS(cancelledCtx)
				Expect(err).To(MatchError(context.Canceled))
			})
		})

		Context("with multiple keys", func() {
			It("should return all non-expired keys", func() {
				activeKey := newTestKey()
				expiredKey := newTestKey()

				storedKeys := []*keys.StoredKey{
					{
						KeyID:      "active-key",
						PrivateKey: activeKey,
						Metadata:   keys.KeyMetadata{ID: "active-key", CreatedAt: time.Now()},
					},
					{
						KeyID:      "current-key",
						PrivateKey: expiredKey,
						Metadata: keys.KeyMetadata{
							ID:        "current-key",
							CreatedAt: time.Now(),
						},
					},
				}
				mockKS.EXPECT().LoadAll(gomock.Any()).Return(storedKeys, nil)

				var err error
				manager, err = keys.NewManager(newTestConfig(mockKS))
				Expect(err).NotTo(HaveOccurred())
				Expect(manager.Start(ctx)).To(Succeed())

				// Set active-key as expired in memory
				manager.Mu().Lock()
				manager.Keys()["active-key"].ExpiresAt = time.Now().Add(-1 * time.Hour)
				manager.Mu().Unlock()

				jwks, err := manager.GetJWKS(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(jwks.Keys).To(HaveLen(1))
				Expect(jwks.Keys[0].KeyID).To(Equal("current-key"))
			})
		})
	})

	// ===== PHASE 7: RotateKeys =====
	Describe("Phase 7: RotateKeys", func() {
		var manager *keys.Manager

		BeforeEach(func() {
			key := newTestKey()
			storedKeys := []*keys.StoredKey{
				{
					KeyID:      "original-key",
					PrivateKey: key,
					Metadata:   keys.KeyMetadata{ID: "original-key", CreatedAt: time.Now()},
				},
			}
			mockKS.EXPECT().LoadAll(gomock.Any()).Return(storedKeys, nil)

			var err error
			manager, err = keys.NewManager(newTestConfig(mockKS))
			Expect(err).NotTo(HaveOccurred())
			Expect(manager.Start(ctx)).To(Succeed())
		})

		AfterEach(func() {
			if manager.IsRunning() {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				manager.Shutdown(shutdownCtx)
			}
		})

		Context("successful rotation", func() {
			It("should save the new key and update the old key's metadata", func() {
				mockKS.EXPECT().Save(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				mockKS.EXPECT().UpdateMetadata(gomock.Any(), "original-key", gomock.Any()).Return(nil)

				err := manager.RotateKeys(ctx)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should change the current signing key ID after rotation", func() {
				_, originalID, _ := manager.GetCurrentSigningKey(ctx)

				mockKS.EXPECT().Save(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				mockKS.EXPECT().UpdateMetadata(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				Expect(manager.RotateKeys(ctx)).To(Succeed())

				_, newID, _ := manager.GetCurrentSigningKey(ctx)
				Expect(newID).NotTo(Equal(originalID))
			})

			It("should mark the old key to expire after KeyOverlapDuration", func() {
				mockKS.EXPECT().Save(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				mockKS.EXPECT().UpdateMetadata(gomock.Any(), "original-key", gomock.Any()).Return(nil)

				Expect(manager.RotateKeys(ctx)).To(Succeed())

				manager.Mu().RLock()
				oldKey := manager.Keys()["original-key"]
				manager.Mu().RUnlock()

				Expect(oldKey.ExpiresAt.IsZero()).To(BeFalse())
			})

			It("should continue if UpdateMetadata fails — in-memory expiry is sufficient", func() {
				mockKS.EXPECT().Save(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				mockKS.EXPECT().UpdateMetadata(gomock.Any(), gomock.Any(), gomock.Any()).Return(testutil.NewMockError("disk error"))

				err := manager.RotateKeys(ctx)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("error cases", func() {
			It("should return ErrManagerNotRunning when not started", func() {
				ctrl2 := gomock.NewController(GinkgoT())
				defer ctrl2.Finish()
				mockKS2 := testutil.NewMockKeyStore(ctrl2)

				m2, _ := keys.NewManager(newTestConfig(mockKS2))
				err := m2.RotateKeys(ctx)
				Expect(err).To(MatchError(keys.ErrManagerNotRunning))
			})

			It("should return error when Save fails", func() {
				mockKS.EXPECT().Save(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(testutil.NewMockError("disk full"))

				err := manager.RotateKeys(ctx)
				Expect(err).To(HaveOccurred())
			})

			It("should return context error when context is already cancelled", func() {
				cancelCtx, cancel := context.WithCancel(context.Background())
				cancel()

				err := manager.RotateKeys(cancelCtx)
				Expect(err).To(MatchError(context.Canceled))
			})
		})
	})

	// ===== PHASE 8: Shutdown =====
	Describe("Phase 8: Shutdown", func() {
		startManager := func() *keys.Manager {
			mockKS.EXPECT().LoadAll(gomock.Any()).Return([]*keys.StoredKey{}, nil)
			mockKS.EXPECT().Save(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			m, err := keys.NewManager(newTestConfig(mockKS))
			Expect(err).NotTo(HaveOccurred())
			Expect(m.Start(ctx)).To(Succeed())
			return m
		}

		Context("graceful shutdown", func() {
			It("should set IsRunning to false after Shutdown", func() {
				m := startManager()
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()

				Expect(m.Shutdown(shutdownCtx)).To(Succeed())
				Expect(m.IsRunning()).To(BeFalse())
			})

			It("should stop the rotation scheduler", func() {
				m := startManager()

				Eventually(m.IsRotationSchedulerActive).Should(BeTrue())

				shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				Expect(m.Shutdown(shutdownCtx)).To(Succeed())

				Eventually(m.IsRotationSchedulerActive).Should(BeFalse())
			})
		})

		Context("idempotency", func() {
			It("should succeed on double Shutdown without error", func() {
				m := startManager()
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()

				Expect(m.Shutdown(shutdownCtx)).To(Succeed())
				Expect(m.Shutdown(shutdownCtx)).To(Succeed())
			})
		})

		Context("context timeout", func() {
			It("should return context error when shutdown context is cancelled", func() {
				m := startManager()

				shortCtx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
				defer cancel()
				time.Sleep(5 * time.Millisecond) // ensure timeout fires

				err := m.Shutdown(shortCtx)
				Expect(err).To(HaveOccurred())
			})
		})
	})

	// ===== PHASE 9: Metrics Recording =====
	Describe("Phase 9: Metrics Recording", func() {
		var mockM *testutil.MockMetrics

		BeforeEach(func() {
			mockM = testutil.NewMockMetrics(ctrl)
		})

		// newMetricManager creates and starts a Manager wired with mockM and mockKS.
		// It sets up LoadAll to return one pre-built key, which triggers the
		// SetGauge(metricKeyActiveVersionsCount) call during Start.
		newMetricManager := func() *keys.Manager {
			existingKey := newTestKey()
			existingID := "existing-metric-key"
			storedKeys := []*keys.StoredKey{
				{
					KeyID:      existingID,
					PrivateKey: existingKey,
					Metadata:   keys.KeyMetadata{ID: existingID, CreatedAt: time.Now()},
				},
			}
			mockKS.EXPECT().LoadAll(gomock.Any()).Return(storedKeys, nil)
			mockM.EXPECT().SetGauge("jwtauth_key_active_versions_count", float64(1), gomock.Nil())

			m, err := keys.NewManager(keys.KeyManagerConfig{
				KeyStore:            mockKS,
				Metrics:             mockM,
				KeySize:             2048,
				KeyRotationInterval: 24 * time.Hour,
				KeyOverlapDuration:  100 * time.Millisecond,
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(m.Start(ctx)).To(Succeed())
			return m
		}

		// expectRotationMetrics sets up MockMetrics expectations for a RotateKeys call.
		// For "success", also expects the active-versions gauge to be updated.
		expectRotationMetrics := func(status string) {
			errorType := status
			if status == "success" {
				errorType = ""
			}
			mockM.EXPECT().IncrementCounter("jwtauth_key_rotations_total", map[string]string{"status": status, "error_type": errorType})
			mockM.EXPECT().RecordDuration("jwtauth_key_operation_duration_seconds", gomock.Any(), map[string]string{"operation": "rotate"})
			if status == "success" {
				mockM.EXPECT().SetGauge("jwtauth_key_active_versions_count", gomock.Any(), gomock.Nil())
			}
		}

		Context("RotateKeys", func() {
			It("should record success counter, duration, and active-versions gauge", func() {
				m := newMetricManager()
				defer func() {
					shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					_ = m.Shutdown(shutdownCtx)
				}()

				expectRotationMetrics("success")
				mockKS.EXPECT().Save(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				mockKS.EXPECT().UpdateMetadata(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				Expect(m.RotateKeys(ctx)).To(Succeed())
			})

			It("should record cancelled status when context is already cancelled", func() {
				m := newMetricManager()
				defer func() {
					shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					_ = m.Shutdown(shutdownCtx)
				}()

				expectRotationMetrics("cancelled")

				cancelledCtx, cancel := context.WithCancel(context.Background())
				cancel() // cancel immediately
				Expect(m.RotateKeys(cancelledCtx)).To(MatchError(context.Canceled))
			})

			It("should record error status when Save fails", func() {
				m := newMetricManager()
				defer func() {
					shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					_ = m.Shutdown(shutdownCtx)
				}()

				expectRotationMetrics("error")
				mockKS.EXPECT().Save(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(testutil.NewMockError("disk full"))

				Expect(m.RotateKeys(ctx)).To(HaveOccurred())
			})
		})

		Context("GetCurrentSigningKey", func() {
			It("should record success counter when manager is running", func() {
				m := newMetricManager()
				defer func() {
					shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					_ = m.Shutdown(shutdownCtx)
				}()

				mockM.EXPECT().IncrementCounter("jwtauth_key_signing_operations_total", map[string]string{"status": "success", "error_type": ""})

				_, _, err := m.GetCurrentSigningKey(ctx)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should record error counter when manager is not running", func() {
				m, err := keys.NewManager(keys.KeyManagerConfig{
					KeyStore:            mockKS,
					Metrics:             mockM,
					KeySize:             2048,
					KeyRotationInterval: 24 * time.Hour,
					KeyOverlapDuration:  100 * time.Millisecond,
				})
				Expect(err).NotTo(HaveOccurred())

				mockM.EXPECT().IncrementCounter("jwtauth_key_signing_operations_total", map[string]string{"status": "error", "error_type": "error"})

				_, _, err = m.GetCurrentSigningKey(ctx)
				Expect(err).To(MatchError(keys.ErrManagerNotRunning))
			})

			It("should record cancelled counter when context is already cancelled", func() {
				m := newMetricManager()
				defer func() {
					shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					_ = m.Shutdown(shutdownCtx)
				}()

				cancelledCtx, cancelFn := context.WithCancel(context.Background())
				cancelFn()

				mockM.EXPECT().IncrementCounter("jwtauth_key_signing_operations_total", map[string]string{"status": "cancelled", "error_type": "cancelled"})

				_, _, err := m.GetCurrentSigningKey(cancelledCtx)
				Expect(err).To(MatchError(context.Canceled))
			})
		})

		Context("GetPublicKey", func() {
			It("should record success counter on cache hit", func() {
				m := newMetricManager()
				defer func() {
					shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					_ = m.Shutdown(shutdownCtx)
				}()

				mockM.EXPECT().IncrementCounter("jwtauth_key_validation_operations_total", map[string]string{"status": "success", "error_type": ""})

				_, err := m.GetPublicKey(ctx, "existing-metric-key")
				Expect(err).NotTo(HaveOccurred())
			})

			It("should record not_found counter when key does not exist in store", func() {
				m := newMetricManager()
				defer func() {
					shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					_ = m.Shutdown(shutdownCtx)
				}()

				mockM.EXPECT().IncrementCounter("jwtauth_key_validation_operations_total", map[string]string{"status": "not_found", "error_type": "not_found"})
				mockKS.EXPECT().LoadKey(gomock.Any(), "ghost-key").Return(nil, nil, keys.ErrKeyStoreKeyNotFound)

				_, err := m.GetPublicKey(ctx, "ghost-key")
				Expect(err).To(MatchError(keys.ErrKeyNotFound))
			})

			It("should record cancelled counter when context is already cancelled", func() {
				m := newMetricManager()
				defer func() {
					shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					_ = m.Shutdown(shutdownCtx)
				}()

				cancelledCtx, cancelFn := context.WithCancel(context.Background())
				cancelFn()

				mockM.EXPECT().IncrementCounter("jwtauth_key_validation_operations_total", map[string]string{"status": "cancelled", "error_type": "cancelled"})

				_, err := m.GetPublicKey(cancelledCtx, "some-key")
				Expect(err).To(MatchError(context.Canceled))
			})
		})

		Context("nil metrics", func() {
			It("should not panic on any operation when metrics is nil", func() {
				existingKey := newTestKey()
				existingID := "nil-metrics-key"
				storedKeys := []*keys.StoredKey{
					{
						KeyID:      existingID,
						PrivateKey: existingKey,
						Metadata:   keys.KeyMetadata{ID: existingID, CreatedAt: time.Now()},
					},
				}
				mockKS.EXPECT().LoadAll(gomock.Any()).Return(storedKeys, nil)

				m, err := keys.NewManager(keys.KeyManagerConfig{
					KeyStore:            mockKS,
					KeySize:             2048,
					KeyRotationInterval: 24 * time.Hour,
					KeyOverlapDuration:  100 * time.Millisecond,
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(m.Start(ctx)).To(Succeed())
				defer func() {
					shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer cancel()
					_ = m.Shutdown(shutdownCtx)
				}()

				Expect(func() { _, _, _ = m.GetCurrentSigningKey(ctx) }).NotTo(Panic())
				Expect(func() { _, _ = m.GetPublicKey(ctx, existingID) }).NotTo(Panic())

				mockKS.EXPECT().Save(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				mockKS.EXPECT().UpdateMetadata(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				Expect(func() { _ = m.RotateKeys(ctx) }).NotTo(Panic())
			})
		})
	})

	// ===== PHASE 11: Tracing =====
	Describe("Phase 11: Tracing", func() {
		var (
			mockTracer *testutil.MockTracer
			manager    *keys.Manager
		)

		BeforeEach(func() {
			mockTracer = testutil.NewMockTracer(ctrl)
		})

		// newTracingManager starts a manager wired with mockTracer. setupSpan is
		// returned for "KeyManager.Start" and "KeyManager.Shutdown" spans so that
		// lifecycle calls do not interfere with the per-test span assertions.
		// Individual tests register their own span (testSpan) for the method under test.
		newTracingManager := func(setupSpan *testutil.MockSpan) *keys.Manager {
			setupSpan.EXPECT().End().AnyTimes()
			setupSpan.EXPECT().SetStatus(gomock.Any(), gomock.Any()).AnyTimes()

			mockTracer.EXPECT().Start(gomock.Any(), gomock.Eq("KeyManager.Start"), gomock.Any()).Return(ctx, setupSpan)
			mockTracer.EXPECT().Start(gomock.Any(), gomock.Eq("KeyManager.Shutdown"), gomock.Any()).Return(ctx, setupSpan).AnyTimes()

			existingKey := newTestKey()
			existingID := "tracing-test-key"
			storedKeys := []*keys.StoredKey{
				{
					KeyID:      existingID,
					PrivateKey: existingKey,
					Metadata:   keys.KeyMetadata{ID: existingID, CreatedAt: time.Now()},
				},
			}
			mockKS.EXPECT().LoadAll(gomock.Any()).Return(storedKeys, nil)

			cfg := newTestConfig(mockKS)
			cfg.Tracer = mockTracer
			var err error
			manager, err = keys.NewManager(cfg)
			Expect(err).NotTo(HaveOccurred())
			Expect(manager.Start(ctx)).To(Succeed())
			return manager
		}

		shutdownManager := func() {
			if manager != nil && manager.IsRunning() {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				_ = manager.Shutdown(shutdownCtx)
			}
		}

		Context("GetCurrentSigningKey success", func() {
			It("should start a span named KeyManager.GetCurrentSigningKey, set key_id attribute, and StatusOK", func() {
				setupSpan := testutil.NewMockSpan(ctrl)
				testSpan := testutil.NewMockSpan(ctrl)
				m := newTracingManager(setupSpan)
				defer shutdownManager()

				mockTracer.EXPECT().Start(gomock.Any(), gomock.Eq("KeyManager.GetCurrentSigningKey"), gomock.Any()).Return(ctx, testSpan)
				testSpan.EXPECT().SetAttribute("key_id", "tracing-test-key")
				testSpan.EXPECT().SetStatus(tracing.StatusOK, "")
				testSpan.EXPECT().End()

				key, keyID, err := m.GetCurrentSigningKey(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(key).NotTo(BeNil())
				Expect(keyID).To(Equal("tracing-test-key"))
			})
		})

		Context("GetPublicKey error path", func() {
			It("should call RecordError and StatusError when key is not found in store", func() {
				setupSpan := testutil.NewMockSpan(ctrl)
				testSpan := testutil.NewMockSpan(ctrl)
				m := newTracingManager(setupSpan)
				defer shutdownManager()

				mockTracer.EXPECT().Start(gomock.Any(), gomock.Eq("KeyManager.GetPublicKey"), gomock.Any()).Return(ctx, testSpan)
				testSpan.EXPECT().SetAttribute("key_id", "ghost-key")
				testSpan.EXPECT().RecordError(keys.ErrKeyNotFound)
				testSpan.EXPECT().SetStatus(tracing.StatusError, keys.ErrKeyNotFound.Error())
				testSpan.EXPECT().End()

				mockKS.EXPECT().LoadKey(gomock.Any(), "ghost-key").Return(nil, nil, keys.ErrKeyStoreKeyNotFound)

				_, err := m.GetPublicKey(ctx, "ghost-key")
				Expect(err).To(MatchError(keys.ErrKeyNotFound))
			})
		})

		Context("RotateKeys success", func() {
			It("should start and end a span for RotateKeys, set key_id attribute, and StatusOK", func() {
				setupSpan := testutil.NewMockSpan(ctrl)
				testSpan := testutil.NewMockSpan(ctrl)
				m := newTracingManager(setupSpan)
				defer shutdownManager()

				mockTracer.EXPECT().Start(gomock.Any(), gomock.Eq("KeyManager.RotateKeys"), gomock.Any()).Return(ctx, testSpan)
				testSpan.EXPECT().SetAttribute("key_id", gomock.Any())
				testSpan.EXPECT().SetStatus(tracing.StatusOK, "")
				testSpan.EXPECT().End()

				mockKS.EXPECT().Save(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
				mockKS.EXPECT().UpdateMetadata(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				Expect(m.RotateKeys(ctx)).To(Succeed())
			})
		})
	})

	// ===== PHASE 10: GetKeyInfo and GetCurrentKeyInfo =====
	Describe("Phase 10: GetKeyInfo and GetCurrentKeyInfo", func() {
		var m *keys.Manager

		// startWithKeys starts the manager after loading the given StoredKeys.
		startWithKeys := func(storedKeys []*keys.StoredKey) {
			mockKS.EXPECT().LoadAll(gomock.Any()).Return(storedKeys, nil)
			var err error
			m, err = keys.NewManager(newTestConfig(mockKS))
			Expect(err).NotTo(HaveOccurred())
			Expect(m.Start(ctx)).To(Succeed())
		}

		shutdownManager := func() {
			if m != nil && m.IsRunning() {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				m.Shutdown(shutdownCtx)
			}
		}

		Context("when the manager is not running", func() {
			BeforeEach(func() {
				var err error
				m, err = keys.NewManager(newTestConfig(mockKS))
				Expect(err).NotTo(HaveOccurred())
			})

			It("GetKeyInfo should return ErrManagerNotRunning", func() {
				info, err := m.GetKeyInfo(ctx, "")
				Expect(err).To(MatchError(keys.ErrManagerNotRunning))
				Expect(info).To(BeNil())
			})

			It("GetCurrentKeyInfo should return ErrManagerNotRunning", func() {
				info, err := m.GetCurrentKeyInfo(ctx)
				Expect(err).To(MatchError(keys.ErrManagerNotRunning))
				Expect(info).To(BeNil())
			})
		})

		Context("when manager is running and keyID is empty", func() {
			var currentKeyID string

			BeforeEach(func() {
				currentKeyID = "key-current"
				startWithKeys([]*keys.StoredKey{
					{
						KeyID:      currentKeyID,
						PrivateKey: newTestKey(),
						Metadata:   keys.KeyMetadata{ID: currentKeyID, CreatedAt: time.Now().Add(-1 * time.Hour)},
					},
				})
			})

			AfterEach(shutdownManager)

			It("should return KeyInfo with IsCurrent=true and IsValid=true", func() {
				info, err := m.GetKeyInfo(ctx, "")
				Expect(err).NotTo(HaveOccurred())
				Expect(info).NotTo(BeNil())
				Expect(info.KeyID).To(Equal(currentKeyID))
				Expect(info.IsCurrent).To(BeTrue())
				Expect(info.IsValid).To(BeTrue())
				Expect(info.Algorithm).To(Equal("RS256"))
				Expect(info.KeySizeBits).To(Equal(2048))
			})

			It("should populate RotateAt for the current key", func() {
				info, err := m.GetKeyInfo(ctx, "")
				Expect(err).NotTo(HaveOccurred())
				Expect(info.RotateAt.IsZero()).To(BeFalse())
			})
		})

		Context("when a specific keyID is provided", func() {
			var currentKeyID, oldKeyID string

			BeforeEach(func() {
				currentKeyID = "key-current"
				oldKeyID = "key-old"
				// currentKeyID has the most recent CreatedAt, so Start will pick it
				startWithKeys([]*keys.StoredKey{
					{
						KeyID:      currentKeyID,
						PrivateKey: newTestKey(),
						Metadata:   keys.KeyMetadata{ID: currentKeyID, CreatedAt: time.Now()},
					},
					{
						KeyID:      oldKeyID,
						PrivateKey: newTestKey(),
						Metadata:   keys.KeyMetadata{ID: oldKeyID, CreatedAt: time.Now().Add(-48 * time.Hour), ExpiresAt: time.Now().Add(-24 * time.Hour)},
					},
				})
			})

			AfterEach(shutdownManager)

			It("should return IsCurrent=true for the current signing key", func() {
				info, err := m.GetKeyInfo(ctx, currentKeyID)
				Expect(err).NotTo(HaveOccurred())
				Expect(info.KeyID).To(Equal(currentKeyID))
				Expect(info.IsCurrent).To(BeTrue())
			})

			It("should return IsCurrent=false for a non-current key", func() {
				info, err := m.GetKeyInfo(ctx, oldKeyID)
				Expect(err).NotTo(HaveOccurred())
				Expect(info.IsCurrent).To(BeFalse())
			})
		})

		Context("when the key does not exist", func() {
			BeforeEach(func() {
				startWithKeys([]*keys.StoredKey{
					{
						KeyID:      "key-only",
						PrivateKey: newTestKey(),
						Metadata:   keys.KeyMetadata{ID: "key-only", CreatedAt: time.Now()},
					},
				})
			})

			AfterEach(shutdownManager)

			It("should return ErrKeyNotFound for an unknown keyID", func() {
				info, err := m.GetKeyInfo(ctx, "does-not-exist")
				Expect(err).To(MatchError(keys.ErrKeyNotFound))
				Expect(info).To(BeNil())
			})
		})

		Context("when the context is already cancelled", func() {
			BeforeEach(func() {
				startWithKeys([]*keys.StoredKey{
					{
						KeyID:      "key-ctx",
						PrivateKey: newTestKey(),
						Metadata:   keys.KeyMetadata{ID: "key-ctx", CreatedAt: time.Now()},
					},
				})
			})

			AfterEach(shutdownManager)

			It("should return context.Canceled", func() {
				cancelCtx, cancelFn := context.WithCancel(context.Background())
				cancelFn()

				info, err := m.GetKeyInfo(cancelCtx, "")
				Expect(err).To(MatchError(context.Canceled))
				Expect(info).To(BeNil())
			})
		})

		Context("when the context deadline has already passed", func() {
			BeforeEach(func() {
				startWithKeys([]*keys.StoredKey{
					{
						KeyID:      "key-deadline",
						PrivateKey: newTestKey(),
						Metadata:   keys.KeyMetadata{ID: "key-deadline", CreatedAt: time.Now()},
					},
				})
			})

			AfterEach(shutdownManager)

			It("should return context.DeadlineExceeded", func() {
				deadCtx, deadCancel := context.WithDeadline(context.Background(), time.Now().Add(-1*time.Second))
				defer deadCancel()

				info, err := m.GetKeyInfo(deadCtx, "")
				Expect(err).To(MatchError(context.DeadlineExceeded))
				Expect(info).To(BeNil())
			})
		})

		Context("when the key has already expired", func() {
			var oldKeyID string

			BeforeEach(func() {
				oldKeyID = "key-expired"
				startWithKeys([]*keys.StoredKey{
					{
						KeyID:      "key-current",
						PrivateKey: newTestKey(),
						Metadata:   keys.KeyMetadata{ID: "key-current", CreatedAt: time.Now()},
					},
					{
						KeyID:      oldKeyID,
						PrivateKey: newTestKey(),
						Metadata: keys.KeyMetadata{
							ID:        oldKeyID,
							CreatedAt: time.Now().Add(-48 * time.Hour),
							ExpiresAt: time.Now().Add(-1 * time.Hour),
						},
					},
				})
			})

			AfterEach(shutdownManager)

			It("should return IsValid=false, IsCurrent=false, RotateAt zero for an expired key", func() {
				info, err := m.GetKeyInfo(ctx, oldKeyID)
				Expect(err).NotTo(HaveOccurred())
				Expect(info.IsValid).To(BeFalse())
				Expect(info.IsCurrent).To(BeFalse())
				Expect(info.RotateAt.IsZero()).To(BeTrue())
			})
		})

		Context("GetCurrentKeyInfo", func() {
			var currentKeyID string

			BeforeEach(func() {
				currentKeyID = "key-convenience"
				startWithKeys([]*keys.StoredKey{
					{
						KeyID:      currentKeyID,
						PrivateKey: newTestKey(),
						Metadata:   keys.KeyMetadata{ID: currentKeyID, CreatedAt: time.Now().Add(-30 * time.Minute)},
					},
				})
			})

			AfterEach(shutdownManager)

			It("should return the same result as GetKeyInfo with empty keyID", func() {
				info1, err1 := m.GetCurrentKeyInfo(ctx)
				info2, err2 := m.GetKeyInfo(ctx, "")

				Expect(err1).NotTo(HaveOccurred())
				Expect(err2).NotTo(HaveOccurred())
				Expect(info1.KeyID).To(Equal(info2.KeyID))
				Expect(info1.CreatedAt).To(Equal(info2.CreatedAt))
				Expect(info1.IsCurrent).To(BeTrue())
				Expect(info2.IsCurrent).To(BeTrue())
			})

			It("should return ErrManagerNotRunning when not running", func() {
				shutdownManager()
				info, err := m.GetCurrentKeyInfo(ctx)
				Expect(err).To(MatchError(keys.ErrManagerNotRunning))
				Expect(info).To(BeNil())
			})
		})
	})
})
