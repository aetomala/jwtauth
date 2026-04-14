package keymanager_test

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
	"github.com/aetomala/jwtauth/pkg/keymanager"
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

// newTestConfig returns a ManagerConfig wired to the given MockKeyStore with
// short rotation/overlap durations suitable for tests.
func newTestConfig(mockKS *testutil.MockKeyStore) keymanager.ManagerConfig {
	return keymanager.ManagerConfig{
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
	)

	BeforeEach(func() {
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	})

	AfterEach(func() {
		cancel()
	})

	// ===== PHASE 1: Constructor and Initialization =====
	Describe("Phase 1: Constructor and Initialization", func() {
		var ctrl *gomock.Controller
		var mockKS *testutil.MockKeyStore

		BeforeEach(func() {
			ctrl = gomock.NewController(GinkgoT())
			mockKS = testutil.NewMockKeyStore(ctrl)
		})

		AfterEach(func() { ctrl.Finish() })

		Context("with valid configuration", func() {
			It("should create manager successfully", func() {
				cfg := newTestConfig(mockKS)
				m, err := keymanager.NewManager(cfg)
				Expect(err).NotTo(HaveOccurred())
				Expect(m).NotTo(BeNil())
			})

			It("should apply default KeySize when zero", func() {
				cfg := keymanager.ManagerConfig{
					KeyStore: mockKS,
					KeySize:  0,
				}
				m, err := keymanager.NewManager(cfg)
				Expect(err).NotTo(HaveOccurred())
				Expect(m).NotTo(BeNil())
			})

			It("should apply default KeyRotationInterval when zero", func() {
				cfg := keymanager.ManagerConfig{
					KeyStore:            mockKS,
					KeyRotationInterval: 0,
				}
				m, err := keymanager.NewManager(cfg)
				Expect(err).NotTo(HaveOccurred())
				Expect(m).NotTo(BeNil())
			})

			It("should apply default KeyOverlapDuration when zero", func() {
				cfg := keymanager.ManagerConfig{
					KeyStore:           mockKS,
					KeyOverlapDuration: 0,
				}
				m, err := keymanager.NewManager(cfg)
				Expect(err).NotTo(HaveOccurred())
				Expect(m).NotTo(BeNil())
			})
		})

		Context("with invalid configuration", func() {
			It("should return ErrInvalidKeyStore when KeyStore is nil", func() {
				_, err := keymanager.NewManager(keymanager.ManagerConfig{})
				Expect(err).To(MatchError(keymanager.ErrInvalidKeyStore))
			})

			It("should return ErrInvalidKeySize when KeySize is negative", func() {
				_, err := keymanager.NewManager(keymanager.ManagerConfig{
					KeyStore: mockKS,
					KeySize:  -1,
				})
				Expect(err).To(MatchError(keymanager.ErrInvalidKeySize))
			})

			It("should return ErrInvalidKeySize when KeySize is below 2048", func() {
				_, err := keymanager.NewManager(keymanager.ManagerConfig{
					KeyStore: mockKS,
					KeySize:  1024,
				})
				Expect(err).To(MatchError(keymanager.ErrInvalidKeySize))
			})

			It("should return ErrInvalidKeyRotationInterval when negative", func() {
				_, err := keymanager.NewManager(keymanager.ManagerConfig{
					KeyStore:            mockKS,
					KeyRotationInterval: -1,
				})
				Expect(err).To(MatchError(keymanager.ErrInvalidKeyRotationInterval))
			})

			It("should return ErrInvalidKeyOverlapDuration when negative", func() {
				_, err := keymanager.NewManager(keymanager.ManagerConfig{
					KeyStore:           mockKS,
					KeyOverlapDuration: -1,
				})
				Expect(err).To(MatchError(keymanager.ErrInvalidKeyOverlapDuration))
			})
		})
	})

	// ===== PHASE 2: ConfigDefault =====
	Describe("Phase 2: ConfigDefault", func() {
		It("should return the correct default key size", func() {
			d := keymanager.ConfigDefault()
			Expect(d.KeySize).To(Equal(2048))
		})

		It("should return the correct default rotation interval", func() {
			d := keymanager.ConfigDefault()
			Expect(d.KeyRotationInterval).To(Equal(30 * 24 * time.Hour))
		})

		It("should return the correct default overlap duration", func() {
			d := keymanager.ConfigDefault()
			Expect(d.KeyOverlapDuration).To(Equal(1 * time.Hour))
		})

		It("should leave KeyStore nil", func() {
			d := keymanager.ConfigDefault()
			Expect(d.KeyStore).To(BeNil())
		})
	})

	// ===== PHASE 3: Start =====
	Describe("Phase 3: Start", func() {
		var (
			ctrl    *gomock.Controller
			mockKS  *testutil.MockKeyStore
			manager *keymanager.Manager
		)

		BeforeEach(func() {
			ctrl = gomock.NewController(GinkgoT())
			mockKS = testutil.NewMockKeyStore(ctrl)
			var err error
			manager, err = keymanager.NewManager(newTestConfig(mockKS))
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			if manager.IsRunning() {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				manager.Shutdown(shutdownCtx)
			}
			ctrl.Finish()
		})

		Context("when the store has existing keys", func() {
			It("should load keys from the store and set IsRunning", func() {
				key := newTestKey()
				storedKeys := []*keymanager.StoredKey{
					{
						KeyID:      "existing-key-id",
						PrivateKey: key,
						Metadata:   keymanager.KeyMetadata{ID: "existing-key-id", CreatedAt: time.Now()},
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
				mockKS.EXPECT().LoadAll(gomock.Any()).Return([]*keymanager.StoredKey{}, nil)
				mockKS.EXPECT().Save(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				err := manager.Start(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(manager.IsRunning()).To(BeTrue())
			})
		})

		Context("error cases", func() {
			It("should return ErrAlreadyRunning on double Start", func() {
				mockKS.EXPECT().LoadAll(gomock.Any()).Return([]*keymanager.StoredKey{}, nil)
				mockKS.EXPECT().Save(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)

				Expect(manager.Start(ctx)).To(Succeed())
				Expect(manager.Start(ctx)).To(MatchError(keymanager.ErrAlreadyRunning))
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
				mockKS.EXPECT().LoadAll(gomock.Any()).Return([]*keymanager.StoredKey{}, nil)
				mockKS.EXPECT().Save(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(testutil.NewMockError("disk full"))

				err := manager.Start(ctx)
				Expect(err).To(HaveOccurred())
				Expect(manager.IsRunning()).To(BeFalse())
			})
		})
	})

	// ===== PHASE 4: GetCurrentSigningKey =====
	Describe("Phase 4: GetCurrentSigningKey", func() {
		var (
			ctrl    *gomock.Controller
			mockKS  *testutil.MockKeyStore
			manager *keymanager.Manager
		)

		BeforeEach(func() {
			ctrl = gomock.NewController(GinkgoT())
			mockKS = testutil.NewMockKeyStore(ctrl)
			var err error
			manager, err = keymanager.NewManager(newTestConfig(mockKS))
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() {
			if manager.IsRunning() {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				manager.Shutdown(shutdownCtx)
			}
			ctrl.Finish()
		})

		Context("when the manager is running", func() {
			BeforeEach(func() {
				mockKS.EXPECT().LoadAll(gomock.Any()).Return([]*keymanager.StoredKey{}, nil)
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
				Expect(err).To(MatchError(keymanager.ErrManagerNotRunning))
			})
		})

		Context("context cancellation", func() {
			BeforeEach(func() {
				mockKS.EXPECT().LoadAll(gomock.Any()).Return([]*keymanager.StoredKey{}, nil)
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
			ctrl      *gomock.Controller
			mockKS    *testutil.MockKeyStore
			manager   *keymanager.Manager
			testKey   *rsa.PrivateKey
			testKeyID string
		)

		BeforeEach(func() {
			ctrl = gomock.NewController(GinkgoT())
			mockKS = testutil.NewMockKeyStore(ctrl)
			testKey = newTestKey()
			testKeyID = "test-key-id"

			storedKeys := []*keymanager.StoredKey{
				{
					KeyID:      testKeyID,
					PrivateKey: testKey,
					Metadata:   keymanager.KeyMetadata{ID: testKeyID, CreatedAt: time.Now()},
				},
			}
			mockKS.EXPECT().LoadAll(gomock.Any()).Return(storedKeys, nil)

			var err error
			manager, err = keymanager.NewManager(newTestConfig(mockKS))
			Expect(err).NotTo(HaveOccurred())
			Expect(manager.Start(ctx)).To(Succeed())
		})

		AfterEach(func() {
			if manager.IsRunning() {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				manager.Shutdown(shutdownCtx)
			}
			ctrl.Finish()
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
				meta := &keymanager.KeyMetadata{ID: uncachedID, CreatedAt: time.Now()}

				mockKS.EXPECT().LoadKey(gomock.Any(), uncachedID).Return(uncachedKey, meta, nil)

				pub, err := manager.GetPublicKey(ctx, uncachedID)
				Expect(err).NotTo(HaveOccurred())
				Expect(pub).To(Equal(&uncachedKey.PublicKey))
			})

			It("should return ErrKeyNotFound when store returns ErrKeyStoreKeyNotFound", func() {
				mockKS.EXPECT().LoadKey(gomock.Any(), "missing-id").Return(nil, nil, keymanager.ErrKeyStoreKeyNotFound)

				_, err := manager.GetPublicKey(ctx, "missing-id")
				Expect(err).To(MatchError(keymanager.ErrKeyNotFound))
			})

			It("should return ErrKeyNotFound for an expired key from the store", func() {
				expiredKey := newTestKey()
				expiredID := "expired-key-id"
				expiredMeta := &keymanager.KeyMetadata{
					ID:        expiredID,
					CreatedAt: time.Now().Add(-2 * time.Hour),
					ExpiresAt: time.Now().Add(-1 * time.Hour),
				}

				mockKS.EXPECT().LoadKey(gomock.Any(), expiredID).Return(expiredKey, expiredMeta, nil)

				_, err := manager.GetPublicKey(ctx, expiredID)
				Expect(err).To(MatchError(keymanager.ErrKeyNotFound))
			})
		})

		Context("input validation", func() {
			It("should return ErrInvalidKeyID for an empty key ID", func() {
				_, err := manager.GetPublicKey(ctx, "")
				Expect(err).To(MatchError(keymanager.ErrInvalidKeyID))
			})

			It("should return ErrInvalidKeyID for a whitespace-only key ID", func() {
				_, err := manager.GetPublicKey(ctx, "   ")
				Expect(err).To(MatchError(keymanager.ErrInvalidKeyID))
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
		var (
			ctrl    *gomock.Controller
			mockKS  *testutil.MockKeyStore
			manager *keymanager.Manager
		)

		AfterEach(func() {
			if manager != nil && manager.IsRunning() {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				manager.Shutdown(shutdownCtx)
			}
			if ctrl != nil {
				ctrl.Finish()
			}
		})

		Context("when the manager is not running", func() {
			BeforeEach(func() {
				ctrl = gomock.NewController(GinkgoT())
				mockKS = testutil.NewMockKeyStore(ctrl)
				var err error
				manager, err = keymanager.NewManager(newTestConfig(mockKS))
				Expect(err).NotTo(HaveOccurred())
			})

			It("should return ErrManagerNotRunning", func() {
				_, err := manager.GetJWKS(ctx)
				Expect(err).To(MatchError(keymanager.ErrManagerNotRunning))
			})
		})

		Context("with multiple keys", func() {
			It("should return all non-expired keys", func() {
				ctrl = gomock.NewController(GinkgoT())
				mockKS = testutil.NewMockKeyStore(ctrl)

				activeKey := newTestKey()
				expiredKey := newTestKey()

				storedKeys := []*keymanager.StoredKey{
					{
						KeyID:      "active-key",
						PrivateKey: activeKey,
						Metadata:   keymanager.KeyMetadata{ID: "active-key", CreatedAt: time.Now()},
					},
					{
						KeyID:      "current-key",
						PrivateKey: expiredKey,
						Metadata: keymanager.KeyMetadata{
							ID:        "current-key",
							CreatedAt: time.Now(),
						},
					},
				}
				mockKS.EXPECT().LoadAll(gomock.Any()).Return(storedKeys, nil)

				var err error
				manager, err = keymanager.NewManager(newTestConfig(mockKS))
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
		var (
			ctrl    *gomock.Controller
			mockKS  *testutil.MockKeyStore
			manager *keymanager.Manager
		)

		BeforeEach(func() {
			ctrl = gomock.NewController(GinkgoT())
			mockKS = testutil.NewMockKeyStore(ctrl)

			key := newTestKey()
			storedKeys := []*keymanager.StoredKey{
				{
					KeyID:      "original-key",
					PrivateKey: key,
					Metadata:   keymanager.KeyMetadata{ID: "original-key", CreatedAt: time.Now()},
				},
			}
			mockKS.EXPECT().LoadAll(gomock.Any()).Return(storedKeys, nil)

			var err error
			manager, err = keymanager.NewManager(newTestConfig(mockKS))
			Expect(err).NotTo(HaveOccurred())
			Expect(manager.Start(ctx)).To(Succeed())
		})

		AfterEach(func() {
			if manager.IsRunning() {
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				manager.Shutdown(shutdownCtx)
			}
			ctrl.Finish()
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

				m2, _ := keymanager.NewManager(newTestConfig(mockKS2))
				err := m2.RotateKeys(ctx)
				Expect(err).To(MatchError(keymanager.ErrManagerNotRunning))
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
		var (
			ctrl   *gomock.Controller
			mockKS *testutil.MockKeyStore
		)

		BeforeEach(func() {
			ctrl = gomock.NewController(GinkgoT())
			mockKS = testutil.NewMockKeyStore(ctrl)
		})

		AfterEach(func() { ctrl.Finish() })

		startManager := func() *keymanager.Manager {
			mockKS.EXPECT().LoadAll(gomock.Any()).Return([]*keymanager.StoredKey{}, nil)
			mockKS.EXPECT().Save(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(nil)
			m, err := keymanager.NewManager(newTestConfig(mockKS))
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
		var (
			ctrl   *gomock.Controller
			mockM  *testutil.MockMetrics
			mockKS *testutil.MockKeyStore
		)

		BeforeEach(func() {
			ctrl = gomock.NewController(GinkgoT())
			mockM = testutil.NewMockMetrics(ctrl)
			mockKS = testutil.NewMockKeyStore(ctrl)
		})

		AfterEach(func() {
			ctrl.Finish()
		})

		// newMetricManager creates and starts a Manager wired with mockM and mockKS.
		// It sets up LoadAll to return one pre-built key, which triggers the
		// SetGauge(metricKeyActiveVersionsCount) call during Start.
		newMetricManager := func() *keymanager.Manager {
			existingKey := newTestKey()
			existingID := "existing-metric-key"
			storedKeys := []*keymanager.StoredKey{
				{
					KeyID:      existingID,
					PrivateKey: existingKey,
					Metadata:   keymanager.KeyMetadata{ID: existingID, CreatedAt: time.Now()},
				},
			}
			mockKS.EXPECT().LoadAll(gomock.Any()).Return(storedKeys, nil)
			mockM.EXPECT().SetGauge("jwtauth_key_active_versions_count", float64(1), gomock.Nil())

			m, err := keymanager.NewManager(keymanager.ManagerConfig{
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
				m, err := keymanager.NewManager(keymanager.ManagerConfig{
					KeyStore:            mockKS,
					Metrics:             mockM,
					KeySize:             2048,
					KeyRotationInterval: 24 * time.Hour,
					KeyOverlapDuration:  100 * time.Millisecond,
				})
				Expect(err).NotTo(HaveOccurred())

				mockM.EXPECT().IncrementCounter("jwtauth_key_signing_operations_total", map[string]string{"status": "error", "error_type": "error"})

				_, _, err = m.GetCurrentSigningKey(ctx)
				Expect(err).To(MatchError(keymanager.ErrManagerNotRunning))
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
				mockKS.EXPECT().LoadKey(gomock.Any(), "ghost-key").Return(nil, nil, keymanager.ErrKeyStoreKeyNotFound)

				_, err := m.GetPublicKey(ctx, "ghost-key")
				Expect(err).To(MatchError(keymanager.ErrKeyNotFound))
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
				storedKeys := []*keymanager.StoredKey{
					{
						KeyID:      existingID,
						PrivateKey: existingKey,
						Metadata:   keymanager.KeyMetadata{ID: existingID, CreatedAt: time.Now()},
					},
				}
				mockKS.EXPECT().LoadAll(gomock.Any()).Return(storedKeys, nil)

				m, err := keymanager.NewManager(keymanager.ManagerConfig{
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
})
