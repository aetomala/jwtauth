package keymanager_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aetomala/jwtauth/pkg/keymanager"
)

func TestKeyManager(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Key Manager Suite")
}

var _ = Describe("Keymanager", func() {
	var (
		manager *keymanager.Manager
		ctx     context.Context
		cancel  context.CancelFunc
		config  keymanager.ManagerConfig
		tempDir string
	)

	BeforeEach(func() {
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		tempDir = GinkgoT().TempDir()

		config = keymanager.ManagerConfig{
			KeyDirectory:        tempDir,
			KeyRotationInterval: 30 * 24 * time.Hour, // 30 days
			KeyOverlapDuration:  1 * time.Hour,
			KeySize:             2048,
		}
	})

	AfterEach(func() {
		if cancel != nil {
			cancel()
		}
		if manager != nil && manager.IsRunning() {
			manager.Shutdown(ctx)
		}
	})

	// === TEST DEFAULTS DIRECTLY ===
	Describe("ConfigDefault", func() {
		It("should return correct default key size", func() {
			defaults := keymanager.ConfigDefault()
			Expect(defaults.KeySize).To(Equal(2048))
		})

		It("should return correct default rotation interval", func() {
			defaults := keymanager.ConfigDefault()
			Expect(defaults.KeyRotationInterval).To(Equal(30 * 24 * time.Hour))
		})

		It("should return correct default overlap duration", func() {
			defaults := keymanager.ConfigDefault()
			Expect(defaults.KeyOverlapDuration).To(Equal(1 * time.Hour))
		})

		It("should leave KeyDirectory empty", func() {
			defaults := keymanager.ConfigDefault()
			Expect(defaults.KeyDirectory).To(BeEmpty())
		})
	})

	// === PHASE 1: Constructor ===
	Describe("Constructor", func() {
		Context("with valid configuration", func() {
			It("should create manager successfully", func() {
				mgr, err := keymanager.NewManager(config)
				Expect(err).NotTo(HaveOccurred())
				Expect(mgr.IsRunning()).To(BeFalse())
			})
			It("should accept configuration with explicit values", func() {
				config.KeySize = 4096
				config.KeyRotationInterval = 60 * 24 * time.Hour

				mgr, err := keymanager.NewManager(config)
				Expect(err).NotTo(HaveOccurred())
				Expect(mgr).NotTo(BeNil())
			})
		})

		Context("with zero values (should apply defaults)", func() {
			It("should accept zero KeySize and not error", func() {
				config.KeySize = 0

				mgr, err := keymanager.NewManager(config)
				Expect(err).NotTo(HaveOccurred())
				Expect(mgr).NotTo(BeNil())
			})

			It("should accept zero KeyRotationInterval and not error", func() {
				config.KeyRotationInterval = 0

				mgr, err := keymanager.NewManager(config)
				Expect(err).NotTo(HaveOccurred())
				Expect(mgr).NotTo(BeNil())
			})

			It("should accept zero KeyOverlapDuration and not error", func() {
				config.KeyOverlapDuration = 0

				mgr, err := keymanager.NewManager(config)
				Expect(err).NotTo(HaveOccurred())
				Expect(mgr).NotTo(BeNil())
			})

			It("should accept all zero values except KeyDirectory", func() {
				config = keymanager.ManagerConfig{
					KeyDirectory: tempDir, // Only required field
					// All others zero - should get defaults
				}

				mgr, err := keymanager.NewManager(config)
				Expect(err).NotTo(HaveOccurred())
				Expect(mgr).NotTo(BeNil())
			})
		})

		Context("with invalid configuration", func() {
			It("should return error for empty key directory", func() {
				config.KeyDirectory = ""
				_, err := keymanager.NewManager(config)
				Expect(err).To(MatchError(ContainSubstring("key directory")))
			})

			It("should return error for invalid key size", func() {
				config.KeySize = 512 // Too small
				_, err := keymanager.NewManager(config)
				Expect(err).To(MatchError(keymanager.ErrInvalidKeySize))
			})

			It("should return error for negative rotation interval", func() {
				config.KeyRotationInterval = -1 * time.Hour
				_, err := keymanager.NewManager(config)
				Expect(err).To(MatchError(keymanager.ErrInvalidKeyRotationInterval))
			})

			It("should return error for negative overlap duration", func() {
				config.KeyOverlapDuration = -1 * time.Hour
				_, err := keymanager.NewManager(config)
				Expect(err).To(MatchError(ContainSubstring("overlap duration")))
			})
		})
	})

	// === PHASE 2: Start/Initialization ===
	Describe("Start", func() {
		BeforeEach(func() {
			var err error
			manager, err = keymanager.NewManager(config)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should start successfully", func() {
			err := manager.Start(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(manager.IsRunning()).To(BeTrue())
		})

		It("shoud generate initial key pair on first start", func() {
			err := manager.Start(ctx)
			Expect(err).NotTo(HaveOccurred())

			// Should have at least one key
			privateKey, keyID, err := manager.GetCurrentSigningKey()
			Expect(err).NotTo(HaveOccurred())
			Expect(privateKey).NotTo(BeNil())
			Expect(keyID).NotTo(BeEmpty())
		})

		Context("testing defaults are applied", func() {
			It("should generate key with default size when KeySize is zero", func() {
				config.KeySize = 0 // Should get default 2048
				mgr, _ := keymanager.NewManager(config)

				err := mgr.Start(ctx)
				Expect(err).NotTo(HaveOccurred())

				privateKey, _, _ := mgr.GetCurrentSigningKey()
				keySize := privateKey.N.BitLen()
				Expect(keySize).To(Equal(2048)) // Default applied!
			})

			It("should use custom key size when explicitly provided", func() {
				config.KeySize = 4096 // Explicit value
				mgr, _ := keymanager.NewManager(config)

				err := mgr.Start(ctx)
				Expect(err).NotTo(HaveOccurred())

				privateKey, _, _ := mgr.GetCurrentSigningKey()
				keySize := privateKey.N.BitLen()
				Expect(keySize).To(Equal(4096)) // Custom value used!
			})
		})

		It("should load existing keys on restart", func() {
			// First start
			err := manager.Start(ctx)
			Expect(err).NotTo(HaveOccurred())

			_, originalKeyID, _ := manager.GetCurrentSigningKey()

			// Shutdown
			manager.Shutdown(ctx)

			// Create new manager with same directory
			manager2, _ := keymanager.NewManager(config)
			err = manager2.Start(ctx)
			Expect(err).NotTo(HaveOccurred())

			// Should have loaded the same key
			_, loadedKeyID, _ := manager2.GetCurrentSigningKey()
			Expect(loadedKeyID).To(Equal(originalKeyID))

			manager2.Shutdown(ctx)
		})

		It("should return error on double start", func() {
			manager.Start(ctx)
			err := manager.Start(ctx)
			Expect(err).To(MatchError(keymanager.ErrAlreadyRunning))
		})

		It("should respect context cancellation during start", func() {
			cancelCtx, cancelFn := context.WithCancel(context.Background())
			cancelFn() // Cancel immediately

			err := manager.Start(cancelCtx)
			Expect(err).To(MatchError(context.Canceled))
		})

		It("should create a key directory if not exists", func() {
			newDir := filepath.Join(tempDir, "newDir")
			config.KeyDirectory = newDir

			mgr, _ := keymanager.NewManager(config)
			err := mgr.Start(ctx)
			Expect(err).NotTo(HaveOccurred())

			// Verify directory is created
			_, err = os.Stat(newDir)
			Expect(err).NotTo(HaveOccurred())

			mgr.Shutdown(ctx)
		})

		It("should start automatic rotation scheduler", func() {
			err := manager.Start(ctx)
			Expect(err).NotTo(HaveOccurred())

			// Verify scheduler is running (internal state check)
			Expect(manager.IsRotationSchedulerActive()).To(BeTrue())
		})
	})

	// === PHASE 3: Key Retrieval (Core Operation) ===
	Describe("GetCurrentSigningKey", func() {
		BeforeEach(func() {
			manager, _ = keymanager.NewManager(config)
			err := manager.Start(ctx)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should return current private key and ID", func() {
			privateKey, keyID, err := manager.GetCurrentSigningKey()
			Expect(err).NotTo(HaveOccurred())
			Expect(privateKey).NotTo(BeNil())
			Expect(keyID).NotTo(BeEmpty())
			Expect(privateKey.N).NotTo(BeNil()) // RSA modulus
		})

		It("should return same key on multiple calls", func() {
			key1, id1, _ := manager.GetCurrentSigningKey()
			key2, id2, _ := manager.GetCurrentSigningKey()

			Expect(key1).To(Equal(key2))
			Expect(id1).To(Equal(id2))
		})

		It("should return key with correct size", func() {
			privateKey, _, err := manager.GetCurrentSigningKey()
			Expect(err).NotTo(HaveOccurred())

			keysize := privateKey.N.BitLen()
			Expect(keysize).To(Equal(2048))
		})

		It("should return key with correct custom size", func() {
			config.KeySize = 4096
			mgr, _ := keymanager.NewManager(config)
			mgr.Start(ctx)
			defer mgr.Shutdown(ctx)

			privateKey, _, _ := mgr.GetCurrentSigningKey()
			keysize := privateKey.N.BitLen()
			Expect(keysize).To(Equal(4096))
		})
	})

	Describe("GetPublicKey", func() {
		var currentKeyID string

		BeforeEach(func() {
			manager, _ = keymanager.NewManager(config)
			manager.Start(ctx)
			_, currentKeyID, _ = manager.GetCurrentSigningKey()
		})

		It("should return public key for valid key ID", func() {
			publicKey, err := manager.GetPublicKey(currentKeyID)
			Expect(err).NotTo(HaveOccurred())
			Expect(publicKey).NotTo(BeNil())
			Expect(publicKey.N).NotTo(BeNil())
		})

		It("should return erro for unknown key ID", func() {
			_, err := manager.GetPublicKey("unkown-key-id")
			Expect(err).To(MatchError(keymanager.ErrKeyNotFound))
		})

		It("should return error for empty key ID", func() {
			_, err := manager.GetPublicKey("")
			Expect(err).To(MatchError(ContainSubstring("key ID")))
		})

		It("should return matching public key for private key", func() {
			privateKey, keyID, _ := manager.GetCurrentSigningKey()
			publicKey, err := manager.GetPublicKey(keyID)

			Expect(err).NotTo(HaveOccurred())
			Expect(publicKey.N).To(Equal(privateKey.PublicKey.N))
			Expect(publicKey.E).To(Equal(privateKey.PublicKey.E))
		})
	})

	// === PHASE 4: JWKS (JSON Web Key Set) ===
	Describe("GetJWKS", func() {
		BeforeEach(func() {
			manager, _ = keymanager.NewManager(config)
			manager.Start(ctx)
		})

		It("should return JKWS with at least one key", func() {
			jwks, err := manager.GetJWKS()
			Expect(err).NotTo(HaveOccurred())
			Expect(jwks).ToNot(BeNil())
			Expect(len(jwks.Keys)).To(BeNumerically(">=", 1))
		})

		It("should include current signing key in JWS", func() {
			_, currentKeyID, _ := manager.GetCurrentSigningKey()

			jwks, err := manager.GetJWKS()
			Expect(err).NotTo(HaveOccurred())

			// Find current key in JWKS
			found := false
			for _, jwk := range jwks.Keys {
				if jwk.KeyID == currentKeyID {
					found = true
					break
				}
			}
			Expect(found).To(BeTrue())
		})

		It("should have the correct JWK structure", func() {
			jwks, err := manager.GetJWKS()
			Expect(err).NotTo(HaveOccurred())

			jwk := jwks.Keys[0]
			Expect(jwk.KeyID).NotTo(BeEmpty())
			Expect(jwk.KeyType).To(Equal("RSA"))
			Expect(jwk.Algorithm).To(Equal("RS256"))
			Expect(jwk.Use).To(Equal("sig"))
			Expect(jwk.N).NotTo(BeEmpty())
			Expect(jwk.E).NotTo(BeEmpty())
		})
		// Perhaps premature test
		It("should only include valid (non-expired) keys", func() {
			jwks, err := manager.GetJWKS()
			Expect(err).NotTo(HaveOccurred())

			now := time.Now()
			for _, jwk := range jwks.Keys {
				// Getl full key into a check expiration
				key, _ := manager.GetKeyInfo(jwk.KeyID)
				if !key.ExpiresAt.IsZero() {
					Expect(key.ExpiresAt).To(BeTemporally(">", now))
				}
			}
		})
	})

	// == PHASE 5: Key Rotation ==
	Describe("RotationKeys", func() {
		BeforeEach(func() {
			manager, _ = keymanager.NewManager(config)
			manager.Start(ctx)
		})

		It("should generate a new key pair", func() {
			_, oldKey, _ := manager.GetCurrentSigningKey()
			err := manager.RotateKeys(ctx)
			Expect(err).NotTo(HaveOccurred())

			_, newKeyID, _ := manager.GetCurrentSigningKey()
			Expect(newKeyID).NotTo(Equal(oldKey))
		})

		It("should keep old key valid during overlap period", func() {
			_, oldKeyID, _ := manager.GetCurrentSigningKey()

			err := manager.RotateKeys(ctx)
			Expect(err).NotTo(HaveOccurred())

			// Old key should still be retrivable
			oldPublicKey, err := manager.GetPublicKey(oldKeyID)
			Expect(err).NotTo(HaveOccurred())
			Expect(oldPublicKey).NotTo(BeNil())
		})

		It("should include both keys in JWKS during overlap", func() {
			_, oldKeyID, _ := manager.GetCurrentSigningKey()

			err := manager.RotateKeys(ctx)
			Expect(err).NotTo(HaveOccurred())

			_, newKeyID, _ := manager.GetCurrentSigningKey()

			jwks, _ := manager.GetJWKS()
			keyIDs := make([]string, len(jwks.Keys))
			for i, jwk := range jwks.Keys {
				keyIDs[i] = jwk.KeyID
			}

			Expect(keyIDs).To(ContainElement(oldKeyID))
			Expect(keyIDs).To(ContainElement(newKeyID))
		})

		It("should persist rotated keys to disk", func() {
			err := manager.RotateKeys(ctx)
			Expect(err).NotTo(HaveOccurred())

			_, newKeyID, _ := manager.GetCurrentSigningKey()

			// Shutdown and restart
			manager.Shutdown(ctx)

			manager2, _ := keymanager.NewManager(config)
			manager2.Start(ctx)

			// should load the new key
			_, loadKeyID, _ := manager2.GetCurrentSigningKey()
			Expect(loadKeyID).To(Equal(newKeyID))

			manager2.Shutdown(ctx)
		})

		It("should set expiration on old key", func() {
			_, oldKeyID, _ := manager.GetCurrentSigningKey()

			err := manager.RotateKeys(ctx)
			Expect(err).NotTo(HaveOccurred())

			//Get old Key info
			oldKey, _ := manager.GetKeyInfo(oldKeyID)
			expextedExpiry := time.Now().Add(config.KeyOverlapDuration)

			Expect(oldKey.ExpiresAt).To(BeTemporally("~", expextedExpiry, 5*time.Second))
		})

		It("should handle multiple rotations", func() {
			keyIDs := make([]string, 3)

			_, keyIDs[0], _ = manager.GetCurrentSigningKey()

			manager.RotateKeys(ctx)
			_, keyIDs[1], _ = manager.GetCurrentSigningKey()

			manager.RotateKeys(ctx)
			_, keyIDs[2], _ = manager.GetCurrentSigningKey()

			// All should be unique
			Expect(keyIDs[0]).NotTo(Equal(keyIDs[1]))
			Expect(keyIDs[1]).NotTo(Equal(keyIDs[2]))
			Expect(keyIDs[0]).NotTo(Equal(keyIDs[2]))
		})

		It("should use default key size after rotation when zero provided", func() {
			config.KeySize = 0 // Should use default
			mgr, _ := keymanager.NewManager(config)
			mgr.Start(ctx)
			defer mgr.Shutdown(ctx)

			// Rotate
			mgr.RotateKeys(ctx)

			// New key should have default size
			privateKey, _, _ := mgr.GetCurrentSigningKey()
			keySize := privateKey.N.BitLen()
			Expect(keySize).To(Equal(2048)) // Default
		})
	})
})
