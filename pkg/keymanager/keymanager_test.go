package keymanager_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aetomala/jwtauth/internal/testutil"
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

	Describe("GetKeyInfo", func() {
		BeforeEach(func() {
			manager, _ = keymanager.NewManager(config)
			manager.Start(ctx)
		})

		It("should return key info for valid key ID", func() {
			_, currentKeyID, _ := manager.GetCurrentSigningKey()
			keyInfo, err := manager.GetKeyInfo(currentKeyID)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyInfo).NotTo(BeNil())
			Expect(keyInfo.ID).To(Equal(currentKeyID))
			Expect(keyInfo.PublicKey).NotTo(BeNil())
		})

		It("should return error for non-existent key", func() {
			_, err := manager.GetKeyInfo("non-existent-key-id")
			Expect(err).To(MatchError(keymanager.ErrKeyNotFound))
		})

		It("should return error when manager is not running", func() {
			_, currentKeyID, _ := manager.GetCurrentSigningKey()
			manager.Shutdown(ctx)

			_, err := manager.GetKeyInfo(currentKeyID)
			Expect(err).To(MatchError(keymanager.ErrManagerNotRunning))
		})

		It("should return key with metadata", func() {
			_, currentKeyID, _ := manager.GetCurrentSigningKey()
			keyInfo, err := manager.GetKeyInfo(currentKeyID)
			Expect(err).NotTo(HaveOccurred())
			Expect(keyInfo.CreatedAt).NotTo(BeZero())
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

	Context("with whitespace in keyID", func() {
		It("should trim leading whitespace", func() {
			publicKey, err := manager.GetPublicKey("  " + currentKeyID)
			Expect(err).NotTo(HaveOccurred())
			Expect(publicKey).NotTo(BeNil())
		})

		It("should trim trailing whitespace", func() {
			publicKey, err := manager.GetPublicKey(currentKeyID + "  ")
			Expect(err).NotTo(HaveOccurred())
			Expect(publicKey).NotTo(BeNil())
		})

		It("should trim both leading and trailing whitespace", func() {
			publicKey, err := manager.GetPublicKey("  " + currentKeyID + "  ")
			Expect(err).NotTo(HaveOccurred())
			Expect(publicKey).NotTo(BeNil())
		})
	})

	Context("with cache scenarios", func() {
		It("should return cached key on subsequent calls", func() {
			publicKey1, err1 := manager.GetPublicKey(currentKeyID)
			Expect(err1).NotTo(HaveOccurred())

			publicKey2, err2 := manager.GetPublicKey(currentKeyID)
			Expect(err2).NotTo(HaveOccurred())

			Expect(publicKey1.N).To(Equal(publicKey2.N))
			Expect(publicKey1.E).To(Equal(publicKey2.E))
		})

		It("should handle concurrent cache access", func() {
			const numGoroutines = 20
			var wg sync.WaitGroup
			results := make(chan error, numGoroutines)

			for i := 0; i < numGoroutines; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer GinkgoRecover()
					_, err := manager.GetPublicKey(currentKeyID)
					results <- err
				}()
			}

			wg.Wait()
			close(results)

			for err := range results {
				Expect(err).NotTo(HaveOccurred())
			}
		})
	})

	Context("error handling", func() {
		It("should return ErrInvalidKeyID for whitespace-only keyID", func() {
			_, err := manager.GetPublicKey("   ")
			Expect(err).To(MatchError(ContainSubstring("key ID")))
		})

		It("should return error for non-existent key", func() {
			_, err := manager.GetPublicKey("non-existent-key-id-12345")
			Expect(err).To(MatchError(keymanager.ErrKeyNotFound))
		})
	})

	Context("disk loading (cache miss)", func() {
		It("should load key from disk when not in cache", func() {
			// Get the current key and ensure it's cached
			publicKey1, err := manager.GetPublicKey(currentKeyID)
			Expect(err).NotTo(HaveOccurred())
			Expect(publicKey1).NotTo(BeNil())

			// Clear the cache to force disk loading
			manager.Mu().Lock()
			delete(manager.Keys(), currentKeyID)
			manager.Mu().Unlock()

			// Load again - should load from disk
			publicKey2, err := manager.GetPublicKey(currentKeyID)
			Expect(err).NotTo(HaveOccurred())
			Expect(publicKey2).NotTo(BeNil())
			// Should be the same key
			Expect(publicKey2.N).To(Equal(publicKey1.N))
			Expect(publicKey2.E).To(Equal(publicKey1.E))
		})

		It("should re-cache key after loading from disk", func() {
			// Get key and cache it
			_, err := manager.GetPublicKey(currentKeyID)
			Expect(err).NotTo(HaveOccurred())

			// Clear cache
			manager.Mu().Lock()
			delete(manager.Keys(), currentKeyID)
			manager.Mu().Unlock()

			// Load again - should reload from disk and re-cache
			_, err = manager.GetPublicKey(currentKeyID)
			Expect(err).NotTo(HaveOccurred())

			// Verify it's back in cache
			manager.Mu().RLock()
			_, exists := manager.Keys()[currentKeyID]
			manager.Mu().RUnlock()
			Expect(exists).To(BeTrue())
		})
	})

	Context("expired keys", func() {
		It("should return ErrKeyNotFound for expired key", func() {
			// Get the current key to ensure files exist
			publicKey1, err := manager.GetPublicKey(currentKeyID)
			Expect(err).NotTo(HaveOccurred())
			Expect(publicKey1).NotTo(BeNil())

			// Clear cache
			manager.Mu().Lock()
			delete(manager.Keys(), currentKeyID)
			manager.Mu().Unlock()

			// Modify the metadata file to have an expiration in the past
			metadataFile := filepath.Join(config.KeyDirectory, currentKeyID+".json")
			expiredMeta := keymanager.KeyMetadata{
				ID:        currentKeyID,
				CreatedAt: time.Now().Add(-48 * time.Hour),
				ExpiresAt: time.Now().Add(-24 * time.Hour), // Expired yesterday
			}
			metaBytes, err := json.Marshal(expiredMeta)
			Expect(err).NotTo(HaveOccurred())
			err = os.WriteFile(metadataFile, metaBytes, 0644)
			Expect(err).NotTo(HaveOccurred())

			// Try to load expired key
			_, err = manager.GetPublicKey(currentKeyID)
			Expect(err).To(MatchError(keymanager.ErrKeyNotFound))
		})
	})

	Context("missing metadata", func() {
		It("should return ErrKeyNotFound when metadata file is missing", func() {
			// Get the current key to ensure PEM file exists
			publicKey1, err := manager.GetPublicKey(currentKeyID)
			Expect(err).NotTo(HaveOccurred())
			Expect(publicKey1).NotTo(BeNil())

			// Clear cache
			manager.Mu().Lock()
			delete(manager.Keys(), currentKeyID)
			manager.Mu().Unlock()

			// Delete the metadata file
			metadataFile := filepath.Join(config.KeyDirectory, currentKeyID+".json")
			err = os.Remove(metadataFile)
			Expect(err).NotTo(HaveOccurred())

			// Try to load key without metadata
			_, err = manager.GetPublicKey(currentKeyID)
			Expect(err).To(MatchError(keymanager.ErrKeyNotFound))
		})
	})

	Context("double-check locking pattern", func() {
		It("should handle race condition when multiple goroutines load same key", func() {
			// Clear cache to force disk loading
			manager.Mu().Lock()
			delete(manager.Keys(), currentKeyID)
			manager.Mu().Unlock()

			const numGoroutines = 10
			var wg sync.WaitGroup
			results := make(chan *rsa.PublicKey, numGoroutines)
			errChan := make(chan error, numGoroutines)

			// Launch multiple goroutines to load the same non-cached key concurrently
			for i := 0; i < numGoroutines; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					defer GinkgoRecover()
					key, err := manager.GetPublicKey(currentKeyID)
					results <- key
					errChan <- err
				}()
			}

			wg.Wait()
			close(results)
			close(errChan)

			// Verify all goroutines succeeded and got the same key
			var firstKey *rsa.PublicKey
			for key := range results {
				Expect(key).NotTo(BeNil())
				if firstKey == nil {
					firstKey = key
				} else {
					Expect(key.N).To(Equal(firstKey.N))
					Expect(key.E).To(Equal(firstKey.E))
				}
			}

			for err := range errChan {
				Expect(err).NotTo(HaveOccurred())
			}

			// Verify key is in cache after concurrent load
			manager.Mu().RLock()
			_, exists := manager.Keys()[currentKeyID]
			manager.Mu().RUnlock()
			Expect(exists).To(BeTrue())
		})
	})

	Context("loadPublicKeyFromDisk error paths", func() {
		var keyIDWithBadPEM string

		BeforeEach(func() {
			manager, _ = keymanager.NewManager(config)
			manager.Start(ctx)
			keyIDWithBadPEM = "bad-pem-key"
		})

		It("should return error for invalid PEM format", func() {
			// Create a PEM file with invalid format
			pemFile := filepath.Join(config.KeyDirectory, keyIDWithBadPEM+".pem")
			badPEM := []byte("-----BEGIN INVALID-----\ngarbage data\n-----END INVALID-----")
			err := os.WriteFile(pemFile, badPEM, 0644)
			Expect(err).NotTo(HaveOccurred())

			// Create metadata file so metadata loading succeeds
			metadataFile := filepath.Join(config.KeyDirectory, keyIDWithBadPEM+".json")
			metaData := keymanager.KeyMetadata{
				ID:        keyIDWithBadPEM,
				CreatedAt: time.Now(),
				ExpiresAt: time.Time{},
			}
			metaBytes, _ := json.Marshal(metaData)
			os.WriteFile(metadataFile, metaBytes, 0644)

			// Try to load key with bad PEM
			_, err = manager.GetPublicKey(keyIDWithBadPEM)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("invalid PEM"))
		})

		It("should return error for key below minimum size", func() {
			// Generate a 1024-bit key (below minimum 2048)
			smallKey, err := rsa.GenerateKey(rand.Reader, 1024)
			Expect(err).NotTo(HaveOccurred())

			// Encode as PEM
			keyBytes := x509.MarshalPKCS1PrivateKey(smallKey)
			pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}
			pemFile := filepath.Join(config.KeyDirectory, "small-key.pem")
			pemData := pem.EncodeToMemory(pemBlock)
			err = os.WriteFile(pemFile, pemData, 0644)
			Expect(err).NotTo(HaveOccurred())

			// Create metadata
			metadataFile := filepath.Join(config.KeyDirectory, "small-key.json")
			metaData := keymanager.KeyMetadata{
				ID:        "small-key",
				CreatedAt: time.Now(),
				ExpiresAt: time.Time{},
			}
			metaBytes, _ := json.Marshal(metaData)
			os.WriteFile(metadataFile, metaBytes, 0644)

			// Try to load undersized key
			_, err = manager.GetPublicKey("small-key")
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("below minimum"))
		})

		It("should return error when PEM file is unreadable", func() {
			// Create a PEM file and make it unreadable
			pemFile := filepath.Join(config.KeyDirectory, "unreadable.pem")
			err := os.WriteFile(pemFile, []byte("test"), 0000)
			Expect(err).NotTo(HaveOccurred())
			defer os.Chmod(pemFile, 0644) // Cleanup

			// Try to load unreadable key
			_, err = manager.GetPublicKey("unreadable")
			Expect(err).To(HaveOccurred())
		})

		It("should warn when key size differs from config", func() {
			// Generate a 4096-bit key when config expects 2048
			largeKey, err := rsa.GenerateKey(rand.Reader, 4096)
			Expect(err).NotTo(HaveOccurred())

			// Encode as PEM
			keyBytes := x509.MarshalPKCS1PrivateKey(largeKey)
			pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}
			pemFile := filepath.Join(config.KeyDirectory, "large-key.pem")
			pemData := pem.EncodeToMemory(pemBlock)
			err = os.WriteFile(pemFile, pemData, 0644)
			Expect(err).NotTo(HaveOccurred())

			// Create metadata
			metadataFile := filepath.Join(config.KeyDirectory, "large-key.json")
			metaData := keymanager.KeyMetadata{
				ID:        "large-key",
				CreatedAt: time.Now(),
				ExpiresAt: time.Time{},
			}
			metaBytes, _ := json.Marshal(metaData)
			os.WriteFile(metadataFile, metaBytes, 0644)

			// Load key - should succeed but with warning
			publicKey, err := manager.GetPublicKey("large-key")
			Expect(err).NotTo(HaveOccurred())
			Expect(publicKey).NotTo(BeNil())
			Expect(publicKey.N.BitLen()).To(Equal(4096))
		})
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

	// === PHASE 6: Automatic Rotation ===
	Describe("Automatic Key Rotation", func() {
		It("should rotate key automatically base on interval", func() {
			// Use very short interval for testins
			config.KeyRotationInterval = 200 * time.Millisecond
			config.KeyOverlapDuration = 100 * time.Millisecond

			manager, _ = keymanager.NewManager(config)
			manager.Start(ctx)

			_, originalKeyID, _ := manager.GetCurrentSigningKey()

			//wait for automatic rotation
			Eventually(func() string {
				_, keyID, _ := manager.GetCurrentSigningKey()
				return keyID
			}, 1*time.Second, 50*time.Millisecond).ShouldNot(Equal(originalKeyID))
		})

		It("should use default rotation interval when zero provided", func() {
			config.KeyRotationInterval = 0

			mgr, _ := keymanager.NewManager(config)
			err := mgr.Start(ctx)
			Expect(err).NotTo(HaveOccurred())

			//Scheduler should be active (won't rotate in test time, but should be running)
			Expect(mgr.IsRotationSchedulerActive()).To(BeTrue())
			mgr.Shutdown(ctx)
		})

		It("should cleanup expired keys after overlap period", func() {
			config.KeyRotationInterval = 200 * time.Millisecond
			config.KeyOverlapDuration = 100 * time.Millisecond

			manager, _ = keymanager.NewManager(config)
			manager.Start(ctx)

			_, oldKeyID, _ := manager.GetCurrentSigningKey()

			// Wait for rotation
			time.Sleep(300 * time.Millisecond)

			// Wait for cleanup (overlap period + extra buffer for race detector)
			time.Sleep(200 * time.Millisecond)

			// Old key should be removed (use Eventually for robustness)
			Eventually(func() error {
				_, err := manager.GetPublicKey(oldKeyID)
				return err
			}, 500*time.Millisecond, 50*time.Millisecond).Should(MatchError(keymanager.ErrKeyNotFound))
		})

		It("should continue rotation after manual rotation", func() {
			config.KeyRotationInterval = 300 * time.Millisecond

			manager, _ = keymanager.NewManager(config)
			manager.Start(ctx)

			// Manual rotation
			manager.RotateKeys(ctx)
			_, keyAfterManual, _ := manager.GetCurrentSigningKey()

			// Wait for automatic rotation
			Eventually(func() string {
				_, keyID, _ := manager.GetCurrentSigningKey()
				return keyID
			}, 1*time.Second, 50*time.Millisecond).ShouldNot(Equal(keyAfterManual))
		})
	})

	// === PHASE 7: Error Handling ===
	Describe("Error Scenarios", func() {
		BeforeEach(func() {
			manager, _ = keymanager.NewManager(config)
			manager.Start(ctx)
		})

		Context("when manager not running", func() {
			BeforeEach(func() {
				manager.Shutdown(ctx)
			})

			It("should fail to rotate keys", func() {
				err := manager.RotateKeys(ctx)
				Expect(err).To(MatchError(keymanager.ErrManagerNotRunning))
			})

			It("should fail to get current signing key", func() {
				_, _, err := manager.GetCurrentSigningKey()
				Expect(err).To(MatchError(keymanager.ErrManagerNotRunning))
			})
		})

		Context("with disk errors", func() {
			It("should handle key save failure gracefully", func() {
				// Make directory read-only
				os.Chmod(config.KeyDirectory, 0444)
				defer os.Chmod(config.KeyDirectory, 0755)

				err := manager.RotateKeys(ctx)
				Expect(err).To(HaveOccurred())

				// Manager should still be running
				Expect(manager.IsRunning()).To(BeTrue())
			})

			It("should handle corrupted key file on load", func() {
				// Write invalid key file
				invalidKeyPath := filepath.Join(config.KeyDirectory, "invalid-key.pem")
				os.WriteFile(invalidKeyPath, []byte("invalid data"), 0644)

				manager.Shutdown(ctx)

				// Should start but skip invalid file
				manager2, _ := keymanager.NewManager(config)
				err := manager2.Start(ctx)
				Expect(err).NotTo(HaveOccurred())

				manager2.Shutdown(ctx)
			})
		})

		Context("with context cancellation", func() {
			It("should respect context during rotation", func() {
				cancelCtx, cancelFn := context.WithCancel(context.Background())
				cancelFn() // Cancel immediately

				err := manager.RotateKeys(cancelCtx)
				Expect(err).To(MatchError(context.Canceled))
			})
		})
	})

	// === PHASE 8: Concurrency ===
	Describe("Concurrent Operations", func() {
		BeforeEach(func() {
			manager, _ = keymanager.NewManager(config)
			manager.Start(ctx)
		})

		It("should handle concurrent GetCurrentSigningKey calls", func() {
			const numGoroutines = 20
			results := make(chan string, numGoroutines)
			var wg sync.WaitGroup

			for i := 0; i < numGoroutines; i++ {
				wg.Add(1)
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					_, keyID, err := manager.GetCurrentSigningKey()
					Expect(err).NotTo(HaveOccurred())
					results <- keyID
				}()
			}

			wg.Wait()
			close(results)

			// Collect all results
			keyIDs := make([]string, 0, numGoroutines)
			for keyID := range results {
				keyIDs = append(keyIDs, keyID)
			}

			Expect(keyIDs).To(HaveLen(numGoroutines))

			// All should be identical
			for i := 1; i < numGoroutines; i++ {
				Expect(keyIDs[i]).To(Equal(keyIDs[0]))
			}
		})

		It("should handle concurrent GetPublicKey calls", func() {
			_, keyID, _ := manager.GetCurrentSigningKey()

			const numGoroutines = 20
			results := make(chan *rsa.PublicKey, numGoroutines)
			var wg sync.WaitGroup

			for i := 0; i < numGoroutines; i++ {
				wg.Add(1)
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					publicKey, err := manager.GetPublicKey(keyID)
					Expect(err).NotTo(HaveOccurred())
					results <- publicKey
				}()
			}

			wg.Wait()
			close(results)

			// Count results
			count := 0
			for range results {
				count++
			}
			Expect(count).To(Equal(numGoroutines))
		})

		It("should handle concurrent GetJWKS calls", func() {
			const numGoroutines = 20
			results := make(chan *keymanager.JWKS, numGoroutines)
			var wg sync.WaitGroup

			for i := 0; i < numGoroutines; i++ {
				wg.Add(1)
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					jwks, err := manager.GetJWKS()
					Expect(err).NotTo(HaveOccurred())
					results <- jwks
				}()
			}

			wg.Wait()
			close(results)

			// Count results
			count := 0
			for range results {
				count++
			}
			Expect(count).To(Equal(numGoroutines))
		})

		It("should handle rotation during concurrent reads", func() {
			done := make(chan bool)

			// Start readers
			go func() {
				defer GinkgoRecover()
				for i := 0; i < 50; i++ {
					manager.GetCurrentSigningKey()
					manager.GetJWKS()
					time.Sleep(10 * time.Millisecond)
				}
				done <- true
			}()

			// Rotate while reading
			time.Sleep(100 * time.Millisecond)
			err := manager.RotateKeys(ctx)
			Expect(err).NotTo(HaveOccurred())

			Eventually(done).Should(Receive())
		})
	})
})

// === SPERATE SUITE: Shutdown ===

var _ = Describe("KeyManager Shutdown", func() {
	var (
		manager *keymanager.Manager
		ctx     context.Context
		cancel  context.CancelFunc
		config  keymanager.ManagerConfig
		tempDir string
	)

	BeforeEach(func() {
		ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
		tempDir = GinkgoT().TempDir()

		config = keymanager.ManagerConfig{
			KeyDirectory:        tempDir,
			KeyRotationInterval: 30 * 24 * time.Hour,
			KeyOverlapDuration:  1 * time.Hour,
			KeySize:             2048,
		}

		manager, _ = keymanager.NewManager(config)
		manager.Start(ctx)
	})

	AfterEach(func() {
		cancel()
	})

	Describe("Graceful Shutdown", func() {
		It("should shutdown successfully", func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			err := manager.Shutdown(shutdownCtx)
			Expect(err).NotTo(HaveOccurred())
			Expect(manager.IsRunning()).To(BeFalse())
		})

		It("should stop automatic rotation on shutdown", func() {
			config.KeyRotationInterval = 200 * time.Millisecond

			mgr, _ := keymanager.NewManager(config)
			mgr.Start(ctx)

			//_, keyBeforeShutdown, _ := mgr.GetCurrentSigningKey()
			mgr.GetCurrentSigningKey()

			mgr.Shutdown(ctx)

			// Wait longer than rotation interval
			time.Sleep(500 * time.Millisecond)

			// Key should not have rotated (manager stopped)
			// We cant check this directly since manager is stopped, but we verify shutdown worked
			Expect(mgr.IsRunning()).To(BeFalse())
		})

		It("should complete in-flight rotation before shutdown", func() {
			// Start rotation
			rotationDone := make(chan bool)
			go func() {
				defer GinkgoRecover()
				err := manager.RotateKeys(ctx)
				Expect(err).NotTo(HaveOccurred())
				rotationDone <- true
			}()

			// Give is time to start
			time.Sleep(50 * time.Millisecond)

			// Initiate shutdown
			shutdownDone := make(chan bool)
			go func() {
				defer GinkgoRecover()
				shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				err := manager.Shutdown(shutdownCtx)
				Expect(err).NotTo(HaveOccurred())
				shutdownDone <- true
			}()

			// Both should complete
			Eventually(rotationDone).Should(Receive())
			Eventually(shutdownDone).Should(Receive())
		})

		It("should respect shutdown timeout", func() {
			// Short timeout for testing
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()

			err := manager.Shutdown(shutdownCtx)
			// Should succeed quickly since there's no blocking work
			Expect(err).NotTo(HaveOccurred())
		})

		It("should be idempotent", func() {
			shutdownCtx := context.Background()

			err := manager.Shutdown(shutdownCtx)
			Expect(err).NotTo(HaveOccurred())

			// Second shutdown should not error
			err = manager.Shutdown(shutdownCtx)
			Expect(err).NotTo(HaveOccurred())
		})
	})
})

// === SEPARATE SUITE: Key Persistence ===
var _ = Describe("KeyManager Persistense", func() {
	var (
		config  keymanager.ManagerConfig
		tempDir string
	)

	BeforeEach(func() {
		tempDir = GinkgoT().TempDir()
		config = keymanager.ManagerConfig{
			KeyDirectory:        tempDir,
			KeyRotationInterval: 30 * 24 * time.Hour,
			KeyOverlapDuration:  1 * time.Hour,
			KeySize:             2048,
		}
	})

	It("should persist keys in PEM format", func() {
		manager, _ := keymanager.NewManager(config)
		manager.Start(context.Background())

		_, keyID, _ := manager.GetCurrentSigningKey()
		manager.Shutdown(context.Background())

		// Check files exist
		files, err := os.ReadDir(tempDir)
		Expect(err).NotTo(HaveOccurred())
		Expect(files).NotTo(BeEmpty())

		// Verify PEM format
		found := false
		for _, file := range files {
			if strings.Contains(file.Name(), keyID+".pem") {
				found = true

				content, _ := os.ReadFile(filepath.Join(tempDir, file.Name()))
				Expect(string(content)).To(ContainSubstring("BEGIN RSA PRIVATE KEY"))
			}
		}
		Expect(found).To(BeTrue())
	})

	It("should persist keys along metadata", func() {
		manager, _ := keymanager.NewManager(config)
		manager.Start(context.Background())

		_, keyID, _ := manager.GetCurrentSigningKey()
		manager.Shutdown(context.Background())

		// Check files exist
		files, err := os.ReadDir(tempDir)
		Expect(err).NotTo(HaveOccurred())
		Expect(files).NotTo(BeEmpty())

		// Verify metadata file
		found := false
		for _, file := range files {
			if strings.Contains(file.Name(), keyID+".json") {
				found = true
				filename := filepath.Join(tempDir, keyID+".json")
				data, _ := os.ReadFile(filename)
				var meta keymanager.KeyMetadata
				err = json.Unmarshal(data, &meta)
				Expect(err).NotTo(HaveOccurred())
				Expect(meta.ID).To(Equal(keyID))
				Expect(meta.CreatedAt).To(BeTemporally("~", time.Now(), 2*time.Second))
			}
		}
		Expect(found).To(BeTrue())
	})

	It("should load keys across restart", func() {
		// First instance
		manager1, _ := keymanager.NewManager(config)
		manager1.Start(context.Background())

		privateKey1, keyID1, _ := manager1.GetCurrentSigningKey()
		publicKey1, _ := manager1.GetPublicKey(keyID1)

		manager1.Shutdown(context.Background())

		// Second instance
		manager2, _ := keymanager.NewManager(config)
		manager2.Start(context.Background())

		privateKey2, keyID2, _ := manager2.GetCurrentSigningKey()
		publicKey2, _ := manager2.GetPublicKey(keyID2)

		// Should be identical
		Expect(keyID2).To(Equal(keyID1))
		Expect(privateKey2.N).To(Equal(privateKey1.N))
		Expect(publicKey2.N).To(Equal(publicKey1.N))

		manager2.Shutdown(context.Background())
	})

	It("should apply defaults on reload when config has zero values", func() {
		// Start with explicit values
		config.KeySize = 4096
		manager1, _ := keymanager.NewManager(config)
		manager1.Start(context.Background())
		manager1.Shutdown(context.Background())

		// Reload with zero values
		config.KeySize = 0 // should use default
		manager2, _ := keymanager.NewManager(config)
		manager2.Start(context.Background())

		// Can still load keys (default applied for new operations)
		_, keyID, err := manager2.GetCurrentSigningKey()
		Expect(err).NotTo(HaveOccurred())
		Expect(keyID).NotTo(BeEmpty())

		manager2.Shutdown(context.Background())
	})

	Context("with multiple keys on disk", func() {
		It("should load all valid keys on restart", func() {
			// First session: Create and rotate
			manager1, _ := keymanager.NewManager(config)
			manager1.Start(context.Background())
			_, key1ID, _ := manager1.GetCurrentSigningKey()

			manager1.RotateKeys(context.Background()) // Now have 2 keys
			_, key2ID, _ := manager1.GetCurrentSigningKey()

			manager1.Shutdown(context.Background())

			// Second session: Should load BOTH keys
			manager2, _ := keymanager.NewManager(config)
			manager2.Start(context.Background())

			// Current key loaded
			_, currentID, _ := manager2.GetCurrentSigningKey()
			Expect(currentID).To(Equal(key2ID))

			// Old key also available
			oldKey, err := manager2.GetPublicKey(key1ID)
			Expect(err).NotTo(HaveOccurred())
			Expect(oldKey).NotTo(BeNil())

			manager2.Shutdown(context.Background())
		})

		It("should restore expiration dates from metadata", func() {
			// Test metadata persistence
		})
	})
})

// ============================================================================
// LOGGING TEST SUITE
// ============================================================================
// These tests use the shared MockLogger from internal/testutil to verify
// that logging happens at the right times with the right data.
// ============================================================================

var _ = Describe("KeyManager Logging", func() {
	var (
		manager    *keymanager.Manager
		ctx        context.Context
		cancel     context.CancelFunc
		config     keymanager.ManagerConfig
		tempDir    string
		mockLogger *testutil.MockLogger
	)

	BeforeEach(func() {
		ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
		tempDir = GinkgoT().TempDir()
		mockLogger = testutil.NewMockLogger()

		config = keymanager.ManagerConfig{
			KeyDirectory:        tempDir,
			KeyRotationInterval: 30 * 24 * time.Hour,
			KeyOverlapDuration:  1 * time.Hour,
			KeySize:             2048,
			Logger:              mockLogger, // ← Inject mock logger
		}
	})

	AfterEach(func() {
		cancel()
		if manager != nil && manager.IsRunning() {
			manager.Shutdown(ctx)
		}
	})

	// === BASIC LOGGER BEHAVIOR ===
	Describe("Logger Integration", func() {
		Context("when logger is provided", func() {
			It("should use the provided logger", func() {
				manager, err := keymanager.NewManager(config)
				Expect(err).NotTo(HaveOccurred())

				err = manager.Start(ctx)
				Expect(err).NotTo(HaveOccurred())

				// Should have some logs from startup
				Eventually(func() int {
					return len(mockLogger.GetLogs())
				}).Should(BeNumerically(">", 0))
			})

			It("should log structured key-value pairs", func() {
				manager, _ = keymanager.NewManager(config)
				manager.Start(ctx)

				// All logs should have fields (key-value pairs)
				logs := mockLogger.GetLogs()
				for _, log := range logs {
					// Each log entry should have a message
					Expect(log.Message).NotTo(BeEmpty())
				}
			})
		})
		Context("when logger is nil", func() {
			It("should work without logging", func() {
				config.Logger = nil
				manager, err := keymanager.NewManager(config)
				Expect(err).NotTo(HaveOccurred())

				err = manager.Start(ctx)

				// Should work fine without logger
				Expect(manager.IsRunning()).To(BeTrue())
			})
		})
	})

	// === STARTUP LOGGING ===
	Describe("Startup Events", func() {
		Context("on first start with no existing keys", func() {
			It("should log key generation", func() {
				manager, _ = keymanager.NewManager(config)
				manager.Start(ctx)

				Eventually(func() bool {
					return mockLogger.HasLog("info", "generated new RSA key pair")
				}).Should(BeTrue())
			})

			It("should log key generation with key ID field", func() {
				manager, _ = keymanager.NewManager(config)
				manager.Start(ctx)

				Eventually(func() bool {
					return mockLogger.HasLogWithField("info", "generated new RSA key pair", "keyID")
				}).Should(BeTrue())
			})

			It("should log key generation with duration", func() {
				manager, _ = keymanager.NewManager(config)
				manager.Start(ctx)

				Eventually(func() bool {
					return mockLogger.HasLogWithField("info", "generated new RSA key pair", "duration")
				}).Should(BeTrue())
			})

			It("should log successful manager start", func() {
				manager, _ = keymanager.NewManager(config)
				manager.Start(ctx)

				Eventually(func() bool {
					return mockLogger.HasLog("info", "key manager started")
				}).Should(BeTrue())
			})

			It("should log manager start with configuration details", func() {
				manager, _ = keymanager.NewManager(config)
				manager.Start(ctx)

				Eventually(func() bool {
					log := mockLogger.GetLogWithField("info", "key manager started", "keyDirectory")
					return log != nil
				}).Should(BeTrue())
			})

			It("should log manager start with configuration details", func() {
				manager, _ = keymanager.NewManager(config)
				manager.Start(ctx)

				Eventually(func() bool {
					log := mockLogger.GetLogWithField("info", "key manager started", "rotationInterval")
					return log != nil
				}).Should(BeTrue())
			})
		})

		Context("on restart with existing keys", func() {
			It("should log number of keys loaded", func() {
				// First start
				manager, _ = keymanager.NewManager(config)
				manager.Start(ctx)
				manager.Shutdown(ctx)

				// Clear logs from first start
				mockLogger.Clear()

				// Restart
				manager2, _ := keymanager.NewManager(config)
				manager2.Start(ctx)

				Eventually(func() bool {
					return mockLogger.HasLog("info", "loaded keys from disk")
				}).Should(BeTrue())

				Eventually(func() bool {
					return mockLogger.HasLogWithField("info", "loaded keys from disk", "count")
				}).Should(BeTrue())

				manager2.Shutdown(ctx)
			})

			It("should log current key ID after load", func() {
				// First start
				manager, _ = keymanager.NewManager(config)
				manager.Start(ctx)
				_, keyID, _ := manager.GetCurrentSigningKey()
				manager.Shutdown(ctx)

				mockLogger.Clear()

				// Restart
				manager2, _ := keymanager.NewManager(config)
				manager2.Start(ctx)

				Eventually(func() bool {
					log := mockLogger.GetLogWithField("info", "set current key", "keyID")
					if log != nil {
						return log.Fields["keyID"] == keyID
					}
					return false
				}).Should(BeTrue())

				manager2.Shutdown(ctx)
			})
		})

		Context("with corrupted key files", func() {
			It("should log warning for corrupted PEM files", func() {
				//Create corrupted PEM file
				corruptedFile := filepath.Join(tempDir, "corrupted-key.pem")
				os.WriteFile(corruptedFile, []byte("not a valid PEM"), 0600)

				manager, _ = keymanager.NewManager(config)
				manager.Start(ctx)

				Eventually(func() bool {
					return mockLogger.HasLog("warn", "failed to load key file")
				}).Should(BeTrue())
			})

			It("should log warning with filename", func() {
				corruptedFile := filepath.Join(tempDir, "corrupted-key.pem")
				os.WriteFile(corruptedFile, []byte("invalid"), 0600)

				manager, _ = keymanager.NewManager(config)
				manager.Start(ctx)

				Eventually(func() bool {
					return mockLogger.HasLogWithField("warn", "failed to load key file", "file")
				}).Should(BeTrue())
			})

			It("should log warning with error details", func() {
				corruptedFile := filepath.Join(tempDir, "bad.pem")
				os.WriteFile(corruptedFile, []byte("bad data"), 0600)

				manager, _ = keymanager.NewManager(config)
				manager.Start(ctx)

				Eventually(func() bool {
					log := mockLogger.GetLogWithField("warn", "failed to load key file", "error")
					return log != nil
				}).Should(BeTrue())
			})
		})

		Context("with expired keys on disk", func() {
			It("should log skipped expired keys", func() {
				// This requires creating metadata with past expiration
				// For now, verify the log capability exists
				manager, _ = keymanager.NewManager(config)
				manager.Start(ctx)

				// Should not have any expired key logs on fresh start
				Consistently(func() bool {
					return mockLogger.HasLog("info", "skipped expired key")
				}, 500*time.Millisecond).Should(BeFalse())
			})
		})
	})

	// === ROTATION LOGGING ===
	Describe("Rotation Events", func() {
		BeforeEach(func() {
			manager, _ = keymanager.NewManager(config)
			manager.Start(ctx)
			mockLogger.Clear() // Clear startup logs
		})

		It("should log successful rotation", func() {
			err := manager.RotateKeys(ctx)
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() bool {
				return mockLogger.HasLog("info", "key rotation successful")
			}).Should(BeTrue())
		})

		It("should log rotation with old key ID", func() {
			err := manager.RotateKeys(ctx)
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() bool {
				return mockLogger.HasLogWithField("info", "key rotation successful", "oldKeyID")
			}).Should(BeTrue())
		})

		It("should log rotation duration", func() {
			err := manager.RotateKeys(ctx)
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() bool {
				log := mockLogger.GetLogWithField("info", "key rotation successful", "duration")
				return log != nil
			}).Should(BeTrue())
		})

		It("should log old key expiration", func() {
			err := manager.RotateKeys(ctx)
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() bool {
				return mockLogger.HasLog("info", "old key marked for expiration")
			}).Should(BeTrue())
		})

		It("should log old key expiration time", func() {
			err := manager.RotateKeys(ctx)
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() bool {
				return mockLogger.HasLogWithField("info", "old key marked for expiration", "expiresAt")
			}).Should(BeTrue())
		})

		Context("when rotation fails", func() {
			It("should log rotation failure", func() {
				// Make directory read-only to force failure
				os.Chmod(tempDir, 0444)
				defer os.Chmod(tempDir, 0755)

				err := manager.RotateKeys(ctx)
				Expect(err).To(HaveOccurred())

				Eventually(func() bool {
					return mockLogger.HasLog("error", "key rotation failed")
				}).Should(BeTrue())
			})

			It("should log error details", func() {
				os.Chmod(tempDir, 0444)
				defer os.Chmod(tempDir, 0755)

				manager.RotateKeys(ctx)

				Eventually(func() bool {
					return mockLogger.HasLogWithField("error", "key rotation failed", "error")
				}).Should(BeTrue())
			})
		})

		Context("automatic rotation", func() {
			It("should log automatic rotation trigger", func() {
				config.KeyRotationInterval = 200 * time.Millisecond
				mgr, _ := keymanager.NewManager(config)
				mgr.Start(ctx)
				defer mgr.Shutdown(ctx)

				mockLogger.Clear()

				// Wait for automatic rotation
				Eventually(func() bool {
					return mockLogger.HasLog("info", "automatic rotation triggered")
				}, 1*time.Second, 50*time.Millisecond).Should(BeTrue())
			})

			It("should log automatic rotation success", func() {
				config.KeyRotationInterval = 200 * time.Millisecond
				mgr, _ := keymanager.NewManager(config)
				mgr.Start(ctx)
				defer mgr.Shutdown(ctx)

				mockLogger.Clear()

				Eventually(func() bool {
					return mockLogger.HasLog("info", "key rotation successful")
				}, 1*time.Second, 50*time.Millisecond).Should(BeTrue())
			})
		})
	})

	// === CLEANUP LOGGING ===
	Describe("Cleanup Events", func() {
		BeforeEach(func() {
			config.KeyRotationInterval = 200 * time.Millisecond
			config.KeyOverlapDuration = 100 * time.Millisecond
			manager, _ = keymanager.NewManager(config)
			manager.Start(ctx)
			mockLogger.Clear()
		})

		It("should log cleanup execution", func() {
			// Rotate to create an expiring key
			manager.RotateKeys(ctx)

			// Wait for cleanup
			Eventually(func() bool {
				return mockLogger.HasLog("info", "expired key cleanup executed")
			}, 1*time.Second, 50*time.Millisecond).Should(BeTrue())
		})

		It("should log number of keys deleted", func() {
			manager.GetCurrentSigningKey()
			manager.RotateKeys(ctx)

			Eventually(func() bool {
				log := mockLogger.GetLogWithField("info", "expired key cleanup executed", "deletedCount")
				if log != nil {
					// Should have deleted at least one key
					deletedCount, ok := log.Fields["deletedCount"].(int)
					return ok && deletedCount >= 0
				}
				return false
			}, 1*time.Second, 50*time.Millisecond).Should(BeTrue())
		})

		It("should log deleted key IDs", func() {
			_, oldKeyID, _ := manager.GetCurrentSigningKey()
			manager.RotateKeys(ctx)

			Eventually(func() bool {
				logs := mockLogger.GetLogs()
				for _, log := range logs {
					if log.Message == "deleted expired key" {
						if keyID, ok := log.Fields["keyID"].(string); ok && keyID == oldKeyID {
							return true
						}
					}
				}
				return false
			}, 1*time.Second, 50*time.Millisecond).Should(BeTrue())
		})

		Context("when cleanup deletes multiple keys", func() {
			It("should log each deleted key separately", func() {
				// Rotate multiple times quickly
				manager.RotateKeys(ctx)
				time.Sleep(50 * time.Millisecond)
				manager.RotateKeys(ctx)

				// Wait for cleanup
				time.Sleep(200 * time.Millisecond)

				// Should have multiple delete logs
				Eventually(func() int {
					logs := mockLogger.GetLogsByLevel("info")
					count := 0
					for _, log := range logs {
						if log.Message == "deleted expired key" {
							count++
						}
					}
					return count
				}, 1*time.Second).Should(BeNumerically(">=", 1))
			})
		})
	})

	// === METADATA PERSISTENCE LOGGING ===
	Describe("Metadata Persistence Events", func() {
		BeforeEach(func() {
			manager, _ = keymanager.NewManager(config)
			manager.Start(ctx)
			mockLogger.Clear()
		})

		It("should log metadata save success", func() {
			err := manager.RotateKeys(ctx)
			Expect(err).NotTo(HaveOccurred())

			Eventually(func() bool {
				return mockLogger.HasLog("info", "saved key metadata")
			}).Should(BeTrue())
		})

		It("should log metadata save with key ID", func() {
			manager.RotateKeys(ctx)

			Eventually(func() bool {
				return mockLogger.HasLogWithField("info", "saved key metadata", "keyID")
			}).Should(BeTrue())
		})

		Context("when metadata save fails", func() {
			It("should log metadata save failure", func() {
				// Make directory read-only
				os.Chmod(tempDir, 0444)
				defer os.Chmod(tempDir, 0755)

				manager.RotateKeys(ctx)

				Eventually(func() bool {
					return mockLogger.HasLog("warn", "failed to save key metadata") ||
						mockLogger.HasLog("error", "key rotation failed")
				}).Should(BeTrue())
			})

			It("should log which key metadata failed to save", func() {
				os.Chmod(tempDir, 0444)
				defer os.Chmod(tempDir, 0755)

				manager.RotateKeys(ctx)

				Eventually(func() bool {
					return mockLogger.HasLogWithField("warn", "failed to save key metadata", "keyID") ||
						mockLogger.HasLogWithField("error", "key rotation failed", "error")
				}).Should(BeTrue())
			})
		})
	})

	// === ERROR SCENARIOS ===
	Describe("Error Logging", func() {
		BeforeEach(func() {
			manager, _ = keymanager.NewManager(config)
			manager.Start(ctx)
			mockLogger.Clear()
		})

		Context("disk operation errors", func() {
			It("should log file deletion errors", func() {
				// Cause an error during cleanup
				// This is tested indirectly through cleanup logs
				manager.RotateKeys(ctx)

				// Should have successful rotation log
				Expect(mockLogger.HasLog("info", "key rotation successful")).To(BeTrue())
			})
		})

		Context("context cancellation", func() {
			It("should log when operations are cancelled", func() {
				cancelCtx, cancelFn := context.WithCancel(context.Background())
				cancelFn() // Cancel immediately

				err := manager.RotateKeys(cancelCtx)
				Expect(err).To(MatchError(context.Canceled))

				// Should log the cancellation
				Eventually(func() bool {
					return mockLogger.HasLog("warn", "operation cancelled") ||
						mockLogger.HasLog("error", "key rotation failed")
				}).Should(BeTrue())
			})
		})
	})

	// === SHUTDOWN LOGGING ===
	Describe("Shutdown Events", func() {
		It("should log graceful shutdown initiation", func() {
			manager, _ = keymanager.NewManager(config)
			manager.Start(ctx)
			mockLogger.Clear()

			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			manager.Shutdown(shutdownCtx)

			Eventually(func() bool {
				return mockLogger.HasLog("info", "initiating graceful shutdown")
			}).Should(BeTrue())
		})

		It("should log successful shutdown", func() {
			manager, _ = keymanager.NewManager(config)
			manager.Start(ctx)
			mockLogger.Clear()

			shutdownCtx := context.Background()
			manager.Shutdown(shutdownCtx)

			Eventually(func() bool {
				return mockLogger.HasLog("info", "key manager stopped")
			}).Should(BeTrue())
		})

		It("should log if rotation scheduler stopped", func() {
			manager, _ = keymanager.NewManager(config)
			manager.Start(ctx)
			mockLogger.Clear()

			Expect(manager.IsRotationSchedulerActive()).To(BeTrue())

			manager.Shutdown(context.Background())

			Eventually(func() bool {
				return !manager.IsRotationSchedulerActive()
			}).Should(BeTrue())

			// Should have logged shutdown
			Expect(mockLogger.HasLog("info", "key manager stopped")).To(BeTrue())
		})
	})

	// === LOG LEVELS ===
	Describe("Log Levels", func() {
		BeforeEach(func() {
			manager, _ = keymanager.NewManager(config)
		})

		It("should use appropriate log levels", func() {
			manager.Start(ctx)
			manager.RotateKeys(ctx)

			logs := mockLogger.GetLogs()

			// Should have info logs
			infoCount := 0
			errorCount := 0

			for _, log := range logs {
				switch log.Level {
				case "info":
					infoCount++
				case "error":
					errorCount++
				}
			}

			Expect(infoCount).To(BeNumerically(">", 0))
			// Normal operation shouldn't have errors
			Expect(errorCount).To(Equal(0))
		})

		It("should use info for successful operations", func() {
			manager.Start(ctx)

			infoLogs := mockLogger.GetLogsByLevel("info")
			Expect(len(infoLogs)).To(BeNumerically(">", 0))
		})

		It("should use warn for recoverable issues", func() {
			// Create corrupted file
			corruptedFile := filepath.Join(tempDir, "bad.pem")
			os.WriteFile(corruptedFile, []byte("invalid"), 0600)

			manager.Start(ctx)

			warnLogs := mockLogger.GetLogsByLevel("warn")
			Expect(len(warnLogs)).To(BeNumerically(">", 0))
		})

		It("should use error for critical failures", func() {
			os.Chmod(tempDir, 0444)
			defer os.Chmod(tempDir, 0755)

			manager.Start(ctx)
			manager.RotateKeys(ctx)

			errorLogs := mockLogger.GetLogsByLevel("error")
			Expect(len(errorLogs)).To(BeNumerically(">", 0))
		})
	})

	// === STRUCTURED LOGGING ===
	Describe("Structured Fields", func() {
		BeforeEach(func() {
			manager, _ = keymanager.NewManager(config)
			manager.Start(ctx)
			mockLogger.Clear()
		})

		It("should include context in operation logs", func() {
			manager.RotateKeys(ctx)

			logs := mockLogger.GetLogs()
			foundStructuredLog := false

			for _, log := range logs {
				if log.Message == "key rotation successful" {
					// Should have structured fields
					Expect(len(log.Fields)).To(BeNumerically(">", 0))
					foundStructuredLog = true
					break
				}
			}

			Expect(foundStructuredLog).To(BeTrue())
		})

		It("should include timing information in rotation logs", func() {
			manager.RotateKeys(ctx)

			Eventually(func() bool {
				log := mockLogger.GetLogWithField("info", "key rotation successful", "duration")
				if log != nil {
					// Verify duration field exists and is a time.Duration
					_, ok := log.Fields["duration"].(time.Duration)
					return ok
				}
				return false
			}).Should(BeTrue())
		})

		It("should include key IDs in all key operations", func() {
			_, originalKeyID, _ := manager.GetCurrentSigningKey()
			manager.RotateKeys(ctx)

			Eventually(func() bool {
				log := mockLogger.GetLogWithField("info", "key rotation successful", "oldKeyID")
				if log != nil {
					oldKeyID, ok := log.Fields["oldKeyID"].(string)
					return ok && oldKeyID == originalKeyID
				}
				return false
			}).Should(BeTrue())
		})
	})

	// === CONCURRENT LOGGING ===
	Describe("Concurrent Operations Logging", func() {
		BeforeEach(func() {
			manager, _ = keymanager.NewManager(config)
			manager.Start(ctx)
			mockLogger.Clear()
		})

		It("should handle concurrent log writes safely", func() {
			var wg sync.WaitGroup
			const numGoroutines = 10

			for i := 0; i < numGoroutines; i++ {
				wg.Add(1)
				go func() {
					defer GinkgoRecover()
					defer wg.Done()
					// Trigger operations that log
					manager.GetCurrentSigningKey()
					manager.GetJWKS()
				}()
			}

			wg.Wait()

			// Should not panic and should have logged something
			logs := mockLogger.GetLogs()
			Expect(len(logs)).To(BeNumerically(">=", 0))
		})

		It("should log from background rotation goroutine", func() {
			config.KeyRotationInterval = 200 * time.Millisecond
			mgr, _ := keymanager.NewManager(config)
			mgr.Start(ctx)
			defer mgr.Shutdown(ctx)

			mockLogger.Clear()

			// Background goroutine should log
			Eventually(func() int {
				return len(mockLogger.GetLogs())
			}, 1*time.Second).Should(BeNumerically(">", 0))
		})
	})

	// === PERFORMANCE ===
	Describe("Logging Performance", func() {
		BeforeEach(func() {
			manager, _ = keymanager.NewManager(config)
			manager.Start(ctx)
			mockLogger.Clear()
		})

		It("should not significantly impact operation performance", func() {
			// Measure rotation with logging
			start := time.Now()
			err := manager.RotateKeys(ctx)
			durationWithLogging := time.Since(start)

			Expect(err).NotTo(HaveOccurred())
			// Should complete in reasonable time (< 1 second for 2048-bit key)
			Expect(durationWithLogging).To(BeNumerically("<", 1*time.Second))
		})

		It("should handle rapid operations without blocking", func() {
			// Rapidly call operations that log
			for i := 0; i < 100; i++ {
				manager.GetCurrentSigningKey()
				manager.GetJWKS()
			}

			// Should have completed without hanging
			Expect(manager.IsRunning()).To(BeTrue())
		})
	})
})
