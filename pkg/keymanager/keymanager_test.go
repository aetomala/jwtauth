package keymanager_test

import (
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
		//manager *keymanager.Manager
		config  keymanager.ManagerConfig
		tempDir string
	)

	BeforeEach(func() {
		tempDir = GinkgoT().TempDir()

		config = keymanager.ManagerConfig{
			KeyDirectory:        tempDir,
			KeyRotationInterval: 30 * 24 * time.Hour, // 30 days
			KeyOverlapDuration:  1 * time.Hour,
			KeySize:             2048,
		}
	})

	AfterEach(func() {
		/*if cancel != nil {
		      cancel()
		  }
		  if manager != nil && manager.IsRunning() {
		      manager.Shutdown(ctx)
		  }*/
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
})
