//go:build integration

package integration

import (
	"os"
	"time"

	. "github.com/onsi/gomega"

	"github.com/aetomala/jwtauth/pkg/keymanager"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/aetomala/jwtauth/pkg/tokens"
)

func init() {
	RunTokenManagerIntegrationTests(
		"TokenManager Integration — DiskKeyStore + MemoryRefreshStore",
		diskMemoryFactory,
	)
}

func diskMemoryFactory(cfg tokens.ManagerConfig) (*tokens.Manager, *keymanager.Manager, func()) {
	tmpDir, err := os.MkdirTemp("", "integration-disk-*")
	Expect(err).NotTo(HaveOccurred())

	ks, err := keymanager.NewDiskKeyStore(keymanager.DiskKeyStoreConfig{Dir: tmpDir, KeySize: 2048})
	Expect(err).NotTo(HaveOccurred())

	km, err := keymanager.NewManager(keymanager.ManagerConfig{
		KeyStore:            ks,
		KeyRotationInterval: 30 * 24 * time.Hour,
		KeySize:             2048,
	})
	Expect(err).NotTo(HaveOccurred())

	cfg.KeyManager = km
	cfg.RefreshStore = storage.NewMemoryRefreshStore(nil, nil)

	mgr, err := tokens.NewManager(cfg)
	Expect(err).NotTo(HaveOccurred())

	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	return mgr, km, cleanup
}
