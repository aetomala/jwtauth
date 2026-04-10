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
	RunTokenServiceIntegrationTests(
		"TokenService Integration — DiskKeyStore + MemoryRefreshStore",
		diskMemoryFactory,
	)
}

func diskMemoryFactory(cfg tokens.ServiceConfig) (*tokens.Service, *keymanager.Manager, func()) {
	tmpDir, err := os.MkdirTemp("", "integration-disk-*")
	Expect(err).NotTo(HaveOccurred())

	ks, err := keymanager.NewDiskKeyStore(tmpDir, 2048, nil, nil)
	Expect(err).NotTo(HaveOccurred())

	km, err := keymanager.NewManager(keymanager.ManagerConfig{
		KeyStore:            ks,
		KeyRotationInterval: 30 * 24 * time.Hour,
		KeySize:             2048,
	})
	Expect(err).NotTo(HaveOccurred())

	cfg.KeyManager = km
	cfg.RefreshStore = storage.NewMemoryRefreshStore(nil, nil)

	svc, err := tokens.NewService(cfg)
	Expect(err).NotTo(HaveOccurred())

	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	return svc, km, cleanup
}
