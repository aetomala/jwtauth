// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"os"
	"time"

	. "github.com/onsi/gomega"

	"github.com/aetomala/jwtauth/pkg/keys"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/aetomala/jwtauth/pkg/tokens"
)

func init() {
	RunTokenManagerIntegrationTests(
		"TokenManager Integration — DiskKeyStore + MemoryRefreshStore",
		diskMemoryFactory,
	)
}

func diskMemoryFactory(cfg tokens.TokenManagerConfig) (*tokens.Manager, *keys.Manager, func()) {
	tmpDir, err := os.MkdirTemp("", "integration-disk-*")
	Expect(err).NotTo(HaveOccurred())

	ks, err := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: tmpDir, KeySize: 2048})
	Expect(err).NotTo(HaveOccurred())

	km, err := keys.NewManager(keys.KeyManagerConfig{
		KeyStore:            ks,
		KeyRotationInterval: 30 * 24 * time.Hour,
		KeySize:             2048,
	})
	Expect(err).NotTo(HaveOccurred())

	cfg.KeyManager = km
	cfg.RefreshStore = storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{})

	mgr, err := tokens.NewManager(cfg)
	Expect(err).NotTo(HaveOccurred())

	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	return mgr, km, cleanup
}
