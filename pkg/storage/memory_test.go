package storage_test

import (
	"github.com/aetomala/jwtauth/internal/testutil"
	"github.com/aetomala/jwtauth/pkg/storage"
)

var _ = RunRefreshStoreTests(
	"MemoryRefreshStore",
	// Factory: creates MemoryRefreshStore
	func(logger *testutil.MockLogger) storage.RefreshStore {
		return storage.NewMemoryRefreshStore(logger)
	},
	// Cleanup: nil (memory needs no cleanup)
	nil,
)
