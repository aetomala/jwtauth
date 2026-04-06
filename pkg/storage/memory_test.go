package storage_test

import (
	"github.com/aetomala/jwtauth/internal/testutil"
	"github.com/aetomala/jwtauth/pkg/metrics"
	"github.com/aetomala/jwtauth/pkg/storage"
)

var _ = RunRefreshStoreTests(
	"MemoryRefreshStore", "memory",
	// Factory: creates MemoryRefreshStore
	func(logger *testutil.MockLogger, m metrics.Metrics) storage.RefreshStore {
		return storage.NewMemoryRefreshStore(logger, m)
	},
	// Cleanup: nil (memory needs no cleanup)
	nil,
)
