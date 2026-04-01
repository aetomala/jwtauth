package storage_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/aetomala/jwtauth/internal/testutil"
	"github.com/aetomala/jwtauth/pkg/storage"
)

func TestMemoryRefreshStore(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Memory Storage Suite")
}

var _ = RunRefreshStoreTests(
	"MemoryRefreshStore",
	// Factory: creates MemoryRefreshStore
	func(logger *testutil.MockLogger) storage.RefreshStore {
		return storage.NewMemoryRefreshStore(logger)
	},
	// Cleanup: nil (memory needs no cleanup)
	nil,
)
