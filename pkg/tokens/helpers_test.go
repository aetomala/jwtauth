package tokens_test

import (
	"time"

	. "github.com/onsi/gomega"

	"github.com/aetomala/jwtauth/internal/testutil"
	"github.com/aetomala/jwtauth/pkg/tokens"
)

func newTestManagerConfig(
	mockKM *testutil.MockKeyManager,
	mockStore *testutil.MockRefreshStore,
	mockLogger *testutil.MockLogger,
) tokens.TokenManagerConfig {
	return tokens.TokenManagerConfig{
		KeyManager:           mockKM,
		RefreshStore:         mockStore,
		Logger:               mockLogger,
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 30 * 24 * time.Hour,
		CleanupInterval:      100 * time.Millisecond,
		Issuer:               "test-issuer",
		Audience:             []string{"test-audience"},
	}
}

func newTestManager(
	mockKM *testutil.MockKeyManager,
	mockStore *testutil.MockRefreshStore,
	mockLogger *testutil.MockLogger,
) *tokens.Manager {
	mgr, err := tokens.NewManager(newTestManagerConfig(mockKM, mockStore, mockLogger))
	Expect(err).NotTo(HaveOccurred())
	return mgr
}
