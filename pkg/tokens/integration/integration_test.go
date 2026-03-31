package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/aetomala/jwtauth/pkg/keymanager"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/aetomala/jwtauth/pkg/tokens"
)

// setupTestService creates a fresh TokenService with real Manager and MemoryRefreshStore
func setupTestService(t *testing.T) (*tokens.Service, *keymanager.Manager, context.Context, string) {
	t.Helper()
	ctx := context.Background()

	tmpDir, err := os.MkdirTemp("", "integration-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	km, err := keymanager.NewManager(keymanager.ManagerConfig{
		KeyDirectory:        tmpDir,
		KeyRotationInterval: 30 * 24 * time.Hour,
		KeySize:             2048,
	})
	if err != nil {
		t.Fatalf("failed to create keymanager: %v", err)
	}
	// Note: Don't call km.Start() here - TokenService.Start() will call it

	store := storage.NewMemoryRefreshStore(nil)

	config := tokens.ServiceConfig{
		KeyManager:           km,
		RefreshStore:         store,
		AccessTokenDuration:  5 * time.Minute,
		RefreshTokenDuration: 1 * time.Hour,
		CleanupInterval:      5 * time.Minute,
		Issuer:               "integration-test",
		Audience:             []string{"integration-test"},
	}

	svc, err := tokens.NewService(config)
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}

	if err := svc.Start(ctx); err != nil {
		t.Fatalf("failed to start service: %v", err)
	}

	return svc, km, ctx, tmpDir
}

func TestFullTokenLifecycle(t *testing.T) {
	svc, km, ctx, tmpDir := setupTestService(t)
	defer func() {
		svc.Shutdown(ctx)
		km.Shutdown(ctx)
		os.RemoveAll(tmpDir)
	}()

	userID := "test-user"

	// Step 1: Issue token pair
	accessToken, refreshToken, err := svc.IssueTokenPair(ctx, userID)
	if err != nil {
		t.Fatalf("IssueTokenPair failed: %v", err)
	}
	if accessToken == "" || refreshToken == "" {
		t.Fatal("tokens should not be empty")
	}

	// Step 2: Validate access token
	claims, err := svc.ValidateAccessToken(ctx, accessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken failed: %v", err)
	}
	if claims.Subject != userID {
		t.Errorf("expected subject %s, got %s", userID, claims.Subject)
	}

	// Step 3: Refresh access token
	newAccessToken, err := svc.RefreshAccessToken(ctx, refreshToken)
	if err != nil {
		t.Fatalf("RefreshAccessToken failed: %v", err)
	}
	if newAccessToken == "" {
		t.Fatal("new access token should not be empty")
	}

	// Step 4: Validate new access token
	newClaims, err := svc.ValidateAccessToken(ctx, newAccessToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken failed: %v", err)
	}
	if newClaims.Subject != userID {
		t.Errorf("expected subject %s, got %s", userID, newClaims.Subject)
	}

	// Step 5: Verify tokens are different
	if accessToken == newAccessToken {
		t.Fatal("access tokens should be different")
	}
}

func TestRefreshTokenRevocation(t *testing.T) {
	svc, km, ctx, tmpDir := setupTestService(t)
	defer func() {
		svc.Shutdown(ctx)
		km.Shutdown(ctx)
		os.RemoveAll(tmpDir)
	}()

	userID := "test-user"

	// Issue a refresh token and then immediately revoke it
	refreshToken, err := svc.IssueRefreshToken(ctx, userID)
	if err != nil {
		t.Fatalf("IssueRefreshToken failed: %v", err)
	}

	// Revoke all user tokens
	if err := svc.RevokeAllUserTokens(ctx, userID); err != nil {
		t.Fatalf("RevokeAllUserTokens failed: %v", err)
	}

	// Attempt to use the revoked token should fail
	_, err = svc.RefreshAccessToken(ctx, refreshToken)
	if err == nil {
		t.Fatal("RefreshAccessToken should fail after revocation")
	}
}

func TestRevokeAllUserTokens(t *testing.T) {
	svc, km, ctx, tmpDir := setupTestService(t)
	defer func() {
		svc.Shutdown(ctx)
		km.Shutdown(ctx)
		os.RemoveAll(tmpDir)
	}()

	userID := "test-user"

	// Step 1: Issue 3 refresh tokens
	token1, err := svc.IssueRefreshToken(ctx, userID)
	if err != nil {
		t.Fatalf("IssueRefreshToken failed: %v", err)
	}

	token2, err := svc.IssueRefreshToken(ctx, userID)
	if err != nil {
		t.Fatalf("IssueRefreshToken failed: %v", err)
	}

	token3, err := svc.IssueRefreshToken(ctx, userID)
	if err != nil {
		t.Fatalf("IssueRefreshToken failed: %v", err)
	}

	// Step 2: Revoke all user tokens
	if err := svc.RevokeAllUserTokens(ctx, userID); err != nil {
		t.Fatalf("RevokeAllUserTokens failed: %v", err)
	}

	// Step 3: All refresh attempts should fail
	if _, err := svc.RefreshAccessToken(ctx, token1); err == nil {
		t.Fatal("RefreshAccessToken should fail for token1")
	}
	if _, err := svc.RefreshAccessToken(ctx, token2); err == nil {
		t.Fatal("RefreshAccessToken should fail for token2")
	}
	if _, err := svc.RefreshAccessToken(ctx, token3); err == nil {
		t.Fatal("RefreshAccessToken should fail for token3")
	}
}

func TestTokenIntrospection(t *testing.T) {
	svc, km, ctx, tmpDir := setupTestService(t)
	defer func() {
		svc.Shutdown(ctx)
		km.Shutdown(ctx)
		os.RemoveAll(tmpDir)
	}()

	userID := "test-user"

	// Issue token pair and validate it works
	accessToken, _, err := svc.IssueTokenPair(ctx, userID)
	if err != nil {
		t.Fatalf("IssueTokenPair failed: %v", err)
	}

	// Introspect the access token
	metadata, err := svc.IntrospectToken(ctx, accessToken)
	if err != nil {
		t.Fatalf("IntrospectToken failed: %v", err)
	}

	// Access tokens validate successfully
	if metadata == nil {
		t.Fatal("metadata should not be nil")
	}
}

func TestServiceNotRunningGuard(t *testing.T) {
	ctx := context.Background()
	tmpDir, _ := os.MkdirTemp("", "integration-test-*")
	defer os.RemoveAll(tmpDir)

	km, _ := keymanager.NewManager(keymanager.ManagerConfig{
		KeyDirectory: tmpDir,
	})
	defer km.Shutdown(ctx)

	// Create a service without starting it
	store := storage.NewMemoryRefreshStore(nil)
	config := tokens.ServiceConfig{
		KeyManager:   km,
		RefreshStore: store,
		Issuer:       "test",
		Audience:     []string{"test"},
	}

	svc, _ := tokens.NewService(config)

	// Operations should fail
	_, err := svc.IssueAccessToken(ctx, "test-user")
	if err == nil {
		t.Fatal("IssueAccessToken should fail when service is not running")
	}
	if err != tokens.ErrServiceNotRunning {
		t.Errorf("expected ErrServiceNotRunning, got %v", err)
	}
}

func TestConcurrentIssuance(t *testing.T) {
	svc, km, ctx, tmpDir := setupTestService(t)
	defer func() {
		svc.Shutdown(ctx)
		km.Shutdown(ctx)
		os.RemoveAll(tmpDir)
	}()

	const goroutineCount = 20
	results := make(chan string, goroutineCount)
	errors := make(chan error, goroutineCount)

	for i := 0; i < goroutineCount; i++ {
		go func(index int) {
			userID := "user-" + string(rune(48+index))
			accessToken, refreshToken, err := svc.IssueTokenPair(ctx, userID)
			if err != nil {
				errors <- err
				return
			}
			results <- accessToken + "|" + refreshToken
		}(i)
	}

	issuedTokens := make(map[string]bool)
	for i := 0; i < goroutineCount; i++ {
		select {
		case err := <-errors:
			t.Errorf("Concurrent issuance error: %v", err)
		case tokens := <-results:
			if tokens == "" {
				t.Fatal("tokens should not be empty")
			}
			issuedTokens[tokens] = true
		}
	}

	if len(issuedTokens) != goroutineCount {
		t.Errorf("expected %d unique token pairs, got %d", goroutineCount, len(issuedTokens))
	}
}

func TestKeyRotationCompatibility(t *testing.T) {
	svc, km, ctx, tmpDir := setupTestService(t)
	defer func() {
		svc.Shutdown(ctx)
		km.Shutdown(ctx)
		os.RemoveAll(tmpDir)
	}()

	userID := "test-user"

	// Step 1: Issue access token
	oldToken, err := svc.IssueAccessToken(ctx, userID)
	if err != nil {
		t.Fatalf("IssueAccessToken failed: %v", err)
	}

	// Step 2: Validate old token
	oldClaims, err := svc.ValidateAccessToken(ctx, oldToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken failed: %v", err)
	}
	if oldClaims.Subject != userID {
		t.Errorf("expected subject %s, got %s", userID, oldClaims.Subject)
	}

	// Step 3: Rotate keys
	if err := km.RotateKeys(ctx); err != nil {
		t.Fatalf("RotateKeys failed: %v", err)
	}

	// Step 4: Validate old token still works
	oldClaimsAfterRotation, err := svc.ValidateAccessToken(ctx, oldToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken failed: %v", err)
	}
	if oldClaimsAfterRotation.Subject != userID {
		t.Errorf("expected subject %s, got %s", userID, oldClaimsAfterRotation.Subject)
	}

	// Step 5: Issue new token and validate
	newToken, err := svc.IssueAccessToken(ctx, userID)
	if err != nil {
		t.Fatalf("IssueAccessToken failed: %v", err)
	}

	newClaims, err := svc.ValidateAccessToken(ctx, newToken)
	if err != nil {
		t.Fatalf("ValidateAccessToken failed: %v", err)
	}
	if newClaims.Subject != userID {
		t.Errorf("expected subject %s, got %s", userID, newClaims.Subject)
	}
}
