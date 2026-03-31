//go:build integration

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

func TestTokenExpirationAndCleanup(t *testing.T) {
	svc, km, ctx, tmpDir := setupTestService(t)
	defer func() {
		svc.Shutdown(ctx)
		km.Shutdown(ctx)
		os.RemoveAll(tmpDir)
	}()

	userID := "test-user"

	// Step 1: Create a service with short token duration but long cleanup interval
	// (to test manual cleanup, not background cleanup)
	tmpDir2, _ := os.MkdirTemp("", "cleanup-test-*")
	defer os.RemoveAll(tmpDir2)

	km2, _ := keymanager.NewManager(keymanager.ManagerConfig{
		KeyDirectory: tmpDir2,
	})

	store := storage.NewMemoryRefreshStore(nil)

	shortLivedConfig := tokens.ServiceConfig{
		KeyManager:           km2,
		RefreshStore:         store,
		AccessTokenDuration:  5 * time.Minute,
		RefreshTokenDuration: 100 * time.Millisecond, // Very short for testing
		CleanupInterval:      10 * time.Second,       // Long interval so background cleanup doesn't interfere
		Issuer:               "integration-test",
		Audience:             []string{"integration-test"},
	}

	svc2, err := tokens.NewService(shortLivedConfig)
	if err != nil {
		t.Fatalf("failed to create service: %v", err)
	}
	defer svc2.Shutdown(ctx)

	if err := svc2.Start(ctx); err != nil {
		t.Fatalf("failed to start service: %v", err)
	}

	// Step 2: Issue 3 refresh tokens
	token1, err := svc2.IssueRefreshToken(ctx, userID)
	if err != nil {
		t.Fatalf("IssueRefreshToken failed: %v", err)
	}

	token2, err := svc2.IssueRefreshToken(ctx, userID)
	if err != nil {
		t.Fatalf("IssueRefreshToken failed: %v", err)
	}

	token3, err := svc2.IssueRefreshToken(ctx, userID)
	if err != nil {
		t.Fatalf("IssueRefreshToken failed: %v", err)
	}

	// Step 3: Wait for tokens to expire
	time.Sleep(150 * time.Millisecond)

	// Step 4: Manually run cleanup to remove expired tokens
	count, err := store.Cleanup(ctx)
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}
	if count < 3 {
		t.Errorf("expected at least 3 expired tokens cleaned up, got %d", count)
	}

	// Step 5: Verify expired tokens can no longer be refreshed
	_, err = svc2.RefreshAccessToken(ctx, token1)
	if err == nil {
		t.Fatal("expected RefreshAccessToken to fail for expired token")
	}

	_, err = svc2.RefreshAccessToken(ctx, token2)
	if err == nil {
		t.Fatal("expected RefreshAccessToken to fail for expired token")
	}

	_, err = svc2.RefreshAccessToken(ctx, token3)
	if err == nil {
		t.Fatal("expected RefreshAccessToken to fail for expired token")
	}

	// Step 6: Issue a fresh token and verify it still works
	freshToken, err := svc2.IssueRefreshToken(ctx, userID)
	if err != nil {
		t.Fatalf("IssueRefreshToken failed: %v", err)
	}

	newAccessToken, err := svc2.RefreshAccessToken(ctx, freshToken)
	if err != nil {
		t.Fatalf("RefreshAccessToken failed: %v", err)
	}

	if newAccessToken == "" {
		t.Fatal("new access token should not be empty")
	}
}

func TestMultipleDevicesPerUser(t *testing.T) {
	svc, km, ctx, tmpDir := setupTestService(t)
	defer func() {
		svc.Shutdown(ctx)
		km.Shutdown(ctx)
		os.RemoveAll(tmpDir)
	}()

	userID := "multi-device-user"
	devices := map[string]string{
		"iPhone":  "device-iphone-uuid",
		"Laptop":  "device-laptop-uuid",
		"iPad":    "device-ipad-uuid",
	}
	refreshTokens := make(map[string]string)

	// Step 1: User logs in on 3 different devices
	for deviceName, deviceID := range devices {
		metadata := map[string]interface{}{
			"device":      deviceName,
			"device_id":   deviceID,
			"ip_address":  "192.168.1.100",
			"user_agent":  "Mozilla/5.0 Device:" + deviceName,
		}

		token, err := svc.IssueRefreshTokenWithMetadata(ctx, userID, metadata)
		if err != nil {
			t.Fatalf("IssueRefreshTokenWithMetadata failed for %s: %v", deviceName, err)
		}

		refreshTokens[deviceName] = token
	}

	// Step 2: Each device refreshes independently
	accessTokens := make(map[string]string)
	for deviceName, refreshToken := range refreshTokens {
		accessToken, err := svc.RefreshAccessToken(ctx, refreshToken)
		if err != nil {
			t.Fatalf("RefreshAccessToken failed for %s: %v", deviceName, err)
		}

		// Verify each device gets a unique access token
		if accessToken == "" {
			t.Fatalf("empty access token for %s", deviceName)
		}

		accessTokens[deviceName] = accessToken
	}

	// Step 3: Verify all access tokens are different
	if len(accessTokens) != 3 {
		t.Errorf("expected 3 unique access tokens, got %d", len(accessTokens))
	}

	seenTokens := make(map[string]bool)
	for _, token := range accessTokens {
		if seenTokens[token] {
			t.Fatal("access tokens should be unique per device")
		}
		seenTokens[token] = true
	}

	// Step 4: Validate each access token still works
	for deviceName, accessToken := range accessTokens {
		claims, err := svc.ValidateAccessToken(ctx, accessToken)
		if err != nil {
			t.Fatalf("ValidateAccessToken failed for %s: %v", deviceName, err)
		}
		if claims.Subject != userID {
			t.Errorf("expected subject %s, got %s for %s", userID, claims.Subject, deviceName)
		}
	}

	// Step 5: Revoke all tokens for the user
	err := svc.RevokeAllUserTokens(ctx, userID)
	if err != nil {
		t.Fatalf("RevokeAllUserTokens failed: %v", err)
	}

	// Step 6: Verify all refresh tokens are revoked
	for deviceName, refreshToken := range refreshTokens {
		_, err := svc.RefreshAccessToken(ctx, refreshToken)
		if err == nil {
			t.Fatalf("RefreshAccessToken should fail for revoked token (%s)", deviceName)
		}
	}
}

func TestInvalidRefreshTokenHandling(t *testing.T) {
	svc, km, ctx, tmpDir := setupTestService(t)
	defer func() {
		svc.Shutdown(ctx)
		km.Shutdown(ctx)
		os.RemoveAll(tmpDir)
	}()

	validUserID := "valid-user"

	// Step 1: Issue a valid refresh token for reference
	validToken, err := svc.IssueRefreshToken(ctx, validUserID)
	if err != nil {
		t.Fatalf("IssueRefreshToken failed: %v", err)
	}

	// Step 2: Test malformed refresh token
	malformedToken := "this-is-not-a-valid-token-format"
	_, err = svc.RefreshAccessToken(ctx, malformedToken)
	if err == nil {
		t.Fatal("RefreshAccessToken should fail for malformed token")
	}

	// Step 3: Test expired refresh token
	// Create a service with very short token duration
	tmpDir2, _ := os.MkdirTemp("", "expired-test-*")
	defer os.RemoveAll(tmpDir2)

	km2, _ := keymanager.NewManager(keymanager.ManagerConfig{
		KeyDirectory: tmpDir2,
	})

	store := storage.NewMemoryRefreshStore(nil)

	expiredConfig := tokens.ServiceConfig{
		KeyManager:           km2,
		RefreshStore:         store,
		AccessTokenDuration:  5 * time.Minute,
		RefreshTokenDuration: 50 * time.Millisecond, // Very short
		Issuer:               "integration-test",
		Audience:             []string{"integration-test"},
	}

	svc2, _ := tokens.NewService(expiredConfig)
	defer svc2.Shutdown(ctx)
	svc2.Start(ctx)

	expiredToken, _ := svc2.IssueRefreshToken(ctx, "expired-user")
	time.Sleep(100 * time.Millisecond) // Wait for expiration

	_, err = svc2.RefreshAccessToken(ctx, expiredToken)
	if err == nil {
		t.Fatal("RefreshAccessToken should fail for expired token")
	}

	// Step 4: Test revoked refresh token
	revokeUserID := "revoke-user"
	revokedToken, err := svc.IssueRefreshToken(ctx, revokeUserID)
	if err != nil {
		t.Fatalf("IssueRefreshToken failed: %v", err)
	}

	// Verify token works before revocation
	beforeRevoke, err := svc.RefreshAccessToken(ctx, revokedToken)
	if err != nil {
		t.Fatalf("RefreshAccessToken should work before revocation: %v", err)
	}
	if beforeRevoke == "" {
		t.Fatal("access token should not be empty")
	}

	// Revoke all tokens for this user
	if err := svc.RevokeAllUserTokens(ctx, revokeUserID); err != nil {
		t.Fatalf("RevokeAllUserTokens failed: %v", err)
	}

	// Try to refresh with revoked token - should fail with ErrTokenRevoked
	_, err = svc.RefreshAccessToken(ctx, revokedToken)
	if err == nil {
		t.Fatal("RefreshAccessToken should fail for revoked token")
	}
	if err != tokens.ErrTokenRevoked {
		t.Errorf("expected ErrTokenRevoked, got %v", err)
	}

	// Step 5: Test token for non-existent user (non-existent in the sense it was never issued)
	// Any random token that wasn't issued by this service
	nonExistentToken := "token-that-was-never-issued"
	_, err = svc.RefreshAccessToken(ctx, nonExistentToken)
	if err == nil {
		t.Fatal("RefreshAccessToken should fail for token never issued")
	}

	// Step 6: Verify valid token still works
	newAccessToken, err := svc.RefreshAccessToken(ctx, validToken)
	if err != nil {
		t.Fatalf("RefreshAccessToken failed for valid token: %v", err)
	}
	if newAccessToken == "" {
		t.Fatal("new access token should not be empty")
	}
}
