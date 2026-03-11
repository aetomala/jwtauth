package tokens

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aetomala/jwtauth/pkg/keymanager"
	"github.com/aetomala/jwtauth/pkg/logging"
	"github.com/aetomala/jwtauth/pkg/ratelimit"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/golang-jwt/jwt/v5"
)

type ServiceConfig struct {
	// Required
	KeyManager   keymanager.KeyManager
	RefreshStore storage.RefreshStore
	RateLimiter  ratelimit.RateLimiter

	// Optional
	Logger               logging.Logger
	AccessTokenDuration  time.Duration
	RefreshTokenDuration time.Duration
	CleanupInterval      time.Duration
	Issuer               string
	Audience             []string
}

type Service struct {
	// ===== Dependencies (Interfaces) =====
	keyManager   keymanager.KeyManager // Crypto operations
	refreshStore storage.RefreshStore  // Token storage
	rateLimiter  ratelimit.RateLimiter // Rate limiting
	logger       logging.Logger        // Optional logging

	// ===== Configuration (Immutable) =====
	accessTokenDuration  time.Duration // e.g., 15 minutes
	refreshTokenDuration time.Duration // e.g., 30 days
	cleanupInterval      time.Duration // e.g., 1 hour
	issuer               string        // JWT "iss" claim
	audience             []string      // JWT "aud" claim

	// ===== State Management ===== (ADD THESE!)
	isRunning    atomic.Bool    // NEW: Thread-safe state
	mu           sync.RWMutex   // NEW: Protects mutable state (if needed)
	shutdownChan chan struct{}  // NEW: Shutdown signal
	wg           sync.WaitGroup // NEW: Goroutine coordination
}

var (
	ErrInvalidUserID       = errors.New("")
	ErrServiceShutdown     = errors.New("")
	ErrRateLimitExceeded   = errors.New("rate limit exceeded")
	ErrAlreadyRunning      = errors.New("service is already running")
	ErrServiceNotRunning   = errors.New("service is not running")
	ErrInvalidToken        = errors.New("invalid token")
	ErrInvalidSignature    = errors.New("invalid signature")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrRefreshTokenExpired = errors.New("refresh token expired")
	ErrTokenRevoked        = errors.New("token revoked")
	ErrTokenNotFound       = errors.New("token not found")
)

func ErrInvalidConfig(msg string) error {
	return errors.New(msg)
}

func ConfigDefault() ServiceConfig {
	return ServiceConfig{
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 30 * 24 * time.Hour,
		CleanupInterval:      1 * time.Hour,
	}
}

const (
	StateStarted int32 = 1
	StateStopped int32 = 0
)

// IsRunning tells caller if the manager is currently running
func (s *Service) IsRunning() bool {
	return s.isRunning.Load()
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.AccessTokenDuration == 0 {
		config.AccessTokenDuration = ConfigDefault().AccessTokenDuration
	}

	if config.RefreshTokenDuration == 0 {
		config.RefreshTokenDuration = ConfigDefault().RefreshTokenDuration
	}

	if config.CleanupInterval == 0 {
		config.CleanupInterval = ConfigDefault().CleanupInterval
	}

	if config.KeyManager == nil {
		return nil, ErrInvalidConfig("KeyManager is required")
	}

	if config.RefreshStore == nil {
		return nil, ErrInvalidConfig("RefreshStore is required")
	}

	if config.RateLimiter == nil {
		return nil, ErrInvalidConfig("RateLimiter is required")
	}

	if config.AccessTokenDuration < 0 {
		return nil, ErrInvalidConfig("AccessTokenDuration must be non-negative")
	}

	if config.RefreshTokenDuration < 0 {
		return nil, ErrInvalidConfig("RefreshTokenDuration must be non-negative")
	}

	if config.CleanupInterval < 0 {
		return nil, ErrInvalidConfig("CleanupInterval must be non-negative")
	}

	s := &Service{
		keyManager:           config.KeyManager,
		refreshStore:         config.RefreshStore,
		rateLimiter:          config.RateLimiter,
		logger:               config.Logger,
		accessTokenDuration:  config.AccessTokenDuration,
		refreshTokenDuration: config.RefreshTokenDuration,
		cleanupInterval:      config.CleanupInterval,
		issuer:               config.Issuer,
		audience:             config.Audience,
		shutdownChan:         make(chan struct{}), // NEW
	}

	// Initialize state
	s.isRunning.Store(false)

	return s, nil
}

func (s *Service) Start(ctx context.Context) error {
	// 1. Check if already running (idempotent)
	if !s.isRunning.CompareAndSwap(false, true) {
		if s.logger != nil {
			s.logger.Warn("start called but service already running")
		}
		return nil // Already running, not an error
	}

	// 2. Log startup
	if s.logger != nil {
		s.logger.Info("starting token service")
	}

	// 3. Start KeyManager (CRITICAL!)
	if err := s.keyManager.Start(ctx); err != nil {
		s.isRunning.Store(false) // Revert state

		if s.logger != nil {
			s.logger.Error("starting token service",
				"error", err)
		}
		return fmt.Errorf("failed to start keymanager: %w", err)
	}

	// 4. Start background cleanup goroutine
	s.wg.Add(1)
	go s.cleanupLoop()

	// 5. Log success
	if s.logger != nil {
		s.logger.Info("token service started")
	}

	return nil
}

func (s *Service) cleanupLoop() {
	defer s.wg.Done()

	// Cleanup at configured interval
	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Cleanup expired refresh tokens
			if count, err := s.refreshStore.Cleanup(); err != nil {
				if s.logger != nil {
					s.logger.Error("refresh token cleanup failed",
						"error", err)
				}
			} else {

				if s.logger != nil {
					s.logger.Info("refresh token cleanup completed",
						"tokens", count)
				}
			}

		case <-s.shutdownChan:
			if s.logger != nil {
				s.logger.Info("cleanup loop stopping")
			}
			return
		}
	}
}

func (s *Service) Shutdown(ctx context.Context) error {
	// 1. Check if running (idempotent)
	if !s.isRunning.CompareAndSwap(true, false) {
		if s.logger != nil {
			s.logger.Warn("shutdown called but service not running")
		}
		return nil // Already stopped, not an error
	}

	// 2. Log shutdown
	if s.logger != nil {
		s.logger.Info("shutting down token service")
	}

	// 3. Signal shutdown to background goroutines
	close(s.shutdownChan)

	// 4. Wait for goroutines with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Goroutines completed
	case <-ctx.Done():
		// Timeout
		if s.logger != nil {
			s.logger.Warn("shutdown timeout waiting for goroutines",
				"error", ctx.Err())
		}
		return ctx.Err()
	}

	// 5. Shutdown KeyManager (CRITICAL!)
	if err := s.keyManager.Shutdown(ctx); err != nil {
		if s.logger != nil {
			s.logger.Error("failed to shutdown keymanager",
				"error", err)
		}
		return fmt.Errorf("failed to shutdown keymanager: %w", err)
	}

	// 6. Log success
	if s.logger != nil {
		s.logger.Info("token service stopped")
	}

	return nil
}

func (s *Service) IssueAccessToken(ctx context.Context, userID string) (string, error) {

	// ===== STEP 1: Validate user id ====
	// validate user ID Split into two to optimize in the event of high volume of invalid requests
	if len(userID) == 0 {
		if s.logger != nil {
			s.logger.Warn("attempted to get token with empty userID")
		}
		return "", ErrInvalidUserID
	}
	if len(strings.TrimSpace(userID)) == 0 {
		if s.logger != nil {
			s.logger.Warn("attempted to get token with empty userID")
		}
		return "", ErrInvalidUserID
	}

	//===== STEP 2: Service State Check =====
	if !s.IsRunning() {
		if s.logger != nil {
			s.logger.Warn("service not running")
		}
		return "", ErrServiceNotRunning
	}
	// ===== STEP 3: Context Check =====
	// Check if context is already cancelled/expired
	// Fail fast if client already disconnected
	if err := ctx.Err(); err != nil {
		if s.logger != nil {
			s.logger.Warn("context cancelled during token issuance",
				"userID", userID,
				"error", err)
		}
		return "", err
	}

	// ===== STEP 4: Rate Limiting =====
	// Prevent abuse by limiting token issuance rate per user
	// Cost of 1 = one request

	allow, err := s.rateLimiter.Allow(userID, 1)

	if err != nil {
		return "", err
	}
	if !allow {
		if s.logger != nil {
			s.logger.Warn("rate limit exceeded",
				"userID", userID)
		}
		return "", ErrRateLimitExceeded
	}

	// ===== STEP 5: Get Signing Key =====
	// Retrieve current private key and its ID from KeyManager
	// The key ID will be included in the JWT header for verification
	privateKey, keyID, err := s.keyManager.GetCurrentSigningKey()
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to get signing key",
				"userID", userID,
				"error", err)
		}
		return "", fmt.Errorf("failed to get signing key: %w", err)
	}

	// ===== STEP 6: Create JWT Claims =====
	now := time.Now()
	expiresAt := now.Add(s.accessTokenDuration)
	// Generate unique token ID (jti claim)
	tokenID, err := generateTokenID()
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to generate token ID",
				"userID", userID,
				"error", err)
		}
		return "", fmt.Errorf("failed to generate token ID: %w", err)
	}

	// Create standard JWT claims
	claims := jwt.RegisteredClaims{
		Subject:   userID,                        // "sub" - who the token is for
		Issuer:    s.issuer,                      // "iss" - who issued the token
		Audience:  s.audience,                    // "aud" - who can use the token
		ExpiresAt: jwt.NewNumericDate(expiresAt), // "exp" - when it expires
		IssuedAt:  jwt.NewNumericDate(now),       // "iat" - when it was issued
		NotBefore: jwt.NewNumericDate(now),       // "nbf" - valid from when
		ID:        tokenID,                       // "jti" - unique token identifier
	}

	// ===== STEP 7: Sign Token =====
	// Create JWT with RS256 algorithm (RSA signature with SHA-256)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Set key ID in header for key rotation support
	// Validators will use this to fetch the correct public key
	token.Header["kid"] = keyID

	// Sign the token with private key
	signedToken, err := token.SignedString(privateKey)

	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to sign token",
				"userID", userID,
				"keyID", keyID,
				"error", err)
		}
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	// ===== STEP 8: Log Success =====
	if s.logger != nil {
		s.logger.Info("access token issued",
			"userID", userID,
			"tokenID", tokenID,
			"keyID", keyID,
			"expiresAt", expiresAt)
	}

	return signedToken, nil
}

func (s *Service) IssueAccessTokenWithClaims(ctx context.Context, userID string, customClaims map[string]interface{}) (string, error) {
	allow, err := s.rateLimiter.Allow(userID, 1)

	if err != nil {
		return "", nil
	}

	if !allow {
		if s.logger != nil {
			s.logger.Warn("rate limit exceeded",
				"userID", userID)
		}
		return "", ErrRateLimitExceeded
	}

	// Get signing key
	privateKey, keyID, err := s.keyManager.GetCurrentSigningKey()
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to get signing key",
				"userID", userID,
				"error", err)
		}
		return "", fmt.Errorf("failed to get signing key: %w", err)
	}

	now := time.Now()
	expiresAt := now.Add(s.accessTokenDuration)
	tokenID, err := generateTokenID()
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to generate token ID",
				"userID", userID,
				"error", err)
		}
		return "", fmt.Errorf("failed to generate token ID: %w", err)
	}

	// Create map claims to support both standard and custom claims
	claims := jwt.MapClaims{
		"sub": userID,
		"iss": s.issuer,
		"aud": s.audience,
		"exp": expiresAt.Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"jti": tokenID,
	}

	// Merge custom claims
	// Custom claims can override standard claims except sub, iss, exp, iat, nbf, jti
	reservedClaims := map[string]bool{
		"sub": true, "iss": true, "exp": true,
		"iat": true, "nbf": true, "jti": true,
	}

	for key, value := range customClaims {
		if !reservedClaims[key] {
			claims[key] = value
		} else {
			if s.logger != nil {
				s.logger.Warn("attempted to override reserved claim",
					"userID", userID,
					"claim", key)
			}
		}
	}

	// Sign token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to sign token with custom claims",
				"userID", userID,
				"keyID", keyID,
				"error", err)
		}
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	// Log success
	if s.logger != nil {
		s.logger.Info("access token with custom claims issued",
			"userID", userID,
			"tokenID", tokenID,
			"keyID", keyID,
			"customClaims", len(customClaims),
			"expiresAt", expiresAt)
	}

	return signedToken, nil
}

func (s *Service) IssueRefreshToken(ctx context.Context, userID string) (string, error) {
	// ===== STEP 1: Validate user id ====
	// validate user ID Split into two to optimize in the event of high volume of invalid requests
	if len(userID) == 0 {
		if s.logger != nil {
			s.logger.Warn("attempted to get token with empty userID")
		}
		return "", ErrInvalidUserID
	}
	if len(strings.TrimSpace(userID)) == 0 {
		if s.logger != nil {
			s.logger.Warn("attempted to get token with empty userID")
		}
		return "", ErrInvalidUserID
	}

	//===== STEP 2: Service State Check =====

	if !s.IsRunning() {
		if s.logger != nil {
			s.logger.Warn("service not running")
		}
		return "", ErrServiceNotRunning
	}

	// ===== STEP 3: Context Check =====
	// Check if context is already cancelled/expired
	// Fail fast if client already disconnected
	if err := ctx.Err(); err != nil {
		if s.logger != nil {
			s.logger.Warn("context cancelled during token issuance",
				"userID", userID,
				"error", err)
		}
		return "", err
	}

	// ===== STEP 4: Rate Limiting =====
	// Prevent abuse by limiting token issuance rate per user
	// Cost of 1 = one request

	allowed, err := s.rateLimiter.Allow(userID, 1)

	if err != nil {
		return "", err
	}
	if !allowed {
		if s.logger != nil {
			s.logger.Warn("rate limit exceeded",
				"userID", userID)
		}
		return "", ErrRateLimitExceeded
	}

	// ==== STEP 5: Generate Refresh Token ======
	// Create cryptographic random token
	// this is an OPAQUE token (not a JWT)
	refreshToken, err := generateRefreshToken()

	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to generate refresh token",
				"userID", userID,
				"error", err)
			return "", fmt.Errorf("failed to generate refresh token: %w", err)
		}
	}

	// ===== STEP 6: Calculate Expiration =====
	now := time.Now()
	expiresAt := now.Add(s.refreshTokenDuration)

	// ===== STEP 7: Store Token =====
	// Store token with metadata in RefreshStore
	// This allows:
	//   - Token validation during refresh
	//   - Token revocation
	//   - User session tracking
	//   - Audit trails
	err = s.refreshStore.Store(
		refreshToken, // Token ID (the token itself is the ID)
		userID,       // Who owns the token
		expiresAt,    // When it expires
		nil,          // No metadata (use IssueRefreshTokenWithMetadata for metadata)
	)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to store refresh token",
				"userID", userID,
				"error", err)
		}
		return "", fmt.Errorf("failed to store refresh token: %w", err)
	}

	// ========== STEP 8: Log Success =============
	if s.logger != nil {
		s.logger.Info("refresh token issued",
			"userID", userID,
			"tokenID", refreshToken,
			expiresAt, expiresAt)
	}

	return refreshToken, nil
}

func (s *Service) IssueRefreshTokenWithMetadata(ctx context.Context, userID string, metadata map[string]interface{}) (string, error) {
	// ===== STEP 1: Validate user id ====
	// validate user ID Split into two to optimize in the event of high volume of invalid requests
	if len(userID) == 0 {
		if s.logger != nil {
			s.logger.Warn("attempted to get token with empty userID")
		}
		return "", ErrInvalidUserID
	}
	if len(strings.TrimSpace(userID)) == 0 {
		if s.logger != nil {
			s.logger.Warn("attempted to get token with empty userID")
		}
		return "", ErrInvalidUserID
	}

	//===== STEP 2: Service State Check =====
	if !s.IsRunning() {
		if s.logger != nil {
			s.logger.Warn("service not running")
		}
		return "", ErrServiceNotRunning
	}

	// ===== STEP 3: Context Check =====
	// Check if context is already cancelled/expired
	// Fail fast if client already disconnected
	if err := ctx.Err(); err != nil {
		if s.logger != nil {
			s.logger.Warn("context cancelled during token issuance",
				"userID", userID,
				"error", err)
		}
		return "", err
	}

	// ===== STEP 4: Rate Limiting =====
	// Prevent abuse by limiting token issuance rate per user
	// Cost of 1 = one request

	allowed, err := s.rateLimiter.Allow(userID, 1)

	if err != nil {
		return "", err
	}
	if !allowed {
		if s.logger != nil {
			s.logger.Warn("rate limit exceeded",
				"userID", userID)
		}
		return "", ErrRateLimitExceeded
	}

	// ==== STEP 5: Generate Refresh Token ======
	// Create cryptographic random token
	// this is an OPAQUE token (not a JWT)
	refreshToken, err := generateRefreshToken()

	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to generate refresh token",
				"userID", userID,
				"error", err)
			return "", fmt.Errorf("failed to generate refresh token: %w", err)
		}
	}

	// ===== STEP 6: Calculate Expiration =====
	now := time.Now()
	expiresAt := now.Add(s.refreshTokenDuration)

	// ===== STEP 7: Store Token =====
	// Store token with metadata in RefreshStore
	// This allows:
	//   - Token validation during refresh
	//   - Token revocation
	//   - User session tracking
	//   - Audit trails
	err = s.refreshStore.Store(
		refreshToken, // Token ID (the token itself is the ID)
		userID,       // Who owns the token
		expiresAt,    // When it expires
		metadata,     // Custom metadata
	)

	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to store refresh token with metadata",
				"userID", userID,
				"error", err)
		}
		return "", fmt.Errorf("failed to store refresh token with metadata: %w", err)
	}

	// ========== STEP 8: Log Success =============
	if s.logger != nil {
		s.logger.Info("refresh token with metadata issued",
			"userID", userID,
			"tokenID", refreshToken,
			expiresAt, expiresAt,
			"metadataKeys", getMapKeys(metadata))

	}
	return refreshToken, nil
}

func (s *Service) IssueTokenPair(ctx context.Context, userID string) (string, string, error) {
	// ===== STEP 1: Validate user id ====
	// validate user ID Split into two to optimize in the event of high volume of invalid requests
	if len(userID) == 0 {
		if s.logger != nil {
			s.logger.Warn("attempted to get token with empty userID")
		}
		return "", "", ErrInvalidUserID
	}
	if len(strings.TrimSpace(userID)) == 0 {
		if s.logger != nil {
			s.logger.Warn("attempted to get token with empty userID")
		}
		return "", "", ErrInvalidUserID
	}

	//===== STEP 2: Service State Check =====
	if !s.IsRunning() {
		if s.logger != nil {
			s.logger.Warn("service not running")
		}
		return "", "", ErrServiceNotRunning
	}

	// ===== STEP 3: Context Check =====
	// Check if context is already cancelled/expired
	// Fail fast if client already disconnected
	if err := ctx.Err(); err != nil {
		if s.logger != nil {
			s.logger.Warn("context cancelled during token issuance",
				"userID", userID,
				"error", err)
		}
		return "", "", err
	}

	// ===== STEP 4: Rate Limiting =====
	// Prevent abuse by limiting token issuance rate per user
	// Cost of 1 = one request

	allowed, err := s.rateLimiter.Allow(userID, 1)

	if err != nil {
		return "", "", err
	}
	if !allowed {
		if s.logger != nil {
			s.logger.Warn("rate limit exceeded",
				"userID", userID)
		}
		return "", "", ErrRateLimitExceeded
	}

	privateKey, keyID, err := s.keyManager.GetCurrentSigningKey()
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to get signing key",
				"userID", userID,
				"error", err)
		}
		return "", "", fmt.Errorf("failed to get signing key: %w", err)
	}

	// ===== STEP 6: Create JWT Claims =====
	now := time.Now()
	expiresAt := now.Add(s.accessTokenDuration)
	// Generate unique token ID (jti claim)
	tokenID, err := generateTokenID()
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to generate token ID",
				"userID", userID,
				"error", err)
		}
		return "", "", fmt.Errorf("failed to generate token ID: %w", err)
	}

	// Create standard JWT claims
	claims := jwt.RegisteredClaims{
		Subject:   userID,                        // "sub" - who the token is for
		Issuer:    s.issuer,                      // "iss" - who issued the token
		Audience:  s.audience,                    // "aud" - who can use the token
		ExpiresAt: jwt.NewNumericDate(expiresAt), // "exp" - when it expires
		IssuedAt:  jwt.NewNumericDate(now),       // "iat" - when it was issued
		NotBefore: jwt.NewNumericDate(now),       // "nbf" - valid from when
		ID:        tokenID,                       // "jti" - unique token identifier
	}

	// ===== STEP 7: Sign Token =====
	// Create JWT with RS256 algorithm (RSA signature with SHA-256)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Set key ID in header for key rotation support
	// Validators will use this to fetch the correct public key
	token.Header["kid"] = keyID

	// Sign the token with private key
	signedToken, err := token.SignedString(privateKey)

	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to sign token",
				"userID", userID,
				"keyID", keyID,
				"error", err)
		}
		return "", "", fmt.Errorf("failed to sign token: %w", err)
	}

	// 6. Create Refresh Token (opaque)
	refreshToken, err := generateRefreshToken()

	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to generate refresh token",
				"userID", userID,
				"error", err)
			return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
		}
	}

	// ===== STEP 6: Calculate Expiration =====
	now = time.Now()
	expiresAt = now.Add(s.refreshTokenDuration)

	// ===== STEP 7: Store Token =====
	// Store token with metadata in RefreshStore
	// This allows:
	//   - Token validation during refresh
	//   - Token revocation
	//   - User session tracking
	//   - Audit trails
	err = s.refreshStore.Store(
		refreshToken, // Token ID (the token itself is the ID)
		userID,       // Who owns the token
		expiresAt,    // When it expires
		nil,          // No metadata (use IssueRefreshTokenWithMetadata for metadata)
	)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to store refresh token",
				"userID", userID,
				"error", err)
		}
		return "", "", fmt.Errorf("failed to store refresh token: %w", err)
	}

	// ========== STEP 8: Log Success =============
	if s.logger != nil {
		s.logger.Info("token pair issued",
			"userID", userID,
			"tokenID", refreshToken,
			expiresAt, expiresAt)
	}
	return signedToken, refreshToken, nil
}

func (s *Service) ValidateAccessToken(ctx context.Context, tokenString string) (*jwt.RegisteredClaims, error) {
	// ===== STEP 1: Service State Check =====
	if !s.IsRunning() {
		if s.logger != nil {
			s.logger.Warn("attempted token validation while service stopped")
		}
		return nil, ErrServiceNotRunning // ← FIX: Return error!
	}

	// ===== STEP 2: Context Check =====
	if err := ctx.Err(); err != nil {
		if s.logger != nil {
			/*s.logger.Debug("context cancelled during token validation",
			  "error", err)
			*/
			s.logger.Info("context cancelled during token validation",
				"error", err)

		}
		return nil, err // ← FIX: Must return!
	}

	// ===== STEP 3: Parse JWT Token =====
	token, err := jwt.ParseWithClaims(
		tokenString,
		&jwt.RegisteredClaims{},
		func(token *jwt.Token) (interface{}, error) {
			// ===== STEP 4a: Verify Signing Method =====
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				if s.logger != nil {
					s.logger.Warn("token uses unexpected signing method",
						"method", token.Header["alg"])
				}
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			// ===== STEP 4b: Extract Key ID =====
			kid, ok := token.Header["kid"].(string)
			if !ok {
				if s.logger != nil {
					s.logger.Warn("token missing kid in header")
				}
				return nil, errors.New("missing kid in token header")
			}

			// ===== STEP 4c: Get Public Key =====
			publicKey, err := s.keyManager.GetPublicKey(kid)
			if err != nil {
				if s.logger != nil {
					s.logger.Error("failed to get public key",
						"kid", kid,
						"error", err)
				}
				return nil, fmt.Errorf("failed to get public key: %w", err)
			}

			return publicKey, nil
		},
	)

	// ===== STEP 5: Check Parsing Errors =====
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("token parsing failed",
				"error", err)
		}

		// Provide specific error messages
		if errors.Is(err, jwt.ErrTokenExpired) {
			if s.logger != nil {
				s.logger.Warn("token expired")
			}
			return nil, ErrTokenExpired
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			return nil, ErrTokenNotYetValid
		}
		if errors.Is(err, keymanager.ErrKeyNotFound) {
			return nil, ErrInvalidSignature
		}

		return nil, ErrInvalidToken
	}

	// ===== STEP 6: Verify Token is Valid =====
	if !token.Valid {
		if s.logger != nil {
			s.logger.Warn("token marked as invalid")
		}
		return nil, ErrInvalidToken
	}

	// ===== STEP 7: Extract Claims =====
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		if s.logger != nil {
			s.logger.Error("failed to extract claims from token")
		}
		return nil, ErrInvalidToken
	}

	// ===== STEP 8: Validate Issuer =====
	if s.issuer != "" && claims.Issuer != s.issuer {
		if s.logger != nil {
			s.logger.Warn("token issuer mismatch",
				"expected", s.issuer,
				"actual", claims.Issuer)
		}
		return nil, ErrInvalidIssuer
	}

	// ===== STEP 9: Validate Audience =====
	if len(s.audience) > 0 {
		validAudience := false
		for _, aud := range s.audience {
			for _, tokenAud := range claims.Audience {
				if aud == tokenAud {
					validAudience = true
					break
				}
			}
			if validAudience {
				break
			}
		}

		if !validAudience {
			if s.logger != nil {
				s.logger.Warn("token audience mismatch",
					"expected", s.audience,
					"actual", claims.Audience)
			}
			return nil, ErrInvalidAudience
		}
	}

	// ===== STEP 10: Log Success & Metrics =====
	if s.logger != nil {
		/*s.logger.Debug("access token validated",
		  "userID", claims.Subject,
		  "tokenID", claims.ID)
		*/
		s.logger.Info("access token validated",
			"userID", claims.Subject,
			"tokenID", claims.ID)
	}

	// Update metrics (if implemented)
	// s.tokenValidationCount.Add(1)

	return claims, nil
}

func (s *Service) RefreshAccessToken(ctx context.Context, refreshToken string) (string, error) {
	// STEP 1: Service State Check
	if !s.isRunning.Load() {
		if s.logger != nil {
			s.logger.Warn("attempted to refresh while service was stopped")
		}
		return "", ErrServiceNotRunning
	}

	// STEP 2: Context Check
	if err := ctx.Err(); err != nil {
		if s.logger != nil {
			s.logger.Info("context cancelled during token refresh")
		}
		return "", err
	}

	// STEP 3: Input Validation
	if refreshToken == "" {
		if s.logger != nil {
			s.logger.Warn("empty refresh token provided")
		}
		return "", ErrInvalidRefreshToken
	}

	// STEP 4: Lookup Refresh Token (CORRECTED!)
	token, err := s.refreshStore.Retrieve(refreshToken) // ← CORRECT: Retrieve, not Get
	if err != nil {
		if s.logger != nil {
			s.logger.Warn("refresh token not found in store",
				"error", err)
		}
		// Propagate specific errors, default to invalid token for generic errors
		if errors.Is(err, ErrTokenRevoked) {
			return "", ErrTokenRevoked
		}
		return "", ErrInvalidRefreshToken
	}

	// STEP 5: Check Expiration
	if token.ExpiresAt.Before(time.Now()) {
		if s.logger != nil {
			s.logger.Warn("refresh token has expired",
				"tokenID", refreshToken,
				"expiredAt", token.ExpiresAt)
		}

		// Clean up expired token
		s.refreshStore.Revoke(refreshToken)

		return "", ErrRefreshTokenExpired
	}

	// STEP 6: Check if Revoked
	if token.Revoked {
		if s.logger != nil {
			s.logger.Warn("refresh token has been revoked",
				"tokenID", refreshToken)
		}
		return "", ErrTokenRevoked
	}

	// STEP 7: Rate Limit Check
	allowed, err := s.rateLimiter.Allow(token.UserID, 1)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("rate limiter error",
				"userID", token.UserID,
				"error", err)
		}
		return "", err
	}

	if !allowed {
		if s.logger != nil {
			s.logger.Warn("rate limit exceeded for token refresh",
				"userID", token.UserID)
		}
		return "", ErrRateLimitExceeded
	}

	// STEP 8: Issue New Access Token
	newAccessToken, err := s.IssueAccessToken(ctx, token.UserID)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to issue new access token",
				"userID", token.UserID,
				"error", err)
		}
		return "", fmt.Errorf("failed to issue access token: %w", err)
	}

	// STEP 9: Log Success
	if s.logger != nil {
		s.logger.Info("access token refreshed",
			"userID", token.UserID,
			"tokenID", refreshToken)
	}

	return newAccessToken, nil
}

// generateTokenID creates a cryptographically random token identifier.
//
// The token ID (jti claim) is used for:
//   - Token revocation (blacklisting)
//   - Audit trails
//   - Preventing replay attacks
//
// Returns a URL-safe base64 encoded string (22 characters).
func generateTokenID() (string, error) {
	// Generate 16 random bytes
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode as URL-safe base64 (no padding)
	// Example: "xF7hN2kP9mQ8rT4vL6wY3g"
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// generateRefreshToken creates a cryptographically random refresh token.
//
// The refresh token is:
//   - Opaque (not a JWT)
//   - 32 bytes of random data (256 bits)
//   - Base64url encoded (URL-safe, 43 characters)
//   - Cryptographically secure
//
// Example output: "xF7hN2kP9mQ8rT4vL6wY3gAaBbCcDdEeFfGgHhIiJjKk"
//
// Security properties:
//   - Unpredictable (cryptographic random)
//   - No information leakage (opaque)
//   - Large space (2^256 possibilities)
//   - Collision-resistant
func generateRefreshToken() (string, error) {
	// Generate 32 random bytes (256 bits)
	// This provides 2^256 possible tokens (~10^77)
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Encode as URL-safe base64 (no padding)
	// Result: 43 characters
	// Example: "xF7hN2kP9mQ8rT4vL6wY3gAaBbCcDdEeFfGgHhIiJjKk"
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// getMapKeys returns the keys of a map (for logging).
func getMapKeys(m map[string]interface{}) []string {
	if m == nil {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
