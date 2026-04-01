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
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/golang-jwt/jwt/v5"
)

// ServiceConfig holds the configuration for a Service.
//
// KeyManager and RefreshStore are required. All duration fields
// default to production-safe values via ConfigDefault if left at zero.
type ServiceConfig struct {
	// Required dependencies
	KeyManager   keymanager.KeyManager // Signs and validates tokens
	RefreshStore storage.RefreshStore  // Persists refresh tokens

	// Optional
	Logger logging.Logger // Structured logger; nil disables logging

	// Token lifetimes — defaults applied by NewService if zero
	AccessTokenDuration  time.Duration // Default: 15 minutes
	RefreshTokenDuration time.Duration // Default: 30 days
	CleanupInterval      time.Duration // How often expired tokens are purged; default: 1 hour

	// JWT claims
	Issuer   string   // Value for the "iss" claim
	Audience []string // Values for the "aud" claim
}

// Service issues, validates, and revokes JWT access tokens and opaque refresh
// tokens. It must be started with Start before use and stopped with Shutdown
// for clean termination.
//
// All public methods are safe for concurrent use.
type Service struct {
	// ===== Dependencies (Interfaces) =====
	keyManager   keymanager.KeyManager // Crypto operations
	refreshStore storage.RefreshStore  // Token storage
	logger       logging.Logger        // Optional logging

	// ===== Configuration (Immutable) =====
	accessTokenDuration  time.Duration // e.g., 15 minutes
	refreshTokenDuration time.Duration // e.g., 30 days
	cleanupInterval      time.Duration // e.g., 1 hour
	issuer               string        // JWT "iss" claim
	audience             []string      // JWT "aud" claim

	// ===== State Management =====
	isRunning    atomic.Bool    // Thread-safe running state
	shutdownChan chan struct{}   // Signals background goroutines to stop
	wg           sync.WaitGroup // Waits for goroutines to finish on shutdown
}

// Sentinel errors returned by Service methods.
var (
	ErrInvalidUserID       = errors.New("invalid user ID")
	ErrServiceNotRunning   = errors.New("service is not running")
	ErrInvalidToken        = errors.New("invalid token")
	ErrInvalidSignature    = errors.New("invalid signature")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrRefreshTokenExpired = errors.New("token has expired")
	ErrTokenRevoked        = errors.New("token revoked")
)

// ErrInvalidConfig returns a configuration error with the given message.
// Returned by NewService when required fields are missing or values are invalid.
func ErrInvalidConfig(msg string) error {
	return errors.New(msg)
}

// ConfigDefault returns a ServiceConfig populated with production-safe defaults.
// NewService applies these automatically for any zero-value duration fields.
func ConfigDefault() ServiceConfig {
	return ServiceConfig{
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 30 * 24 * time.Hour,
		CleanupInterval:      1 * time.Hour,
	}
}

// IsRunning reports whether the service has been started and not yet shut down.
// Safe to call concurrently.
func (s *Service) IsRunning() bool {
	return s.isRunning.Load()
}

// NewService constructs a Service from the given config. Zero-value duration
// fields are filled with defaults from ConfigDefault. Returns an error if any
// required dependency is nil or a duration is negative.
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
		logger:               config.Logger,
		accessTokenDuration:  config.AccessTokenDuration,
		refreshTokenDuration: config.RefreshTokenDuration,
		cleanupInterval:      config.CleanupInterval,
		issuer:               config.Issuer,
		audience:             config.Audience,
		shutdownChan: make(chan struct{}),
	}

	return s, nil
}

// Start initializes the service and begins background operations. It starts
// the KeyManager and launches the cleanup goroutine that periodically purges
// expired refresh tokens.
//
// Start is idempotent — calling it on an already-running service is a no-op.
// Returns an error if the KeyManager fails to start or the context is cancelled.
func (s *Service) Start(ctx context.Context) error {
	// ===== STEP 1: Check If Already Running (Idempotent) =====
	if !s.isRunning.CompareAndSwap(false, true) {
		if s.logger != nil {
			s.logger.Warn("start called but service already running")
		}
		return nil // Already running, not an error
	}

	// ===== STEP 2: Log Startup =====
	if s.logger != nil {
		s.logger.Info("starting token service")
	}

	// ===== STEP 3: Start KeyManager =====
	if err := s.keyManager.Start(ctx); err != nil {
		s.isRunning.Store(false) // Revert state

		if s.logger != nil {
			s.logger.Error("failed to start token service",
				"error", err)
		}
		return fmt.Errorf("failed to start keymanager: %w", err)
	}

	// ===== STEP 4: Start Background Cleanup Goroutine =====
	s.wg.Add(1)
	go s.cleanupLoop(ctx)

	// ===== STEP 5: Log Success =====
	if s.logger != nil {
		s.logger.Info("token service started")
	}

	return nil
}

func (s *Service) cleanupLoop(ctx context.Context) {
	defer s.wg.Done()

	// Cleanup at configured interval
	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Cleanup expired refresh tokens
			if s.logger != nil {
				s.logger.Debug("cleanup ticker fired")
			}
			if count, err := s.refreshStore.Cleanup(ctx); err != nil {
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

// Shutdown stops the service gracefully. It signals background goroutines to
// stop, waits for them to finish, then shuts down the KeyManager.
//
// Shutdown is idempotent — calling it on a stopped service is a no-op.
// Returns context.DeadlineExceeded if the goroutines do not finish within
// the deadline, or any error returned by the KeyManager's Shutdown.
func (s *Service) Shutdown(ctx context.Context) error {
	// ===== STEP 1: Check If Running (Idempotent) =====
	if !s.isRunning.CompareAndSwap(true, false) {
		if s.logger != nil {
			s.logger.Warn("shutdown called but service not running")
		}
		return nil // Already stopped, not an error
	}

	// ===== STEP 2: Log Shutdown =====
	if s.logger != nil {
		s.logger.Info("shutting down token service")
	}

	// ===== STEP 3: Signal Background Goroutines =====
	close(s.shutdownChan)

	// ===== STEP 4: Wait For Goroutines With Timeout =====
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

	// ===== STEP 5: Shutdown KeyManager =====
	if err := s.keyManager.Shutdown(ctx); err != nil {
		if s.logger != nil {
			s.logger.Error("failed to shutdown keymanager",
				"error", err)
		}
		return fmt.Errorf("failed to shutdown keymanager: %w", err)
	}

	// ===== STEP 6: Log Success =====
	if s.logger != nil {
		s.logger.Info("token service stopped")
	}

	return nil
}

// IssueAccessToken creates and signs an RS256 JWT access token for the given
// user. The token carries standard registered claims (sub, iss, aud, exp, iat,
// nbf, jti) and is signed with the current key from the KeyManager.
//
// Returns ErrInvalidUserID for empty/whitespace-only user IDs, ErrServiceNotRunning
// if the service is stopped, or the context error if the context is already cancelled.
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

	// ===== STEP 4: Get Signing Key =====
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

	if s.logger != nil {
		s.logger.Debug("signing key retrieved",
			"userID", userID,
			"keyID", keyID)
	}

	// ===== STEP 5: Create JWT Claims =====
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

	if s.logger != nil {
		s.logger.Debug("claims constructed",
			"userID", userID,
			"tokenID", tokenID,
			"expiresAt", expiresAt)
	}

	// ===== STEP 6: Sign Token =====
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

// IssueAccessTokenWithClaims creates a signed RS256 JWT access token with
// additional custom claims merged into the payload. Reserved claims (sub, iss,
// exp, iat, nbf, jti) cannot be overridden; any attempt is silently dropped
// and logged as a warning.
//
// Returns the same errors as IssueAccessToken.
func (s *Service) IssueAccessTokenWithClaims(ctx context.Context, userID string, customClaims map[string]interface{}) (string, error) {
	// ===== STEP 1: Validate User ID =====
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

	// ===== STEP 2: Service State Check =====
	if !s.IsRunning() {
		if s.logger != nil {
			s.logger.Warn("service not running")
		}
		return "", ErrServiceNotRunning
	}

	// ===== STEP 3: Context Check =====
	if err := ctx.Err(); err != nil {
		if s.logger != nil {
			s.logger.Warn("context cancelled during token issuance",
				"userID", userID,
				"error", err)
		}
		return "", err
	}

	// ===== STEP 4: Get Signing Key =====
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

// IssueRefreshToken creates and stores an opaque, cryptographically random
// refresh token for the given user. Unlike access tokens, refresh tokens are
// not JWTs — they are 256-bit random values stored in the RefreshStore.
//
// Returns the same errors as IssueAccessToken.
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

	if s.logger != nil {
		s.logger.Debug("issuing refresh token", "userID", userID)
	}

	// ===== STEP 4: Generate Refresh Token =====
	// Create cryptographic random token
	// this is an OPAQUE token (not a JWT)
	refreshToken, err := generateRefreshToken()
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to generate refresh token",
				"userID", userID,
				"error", err)
		}
		return "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// ===== STEP 5: Calculate Expiration =====
	now := time.Now()
	expiresAt := now.Add(s.refreshTokenDuration)

	// ===== STEP 6: Store Token =====
	// Store token with metadata in RefreshStore
	// This allows:
	//   - Token validation during refresh
	//   - Token revocation
	//   - User session tracking
	//   - Audit trails
	err = s.refreshStore.Store(
		ctx,          // Context for cancellation
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

	// ===== STEP 7: Log Success =====
	if s.logger != nil {
		s.logger.Info("refresh token issued",
			"userID", userID,
			"tokenID", refreshToken,
			"expiresAt", expiresAt)
	}

	return refreshToken, nil
}

// IssueRefreshTokenWithMetadata behaves like IssueRefreshToken but stores
// arbitrary metadata alongside the token (e.g. device ID, IP address, session
// tags). The metadata is retrievable via IntrospectToken.
//
// Returns the same errors as IssueAccessToken.
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

	if s.logger != nil {
		s.logger.Debug("issuing refresh token with metadata", "userID", userID)
	}

	// ===== STEP 4: Generate Refresh Token =====
	// Create cryptographic random token
	// this is an OPAQUE token (not a JWT)
	refreshToken, err := generateRefreshToken()
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to generate refresh token",
				"userID", userID,
				"error", err)
		}
		return "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// ===== STEP 5: Calculate Expiration =====
	now := time.Now()
	expiresAt := now.Add(s.refreshTokenDuration)

	// ===== STEP 6: Store Token =====
	// Store token with metadata in RefreshStore
	// This allows:
	//   - Token validation during refresh
	//   - Token revocation
	//   - User session tracking
	//   - Audit trails
	err = s.refreshStore.Store(
		ctx,          // Context for cancellation
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

	// ===== STEP 7: Log Success =====
	if s.logger != nil {
		s.logger.Info("refresh token with metadata issued",
			"userID", userID,
			"tokenID", refreshToken,
			"expiresAt", expiresAt,
			"metadataKeys", getMapKeys(metadata))
	}
	return refreshToken, nil
}

// IssueTokenPair issues an access token and a refresh token in a single
// operation. The access token is a signed RS256 JWT; the refresh token is an
// opaque random value stored in the RefreshStore.
//
// Returns (accessToken, refreshToken, error). Returns the same errors as
// IssueAccessToken.
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

	if s.logger != nil {
		s.logger.Debug("issuing token pair", "userID", userID)
	}

	// ===== STEP 4: Get Signing Key =====
	privateKey, keyID, err := s.keyManager.GetCurrentSigningKey()
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to get signing key",
				"userID", userID,
				"error", err)
		}
		return "", "", fmt.Errorf("failed to get signing key: %w", err)
	}

	// ===== STEP 5: Create JWT Claims =====
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

	// ===== STEP 6: Sign Token =====
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

	// ===== STEP 8: Generate Refresh Token =====
	refreshToken, err := generateRefreshToken()
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to generate refresh token",
				"userID", userID,
				"error", err)
		}
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// ===== STEP 9: Calculate Refresh Token Expiration =====
	now = time.Now()
	expiresAt = now.Add(s.refreshTokenDuration)

	// ===== STEP 10: Store Refresh Token =====
	// Store token with metadata in RefreshStore
	// This allows:
	//   - Token validation during refresh
	//   - Token revocation
	//   - User session tracking
	//   - Audit trails
	err = s.refreshStore.Store(
		ctx,          // Context for cancellation
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

	// ===== STEP 11: Log Success =====
	if s.logger != nil {
		s.logger.Info("token pair issued",
			"userID", userID,
			"tokenID", refreshToken,
			"expiresAt", expiresAt)
	}
	return signedToken, refreshToken, nil
}

// ValidateAccessToken parses and validates a signed JWT access token string.
// It verifies the RS256 signature using the public key identified by the token's
// "kid" header, then checks expiration, issuer, and audience claims.
//
// Returns the parsed RegisteredClaims on success, or one of: ErrServiceNotRunning,
// ErrTokenExpired, ErrTokenNotYetValid, ErrInvalidSignature, ErrInvalidIssuer,
// ErrInvalidAudience, ErrInvalidToken, or the context error.
func (s *Service) ValidateAccessToken(ctx context.Context, tokenString string) (*jwt.RegisteredClaims, error) {
	// ===== STEP 1: Service State Check =====
	if !s.IsRunning() {
		if s.logger != nil {
			s.logger.Warn("attempted token validation while service stopped")
		}
		return nil, ErrServiceNotRunning
	}

	// ===== STEP 2: Context Check =====
	if err := ctx.Err(); err != nil {
		if s.logger != nil {
			s.logger.Info("context cancelled during token validation",
				"error", err)
		}
		return nil, err
	}

	if s.logger != nil {
		s.logger.Debug("validating access token")
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

	// ===== STEP 10: Log Success =====
	if s.logger != nil {
		s.logger.Info("access token validated",
			"userID", claims.Subject,
			"tokenID", claims.ID)
	}

	return claims, nil
}

// RefreshAccessToken exchanges a valid refresh token for a new access token.
// It retrieves the refresh token from storage, checks expiration and revocation
// status, then calls IssueAccessToken for the token's owner.
//
// Returns ErrServiceNotRunning, ErrInvalidRefreshToken, ErrRefreshTokenExpired,
// ErrTokenRevoked, or the context error.
func (s *Service) RefreshAccessToken(ctx context.Context, refreshToken string) (string, error) {
	// ===== STEP 1: Service State Check =====
	if !s.isRunning.Load() {
		if s.logger != nil {
			s.logger.Warn("attempted to refresh while service was stopped")
		}
		return "", ErrServiceNotRunning
	}

	// ===== STEP 2: Context Check =====
	if err := ctx.Err(); err != nil {
		if s.logger != nil {
			s.logger.Info("context cancelled during token refresh")
		}
		return "", err
	}

	if s.logger != nil {
		s.logger.Debug("attempting token refresh")
	}

	// ===== STEP 3: Input Validation =====
	if refreshToken == "" {
		if s.logger != nil {
			s.logger.Warn("empty refresh token provided")
		}
		return "", ErrInvalidRefreshToken
	}

	// ===== STEP 4: Lookup Refresh Token =====
	token, err := s.refreshStore.Retrieve(ctx, refreshToken)
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

	if s.logger != nil {
		s.logger.Debug("refresh token retrieved from store",
			"userID", token.UserID,
			"tokenID", token.TokenID)
	}

	// ===== STEP 5: Check Expiration =====
	if token.ExpiresAt.Before(time.Now()) {
		if s.logger != nil {
			s.logger.Warn("refresh token has expired",
				"tokenID", refreshToken,
				"expiredAt", token.ExpiresAt)
		}

		// Clean up expired token
		s.refreshStore.Revoke(ctx, refreshToken)

		return "", ErrRefreshTokenExpired
	}

	// ===== STEP 6: Check If Revoked =====
	if token.Revoked {
		if s.logger != nil {
			s.logger.Warn("refresh token has been revoked",
				"tokenID", refreshToken)
		}
		return "", ErrTokenRevoked
	}

	// ===== STEP 7: Issue New Access Token =====
	newAccessToken, err := s.IssueAccessToken(ctx, token.UserID)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to issue new access token",
				"userID", token.UserID,
				"error", err)
		}
		return "", fmt.Errorf("failed to issue access token: %w", err)
	}

	// ===== STEP 9: Log Success =====
	if s.logger != nil {
		s.logger.Info("access token refreshed",
			"userID", token.UserID,
			"tokenID", refreshToken)
	}

	return newAccessToken, nil
}

// RevokeRefreshToken marks a single refresh token as revoked in the RefreshStore.
// Subsequent calls to RefreshAccessToken or IntrospectToken will see the token
// as inactive.
//
// Returns ErrServiceNotRunning, ErrInvalidRefreshToken for empty tokenID, or
// the context error.
func (s *Service) RevokeRefreshToken(ctx context.Context, tokenID string) error {
	// ===== STEP 1: Service State Check =====
	if !s.isRunning.Load() {
		if s.logger != nil {
			s.logger.Warn("attempted to revoke token while service stopped")
		}
		return ErrServiceNotRunning
	}

	// ===== STEP 2: Context Check =====
	if err := ctx.Err(); err != nil {
		if s.logger != nil {
			s.logger.Info("context cancelled during token revocation")
		}
		return err
	}

	// ===== STEP 3: Input Validation =====
	if tokenID == "" {
		if s.logger != nil {
			s.logger.Warn("empty token ID provided for revocation")
		}
		return ErrInvalidRefreshToken
	}

	// ===== STEP 4: Revoke Token =====
	err := s.refreshStore.Revoke(ctx, tokenID)
	if err != nil {
		if s.logger != nil {

			s.logger.Error("failed to revoke refresh token",
				"tokenID", tokenID,
				"error", err)
		}
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	// ===== STEP 5: Log Success =====
	if s.logger != nil {
		s.logger.Info("refresh token revoked",
			"tokenID", tokenID)
	}

	return nil
}

// RevokeAllUserTokens revokes every refresh token belonging to the given user.
// Use this for logout-all-devices or account suspension scenarios.
//
// Returns ErrServiceNotRunning, ErrInvalidUserID for empty userID, or the
// context error.
func (s *Service) RevokeAllUserTokens(ctx context.Context, userID string) error {
	// ===== STEP 1: Service State Check =====
	if !s.isRunning.Load() {
		if s.logger != nil {
			s.logger.Warn("attempted to revoke all user tokens while service stopped")
		}
		return ErrServiceNotRunning
	}

	// ===== STEP 2: Context Check =====
	if err := ctx.Err(); err != nil {
		if s.logger != nil {
			s.logger.Info("context cancelled during bulk token revocation",
				"error", err)
		}
		return err
	}

	// ===== STEP 3: Input Validation =====
	if userID == "" {
		if s.logger != nil {
			s.logger.Warn("empty user ID provided for bulk revocation")
		}
		return ErrInvalidUserID // Note: Different error than single revoke
	}

	// ===== STEP 4: Revoke All Tokens For User =====
	err := s.refreshStore.RevokeAllForUser(ctx, userID)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to revoke all user tokens",
				"userID", userID,
				"error", err)
		}
		return fmt.Errorf("failed to revoke all tokens: %w", err)
	}

	// ===== STEP 5: Log Success =====
	if s.logger != nil {
		s.logger.Info("all refresh tokens revoked for user",
			"userID", userID)
	}

	return nil
}

// IntrospectToken returns metadata about an opaque refresh token, per RFC 7662.
// It never returns an error for unknown or invalid tokens — instead, it returns
// a TokenMetadata with Active set to false.
//
// Only refresh tokens are supported. Access tokens (JWTs) should be validated
// with ValidateAccessToken instead.
//
// Returns ErrServiceNotRunning, ErrInvalidRefreshToken for empty tokens, or
// the context error.
func (s *Service) IntrospectToken(ctx context.Context, token string) (*TokenMetadata, error) {
	// ===== STEP 1: Service State Check =====
	if !s.isRunning.Load() {
		if s.logger != nil {
			s.logger.Warn("attempted to introspect token while service is stopped")
		}
		return nil, ErrServiceNotRunning
	}

	// ===== STEP 2: Context Check =====
	if err := ctx.Err(); err != nil {
		if s.logger != nil {
			s.logger.Info("context cancelled during token introspection")
		}
		return nil, err
	}

	if s.logger != nil {
		s.logger.Debug("introspecting token")
	}

	// ===== STEP 3: Input Validation =====
	if token == "" {
		if s.logger != nil {
			s.logger.Warn("empty token provided for introspection")
		}
		return nil, ErrInvalidRefreshToken
	}

	// ===== STEP 4: Retrieve Token From Storage =====
	refreshToken, err := s.refreshStore.Retrieve(ctx, token)
	if err != nil {
		if s.logger != nil {
			s.logger.Info("token not found during introspection",
				"error", err)
		}
		// Return inactive metadata instead of error
		return &TokenMetadata{
			Active:    false,
			Subject:   "",
			TokenType: "refresh_token",
			ExpiresAt: time.Time{},
			IssuedAt:  time.Time{},
		}, nil
	}

	// ===== STEP 5: Check Token Status =====
	now := time.Now()

	// Check if expired
	if refreshToken.ExpiresAt.Before(now) {
		if s.logger != nil {
			s.logger.Info("introspect token is expired",
				"token", token,
				"expiredAt", refreshToken.ExpiresAt)
		}
		return &TokenMetadata{
			Active:    false,
			Subject:   refreshToken.UserID,
			TokenType: "refresh_token",
			ExpiresAt: refreshToken.ExpiresAt,
			IssuedAt:  refreshToken.CreatedAt,
		}, nil
	}

	// Check if revoked
	if refreshToken.Revoked {
		if s.logger != nil {
			s.logger.Info("introspected token is revoked",
				"tokenID", token)
		}

		return &TokenMetadata{
			Active:    false,
			Subject:   refreshToken.UserID,
			TokenType: "refresh_token",
			ExpiresAt: refreshToken.ExpiresAt,
			IssuedAt:  refreshToken.CreatedAt,
		}, nil
	}

	// ===== STEP 6: Return Active Token Metadata =====
	if s.logger != nil {
		s.logger.Info("token introspection successfully",
			"tokenID", token,
			"userID", refreshToken.UserID,
			"active", true)
	}
	return &TokenMetadata{
		Active:    true,
		Subject:   refreshToken.UserID,
		TokenType: "refresh_token",
		ExpiresAt: refreshToken.ExpiresAt,
		IssuedAt:  refreshToken.CreatedAt,
	}, nil
}

// CleanupExpiredTokens removes all expired refresh tokens from the RefreshStore.
// The service also runs this automatically in the background at CleanupInterval,
// so manual calls are only needed for on-demand sweeps.
//
// Returns the number of tokens deleted, ErrServiceNotRunning, or the context error.
func (s *Service) CleanupExpiredTokens(ctx context.Context) (int, error) {
	// ===== STEP 1: Service State Check =====
	if !s.isRunning.Load() {
		if s.logger != nil {
			s.logger.Warn("attempted cleanup while service stopped")
		}
		return 0, ErrServiceNotRunning
	}

	// ===== STEP 2: Context Check =====
	if err := ctx.Err(); err != nil {
		if s.logger != nil {
			s.logger.Info("context cancelled during cleanup",
				"error", err)
		}
		return 0, err
	}

	// ===== STEP 3: Run Cleanup =====
	count, err := s.refreshStore.Cleanup(ctx)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to cleanup expired tokens",
				"error", err)
		}
		return 0, fmt.Errorf("cleanup failed: %w", err)
	}

	// ===== STEP 4: Log Success =====
	if s.logger != nil {
		s.logger.Info("expired tokens cleaned up",
			"deleted", count)
	}

	return count, nil
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
