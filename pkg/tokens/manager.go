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
	"github.com/aetomala/jwtauth/pkg/metrics"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/golang-jwt/jwt/v5"
)

// ManagerConfig holds the configuration for a Manager.
//
// KeyManager and RefreshStore are required. All duration fields
// default to production-safe values via DefaultManagerConfig if left at zero.
type ManagerConfig struct {
	// Required dependencies
	KeyManager   keymanager.KeyManager // Signs and validates tokens
	RefreshStore storage.RefreshStore  // Persists refresh tokens

	// Optional
	Logger  logging.Logger  // Structured logger; nil disables logging
	Metrics metrics.Metrics // Optional; nil disables metrics.

	// Token lifetimes — defaults applied by NewManager if zero
	AccessTokenDuration  time.Duration // Default: 15 minutes
	RefreshTokenDuration time.Duration // Default: 30 days
	CleanupInterval      time.Duration // How often expired tokens are purged; default: 1 hour

	// Clock skew tolerance
	ClockSkew time.Duration // Leeway for exp/nbf validation; zero means strict. Default: 0

	// JWT claims
	Issuer   string   // Value for the "iss" claim
	Audience []string // Values for the "aud" claim
}

// Manager issues, validates, and revokes JWT access tokens and opaque refresh
// tokenm. It must be started with Start before use and stopped with Shutdown
// for clean termination.
//
// All public methods are safe for concurrent use.
type Manager struct {
	// ===== Dependencies (Interfaces) =====
	keyManager   keymanager.KeyManager // Crypto operations
	refreshStore storage.RefreshStore  // Token storage
	logger       logging.Logger        // Optional logging
	metrics      metrics.Metrics       // Optional metrics recorder

	// ===== Configuration (Immutable) =====
	accessTokenDuration  time.Duration // e.g., 15 minutes
	refreshTokenDuration time.Duration // e.g., 30 days
	cleanupInterval      time.Duration // e.g., 1 hour
	issuer               string        // JWT "iss" claim
	audience             []string      // JWT "aud" claim
	clockSkew            time.Duration // Leeway applied to exp and nbf validation

	// ===== State Management =====
	isRunning    atomic.Bool    // Thread-safe running state
	shutdownChan chan struct{}   // Signals background goroutines to stop
	wg           sync.WaitGroup // Waits for goroutines to finish on shutdown
}

// Sentinel errors returned by Manager methodm.
var (
	ErrInvalidUserID       = errors.New("invalid user ID")
	ErrManagerNotRunning   = errors.New("manager is not running")
	ErrInvalidToken        = errors.New("invalid token")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrRefreshTokenExpired = errors.New("token has expired")
	ErrTokenRevoked        = errors.New("token revoked")
)

// ErrInvalidConfig returns a configuration error with the given message.
// Returned by NewManager when required fields are missing or values are invalid.
func ErrInvalidConfig(msg string) error {
	return errors.New(msg)
}

// DefaultManagerConfig returns a ManagerConfig populated with production-safe defaultm.
// NewManager applies these automatically for any zero-value duration fieldm.
func DefaultManagerConfig() ManagerConfig {
	return ManagerConfig{
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 30 * 24 * time.Hour,
		CleanupInterval:      1 * time.Hour,
	}
}

// IsRunning reports whether the manager has been started and not yet shut down.
// Safe to call concurrently.
func (m *Manager) IsRunning() bool {
	return m.isRunning.Load()
}

// NewManager constructs a Manager from the given config. Zero-value duration
// fields are filled with defaults from DefaultManagerConfig. Returns an error if any
// required dependency is nil or a duration is negative.
func NewManager(config ManagerConfig) (*Manager, error) {
	if config.AccessTokenDuration == 0 {
		config.AccessTokenDuration = DefaultManagerConfig().AccessTokenDuration
	}

	if config.RefreshTokenDuration == 0 {
		config.RefreshTokenDuration = DefaultManagerConfig().RefreshTokenDuration
	}

	if config.CleanupInterval == 0 {
		config.CleanupInterval = DefaultManagerConfig().CleanupInterval
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

	if config.ClockSkew < 0 {
		return nil, ErrInvalidConfig("ClockSkew must be non-negative")
	}

	m := &Manager{
		keyManager:           config.KeyManager,
		refreshStore:         config.RefreshStore,
		logger:               config.Logger,
		metrics:              config.Metrics,
		accessTokenDuration:  config.AccessTokenDuration,
		refreshTokenDuration: config.RefreshTokenDuration,
		cleanupInterval:      config.CleanupInterval,
		clockSkew:            config.ClockSkew,
		issuer:               config.Issuer,
		audience:             config.Audience,
		shutdownChan:         make(chan struct{}),
	}

	return m, nil
}

// Start initializes the service and begins background operationm. It starts
// the KeyManager and launches the cleanup goroutine that periodically purges
// expired refresh tokenm.
//
// Start is idempotent — calling it on an already-running service is a no-op.
// Returns an error if the KeyManager fails to start or the context is cancelled.
func (m *Manager)Start(ctx context.Context) error {
	// ===== STEP 1: Check If Already Running (Idempotent) =====
	if !m.isRunning.CompareAndSwap(false, true) {
		// Already running — idempotent no-op, no metric recorded
		if m.logger != nil {
			m.logger.Warn("start called but service already running", ctx)
		}
		return nil // Already running, not an error
	}

	// ===== STEP 2: Log Startup =====
	if m.logger != nil {
		m.logger.Info("starting token service", ctx)
	}

	// ===== STEP 3: Start KeyManager =====
	if err := m.keyManager.Start(ctx); err != nil {
		m.isRunning.Store(false) // Revert state

		if m.logger != nil {
			m.logger.Error("failed to start token service", ctx,
				"error", err)
		}
		return fmt.Errorf("failed to start keymanager: %w", err)
	}

	// ===== STEP 4: Start Background Cleanup Goroutine =====
	m.wg.Add(1)
	go m.cleanupLoop(ctx)

	// ===== STEP 5: Record Metric and Log Success =====
	if m.metrics != nil {
		m.metrics.SetGauge(metricServiceRunning, 1.0, map[string]string{})
	}
	if m.logger != nil {
		m.logger.Info("token service started", ctx)
	}

	return nil
}

func (m *Manager)cleanupLoop(ctx context.Context) {
	defer m.wg.Done()

	// Cleanup at configured interval
	ticker := time.NewTicker(m.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if m.logger != nil {
				m.logger.Debug("cleanup loop tick started", ctx)
			}
			// Cleanup expired refresh tokens
			if m.logger != nil {
				m.logger.Debug("cleanup ticker fired", ctx)
			}
			if count, err := m.refreshStore.Cleanup(ctx); err != nil {
				if m.logger != nil {
					m.logger.Error("refresh token cleanup failed", ctx,
						"error", err)
				}
			} else {

				if m.logger != nil {
					m.logger.Info("refresh token cleanup completed", ctx,
						"tokens", count)
				}
			}

		case <-m.shutdownChan:
			if m.logger != nil {
				m.logger.Info("cleanup loop stopping", ctx)
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
func (m *Manager)Shutdown(ctx context.Context) error {
	// ===== STEP 1: Check If Running (Idempotent) =====
	if !m.isRunning.CompareAndSwap(true, false) {
		if m.logger != nil {
			m.logger.Warn("shutdown called but service not running", ctx)
		}
		return nil // Already stopped, not an error
	}

	// ===== STEP 2: Log Shutdown =====
	if m.logger != nil {
		m.logger.Info("shutting down token service", ctx)
	}

	// ===== STEP 3: Signal Background Goroutines =====
	close(m.shutdownChan)

	// ===== STEP 4: Wait For Goroutines With Timeout =====
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Goroutines completed
	case <-ctx.Done():
		// Timeout
		if m.logger != nil {
			m.logger.Warn("shutdown timeout waiting for goroutines", ctx,
				"error", ctx.Err())
		}
		return ctx.Err()
	}

	// ===== STEP 5: Shutdown KeyManager =====
	if err := m.keyManager.Shutdown(ctx); err != nil {
		if m.logger != nil {
			m.logger.Error("failed to shutdown keymanager", ctx,
				"error", err)
		}
		return fmt.Errorf("failed to shutdown keymanager: %w", err)
	}

	// ===== STEP 6: Record Metric and Log Success =====
	if m.metrics != nil {
		m.metrics.SetGauge(metricServiceRunning, 0.0, map[string]string{})
	}
	if m.logger != nil {
		m.logger.Info("token service stopped", ctx)
	}

	return nil
}

// IssueAccessToken creates and signs an RS256 JWT access token for the given
// user. The token carries standard registered claims (sub, iss, aud, exp, iat,
// nbf, jti) and is signed with the current key from the KeyManager.
//
// Returns ErrInvalidUserID for empty/whitespace-only user IDs, ErrManagerNotRunning
// if the service is stopped, or the context error if the context is already cancelled.
func (m *Manager)IssueAccessToken(ctx context.Context, userID string) (string, error) {
	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		if m.metrics != nil {
			m.metrics.IncrementCounter(metricTokensIssuedTotal, map[string]string{
				"status":     status,
				"error_type": errorType,
			})
			m.metrics.RecordDuration(metricOperationDuration, time.Since(start), map[string]string{
				"operation": "issue_access_token",
			})
		}
	}()

	// ===== STEP 1: Validate User ID =====
	if len(strings.TrimSpace(userID)) == 0 {
		status = "invalid_input"
		errorType = "invalid_input"
		if m.logger != nil {
			m.logger.Warn("attempted to get token with empty userID", ctx)
		}
		return "", ErrInvalidUserID
	}

	// ===== STEP 2: Service State Check =====
	if !m.IsRunning() {
		status = "not_running"
		errorType = "not_running"
		if m.logger != nil {
			m.logger.Warn("service not running", ctx)
		}
		return "", ErrManagerNotRunning
	}
	// ===== STEP 3: Context Check =====
	// Check if context is already cancelled/expired
	// Fail fast if client already disconnected
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		if m.logger != nil {
			m.logger.Warn("context cancelled during token issuance", ctx,
				"userID", userID,
				"error", err)
		}
		return "", err
	}

	// ===== STEP 4: Get Signing Key =====
	// Retrieve current private key and its ID from KeyManager
	// The key ID will be included in the JWT header for verification
	privateKey, keyID, err := m.keyManager.GetCurrentSigningKey(ctx)
	if err != nil {
		if m.logger != nil {
			m.logger.Error("failed to get signing key", ctx,
				"userID", userID,
				"error", err)
		}
		return "", fmt.Errorf("failed to get signing key: %w", err)
	}
	if m.logger != nil {
		m.logger.Debug("signing key retrieved", ctx,
			"userID", userID,
			"keyID", keyID)
	}

	// ===== STEP 5: Create JWT Claims =====
	now := time.Now()
	expiresAt := now.Add(m.accessTokenDuration)
	// Generate unique token ID (jti claim)
	tokenID, err := generateTokenID()
	if err != nil {
		if m.logger != nil {
			m.logger.Error("failed to generate token ID", ctx,
				"userID", userID,
				"error", err)
		}
		return "", fmt.Errorf("failed to generate token ID: %w", err)
	}

	// Create standard JWT claims
	claims := jwt.RegisteredClaims{
		Subject:   userID,                        // "sub" - who the token is for
		Issuer:    m.issuer,                      // "iss" - who issued the token
		Audience:  m.audience,                    // "aud" - who can use the token
		ExpiresAt: jwt.NewNumericDate(expiresAt), // "exp" - when it expires
		IssuedAt:  jwt.NewNumericDate(now),       // "iat" - when it was issued
		NotBefore: jwt.NewNumericDate(now),       // "nbf" - valid from when
		ID:        tokenID,                       // "jti" - unique token identifier
	}
	if m.logger != nil {
		m.logger.Debug("access token claims created", ctx,
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
		if m.logger != nil {
			m.logger.Error("failed to sign token", ctx,
				"userID", userID,
				"keyID", keyID,
				"error", err)
		}
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	if m.logger != nil {
		m.logger.Debug("access token signed", ctx,
			"userID", userID,
			"tokenID", tokenID)
	}

	// ===== STEP 8: Record Success and Log =====
	status = "success"
	errorType = ""
	if m.logger != nil {
		m.logger.Info("access token issued", ctx,
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
func (m *Manager)IssueAccessTokenWithClaims(ctx context.Context, userID string, customClaims map[string]interface{}) (string, error) {
	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		if m.metrics != nil {
			m.metrics.IncrementCounter(metricTokensIssuedTotal, map[string]string{
				"status":     status,
				"error_type": errorType,
			})
			m.metrics.RecordDuration(metricOperationDuration, time.Since(start), map[string]string{
				"operation": "issue_access_token",
			})
		}
	}()

	// ===== STEP 1: Validate User ID =====
	if len(strings.TrimSpace(userID)) == 0 {
		status = "invalid_input"
		errorType = "invalid_input"
		if m.logger != nil {
			m.logger.Warn("attempted to get token with empty userID", ctx)
		}
		return "", ErrInvalidUserID
	}

	// ===== STEP 2: Service State Check =====
	if !m.IsRunning() {
		status = "not_running"
		errorType = "not_running"
		if m.logger != nil {
			m.logger.Warn("service not running", ctx)
		}
		return "", ErrManagerNotRunning
	}

	// ===== STEP 3: Context Check =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		if m.logger != nil {
			m.logger.Warn("context cancelled during token issuance", ctx,
				"userID", userID,
				"error", err)
		}
		return "", err
	}

	// ===== STEP 4: Get Signing Key =====
	privateKey, keyID, err := m.keyManager.GetCurrentSigningKey(ctx)
	if err != nil {
		if m.logger != nil {
			m.logger.Error("failed to get signing key", ctx,
				"userID", userID,
				"error", err)
		}
		return "", fmt.Errorf("failed to get signing key: %w", err)
	}
	if m.logger != nil {
		m.logger.Debug("signing key retrieved", ctx,
			"userID", userID,
			"keyID", keyID)
	}

	now := time.Now()
	expiresAt := now.Add(m.accessTokenDuration)
	tokenID, err := generateTokenID()
	if err != nil {
		if m.logger != nil {
			m.logger.Error("failed to generate token ID", ctx,
				"userID", userID,
				"error", err)
		}
		return "", fmt.Errorf("failed to generate token ID: %w", err)
	}

	// Create map claims to support both standard and custom claims
	claims := jwt.MapClaims{
		"sub": userID,
		"iss": m.issuer,
		"aud": m.audience,
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

	customClaimsCount := 0
	for key, value := range customClaims {
		if !reservedClaims[key] {
			claims[key] = value
			customClaimsCount++
		} else {
			if m.logger != nil {
				m.logger.Warn("attempted to override reserved claim", ctx,
					"userID", userID,
					"claim", key)
			}
		}
	}
	if m.logger != nil {
		m.logger.Debug("access token claims created with custom claims", ctx,
			"userID", userID,
			"tokenID", tokenID,
			"customClaimsCount", customClaimsCount,
			"expiresAt", expiresAt)
	}

	// Sign token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		if m.logger != nil {
			m.logger.Error("failed to sign token with custom claims", ctx,
				"userID", userID,
				"keyID", keyID,
				"error", err)
		}
		return "", fmt.Errorf("failed to sign token: %w", err)
	}
	if m.logger != nil {
		m.logger.Debug("access token with custom claims signed", ctx,
			"userID", userID,
			"tokenID", tokenID)
	}
	// ===== STEP 8: Record Success and Log =====
	status = "success"
	errorType = ""
	if m.logger != nil {
		m.logger.Info("access token with custom claims issued", ctx,
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
func (m *Manager)IssueRefreshToken(ctx context.Context, userID string) (string, error) {
	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		if m.metrics != nil {
			m.metrics.IncrementCounter(metricTokensIssuedTotal, map[string]string{
				"status":     status,
				"error_type": errorType,
			})
			m.metrics.RecordDuration(metricOperationDuration, time.Since(start), map[string]string{
				"operation": "issue_refresh_token",
			})
		}
	}()

	// ===== STEP 1: Validate User ID =====
	if len(strings.TrimSpace(userID)) == 0 {
		status = "invalid_input"
		errorType = "invalid_input"
		if m.logger != nil {
			m.logger.Warn("attempted to get token with empty userID", ctx)
		}
		return "", ErrInvalidUserID
	}

	// ===== STEP 2: Service State Check =====

	if !m.IsRunning() {
		status = "not_running"
		errorType = "not_running"
		if m.logger != nil {
			m.logger.Warn("service not running", ctx)
		}
		return "", ErrManagerNotRunning
	}

	// ===== STEP 3: Context Check =====
	// Check if context is already cancelled/expired
	// Fail fast if client already disconnected
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		if m.logger != nil {
			m.logger.Warn("context cancelled during token issuance", ctx,
				"userID", userID,
				"error", err)
		}
		return "", err
	}

	if m.logger != nil {
		m.logger.Debug("issuing refresh token", ctx, "userID", userID)
	}

	// ===== STEP 4: Generate Refresh Token =====
	// Create cryptographic random token
	// this is an OPAQUE token (not a JWT)
	refreshToken, err := generateRefreshToken()
	if err != nil {
		if m.logger != nil {
			m.logger.Error("failed to generate refresh token", ctx,
				"userID", userID,
				"error", err)
		}
		return "", fmt.Errorf("failed to generate refresh token: %w", err)
	}
	if m.logger != nil {
		m.logger.Debug("refresh token generated", ctx,
			"userID", userID)
	}

	// ===== STEP 5: Calculate Expiration =====
	now := time.Now()
	expiresAt := now.Add(m.refreshTokenDuration)

	// ===== STEP 6: Store Token =====
	// Store token with metadata in RefreshStore
	// This allows:
	//   - Token validation during refresh
	//   - Token revocation
	//   - User session tracking
	//   - Audit trails
	err = m.refreshStore.Store(
		ctx,          // Context for cancellation
		refreshToken, // Token ID (the token itself is the ID)
		userID,       // Who owns the token
		expiresAt,    // When it expires
		nil,          // No metadata (use IssueRefreshTokenWithMetadata for metadata)
	)
	if err != nil {
		if m.logger != nil {
			m.logger.Error("failed to store refresh token", ctx,
				"userID", userID,
				"error", err)
		}
		return "", fmt.Errorf("failed to store refresh token: %w", err)
	}
	if m.logger != nil {
		m.logger.Debug("refresh token stored", ctx,
			"userID", userID,
			"expiresAt", expiresAt)
	}

	// ===== STEP 7: Record Success and Log =====
	status = "success"
	errorType = ""
	if m.logger != nil {
		m.logger.Info("refresh token issued", ctx,
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
func (m *Manager)IssueRefreshTokenWithMetadata(ctx context.Context, userID string, metadata map[string]interface{}) (string, error) {
	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		if m.metrics != nil {
			m.metrics.IncrementCounter(metricTokensIssuedTotal, map[string]string{
				"status":     status,
				"error_type": errorType,
			})
			m.metrics.RecordDuration(metricOperationDuration, time.Since(start), map[string]string{
				"operation": "issue_refresh_token",
			})
		}
	}()

	// ===== STEP 1: Validate User ID =====
	if len(strings.TrimSpace(userID)) == 0 {
		status = "invalid_input"
		errorType = "invalid_input"
		if m.logger != nil {
			m.logger.Warn("attempted to get token with empty userID", ctx)
		}
		return "", ErrInvalidUserID
	}

	// ===== STEP 2: Service State Check =====
	if !m.IsRunning() {
		status = "not_running"
		errorType = "not_running"
		if m.logger != nil {
			m.logger.Warn("service not running", ctx)
		}
		return "", ErrManagerNotRunning
	}

	// ===== STEP 3: Context Check =====
	// Check if context is already cancelled/expired
	// Fail fast if client already disconnected
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		if m.logger != nil {
			m.logger.Warn("context cancelled during token issuance", ctx,
				"userID", userID,
				"error", err)
		}
		return "", err
	}

	if m.logger != nil {
		m.logger.Debug("issuing refresh token with metadata", ctx, "userID", userID)
	}

	// ===== STEP 4: Generate Refresh Token =====
	// Create cryptographic random token
	// this is an OPAQUE token (not a JWT)
	refreshToken, err := generateRefreshToken()
	if err != nil {
		if m.logger != nil {
			m.logger.Error("failed to generate refresh token", ctx,
				"userID", userID,
				"error", err)
		}
		return "", fmt.Errorf("failed to generate refresh token: %w", err)
	}
	if m.logger != nil {
		m.logger.Debug("refresh token generated", ctx,
			"userID", userID)
	}

	// ===== STEP 5: Calculate Expiration =====
	now := time.Now()
	expiresAt := now.Add(m.refreshTokenDuration)

	// ===== STEP 6: Store Token =====
	// Store token with metadata in RefreshStore
	// This allows:
	//   - Token validation during refresh
	//   - Token revocation
	//   - User session tracking
	//   - Audit trails
	err = m.refreshStore.Store(
		ctx,          // Context for cancellation
		refreshToken, // Token ID (the token itself is the ID)
		userID,       // Who owns the token
		expiresAt,    // When it expires
		metadata,     // Custom metadata
	)
	if err != nil {
		if m.logger != nil {
			m.logger.Error("failed to store refresh token with metadata", ctx,
				"userID", userID,
				"error", err)
		}
		return "", fmt.Errorf("failed to store refresh token with metadata: %w", err)
	}
	if m.logger != nil {
		m.logger.Debug("refresh token with metadata stored", ctx,
			"userID", userID,
			"metadataKeys", len(metadata),
			"expiresAt", expiresAt)
	}

	// ===== STEP 7: Record Success and Log =====
	status = "success"
	errorType = ""
	if m.logger != nil {
		m.logger.Info("refresh token with metadata issued", ctx,
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
func (m *Manager)IssueTokenPair(ctx context.Context, userID string) (string, string, error) {
	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		if m.metrics != nil {
			m.metrics.IncrementCounter(metricTokensIssuedTotal, map[string]string{
				"status":     status,
				"error_type": errorType,
			})
			m.metrics.RecordDuration(metricOperationDuration, time.Since(start), map[string]string{
				"operation": "issue_token_pair",
			})
		}
	}()

	// ===== STEP 1: Validate User ID =====
	if len(strings.TrimSpace(userID)) == 0 {
		status = "invalid_input"
		errorType = "invalid_input"
		if m.logger != nil {
			m.logger.Warn("attempted to get token with empty userID", ctx)
		}
		return "", "", ErrInvalidUserID
	}

	// ===== STEP 2: Service State Check =====
	if !m.IsRunning() {
		status = "not_running"
		errorType = "not_running"
		if m.logger != nil {
			m.logger.Warn("service not running", ctx)
		}
		return "", "", ErrManagerNotRunning
	}

	// ===== STEP 3: Context Check =====
	// Check if context is already cancelled/expired
	// Fail fast if client already disconnected
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		if m.logger != nil {
			m.logger.Warn("context cancelled during token issuance", ctx,
				"userID", userID,
				"error", err)
		}
		return "", "", err
	}

	if m.logger != nil {
		m.logger.Debug("issuing token pair", ctx, "userID", userID)
	}

	// ===== STEP 4: Get Signing Key =====
	privateKey, keyID, err := m.keyManager.GetCurrentSigningKey(ctx)
	if err != nil {
		if m.logger != nil {
			m.logger.Error("failed to get signing key", ctx,
				"userID", userID,
				"error", err)
		}
		return "", "", fmt.Errorf("failed to get signing key: %w", err)
	}

	// ===== STEP 5: Create JWT Claims =====
	now := time.Now()
	expiresAt := now.Add(m.accessTokenDuration)
	// Generate unique token ID (jti claim)
	tokenID, err := generateTokenID()
	if err != nil {
		if m.logger != nil {
			m.logger.Error("failed to generate token ID", ctx,
				"userID", userID,
				"error", err)
		}
		return "", "", fmt.Errorf("failed to generate token ID: %w", err)
	}

	// Create standard JWT claims
	claims := jwt.RegisteredClaims{
		Subject:   userID,                        // "sub" - who the token is for
		Issuer:    m.issuer,                      // "iss" - who issued the token
		Audience:  m.audience,                    // "aud" - who can use the token
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
		if m.logger != nil {
			m.logger.Error("failed to sign token", ctx,
				"userID", userID,
				"keyID", keyID,
				"error", err)
		}
		return "", "", fmt.Errorf("failed to sign token: %w", err)
	}

	// ===== STEP 8: Generate Refresh Token =====
	refreshToken, err := generateRefreshToken()
	if err != nil {
		if m.logger != nil {
			m.logger.Error("failed to generate refresh token", ctx,
				"userID", userID,
				"error", err)
		}
		return "", "", fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// ===== STEP 9: Calculate Refresh Token Expiration =====
	now = time.Now()
	expiresAt = now.Add(m.refreshTokenDuration)

	// ===== STEP 10: Store Refresh Token =====
	// Store token with metadata in RefreshStore
	// This allows:
	//   - Token validation during refresh
	//   - Token revocation
	//   - User session tracking
	//   - Audit trails
	err = m.refreshStore.Store(
		ctx,          // Context for cancellation
		refreshToken, // Token ID (the token itself is the ID)
		userID,       // Who owns the token
		expiresAt,    // When it expires
		nil,          // No metadata (use IssueRefreshTokenWithMetadata for metadata)
	)
	if err != nil {
		if m.logger != nil {
			m.logger.Error("failed to store refresh token", ctx,
				"userID", userID,
				"error", err)
		}
		return "", "", fmt.Errorf("failed to store refresh token: %w", err)
	}

	// ===== STEP 11: Record Success and Log =====
	status = "success"
	errorType = ""
	if m.logger != nil {
		m.logger.Info("token pair issued", ctx,
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
/// Returns the parsed RegisteredClaims on success, or one of: ErrManagerNotRunning,
// ErrTokenExpired, ErrTokenNotYetValid, ErrInvalidIssuer, ErrInvalidAudience,
// ErrInvalidToken (covers malformed tokens, wrong signing method, and unknown key IDs),
// or the context error.
func (m *Manager)ValidateAccessToken(ctx context.Context, tokenString string) (*jwt.RegisteredClaims, error) {
	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		if m.metrics != nil {
			m.metrics.IncrementCounter(metricTokensValidatedTotal, map[string]string{
				"status":     status,
				"error_type": errorType,
			})
			m.metrics.RecordDuration(metricOperationDuration, time.Since(start), map[string]string{
				"operation": "validate_access_token",
			})
		}
	}()

	// ===== STEP 1: Service State Check =====
	if !m.IsRunning() {
		status = "not_running"
		errorType = "not_running"
		if m.logger != nil {
			m.logger.Warn("attempted token validation while service stopped", ctx)
		}
		return nil, ErrManagerNotRunning
	}

	// ===== STEP 2: Context Check =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		if m.logger != nil {
			m.logger.Info("context cancelled during token validation", ctx,
				"error", err)
		}
		return nil, err
	}

	if m.logger != nil {
		m.logger.Debug("validating access token", ctx)
	}

	// ===== STEP 3: Parse JWT Token =====
	parseOpts := []jwt.ParserOption{}
	if m.clockSkew > 0 {
		parseOpts = append(parseOpts, jwt.WithLeeway(m.clockSkew))
	}

	token, err := jwt.ParseWithClaims(
		tokenString,
		&jwt.RegisteredClaims{},
		func(token *jwt.Token) (interface{}, error) {
			// ===== STEP 4a: Verify Signing Method =====
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				if m.logger != nil {
					m.logger.Warn("token uses unexpected signing method", ctx,
						"method", token.Header["alg"])
				}
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			// ===== STEP 4b: Extract Key ID =====
			kid, ok := token.Header["kid"].(string)
			if !ok {
				if m.logger != nil {
					m.logger.Warn("token missing kid in header", ctx)
				}
				return nil, errors.New("missing kid in token header")
			}
			if m.logger != nil {
				m.logger.Debug("token kid extracted from header", ctx,
					"kid", kid)
			}

			// ===== STEP 4c: Get Public Key =====
			publicKey, err := m.keyManager.GetPublicKey(ctx, kid)
			if err != nil {
				if m.logger != nil {
					m.logger.Error("failed to get public key", ctx,
						"kid", kid,
						"error", err)
				}
				return nil, fmt.Errorf("failed to get public key: %w", err)
			}
			if m.logger != nil {
				m.logger.Debug("public key retrieved for token validation", ctx,
					"kid", kid)
			}

			return publicKey, nil
		},
		parseOpts...,
	)

	// ===== STEP 5: Check Parsing Errors =====
	if err != nil {
		if m.logger != nil {
			m.logger.Warn("token parsing failed", ctx,
				"error", err)
		}

		// Provide specific error messages
		if errors.Is(err, jwt.ErrTokenExpired) {
			status = "expired"
			errorType = "expired"
			if m.logger != nil {
				m.logger.Warn("token expired", ctx)
			}
			return nil, ErrTokenExpired
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			status = "error"
			errorType = "not_yet_valid"
			return nil, ErrTokenNotYetValid
		}
		if errors.Is(err, keymanager.ErrKeyNotFound) {
			status = "error"
			errorType = "key_not_found"
			if m.logger != nil {
				m.logger.Warn("token references unknown key ID", ctx)
			}
			return nil, ErrInvalidToken
		}

		return nil, ErrInvalidToken
	}

	// ===== STEP 6: Verify Token is Valid =====
	if !token.Valid {
		if m.logger != nil {
			m.logger.Warn("token marked as invalid", ctx)
		}
		return nil, ErrInvalidToken
	}
	if m.logger != nil {
		m.logger.Debug("token signature and structure validated", ctx)
	}

	// ===== STEP 7: Extract Claims =====
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		if m.logger != nil {
			m.logger.Error("failed to extract claims from token", ctx)
		}
		return nil, ErrInvalidToken
	}
	if m.logger != nil {
		m.logger.Debug("claims extracted from token", ctx,
			"tokenID", claims.ID,
			"userID", claims.Subject)
	}

	// ===== STEP 8: Validate Issuer =====
	if m.issuer != "" && claims.Issuer != m.issuer {
		if m.logger != nil {
			m.logger.Warn("token issuer mismatch", ctx,
				"expected", m.issuer,
				"actual", claims.Issuer)
		}
		return nil, ErrInvalidIssuer
	}
	if m.logger != nil {
		m.logger.Debug("token issuer validated", ctx,
			"issuer", claims.Issuer)
	}

	// ===== STEP 9: Validate Audience =====
	if len(m.audience) > 0 {
		validAudience := false
		for _, aud := range m.audience {
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
			if m.logger != nil {
				m.logger.Warn("token audience mismatch", ctx,
					"expected", m.audience,
					"actual", claims.Audience)
			}
			return nil, ErrInvalidAudience
		}
		if m.logger != nil {
			m.logger.Debug("token audience validated", ctx,
				"audience", claims.Audience)
		}
	}

	// ===== STEP 10: Record Success and Log =====
	status = "success"
	errorType = ""
	if m.logger != nil {
		m.logger.Info("access token validated", ctx,
			"userID", claims.Subject,
			"tokenID", claims.ID)
	}

	return claims, nil
}

// ValidateAccessTokenWithClaims validates the token and returns both the registered
// claims and any custom claims embedded at issuance via IssueAccessTokenWithClaimm.
// Reserved claim keys (sub, exp, nbf, iat, jti, iss, aud) are excluded from the
// custom claims map so callers receive only the application-defined fieldm.
// Returns an empty map when no custom claims were embedded.
//
// Returns ErrManagerNotRunning if the service has not been started, ErrTokenExpired
// if the token has expired beyond the configured ClockSkew, ErrTokenNotYetValid if
// the nbf claim has not been reached, ErrInvalidIssuer or ErrInvalidAudience if
// configured values do not match, ErrInvalidToken for malformed tokens or unknown
// key IDs, or the context error if the context is cancelled.
func (m *Manager)ValidateAccessTokenWithClaims(ctx context.Context, tokenString string) (*jwt.RegisteredClaims, map[string]interface{}, error) {
	// ===== STEP 1: Validate via Standard Path =====
	// All error handling (signature, expiry, issuer, audience, metrics, logging)
	// is handled by ValidateAccessToken — no duplication needed.
	registered, err := m.ValidateAccessToken(ctx, tokenString)
	if err != nil {
		return nil, nil, err
	}

	// ===== STEP 2: Re-Parse for Custom Claims =====
	// Signature is already verified above; ParseUnverified is safe here and
	// avoids a second key-manager round-trip.
	rawToken, _, parseErr := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if parseErr != nil {
		// Token validated above — treat missing custom claims as empty rather than error.
		return registered, map[string]interface{}{}, nil
	}

	mapClaims, ok := rawToken.Claims.(jwt.MapClaims)
	if !ok {
		return registered, map[string]interface{}{}, nil
	}

	// ===== STEP 3: Strip Reserved Claims =====
	reserved := map[string]struct{}{
		"sub": {}, "exp": {}, "nbf": {}, "iat": {}, "jti": {}, "iss": {}, "aud": {},
	}
	custom := make(map[string]interface{}, len(mapClaims))
	for k, v := range mapClaims {
		if _, isReserved := reserved[k]; !isReserved {
			custom[k] = v
		}
	}

	return registered, custom, nil
}

// RefreshAccessToken exchanges a valid refresh token for a new access token.
// It retrieves the refresh token from storage, checks expiration and revocation
// status, then calls IssueAccessToken for the token's owner.
//
// Returns ErrManagerNotRunning, ErrInvalidRefreshToken, ErrRefreshTokenExpired,
// ErrTokenRevoked, or the context error.
func (m *Manager)RefreshAccessToken(ctx context.Context, refreshToken string) (string, error) {
	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		if m.metrics != nil {
			m.metrics.IncrementCounter(metricTokensRefreshedTotal, map[string]string{
				"status":     status,
				"error_type": errorType,
			})
			m.metrics.RecordDuration(metricOperationDuration, time.Since(start), map[string]string{
				"operation": "refresh_access_token",
			})
		}
	}()

	// ===== STEP 1: Service State Check =====
	if !m.isRunning.Load() {
		status = "not_running"
		errorType = "not_running"
		if m.logger != nil {
			m.logger.Warn("attempted to refresh while service was stopped", ctx)
		}
		return "", ErrManagerNotRunning
	}

	// ===== STEP 2: Context Check =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		if m.logger != nil {
			m.logger.Info("context cancelled during token refresh", ctx)
		}
		return "", err
	}

	if m.logger != nil {
		m.logger.Debug("attempting token refresh", ctx)
	}

	// ===== STEP 3: Input Validation =====
	if refreshToken == "" {
		status = "invalid_input"
		errorType = "invalid_input"
		if m.logger != nil {
			m.logger.Warn("empty refresh token provided", ctx)
		}
		return "", ErrInvalidRefreshToken
	}

	// ===== STEP 4: Lookup Refresh Token =====
	token, err := m.refreshStore.Retrieve(ctx, refreshToken)
	if err != nil {
		if m.logger != nil {
			m.logger.Warn("refresh token not found in store", ctx,
				"error", err)
		}
		// Propagate specific errors, default to invalid token for generic errors
		if errors.Is(err, storage.ErrTokenRevoked) {
			status = "revoked"
			errorType = "revoked"
			return "", ErrTokenRevoked
		}
		status = "not_found"
		errorType = "not_found"
		return "", ErrInvalidRefreshToken
	}

	if m.logger != nil {
		m.logger.Debug("refresh token retrieved from store", ctx,
			"userID", token.UserID,
			"tokenID", token.TokenID)
	}

	// ===== STEP 5: Check Expiration =====
	if token.ExpiresAt.Before(time.Now()) {
		status = "expired"
		errorType = "expired"
		if m.logger != nil {
			m.logger.Warn("refresh token has expired", ctx,
				"tokenID", refreshToken,
				"expiredAt", token.ExpiresAt)
		}

		// Clean up expired token (ignore error — we're returning ErrRefreshTokenExpired anyway)
		_ = m.refreshStore.Revoke(ctx, refreshToken)

		return "", ErrRefreshTokenExpired
	}

	// ===== STEP 6: Check If Revoked =====
	if token.Revoked {
		status = "revoked"
		errorType = "revoked"
		if m.logger != nil {
			m.logger.Warn("refresh token has been revoked", ctx,
				"tokenID", refreshToken)
		}
		return "", ErrTokenRevoked
	}

	// ===== STEP 7: Issue New Access Token =====
	newAccessToken, err := m.IssueAccessToken(ctx, token.UserID)
	if err != nil {
		if m.logger != nil {
			m.logger.Error("failed to issue new access token", ctx,
				"userID", token.UserID,
				"error", err)
		}
		return "", fmt.Errorf("failed to issue access token: %w", err)
	}

	// ===== STEP 9: Record Success and Log =====
	status = "success"
	errorType = ""
	if m.logger != nil {
		m.logger.Info("access token refreshed", ctx,
			"userID", token.UserID,
			"tokenID", refreshToken)
	}

	return newAccessToken, nil
}

// RevokeRefreshToken marks a single refresh token as revoked in the RefreshStore.
// Subsequent calls to RefreshAccessToken or IntrospectToken will see the token
// as inactive.
//
// Returns ErrManagerNotRunning, ErrInvalidRefreshToken for empty tokenID, or
// the context error.
func (m *Manager)RevokeRefreshToken(ctx context.Context, tokenID string) error {
	start := time.Now()
	status := "error"
	defer func() {
		if m.metrics != nil {
			m.metrics.IncrementCounter(metricTokensRevokedTotal, map[string]string{
				"operation": "single",
				"status":    status,
			})
			m.metrics.RecordDuration(metricOperationDuration, time.Since(start), map[string]string{
				"operation": "revoke_token",
			})
		}
	}()

	// ===== STEP 1: Service State Check =====
	if !m.isRunning.Load() {
		status = "not_running"
		if m.logger != nil {
			m.logger.Warn("attempted to revoke token while service stopped", ctx)
		}
		return ErrManagerNotRunning
	}

	// ===== STEP 2: Context Check =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		if m.logger != nil {
			m.logger.Info("context cancelled during token revocation", ctx)
		}
		return err
	}

	// ===== STEP 3: Input Validation =====
	if tokenID == "" {
		status = "invalid_input"
		if m.logger != nil {
			m.logger.Warn("empty token ID provided for revocation", ctx)
		}
		return ErrInvalidRefreshToken
	}

	// ===== STEP 4: Revoke Token =====
	err := m.refreshStore.Revoke(ctx, tokenID)
	if err != nil {
		if m.logger != nil {

			m.logger.Error("failed to revoke refresh token", ctx,
				"tokenID", tokenID,
				"error", err)
		}
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	// ===== STEP 5: Record Success and Log =====
	status = "success"
	if m.logger != nil {
		m.logger.Info("refresh token revoked", ctx,
			"tokenID", tokenID)
	}

	return nil
}

// RevokeAllUserTokens revokes every refresh token belonging to the given user.
// Use this for logout-all-devices or account suspension scenariom.
//
// Returns ErrManagerNotRunning, ErrInvalidUserID for empty userID, or the
// context error.
func (m *Manager)RevokeAllUserTokens(ctx context.Context, userID string) error {
	start := time.Now()
	status := "error"
	defer func() {
		if m.metrics != nil {
			m.metrics.IncrementCounter(metricTokensRevokedTotal, map[string]string{
				"operation": "all_user",
				"status":    status,
			})
			m.metrics.RecordDuration(metricOperationDuration, time.Since(start), map[string]string{
				"operation": "revoke_all_user_tokens",
			})
		}
	}()

	// ===== STEP 1: Service State Check =====
	if !m.isRunning.Load() {
		status = "not_running"
		if m.logger != nil {
			m.logger.Warn("attempted to revoke all user tokens while service stopped", ctx)
		}
		return ErrManagerNotRunning
	}

	// ===== STEP 2: Context Check =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		if m.logger != nil {
			m.logger.Info("context cancelled during bulk token revocation", ctx,
				"error", err)
		}
		return err
	}

	// ===== STEP 3: Input Validation =====
	if userID == "" {
		status = "invalid_input"
		if m.logger != nil {
			m.logger.Warn("empty user ID provided for bulk revocation", ctx)
		}
		return ErrInvalidUserID // Note: Different error than single revoke
	}

	// ===== STEP 4: Revoke All Tokens For User =====
	err := m.refreshStore.RevokeAllForUser(ctx, userID)
	if err != nil {
		if m.logger != nil {
			m.logger.Error("failed to revoke all user tokens", ctx,
				"userID", userID,
				"error", err)
		}
		return fmt.Errorf("failed to revoke all tokens: %w", err)
	}

	// ===== STEP 5: Record Success and Log =====
	status = "success"
	if m.logger != nil {
		m.logger.Info("all refresh tokens revoked for user", ctx,
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
// Returns ErrManagerNotRunning, ErrInvalidRefreshToken for empty tokens, or
// the context error.
func (m *Manager)IntrospectToken(ctx context.Context, token string) (*TokenMetadata, error) {
	start := time.Now()
	status := "error"
	defer func() {
		if m.metrics != nil {
			m.metrics.IncrementCounter(metricTokensIntrospectedTotal, map[string]string{
				"status": status,
			})
			m.metrics.RecordDuration(metricOperationDuration, time.Since(start), map[string]string{
				"operation": "introspect_token",
			})
		}
	}()

	// ===== STEP 1: Service State Check =====
	if !m.isRunning.Load() {
		status = "not_running"
		if m.logger != nil {
			m.logger.Warn("attempted to introspect token while service is stopped", ctx)
		}
		return nil, ErrManagerNotRunning
	}

	// ===== STEP 2: Context Check =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		if m.logger != nil {
			m.logger.Info("context cancelled during token introspection", ctx)
		}
		return nil, err
	}

	if m.logger != nil {
		m.logger.Debug("introspecting token", ctx)
	}

	// ===== STEP 3: Input Validation =====
	if token == "" {
		status = "invalid_input"
		if m.logger != nil {
			m.logger.Warn("empty token provided for introspection", ctx)
		}
		return nil, ErrInvalidRefreshToken
	}

	// ===== STEP 4: Retrieve Token From Storage =====
	refreshToken, err := m.refreshStore.Retrieve(ctx, token)
	if err != nil {
		// Return inactive metadata instead of error — introspect never errors on unknown tokens
		status = "success"
		if m.logger != nil {
			m.logger.Info("token not found during introspection", ctx,
				"error", err)
		}
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
		status = "success"
		if m.logger != nil {
			m.logger.Info("introspect token is expired", ctx,
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
		status = "success"
		if m.logger != nil {
			m.logger.Info("introspected token is revoked", ctx,
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

	// ===== STEP 6: Record Success and Return Active Token Metadata =====
	status = "success"
	if m.logger != nil {
		m.logger.Info("token introspection successfully", ctx,
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
// so manual calls are only needed for on-demand sweepm.
//
// Returns the number of tokens deleted, ErrManagerNotRunning, or the context error.
func (m *Manager)CleanupExpiredTokens(ctx context.Context) (int, error) {
	start := time.Now()
	status := "error"
	defer func() {
		if m.metrics != nil {
			m.metrics.IncrementCounter(metricOperationsTotal, map[string]string{
				"operation": "cleanup",
				"status":    status,
			})
			m.metrics.RecordDuration(metricOperationDuration, time.Since(start), map[string]string{
				"operation": "cleanup",
			})
		}
	}()

	// ===== STEP 1: Service State Check =====
	if !m.isRunning.Load() {
		status = "not_running"
		if m.logger != nil {
			m.logger.Warn("attempted cleanup while service stopped", ctx)
		}
		return 0, ErrManagerNotRunning
	}

	// ===== STEP 2: Context Check =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		if m.logger != nil {
			m.logger.Info("context cancelled during cleanup", ctx,
				"error", err)
		}
		return 0, err
	}

	// ===== STEP 3: Run Cleanup =====
	count, err := m.refreshStore.Cleanup(ctx)
	if err != nil {
		if m.logger != nil {
			m.logger.Error("failed to cleanup expired tokens", ctx,
				"error", err)
		}
		return 0, fmt.Errorf("cleanup failed: %w", err)
	}

	// ===== STEP 4: Record Success and Log =====
	status = "success"
	if m.logger != nil {
		m.logger.Info("expired tokens cleaned up", ctx,
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
