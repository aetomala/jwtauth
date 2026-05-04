// Package tokens provides stateful JWT authorization token management.
//
// Manager handles the complete token lifecycle: access token issuance with
// RS256 signing, refresh token rotation with expiration checks, instant revocation
// (single token and bulk operations), and coordinated cleanup across distributed
// deployments.
//
// Identity verification is out of scope. Pass a verified subject ID (user ID) to
// IssueTokenPair or IssueAccessToken after you've authenticated the user.
//
// Key capabilities:
//   - Access token issuance (short-lived, typically 15 minutes)
//   - Refresh token issuance and rotation (long-lived, typically 30 days)
//   - Token validation with signature verification and claims enforcement
//   - Instant revocation (RevokeRefreshToken, RevokeAllUserTokens)
//   - Token introspection per RFC 7662 (IntrospectToken)
//   - Background cleanup of expired refresh tokens
//   - Clock skew tolerance for distributed deployments (ClockSkew field)
//   - Custom claims support with reserved claim protection
//
// Example usage:
//
//	config := tokens.TokenManagerConfig{
//	    KeyManager:   keyManager,        // Handles RSA keys and rotation
//	    RefreshStore: refreshStore,      // Persists refresh tokens (Redis, Memory, etc.)
//	    Logger:       logger,            // Optional structured logging
//	    Metrics:      metrics,           // Optional Prometheus metrics
//	    AccessTokenDuration:  15 * time.Minute,
//	    RefreshTokenDuration: 30 * 24 * time.Hour,
//	    ClockSkew:    30 * time.Second,  // Optional leeway for NTP drift
//	    Issuer:       "my-app",
//	    Audience:     []string{"my-app-api"},
//	}
//
//	mgr, err := tokens.NewManager(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Start lifecycle (background cleanup, etc.)
//	ctx := context.Background()
//	if err := mgr.Start(ctx); err != nil {
//	    log.Fatal(err)
//	}
//	defer mgr.Shutdown(ctx)
//
//	// Issue token pair (access + refresh)
//	accessToken, refreshToken, err := mgr.IssueTokenPair(ctx, userID)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Later: validate access token
//	claims, err := mgr.ValidateAccessToken(ctx, accessToken)
//	if err != nil {
//	    // Handle error (expired, revoked, invalid, etc.)
//	}
//
//	// Later: refresh access token
//	newAccessToken, err := mgr.RefreshAccessToken(ctx, refreshToken)
//	if err != nil {
//	    // Handle error (refresh token expired, revoked, etc.)
//	}
//
//	// On logout: revoke all user sessions
//	if err := mgr.RevokeAllUserTokens(ctx, userID); err != nil {
//	    log.Fatal(err)
//	}
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

	"github.com/aetomala/jwtauth/pkg/keys"
	"github.com/aetomala/jwtauth/pkg/logging"
	"github.com/aetomala/jwtauth/pkg/metrics"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/aetomala/jwtauth/pkg/tracing"
	"github.com/golang-jwt/jwt/v5"
)

// TokenManagerConfig holds the configuration for a Manager.
//
// KeyManager and RefreshStore are required. All duration fields
// default to production-safe values via DefaultTokenManagerConfig if left at zero.
type TokenManagerConfig struct {
	// Required dependencies
	KeyManager   keys.KeyManager // Signs and validates tokens
	RefreshStore storage.RefreshStore  // Persists refresh tokens

	// Optional
	Logger    logging.Logger  // Optional; nil defaults to NoOpLogger.
	Metrics   metrics.Metrics // Optional; nil defaults to NoOpMetrics.
	Tracer    tracing.Tracer  // Optional; nil defaults to NoOpTracer.
	Namespace string          // Optional; opaque label attached to observability output — empty disables labeling

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
	keyManager   keys.KeyManager // Crypto operations
	refreshStore storage.RefreshStore  // Token storage
	logger       logging.Logger        // never nil; defaults to NoOpLogger
	metrics      metrics.Metrics       // never nil; defaults to NoOpMetrics
	tracer       tracing.Tracer        // never nil; defaults to NoOpTracer

	// ===== Configuration (Immutable) =====
	accessTokenDuration  time.Duration // e.g., 15 minutes
	refreshTokenDuration time.Duration // e.g., 30 days
	cleanupInterval      time.Duration // e.g., 1 hour
	issuer               string        // JWT "iss" claim
	audience             []string      // JWT "aud" claim
	clockSkew            time.Duration // Leeway applied to exp and nbf validation
	namespace            string        // Optional; opaque label for observability output

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

// DefaultTokenManagerConfig returns a TokenManagerConfig populated with production-safe defaultm.
// NewManager applies these automatically for any zero-value duration fieldm.
func DefaultTokenManagerConfig() TokenManagerConfig {
	return TokenManagerConfig{
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 30 * 24 * time.Hour,
		CleanupInterval:      1 * time.Hour,
		Logger:               &logging.NoOpLogger{},
		Metrics:              metrics.NewNoOpMetrics(),
		Tracer:               tracing.NewNoOpTracer(),
	}
}

// IsRunning reports whether the manager has been started and not yet shut down.
// Safe to call concurrently.
func (m *Manager) IsRunning() bool {
	return m.isRunning.Load()
}

// NewManager constructs a Manager from the given config. Zero-value duration
// fields are filled with defaults from DefaultTokenManagerConfig. Returns an error if any
// required dependency is nil or a duration is negative.
func NewManager(config TokenManagerConfig) (*Manager, error) {
	if config.AccessTokenDuration == 0 {
		config.AccessTokenDuration = DefaultTokenManagerConfig().AccessTokenDuration
	}

	if config.RefreshTokenDuration == 0 {
		config.RefreshTokenDuration = DefaultTokenManagerConfig().RefreshTokenDuration
	}

	if config.CleanupInterval == 0 {
		config.CleanupInterval = DefaultTokenManagerConfig().CleanupInterval
	}

	if config.Logger == nil {
		config.Logger = DefaultTokenManagerConfig().Logger
	}
	if config.Metrics == nil {
		config.Metrics = DefaultTokenManagerConfig().Metrics
	}
	if config.Tracer == nil {
		config.Tracer = DefaultTokenManagerConfig().Tracer
	}

	if config.Namespace != "" {
		config.Logger = config.Logger.With("namespace", config.Namespace)
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
		tracer:               config.Tracer,
		accessTokenDuration:  config.AccessTokenDuration,
		refreshTokenDuration: config.RefreshTokenDuration,
		cleanupInterval:      config.CleanupInterval,
		clockSkew:            config.ClockSkew,
		issuer:               config.Issuer,
		audience:             config.Audience,
		namespace:            config.Namespace,
		shutdownChan:         make(chan struct{}),
	}

	return m, nil
}

// startSpan begins a new tracing span for the given Manager operation.
func (m *Manager) startSpan(ctx context.Context, operation string, opts ...tracing.SpanOption) (context.Context, tracing.Span) {
	opts = append([]tracing.SpanOption{
		tracing.WithAttributes(map[string]any{
			"token.namespace": m.namespace,
		}),
	}, opts...)
	return m.tracer.Start(ctx, "TokenManager."+operation, opts...)
}

// Start initializes the service and begins background operations. It starts
// the KeyManager and launches the cleanup goroutine that periodically purges
// expired refresh tokens.
//
// Start is idempotent — calling it on an already-running service is a no-op.
// Returns an error if the KeyManager fails to start or the context is cancelled.
// The ctx passed to Start is forwarded to the cleanup goroutine's store calls —
// pass a long-lived context (e.g. the process root) so cleanup continues for
// the full lifetime of the service.
func (m *Manager) Start(ctx context.Context) error {
	ctx, span := m.startSpan(ctx, "Start")
	defer span.End()

	// ===== STEP 1: Check If Already Running (Idempotent) =====
	if !m.isRunning.CompareAndSwap(false, true) {
		// Already running — idempotent no-op, no metric recorded
		m.logger.Debug("start called but service already running", ctx)
		return nil // Already running, not an error
	}

	// ===== STEP 2: Log Startup =====
	m.logger.Info("starting token service", ctx)

	// ===== STEP 3: Start KeyManager =====
	if err := m.keyManager.Start(ctx); err != nil {
		m.isRunning.Store(false) // Revert state

		m.logger.Error("failed to start token service", ctx,
			"error", err)
		wrapped := fmt.Errorf("failed to start key manager: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return wrapped
	}

	// ===== STEP 4: Start Background Cleanup Goroutine =====
	m.wg.Add(1)
	go m.cleanupLoop(ctx)

	// ===== STEP 5: Record Metric and Log Success =====
	m.metrics.SetGauge(metricServiceRunning, 1.0, map[string]string{})
	m.logger.Info("token service started", ctx)
	span.SetStatus(tracing.StatusOK, "")
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
			m.logger.Debug("cleanup loop tick started", ctx)
			// Cleanup expired refresh tokens
			m.logger.Debug("cleanup ticker fired", ctx)
			if count, err := m.refreshStore.Cleanup(ctx); err != nil {
				m.logger.Error("refresh token cleanup failed", ctx,
					"error", err)
			} else {
				m.logger.Info("refresh token cleanup completed", ctx,
					"tokens", count)
			}

		case <-m.shutdownChan:
			m.logger.Info("cleanup loop stopping", ctx)
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
// After a clean shutdown the manager may be restarted via Start. Restart is
// not guaranteed after a timeout shutdown — the cleanup goroutine may still
// hold a reference to the closed channel; treat a timeout Shutdown as fatal
// and discard the manager.
func (m *Manager) Shutdown(ctx context.Context) error {
	ctx, span := m.startSpan(ctx, "Shutdown")
	defer span.End()

	// ===== STEP 1: Check If Running (Idempotent) =====
	if !m.isRunning.CompareAndSwap(true, false) {
		m.logger.Debug("shutdown called but service not running", ctx)
		span.SetStatus(tracing.StatusOK, "")
		return nil // Already stopped, not an error
	}

	// ===== STEP 2: Log Shutdown =====
	m.logger.Info("shutting down token service", ctx)

	// ===== STEP 3: Signal Background Goroutines =====
	close(m.shutdownChan)

	// ===== STEP 4: Wait For Goroutines With Timeout =====
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	// Drain a pre-cancelled context before the blocking select so that a
	// caller-cancelled ctx reliably wins over a fast goroutine exit.
	select {
	case <-ctx.Done():
		span.RecordError(ctx.Err())
		span.SetStatus(tracing.StatusError, ctx.Err().Error())
		return ctx.Err()
	default:
	}

	select {
	case <-done:
		// Goroutines completed — recreate shutdownChan so the manager can be
		// restarted via Start.
		m.shutdownChan = make(chan struct{})
	case <-ctx.Done():
		// Timeout
		m.logger.Warn("shutdown timeout waiting for goroutines", ctx,
			"error", ctx.Err())
		span.RecordError(ctx.Err())
		span.SetStatus(tracing.StatusError, ctx.Err().Error())
		return ctx.Err()
	}

	// ===== STEP 5: Shutdown KeyManager =====
	if err := m.keyManager.Shutdown(ctx); err != nil {
		m.logger.Error("failed to shutdown key manager", ctx,
			"error", err)
		wrapped := fmt.Errorf("failed to shutdown key manager: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return wrapped
	}

	// ===== STEP 6: Record Metric and Log Success =====
	m.metrics.SetGauge(metricServiceRunning, 0.0, map[string]string{})
	m.logger.Info("token service stopped", ctx)
	span.SetStatus(tracing.StatusOK, "")
	return nil
}

// IssueAccessToken creates and signs an RS256 JWT access token for the given
// user. The token carries standard registered claims (sub, iss, aud, exp, iat,
// nbf, jti) and is signed with the current key from the KeyManager.
//
// Returns ErrInvalidUserID for empty/whitespace-only user IDs, ErrManagerNotRunning
// if the service is stopped, or the context error if the context is already cancelled.
func (m *Manager) IssueAccessToken(ctx context.Context, userID string) (string, error) {
	ctx, span := m.startSpan(ctx, "IssueAccessToken")
	defer span.End()

	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		m.metrics.IncrementCounter(metricTokensIssuedTotal, map[string]string{
			"status":     status,
			"error_type": errorType,
			"namespace":  m.namespace,
		})
		m.metrics.RecordDuration(metricOperationDuration, time.Since(start), map[string]string{
			"operation": "issue_access_token",
			"namespace":  m.namespace,
		})
	}()

	// ===== STEP 1: Validate User ID =====
	if len(strings.TrimSpace(userID)) == 0 {
		status = "invalid_input"
		errorType = "invalid_input"
		m.logger.Warn("attempted to get token with empty userID", ctx)
		span.RecordError(ErrInvalidUserID)
		span.SetStatus(tracing.StatusError, ErrInvalidUserID.Error())
		return "", ErrInvalidUserID
	}

	span.SetAttribute("user_id", userID)

	// ===== STEP 2: Service State Check =====
	if !m.IsRunning() {
		status = "not_running"
		errorType = "not_running"
		m.logger.Warn("service not running", ctx)
		span.RecordError(ErrManagerNotRunning)
		span.SetStatus(tracing.StatusError, ErrManagerNotRunning.Error())
		return "", ErrManagerNotRunning
	}
	// ===== STEP 3: Context Check =====
	// Check if context is already cancelled/expired
	// Fail fast if client already disconnected
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		m.logger.Warn("context cancelled during token issuance", ctx,
			"userID", userID,
			"error", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return "", err
	}

	// ===== STEP 4: Get Signing Key =====
	// Retrieve current private key and its ID from KeyManager
	// The key ID will be included in the JWT header for verification
	privateKey, keyID, err := m.keyManager.GetCurrentSigningKey(ctx)
	if err != nil {
		m.logger.Error("failed to get signing key", ctx,
			"userID", userID,
			"error", err)
		wrapped := fmt.Errorf("failed to get signing key: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return "", wrapped
	}
	m.logger.Debug("signing key retrieved", ctx,
		"userID", userID,
		"keyID", keyID)

	// ===== STEP 5: Create JWT Claims =====
	now := time.Now()
	expiresAt := now.Add(m.accessTokenDuration)
	// Generate unique token ID (jti claim)
	tokenID, err := generateTokenID()
	if err != nil {
		m.logger.Error("failed to generate token ID", ctx,
			"userID", userID,
			"error", err)
		wrapped := fmt.Errorf("failed to generate token ID: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return "", wrapped
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
	m.logger.Debug("access token claims created", ctx,
		"userID", userID,
		"tokenID", tokenID,
		"expiresAt", expiresAt)

	span.SetAttribute("token_id", tokenID)

	// ===== STEP 6: Sign Token =====
	// Create JWT with RS256 algorithm (RSA signature with SHA-256)
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Set key ID in header for key rotation support
	// Validators will use this to fetch the correct public key
	token.Header["kid"] = keyID

	// Sign the token with private key
	signedToken, err := token.SignedString(privateKey)

	if err != nil {
		m.logger.Error("failed to sign token", ctx,
			"userID", userID,
			"keyID", keyID,
			"error", err)
		wrapped := fmt.Errorf("failed to sign token: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return "", wrapped
	}
	m.logger.Debug("access token signed", ctx,
		"userID", userID,
		"tokenID", tokenID)

	// ===== STEP 8: Record Success and Log =====
	status = "success"
	errorType = ""
	m.logger.Info("access token issued", ctx,
		"userID", userID,
		"tokenID", tokenID,
		"keyID", keyID,
		"expiresAt", expiresAt)
	span.SetStatus(tracing.StatusOK, "")
	return signedToken, nil
}

// IssueAccessTokenWithClaims creates a signed RS256 JWT access token with
// additional custom claims merged into the payload. Reserved claims (sub, iss,
// exp, iat, nbf, jti) cannot be overridden — any attempt is silently dropped
// and logged as a warning.
//
// Returns the same errors as IssueAccessToken.
func (m *Manager) IssueAccessTokenWithClaims(ctx context.Context, userID string, claims CustomClaims) (string, error) {
	ctx, span := m.startSpan(ctx, "IssueAccessTokenWithClaims")
	defer span.End()

	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		m.metrics.IncrementCounter(metricTokensIssuedTotal, map[string]string{
			"status":     status,
			"error_type": errorType,
			"namespace":  m.namespace,
		})
		m.metrics.RecordDuration(metricOperationDuration, time.Since(start), map[string]string{
			"operation": "issue_access_token",
			"namespace":  m.namespace,
		})
	}()

	// ===== STEP 1: Validate User ID =====
	if len(strings.TrimSpace(userID)) == 0 {
		status = "invalid_input"
		errorType = "invalid_input"
		m.logger.Warn("attempted to get token with empty userID", ctx)
		span.RecordError(ErrInvalidUserID)
		span.SetStatus(tracing.StatusError, ErrInvalidUserID.Error())
		return "", ErrInvalidUserID
	}

	span.SetAttribute("user_id", userID)

	// ===== STEP 2: Service State Check =====
	if !m.IsRunning() {
		status = "not_running"
		errorType = "not_running"
		m.logger.Warn("service not running", ctx)
		span.RecordError(ErrManagerNotRunning)
		span.SetStatus(tracing.StatusError, ErrManagerNotRunning.Error())
		return "", ErrManagerNotRunning
	}

	// ===== STEP 3: Context Check =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		m.logger.Warn("context cancelled during token issuance", ctx,
			"userID", userID,
			"error", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return "", err
	}

	// ===== STEP 4: Get Signing Key =====
	privateKey, keyID, err := m.keyManager.GetCurrentSigningKey(ctx)
	if err != nil {
		m.logger.Error("failed to get signing key", ctx,
			"userID", userID,
			"error", err)
		wrapped := fmt.Errorf("failed to get signing key: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return "", wrapped
	}
	m.logger.Debug("signing key retrieved", ctx,
		"userID", userID,
		"keyID", keyID)

	now := time.Now()
	expiresAt := now.Add(m.accessTokenDuration)
	tokenID, err := generateTokenID()
	if err != nil {
		m.logger.Error("failed to generate token ID", ctx,
			"userID", userID,
			"error", err)
		wrapped := fmt.Errorf("failed to generate token ID: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return "", wrapped
	}

	span.SetAttribute("token_id", tokenID)

	// Create map claims to support both standard and custom claims
	jwtClaims := jwt.MapClaims{
		"sub": userID,
		"iss": m.issuer,
		"aud": m.audience,
		"exp": expiresAt.Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"jti": tokenID,
	}

	// Merge custom claims — reserved keys are silently dropped.
	reservedClaims := map[string]bool{
		"sub": true, "iss": true, "aud": true, "exp": true,
		"iat": true, "nbf": true, "jti": true,
	}

	customClaimsCount := 0
	for key, value := range claims {
		if !reservedClaims[key] {
			jwtClaims[key] = value
			customClaimsCount++
		} else {
			m.logger.Warn("attempted to override reserved claim", ctx,
				"userID", userID,
				"claim", key)
		}
	}
	m.logger.Debug("access token claims created with custom claims", ctx,
		"userID", userID,
		"tokenID", tokenID,
		"customClaimsCount", customClaimsCount,
		"expiresAt", expiresAt)

	// Sign token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwtClaims)
	token.Header["kid"] = keyID

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		m.logger.Error("failed to sign token with custom claims", ctx,
			"userID", userID,
			"keyID", keyID,
			"error", err)
		wrapped := fmt.Errorf("failed to sign token: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return "", wrapped
	}
	m.logger.Debug("access token with custom claims signed", ctx,
		"userID", userID,
		"tokenID", tokenID)
	// ===== STEP 8: Record Success and Log =====
	status = "success"
	errorType = ""
	m.logger.Info("access token with custom claims issued", ctx,
		"userID", userID,
		"tokenID", tokenID,
		"keyID", keyID,
		"customClaims", len(claims),
		"expiresAt", expiresAt)
	span.SetStatus(tracing.StatusOK, "")
	return signedToken, nil
}

// IssueRefreshToken creates and stores an opaque, cryptographically random
// refresh token for the given user. Unlike access tokens, refresh tokens are
// not JWTs — they are 256-bit random values stored in the RefreshStore.
//
// Returns the same errors as IssueAccessToken.
func (m *Manager) IssueRefreshToken(ctx context.Context, userID string) (string, error) {
	ctx, span := m.startSpan(ctx, "IssueRefreshToken")
	defer span.End()

	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		m.metrics.IncrementCounter(metricTokensIssuedTotal, map[string]string{
			"status":     status,
			"error_type": errorType,
			"namespace":  m.namespace,
		})
		m.metrics.RecordDuration(metricOperationDuration, time.Since(start), map[string]string{
			"operation": "issue_refresh_token",
			"namespace":  m.namespace,
		})
	}()

	// ===== STEP 1: Validate User ID =====
	if len(strings.TrimSpace(userID)) == 0 {
		status = "invalid_input"
		errorType = "invalid_input"
		m.logger.Warn("attempted to get token with empty userID", ctx)
		span.RecordError(ErrInvalidUserID)
		span.SetStatus(tracing.StatusError, ErrInvalidUserID.Error())
		return "", ErrInvalidUserID
	}

	span.SetAttribute("user_id", userID)

	// ===== STEP 2: Service State Check =====
	if !m.IsRunning() {
		status = "not_running"
		errorType = "not_running"
		m.logger.Warn("service not running", ctx)
		span.RecordError(ErrManagerNotRunning)
		span.SetStatus(tracing.StatusError, ErrManagerNotRunning.Error())
		return "", ErrManagerNotRunning
	}

	// ===== STEP 3: Context Check =====
	// Check if context is already cancelled/expired
	// Fail fast if client already disconnected
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		m.logger.Warn("context cancelled during token issuance", ctx,
			"userID", userID,
			"error", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return "", err
	}

	m.logger.Debug("issuing refresh token", ctx, "userID", userID)

	// ===== STEP 4: Generate Refresh Token =====
	// Create cryptographic random token
	// this is an OPAQUE token (not a JWT)
	refreshToken, err := generateRefreshToken()
	if err != nil {
		m.logger.Error("failed to generate refresh token", ctx,
			"userID", userID,
			"error", err)
		wrapped := fmt.Errorf("failed to generate refresh token: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return "", wrapped
	}
	m.logger.Debug("refresh token generated", ctx,
		"userID", userID)

	span.SetAttribute("token_id", refreshToken)

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
		m.audience,   // Audience — overridden per-call in Phase 3
		expiresAt,    // When it expires
		nil,          // No claims (use IssueRefreshTokenWithClaims to attach claims)
	)
	if err != nil {
		m.logger.Error("failed to store refresh token", ctx,
			"userID", userID,
			"error", err)
		wrapped := fmt.Errorf("failed to store refresh token: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return "", wrapped
	}
	m.logger.Debug("refresh token stored", ctx,
		"userID", userID,
		"expiresAt", expiresAt)

	// ===== STEP 7: Record Success and Log =====
	status = "success"
	errorType = ""
	m.logger.Info("refresh token issued", ctx,
		"userID", userID,
		"tokenID", refreshToken,
		"expiresAt", expiresAt)
	span.SetStatus(tracing.StatusOK, "")
	return refreshToken, nil
}

// IssueRefreshTokenWithClaims behaves like IssueRefreshToken but stores
// arbitrary claims alongside the token (e.g. device ID, IP address, session
// tags). The claims are retrievable via IntrospectToken.
//
// Returns the same errors as IssueAccessToken.
func (m *Manager) IssueRefreshTokenWithClaims(ctx context.Context, userID string, claims CustomClaims) (string, error) {
	ctx, span := m.startSpan(ctx, "IssueRefreshTokenWithClaims")
	defer span.End()

	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		m.metrics.IncrementCounter(metricTokensIssuedTotal, map[string]string{
			"status":     status,
			"error_type": errorType,
			"namespace":  m.namespace,
		})
		m.metrics.RecordDuration(metricOperationDuration, time.Since(start), map[string]string{
			"operation": "issue_refresh_token",
			"namespace":  m.namespace,
		})
	}()

	// ===== STEP 1: Validate User ID =====
	if len(strings.TrimSpace(userID)) == 0 {
		status = "invalid_input"
		errorType = "invalid_input"
		m.logger.Warn("attempted to get token with empty userID", ctx)
		span.RecordError(ErrInvalidUserID)
		span.SetStatus(tracing.StatusError, ErrInvalidUserID.Error())
		return "", ErrInvalidUserID
	}

	span.SetAttribute("user_id", userID)

	// ===== STEP 2: Service State Check =====
	if !m.IsRunning() {
		status = "not_running"
		errorType = "not_running"
		m.logger.Warn("service not running", ctx)
		span.RecordError(ErrManagerNotRunning)
		span.SetStatus(tracing.StatusError, ErrManagerNotRunning.Error())
		return "", ErrManagerNotRunning
	}

	// ===== STEP 3: Context Check =====
	// Check if context is already cancelled/expired
	// Fail fast if client already disconnected
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		m.logger.Warn("context cancelled during token issuance", ctx,
			"userID", userID,
			"error", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return "", err
	}

	m.logger.Debug("issuing refresh token with claims", ctx, "userID", userID)

	// ===== STEP 4: Generate Refresh Token =====
	// Create cryptographic random token
	// this is an OPAQUE token (not a JWT)
	refreshToken, err := generateRefreshToken()
	if err != nil {
		m.logger.Error("failed to generate refresh token", ctx,
			"userID", userID,
			"error", err)
		wrapped := fmt.Errorf("failed to generate refresh token: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return "", wrapped
	}
	m.logger.Debug("refresh token generated", ctx,
		"userID", userID)

	span.SetAttribute("token_id", refreshToken)

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
		m.audience,   // Audience — overridden per-call in Phase 3
		expiresAt,    // When it expires
		claims,       // Custom claims
	)
	if err != nil {
		m.logger.Error("failed to store refresh token with claims", ctx,
			"userID", userID,
			"error", err)
		wrapped := fmt.Errorf("failed to store refresh token with claims: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return "", wrapped
	}
	m.logger.Debug("refresh token with claims stored", ctx,
		"userID", userID,
		"claimsKeys", len(claims),
		"expiresAt", expiresAt)

	// ===== STEP 7: Record Success and Log =====
	status = "success"
	errorType = ""
	m.logger.Info("refresh token with claims issued", ctx,
		"userID", userID,
		"tokenID", refreshToken,
		"expiresAt", expiresAt,
		"claimsKeys", getMapKeys(claims))
	span.SetStatus(tracing.StatusOK, "")
	return refreshToken, nil
}

// IssueTokenPair issues an access token and a refresh token in a single
// operation. The access token is a signed RS256 JWT; the refresh token is an
// opaque random value stored in the RefreshStore.
//
// Returns (accessToken, refreshToken, error). Returns the same errors as
// IssueAccessToken.
func (m *Manager) IssueTokenPair(ctx context.Context, userID string) (string, string, error) {
	ctx, span := m.startSpan(ctx, "IssueTokenPair")
	defer span.End()

	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		m.metrics.IncrementCounter(metricTokensIssuedTotal, map[string]string{
			"status":     status,
			"error_type": errorType,
			"namespace":  m.namespace,
		})
		m.metrics.RecordDuration(metricOperationDuration, time.Since(start), map[string]string{
			"operation": "issue_token_pair",
			"namespace":  m.namespace,
		})
	}()

	// ===== STEP 1: Validate User ID =====
	if len(strings.TrimSpace(userID)) == 0 {
		status = "invalid_input"
		errorType = "invalid_input"
		m.logger.Warn("attempted to get token with empty userID", ctx)
		span.RecordError(ErrInvalidUserID)
		span.SetStatus(tracing.StatusError, ErrInvalidUserID.Error())
		return "", "", ErrInvalidUserID
	}

	span.SetAttribute("user_id", userID)

	// ===== STEP 2: Service State Check =====
	if !m.IsRunning() {
		status = "not_running"
		errorType = "not_running"
		m.logger.Warn("service not running", ctx)
		span.RecordError(ErrManagerNotRunning)
		span.SetStatus(tracing.StatusError, ErrManagerNotRunning.Error())
		return "", "", ErrManagerNotRunning
	}

	// ===== STEP 3: Context Check =====
	// Check if context is already cancelled/expired
	// Fail fast if client already disconnected
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		m.logger.Warn("context cancelled during token issuance", ctx,
			"userID", userID,
			"error", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return "", "", err
	}

	m.logger.Debug("issuing token pair", ctx, "userID", userID)

	// ===== STEP 4: Get Signing Key =====
	privateKey, keyID, err := m.keyManager.GetCurrentSigningKey(ctx)
	if err != nil {
		m.logger.Error("failed to get signing key", ctx,
			"userID", userID,
			"error", err)
		wrapped := fmt.Errorf("failed to get signing key: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return "", "", wrapped
	}

	// ===== STEP 5: Create JWT Claims =====
	now := time.Now()
	expiresAt := now.Add(m.accessTokenDuration)
	// Generate unique token ID (jti claim)
	tokenID, err := generateTokenID()
	if err != nil {
		m.logger.Error("failed to generate token ID", ctx,
			"userID", userID,
			"error", err)
		wrapped := fmt.Errorf("failed to generate token ID: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return "", "", wrapped
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
		m.logger.Error("failed to sign token", ctx,
			"userID", userID,
			"keyID", keyID,
			"error", err)
		wrapped := fmt.Errorf("failed to sign token: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return "", "", wrapped
	}

	// ===== STEP 8: Generate Refresh Token =====
	refreshToken, err := generateRefreshToken()
	if err != nil {
		m.logger.Error("failed to generate refresh token", ctx,
			"userID", userID,
			"error", err)
		wrapped := fmt.Errorf("failed to generate refresh token: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return "", "", wrapped
	}

	span.SetAttribute("token_id", refreshToken)

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
		m.audience,   // Audience — overridden per-call in Phase 3
		expiresAt,    // When it expires
		nil,          // No claims (use IssueRefreshTokenWithClaims to attach claims)
	)
	if err != nil {
		m.logger.Error("failed to store refresh token", ctx,
			"userID", userID,
			"error", err)
		wrapped := fmt.Errorf("failed to store refresh token: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return "", "", wrapped
	}

	// ===== STEP 11: Record Success and Log =====
	status = "success"
	errorType = ""
	m.logger.Info("token pair issued", ctx,
		"userID", userID,
		"tokenID", refreshToken,
		"expiresAt", expiresAt)
	span.SetStatus(tracing.StatusOK, "")
	return signedToken, refreshToken, nil
}

// IssueTokenPairWithClaims issues an access token and a refresh token in a single
// operation, embedding caller-supplied custom claims into the access token and
// optionally attaching metadata to the refresh token. Reserved JWT field names
// (sub, iss, aud, exp, nbf, iat, jti) in accessClaims are silently dropped to
// prevent caller-controlled claim injection.
//
// Returns (accessToken, refreshToken, error). Returns ErrManagerNotRunning if
// the manager has not been started, ErrInvalidUserID if userID is empty or
// whitespace-only, or the context error if the context is cancelled before
// issuance completes.
func (m *Manager) IssueTokenPairWithClaims(ctx context.Context, userID string, accessClaims CustomClaims, refreshClaims CustomClaims) (string, string, error) {
	ctx, span := m.startSpan(ctx, "IssueTokenPairWithClaims")
	defer span.End()

	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		m.metrics.IncrementCounter(metricTokensIssuedTotal, map[string]string{
			"status":     status,
			"error_type": errorType,
			"namespace":  m.namespace,
		})
		m.metrics.RecordDuration(metricOperationDuration, time.Since(start), map[string]string{
			"operation": "issue_token_pair",
			"namespace":  m.namespace,
		})
	}()

	// ===== STEP 1: Validate User ID =====
	if len(strings.TrimSpace(userID)) == 0 {
		status = "invalid_input"
		errorType = "invalid_input"
		m.logger.Warn("attempted to get token with empty userID", ctx)
		span.RecordError(ErrInvalidUserID)
		span.SetStatus(tracing.StatusError, ErrInvalidUserID.Error())
		return "", "", ErrInvalidUserID
	}

	span.SetAttribute("user_id", userID)

	// ===== STEP 2: Service State Check =====
	if !m.IsRunning() {
		status = "not_running"
		errorType = "not_running"
		m.logger.Warn("service not running", ctx)
		span.RecordError(ErrManagerNotRunning)
		span.SetStatus(tracing.StatusError, ErrManagerNotRunning.Error())
		return "", "", ErrManagerNotRunning
	}

	// ===== STEP 3: Context Check =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		m.logger.Warn("context cancelled during token issuance", ctx,
			"userID", userID,
			"error", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return "", "", err
	}

	m.logger.Debug("issuing token pair with claims", ctx, "userID", userID)

	// ===== STEP 4: Get Signing Key =====
	privateKey, keyID, err := m.keyManager.GetCurrentSigningKey(ctx)
	if err != nil {
		m.logger.Error("failed to get signing key", ctx,
			"userID", userID,
			"error", err)
		wrapped := fmt.Errorf("failed to get signing key: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return "", "", wrapped
	}

	// ===== STEP 5: Create JWT Claims =====
	now := time.Now()
	expiresAt := now.Add(m.accessTokenDuration)
	tokenID, err := generateTokenID()
	if err != nil {
		m.logger.Error("failed to generate token ID", ctx,
			"userID", userID,
			"error", err)
		wrapped := fmt.Errorf("failed to generate token ID: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return "", "", wrapped
	}

	jwtClaims := jwt.MapClaims{
		"sub": userID,
		"iss": m.issuer,
		"aud": m.audience,
		"exp": expiresAt.Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"jti": tokenID,
	}

	// Merge access claims — reserved keys are silently dropped.
	reservedClaims := map[string]bool{
		"sub": true, "iss": true, "aud": true, "exp": true,
		"iat": true, "nbf": true, "jti": true,
	}

	customClaimsCount := 0
	for key, value := range accessClaims {
		if !reservedClaims[key] {
			jwtClaims[key] = value
			customClaimsCount++
		} else {
			m.logger.Warn("attempted to override reserved claim", ctx,
				"userID", userID,
				"claim", key)
		}
	}

	// ===== STEP 6: Sign Token =====
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwtClaims)
	token.Header["kid"] = keyID

	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		m.logger.Error("failed to sign token", ctx,
			"userID", userID,
			"keyID", keyID,
			"error", err)
		wrapped := fmt.Errorf("failed to sign token: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return "", "", wrapped
	}

	// ===== STEP 8: Generate Refresh Token =====
	refreshToken, err := generateRefreshToken()
	if err != nil {
		m.logger.Error("failed to generate refresh token", ctx,
			"userID", userID,
			"error", err)
		wrapped := fmt.Errorf("failed to generate refresh token: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return "", "", wrapped
	}

	span.SetAttribute("token_id", refreshToken)

	// ===== STEP 9: Calculate Refresh Token Expiration =====
	now = time.Now()
	expiresAt = now.Add(m.refreshTokenDuration)

	// ===== STEP 10: Store Refresh Token =====
	err = m.refreshStore.Store(
		ctx,
		refreshToken,
		userID,
		m.audience,   // Audience — overridden per-call in Phase 3
		expiresAt,
		refreshClaims,
	)
	if err != nil {
		m.logger.Error("failed to store refresh token", ctx,
			"userID", userID,
			"error", err)
		wrapped := fmt.Errorf("failed to store refresh token: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return "", "", wrapped
	}

	// ===== STEP 11: Record Success and Log =====
	status = "success"
	errorType = ""
	m.logger.Info("token pair with claims issued", ctx,
		"userID", userID,
		"tokenID", refreshToken,
		"expiresAt", expiresAt,
		"customClaimsCount", customClaimsCount)
	span.SetStatus(tracing.StatusOK, "")
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
func (m *Manager) ValidateAccessToken(ctx context.Context, tokenString string) (*jwt.RegisteredClaims, error) {
	ctx, span := m.startSpan(ctx, "ValidateAccessToken")
	defer span.End()

	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		m.metrics.IncrementCounter(metricTokensValidatedTotal, map[string]string{
			"status":     status,
			"error_type": errorType,
			"namespace":  m.namespace,
		})
		m.metrics.RecordDuration(metricOperationDuration, time.Since(start), map[string]string{
			"operation": "validate_access_token",
			"namespace":  m.namespace,
		})
	}()

	// ===== STEP 1: Service State Check =====
	if !m.IsRunning() {
		status = "not_running"
		errorType = "not_running"
		m.logger.Warn("attempted token validation while service stopped", ctx)
		span.RecordError(ErrManagerNotRunning)
		span.SetStatus(tracing.StatusError, ErrManagerNotRunning.Error())
		return nil, ErrManagerNotRunning
	}

	// ===== STEP 2: Context Check =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		m.logger.Warn("context cancelled during token validation", ctx,
			"error", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return nil, err
	}

	m.logger.Debug("validating access token", ctx)

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
				m.logger.Warn("token uses unexpected signing method", ctx,
					"method", token.Header["alg"])
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}

			// ===== STEP 4b: Extract Key ID =====
			kid, ok := token.Header["kid"].(string)
			if !ok {
				m.logger.Warn("token missing kid in header", ctx)
				return nil, errors.New("missing kid in token header")
			}
			m.logger.Debug("token kid extracted from header", ctx,
				"kid", kid)

			// ===== STEP 4c: Get Public Key =====
			publicKey, err := m.keyManager.GetPublicKey(ctx, kid)
			if err != nil {
				m.logger.Error("failed to get public key", ctx,
					"kid", kid,
					"error", err)
				return nil, fmt.Errorf("failed to get public key: %w", err)
			}
			m.logger.Debug("public key retrieved for token validation", ctx,
				"kid", kid)

			return publicKey, nil
		},
		parseOpts...,
	)

	// ===== STEP 5: Check Parsing Errors =====
	if err != nil {
		m.logger.Warn("token parsing failed", ctx,
			"error", err)

		// Provide specific error messages
		if errors.Is(err, jwt.ErrTokenExpired) {
			status = "expired"
			errorType = "expired"
			m.logger.Warn("token expired", ctx)
			span.RecordError(ErrTokenExpired)
			span.SetStatus(tracing.StatusError, ErrTokenExpired.Error())
			return nil, ErrTokenExpired
		}
		if errors.Is(err, jwt.ErrTokenNotValidYet) {
			status = "error"
			errorType = "not_yet_valid"
			span.RecordError(ErrTokenNotYetValid)
			span.SetStatus(tracing.StatusError, ErrTokenNotYetValid.Error())
			return nil, ErrTokenNotYetValid
		}
		if errors.Is(err, keys.ErrKeyNotFound) {
			status = "error"
			errorType = "key_not_found"
			m.logger.Warn("token references unknown key ID", ctx)
			span.RecordError(ErrInvalidToken)
			span.SetStatus(tracing.StatusError, ErrInvalidToken.Error())
			return nil, ErrInvalidToken
		}

		span.RecordError(ErrInvalidToken)
		span.SetStatus(tracing.StatusError, ErrInvalidToken.Error())
		return nil, ErrInvalidToken
	}

	// ===== STEP 6: Verify Token is Valid =====
	if !token.Valid {
		m.logger.Warn("token marked as invalid", ctx)
		span.RecordError(ErrInvalidToken)
		span.SetStatus(tracing.StatusError, ErrInvalidToken.Error())
		return nil, ErrInvalidToken
	}
	m.logger.Debug("token signature and structure validated", ctx)

	// ===== STEP 7: Extract Claims =====
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok {
		m.logger.Error("failed to extract claims from token", ctx)
		span.RecordError(ErrInvalidToken)
		span.SetStatus(tracing.StatusError, ErrInvalidToken.Error())
		return nil, ErrInvalidToken
	}
	m.logger.Debug("claims extracted from token", ctx,
		"tokenID", claims.ID,
		"userID", claims.Subject)

	span.SetAttribute("user_id", claims.Subject)
	span.SetAttribute("token_id", claims.ID)

	// ===== STEP 8: Validate Issuer =====
	if m.issuer != "" && claims.Issuer != m.issuer {
		m.logger.Warn("token issuer mismatch", ctx,
			"expected", m.issuer,
			"actual", claims.Issuer)
		span.RecordError(ErrInvalidIssuer)
		span.SetStatus(tracing.StatusError, ErrInvalidIssuer.Error())
		return nil, ErrInvalidIssuer
	}
	m.logger.Debug("token issuer validated", ctx,
		"issuer", claims.Issuer)

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
			m.logger.Warn("token audience mismatch", ctx,
				"expected", m.audience,
				"actual", claims.Audience)
			span.RecordError(ErrInvalidAudience)
			span.SetStatus(tracing.StatusError, ErrInvalidAudience.Error())
			return nil, ErrInvalidAudience
		}
		m.logger.Debug("token audience validated", ctx,
			"audience", claims.Audience)
	}

	// ===== STEP 10: Record Success and Log =====
	status = "success"
	errorType = ""
	m.logger.Info("access token validated", ctx,
		"userID", claims.Subject,
		"tokenID", claims.ID)
	span.SetStatus(tracing.StatusOK, "")
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
func (m *Manager) ValidateAccessTokenWithClaims(ctx context.Context, tokenString string) (*jwt.RegisteredClaims, map[string]interface{}, error) {
	ctx, span := m.startSpan(ctx, "ValidateAccessTokenWithClaims")
	defer span.End()

	// ===== STEP 1: Validate via Standard Path =====
	// All error handling (signature, expiry, issuer, audience, metrics, logging)
	// is handled by ValidateAccessToken — no duplication needed.
	registered, err := m.ValidateAccessToken(ctx, tokenString)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return nil, nil, err
	}

	span.SetAttribute("user_id", registered.Subject)
	span.SetAttribute("token_id", registered.ID)

	// ===== STEP 2: Re-Parse for Custom Claims =====
	// Signature is already verified above; ParseUnverified is safe here and
	// avoids a second key-manager round-trip.
	rawToken, _, parseErr := jwt.NewParser().ParseUnverified(tokenString, jwt.MapClaims{})
	if parseErr != nil {
		// Token validated above — treat missing custom claims as empty rather than error.
		span.SetStatus(tracing.StatusOK, "")
		return registered, map[string]interface{}{}, nil
	}

	mapClaims, ok := rawToken.Claims.(jwt.MapClaims)
	if !ok {
		span.SetStatus(tracing.StatusOK, "")
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

	m.logger.Info("access token with custom claims validated", ctx)
	span.SetStatus(tracing.StatusOK, "")
	return registered, custom, nil
}

// RefreshAccessToken exchanges a valid refresh token for a new access token.
// It retrieves the refresh token from storage, checks expiration and revocation
// status, then calls IssueAccessToken for the token's owner.
//
// Returns ErrManagerNotRunning, ErrInvalidRefreshToken, ErrRefreshTokenExpired,
// ErrTokenRevoked, or the context error.
func (m *Manager) RefreshAccessToken(ctx context.Context, refreshToken string) (string, error) {
	ctx, span := m.startSpan(ctx, "RefreshAccessToken")
	defer span.End()

	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		m.metrics.IncrementCounter(metricTokensRefreshedTotal, map[string]string{
			"status":     status,
			"error_type": errorType,
			"namespace":  m.namespace,
		})
		m.metrics.RecordDuration(metricOperationDuration, time.Since(start), map[string]string{
			"operation": "refresh_access_token",
			"namespace":  m.namespace,
		})
	}()

	// ===== STEP 1: Service State Check =====
	if !m.isRunning.Load() {
		status = "not_running"
		errorType = "not_running"
		m.logger.Warn("attempted to refresh while service was stopped", ctx)
		span.RecordError(ErrManagerNotRunning)
		span.SetStatus(tracing.StatusError, ErrManagerNotRunning.Error())
		return "", ErrManagerNotRunning
	}

	// ===== STEP 2: Context Check =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		m.logger.Warn("context cancelled during token refresh", ctx)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return "", err
	}

	m.logger.Debug("attempting token refresh", ctx)

	// ===== STEP 3: Input Validation =====
	if refreshToken == "" {
		status = "invalid_input"
		errorType = "invalid_input"
		m.logger.Warn("empty refresh token provided", ctx)
		span.RecordError(ErrInvalidRefreshToken)
		span.SetStatus(tracing.StatusError, ErrInvalidRefreshToken.Error())
		return "", ErrInvalidRefreshToken
	}

	span.SetAttribute("token_id", refreshToken)

	// ===== STEP 4: Lookup Refresh Token =====
	token, err := m.refreshStore.Retrieve(ctx, refreshToken)
	if err != nil {
		m.logger.Warn("refresh token not found in store", ctx,
			"error", err)
		// storage.ErrTokenRevoked is translated to tokens.ErrTokenRevoked so that
		// callers only ever see tokens-package sentinels and have no dependency on
		// the storage package. All other storage errors map to ErrInvalidRefreshToken.
		if errors.Is(err, storage.ErrTokenRevoked) {
			status = "revoked"
			errorType = "revoked"
			span.RecordError(ErrTokenRevoked)
			span.SetStatus(tracing.StatusError, ErrTokenRevoked.Error())
			return "", ErrTokenRevoked
		}
		status = "not_found"
		errorType = "not_found"
		span.RecordError(ErrInvalidRefreshToken)
		span.SetStatus(tracing.StatusError, ErrInvalidRefreshToken.Error())
		return "", ErrInvalidRefreshToken
	}

	m.logger.Debug("refresh token retrieved from store", ctx,
		"userID", token.UserID,
		"tokenID", token.TokenID)

	// ===== STEP 5: Check Expiration =====
	if token.ExpiresAt.Before(time.Now()) {
		status = "expired"
		errorType = "expired"
		m.logger.Warn("refresh token has expired", ctx,
			"tokenID", refreshToken,
			"expiredAt", token.ExpiresAt)

		// Clean up expired token (ignore error — we're returning ErrRefreshTokenExpired anyway)
		_ = m.refreshStore.Revoke(ctx, refreshToken)

		span.RecordError(ErrRefreshTokenExpired)
		span.SetStatus(tracing.StatusError, ErrRefreshTokenExpired.Error())
		return "", ErrRefreshTokenExpired
	}

	// ===== STEP 6: Check If Revoked =====
	if token.Revoked {
		status = "revoked"
		errorType = "revoked"
		m.logger.Warn("refresh token has been revoked", ctx,
			"tokenID", refreshToken)
		span.RecordError(ErrTokenRevoked)
		span.SetStatus(tracing.StatusError, ErrTokenRevoked.Error())
		return "", ErrTokenRevoked
	}

	// ===== STEP 7: Issue New Access Token =====
	newAccessToken, err := m.IssueAccessToken(ctx, token.UserID)
	if err != nil {
		m.logger.Error("failed to issue new access token", ctx,
			"userID", token.UserID,
			"error", err)
		wrapped := fmt.Errorf("failed to issue access token: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return "", wrapped
	}

	// ===== STEP 9: Record Success and Log =====
	status = "success"
	errorType = ""
	m.logger.Info("access token refreshed", ctx,
		"userID", token.UserID,
		"tokenID", refreshToken)
	span.SetStatus(tracing.StatusOK, "")
	return newAccessToken, nil
}

// RefreshAccessTokenWithClaims exchanges a valid refresh token for a new access
// token, embedding caller-supplied custom claims into the issued token. It
// retrieves the refresh token from storage, checks expiration and revocation
// status, then calls IssueAccessTokenWithClaims for the token's owner. Reserved
// JWT field names (sub, iss, aud, exp, nbf, iat, jti) in claims are silently
// dropped to prevent caller-controlled claim injection.
//
// Returns ErrManagerNotRunning, ErrInvalidRefreshToken, ErrRefreshTokenExpired,
// ErrTokenRevoked, or the context error.
func (m *Manager) RefreshAccessTokenWithClaims(ctx context.Context, refreshToken string, claims CustomClaims) (string, error) {
	ctx, span := m.startSpan(ctx, "RefreshAccessTokenWithClaims")
	defer span.End()

	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		m.metrics.IncrementCounter(metricTokensRefreshedTotal, map[string]string{
			"status":     status,
			"error_type": errorType,
			"namespace":  m.namespace,
		})
		m.metrics.RecordDuration(metricOperationDuration, time.Since(start), map[string]string{
			"operation": "refresh_access_token",
			"namespace":  m.namespace,
		})
	}()

	// ===== STEP 1: Service State Check =====
	if !m.isRunning.Load() {
		status = "not_running"
		errorType = "not_running"
		m.logger.Warn("attempted to refresh while service was stopped", ctx)
		span.RecordError(ErrManagerNotRunning)
		span.SetStatus(tracing.StatusError, ErrManagerNotRunning.Error())
		return "", ErrManagerNotRunning
	}

	// ===== STEP 2: Context Check =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		m.logger.Warn("context cancelled during token refresh", ctx)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return "", err
	}

	m.logger.Debug("attempting token refresh with claims", ctx)

	// ===== STEP 3: Input Validation =====
	if refreshToken == "" {
		status = "invalid_input"
		errorType = "invalid_input"
		m.logger.Warn("empty refresh token provided", ctx)
		span.RecordError(ErrInvalidRefreshToken)
		span.SetStatus(tracing.StatusError, ErrInvalidRefreshToken.Error())
		return "", ErrInvalidRefreshToken
	}

	span.SetAttribute("token_id", refreshToken)

	// ===== STEP 4: Lookup Refresh Token =====
	token, err := m.refreshStore.Retrieve(ctx, refreshToken)
	if err != nil {
		m.logger.Warn("refresh token not found in store", ctx,
			"error", err)
		// storage.ErrTokenRevoked is translated to tokens.ErrTokenRevoked so that
		// callers only ever see tokens-package sentinels and have no dependency on
		// the storage package. All other storage errors map to ErrInvalidRefreshToken.
		if errors.Is(err, storage.ErrTokenRevoked) {
			status = "revoked"
			errorType = "revoked"
			span.RecordError(ErrTokenRevoked)
			span.SetStatus(tracing.StatusError, ErrTokenRevoked.Error())
			return "", ErrTokenRevoked
		}
		status = "not_found"
		errorType = "not_found"
		span.RecordError(ErrInvalidRefreshToken)
		span.SetStatus(tracing.StatusError, ErrInvalidRefreshToken.Error())
		return "", ErrInvalidRefreshToken
	}

	m.logger.Debug("refresh token retrieved from store", ctx,
		"userID", token.UserID,
		"tokenID", token.TokenID)

	// ===== STEP 5: Check Expiration =====
	if token.ExpiresAt.Before(time.Now()) {
		status = "expired"
		errorType = "expired"
		m.logger.Warn("refresh token has expired", ctx,
			"tokenID", refreshToken,
			"expiredAt", token.ExpiresAt)

		// Clean up expired token (ignore error — we're returning ErrRefreshTokenExpired anyway)
		_ = m.refreshStore.Revoke(ctx, refreshToken)

		span.RecordError(ErrRefreshTokenExpired)
		span.SetStatus(tracing.StatusError, ErrRefreshTokenExpired.Error())
		return "", ErrRefreshTokenExpired
	}

	// ===== STEP 6: Check If Revoked =====
	if token.Revoked {
		status = "revoked"
		errorType = "revoked"
		m.logger.Warn("refresh token has been revoked", ctx,
			"tokenID", refreshToken)
		span.RecordError(ErrTokenRevoked)
		span.SetStatus(tracing.StatusError, ErrTokenRevoked.Error())
		return "", ErrTokenRevoked
	}

	// ===== STEP 7: Issue New Access Token With Claims =====
	newAccessToken, err := m.IssueAccessTokenWithClaims(ctx, token.UserID, claims)
	if err != nil {
		m.logger.Error("failed to issue new access token", ctx,
			"userID", token.UserID,
			"error", err)
		wrapped := fmt.Errorf("failed to issue access token: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return "", wrapped
	}

	// ===== STEP 9: Record Success and Log =====
	status = "success"
	errorType = ""
	m.logger.Info("access token refreshed with claims", ctx,
		"userID", token.UserID,
		"tokenID", refreshToken)
	span.SetStatus(tracing.StatusOK, "")
	return newAccessToken, nil
}

// RevokeRefreshToken marks a single refresh token as revoked in the RefreshStore.
// Subsequent calls to RefreshAccessToken or IntrospectToken will see the token
// as inactive.
//
// Returns ErrManagerNotRunning, ErrInvalidRefreshToken for empty tokenID, or
// the context error.
func (m *Manager) RevokeRefreshToken(ctx context.Context, tokenID string) error {
	ctx, span := m.startSpan(ctx, "RevokeRefreshToken")
	defer span.End()

	start := time.Now()
	status := "error"
	defer func() {
		m.metrics.IncrementCounter(metricTokensRevokedTotal, map[string]string{
			"operation": "single",
			"status":    status,
			"namespace":  m.namespace,
		})
		m.metrics.RecordDuration(metricOperationDuration, time.Since(start), map[string]string{
			"operation": "revoke_token",
			"namespace":  m.namespace,
		})
	}()

	// ===== STEP 1: Service State Check =====
	if !m.isRunning.Load() {
		status = "not_running"
		m.logger.Warn("attempted to revoke token while service stopped", ctx)
		span.RecordError(ErrManagerNotRunning)
		span.SetStatus(tracing.StatusError, ErrManagerNotRunning.Error())
		return ErrManagerNotRunning
	}

	// ===== STEP 2: Context Check =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		m.logger.Info("context cancelled during token revocation", ctx)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return err
	}

	// ===== STEP 3: Input Validation =====
	if tokenID == "" {
		status = "invalid_input"
		m.logger.Warn("empty token ID provided for revocation", ctx)
		span.RecordError(ErrInvalidRefreshToken)
		span.SetStatus(tracing.StatusError, ErrInvalidRefreshToken.Error())
		return ErrInvalidRefreshToken
	}

	span.SetAttribute("token_id", tokenID)

	// ===== STEP 4: Revoke Token =====
	err := m.refreshStore.Revoke(ctx, tokenID)
	if err != nil {
		m.logger.Error("failed to revoke refresh token", ctx,
			"tokenID", tokenID,
			"error", err)
		wrapped := fmt.Errorf("failed to revoke token: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return wrapped
	}

	// ===== STEP 5: Record Success and Log =====
	status = "success"
	m.logger.Info("refresh token revoked", ctx,
		"tokenID", tokenID)
	span.SetStatus(tracing.StatusOK, "")
	return nil
}

// RevokeAllUserTokens revokes every refresh token belonging to the given user.
// Use this for logout-all-devices or account suspension scenariom.
//
// Returns ErrManagerNotRunning, ErrInvalidUserID for empty userID, or the
// context error.
func (m *Manager) RevokeAllUserTokens(ctx context.Context, userID string) error {
	ctx, span := m.startSpan(ctx, "RevokeAllUserTokens")
	defer span.End()

	start := time.Now()
	status := "error"
	defer func() {
		m.metrics.IncrementCounter(metricTokensRevokedTotal, map[string]string{
			"operation": "all_user",
			"status":    status,
			"namespace":  m.namespace,
		})
		m.metrics.RecordDuration(metricOperationDuration, time.Since(start), map[string]string{
			"operation": "revoke_all_user_tokens",
			"namespace":  m.namespace,
		})
	}()

	// ===== STEP 1: Service State Check =====
	if !m.isRunning.Load() {
		status = "not_running"
		m.logger.Warn("attempted to revoke all user tokens while service stopped", ctx)
		span.RecordError(ErrManagerNotRunning)
		span.SetStatus(tracing.StatusError, ErrManagerNotRunning.Error())
		return ErrManagerNotRunning
	}

	// ===== STEP 2: Context Check =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		m.logger.Info("context cancelled during bulk token revocation", ctx,
			"error", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return err
	}

	// ===== STEP 3: Input Validation =====
	if userID == "" {
		status = "invalid_input"
		m.logger.Warn("empty user ID provided for bulk revocation", ctx)
		span.RecordError(ErrInvalidUserID)
		span.SetStatus(tracing.StatusError, ErrInvalidUserID.Error())
		return ErrInvalidUserID // Note: Different error than single revoke
	}

	span.SetAttribute("user_id", userID)

	// ===== STEP 4: Revoke All Tokens For User =====
	// storage.ErrInvalidUserID cannot surface here — userID is validated above
	// before this call, so storage never receives an empty value.
	err := m.refreshStore.RevokeAllForUser(ctx, userID)
	if err != nil {
		m.logger.Error("failed to revoke all user tokens", ctx,
			"userID", userID,
			"error", err)
		wrapped := fmt.Errorf("failed to revoke all tokens: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return wrapped
	}

	// ===== STEP 5: Record Success and Log =====
	status = "success"
	m.logger.Info("all refresh tokens revoked for user", ctx,
		"userID", userID)
	span.SetStatus(tracing.StatusOK, "")
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
func (m *Manager) IntrospectToken(ctx context.Context, token string) (*TokenMetadata, error) {
	ctx, span := m.startSpan(ctx, "IntrospectToken")
	defer span.End()

	start := time.Now()
	status := "error"
	defer func() {
		m.metrics.IncrementCounter(metricTokensIntrospectedTotal, map[string]string{
			"status": status,
			"namespace": m.namespace,
		})
		m.metrics.RecordDuration(metricOperationDuration, time.Since(start), map[string]string{
			"operation": "introspect_token",
			"namespace":  m.namespace,
		})
	}()

	// ===== STEP 1: Service State Check =====
	if !m.isRunning.Load() {
		status = "not_running"
		m.logger.Warn("attempted to introspect token while service is stopped", ctx)
		span.RecordError(ErrManagerNotRunning)
		span.SetStatus(tracing.StatusError, ErrManagerNotRunning.Error())
		return nil, ErrManagerNotRunning
	}

	// ===== STEP 2: Context Check =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		m.logger.Warn("context cancelled during token introspection", ctx)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return nil, err
	}

	m.logger.Debug("introspecting token", ctx)

	// ===== STEP 3: Input Validation =====
	if token == "" {
		status = "invalid_input"
		m.logger.Warn("empty token provided for introspection", ctx)
		span.RecordError(ErrInvalidRefreshToken)
		span.SetStatus(tracing.StatusError, ErrInvalidRefreshToken.Error())
		return nil, ErrInvalidRefreshToken
	}

	span.SetAttribute("token_id", token)

	// ===== STEP 4: Retrieve Token From Storage =====
	refreshToken, err := m.refreshStore.Retrieve(ctx, token)
	if err != nil {
		// Return inactive metadata instead of error — introspect never errors on unknown tokens
		status = "success"
		m.logger.Info("token not found during introspection", ctx,
			"error", err)
		span.SetAttribute("active", false)
		span.SetStatus(tracing.StatusOK, "")
		return &TokenMetadata{
			Active:    false,
			Subject:   "",
			TokenType: "refresh_token",
			ExpiresAt: time.Time{},
			IssuedAt:  time.Time{},
			TokenID:   token,
		}, nil
	}

	// ===== STEP 5: Check Token Status =====
	now := time.Now()

	// Check if expired
	if refreshToken.ExpiresAt.Before(now) {
		status = "success"
		m.logger.Info("introspect token is expired", ctx,
			"token", token,
			"expiredAt", refreshToken.ExpiresAt)
		span.SetAttribute("active", false)
		span.SetStatus(tracing.StatusOK, "")
		return &TokenMetadata{
			Active:    false,
			Subject:   refreshToken.UserID,
			TokenType: "refresh_token",
			ExpiresAt: refreshToken.ExpiresAt,
			IssuedAt:  refreshToken.CreatedAt,
			TokenID:   refreshToken.TokenID,
		}, nil
	}

	// Check if revoked
	if refreshToken.Revoked {
		status = "success"
		m.logger.Info("introspected token is revoked", ctx,
			"tokenID", token)
		span.SetAttribute("active", false)
		span.SetStatus(tracing.StatusOK, "")
		return &TokenMetadata{
			Active:    false,
			Subject:   refreshToken.UserID,
			TokenType: "refresh_token",
			ExpiresAt: refreshToken.ExpiresAt,
			IssuedAt:  refreshToken.CreatedAt,
			TokenID:   refreshToken.TokenID,
		}, nil
	}

	// ===== STEP 6: Record Success and Return Active Token Metadata =====
	status = "success"
	m.logger.Info("token introspected", ctx,
		"tokenID", token,
		"userID", refreshToken.UserID,
		"active", true)
	span.SetAttribute("active", true)
	span.SetStatus(tracing.StatusOK, "")
	return &TokenMetadata{
		Active:    true,
		Subject:   refreshToken.UserID,
		TokenType: "refresh_token",
		ExpiresAt: refreshToken.ExpiresAt,
		IssuedAt:  refreshToken.CreatedAt,
		TokenID:   refreshToken.TokenID,
	}, nil
}

// CleanupExpiredTokens removes all expired refresh tokens from the RefreshStore.
// The service also runs this automatically in the background at CleanupInterval,
// so manual calls are only needed for on-demand sweepm.
//
// Returns the number of tokens deleted, ErrManagerNotRunning, or the context error.
func (m *Manager) CleanupExpiredTokens(ctx context.Context) (int, error) {
	ctx, span := m.startSpan(ctx, "CleanupExpiredTokens")
	defer span.End()

	start := time.Now()
	status := "error"
	defer func() {
		m.metrics.IncrementCounter(metricOperationsTotal, map[string]string{
			"operation": "cleanup",
			"status":    status,
			"namespace":  m.namespace,
		})
		m.metrics.RecordDuration(metricOperationDuration, time.Since(start), map[string]string{
			"operation": "cleanup",
			"namespace":  m.namespace,
		})
	}()

	// ===== STEP 1: Service State Check =====
	if !m.isRunning.Load() {
		status = "not_running"
		m.logger.Warn("attempted cleanup while service stopped", ctx)
		span.RecordError(ErrManagerNotRunning)
		span.SetStatus(tracing.StatusError, ErrManagerNotRunning.Error())
		return 0, ErrManagerNotRunning
	}

	// ===== STEP 2: Context Check =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		m.logger.Info("context cancelled during cleanup", ctx,
			"error", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return 0, err
	}

	// ===== STEP 3: Run Cleanup =====
	count, err := m.refreshStore.Cleanup(ctx)
	if err != nil {
		m.logger.Error("failed to cleanup expired tokens", ctx,
			"error", err)
		wrapped := fmt.Errorf("cleanup failed: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return 0, wrapped
	}

	// ===== STEP 4: Record Success and Log =====
	status = "success"
	m.logger.Info("expired tokens cleaned up", ctx,
		"deleted", count)
	span.SetAttribute("deleted_count", count)
	span.SetStatus(tracing.StatusOK, "")
	return count, nil
}

// ListTokens returns a page of refresh tokens from the underlying store.
// See storage.RefreshStore.ListTokens for cursor and filtering semantics.
// Returns the context error if the context is cancelled.
func (m *Manager) ListTokens(ctx context.Context, cursor string, count int) ([]*storage.RefreshToken, string, error) {
	ctx, span := m.startSpan(ctx, "ListTokens")
	defer span.End()
	span.SetAttribute("token.namespace", m.namespace)
	span.SetAttribute("token.cursor", cursor)
	span.SetAttribute("token.count", count)

	start := time.Now()
	errorType := "error"
	defer func() {
		m.metrics.IncrementCounter(metricTokensListTotal, map[string]string{
			"namespace":  m.namespace,
			"error_type": errorType,
		})
		m.metrics.RecordDuration(metricTokensListDuration, time.Since(start), map[string]string{
			"namespace": m.namespace,
		})
	}()

	// ===== STEP 1: Service State Check =====
	if !m.isRunning.Load() {
		errorType = "not_running"
		m.logger.Warn("attempted listTokens while service stopped", ctx)
		span.RecordError(ErrManagerNotRunning)
		span.SetStatus(tracing.StatusError, ErrManagerNotRunning.Error())
		return nil, "", ErrManagerNotRunning
	}

	// ===== STEP 2: Context Check =====
	if err := ctx.Err(); err != nil {
		errorType = "cancelled"
		m.logger.Info("context cancelled during listTokens", ctx, "error", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return nil, "", err
	}

	// ===== STEP 3: Delegate to Store =====
	tokens, nextCursor, err := m.refreshStore.ListTokens(ctx, cursor, count)
	if err != nil {
		m.logger.Error("failed to list tokens", ctx, "error", err)
		wrapped := fmt.Errorf("list tokens failed: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return nil, "", wrapped
	}

	// ===== STEP 4: Record Success and Log =====
	errorType = ""
	span.SetAttribute("token.result_count", len(tokens))
	span.SetStatus(tracing.StatusOK, "")
	m.logger.Info("tokens listed", ctx,
		"result_count", len(tokens),
		"next_cursor", nextCursor)
	return tokens, nextCursor, nil
}

// ListTokensForUser returns a page of refresh tokens belonging to userID from
// the underlying store. See storage.RefreshStore.ListTokensForUser for cursor
// and filtering semantics. Returns ErrInvalidUserID if userID is empty.
// Returns the context error if the context is cancelled.
func (m *Manager) ListTokensForUser(ctx context.Context, userID string, cursor string, count int) ([]*storage.RefreshToken, string, error) {
	ctx, span := m.startSpan(ctx, "ListTokensForUser")
	defer span.End()
	span.SetAttribute("token.namespace", m.namespace)
	span.SetAttribute("token.user_id", userID)
	span.SetAttribute("token.cursor", cursor)
	span.SetAttribute("token.count", count)

	start := time.Now()
	errorType := "error"
	defer func() {
		m.metrics.IncrementCounter(metricTokensListForUserTotal, map[string]string{
			"namespace":  m.namespace,
			"error_type": errorType,
		})
		m.metrics.RecordDuration(metricTokensListForUserDuration, time.Since(start), map[string]string{
			"namespace": m.namespace,
		})
	}()

	// ===== STEP 1: Service State Check =====
	if !m.isRunning.Load() {
		errorType = "not_running"
		m.logger.Warn("attempted listTokensForUser while service stopped", ctx)
		span.RecordError(ErrManagerNotRunning)
		span.SetStatus(tracing.StatusError, ErrManagerNotRunning.Error())
		return nil, "", ErrManagerNotRunning
	}

	// ===== STEP 2: Context Check =====
	if err := ctx.Err(); err != nil {
		errorType = "cancelled"
		m.logger.Info("context cancelled during listTokensForUser", ctx, "error", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return nil, "", err
	}

	// ===== STEP 3: Delegate to Store =====
	tokens, nextCursor, err := m.refreshStore.ListTokensForUser(ctx, userID, cursor, count)
	if err != nil {
		m.logger.Error("failed to list tokens for user", ctx, "user_id", userID, "error", err)
		wrapped := fmt.Errorf("list tokens for user failed: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return nil, "", wrapped
	}

	// ===== STEP 4: Record Success and Log =====
	errorType = ""
	span.SetAttribute("token.result_count", len(tokens))
	span.SetStatus(tracing.StatusOK, "")
	m.logger.Info("tokens listed for user", ctx,
		"user_id", userID,
		"result_count", len(tokens),
		"next_cursor", nextCursor)
	return tokens, nextCursor, nil
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

// getMapKeys returns the keys of a CustomClaims map (for logging).
func getMapKeys(m CustomClaims) []string {
	if m == nil {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
