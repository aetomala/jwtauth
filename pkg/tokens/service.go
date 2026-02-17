package tokens

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
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
	issuer               string        // JWT "iss" claim
	audience             []string      // JWT "aud" claim

}

var (
	ErrInvalidUserID     = errors.New("")
	ErrServiceShutdown   = errors.New("")
	ErrRateLimitExceeded = errors.New("rate limit exceeded")
)

func ErrIvalidConfig(msg string) error {
	return errors.New(msg)
}

func ConfigDefault() ServiceConfig {
	return ServiceConfig{
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 30 * 24 * time.Hour,
	}
}

func NewService(config ServiceConfig) (*Service, error) {
	if config.AccessTokenDuration == 0 {
		config.AccessTokenDuration = ConfigDefault().AccessTokenDuration
	}

	if config.RefreshTokenDuration == 0 {
		config.RefreshTokenDuration = ConfigDefault().RefreshTokenDuration
	}

	if config.KeyManager == nil {
		return nil, ErrIvalidConfig("KeyManager is required")
	}

	if config.RefreshStore == nil {
		return nil, ErrIvalidConfig("RefreshStore is required")
	}

	if config.RateLimiter == nil {
		return nil, ErrIvalidConfig("RateLimiter is required")
	}

	if config.AccessTokenDuration < 0 {
		return nil, ErrIvalidConfig("AccessTokenDuration must be non-negative")
	}

	if config.RefreshTokenDuration < 0 {
		return nil, ErrIvalidConfig("RefreshTokenDuration must be non-negative")
	}

	return &Service{
		keyManager:           config.KeyManager,
		refreshStore:         config.RefreshStore,
		rateLimiter:          config.RateLimiter,
		logger:               config.Logger,
		accessTokenDuration:  config.AccessTokenDuration,
		refreshTokenDuration: config.RefreshTokenDuration,
	}, nil
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

func (s *Service) createStandardClaims(userID, tokenID string) *jwt.RegisteredClaims {
	now := time.Now()
	expiresAt := now.Add(s.accessTokenDuration)
	return &jwt.RegisteredClaims{
		Subject:   userID,                        // "sub" - who the token is for
		Issuer:    s.issuer,                      // "iss" - who issued the token
		Audience:  s.audience,                    // "aud" - who can use the token
		ExpiresAt: jwt.NewNumericDate(expiresAt), // "exp" - when it expires
		IssuedAt:  jwt.NewNumericDate(now),       // "iat" - when it was issued
		NotBefore: jwt.NewNumericDate(now),       // "nbf" - valid from when
		ID:        tokenID,                       // "jti" - unique token identifier
	}
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
