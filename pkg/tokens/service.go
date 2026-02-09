package tokens

import (
	"errors"
	"time"

	"github.com/aetomala/jwtauth/pkg/keymanager"
	"github.com/aetomala/jwtauth/pkg/logging"
	"github.com/aetomala/jwtauth/pkg/ratelimit"
	"github.com/aetomala/jwtauth/pkg/storage"
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
