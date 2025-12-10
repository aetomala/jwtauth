package keymanager

import (
	"errors"
	"time"
)

type Manager struct {
	config ManagerConfig
}

type ManagerConfig struct {
	KeyDirectory        string
	KeyRotationInterval time.Duration
	KeyOverlapDuration  time.Duration
	KeySize             int
}

func ConfigDefault() ManagerConfig {
	return ManagerConfig{
		KeySize:             2048,
		KeyRotationInterval: 30 * 24 * time.Hour,
		KeyOverlapDuration:  1 * time.Hour,
	}
}

// Sentiner Errors
var (
	ErrInvalidKeyDirectory        = errors.New("invalid key directory")
	ErrInvalidKeySize             = errors.New("invalid key size")
	ErrInvalidKeyRotationInterval = errors.New("invalid key rotation interval")
	ErrInvalidKeyOverlapDuration  = errors.New("invalid key overlap duration")
)

// IsRunning tells caller if the manager is currently running
func (k *Manager) IsRunning() bool {
	return false
}

// NewManager KeyManager constructor
func NewManager(config ManagerConfig) (*Manager, error) {
	// 1. Validate required fields
	if config.KeyDirectory == "" {
		return nil, ErrInvalidKeyDirectory
	}

	// 2. Reject negative values (invalid input)
	if config.KeySize < 0 {
		return nil, ErrInvalidKeySize
	}
	if config.KeyRotationInterval < 0 {
		return nil, ErrInvalidKeyRotationInterval
	}
	if config.KeyOverlapDuration < 0 {
		return nil, ErrInvalidKeyOverlapDuration
	}

	// 3. Apply defaults for zero values
	defaults := ConfigDefault()

	if config.KeySize == 0 {
		config.KeySize = defaults.KeySize
	}
	if config.KeyRotationInterval == 0 {
		config.KeyRotationInterval = defaults.KeyRotationInterval
	}
	if config.KeyOverlapDuration == 0 {
		config.KeyOverlapDuration = defaults.KeyOverlapDuration
	}

	// 4. Validate ranges (after defaults)
	// Minimum key size for security
	if config.KeySize < 2048 {
		return nil, ErrInvalidKeySize
	}

	return &Manager{
		config: config,
	}, nil
}
