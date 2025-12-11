package keymanager

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

const (
	StateStarted int32 = 1
	StateStopped int32 = 0
)

type Manager struct {
	config       ManagerConfig
	state        int32 //0 stopped 1 running
	currentKey   *rsa.PrivateKey
	currentKeyID string
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
	ErrAlreadyRunning             = errors.New("manager is already running")
	ErrManagerNotRunning          = errors.New("manager is not running")
)

// IsRunning tells caller if the manager is currently running
func (m *Manager) IsRunning() bool {
	return atomic.LoadInt32(&m.state) == StateStarted
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

// Start start the key manager
func (m *Manager) Start(ctx context.Context) error {

	// Check context before starting
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// 1. Check not already running
	if !atomic.CompareAndSwapInt32(&m.state, StateStopped, StateStarted) {
		return ErrAlreadyRunning
	}

	// 2. Create directory if needed
	if err := os.MkdirAll(m.config.KeyDirectory, 0755); err != nil {
		atomic.StoreInt32(&m.state, StateStopped)
		return fmt.Errorf("create key directory: %w", err)
	}

	// 3. Try to load existing keys from disk first
	exitingKey, existingKeyID, err := m.loadKeyFromDisk()
	if err == nil {
		m.currentKey = exitingKey
		m.currentKeyID = existingKeyID
		return nil
	}

	// 4. No existing key - generate new one
	privateKey, err := rsa.GenerateKey(rand.Reader, m.config.KeySize)
	if err != nil {
		atomic.StoreInt32(&m.state, StateStopped)
		return fmt.Errorf("generate key: %w", err)
	}

	// 5. Generate unique ID for this key
	keyID := uuid.New().String() // Generate ID here

	// 6. Store in memory
	m.currentKey = privateKey
	m.currentKeyID = keyID

	// 7. Save to disk for persistence
	if err := m.saveKeyToDisk(privateKey, keyID); err != nil {
		atomic.StoreInt32(&m.state, StateStopped)
		return fmt.Errorf("generate key: %w", err)
	}

	return nil
}

// loadKeyFromDisk searched for persisted keys and returns currentKey
func (m *Manager) loadKeyFromDisk() (*rsa.PrivateKey, string, error) {
	// 1. Read all files in key directory
	pattern := filepath.Join(m.config.KeyDirectory, "*.pem")
	matches, err := filepath.Glob(pattern)

	if err != nil {
		return nil, "", fmt.Errorf("glob key files: %w", err)
	}
	if len(matches) == 0 {
		return nil, "", fmt.Errorf("no keys found")
	}

	// Use the first key found
	keyFile := matches[0]

	// Extract key ID from filename
	filename := filepath.Base(keyFile)
	keyID := strings.TrimSuffix(filename, ".pem")

	// Read and parse key
	pemData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, "", fmt.Errorf("read key file: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, "", fmt.Errorf("invalid PEM format")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("parse private key: %w", err)
	}

	return privateKey, keyID, nil
}

func (m *Manager) saveKeyToDisk(privateKey *rsa.PrivateKey, keyID string) error {
	// 1. Encode private key to PEM format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	// 2. Create file with key ID in filename
	filename := filepath.Join(m.config.KeyDirectory, keyID+".pem")
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	defer file.Close()

	// 3. Write PEM file
	if err := pem.Encode(file, pemBlock); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}

	return nil
}

func (m *Manager) GetCurrentSigningKey() (*rsa.PrivateKey, string, error) {
	if !m.IsRunning() {
		return nil, "", ErrManagerNotRunning
	}
	return m.currentKey, m.currentKeyID, nil
}

func (m *Manager) Shutdown(ctx context.Context) error {

	if !atomic.CompareAndSwapInt32(&m.state, StateStarted, StateStopped) {
		// Already stopped
		return nil
	}
	return nil
}
