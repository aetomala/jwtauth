package keymanager

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

const (
	StateStarted int32 = 1
	StateStopped int32 = 0
)

type Manager struct {
	config                  ManagerConfig
	state                   int32 //0 stopped 1 running
	currentKey              *rsa.PrivateKey
	currentKeyID            string
	rotationSchedulerActive atomic.Bool
	mu                      sync.RWMutex
	keys                    map[string]*KeyPair
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

type JKWS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	KeyID     string `json:"kid"` // Key ID
	KeyType   string `json:"kty"` // "RSA"
	Algorithm string `json:"alg"` // "RS256"
	Use       string `json:"use"` // "sig"
	N         string `json:"n"`   // RSA modulus (base64url)
	E         string `json:"e"`   // RSA exponent (base64url)
}

type KeyPair struct {
	ID         string
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	CreatedAt  time.Time
	ExpiresAt  time.Time // Zero value = never expires
	cachedJWK  *JWK      // cache JWK
}

// Sentinel Errors
var (
	ErrInvalidKeyDirectory        = errors.New("invalid key directory")
	ErrInvalidKeySize             = errors.New("invalid key size")
	ErrInvalidKeyRotationInterval = errors.New("invalid key rotation interval")
	ErrInvalidKeyOverlapDuration  = errors.New("invalid key overlap duration")
	ErrAlreadyRunning             = errors.New("manager is already running")
	ErrManagerNotRunning          = errors.New("manager is not running")
	ErrKeyNotFound                = errors.New("key not found")
	ErrInvalidKeyID               = errors.New("invalid key ID")
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
		keys:   make(map[string]*KeyPair), // Initialize the map
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
	existingKey, existingKeyID, err := m.loadKeyFromDisk()
	if err == nil {
		m.currentKey = existingKey
		m.currentKeyID = existingKeyID
		// store in keys
		m.keys[m.currentKeyID] = &KeyPair{
			ID:         existingKeyID,
			PrivateKey: m.currentKey,
			PublicKey:  &m.currentKey.PublicKey,
			CreatedAt:  time.Now(), // TODO load date from JSON metadata or PEM file
			ExpiresAt:  time.Now().Add(m.config.KeyRotationInterval).Add(m.config.KeyOverlapDuration),
			cachedJWK:  m.getJWK(m.currentKey, m.currentKeyID),
		}
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

	// 6.a store in keys
	m.keys[m.currentKeyID] = &KeyPair{
		ID:         keyID,
		PrivateKey: m.currentKey,
		PublicKey:  &m.currentKey.PublicKey,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(m.config.KeyRotationInterval).Add(m.config.KeyOverlapDuration),
		cachedJWK:  m.getJWK(m.currentKey, keyID),
	}

	// 7. Save to disk for persistence
	if err := m.saveKeyToDisk(privateKey, keyID); err != nil {
		atomic.StoreInt32(&m.state, StateStopped)
		return fmt.Errorf("generate key: %w", err)
	}

	m.rotationSchedulerActive.Store(true)

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

	// Find the most recently modified file
	var newestFile string
	var newestTime time.Time

	for _, file := range matches {
		info, err := os.Stat(file)
		if err != nil {
			continue
		}
		if newestFile == "" || info.ModTime().After(newestTime) {
			newestFile = file
			newestTime = info.ModTime()
		}
	}

	if newestFile == "" {
		return nil, "", fmt.Errorf("no valid keys found")
	}

	keyFile := newestFile

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

	// validate if the key found is the same size as configuration says
	if privateKey.N.BitLen() != m.config.KeySize {
		return nil, "", errors.New("key found is incorrect size")
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

// GetCurrentSigningKey. Returns the manager's current privatekey
func (m *Manager) GetCurrentSigningKey() (*rsa.PrivateKey, string, error) {
	if !m.IsRunning() {
		return nil, "", ErrManagerNotRunning
	}
	return m.currentKey, m.currentKeyID, nil
}

// Shutdown. Gracefully shutsdown the key manager.
func (m *Manager) Shutdown(ctx context.Context) error {

	if !atomic.CompareAndSwapInt32(&m.state, StateStarted, StateStopped) {
		// Already stopped
		return nil
	}
	return nil
}

func (m *Manager) IsRotationSchedulerActive() bool {
	return m.rotationSchedulerActive.Load()
}

// loadKeyFromDisk searched for persisted keys by keyID and returns public key
func (m *Manager) loadPublicKeyFromDisk(keyID string) (*rsa.PublicKey, error) {

	// Extract key ID from filename
	keyFile := filepath.Join(m.config.KeyDirectory, keyID+".pem")

	// Read and parse key
	pemData, err := os.ReadFile(keyFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrKeyNotFound
		}
		return nil, fmt.Errorf("read key file: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("invalid PEM format")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	// validate if the key found is the same size as configuration says
	if privateKey.N.BitLen() != m.config.KeySize {
		return nil, errors.New("key found is incorrect size")
	}

	return &privateKey.PublicKey, nil
}

// GetPublicKey returns publickey by key ID
func (m *Manager) GetPublicKey(keyID string) (*rsa.PublicKey, error) {

	keyID = strings.Trim(keyID, " ")
	if len(keyID) == 0 {
		return nil, ErrInvalidKeyID
	}

	m.mu.RLock()
	keyPair, exists := m.keys[keyID]
	m.mu.RUnlock()

	if exists {
		return keyPair.PublicKey, nil
	}

	// fallback to disk

	publicKey, err := m.loadPublicKeyFromDisk(keyID)

	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func base64urlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// GetJKWS returns Manager public keys
func (m *Manager) GetJWKS() (*JKWS, error) {

	// 1 check if running
	if !m.IsRunning() {
		return nil, ErrManagerNotRunning
	}

	// 2 aquire lock
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]JWK, 0, len(m.keys))
	for _, key := range m.keys {
		// skip expired keys
		if !key.ExpiresAt.IsZero() && time.Now().After(key.ExpiresAt) {
			continue
		}
		keys = append(keys, *key.cachedJWK)
	}

	return &JKWS{
		Keys: keys,
	}, nil
}

// getJWK returns a properly formatted token
func (m *Manager) getJWK(key *rsa.PrivateKey, keyID string) *JWK {
	publicKey := key.PublicKey
	return &JWK{
		KeyID:     keyID,
		KeyType:   "RSA",
		Algorithm: "RS256",
		Use:       "sig",
		N:         base64urlEncode(publicKey.N.Bytes()),
		E:         base64urlEncode(big.NewInt(int64(publicKey.E)).Bytes()),
	}
}

// GetKeyInfo. returns meta data information for stored key by keyID
func (m *Manager) GetKeyInfo(keyID string) (*KeyPair, error) {
	// check if the manager is running
	if !m.IsRunning() {
		return nil, ErrManagerNotRunning
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	keyPair, exists := m.keys[keyID]

	if !exists {
		return nil, ErrKeyNotFound
	}

	return keyPair, nil
}

// RotateKeys
func (m *Manager) RotateKeys(ctx context.Context) error {
	//1. Acquire lock
	m.mu.Lock()
	defer m.mu.Unlock()
	// 2. check if manager is running
	if !m.IsRunning() {
		return ErrManagerNotRunning
	}
	// 2. Generate new RSA key pair
	privatekey, err := rsa.GenerateKey(rand.Reader, m.config.KeySize)
	if err != nil {
		atomic.StoreInt32(&m.state, StateStopped)
		return fmt.Errorf("generate key: %w", err)
	}
	// 3. Generate new key ID (UUID)
	keyID := uuid.New().String() // Generate ID here

	// 4. Save to disk for persistence
	if err := m.saveKeyToDisk(privatekey, keyID); err != nil {
		atomic.StoreInt32(&m.state, StateStopped)
		return fmt.Errorf("generate key: %w", err)
	}

	// Update old key expiration before switching
	oldKeyID := m.currentKeyID
	if oldKey, exists := m.keys[oldKeyID]; exists {
		oldKey.ExpiresAt = time.Now().Add(m.config.KeyOverlapDuration)
	}

	// 5. Store in memory
	m.currentKey = privatekey
	m.currentKeyID = keyID

	// 6. add new key to keys
	m.keys[keyID] = &KeyPair{
		ID:         keyID,
		PrivateKey: m.currentKey,
		PublicKey:  &m.currentKey.PublicKey,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Now().Add(m.config.KeyRotationInterval).Add(m.config.KeyOverlapDuration),
		cachedJWK:  m.getJWK(privatekey, keyID),
	}

	return nil
}
