package keymanager

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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
	currentKeyID            string
	rotationSchedulerActive atomic.Bool
	mu                      sync.RWMutex
	keys                    map[string]*KeyPair
	stopRotationCh          chan struct{}  // Signal to stop rotation goroutine
	rotationWG              sync.WaitGroup // Wait for goroutine to exit
	rotationTicker          *time.Ticker   // Store ticker so we can stop it
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

type KeyMetadata struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

type JWKS struct {
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
	ErrInvalidKeySize             = errors.New("invalid key size: must be at least 2048 bits")
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
		config:         config,
		keys:           make(map[string]*KeyPair), // Initialize the map
		stopRotationCh: make(chan struct{}),       // ← Initialize once
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
		m.currentKeyID = existingKeyID
		// store in keys
		m.keys[m.currentKeyID] = &KeyPair{
			ID:         existingKeyID,
			PrivateKey: existingKey,
			PublicKey:  &existingKey.PublicKey,
			CreatedAt:  time.Now(), // TODO load date from JSON metadata or PEM file
			ExpiresAt:  time.Time{},
			cachedJWK:  m.getJWK(existingKey, m.currentKeyID),
		}
		// Start rotation scheduler
		m.rotationSchedulerActive.Store(true)
		m.stopRotationCh = make(chan struct{})
		m.rotationWG.Add(1)
		go m.rotationSchedulerLoop(ctx)
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
	m.currentKeyID = keyID

	// 6.a store in keys
	m.keys[m.currentKeyID] = &KeyPair{
		ID:         keyID,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Time{},
		cachedJWK:  m.getJWK(privateKey, keyID),
	}

	// 7. Save to disk for persistence
	if err := m.saveKeyToDisk(ctx, privateKey, keyID); err != nil {
		atomic.StoreInt32(&m.state, StateStopped)
		return fmt.Errorf("generate key: %w", err)
	}

	// START ROTATION SCHEDULER
	m.rotationSchedulerActive.Store(true)
	m.stopRotationCh = make(chan struct{})
	m.rotationWG.Add(1)
	go m.rotationSchedulerLoop(ctx)

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

func (m *Manager) saveKeyToDisk(ctx context.Context, privateKey *rsa.PrivateKey, keyID string) error {

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

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

	// save meta data
	meta := KeyMetadata{
		ID:        keyID,
		CreatedAt: time.Now(),
	}
	if err := m.saveMetadata(keyID, meta); err != nil {
		return fmt.Errorf("write key meta file %w", err)
	}

	return nil
}

func (m *Manager) deleteKeyFromDisk(keyID string) error {
	filename := filepath.Join(m.config.KeyDirectory, keyID+".pem")
	err := os.Remove(filename)
	if err != nil {
		return fmt.Errorf("deleting key from disk: %w", err)
	}
	return nil
}

// GetCurrentSigningKey. Returns the manager's current privatekey
func (m *Manager) GetCurrentSigningKey() (*rsa.PrivateKey, string, error) {
	if !m.IsRunning() {
		return nil, "", ErrManagerNotRunning
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	keyPair, found := m.keys[m.currentKeyID]

	if !found {
		return nil, "", ErrKeyNotFound
	}
	return keyPair.PrivateKey, m.currentKeyID, nil
}

// Shutdown. Gracefully shutsdown the key manager.
func (m *Manager) Shutdown(ctx context.Context) error {

	if !atomic.CompareAndSwapInt32(&m.state, StateStarted, StateStopped) {
		// Already stopped
		return nil
	}

	// Signal the rotation goroutine to stop
	close(m.stopRotationCh)

	// wiat for goroutine to exit (with timeout)
	done := make(chan struct{})

	go func() {
		m.rotationWG.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Goroutine exited cleanly
	case <-ctx.Done():
		// Timeout - goroutine didn't exit in time
		return ctx.Err()
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

	// Check cache first
	m.mu.RLock()
	if keyPair, exists := m.keys[keyID]; exists {
		m.mu.RUnlock()
		return keyPair.PublicKey, nil
	}
	m.mu.RUnlock()

	// Load from disk (outside lock)
	publicKey, err := m.loadPublicKeyFromDisk(keyID)
	if err != nil {
		return nil, err
	}

	// Cache with double-check pattern
	m.mu.Lock()
	defer m.mu.Unlock()

	// Double-check: another goroutine might have loaded it
	if keyPair, exists := m.keys[keyID]; exists {
		return keyPair.PublicKey, nil // Use the one already cached
	}

	// Still not there, cache our loaded version
	m.keys[keyID] = &KeyPair{
		ID:        keyID,
		PublicKey: publicKey,
	}

	return publicKey, nil
}

func base64urlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// GetJWKS returns Manager public keys
func (m *Manager) GetJWKS() (*JWKS, error) {

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

	return &JWKS{
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

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
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
		return fmt.Errorf("generate key: %w", err)
	}
	// 3. Generate new key ID (UUID)
	keyID := uuid.New().String() // Generate ID here

	// 4. Save to disk for persistence
	if err := m.saveKeyToDisk(ctx, privatekey, keyID); err != nil {
		return fmt.Errorf("save key: %w", err)
	}

	// Update old key expiration before switching
	oldKeyID := m.currentKeyID
	if oldKey, exists := m.keys[oldKeyID]; exists {
		oldKey.ExpiresAt = time.Now().Add(m.config.KeyOverlapDuration)
	}

	// 5. Store in memory
	m.currentKeyID = keyID

	// 6. add new key to keys
	m.keys[keyID] = &KeyPair{
		ID:         keyID,
		PrivateKey: privatekey,
		PublicKey:  &privatekey.PublicKey,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Time{},
		cachedJWK:  m.getJWK(privatekey, keyID),
	}

	return nil
}

// rotationSchedulerLoop Sets up the infinite loop that will automatically rotake keys
func (m *Manager) rotationSchedulerLoop(ctx context.Context) {
	m.rotationTicker = time.NewTicker(m.config.KeyRotationInterval)

	// Cleanup ticker - check frequently enough to catch expiration
	// For tests with short overlap (100ms), we need frequent checks
	// For production (1 hour overlap), less frequent is fine
	cleanupInterval := m.config.KeyOverlapDuration / 4
	if cleanupInterval > 1*time.Minute {
		cleanupInterval = 1 * time.Minute // Max 1 minute in production
	}
	if cleanupInterval < 10*time.Millisecond {
		cleanupInterval = 10 * time.Millisecond // Min for tests
	}

	cleanupTicker := time.NewTicker(cleanupInterval)

	m.rotationSchedulerActive.Store(true)

	defer m.rotationWG.Done()
	defer m.rotationSchedulerActive.Store(false)
	defer m.rotationTicker.Stop()
	defer cleanupTicker.Stop() // Critical: prevent cleanup ticker leak!

	for {
		select {
		case <-m.rotationTicker.C:
			// Rotation time!
			if err := m.RotateKeys(ctx); err != nil {
				fmt.Printf("rotation failed: %v\n", err)
			}
			// Also cleanup right after rotation
			m.cleanupExpiredKeys()

		case <-cleanupTicker.C:
			// Periodic cleanup
			m.cleanupExpiredKeys()

		case <-ctx.Done():
			return
		case <-m.stopRotationCh:
			return
		}
	}
}

func (m *Manager) cleanupExpiredKeys() {
	if !m.IsRunning() {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for keyID, key := range m.keys {
		// Never remove current key
		if keyID == m.currentKeyID {
			continue
		}
		// Remove is expired
		if !key.ExpiresAt.IsZero() && now.After(key.ExpiresAt) {
			// remove from memory
			delete(m.keys, keyID)
			// remove from disk
			if err := m.deleteKeyFromDisk(keyID); err != nil {
				fmt.Printf("delete key failed: %v\n", err)
			}
		}
	}
}

// Save alongside PEM
func (m *Manager) saveMetadata(keyID string, meta KeyMetadata) error {
	filename := filepath.Join(m.config.KeyDirectory, keyID+".json")
	data, _ := json.Marshal(meta)
	return os.WriteFile(filename, data, 0600)
}

// Load with PEM
func (m *Manager) loadMetadata(keyID string) (KeyMetadata, error) {
	filename := filepath.Join(m.config.KeyDirectory, keyID+".json")
	data, err := os.ReadFile(filename)
	if err != nil {
		return KeyMetadata{}, err
	}

	var meta KeyMetadata
	err = json.Unmarshal(data, &meta)
	return meta, err
}
