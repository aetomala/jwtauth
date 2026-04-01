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

	"github.com/aetomala/jwtauth/pkg/logging"
	"github.com/google/uuid"
)

const (
	StateStarted int32 = 1
	StateStopped int32 = 0
)

// Manager is a thread-safe RSA key pair manager responsible for generating,
// storing, rotating, and serving cryptographic keys for JWT signing. It manages
// both the current signing key and a history of public keys that can be used
// for token validation (to support key rotation without invalidating existing tokens).
//
// Manager persists keys to disk for durability and implements automatic rotation
// on a configurable schedule. All methods are safe for concurrent use.
type Manager struct {
	// ===== Configuration =====
	config ManagerConfig // Configuration settings (directory, intervals, key size, logger)

	// ===== Key Storage =====
	keys       map[string]*KeyPair // keyID -> KeyPair; all keys (current + historical)
	currentKeyID string             // ID of the key currently used for signing

	// ===== Synchronization =====
	mu sync.RWMutex // Protects keys, currentKeyID

	// ===== Lifecycle & Rotation =====
	state                   int32        // StateStarted or StateStopped; use atomic operations
	rotationSchedulerActive atomic.Bool  // Whether rotation scheduler goroutine is running
	rotationWG              sync.WaitGroup // Waits for rotation scheduler to exit
	stopRotationCh          chan struct{} // Signal to stop rotation scheduler
	rotationTicker          *time.Ticker  // Fires at KeyRotationInterval for automatic rotation
}

// ManagerConfig holds configuration settings for the Manager.
// All fields should be set before passing to NewManager.
type ManagerConfig struct {
	Logger              logging.Logger // Optional; nil disables logging
	KeyDirectory        string         // Directory where keys are persisted to disk
	KeyRotationInterval time.Duration  // How often to rotate to a new signing key
	KeyOverlapDuration  time.Duration  // How long old keys remain valid after rotation
	KeySize             int            // RSA key size in bits (minimum 2048)
}

// ConfigDefault returns a ManagerConfig with sensible defaults suitable for
// most production deployments. Set KeyDirectory before use, or override other
// fields as needed.
func ConfigDefault() ManagerConfig {
	return ManagerConfig{
		KeySize:             2048,
		KeyRotationInterval: 30 * 24 * time.Hour,
		KeyOverlapDuration:  1 * time.Hour,
	}
}

// KeyMetadata holds metadata about a key for persistence and audit purposes.
type KeyMetadata struct {
	CreatedAt time.Time `json:"created_at"` // When the key was generated
	ExpiresAt time.Time `json:"expires_at"` // When the key expires (can be zero for indefinite)
	ID        string    `json:"id"`         // Unique key identifier
}

// JWKS (JSON Web Key Set) is the standard format for publishing public keys,
// typically served at /.well-known/jwks.json for OAuth/OIDC compliance.
type JWKS struct {
	Keys []JWK `json:"keys"` // Array of public keys
}

// JWK (JSON Web Key) represents a single public key in JWKS format.
// All fields are base64url-encoded as per RFC 7517.
type JWK struct {
	KeyID     string `json:"kid"` // Key ID (matches KeyPair.ID)
	KeyType   string `json:"kty"` // Key type; always "RSA" for this manager
	Algorithm string `json:"alg"` // Signing algorithm; "RS256" for RSA with SHA-256
	Use       string `json:"use"` // Key usage; "sig" for signing
	N         string `json:"n"`   // RSA modulus (base64url-encoded)
	E         string `json:"e"`   // RSA public exponent (base64url-encoded)
}

// KeyPair holds a public-private key pair with metadata.
type KeyPair struct {
	// ===== Cryptographic Material =====
	PrivateKey *rsa.PrivateKey // Private key used for signing (kept in memory only)
	PublicKey  *rsa.PublicKey  // Public key used for verification
	cachedJWK  *JWK            // Cached JWK representation (computed once, reused)

	// ===== Metadata =====
	ID        string    // Unique identifier for this key
	CreatedAt time.Time // When the key was generated
	ExpiresAt time.Time // When this key expires (zero = never expires)
}

// Sentinel Errors for Manager operations.
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

// IsRunning reports whether the Manager is currently running. It returns false
// before Start() is called and after Shutdown() completes.
func (m *Manager) IsRunning() bool {
	return atomic.LoadInt32(&m.state) == StateStarted
}

// Mu returns the Manager's read-write mutex for testing purposes only.
// This is exported solely to enable tests that need to synchronize access with
// key cache mutations.
func (m *Manager) Mu() *sync.RWMutex {
	return &m.mu
}

// Keys returns the Manager's key cache map for testing purposes only.
// This is exported solely to enable tests that need to inspect or manipulate
// the in-memory key cache. Do not use in production code.
func (m *Manager) Keys() map[string]*KeyPair {
	return m.keys
}

// NewManager creates and returns a new Manager with the given configuration.
// Returns ErrInvalidKeyDirectory if KeyDirectory is empty, ErrInvalidKeySize
// if KeySize is less than 2048 bits, ErrInvalidKeyRotationInterval if
// KeyRotationInterval is negative, or ErrInvalidKeyOverlapDuration if
// KeyOverlapDuration is negative. Applies defaults for zero values before validation.
func NewManager(config ManagerConfig) (*Manager, error) {
	// ===== STEP 1: Validate Required Fields =====
	if config.KeyDirectory == "" {
		return nil, ErrInvalidKeyDirectory
	}

	// ===== STEP 2: Reject Negative Values =====
	if config.KeySize < 0 {
		return nil, ErrInvalidKeySize
	}
	if config.KeyRotationInterval < 0 {
		return nil, ErrInvalidKeyRotationInterval
	}
	if config.KeyOverlapDuration < 0 {
		return nil, ErrInvalidKeyOverlapDuration
	}

	// ===== STEP 3: Apply Defaults for Zero Values =====
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

	// ===== STEP 4: Validate Ranges (After Defaults) =====
	if config.KeySize < 2048 {
		return nil, ErrInvalidKeySize
	}

	// ===== STEP 5: Return Initialized Manager =====
	return &Manager{
		config:         config,
		keys:           make(map[string]*KeyPair),
		stopRotationCh: make(chan struct{}),
	}, nil
}

// Start initializes and starts the Manager, preparing it for key operations.
// It loads existing keys from disk (if present) or generates a new key pair.
// Starts the background key rotation scheduler. Returns ErrAlreadyRunning if
// Start() has already been called without a corresponding Shutdown(). Returns
// the context error if the context is cancelled before Start completes.
func (m *Manager) Start(ctx context.Context) error {
	// ===== STEP 1: Check Context =====
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// ===== STEP 2: Check Not Already Running =====
	if !atomic.CompareAndSwapInt32(&m.state, StateStopped, StateStarted) {
		return ErrAlreadyRunning
	}

	// ===== STEP 3: Create Key Directory =====
	if err := os.MkdirAll(m.config.KeyDirectory, 0755); err != nil {
		atomic.StoreInt32(&m.state, StateStopped)
		return fmt.Errorf("create key directory: %w", err)
	}

	// ===== STEP 4: Try Loading Existing Keys from Disk =====
	err := m.loadAllKeysFromDisk()
	if err == nil {
		// Keys loaded successfully; start rotation scheduler
		m.rotationSchedulerActive.Store(true)
		m.rotationWG.Add(1)
		go m.rotationSchedulerLoop(ctx)

		if m.config.Logger != nil {
			m.config.Logger.Info("loaded existing keys from disk",
				"keyID", m.currentKeyID,
				"keyCount", len(m.keys))
		}

		if m.config.Logger != nil {
			m.config.Logger.Info("key manager started",
				"keyDirectory", m.config.KeyDirectory,
				"rotationInterval", m.config.KeyRotationInterval)
		}

		return nil
	}

	// ===== STEP 5: Generate New Key Pair =====
	privateKey, err := rsa.GenerateKey(rand.Reader, m.config.KeySize)
	if err != nil {
		atomic.StoreInt32(&m.state, StateStopped)
		if m.config.Logger != nil {
			m.config.Logger.Error("failed to generate initial key",
				"error", err)
		}
		return fmt.Errorf("generate key: %w", err)
	}

	// ===== STEP 6: Generate Unique Key ID =====
	keyID := uuid.New().String()

	// ===== STEP 7: Store Key Pair in Memory =====
	m.currentKeyID = keyID
	m.keys[m.currentKeyID] = &KeyPair{
		ID:         keyID,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Time{},
		cachedJWK:  m.getJWK(privateKey, keyID),
	}

	// ===== STEP 8: Save Key Pair to Disk =====
	if err := m.saveKeyToDisk(ctx, privateKey, keyID); err != nil {
		atomic.StoreInt32(&m.state, StateStopped)
		if m.config.Logger != nil {
			m.config.Logger.Error("failed to save initial key to disk",
				"error", err)
		}
		return fmt.Errorf("save key to disk: %w", err)
	}

	// ===== STEP 9: Start Rotation Scheduler =====
	m.rotationSchedulerActive.Store(true)
	m.rotationWG.Add(1)
	go m.rotationSchedulerLoop(ctx)

	if m.config.Logger != nil {
		m.config.Logger.Info("generated new RSA key pair",
			"keyID", m.currentKeyID,
			"keySize", m.config.KeySize,
			"duration", time.Since(m.keys[m.currentKeyID].CreatedAt))
	}

	if m.config.Logger != nil {
		m.config.Logger.Info("key manager started",
			"keyDirectory", m.config.KeyDirectory,
			"rotationInterval", m.config.KeyRotationInterval)
	}

	return nil
}

// loadKeyFromDisk loads a private key from the PEM file at the given path.
// Extracts the key ID from the filename (without .pem extension) and validates
// that the key size matches the Manager's configured KeySize. Returns the parsed
// private key, the keyID, and any error that occurs.
func (m *Manager) loadKeyFromDisk(keyFile string) (*rsa.PrivateKey, string, error) {
	// ===== STEP 1: Read PEM File =====
	pemData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, "", fmt.Errorf("read key file: %w", err)
	}

	// ===== STEP 2: Extract Key ID from Filename =====
	keyID := strings.TrimSuffix(filepath.Base(keyFile), ".pem")

	// ===== STEP 3: Decode PEM Block =====
	block, _ := pem.Decode(pemData)
	if block == nil {
		if m.config.Logger != nil {
			m.config.Logger.Warn("failed to load key file",
				"file", filepath.Base(keyFile),
				"error", "invalid PEM format")
		}
		return nil, "", fmt.Errorf("invalid PEM format")
	}

	// ===== STEP 4: Parse Private Key =====
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("parse private key: %w", err)
	}

	// ===== STEP 5: Validate Key Size =====
	if privateKey.N.BitLen() != m.config.KeySize {
		return nil, "", fmt.Errorf("key size mismatch: got %d bits, expected %d bits", privateKey.N.BitLen(), m.config.KeySize)
	}

	return privateKey, keyID, nil
}

// saveKeyToDisk persists a private key to disk in PEM format along with its metadata.
// The key is written with 0600 permissions for security. If metadata save fails, the
// PEM file is removed to maintain consistency. Returns the context error if ctx is
// cancelled before completion.
func (m *Manager) saveKeyToDisk(ctx context.Context, privateKey *rsa.PrivateKey, keyID string) error {
	// ===== STEP 1: Check Context =====
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// ===== STEP 2: Encode Private Key to PEM Format =====
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	// ===== STEP 3: Create PEM File =====
	filename := filepath.Join(m.config.KeyDirectory, keyID+".pem")
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create key file: %w", err)
	}
	defer file.Close()

	// ===== STEP 4: Write PEM File =====
	if err := pem.Encode(file, pemBlock); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}

	// ===== STEP 5: Save Metadata =====
	meta := KeyMetadata{
		ID:        keyID,
		CreatedAt: time.Now(),
	}
	if err := m.saveMetadata(keyID, meta); err != nil {
		// Rollback: remove the PEM file to maintain consistency
		os.Remove(filename)
		if m.config.Logger != nil {
			m.config.Logger.Warn("failed to save key metadata",
				"keyID", keyID)
		}
		return fmt.Errorf("save key metadata: %w", err)
	}

	if m.config.Logger != nil {
		m.config.Logger.Info("saved key metadata",
			"keyID", keyID)
	}

	return nil
}

// deleteKeyFromDisk removes the PEM key file and its associated metadata JSON file
// from disk. It is called during cleanup of expired keys. Returns an error if either
// file cannot be deleted.
func (m *Manager) deleteKeyFromDisk(keyID string) error {
	// ===== STEP 1: Delete PEM File =====
	filename := filepath.Join(m.config.KeyDirectory, keyID+".pem")
	if err := os.Remove(filename); err != nil {
		return fmt.Errorf("delete key file: %w", err)
	}

	// ===== STEP 2: Delete Metadata File =====
	metaFilename := filepath.Join(m.config.KeyDirectory, keyID+".json")
	if err := os.Remove(metaFilename); err != nil {
		return fmt.Errorf("delete metadata file: %w", err)
	}

	return nil
}

// GetCurrentSigningKey returns the Manager's current private key and its ID.
// Returns ErrManagerNotRunning if the Manager is not running, or ErrKeyNotFound
// if the current key is not in the cache (should not happen in practice).
// The returned key is safe to use for concurrent signing operations.
func (m *Manager) GetCurrentSigningKey() (*rsa.PrivateKey, string, error) {
	// ===== STEP 1: Check Manager is Running =====
	if !m.IsRunning() {
		return nil, "", ErrManagerNotRunning
	}

	// ===== STEP 2: Acquire Read Lock and Retrieve Key =====
	if m.config.Logger != nil {
		m.config.Logger.Debug("getting current signing key")
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	keyPair, found := m.keys[m.currentKeyID]

	if !found {
		return nil, "", ErrKeyNotFound
	}

	// ===== STEP 3: Return Key and ID =====
	return keyPair.PrivateKey, m.currentKeyID, nil
}

// Shutdown gracefully shuts down the Manager, stopping the rotation scheduler and
// releasing resources. It is idempotent — calling it multiple times is safe.
// Returns the context error if the context is cancelled before shutdown completes.
// All background goroutines are waited on with a timeout specified by ctx.
func (m *Manager) Shutdown(ctx context.Context) error {
	// ===== STEP 1: Check Not Already Running =====
	if !atomic.CompareAndSwapInt32(&m.state, StateStarted, StateStopped) {
		// Already stopped; shutdown is idempotent
		return nil
	}

	if m.config.Logger != nil {
		m.config.Logger.Info("initiating graceful shutdown")
	}

	// ===== STEP 2: Signal Rotation Scheduler to Stop =====
	close(m.stopRotationCh)

	// ===== STEP 3: Wait for Rotation Goroutine to Exit =====
	done := make(chan struct{})
	go func() {
		m.rotationWG.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Goroutine exited cleanly
	case <-ctx.Done():
		// Context cancelled; timeout or cancellation
		return ctx.Err()
	}

	// ===== STEP 4: Recreate Stop Channel for Potential Restart =====
	m.stopRotationCh = make(chan struct{})

	if m.config.Logger != nil {
		m.config.Logger.Info("key manager stopped")
	}

	return nil
}

// IsRotationSchedulerActive reports whether the background rotation scheduler
// goroutine is currently running. Used for testing and diagnostics.
func (m *Manager) IsRotationSchedulerActive() bool {
	return m.rotationSchedulerActive.Load()
}

// loadPublicKeyFromDisk loads a public key from the PEM file for the given keyID.
// Returns ErrKeyNotFound if the key file does not exist, or an error if the PEM
// is malformed or cannot be parsed.
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
		if m.config.Logger != nil {
			m.config.Logger.Warn("failed to load key file",
				"file", filepath.Base(keyFile),
				"error", "invalid PEM format")
		}
		return nil, fmt.Errorf("invalid PEM format")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	// Validate key size is not less than default
	if privateKey.N.BitLen() < ConfigDefault().KeySize {
		return nil, fmt.Errorf("key size %d below minimum %d", privateKey.N.BitLen(), ConfigDefault().KeySize)
	}
	// Different size OK - just warn
	if privateKey.N.BitLen() != m.config.KeySize {
		if m.config.Logger != nil {
			m.config.Logger.Warn("loaded key",
				"keyId", keyID,
				"size", privateKey.N.BitLen(),
				"configSize", m.config.KeySize)
		}
	}

	return &privateKey.PublicKey, nil
}

// GetPublicKey returns the public key for the given key ID. Checks the in-memory
// cache first, then loads from disk if not found. Returns ErrInvalidKeyID if keyID
// is empty or whitespace-only, or ErrKeyNotFound if the key does not exist or has
// expired. Uses a double-check locking pattern to cache loaded keys.
func (m *Manager) GetPublicKey(keyID string) (*rsa.PublicKey, error) {
	// ===== STEP 1: Validate Key ID =====
	keyID = strings.TrimSpace(keyID)
	if len(keyID) == 0 {
		return nil, ErrInvalidKeyID
	}

	// ===== STEP 2: Check Cache First =====
	m.mu.RLock()
	if keyPair, exists := m.keys[keyID]; exists {
		m.mu.RUnlock()
		if m.config.Logger != nil {
			m.config.Logger.Debug("public key cache hit", "keyID", keyID)
		}
		return keyPair.PublicKey, nil
	}
	m.mu.RUnlock()

	// ===== STEP 3: Load from Disk =====
	if m.config.Logger != nil {
		m.config.Logger.Debug("public key not in memory, loading from disk", "keyID", keyID)
	}
	publicKey, err := m.loadPublicKeyFromDisk(keyID)
	if err != nil {
		return nil, err
	}

	// ===== STEP 4: Load Metadata and Check Expiration =====
	metadata, err := m.loadMetadata(keyID)
	if err != nil {
		return nil, ErrKeyNotFound
	}

	if !metadata.ExpiresAt.IsZero() && time.Now().After(metadata.ExpiresAt) {
		return nil, ErrKeyNotFound
	}

	// ===== STEP 5: Cache with Double-Check Pattern =====
	m.mu.Lock()
	defer m.mu.Unlock()

	// Another goroutine may have cached it already
	if keyPair, exists := m.keys[keyID]; exists {
		return keyPair.PublicKey, nil
	}

	// Cache our loaded version
	m.keys[keyID] = &KeyPair{
		ID:        keyID,
		PublicKey: publicKey,
		CreatedAt: metadata.CreatedAt,
		ExpiresAt: metadata.ExpiresAt,
	}

	return publicKey, nil
}

// loadAllKeysFromDisk loads all persisted keys from the key directory into the
// in-memory cache. Skips keys with missing or corrupted metadata, and skips
// already-expired keys. Returns an error if no valid keys are found.
func (m *Manager) loadAllKeysFromDisk() error {
	pattern := filepath.Join(m.config.KeyDirectory, "*.pem")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("glob key files: %w", err)
	}

	if len(matches) == 0 {
		return fmt.Errorf("no keys found")
	}

	var mostRecentKeyID string
	var mostRecentTime time.Time

	m.mu.Lock()
	defer m.mu.Unlock()

	// Load ALL keys
	for _, file := range matches {
		privateKey, keyID, err := m.loadKeyFromDisk(file)
		if err != nil {
			// Skip corrupted files
			if m.config.Logger != nil {
				m.config.Logger.Warn("failed to load key",
					"keyID", m.currentKeyID,
					"error", err)
			}
			continue
		}
		// Get keymetadata
		metadata, err := m.loadMetadata(keyID)
		if err != nil {
			// Skip corrupted metadata
			if m.config.Logger != nil {
				m.config.Logger.Warn("failed to load key metadata",
					"keyID", filepath.Base(file),
					"error", err)
			}
			continue
		}

		// Skip already-expired keys
		if !metadata.ExpiresAt.IsZero() && time.Now().After(metadata.ExpiresAt) {
			if m.config.Logger != nil {
				m.config.Logger.Info("skipped expired key",
					"keyID", keyID,
					"expiredAt", metadata.ExpiresAt.Format(time.RFC3339))
			}
			continue
		}

		// Add to keys map
		m.keys[keyID] = &KeyPair{
			ID:         keyID,
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
			CreatedAt:  metadata.CreatedAt,
			ExpiresAt:  metadata.ExpiresAt,
			cachedJWK:  m.getJWK(privateKey, keyID),
		}
		if m.config.Logger != nil {
			m.config.Logger.Debug("loaded key from disk", "keyID", keyID)
		}

		if mostRecentKeyID == "" || metadata.CreatedAt.After(mostRecentTime) {
			mostRecentKeyID = keyID
			mostRecentTime = metadata.CreatedAt
		}
	}

	if mostRecentKeyID == "" {
		return fmt.Errorf("no valid keys loaded")
	}

	m.currentKeyID = mostRecentKeyID

	if m.config.Logger != nil {
		m.config.Logger.Info("set current key", "keyID", m.currentKeyID)
	}

	if m.config.Logger != nil {
		m.config.Logger.Info("loaded keys from disk", "count", len(m.keys))
	}
	return nil
}

func base64urlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// GetJWKS returns a JSON Web Key Set (JWKS) containing all non-expired public keys.
// Returns ErrManagerNotRunning if the Manager is not running. The returned JWKS
// is suitable for serving at /.well-known/jwks.json for OAuth/OIDC compliance.
func (m *Manager) GetJWKS() (*JWKS, error) {
	// ===== STEP 1: Check Manager is Running =====
	if !m.IsRunning() {
		return nil, ErrManagerNotRunning
	}

	if m.config.Logger != nil {
		m.config.Logger.Debug("getting JWKS")
	}

	// ===== STEP 2: Acquire Read Lock and Collect Keys =====
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]JWK, 0, len(m.keys))
	for _, key := range m.keys {
		// Skip expired keys
		if !key.ExpiresAt.IsZero() && time.Now().After(key.ExpiresAt) {
			continue
		}
		keys = append(keys, *key.cachedJWK)
	}

	// ===== STEP 3: Return JWKS =====
	return &JWKS{
		Keys: keys,
	}, nil
}

// getJWK converts an RSA private key and its ID into a JWK (JSON Web Key) format
// suitable for JWKS (JSON Web Key Set) publication. All numeric values are
// base64url-encoded as per RFC 7517.
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

// GetKeyInfo returns metadata information for the key with the given ID.
// Returns ErrManagerNotRunning if the Manager is not running, or ErrKeyNotFound
// if the key does not exist in the cache.
func (m *Manager) GetKeyInfo(keyID string) (*KeyPair, error) {
	// ===== STEP 1: Check Manager is Running =====
	if !m.IsRunning() {
		return nil, ErrManagerNotRunning
	}

	// ===== STEP 2: Acquire Read Lock and Lookup =====
	m.mu.RLock()
	defer m.mu.RUnlock()

	keyPair, exists := m.keys[keyID]
	if !exists {
		return nil, ErrKeyNotFound
	}

	// ===== STEP 3: Return Key Pair =====
	return keyPair, nil
}

// RotateKeys rotates the current signing key to a newly generated one, and marks
// the old key to expire after KeyOverlapDuration. This allows old tokens to be
// validated during the transition period. Returns ErrManagerNotRunning if the
// Manager is not running. Returns the context error if the context is cancelled.
func (m *Manager) RotateKeys(ctx context.Context) error {
	// ===== STEP 1: Check Context =====
	select {
	case <-ctx.Done():
		if m.config.Logger != nil {
			m.config.Logger.Warn("key rotation cancelled")
		}
		return ctx.Err()
	default:
	}

	startTime := time.Now()

	// ===== STEP 2: Acquire Write Lock =====
	m.mu.Lock()
	defer m.mu.Unlock()

	// ===== STEP 3: Check Manager is Running =====
	if !m.IsRunning() {
		return ErrManagerNotRunning
	}

	// ===== STEP 4: Generate New RSA Key Pair =====
	privatekey, err := rsa.GenerateKey(rand.Reader, m.config.KeySize)
	if err != nil {
		if m.config.Logger != nil {
			m.config.Logger.Error("key rotation failed",
				"error", err)
		}
		return fmt.Errorf("generate key: %w", err)
	}

	// ===== STEP 5: Generate Unique Key ID =====
	keyID := uuid.New().String()

	// ===== STEP 6: Save New Key to Disk =====
	if err := m.saveKeyToDisk(ctx, privatekey, keyID); err != nil {
		if m.config.Logger != nil {
			m.config.Logger.Error("key rotation failed",
				"error", err)
		}
		return fmt.Errorf("save key to disk: %w", err)
	}

	// ===== STEP 7: Mark Old Key to Expire =====
	oldKeyID := m.currentKeyID
	oldKey, exists := m.keys[oldKeyID]
	if exists {
		oldKey.ExpiresAt = time.Now().Add(m.config.KeyOverlapDuration)

		// Persist old key's new expiration to disk
		updatedMeta := KeyMetadata{
			ID:        oldKeyID,
			CreatedAt: oldKey.CreatedAt,
			ExpiresAt: oldKey.ExpiresAt,
		}
		if err := m.saveMetadata(oldKeyID, updatedMeta); err != nil {
			// Log but continue; in-memory expiration is sufficient
			if m.config.Logger != nil {
				m.config.Logger.Warn("failed to persist expiration for old key",
					"oldKey", oldKeyID,
					"error", err)
			}
		}
		if m.config.Logger != nil {
			m.config.Logger.Info("saved key metadata",
				"keyID", oldKeyID)
		}
	}

	// ===== STEP 8: Switch to New Signing Key =====
	m.currentKeyID = keyID

	// ===== STEP 9: Cache New Key in Memory =====
	m.keys[keyID] = &KeyPair{
		ID:         keyID,
		PrivateKey: privatekey,
		PublicKey:  &privatekey.PublicKey,
		CreatedAt:  time.Now(),
		ExpiresAt:  time.Time{},
		cachedJWK:  m.getJWK(privatekey, keyID),
	}

	if m.config.Logger != nil {
		m.config.Logger.Info("key rotation successful",
			"newKeyID", keyID,
			"oldKeyID", oldKeyID,
			"duration", time.Since(startTime))
		m.config.Logger.Info("old key marked for expiration",
			"expiresAt", oldKey.ExpiresAt)
	}

	return nil
}

// rotationSchedulerLoop implements the background goroutine that automatically rotates
// keys at the configured interval and periodically cleans up expired keys. Runs until
// ctx is cancelled or the Manager is shut down via stopRotationCh.
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
			if m.config.Logger != nil {
				m.config.Logger.Info("automatic rotation triggered")
			}
			if err := m.RotateKeys(ctx); err != nil {
				if m.config.Logger != nil {
					m.config.Logger.Error("rotation failed",
						"error", err)
				}
			}
			// Also cleanup right after rotation
			m.cleanupExpiredKeys()

		case <-cleanupTicker.C:
			// Periodic cleanup
			if m.config.Logger != nil {
				m.config.Logger.Debug("rotation cleanup tick fired")
			}
			m.cleanupExpiredKeys()

		case <-ctx.Done():
			return
		case <-m.stopRotationCh:
			return
		}
	}
}

// cleanupExpiredKeys removes expired keys from memory and disk. It is called
// periodically by the rotation scheduler loop and also immediately after key
// rotation. The current signing key is never removed. If cleanup removes nothing,
// it logs at Debug level; successful removals are logged at Info level.
func (m *Manager) cleanupExpiredKeys() {
	// ===== STEP 1: Check Manager is Running =====
	if !m.IsRunning() {
		return
	}

	// ===== STEP 2: Acquire Write Lock =====
	m.mu.Lock()
	defer m.mu.Unlock()

	// ===== STEP 3: Sweep Expired Keys =====
	now := time.Now()
	count := 0
	deletedKeys := []string{}

	for keyID, key := range m.keys {
		// Never remove current signing key
		if keyID == m.currentKeyID {
			continue
		}

		// Remove if expired
		if !key.ExpiresAt.IsZero() && now.After(key.ExpiresAt) {
			// Remove from memory
			delete(m.keys, keyID)

			// Remove from disk
			if err := m.deleteKeyFromDisk(keyID); err != nil {
				if m.config.Logger != nil {
					m.config.Logger.Error("delete key failed",
						"error", err)
				}
			} else {
				count++
				deletedKeys = append(deletedKeys, keyID)
			}
		}
	}

	// ===== STEP 4: Log Results =====
	if m.config.Logger != nil {
		if count == 0 {
			m.config.Logger.Debug("no expired keys found during cleanup")
		} else {
			m.config.Logger.Info("expired key cleanup executed",
				"deletedCount", count)
			for _, key := range deletedKeys {
				m.config.Logger.Info("deleted expired key",
					"keyID", key)
			}
		}
	}
}

// saveMetadata persists key metadata (creation time, expiration, ID) to a JSON file
// alongside the corresponding PEM key file. Used to track key lifecycle and expiration.
func (m *Manager) saveMetadata(keyID string, meta KeyMetadata) error {
	filename := filepath.Join(m.config.KeyDirectory, keyID+".json")
	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	return os.WriteFile(filename, data, 0600)
}

// loadMetadata loads key metadata from the JSON file corresponding to the given keyID.
// Returns an error if the file does not exist or cannot be parsed.
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
