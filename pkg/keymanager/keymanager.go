// Package keymanager provides zero-downtime RSA key rotation for JWT signing.
//
// KeyManager generates RSA key pairs, rotates them on a configurable schedule, and
// maintains an overlap period where both old and new keys remain valid. This enables
// key rotation without service restarts or forced re-authentication — tokens signed
// with the old key continue to validate during the overlap window.
//
// Key rotation timeline example:
//
//	Day 0:      Key A (current, signs new tokens)
//	Day 30:     Rotate → Key A (validates old tokens), Key B (current, signs new tokens)
//	Day 30+1h:  Overlap ends → Key B (current, only valid key)
//
// Manager delegates all key persistence to an injected KeyStore implementation:
//   - DiskKeyStore:  Single-instance deployments (PEM + JSON files on local filesystem)
//   - RedisKeyStore: Distributed/multi-instance deployments (shared Redis backend)
//
// The Manager handles lifecycle (Start/Shutdown), automatic rotation scheduling, and
// cleanup of expired keys. It never performs I/O directly — all storage operations
// go through the KeyStore interface.
//
// Example usage:
//
//	// Create a KeyStore (choose based on deployment)
//	ks, err := keymanager.NewDiskKeyStore("./keys", 2048, logger, metrics)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Create KeyManager
//	config := keymanager.ManagerConfig{
//	    KeyStore:            ks,
//	    KeyRotationInterval: 30 * 24 * time.Hour, // 30 days
//	    KeyOverlapDuration:  1 * time.Hour,        // 1 hour overlap
//	    Logger:              logger,               // Optional
//	    Metrics:             metrics,              // Optional
//	}
//
//	mgr, err := keymanager.NewManager(config)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Start background rotation
//	ctx := context.Background()
//	if err := mgr.Start(ctx); err != nil {
//	    log.Fatal(err)
//	}
//	defer mgr.Shutdown(ctx)
//
//	// Get current signing key (for TokenService to use)
//	privateKey, keyID, err := mgr.GetCurrentSigningKey(ctx)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Get JWKS for token validation endpoints
//	jwks, err := mgr.GetJWKS(ctx)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Manual rotation (optional, for testing or emergency rotation)
//	if err := mgr.RotateKeys(ctx); err != nil {
//	    log.Fatal(err)
//	}
//
// ## Key Inspection
//
// GetCurrentKeyInfo and GetKeyInfo expose key metadata — creation time, estimated
// rotation time, expiry, key size, and validity — without returning private key
// material. Suitable for health check endpoints, Prometheus gauges, and admin APIs:
//
//	info, err := mgr.GetCurrentKeyInfo(ctx)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Current key: %s\n", info.KeyID)
//	fmt.Printf("Key age:     %s\n", time.Since(info.CreatedAt))
//	fmt.Printf("Rotates at:  %s\n", info.RotateAt.Format(time.RFC3339))
//
// Use cases:
//   - /health/keys endpoints showing rotation schedule
//   - Prometheus gauges (key age, time-until-rotation, validity)
//   - Debugging token validation failures against a specific kid
//   - Admin dashboards displaying key state
package keymanager

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aetomala/jwtauth/pkg/logging"
	"github.com/aetomala/jwtauth/pkg/metrics"
	"github.com/google/uuid"
)

const (
	StateStarted int32 = 1
	StateStopped int32 = 0
)

// Manager is a thread-safe RSA key pair manager responsible for generating,
// caching, rotating, and serving cryptographic keys for JWT signing. It manages
// both the current signing key and a history of public keys that support token
// validation across rotation boundaries (overlap period).
//
// Manager delegates all key persistence to an injected KeyStore, which makes the
// storage backend replaceable without changing this struct. All methods are safe
// for concurrent use.
type Manager struct {
	// ===== Configuration =====
	config ManagerConfig // Configuration settings (key store, intervals, key size, logger)

	// ===== Key Cache =====
	keys         map[string]*KeyPair // keyID -> KeyPair; all keys (current + historical)
	currentKeyID string              // ID of the key currently used for signing

	// ===== Observability =====
	metrics metrics.Metrics // Optional; nil disables metrics

	// ===== Synchronization =====
	mu sync.RWMutex // Protects keys, currentKeyID

	// ===== Lifecycle & Rotation =====
	state                   int32          // StateStarted or StateStopped; use atomic operations
	rotationSchedulerActive atomic.Bool    // Whether rotation scheduler goroutine is running
	rotationWG              sync.WaitGroup // Waits for rotation scheduler to exit
	stopRotationCh          chan struct{}   // Signal to stop rotation scheduler
	rotationTicker          *time.Ticker   // Fires at KeyRotationInterval for automatic rotation
}

// ManagerConfig holds configuration settings for the Manager.
// All fields should be set before passing to NewManager.
type ManagerConfig struct {
	Logger              logging.Logger  // Optional; nil disables logging
	KeyStore            KeyStore        // Required; the persistence backend for RSA key pairs
	Metrics             metrics.Metrics // Optional; nil disables metrics
	KeyRotationInterval time.Duration   // How often to rotate to a new signing key
	KeyOverlapDuration  time.Duration   // How long old keys remain valid after rotation
	KeySize             int             // RSA key size in bits (minimum 2048)
}

// ConfigDefault returns a ManagerConfig with sensible defaults suitable for
// most production deployments. Set KeyStore before use, or override other
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
	ExpiresAt time.Time `json:"expires_at"` // When the key expires (zero means no expiry)
	ID        string    `json:"id"`         // Unique key identifier
}

// KeyInfo contains public metadata about a cryptographic key — no private key
// material is included. Suitable for health check endpoints, Prometheus metrics,
// debugging, and admin dashboards. All methods are safe for concurrent use.
type KeyInfo struct {
	KeyID       string    `json:"key_id"`              // Unique key identifier
	CreatedAt   time.Time `json:"created_at"`          // When the key was generated
	RotateAt    time.Time `json:"rotate_at,omitempty"` // Estimated rotation time — current key only; zero for historical keys
	ExpiresAt   time.Time `json:"expires_at,omitempty"` // When the key stops being valid for verification; zero means still current
	KeySizeBits int       `json:"key_size_bits"`       // RSA key size in bits (e.g., 2048)
	Algorithm   string    `json:"algorithm"`           // Signing algorithm — always "RS256"
	IsCurrent   bool      `json:"is_current"`          // True if this is the active signing key
	IsValid     bool      `json:"is_valid"`            // True if the key has not yet expired
}

// JWKS (JSON Web Key Set) is the standard format for publishing public keys,
// typically served at /.well-known/jwks.json for OAuth/OIDC compliance.
type JWKS struct {
	Keys []JWK `json:"keys"` // Array of public keys
}

// JWK (JSON Web Key) represents a single public key in JWKS format.
// All numeric fields are base64url-encoded as per RFC 7517.
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

// Sentinel errors for Manager operations.
var (
	ErrInvalidKeyStore            = errors.New("key store is required")
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
// Returns ErrInvalidKeyStore if KeyStore is nil, ErrInvalidKeySize if KeySize is
// less than 2048 bits, ErrInvalidKeyRotationInterval if KeyRotationInterval is
// negative, or ErrInvalidKeyOverlapDuration if KeyOverlapDuration is negative.
// Applies defaults for zero-value duration and size fields before validation.
func NewManager(config ManagerConfig) (*Manager, error) {
	// ===== STEP 1: Validate Required Fields =====
	if config.KeyStore == nil {
		return nil, ErrInvalidKeyStore
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
		metrics:        config.Metrics,
		stopRotationCh: make(chan struct{}),
	}, nil
}

// Start initializes and starts the Manager, preparing it for key operations.
// It loads existing keys from the KeyStore (if any) or generates a new key pair.
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

	// ===== STEP 3: Try Loading Existing Keys from Store =====
	storedKeys, err := m.config.KeyStore.LoadAll(ctx)
	if err != nil {
		atomic.StoreInt32(&m.state, StateStopped)
		if m.config.Logger != nil {
			m.config.Logger.Error("failed to load keys from store", ctx, "error", err)
		}
		return fmt.Errorf("load keys: %w", err)
	}

	if len(storedKeys) > 0 {
		// ===== STEP 4a: Populate Cache from Stored Keys =====
		m.mu.Lock()
		var mostRecentKeyID string
		var mostRecentTime time.Time
		for _, sk := range storedKeys {
			m.keys[sk.KeyID] = &KeyPair{
				ID:         sk.KeyID,
				PrivateKey: sk.PrivateKey,
				PublicKey:  &sk.PrivateKey.PublicKey,
				CreatedAt:  sk.Metadata.CreatedAt,
				ExpiresAt:  sk.Metadata.ExpiresAt,
				cachedJWK:  m.getJWK(sk.PrivateKey, sk.KeyID),
			}
			if mostRecentKeyID == "" || sk.Metadata.CreatedAt.After(mostRecentTime) {
				mostRecentKeyID = sk.KeyID
				mostRecentTime = sk.Metadata.CreatedAt
			}
		}
		m.currentKeyID = mostRecentKeyID
		keyCount := len(m.keys)
		m.mu.Unlock()

		if m.config.Logger != nil {
			m.config.Logger.Info("loaded existing keys from store", ctx,
				"keyID", m.currentKeyID,
				"keyCount", len(storedKeys))
		}
		if m.metrics != nil {
			m.metrics.SetGauge(metricKeyActiveVersionsCount, float64(keyCount), nil)
		}
	} else {
		// ===== STEP 4b: Generate Initial Key Pair =====
		privateKey, err := rsa.GenerateKey(rand.Reader, m.config.KeySize)
		if err != nil {
			atomic.StoreInt32(&m.state, StateStopped)
			if m.config.Logger != nil {
				m.config.Logger.Error("failed to generate initial key", ctx, "error", err)
			}
			return fmt.Errorf("generate key: %w", err)
		}

		keyID := uuid.New().String()
		now := time.Now()

		m.mu.Lock()
		m.currentKeyID = keyID
		m.keys[keyID] = &KeyPair{
			ID:         keyID,
			PrivateKey: privateKey,
			PublicKey:  &privateKey.PublicKey,
			CreatedAt:  now,
			ExpiresAt:  time.Time{},
			cachedJWK:  m.getJWK(privateKey, keyID),
		}
		keyCount := len(m.keys)
		m.mu.Unlock()

		meta := KeyMetadata{ID: keyID, CreatedAt: now}
		if err := m.config.KeyStore.Save(ctx, keyID, privateKey, meta); err != nil {
			atomic.StoreInt32(&m.state, StateStopped)
			if m.config.Logger != nil {
				m.config.Logger.Error("failed to save initial key", ctx, "error", err)
			}
			return fmt.Errorf("save initial key: %w", err)
		}

		if m.config.Logger != nil {
			m.config.Logger.Info("generated new RSA key pair", ctx,
				"keyID", keyID,
				"keySize", m.config.KeySize)
		}
		if m.metrics != nil {
			m.metrics.SetGauge(metricKeyActiveVersionsCount, float64(keyCount), nil)
		}
	}

	// ===== STEP 5: Start Rotation Scheduler =====
	m.rotationSchedulerActive.Store(true)
	m.rotationWG.Add(1)
	go m.rotationSchedulerLoop(ctx)

	if m.config.Logger != nil {
		m.config.Logger.Info("key manager started", ctx,
			"rotationInterval", m.config.KeyRotationInterval)
	}

	return nil
}

// GetCurrentSigningKey returns the Manager's current private key and its ID.
// Returns ErrManagerNotRunning if the Manager is not running, or ErrKeyNotFound
// if the current key is not in the cache (should not happen in practice).
// The returned key is safe to use for concurrent signing operations.
// Returns the context error if the context is cancelled.
func (m *Manager) GetCurrentSigningKey(ctx context.Context) (*rsa.PrivateKey, string, error) {
	// ===== STEP 1: Check Manager is Running =====
	if !m.IsRunning() {
		if m.metrics != nil {
			m.metrics.IncrementCounter(metricKeySigningOpsTotal, map[string]string{"status": "error", "error_type": "error"})
		}
		return nil, "", ErrManagerNotRunning
	}

	// ===== STEP 2: Context Check =====
	if err := ctx.Err(); err != nil {
		if m.metrics != nil {
			m.metrics.IncrementCounter(metricKeySigningOpsTotal, map[string]string{"status": "cancelled", "error_type": "cancelled"})
		}
		return nil, "", err
	}

	// ===== STEP 3: Acquire Read Lock and Retrieve Key =====
	if m.config.Logger != nil {
		m.config.Logger.Debug("getting current signing key", ctx)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	keyPair, found := m.keys[m.currentKeyID]

	if !found {
		if m.metrics != nil {
			m.metrics.IncrementCounter(metricKeySigningOpsTotal, map[string]string{"status": "error", "error_type": "error"})
		}
		return nil, "", ErrKeyNotFound
	}

	// ===== STEP 4: Return Key and ID =====
	if m.metrics != nil {
		m.metrics.IncrementCounter(metricKeySigningOpsTotal, map[string]string{"status": "success", "error_type": ""})
	}
	return keyPair.PrivateKey, m.currentKeyID, nil
}

// Shutdown gracefully shuts down the Manager, stopping the rotation scheduler and
// releasing resources. It is idempotent — calling it multiple times is safe.
// Returns the context error if the context is cancelled before shutdown completes.
// All background goroutines are waited on with a timeout specified by ctx.
func (m *Manager) Shutdown(ctx context.Context) error {
	// ===== STEP 1: Check Not Already Stopped =====
	if !atomic.CompareAndSwapInt32(&m.state, StateStarted, StateStopped) {
		return nil
	}

	if m.config.Logger != nil {
		m.config.Logger.Info("initiating graceful shutdown", ctx)
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
		return ctx.Err()
	}

	// ===== STEP 4: Recreate Stop Channel for Potential Restart =====
	m.stopRotationCh = make(chan struct{})

	if m.config.Logger != nil {
		m.config.Logger.Info("key manager stopped", ctx)
	}

	return nil
}

// IsRotationSchedulerActive reports whether the background rotation scheduler
// goroutine is currently running. Used for testing and diagnostics.
func (m *Manager) IsRotationSchedulerActive() bool {
	return m.rotationSchedulerActive.Load()
}

// GetPublicKey returns the public key for the given key ID. Checks the in-memory
// cache first, then loads from the KeyStore if not found. Returns ErrInvalidKeyID
// if keyID is empty or whitespace-only, or ErrKeyNotFound if the key does not
// exist or has expired. Uses a double-check locking pattern to cache loaded keys.
// Returns the context error if the context is cancelled.
func (m *Manager) GetPublicKey(ctx context.Context, keyID string) (*rsa.PublicKey, error) {
	status := "error"
	errorType := "error"
	defer func() {
		if m.metrics != nil {
			m.metrics.IncrementCounter(metricKeyValidationOpsTotal, map[string]string{"status": status, "error_type": errorType})
		}
	}()

	// ===== STEP 1: Validate Key ID =====
	keyID = strings.TrimSpace(keyID)
	if len(keyID) == 0 {
		return nil, ErrInvalidKeyID
	}

	// ===== STEP 2: Context Check =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		return nil, err
	}

	// ===== STEP 3: Check Cache First =====
	m.mu.RLock()
	if keyPair, exists := m.keys[keyID]; exists {
		m.mu.RUnlock()
		if m.config.Logger != nil {
			m.config.Logger.Debug("public key cache hit", ctx, "keyID", keyID)
		}
		status = "success"
		errorType = ""
		return keyPair.PublicKey, nil
	}
	m.mu.RUnlock()

	// ===== STEP 4: Load from KeyStore =====
	if m.config.Logger != nil {
		m.config.Logger.Debug("public key not in cache, loading from store", ctx, "keyID", keyID)
	}
	privateKey, meta, err := m.config.KeyStore.LoadKey(ctx, keyID)
	if err != nil {
		if errors.Is(err, ErrKeyStoreKeyNotFound) {
			status = "not_found"
			errorType = "not_found"
			return nil, ErrKeyNotFound
		}
		return nil, err
	}

	// ===== STEP 5: Check Expiration =====
	if !meta.ExpiresAt.IsZero() && time.Now().After(meta.ExpiresAt) {
		status = "not_found"
		errorType = "not_found"
		return nil, ErrKeyNotFound
	}

	// ===== STEP 6: Cache with Double-Check Pattern =====
	m.mu.Lock()
	defer m.mu.Unlock()

	if keyPair, exists := m.keys[keyID]; exists {
		status = "success"
		errorType = ""
		return keyPair.PublicKey, nil
	}

	m.keys[keyID] = &KeyPair{
		ID:        keyID,
		PublicKey: &privateKey.PublicKey,
		CreatedAt: meta.CreatedAt,
		ExpiresAt: meta.ExpiresAt,
	}

	status = "success"
	errorType = ""
	return &privateKey.PublicKey, nil
}

// GetJWKS returns a JSON Web Key Set (JWKS) containing all non-expired public keys.
// Returns ErrManagerNotRunning if the Manager is not running. The returned JWKS
// is suitable for serving at /.well-known/jwks.json for OAuth/OIDC compliance.
func (m *Manager) GetJWKS(ctx context.Context) (*JWKS, error) {
	// ===== STEP 1: Check Manager is Running =====
	if !m.IsRunning() {
		return nil, ErrManagerNotRunning
	}

	// ===== STEP 2: Context Check =====
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if m.config.Logger != nil {
		m.config.Logger.Debug("getting JWKS", ctx)
	}

	// ===== STEP 3: Acquire Read Lock and Collect Keys =====
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]JWK, 0, len(m.keys))
	for _, key := range m.keys {
		if !key.ExpiresAt.IsZero() && time.Now().After(key.ExpiresAt) {
			continue
		}
		keys = append(keys, *key.cachedJWK)
	}

	// ===== STEP 4: Return JWKS =====
	return &JWKS{Keys: keys}, nil
}

// GetKeyInfo returns public metadata for a specific key by ID.
// If keyID is empty, returns metadata for the current signing key.
// Returns ErrManagerNotRunning if the manager is not running.
// Returns ErrKeyNotFound if the specified key does not exist.
// Returns the context error if the context is cancelled.
//
// The returned KeyInfo contains no private key material — safe to expose via
// health check endpoints or admin APIs.
func (m *Manager) GetKeyInfo(ctx context.Context, keyID string) (*KeyInfo, error) {
	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// ===== STEP 2: Check Manager is Running =====
	if !m.IsRunning() {
		return nil, ErrManagerNotRunning
	}

	// ===== STEP 3: Acquire Read Lock =====
	m.mu.RLock()
	defer m.mu.RUnlock()

	// ===== STEP 4: Resolve Key =====
	var keyPair *KeyPair
	if keyID == "" {
		if m.currentKeyID == "" {
			return nil, ErrKeyNotFound
		}
		keyPair = m.keys[m.currentKeyID]
	} else {
		var exists bool
		keyPair, exists = m.keys[keyID]
		if !exists {
			return nil, ErrKeyNotFound
		}
	}

	// ===== STEP 5: Build KeyInfo =====
	isCurrent := keyPair.ID == m.currentKeyID
	isValid := keyPair.ExpiresAt.IsZero() || time.Now().Before(keyPair.ExpiresAt)

	var rotateAt time.Time
	if isCurrent {
		rotateAt = keyPair.CreatedAt.Add(m.config.KeyRotationInterval)
	}

	return &KeyInfo{
		KeyID:       keyPair.ID,
		CreatedAt:   keyPair.CreatedAt,
		RotateAt:    rotateAt,
		ExpiresAt:   keyPair.ExpiresAt,
		KeySizeBits: keyPair.PrivateKey.N.BitLen(),
		Algorithm:   "RS256",
		IsCurrent:   isCurrent,
		IsValid:     isValid,
	}, nil
}

// GetCurrentKeyInfo returns metadata for the current signing key.
// This is a convenience wrapper around GetKeyInfo(ctx, "").
// Returns ErrManagerNotRunning if the manager is not running.
// Returns ErrKeyNotFound if no current key exists.
// Returns the context error if the context is cancelled.
func (m *Manager) GetCurrentKeyInfo(ctx context.Context) (*KeyInfo, error) {
	return m.GetKeyInfo(ctx, "")
}

// RotateKeys rotates the current signing key to a newly generated one, and marks
// the old key to expire after KeyOverlapDuration. This allows old tokens to be
// validated during the transition period. Returns ErrManagerNotRunning if the
// Manager is not running. Returns the context error if the context is cancelled.
func (m *Manager) RotateKeys(ctx context.Context) error {
	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		if m.metrics != nil {
			m.metrics.IncrementCounter(metricKeyRotationsTotal, map[string]string{"status": status, "error_type": errorType})
			m.metrics.RecordDuration(metricKeyOpDuration, time.Since(start), map[string]string{"operation": "rotate"})
		}
	}()

	// ===== STEP 1: Check Context =====
	select {
	case <-ctx.Done():
		status = "cancelled"
		errorType = "cancelled"
		if m.config.Logger != nil {
			m.config.Logger.Warn("key rotation cancelled", ctx)
		}
		return ctx.Err()
	default:
	}

	// ===== STEP 2: Acquire Write Lock =====
	m.mu.Lock()
	defer m.mu.Unlock()

	// ===== STEP 3: Check Manager is Running =====
	if !m.IsRunning() {
		return ErrManagerNotRunning
	}

	// ===== STEP 4: Generate New RSA Key Pair =====
	privateKey, err := rsa.GenerateKey(rand.Reader, m.config.KeySize)
	if err != nil {
		if m.config.Logger != nil {
			m.config.Logger.Error("key rotation failed", ctx, "error", err)
		}
		return fmt.Errorf("generate key: %w", err)
	}

	// ===== STEP 5: Generate Unique Key ID =====
	keyID := uuid.New().String()
	now := time.Now()

	// ===== STEP 6: Save New Key to Store =====
	newMeta := KeyMetadata{ID: keyID, CreatedAt: now}
	if err := m.config.KeyStore.Save(ctx, keyID, privateKey, newMeta); err != nil {
		if m.config.Logger != nil {
			m.config.Logger.Error("key rotation failed: could not save new key", ctx, "error", err)
		}
		return fmt.Errorf("save new key: %w", err)
	}

	// ===== STEP 7: Mark Old Key to Expire =====
	oldKeyID := m.currentKeyID
	if oldKey, exists := m.keys[oldKeyID]; exists {
		oldKey.ExpiresAt = now.Add(m.config.KeyOverlapDuration)

		updatedMeta := KeyMetadata{
			ID:        oldKeyID,
			CreatedAt: oldKey.CreatedAt,
			ExpiresAt: oldKey.ExpiresAt,
		}
		if err := m.config.KeyStore.UpdateMetadata(ctx, oldKeyID, updatedMeta); err != nil {
			// Log but continue — in-memory expiration is sufficient for correctness
			if m.config.Logger != nil {
				m.config.Logger.Warn("failed to persist expiration for old key", ctx,
					"oldKeyID", oldKeyID,
					"error", err)
			}
		} else {
			if m.config.Logger != nil {
				m.config.Logger.Info("old key marked for expiration", ctx,
					"keyID", oldKeyID,
					"expiresAt", oldKey.ExpiresAt)
			}
		}
	}

	// ===== STEP 8: Switch to New Signing Key =====
	m.currentKeyID = keyID
	m.keys[keyID] = &KeyPair{
		ID:         keyID,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		CreatedAt:  now,
		ExpiresAt:  time.Time{},
		cachedJWK:  m.getJWK(privateKey, keyID),
	}

	status = "success"
	errorType = ""
	if m.metrics != nil {
		m.metrics.SetGauge(metricKeyActiveVersionsCount, float64(len(m.keys)), nil)
	}

	if m.config.Logger != nil {
		m.config.Logger.Info("key rotation successful", ctx,
			"newKeyID", keyID,
			"oldKeyID", oldKeyID,
			"duration", time.Since(start))
	}

	return nil
}

// rotationSchedulerLoop implements the background goroutine that automatically rotates
// keys at the configured interval and periodically cleans up expired keys. Runs until
// ctx is cancelled or the Manager is shut down via stopRotationCh.
func (m *Manager) rotationSchedulerLoop(ctx context.Context) {
	m.rotationTicker = time.NewTicker(m.config.KeyRotationInterval)

	cleanupInterval := m.config.KeyOverlapDuration / 4
	if cleanupInterval > 1*time.Minute {
		cleanupInterval = 1 * time.Minute
	}
	if cleanupInterval < 10*time.Millisecond {
		cleanupInterval = 10 * time.Millisecond
	}

	cleanupTicker := time.NewTicker(cleanupInterval)

	m.rotationSchedulerActive.Store(true)

	defer m.rotationWG.Done()
	defer m.rotationSchedulerActive.Store(false)
	defer m.rotationTicker.Stop()
	defer cleanupTicker.Stop()

	for {
		select {
		case <-m.rotationTicker.C:
			if m.config.Logger != nil {
				m.config.Logger.Info("automatic rotation triggered", ctx)
			}
			if err := m.RotateKeys(ctx); err != nil {
				if m.config.Logger != nil {
					m.config.Logger.Error("rotation failed", ctx, "error", err)
				}
			}
			m.cleanupExpiredKeys(ctx)

		case <-cleanupTicker.C:
			if m.config.Logger != nil {
				m.config.Logger.Debug("rotation cleanup tick fired", ctx)
			}
			m.cleanupExpiredKeys(ctx)

		case <-ctx.Done():
			return
		case <-m.stopRotationCh:
			return
		}
	}
}

// cleanupExpiredKeys removes expired keys from the in-memory cache and from the
// KeyStore. It is called periodically by the rotation scheduler and immediately
// after each rotation. The current signing key is never removed. Removals are
// logged at Info level; a no-op sweep is logged at Debug level.
func (m *Manager) cleanupExpiredKeys(ctx context.Context) {
	// ===== STEP 1: Check Manager is Running =====
	if !m.IsRunning() {
		if m.config.Logger != nil {
			m.config.Logger.Warn("cleanup aborted: manager is not running", ctx)
		}
		return
	}

	// ===== STEP 2: Context Check =====
	if err := ctx.Err(); err != nil {
		if m.config.Logger != nil {
			m.config.Logger.Warn("cleanup aborted: context cancelled", ctx, "reason", err)
		}
		return
	}

	// ===== STEP 3: Acquire Write Lock =====
	m.mu.Lock()
	defer m.mu.Unlock()

	// ===== STEP 4: Sweep Expired Keys =====
	now := time.Now()
	count := 0
	deletedKeys := []string{}

	for keyID, key := range m.keys {
		if keyID == m.currentKeyID {
			continue
		}
		if !key.ExpiresAt.IsZero() && now.After(key.ExpiresAt) {
			delete(m.keys, keyID)
			if err := m.config.KeyStore.Delete(ctx, keyID); err != nil {
				if m.config.Logger != nil {
					m.config.Logger.Error("failed to delete expired key from store", ctx,
						"keyID", keyID,
						"error", err)
				}
			} else {
				count++
				deletedKeys = append(deletedKeys, keyID)
			}
		}
	}

	// ===== STEP 5: Log Results =====
	if m.config.Logger != nil {
		if count == 0 {
			m.config.Logger.Debug("no expired keys found during cleanup", ctx)
		} else {
			m.config.Logger.Info("expired key cleanup executed", ctx, "deletedCount", count)
			for _, key := range deletedKeys {
				m.config.Logger.Info("deleted expired key", ctx, "keyID", key)
			}
		}
	}

	// ===== STEP 5: Update Active Keys Gauge (only when keys were removed) =====
	if count > 0 && m.metrics != nil {
		m.metrics.SetGauge(metricKeyActiveVersionsCount, float64(len(m.keys)), nil)
	}
}

func base64urlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

// getJWK converts an RSA private key and its ID into a JWK (JSON Web Key) format
// suitable for JWKS publication. All numeric values are base64url-encoded as per
// RFC 7517.
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
