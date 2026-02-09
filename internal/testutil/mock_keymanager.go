package testutil

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sync"

	"github.com/google/uuid"
)

// MockKeyManager is a mock implementation of the KeyManager interface for testing.
// It provides controllable behavior for testing components that depend on KeyManager.
//
// Thread-safe: Can be used with concurrent tests.
//
// Example Usage:
//
//	mockKM := testutil.NewMockKeyManager()
//	mockKM.SetCurrentKey(privateKey, "test-key-id")
//
//	tokenService := tokens.NewService(tokens.Config{
//	    KeyManager: mockKM,
//	})
//
//	// Verify key was retrieved
//	Expect(mockKM.GetCurrentSigningKeyCalls).To(Equal(1))
type MockKeyManager struct {
	getCurrentSigningKeyError error
	rotateKeysError           error
	getJWKSError              error
	getPublicKeyError         error
	jwks                      *MockJWKS
	publicKeys                map[string]*rsa.PublicKey
	currentPrivateKey         *rsa.PrivateKey
	currentKeyID              string
	GetPublicKeyArgs          []string
	GetCurrentSigningKeyCalls int
	GetPublicKeyCalls         int
	GetJWKSCalls              int
	RotateKeysCalls           int
	StartCalls                int
	ShutdownCalls             int
	mu                        sync.RWMutex
	isRunning                 bool
}

// MockJWKS represents a mock JWKS response
type MockJWKS struct {
	Keys []MockJWK
}

// MockJWK represents a mock JWK
type MockJWK struct {
	KeyID     string
	KeyType   string
	Algorithm string
	Use       string
	N         string
	E         string
}

// NewMockKeyManager creates a new MockKeyManager with a default key pair.
func NewMockKeyManager() *MockKeyManager {
	// Generate a default key pair for convenience
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("failed to generate mock key: %v", err))
	}
	keyID := uuid.New().String()

	mock := &MockKeyManager{
		currentPrivateKey: privateKey,
		currentKeyID:      keyID,
		publicKeys: map[string]*rsa.PublicKey{
			keyID: &privateKey.PublicKey,
		},
		jwks: &MockJWKS{
			Keys: []MockJWK{
				{
					KeyID:     keyID,
					KeyType:   "RSA",
					Algorithm: "RS256",
					Use:       "sig",
					N:         "mock-n",
					E:         "mock-e",
				},
			},
		},
		isRunning: true,
	}

	return mock
}

// GetCurrentSigningKey returns the current private key and key ID.
// Tracks call count and returns configured error if set.
func (m *MockKeyManager) GetCurrentSigningKey() (*rsa.PrivateKey, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.GetCurrentSigningKeyCalls++

	if m.getCurrentSigningKeyError != nil {
		return nil, "", m.getCurrentSigningKeyError
	}

	return m.currentPrivateKey, m.currentKeyID, nil
}

// GetPublicKey returns the public key for the given key ID.
// Tracks call count and arguments, returns configured error if set.
func (m *MockKeyManager) GetPublicKey(keyID string) (*rsa.PublicKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.GetPublicKeyCalls++
	m.GetPublicKeyArgs = append(m.GetPublicKeyArgs, keyID)

	if m.getPublicKeyError != nil {
		return nil, m.getPublicKeyError
	}

	publicKey, exists := m.publicKeys[keyID]
	if !exists {
		return nil, ErrMockKeyNotFound
	}

	return publicKey, nil
}

// GetJWKS returns the JWKS (JSON Web Key Set).
// Tracks call count and returns configured error if set.
func (m *MockKeyManager) GetJWKS() (*MockJWKS, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.GetJWKSCalls++

	if m.getJWKSError != nil {
		return nil, m.getJWKSError
	}

	return m.jwks, nil
}

// RotateKeys simulates key rotation.
// Tracks call count and returns configured error if set.
func (m *MockKeyManager) RotateKeys() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.RotateKeysCalls++

	if m.rotateKeysError != nil {
		return m.rotateKeysError
	}

	// Generate new key
	newPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate key for rotation: %w", err)
	}
	newKeyID := uuid.New().String()

	// Update current key
	oldKeyID := m.currentKeyID
	m.currentPrivateKey = newPrivateKey
	m.currentKeyID = newKeyID

	// Add new public key
	m.publicKeys[newKeyID] = &newPrivateKey.PublicKey

	// Update JWKS
	m.jwks.Keys = append(m.jwks.Keys, MockJWK{
		KeyID:     newKeyID,
		KeyType:   "RSA",
		Algorithm: "RS256",
		Use:       "sig",
		N:         "mock-n-" + newKeyID,
		E:         "mock-e",
	})

	// Keep old key available for overlap period (in real system)
	// Here we just keep it in publicKeys map
	_ = oldKeyID

	return nil
}

// Start simulates starting the key manager.
func (m *MockKeyManager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.StartCalls++
	m.isRunning = true
	return nil
}

// Shutdown simulates shutting down the key manager.
func (m *MockKeyManager) Shutdown() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.ShutdownCalls++
	m.isRunning = false
	return nil
}

// IsRunning returns whether the mock key manager is running.
func (m *MockKeyManager) IsRunning() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isRunning
}

// ===== Behavior Control Methods =====

// SetCurrentKey sets the current signing key for the mock.
func (m *MockKeyManager) SetCurrentKey(privateKey *rsa.PrivateKey, keyID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.currentPrivateKey = privateKey
	m.currentKeyID = keyID
	m.publicKeys[keyID] = &privateKey.PublicKey
}

// AddPublicKey adds a public key to the mock's key set.
func (m *MockKeyManager) AddPublicKey(keyID string, publicKey *rsa.PublicKey) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.publicKeys[keyID] = publicKey
}

// RemovePublicKey removes a public key from the mock's key set.
func (m *MockKeyManager) RemovePublicKey(keyID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.publicKeys, keyID)
}

// SetGetCurrentSigningKeyError configures GetCurrentSigningKey to return an error.
func (m *MockKeyManager) SetGetCurrentSigningKeyError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.getCurrentSigningKeyError = err
}

// SetGetPublicKeyError configures GetPublicKey to return an error.
func (m *MockKeyManager) SetGetPublicKeyError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.getPublicKeyError = err
}

// SetGetJWKSError configures GetJWKS to return an error.
func (m *MockKeyManager) SetGetJWKSError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.getJWKSError = err
}

// SetRotateKeysError configures RotateKeys to return an error.
func (m *MockKeyManager) SetRotateKeysError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.rotateKeysError = err
}

// ===== Query Methods =====

// GetCallCount returns the number of times a specific method was called.
func (m *MockKeyManager) GetCallCount(method string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	switch method {
	case "GetCurrentSigningKey":
		return m.GetCurrentSigningKeyCalls
	case "GetPublicKey":
		return m.GetPublicKeyCalls
	case "GetJWKS":
		return m.GetJWKSCalls
	case "RotateKeys":
		return m.RotateKeysCalls
	case "Start":
		return m.StartCalls
	case "Shutdown":
		return m.ShutdownCalls
	default:
		return 0
	}
}

// WasPublicKeyRequested checks if a specific key ID was requested.
func (m *MockKeyManager) WasPublicKeyRequested(keyID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, arg := range m.GetPublicKeyArgs {
		if arg == keyID {
			return true
		}
	}
	return false
}

// GetCurrentKeyID returns the current key ID.
func (m *MockKeyManager) GetCurrentKeyID() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.currentKeyID
}

// GetPublicKeyCount returns the number of public keys in the mock.
func (m *MockKeyManager) GetPublicKeyCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.publicKeys)
}

// ===== Reset Methods =====

// Reset resets all call counters and arguments.
func (m *MockKeyManager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.GetCurrentSigningKeyCalls = 0
	m.GetPublicKeyCalls = 0
	m.GetJWKSCalls = 0
	m.RotateKeysCalls = 0
	m.StartCalls = 0
	m.ShutdownCalls = 0
	m.GetPublicKeyArgs = nil
}

// ResetErrors resets all configured errors.
func (m *MockKeyManager) ResetErrors() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.getCurrentSigningKeyError = nil
	m.getPublicKeyError = nil
	m.getJWKSError = nil
	m.rotateKeysError = nil
}

// ===== Mock-Specific Errors =====

var (
	// ErrMockKeyNotFound is returned when a requested key is not in the mock.
	ErrMockKeyNotFound = NewMockError("key not found in mock")

	// ErrMockKeyManagerStopped is returned when operations are attempted on a stopped mock.
	ErrMockKeyManagerStopped = NewMockError("mock key manager is stopped")
)
