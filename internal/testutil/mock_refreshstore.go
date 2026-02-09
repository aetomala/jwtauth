package testutil

import (
	"sync"
	"time"
)

// MockRefreshStore is a mock implementation of the RefreshTokenStore interface for testing.
// It provides controllable behavior for testing components that depend on refresh token storage.
//
// Thread-safe: Can be used with concurrent tests.
//
// Example Usage:
//
//	mockStore := testutil.NewMockRefreshStore()
//	mockStore.SetStoreError(errors.New("storage failure"))
//
//	service := tokens.NewService(tokens.Config{
//	    RefreshStore: mockStore,
//	})
//
//	// Verify storage was attempted
//	Expect(mockStore.StoreCalls).To(Equal(1))
type MockRefreshStore struct {
	storeError    error
	retrieveError error
	revokeError   error
	cleanupError  error
	tokens        map[string]*MockRefreshToken
	StoreArgs     []StoreCallArgs
	RevokeArgs    []string
	RetrieveArgs  []string
	StoreCalls    int
	CleanupCalls  int
	RevokeCalls   int
	RetrieveCalls int
	mu            sync.RWMutex
}

// MockRefreshToken represents a stored refresh token.
type MockRefreshToken struct {
	ExpiresAt time.Time
	CreatedAt time.Time
	Metadata  map[string]interface{}
	TokenID   string
	UserID    string
	Revoked   bool
}

// StoreCallArgs captures arguments from Store calls.
type StoreCallArgs struct {
	ExpiresAt time.Time
	Metadata  map[string]interface{}
	TokenID   string
	UserID    string
}

// NewMockRefreshStore creates a new MockRefreshStore.
func NewMockRefreshStore() *MockRefreshStore {
	return &MockRefreshStore{
		tokens: make(map[string]*MockRefreshToken),
	}
}

// Store saves a refresh token.
// Tracks call count and arguments, returns configured error if set.
func (m *MockRefreshStore) Store(tokenID, userID string, expiresAt time.Time, metadata map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.StoreCalls++
	m.StoreArgs = append(m.StoreArgs, StoreCallArgs{
		TokenID:   tokenID,
		UserID:    userID,
		ExpiresAt: expiresAt,
		Metadata:  metadata,
	})

	if m.storeError != nil {
		return m.storeError
	}

	m.tokens[tokenID] = &MockRefreshToken{
		TokenID:   tokenID,
		UserID:    userID,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
		Revoked:   false,
		Metadata:  metadata,
	}

	return nil
}

// Retrieve fetches a refresh token by ID.
// Tracks call count and arguments, returns configured error if set.
func (m *MockRefreshStore) Retrieve(tokenID string) (*MockRefreshToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.RetrieveCalls++
	m.RetrieveArgs = append(m.RetrieveArgs, tokenID)

	if m.retrieveError != nil {
		return nil, m.retrieveError
	}

	token, exists := m.tokens[tokenID]
	if !exists {
		return nil, ErrMockTokenNotFound
	}

	// Check if revoked
	if token.Revoked {
		return nil, ErrMockTokenRevoked
	}

	// Check if expired
	if time.Now().After(token.ExpiresAt) {
		return nil, ErrMockTokenExpired
	}

	return token, nil
}

// Revoke marks a refresh token as revoked.
// Tracks call count and arguments, returns configured error if set.
func (m *MockRefreshStore) Revoke(tokenID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.RevokeCalls++
	m.RevokeArgs = append(m.RevokeArgs, tokenID)

	if m.revokeError != nil {
		return m.revokeError
	}

	token, exists := m.tokens[tokenID]
	if !exists {
		return ErrMockTokenNotFound
	}

	token.Revoked = true
	return nil
}

// RevokeAllForUser revokes all tokens for a specific user.
func (m *MockRefreshStore) RevokeAllForUser(userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.revokeError != nil {
		return m.revokeError
	}

	count := 0
	for _, token := range m.tokens {
		if token.UserID == userID {
			token.Revoked = true
			count++
		}
	}

	if count == 0 {
		return ErrMockNoTokensForUser
	}

	return nil
}

// Cleanup removes expired tokens.
// Tracks call count and returns configured error if set.
func (m *MockRefreshStore) Cleanup() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.CleanupCalls++

	if m.cleanupError != nil {
		return 0, m.cleanupError
	}

	now := time.Now()
	deleted := 0

	for tokenID, token := range m.tokens {
		if now.After(token.ExpiresAt) || token.Revoked {
			delete(m.tokens, tokenID)
			deleted++
		}
	}

	return deleted, nil
}

// ===== Behavior Control Methods =====

// SetStoreError configures Store to return an error.
func (m *MockRefreshStore) SetStoreError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.storeError = err
}

// SetRetrieveError configures Retrieve to return an error.
func (m *MockRefreshStore) SetRetrieveError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.retrieveError = err
}

// SetRevokeError configures Revoke to return an error.
func (m *MockRefreshStore) SetRevokeError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revokeError = err
}

// SetCleanupError configures Cleanup to return an error.
func (m *MockRefreshStore) SetCleanupError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanupError = err
}

// ===== Query Methods =====

// GetCallCount returns the number of times a specific method was called.
func (m *MockRefreshStore) GetCallCount(method string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	switch method {
	case "Store":
		return m.StoreCalls
	case "Retrieve":
		return m.RetrieveCalls
	case "Revoke":
		return m.RevokeCalls
	case "Cleanup":
		return m.CleanupCalls
	default:
		return 0
	}
}

// WasTokenStored checks if a specific token ID was stored.
func (m *MockRefreshStore) WasTokenStored(tokenID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, args := range m.StoreArgs {
		if args.TokenID == tokenID {
			return true
		}
	}
	return false
}

// WasTokenRetrieved checks if a specific token ID was retrieved.
func (m *MockRefreshStore) WasTokenRetrieved(tokenID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, arg := range m.RetrieveArgs {
		if arg == tokenID {
			return true
		}
	}
	return false
}

// WasTokenRevoked checks if a specific token ID was revoked.
func (m *MockRefreshStore) WasTokenRevoked(tokenID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, arg := range m.RevokeArgs {
		if arg == tokenID {
			return true
		}
	}
	return false
}

// GetTokenCount returns the number of tokens in storage.
func (m *MockRefreshStore) GetTokenCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.tokens)
}

// GetActiveTokenCount returns the number of active (non-revoked, non-expired) tokens.
func (m *MockRefreshStore) GetActiveTokenCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now()
	count := 0

	for _, token := range m.tokens {
		if !token.Revoked && now.Before(token.ExpiresAt) {
			count++
		}
	}

	return count
}

// GetTokensForUser returns all token IDs for a specific user.
func (m *MockRefreshStore) GetTokensForUser(userID string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var tokenIDs []string
	for _, token := range m.tokens {
		if token.UserID == userID {
			tokenIDs = append(tokenIDs, token.TokenID)
		}
	}

	return tokenIDs
}

// HasToken checks if a token exists in storage (regardless of revoked status).
func (m *MockRefreshStore) HasToken(tokenID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	_, exists := m.tokens[tokenID]
	return exists
}

// IsTokenRevoked checks if a token is marked as revoked.
func (m *MockRefreshStore) IsTokenRevoked(tokenID string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	token, exists := m.tokens[tokenID]
	if !exists {
		return false
	}

	return token.Revoked
}

// ===== Helper Methods for Test Setup =====

// AddToken directly adds a token to storage (for test setup).
func (m *MockRefreshStore) AddToken(token *MockRefreshToken) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.tokens[token.TokenID] = token
}

// AddExpiredToken adds an expired token (for testing expiration logic).
func (m *MockRefreshStore) AddExpiredToken(tokenID, userID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.tokens[tokenID] = &MockRefreshToken{
		TokenID:   tokenID,
		UserID:    userID,
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Already expired
		CreatedAt: time.Now().Add(-2 * time.Hour),
		Revoked:   false,
	}
}

// AddRevokedToken adds a revoked token (for testing revocation logic).
func (m *MockRefreshStore) AddRevokedToken(tokenID, userID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.tokens[tokenID] = &MockRefreshToken{
		TokenID:   tokenID,
		UserID:    userID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
		Revoked:   true, // Pre-revoked
	}
}

// ===== Reset Methods =====

// Reset resets all call counters, arguments, and clears storage.
func (m *MockRefreshStore) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.StoreCalls = 0
	m.RetrieveCalls = 0
	m.RevokeCalls = 0
	m.CleanupCalls = 0

	m.StoreArgs = nil
	m.RetrieveArgs = nil
	m.RevokeArgs = nil

	m.tokens = make(map[string]*MockRefreshToken)
}

// ResetCallCounters resets call counters but keeps storage intact.
func (m *MockRefreshStore) ResetCallCounters() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.StoreCalls = 0
	m.RetrieveCalls = 0
	m.RevokeCalls = 0
	m.CleanupCalls = 0

	m.StoreArgs = nil
	m.RetrieveArgs = nil
	m.RevokeArgs = nil
}

// ResetErrors resets all configured errors.
func (m *MockRefreshStore) ResetErrors() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.storeError = nil
	m.retrieveError = nil
	m.revokeError = nil
	m.cleanupError = nil
}

// ClearStorage removes all tokens from storage.
func (m *MockRefreshStore) ClearStorage() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.tokens = make(map[string]*MockRefreshToken)
}

// ===== Mock-Specific Errors =====

var (
	// ErrMockTokenNotFound is returned when a requested token is not in storage.
	ErrMockTokenNotFound = NewMockError("token not found in mock storage")

	// ErrMockTokenRevoked is returned when attempting to retrieve a revoked token.
	ErrMockTokenRevoked = NewMockError("token has been revoked")

	// ErrMockTokenExpired is returned when attempting to retrieve an expired token.
	ErrMockTokenExpired = NewMockError("token has expired")

	// ErrMockNoTokensForUser is returned when revoking all tokens for a user with no tokens.
	ErrMockNoTokensForUser = NewMockError("no tokens found for user")
)
