package storage

import (
	"time"
)

// Generate mock from this interface using mockgen
//go:generate mockgen -source=interface.go -destination=../../internal/testutil/mock_refreshstore.go -package=testutil -mock_names=RefreshStore=MockRefreshStore

// RefreshStore defines the interface for refresh token storage operations.
//
// This interface ensures:
//   - Compile-time verification that implementations are complete
//   - Clear contract for token persistence
//   - Easy mocking for testing
//   - Automatic mock generation via mockgen
//
// Implementations might include:
//   - RedisStore: Redis-backed storage
//   - PostgresStore: PostgreSQL-backed storage
//   - MemoryStore: In-memory storage (testing only)
//   - MockRefreshStore (testutil): Auto-generated testing implementation
type RefreshStore interface {
	// Store saves a refresh token with its metadata.
	//
	// The token should be stored with:
	//   - Expiration time (for TTL/cleanup)
	//   - User ID (for revocation by user)
	//   - Metadata (optional, for audit/tracking)
	//
	// Args:
	//   - tokenID: Unique identifier for the token
	//   - userID: User who owns the token
	//   - expiresAt: When the token expires
	//   - metadata: Optional metadata (IP, user agent, etc.)
	//
	// Returns:
	//   - error: If storage fails
	Store(tokenID, userID string, expiresAt time.Time, metadata map[string]interface{}) error

	// Retrieve fetches a refresh token by ID.
	//
	// Should return error if:
	//   - Token doesn't exist
	//   - Token has been revoked
	//   - Token has expired
	//
	// Args:
	//   - tokenID: The token identifier to retrieve
	//
	// Returns:
	//   - token: The stored token data
	//   - error: If not found, revoked, or expired
	Retrieve(tokenID string) (*RefreshToken, error)

	// Revoke marks a refresh token as revoked.
	//
	// After revocation:
	//   - Retrieve should return error
	//   - Token cannot be used to refresh access tokens
	//
	// Args:
	//   - tokenID: The token to revoke
	//
	// Returns:
	//   - error: If revocation fails
	Revoke(tokenID string) error

	// RevokeAllForUser revokes all tokens for a specific user.
	//
	// Use cases:
	//   - User logout from all devices
	//   - Password change
	//   - Account compromise
	//
	// Args:
	//   - userID: User whose tokens should be revoked
	//
	// Returns:
	//   - error: If revocation fails
	RevokeAllForUser(userID string) error

	// Cleanup removes expired tokens.
	//
	// This should be called periodically to:
	//   - Free storage space
	//   - Improve query performance
	//   - Maintain security (remove old tokens)
	//
	// Returns:
	//   - count: Number of tokens deleted
	//   - error: If cleanup fails
	Cleanup() (int, error)
}

// RefreshToken represents a stored refresh token.
type RefreshToken struct {
	TokenID   string
	UserID    string
	ExpiresAt time.Time
	CreatedAt time.Time
	Revoked   bool
	Metadata  map[string]interface{}
}
