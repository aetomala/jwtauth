package storage

import (
	"context"
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
	//   - ctx: Request context for cancellation and deadline propagation
	//   - tokenID: Unique identifier for the token
	//   - userID: User who owns the token
	//   - expiresAt: When the token expires
	//   - metadata: Optional metadata (IP, user agent, etc.)
	//
	// Returns:
	//   - error: If storage fails
	Store(ctx context.Context, tokenID, userID string, expiresAt time.Time, metadata map[string]interface{}) error

	// Retrieve fetches a refresh token by ID.
	//
	// Should return error if:
	//   - Token doesn't exist
	//   - Token has been revoked
	//   - Token has expired
	//
	// Args:
	//   - ctx: Request context for cancellation and deadline propagation
	//   - tokenID: The token identifier to retrieve
	//
	// Returns:
	//   - token: The stored token data
	//   - error: If not found, revoked, or expired
	Retrieve(ctx context.Context, tokenID string) (*RefreshToken, error)

	// Revoke marks a refresh token as revoked.
	//
	// After revocation:
	//   - Retrieve should return error
	//   - Token cannot be used to refresh access tokens
	//
	// Args:
	//   - ctx: Request context for cancellation and deadline propagation
	//   - tokenID: The token to revoke
	//
	// Returns:
	//   - error: If revocation fails
	Revoke(ctx context.Context, tokenID string) error

	// RevokeAllForUser revokes all tokens for a specific user.
	//
	// Use cases:
	//   - User logout from all devices
	//   - Password change
	//   - Account compromise
	//
	// Args:
	//   - ctx: Request context for cancellation and deadline propagation
	//   - userID: User whose tokens should be revoked
	//
	// Returns:
	//   - error: If revocation fails
	RevokeAllForUser(ctx context.Context, userID string) error

	// Cleanup removes expired tokens.
	//
	// This should be called periodically to:
	//   - Free storage space
	//   - Improve query performance
	//   - Maintain security (remove old tokens)
	//
	// Args:
	//   - ctx: Request context for cancellation and deadline propagation
	//
	// Returns:
	//   - count: Number of tokens deleted
	//   - error: If cleanup fails
	Cleanup(ctx context.Context) (int, error)

	// ListTokens returns a page of refresh tokens starting from cursor. Pass an
	// empty string for cursor to begin from the start. Returns the next cursor
	// and a nil error on success. Returns an empty next cursor when iteration is
	// exhausted. Count is a hint — actual page size may vary.
	//
	// All tokens are returned regardless of revocation or expiry status — the
	// caller is responsible for filtering. Note: Redis TTL means truly expired
	// tokens may already be absent from the Redis store.
	//
	// Cursor semantics are best-effort: tokens inserted or deleted between pages
	// may appear, be skipped, or duplicated — the same guarantee Redis SCAN
	// provides. Returns the context error if the context is cancelled.
	ListTokens(ctx context.Context, cursor string, count int) ([]*RefreshToken, string, error)

	// ListTokensForUser returns a page of refresh tokens belonging to userID
	// starting from cursor. Pass an empty string for cursor to begin from the
	// start. Returns the next cursor and a nil error on success. Returns an
	// empty next cursor when iteration is exhausted. Count is a hint — actual
	// page size may vary.
	//
	// All tokens are returned regardless of revocation or expiry status — the
	// caller is responsible for filtering. Cursor semantics are best-effort and
	// share the same guarantees as ListTokens. Returns ErrInvalidUserID if
	// userID is empty. Returns the context error if the context is cancelled.
	ListTokensForUser(ctx context.Context, userID string, cursor string, count int) ([]*RefreshToken, string, error)

	// Namespace returns the namespace this store is operating in. For Redis-backed
	// stores this matches the configured KeyPrefix. Implementations that do not
	// support namespacing return empty string.
	Namespace() string
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
