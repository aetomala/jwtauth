// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package keys

import (
	"context"
	"crypto/rsa"
)

// Generate mock from this interface using mockgen
//go:generate mockgen -source=interface.go -destination=../../internal/testutil/mock_keys.go -package=testutil -mock_names=KeyManager=MockKeyManager

// KeyManager is a thread-safe interface for JWT key management operations,
// suitable for use in long-running services with automatic key rotation. All
// methods are safe for concurrent use.
type KeyManager interface {
	// GetCurrentSigningKey returns the current private key and its ID for JWT signing.
	// Returns ErrManagerNotRunning if the manager has not been started.
	// Returns the context error if the context is cancelled.
	GetCurrentSigningKey(ctx context.Context) (*rsa.PrivateKey, string, error)

	// GetPublicKey returns the public key for the given key ID. During key rotation,
	// multiple keys may be valid concurrently — this method supports retrieving both
	// current and recently-rotated keys. Returns ErrInvalidKeyID if keyID is empty
	// or whitespace-only, ErrKeyNotFound if the key does not exist or has expired.
	// Returns the context error if the context is cancelled.
	GetPublicKey(ctx context.Context, keyID string) (*rsa.PublicKey, error)

	// GetKeyInfo returns public metadata for a specific key by ID — no private key
	// material is included. If keyID is empty, returns metadata for the current
	// signing key. Returns ErrManagerNotRunning if the manager is not running.
	// Returns ErrKeyNotFound if the specified key does not exist.
	// Returns the context error if the context is cancelled.
	GetKeyInfo(ctx context.Context, keyID string) (*KeyInfo, error)

	// GetCurrentKeyInfo returns metadata for the current signing key.
	// This is a convenience wrapper around GetKeyInfo(ctx, "").
	// Returns ErrManagerNotRunning if the manager is not running.
	// Returns ErrKeyNotFound if no current key exists.
	// Returns the context error if the context is cancelled.
	GetCurrentKeyInfo(ctx context.Context) (*KeyInfo, error)

	// GetAllKeyInfo returns metadata for all keys currently held in the manager's
	// in-memory cache — the active signing key plus any keys still in their overlap
	// window. Order is unspecified. Returns an empty slice (not an error) when no
	// keys are loaded. Returns ErrManagerNotRunning if the manager is not running.
	// Returns the context error if the context is cancelled. No private key material
	// is included in the result.
	GetAllKeyInfo(ctx context.Context) ([]KeyInfo, error)

	// GetJWKS returns the JSON Web Key Set.
	// Contains all currently valid public keys for token verification.
	//
	// This is typically exposed at a /.well-known/jwks.json endpoint.
	//
	// Returns:
	//   - jwks: Set of public keys in JWKS format
	//   - error: If JWKS generation fails
	GetJWKS(ctx context.Context) (*JWKS, error)

	// RotateKeys generates a new signing key and marks the old key for expiration.
	//
	// Process:
	//   1. Generate new RSA key pair
	//   2. Mark old key with expiration time (overlap period)
	//   3. Make new key the current signing key
	//   4. Persist both keys to disk
	//
	// After rotation, both keys are valid during the overlap period.
	// This allows tokens signed with the old key to remain valid briefly.
	//
	// Args:
	//   - ctx: Context for cancellation
	//
	// Returns:
	//   - error: If rotation fails (old key remains current)
	RotateKeys(ctx context.Context) error

	// Start initializes the key manager and starts background processes.
	//
	// Operations:
	//   - Load existing keys from disk OR generate initial key
	//   - Start automatic rotation scheduler (if configured)
	//   - Start expired key cleanup ticker
	//
	// This must be called before using other methods.
	//
	// Args:
	//   - ctx: Context for initialization
	//
	// Returns:
	//   - error: If initialization fails
	Start(ctx context.Context) error

	// Shutdown gracefully stops the key manager.
	//
	// Operations:
	//   - Stop rotation scheduler
	//   - Stop cleanup ticker
	//   - Wait for in-progress operations (respects context timeout)
	//   - Persist final state to disk
	//
	// Args:
	//   - ctx: Context with timeout for graceful shutdown
	//
	// Returns:
	//   - error: If shutdown times out or cleanup fails
	Shutdown(ctx context.Context) error

	// IsRunning returns whether the key manager is currently running.
	//
	// Returns:
	//   - bool: true if Start() was called and Shutdown() has not completed
	IsRunning() bool
}

// Ensure Manager implements KeyManager at compile time.
// If Manager doesn't satisfy the interface, this will cause a compile error.
var _ KeyManager = (*Manager)(nil)
