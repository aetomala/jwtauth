package keymanager

import (
	"context"
	"crypto/rsa"
)

// KeyManager defines the interface for JWT key management operations.
//
// This interface ensures:
//   - Compile-time verification that implementations are complete
//   - Clear contract for all key management operations
//   - Easy mocking for testing dependent components
//   - Automatic mock generation via mockgen
//
// Implementations:
//   - Manager: Production implementation with file persistence and automatic rotation
//   - MockKeyManager (testutil): Auto-generated testing implementation
type KeyManager interface {
	// GetCurrentSigningKey returns the current private key for signing tokens.
	// Returns the private key and its unique identifier.
	//
	// This is called when issuing new tokens.
	//
	// Returns:
	//   - privateKey: RSA private key for signing
	//   - keyID: Unique identifier for this key (used in JWT header)
	//   - error: If key retrieval fails
	GetCurrentSigningKey() (*rsa.PrivateKey, string, error)

	// GetPublicKey returns the public key for the given key ID.
	// This is used to verify tokens that were signed with a specific key.
	//
	// During key rotation, multiple keys may be valid (overlap period).
	// This method must support retrieving both current and recently-expired keys.
	//
	// Args:
	//   - keyID: The key identifier from the JWT header
	//
	// Returns:
	//   - publicKey: RSA public key for verification
	//   - error: If key not found or retrieval fails
	GetPublicKey(keyID string) (*rsa.PublicKey, error)

	// GetJWKS returns the JSON Web Key Set.
	// Contains all currently valid public keys for token verification.
	//
	// This is typically exposed at a /.well-known/jwks.json endpoint.
	//
	// Returns:
	//   - jwks: Set of public keys in JWKS format
	//   - error: If JWKS generation fails
	GetJWKS() (*JWKS, error)

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
