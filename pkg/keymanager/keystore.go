package keymanager

import (
	"context"
	"crypto/rsa"
	"errors"
)

//go:generate mockgen -source=keystore.go -destination=../../internal/testutil/mock_keystore.go -package=testutil -mock_names=KeyStore=MockKeyStore

// StoredKey is the value returned by KeyStore.LoadAll. It carries both the private
// key and its associated metadata in a single unit so callers do not need to make
// separate calls to reconstruct a key pair.
type StoredKey struct {
	KeyID      string
	PrivateKey *rsa.PrivateKey
	Metadata   KeyMetadata
}

// KeyStore defines the persistence contract for RSA key pairs managed by Manager.
// Implementations store private keys and their metadata and must be safe for
// concurrent use.
//
// DiskKeyStore is the reference implementation. Alternative backends (e.g. Redis)
// can be provided to support distributed deployments. All methods are safe for
// concurrent use.
type KeyStore interface {
	// LoadAll returns every valid (non-expired) persisted key. It is called once
	// at startup to warm the Manager's in-memory cache. Returns an empty slice
	// when no keys are found — this is not an error.
	LoadAll(ctx context.Context) ([]*StoredKey, error)

	// Save persists a newly generated key pair and its metadata. The caller is
	// responsible for populating meta.ID and meta.CreatedAt before calling.
	// Returns the context error if the context is cancelled.
	Save(ctx context.Context, keyID string, privateKey *rsa.PrivateKey, meta KeyMetadata) error

	// UpdateMetadata overwrites the persisted metadata for an existing key. Used
	// during rotation to set ExpiresAt on the outgoing signing key.
	// Returns ErrKeyStoreKeyNotFound if keyID does not exist.
	UpdateMetadata(ctx context.Context, keyID string, meta KeyMetadata) error

	// LoadKey fetches the private key and metadata for the given key ID. Called
	// by Manager.GetPublicKey on a cache miss.
	// Returns ErrKeyStoreKeyNotFound if the key does not exist.
	// Returns ErrKeyStoreInvalidKeyID if keyID is empty or whitespace.
	LoadKey(ctx context.Context, keyID string) (*rsa.PrivateKey, *KeyMetadata, error)

	// Delete removes the key identified by keyID from the store. Called by
	// Manager.cleanupExpiredKeys. If the key does not exist, no error is returned.
	Delete(ctx context.Context, keyID string) error
}

// Sentinel errors for KeyStore operations.
var (
	ErrKeyStoreKeyNotFound  = errors.New("key not found in store")
	ErrKeyStoreInvalidKeyID = errors.New("invalid key ID")
)
