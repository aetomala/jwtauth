package keymanager

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aetomala/jwtauth/pkg/logging"
	"github.com/aetomala/jwtauth/pkg/metrics"
)

// DiskKeyStore is a thread-safe, filesystem-backed implementation of KeyStore.
// Each key pair is persisted as a PKCS#1 PEM file alongside a companion JSON
// metadata file in a configurable directory. It is suitable for single-instance
// deployments. For distributed deployments, use a shared-storage implementation
// such as RedisKeyStore. All methods are safe for concurrent use.
type DiskKeyStore struct {
	// ===== Configuration =====
	dir     string // absolute path to the key directory
	keySize int    // minimum accepted RSA key bit-size for load-time validation

	// ===== Observability =====
	logger  logging.Logger  // Optional; nil disables logging
	metrics metrics.Metrics // Optional; nil disables metrics
	backend string          // always "disk"
}

// NewDiskKeyStore returns a new DiskKeyStore rooted at dir. The directory is
// created if it does not already exist. Returns ErrInvalidKeyDirectory if dir
// is empty or the directory cannot be created.
func NewDiskKeyStore(dir string, keySize int, logger logging.Logger, m metrics.Metrics) (*DiskKeyStore, error) {
	// ===== STEP 1: Validate Directory =====
	if strings.TrimSpace(dir) == "" {
		return nil, ErrInvalidKeyDirectory
	}

	// ===== STEP 2: Create Directory =====
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create key directory: %w", err)
	}

	// ===== STEP 3: Return Initialized Store =====
	store := &DiskKeyStore{
		dir:     dir,
		keySize: keySize,
		backend: "disk",
	}
	if logger != nil {
		store.logger = logger
	}
	if m != nil {
		store.metrics = m
	}
	return store, nil
}

// LoadAll returns every valid (non-expired) key in the directory. Corrupted PEM
// files and keys with missing or unreadable metadata are silently skipped. Returns
// an empty slice when no valid keys exist — this is not an error. Returns the
// context error if the context is cancelled before completion.
func (d *DiskKeyStore) LoadAll(ctx context.Context) ([]*StoredKey, error) {
	start := time.Now()
	status := "error"
	errorType := "error"
	var keyCount int
	defer func() {
		if d.metrics != nil {
			d.metrics.IncrementCounter(metricKeyStoreOpsTotal, map[string]string{
				"operation":       "load_all",
				"status":          status,
				"error_type":      errorType,
				"storage_backend": d.backend,
			})
			d.metrics.RecordDuration(metricKeyStoreOpDuration, time.Since(start), map[string]string{
				"operation":       "load_all",
				"storage_backend": d.backend,
			})
			if status == "success" {
				d.metrics.SetGauge(metricKeyStoreKeysCount, float64(keyCount), map[string]string{
					"storage_backend": d.backend,
				})
			}
		}
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		return nil, err
	}

	// ===== STEP 2: Glob PEM Files =====
	pattern := filepath.Join(d.dir, "*.pem")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		if d.logger != nil {
			d.logger.Error("failed to glob key files", "error", err)
		}
		return nil, fmt.Errorf("glob key files: %w", err)
	}

	// ===== STEP 3: Load Each Key =====
	keys := make([]*StoredKey, 0, len(matches))
	for _, file := range matches {
		privateKey, keyID, err := d.readKeyFile(file)
		if err != nil {
			if d.logger != nil {
				d.logger.Warn("skipping key file: failed to load",
					"file", filepath.Base(file),
					"error", err)
			}
			continue
		}

		meta, err := d.readMetadata(keyID)
		if err != nil {
			if d.logger != nil {
				d.logger.Warn("skipping key: failed to load metadata",
					"keyID", keyID,
					"error", err)
			}
			continue
		}

		// Skip already-expired keys
		if !meta.ExpiresAt.IsZero() && time.Now().After(meta.ExpiresAt) {
			if d.logger != nil {
				d.logger.Info("skipping expired key",
					"keyID", keyID,
					"expiredAt", meta.ExpiresAt.Format(time.RFC3339))
			}
			continue
		}

		keys = append(keys, &StoredKey{
			KeyID:      keyID,
			PrivateKey: privateKey,
			Metadata:   meta,
		})

		if d.logger != nil {
			d.logger.Debug("loaded key from disk", "keyID", keyID)
		}
	}

	// ===== STEP 4: Log and Return =====
	status = "success"
	errorType = ""
	keyCount = len(keys)
	if d.logger != nil {
		d.logger.Info("loaded keys from disk", "count", keyCount)
	}
	return keys, nil
}

// Save persists a new key pair and its metadata to disk. The PEM file is written
// with 0600 permissions. If the metadata write fails, the PEM file is removed to
// maintain consistency. Returns the context error if the context is cancelled.
func (d *DiskKeyStore) Save(ctx context.Context, keyID string, privateKey *rsa.PrivateKey, meta KeyMetadata) error {
	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		if d.metrics != nil {
			d.metrics.IncrementCounter(metricKeyStoreOpsTotal, map[string]string{
				"operation":       "save",
				"status":          status,
				"error_type":      errorType,
				"storage_backend": d.backend,
			})
			d.metrics.RecordDuration(metricKeyStoreOpDuration, time.Since(start), map[string]string{
				"operation":       "save",
				"storage_backend": d.backend,
			})
		}
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		return err
	}

	// ===== STEP 2: Encode Private Key to PEM =====
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	// ===== STEP 3: Write PEM File =====
	pemPath := filepath.Join(d.dir, keyID+".pem")
	file, err := os.OpenFile(pemPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		if d.logger != nil {
			d.logger.Error("failed to create key file",
				"keyID", keyID,
				"error", err)
		}
		return fmt.Errorf("create key file: %w", err)
	}
	defer file.Close()

	if err := pem.Encode(file, pemBlock); err != nil {
		if d.logger != nil {
			d.logger.Error("failed to write key file",
				"keyID", keyID,
				"error", err)
		}
		return fmt.Errorf("write key file: %w", err)
	}

	// ===== STEP 4: Write Metadata File =====
	if err := d.writeMetadata(keyID, meta); err != nil {
		// Rollback: remove the PEM file to maintain consistency
		os.Remove(pemPath)
		if d.logger != nil {
			d.logger.Warn("failed to save key metadata — rolling back PEM",
				"keyID", keyID,
				"error", err)
		}
		return fmt.Errorf("save key metadata: %w", err)
	}

	// ===== STEP 5: Log and Return =====
	status = "success"
	errorType = ""
	if d.logger != nil {
		d.logger.Info("saved key to disk", "keyID", keyID)
	}
	return nil
}

// UpdateMetadata overwrites the persisted metadata for keyID. Used by Manager
// during rotation to set ExpiresAt on the outgoing signing key.
// Returns ErrKeyStoreKeyNotFound if the PEM file for keyID does not exist.
// Returns the context error if the context is cancelled.
func (d *DiskKeyStore) UpdateMetadata(ctx context.Context, keyID string, meta KeyMetadata) error {
	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		if d.metrics != nil {
			d.metrics.IncrementCounter(metricKeyStoreOpsTotal, map[string]string{
				"operation":       "update_metadata",
				"status":          status,
				"error_type":      errorType,
				"storage_backend": d.backend,
			})
			d.metrics.RecordDuration(metricKeyStoreOpDuration, time.Since(start), map[string]string{
				"operation":       "update_metadata",
				"storage_backend": d.backend,
			})
		}
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		return err
	}

	// ===== STEP 2: Verify Key Exists =====
	pemPath := filepath.Join(d.dir, keyID+".pem")
	if _, err := os.Stat(pemPath); errors.Is(err, os.ErrNotExist) {
		status = "not_found"
		errorType = "not_found"
		return ErrKeyStoreKeyNotFound
	}

	// ===== STEP 3: Write Updated Metadata =====
	if err := d.writeMetadata(keyID, meta); err != nil {
		if d.logger != nil {
			d.logger.Error("failed to update metadata",
				"keyID", keyID,
				"error", err)
		}
		return fmt.Errorf("update metadata: %w", err)
	}

	// ===== STEP 4: Log and Return =====
	status = "success"
	errorType = ""
	if d.logger != nil {
		d.logger.Info("updated key metadata", "keyID", keyID)
	}
	return nil
}

// LoadKey fetches the private key and metadata for keyID. Called by Manager on a
// GetPublicKey cache miss. Returns ErrKeyStoreInvalidKeyID if keyID is empty or
// whitespace-only, ErrKeyStoreKeyNotFound if the key does not exist on disk.
func (d *DiskKeyStore) LoadKey(ctx context.Context, keyID string) (*rsa.PrivateKey, *KeyMetadata, error) {
	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		if d.metrics != nil {
			d.metrics.IncrementCounter(metricKeyStoreOpsTotal, map[string]string{
				"operation":       "load_key",
				"status":          status,
				"error_type":      errorType,
				"storage_backend": d.backend,
			})
			d.metrics.RecordDuration(metricKeyStoreOpDuration, time.Since(start), map[string]string{
				"operation":       "load_key",
				"storage_backend": d.backend,
			})
		}
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		return nil, nil, err
	}

	// ===== STEP 2: Validate Key ID =====
	if strings.TrimSpace(keyID) == "" {
		status = "not_found"
		errorType = "not_found"
		return nil, nil, ErrKeyStoreInvalidKeyID
	}

	// ===== STEP 3: Load PEM File =====
	pemPath := filepath.Join(d.dir, keyID+".pem")
	privateKey, _, err := d.readKeyFile(pemPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "no such file") {
			status = "not_found"
			errorType = "not_found"
			return nil, nil, ErrKeyStoreKeyNotFound
		}
		if d.logger != nil {
			d.logger.Error("failed to load key file",
				"keyID", keyID,
				"error", err)
		}
		return nil, nil, fmt.Errorf("load key: %w", err)
	}

	// ===== STEP 4: Load Metadata =====
	meta, err := d.readMetadata(keyID)
	if err != nil {
		if d.logger != nil {
			d.logger.Error("failed to load key metadata",
				"keyID", keyID,
				"error", err)
		}
		return nil, nil, fmt.Errorf("load metadata: %w", err)
	}

	// ===== STEP 5: Log and Return =====
	status = "success"
	errorType = ""
	if d.logger != nil {
		d.logger.Debug("loaded key from disk", "keyID", keyID)
	}
	return privateKey, &meta, nil
}

// Delete removes the PEM file and metadata JSON file for keyID from disk.
// If the key does not exist, no error is returned — the call is idempotent.
// Returns the context error if the context is cancelled.
func (d *DiskKeyStore) Delete(ctx context.Context, keyID string) error {
	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		if d.metrics != nil {
			d.metrics.IncrementCounter(metricKeyStoreOpsTotal, map[string]string{
				"operation":       "delete",
				"status":          status,
				"error_type":      errorType,
				"storage_backend": d.backend,
			})
			d.metrics.RecordDuration(metricKeyStoreOpDuration, time.Since(start), map[string]string{
				"operation":       "delete",
				"storage_backend": d.backend,
			})
		}
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		return err
	}

	// ===== STEP 2: Remove PEM File =====
	pemPath := filepath.Join(d.dir, keyID+".pem")
	if err := os.Remove(pemPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		if d.logger != nil {
			d.logger.Error("failed to delete key file",
				"keyID", keyID,
				"error", err)
		}
		return fmt.Errorf("delete key file: %w", err)
	}

	// ===== STEP 3: Remove Metadata File =====
	metaPath := filepath.Join(d.dir, keyID+".json")
	if err := os.Remove(metaPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		if d.logger != nil {
			d.logger.Error("failed to delete metadata file",
				"keyID", keyID,
				"error", err)
		}
		return fmt.Errorf("delete metadata file: %w", err)
	}

	// ===== STEP 4: Log and Return =====
	status = "success"
	errorType = ""
	if d.logger != nil {
		d.logger.Info("deleted key from disk", "keyID", keyID)
	}
	return nil
}

// readKeyFile reads and parses the PKCS#1 PEM file at keyFile. The key ID is
// extracted from the filename (strip .pem extension). Validates that the loaded
// key's bit length is not below 2048 bits.
func (d *DiskKeyStore) readKeyFile(keyFile string) (*rsa.PrivateKey, string, error) {
	// ===== STEP 1: Read PEM File =====
	pemData, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, "", err
	}

	// ===== STEP 2: Extract Key ID from Filename =====
	keyID := strings.TrimSuffix(filepath.Base(keyFile), ".pem")

	// ===== STEP 3: Decode PEM Block =====
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, "", fmt.Errorf("invalid PEM format")
	}

	// ===== STEP 4: Parse Private Key =====
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("parse private key: %w", err)
	}

	// ===== STEP 5: Validate Key Size =====
	minSize := d.keySize
	if minSize < 2048 {
		minSize = 2048
	}
	if privateKey.N.BitLen() < minSize {
		return nil, "", fmt.Errorf("key size %d below minimum %d bits", privateKey.N.BitLen(), minSize)
	}

	return privateKey, keyID, nil
}

// writeMetadata serialises meta to JSON and writes it to {dir}/{keyID}.json.
func (d *DiskKeyStore) writeMetadata(keyID string, meta KeyMetadata) error {
	data, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	metaPath := filepath.Join(d.dir, keyID+".json")
	return os.WriteFile(metaPath, data, 0600)
}

// readMetadata reads and deserialises the JSON metadata file for keyID.
func (d *DiskKeyStore) readMetadata(keyID string) (KeyMetadata, error) {
	metaPath := filepath.Join(d.dir, keyID+".json")
	data, err := os.ReadFile(metaPath)
	if err != nil {
		return KeyMetadata{}, err
	}
	var meta KeyMetadata
	if err := json.Unmarshal(data, &meta); err != nil {
		return KeyMetadata{}, fmt.Errorf("unmarshal metadata: %w", err)
	}
	return meta, nil
}

// Sentinel errors for DiskKeyStore operations.
var (
	ErrInvalidKeyDirectory = errors.New("invalid key directory")
)

// Ensure DiskKeyStore implements KeyStore at compile time.
var _ KeyStore = (*DiskKeyStore)(nil)
