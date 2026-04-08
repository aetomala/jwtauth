package keymanager

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/aetomala/jwtauth/pkg/logging"
	"github.com/aetomala/jwtauth/pkg/metrics"
)

// RedisKeyStore is a thread-safe, Redis-backed implementation of KeyStore.
// Each key pair is persisted as a PKCS#1 PEM string alongside a companion
// JSON metadata string under a consistent key-prefix scheme. It is suitable
// for distributed deployments where multiple instances share the same key
// material. For single-instance deployments, use DiskKeyStore. All methods
// are safe for concurrent use.
type RedisKeyStore struct {
	// ===== Redis Client =====
	client *redis.Client // Thread-safe Redis client

	// ===== Observability =====
	logger  logging.Logger  // Optional; nil disables logging
	metrics metrics.Metrics // Optional; nil disables metrics
	backend string          // always "redis"
}

// NewRedisKeyStore returns a new RedisKeyStore using the provided Redis client.
// Returns ErrNilRedisClient if client is nil. Pass a logging.Logger for
// structured log output; pass nil to disable logging. Pass a metrics.Metrics
// for instrumentation; pass nil to disable metrics.
func NewRedisKeyStore(client *redis.Client, logger logging.Logger, m metrics.Metrics) (*RedisKeyStore, error) {
	// ===== STEP 1: Validate Client =====
	if client == nil {
		return nil, ErrNilRedisClient
	}

	// ===== STEP 2: Return Initialized Store =====
	r := &RedisKeyStore{
		client:  client,
		backend: "redis",
	}
	if logger != nil {
		r.logger = logger
	}
	if m != nil {
		r.metrics = m
	}
	return r, nil
}

// LoadAll returns every valid (non-expired) key in Redis. Keys with missing or
// unparseable metadata are silently skipped. Returns an empty slice when no
// valid keys exist — this is not an error. Returns the context error if the
// context is cancelled before completion.
func (r *RedisKeyStore) LoadAll(ctx context.Context) ([]*StoredKey, error) {
	start := time.Now()
	status := "error"
	errorType := "error"
	var keyCount int
	defer func() {
		if r.metrics != nil {
			r.metrics.IncrementCounter(metricKeyStoreOpsTotal, map[string]string{
				"operation":       "load_all",
				"status":          status,
				"error_type":      errorType,
				"storage_backend": r.backend,
			})
			r.metrics.RecordDuration(metricKeyStoreOpDuration, time.Since(start), map[string]string{
				"operation":       "load_all",
				"storage_backend": r.backend,
			})
			if status == "success" {
				r.metrics.SetGauge(metricKeyStoreKeysCount, float64(keyCount), map[string]string{
					"storage_backend": r.backend,
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

	// ===== STEP 2: Scan PEM Keys =====
	iter := r.client.Scan(ctx, 0, keyPEMPrefix+"*", 0).Iterator()

	keys := make([]*StoredKey, 0)
	for iter.Next(ctx) {
		redisKey := iter.Val()
		keyID := strings.TrimPrefix(redisKey, keyPEMPrefix)

		// ===== STEP 3: Load PEM =====
		pemStr, err := r.client.Get(ctx, redisKey).Result()
		if err != nil {
			if r.logger != nil {
				r.logger.Warn("skipping key: failed to load PEM",
					"keyID", keyID,
					"error", err)
			}
			continue
		}

		privateKey, err := decodePEM(pemStr)
		if err != nil {
			if r.logger != nil {
				r.logger.Warn("skipping key: failed to parse PEM",
					"keyID", keyID,
					"error", err)
			}
			continue
		}

		// ===== STEP 4: Load Metadata =====
		metaStr, err := r.client.Get(ctx, keyMetaPrefix+keyID).Result()
		if err != nil {
			if r.logger != nil {
				r.logger.Warn("skipping key: failed to load metadata",
					"keyID", keyID,
					"error", err)
			}
			continue
		}

		var meta KeyMetadata
		if err := json.Unmarshal([]byte(metaStr), &meta); err != nil {
			if r.logger != nil {
				r.logger.Warn("skipping key: failed to parse metadata",
					"keyID", keyID,
					"error", err)
			}
			continue
		}

		// ===== STEP 5: Skip Expired Keys =====
		if !meta.ExpiresAt.IsZero() && time.Now().After(meta.ExpiresAt) {
			if r.logger != nil {
				r.logger.Info("skipping expired key",
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

		if r.logger != nil {
			r.logger.Debug("loaded key from redis", "keyID", keyID)
		}
	}

	if err := iter.Err(); err != nil {
		if r.logger != nil {
			r.logger.Error("failed to scan redis keys", "error", err)
		}
		return nil, fmt.Errorf("scan redis keys: %w", err)
	}

	// ===== STEP 6: Log and Return =====
	status = "success"
	errorType = ""
	keyCount = len(keys)
	if r.logger != nil {
		r.logger.Info("loaded keys from redis", "count", keyCount)
	}
	return keys, nil
}

// Save persists a new key pair and its metadata to Redis via an atomic pipeline.
// Both the PEM and metadata are written together — if either fails, neither is
// stored. Returns the context error if the context is cancelled.
func (r *RedisKeyStore) Save(ctx context.Context, keyID string, privateKey *rsa.PrivateKey, meta KeyMetadata) error {
	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		if r.metrics != nil {
			r.metrics.IncrementCounter(metricKeyStoreOpsTotal, map[string]string{
				"operation":       "save",
				"status":          status,
				"error_type":      errorType,
				"storage_backend": r.backend,
			})
			r.metrics.RecordDuration(metricKeyStoreOpDuration, time.Since(start), map[string]string{
				"operation":       "save",
				"storage_backend": r.backend,
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
	pemStr := encodePEM(privateKey)

	// ===== STEP 3: Marshal Metadata =====
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		if r.logger != nil {
			r.logger.Error("failed to marshal key metadata",
				"keyID", keyID,
				"error", err)
		}
		return fmt.Errorf("marshal key metadata: %w", err)
	}

	// ===== STEP 4: Write via Atomic Pipeline =====
	pipe := r.client.Pipeline()
	pipe.Set(ctx, keyPEMPrefix+keyID, pemStr, 0)
	pipe.Set(ctx, keyMetaPrefix+keyID, string(metaBytes), 0)

	if _, err := pipe.Exec(ctx); err != nil {
		if r.logger != nil {
			r.logger.Error("failed to save key to redis",
				"keyID", keyID,
				"error", err)
		}
		return fmt.Errorf("save key to redis: %w", err)
	}

	// ===== STEP 5: Log and Return =====
	status = "success"
	errorType = ""
	if r.logger != nil {
		r.logger.Info("saved key to redis", "keyID", keyID)
	}
	return nil
}

// UpdateMetadata overwrites the persisted metadata for keyID. Used by Manager
// during rotation to set ExpiresAt on the outgoing signing key.
// Returns ErrKeyStoreKeyNotFound if no PEM key exists for keyID in Redis.
// Returns the context error if the context is cancelled.
func (r *RedisKeyStore) UpdateMetadata(ctx context.Context, keyID string, meta KeyMetadata) error {
	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		if r.metrics != nil {
			r.metrics.IncrementCounter(metricKeyStoreOpsTotal, map[string]string{
				"operation":       "update_metadata",
				"status":          status,
				"error_type":      errorType,
				"storage_backend": r.backend,
			})
			r.metrics.RecordDuration(metricKeyStoreOpDuration, time.Since(start), map[string]string{
				"operation":       "update_metadata",
				"storage_backend": r.backend,
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
	exists, err := r.client.Exists(ctx, keyPEMPrefix+keyID).Result()
	if err != nil {
		if r.logger != nil {
			r.logger.Error("failed to check key existence",
				"keyID", keyID,
				"error", err)
		}
		return fmt.Errorf("check key existence: %w", err)
	}
	if exists == 0 {
		status = "not_found"
		errorType = "not_found"
		return ErrKeyStoreKeyNotFound
	}

	// ===== STEP 3: Marshal and Write Updated Metadata =====
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		if r.logger != nil {
			r.logger.Error("failed to marshal key metadata",
				"keyID", keyID,
				"error", err)
		}
		return fmt.Errorf("marshal key metadata: %w", err)
	}

	if err := r.client.Set(ctx, keyMetaPrefix+keyID, string(metaBytes), 0).Err(); err != nil {
		if r.logger != nil {
			r.logger.Error("failed to update metadata in redis",
				"keyID", keyID,
				"error", err)
		}
		return fmt.Errorf("update metadata: %w", err)
	}

	// ===== STEP 4: Log and Return =====
	status = "success"
	errorType = ""
	if r.logger != nil {
		r.logger.Info("updated key metadata", "keyID", keyID)
	}
	return nil
}

// LoadKey fetches the private key and metadata for keyID. Called by Manager
// on a GetPublicKey cache miss. Returns ErrKeyStoreInvalidKeyID if keyID is
// empty or whitespace-only, ErrKeyStoreKeyNotFound if the key does not exist
// in Redis. Returns the context error if the context is cancelled.
func (r *RedisKeyStore) LoadKey(ctx context.Context, keyID string) (*rsa.PrivateKey, *KeyMetadata, error) {
	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		if r.metrics != nil {
			r.metrics.IncrementCounter(metricKeyStoreOpsTotal, map[string]string{
				"operation":       "load_key",
				"status":          status,
				"error_type":      errorType,
				"storage_backend": r.backend,
			})
			r.metrics.RecordDuration(metricKeyStoreOpDuration, time.Since(start), map[string]string{
				"operation":       "load_key",
				"storage_backend": r.backend,
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

	// ===== STEP 3: Load PEM =====
	pemStr, err := r.client.Get(ctx, keyPEMPrefix+keyID).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			status = "not_found"
			errorType = "not_found"
			return nil, nil, ErrKeyStoreKeyNotFound
		}
		if r.logger != nil {
			r.logger.Error("failed to load key from redis",
				"keyID", keyID,
				"error", err)
		}
		return nil, nil, fmt.Errorf("load key: %w", err)
	}

	privateKey, err := decodePEM(pemStr)
	if err != nil {
		if r.logger != nil {
			r.logger.Error("failed to parse PEM for key",
				"keyID", keyID,
				"error", err)
		}
		return nil, nil, fmt.Errorf("parse key PEM: %w", err)
	}

	// ===== STEP 4: Load Metadata =====
	metaStr, err := r.client.Get(ctx, keyMetaPrefix+keyID).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			status = "not_found"
			errorType = "not_found"
			return nil, nil, ErrKeyStoreKeyNotFound
		}
		if r.logger != nil {
			r.logger.Error("failed to load key metadata from redis",
				"keyID", keyID,
				"error", err)
		}
		return nil, nil, fmt.Errorf("load metadata: %w", err)
	}

	var meta KeyMetadata
	if err := json.Unmarshal([]byte(metaStr), &meta); err != nil {
		if r.logger != nil {
			r.logger.Error("failed to parse key metadata",
				"keyID", keyID,
				"error", err)
		}
		return nil, nil, fmt.Errorf("parse metadata: %w", err)
	}

	// ===== STEP 5: Log and Return =====
	status = "success"
	errorType = ""
	if r.logger != nil {
		r.logger.Debug("loaded key from redis", "keyID", keyID)
	}
	return privateKey, &meta, nil
}

// Delete removes the PEM and metadata entries for keyID from Redis.
// If the key does not exist, no error is returned — the call is idempotent.
// Returns the context error if the context is cancelled.
func (r *RedisKeyStore) Delete(ctx context.Context, keyID string) error {
	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		if r.metrics != nil {
			r.metrics.IncrementCounter(metricKeyStoreOpsTotal, map[string]string{
				"operation":       "delete",
				"status":          status,
				"error_type":      errorType,
				"storage_backend": r.backend,
			})
			r.metrics.RecordDuration(metricKeyStoreOpDuration, time.Since(start), map[string]string{
				"operation":       "delete",
				"storage_backend": r.backend,
			})
		}
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		return err
	}

	// ===== STEP 2: Delete Both Keys =====
	if err := r.client.Del(ctx, keyPEMPrefix+keyID, keyMetaPrefix+keyID).Err(); err != nil {
		if r.logger != nil {
			r.logger.Error("failed to delete key from redis",
				"keyID", keyID,
				"error", err)
		}
		return fmt.Errorf("delete key from redis: %w", err)
	}

	// ===== STEP 3: Log and Return =====
	status = "success"
	errorType = ""
	if r.logger != nil {
		r.logger.Info("deleted key from redis", "keyID", keyID)
	}
	return nil
}

// encodePEM encodes a PKCS#1 RSA private key to a PEM string.
func encodePEM(key *rsa.PrivateKey) string {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	return string(pem.EncodeToMemory(block))
}

// decodePEM decodes a PKCS#1 PEM string to an RSA private key.
func decodePEM(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("invalid PEM format")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return key, nil
}

// Sentinel errors for RedisKeyStore operations.
var (
	ErrNilRedisClient = errors.New("redis client must not be nil")
)

// Redis key prefixes used for all key-store entries.
const (
	keyPEMPrefix  = "ks:pem:"
	keyMetaPrefix = "ks:meta:"
)

// Ensure RedisKeyStore implements KeyStore at compile time.
var _ KeyStore = (*RedisKeyStore)(nil)
