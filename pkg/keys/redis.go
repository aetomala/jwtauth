// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package keys

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
	"github.com/aetomala/jwtauth/pkg/tracing"
)

// RedisKeyStoreConfig holds configuration for a RedisKeyStore instance.
type RedisKeyStoreConfig struct {
	Client    *redis.Client   // Required; must not be nil.
	KeyPrefix string          // Optional; prepended to all Redis keys; empty preserves current behavior.
	Logger    logging.Logger  // Optional; nil defaults to NoOpLogger.
	Metrics   metrics.Metrics // Optional; nil defaults to NoOpMetrics.
	Tracer    tracing.Tracer  // Optional; nil defaults to NoOpTracer.
}

// RedisKeyStoreConfigDefault returns a RedisKeyStoreConfig with NoOp defaults
// for all optional observability fields.
func RedisKeyStoreConfigDefault() RedisKeyStoreConfig {
	return RedisKeyStoreConfig{
		Logger:  &logging.NoOpLogger{},
		Metrics: metrics.NewNoOpMetrics(),
		Tracer:  tracing.NewNoOpTracer(),
	}
}

// RedisKeyStore is a thread-safe, Redis-backed implementation of KeyStore.
// Each key pair is persisted as a PKCS#1 PEM string alongside a companion
// JSON metadata string under a consistent key-prefix scheme. It is suitable
// for distributed deployments where multiple instances share the same key
// material. For single-instance deployments, use DiskKeyStore. All methods
// are safe for concurrent use.
type RedisKeyStore struct {
	// ===== Redis Client =====
	client *redis.Client // Thread-safe Redis client

	// ===== Key Prefixes =====
	namespace  string // = cfg.KeyPrefix; returned by Namespace()
	pemPrefix  string // = cfg.KeyPrefix + keyPEMPrefix;  applied to all PEM keys
	metaPrefix string // = cfg.KeyPrefix + keyMetaPrefix; applied to all metadata keys

	// ===== Observability =====
	logger  logging.Logger  // never nil; defaults to NoOpLogger
	metrics metrics.Metrics // never nil; defaults to NoOpMetrics
	tracer  tracing.Tracer  // never nil; defaults to NoOpTracer
	backend string          // always "redis"
}

// NewRedisKeyStore returns a new RedisKeyStore using the provided config.
// Returns ErrNilRedisClient if cfg.Client is nil.
func NewRedisKeyStore(cfg RedisKeyStoreConfig) (*RedisKeyStore, error) {
	// ===== STEP 1: Validate Client =====
	if cfg.Client == nil {
		return nil, ErrNilRedisClient
	}

	// ===== STEP 2: Apply Defaults =====
	defaults := RedisKeyStoreConfigDefault()
	if cfg.Logger == nil {
		cfg.Logger = defaults.Logger
	}
	if cfg.Metrics == nil {
		cfg.Metrics = defaults.Metrics
	}
	if cfg.Tracer == nil {
		cfg.Tracer = defaults.Tracer
	}
	if cfg.KeyPrefix != "" {
		cfg.Logger = cfg.Logger.With("namespace", cfg.KeyPrefix)
	}

	// ===== STEP 3: Return Initialized Store =====
	return &RedisKeyStore{
		client:     cfg.Client,
		namespace:  cfg.KeyPrefix,
		pemPrefix:  cfg.KeyPrefix + keyPEMPrefix,
		metaPrefix: cfg.KeyPrefix + keyMetaPrefix,
		logger:     cfg.Logger,
		metrics:    cfg.Metrics,
		tracer:     cfg.Tracer,
		backend:    "redis",
	}, nil
}

// Namespace returns the KeyPrefix this store was configured with. An empty
// string indicates an unscoped (single-tenant) deployment.
func (r *RedisKeyStore) Namespace() string { return r.namespace }

// startSpan starts a new span for the given operation name, pre-seeded with
// the storage.backend and storage.namespace attributes.
func (r *RedisKeyStore) startSpan(ctx context.Context, operation string) (context.Context, tracing.Span) {
	return r.tracer.Start(ctx, "RedisKeyStore."+operation,
		tracing.WithAttributes(map[string]any{
			"storage.backend":   r.backend,
			"storage.namespace": r.namespace,
		}),
	)
}

// LoadAll returns every valid (non-expired) key in Redis. Keys with missing or
// unparseable metadata are silently skipped. Returns an empty slice when no
// valid keys exist — this is not an error. Returns the context error if the
// context is cancelled before completion.
func (r *RedisKeyStore) LoadAll(ctx context.Context) ([]*StoredKey, error) {
	ctx, span := r.startSpan(ctx, "LoadAll")
	defer span.End()

	start := time.Now()
	status := "error"
	errorType := "error"
	var keyCount int
	defer func() {
		r.metrics.IncrementCounter(metricKeyStoreOpsTotal, map[string]string{
			"operation":       "load_all",
			"status":          status,
			"error_type":      errorType,
			"storage_backend": r.backend,
			"namespace":       r.namespace,
		})
		r.metrics.RecordDuration(metricKeyStoreOpDuration, time.Since(start), map[string]string{
			"operation":       "load_all",
			"storage_backend": r.backend,
			"namespace":       r.namespace,
		})
		if status == "success" {
			r.metrics.SetGauge(metricKeyStoreKeysCount, float64(keyCount), map[string]string{
				"storage_backend": r.backend,
				"namespace":       r.namespace,
			})
		}
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return nil, err
	}

	// ===== STEP 2: Scan PEM Keys =====
	iter := r.client.Scan(ctx, 0, r.pemPrefix+"*", 0).Iterator()

	keys := make([]*StoredKey, 0)
	for iter.Next(ctx) {
		redisKey := iter.Val()
		keyID := strings.TrimPrefix(redisKey, r.pemPrefix)

		// ===== STEP 3: Load PEM =====
		pemStr, err := r.client.Get(ctx, redisKey).Result()
		if err != nil {
			r.logger.Warn("skipping key: failed to load PEM", ctx,
				"keyID", keyID,
				"error", err)
			continue
		}

		privateKey, err := decodePEM(pemStr)
		if err != nil {
			r.logger.Warn("skipping key: failed to parse PEM", ctx,
				"keyID", keyID,
				"error", err)
			continue
		}

		// ===== STEP 4: Load Metadata =====
		metaStr, err := r.client.Get(ctx, r.metaPrefix+keyID).Result()
		if err != nil {
			r.logger.Warn("skipping key: failed to load metadata", ctx,
				"keyID", keyID,
				"error", err)
			continue
		}

		var meta KeyMetadata
		if err := json.Unmarshal([]byte(metaStr), &meta); err != nil {
			r.logger.Warn("skipping key: failed to parse metadata", ctx,
				"keyID", keyID,
				"error", err)
			continue
		}

		// ===== STEP 5: Skip Expired Keys =====
		if !meta.ExpiresAt.IsZero() && time.Now().After(meta.ExpiresAt) {
			r.logger.Info("skipping expired key", ctx,
				"keyID", keyID,
				"expiredAt", meta.ExpiresAt.Format(time.RFC3339))
			continue
		}

		keys = append(keys, &StoredKey{
			KeyID:      keyID,
			PrivateKey: privateKey,
			Metadata:   meta,
		})

		r.logger.Debug("loaded key from redis", ctx, "keyID", keyID)
	}

	if err := iter.Err(); err != nil {
		r.logger.Error("failed to scan redis keys", ctx, "error", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return nil, fmt.Errorf("scan redis keys: %w", err)
	}

	// ===== STEP 6: Log and Return =====
	status = "success"
	errorType = ""
	keyCount = len(keys)
	r.logger.Info("loaded keys from redis", ctx, "count", keyCount)
	span.SetStatus(tracing.StatusOK, "")
	return keys, nil
}

// Save persists a new key pair and its metadata to Redis via an atomic pipeline.
// Both the PEM and metadata are written together — if either fails, neither is
// stored. Returns the context error if the context is cancelled.
func (r *RedisKeyStore) Save(ctx context.Context, keyID string, privateKey *rsa.PrivateKey, meta KeyMetadata) error {
	ctx, span := r.startSpan(ctx, "Save")
	defer span.End()
	span.SetAttribute("key_id", keyID)

	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		r.metrics.IncrementCounter(metricKeyStoreOpsTotal, map[string]string{
			"operation":       "save",
			"status":          status,
			"error_type":      errorType,
			"storage_backend": r.backend,
			"namespace":       r.namespace,
		})
		r.metrics.RecordDuration(metricKeyStoreOpDuration, time.Since(start), map[string]string{
			"operation":       "save",
			"storage_backend": r.backend,
			"namespace":       r.namespace,
		})
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return err
	}

	// ===== STEP 2: Validate Key ID =====
	if !isValidKeyID(keyID) {
		status = "validation_error"
		errorType = "validation_error"
		span.RecordError(ErrKeyStoreInvalidKeyID)
		span.SetStatus(tracing.StatusError, ErrKeyStoreInvalidKeyID.Error())
		return ErrKeyStoreInvalidKeyID
	}

	// ===== STEP 3: Encode Private Key to PEM =====
	pemStr := encodePEM(privateKey)

	// ===== STEP 4: Marshal Metadata =====
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		r.logger.Error("failed to marshal key metadata", ctx,
			"keyID", keyID,
			"error", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return fmt.Errorf("marshal key metadata: %w", err)
	}

	// ===== STEP 5: Write via Atomic Pipeline =====
	pipe := r.client.Pipeline()
	pipe.Set(ctx, r.pemPrefix+keyID, pemStr, 0)
	pipe.Set(ctx, r.metaPrefix+keyID, string(metaBytes), 0)

	if _, err := pipe.Exec(ctx); err != nil {
		r.logger.Error("failed to save key to redis", ctx,
			"keyID", keyID,
			"error", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return fmt.Errorf("save key to redis: %w", err)
	}

	// ===== STEP 6: Log and Return =====
	status = "success"
	errorType = ""
	r.logger.Info("saved key to redis", ctx, "keyID", keyID)
	span.SetStatus(tracing.StatusOK, "")
	return nil
}

// UpdateMetadata overwrites the persisted metadata for keyID. Used by Manager
// during rotation to set ExpiresAt on the outgoing signing key.
// Returns ErrKeyStoreKeyNotFound if no PEM key exists for keyID in Redis.
// Returns the context error if the context is cancelled.
func (r *RedisKeyStore) UpdateMetadata(ctx context.Context, keyID string, meta KeyMetadata) error {
	ctx, span := r.startSpan(ctx, "UpdateMetadata")
	defer span.End()
	span.SetAttribute("key_id", keyID)

	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		r.metrics.IncrementCounter(metricKeyStoreOpsTotal, map[string]string{
			"operation":       "update_metadata",
			"status":          status,
			"error_type":      errorType,
			"storage_backend": r.backend,
			"namespace":       r.namespace,
		})
		r.metrics.RecordDuration(metricKeyStoreOpDuration, time.Since(start), map[string]string{
			"operation":       "update_metadata",
			"storage_backend": r.backend,
			"namespace":       r.namespace,
		})
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return err
	}

	// ===== STEP 2: Validate Key ID =====
	if !isValidKeyID(keyID) {
		status = "validation_error"
		errorType = "validation_error"
		span.RecordError(ErrKeyStoreInvalidKeyID)
		span.SetStatus(tracing.StatusError, ErrKeyStoreInvalidKeyID.Error())
		return ErrKeyStoreInvalidKeyID
	}

	// ===== STEP 3: Verify Key Exists =====
	exists, err := r.client.Exists(ctx, r.pemPrefix+keyID).Result()
	if err != nil {
		r.logger.Error("failed to check key existence", ctx,
			"keyID", keyID,
			"error", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return fmt.Errorf("check key existence: %w", err)
	}
	if exists == 0 {
		status = "not_found"
		errorType = "not_found"
		span.RecordError(ErrKeyStoreKeyNotFound)
		span.SetStatus(tracing.StatusError, ErrKeyStoreKeyNotFound.Error())
		return ErrKeyStoreKeyNotFound
	}

	// ===== STEP 4: Marshal and Write Updated Metadata =====
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		r.logger.Error("failed to marshal key metadata", ctx,
			"keyID", keyID,
			"error", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return fmt.Errorf("marshal key metadata: %w", err)
	}

	if err := r.client.Set(ctx, r.metaPrefix+keyID, string(metaBytes), 0).Err(); err != nil {
		r.logger.Error("failed to update metadata in redis", ctx,
			"keyID", keyID,
			"error", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return fmt.Errorf("update metadata: %w", err)
	}

	// ===== STEP 5: Log and Return =====
	status = "success"
	errorType = ""
	r.logger.Info("updated key metadata", ctx, "keyID", keyID)
	span.SetStatus(tracing.StatusOK, "")
	return nil
}

// LoadKey fetches the private key and metadata for keyID. Called by Manager
// on a GetPublicKey cache miss. Returns ErrKeyStoreInvalidKeyID if keyID is
// empty or whitespace-only, ErrKeyStoreKeyNotFound if the key does not exist
// in Redis. Returns the context error if the context is cancelled.
func (r *RedisKeyStore) LoadKey(ctx context.Context, keyID string) (*rsa.PrivateKey, *KeyMetadata, error) {
	ctx, span := r.startSpan(ctx, "LoadKey")
	defer span.End()
	span.SetAttribute("key_id", keyID)

	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		r.metrics.IncrementCounter(metricKeyStoreOpsTotal, map[string]string{
			"operation":       "load_key",
			"status":          status,
			"error_type":      errorType,
			"storage_backend": r.backend,
			"namespace":       r.namespace,
		})
		r.metrics.RecordDuration(metricKeyStoreOpDuration, time.Since(start), map[string]string{
			"operation":       "load_key",
			"storage_backend": r.backend,
			"namespace":       r.namespace,
		})
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return nil, nil, err
	}

	// ===== STEP 2: Validate Key ID =====
	if !isValidKeyID(keyID) {
		status = "validation_error"
		errorType = "validation_error"
		span.RecordError(ErrKeyStoreInvalidKeyID)
		span.SetStatus(tracing.StatusError, ErrKeyStoreInvalidKeyID.Error())
		return nil, nil, ErrKeyStoreInvalidKeyID
	}

	// ===== STEP 3: Load PEM =====
	pemStr, err := r.client.Get(ctx, r.pemPrefix+keyID).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			status = "not_found"
			errorType = "not_found"
			span.RecordError(ErrKeyStoreKeyNotFound)
			span.SetStatus(tracing.StatusError, ErrKeyStoreKeyNotFound.Error())
			return nil, nil, ErrKeyStoreKeyNotFound
		}
		r.logger.Error("failed to load key from redis", ctx,
			"keyID", keyID,
			"error", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return nil, nil, fmt.Errorf("load key: %w", err)
	}

	privateKey, err := decodePEM(pemStr)
	if err != nil {
		r.logger.Error("failed to parse PEM for key", ctx,
			"keyID", keyID,
			"error", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return nil, nil, fmt.Errorf("parse key PEM: %w", err)
	}

	// ===== STEP 4: Load Metadata =====
	metaStr, err := r.client.Get(ctx, r.metaPrefix+keyID).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			status = "not_found"
			errorType = "not_found"
			span.RecordError(ErrKeyStoreKeyNotFound)
			span.SetStatus(tracing.StatusError, ErrKeyStoreKeyNotFound.Error())
			return nil, nil, ErrKeyStoreKeyNotFound
		}
		r.logger.Error("failed to load key metadata from redis", ctx,
			"keyID", keyID,
			"error", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return nil, nil, fmt.Errorf("load metadata: %w", err)
	}

	var meta KeyMetadata
	if err := json.Unmarshal([]byte(metaStr), &meta); err != nil {
		r.logger.Error("failed to parse key metadata", ctx,
			"keyID", keyID,
			"error", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return nil, nil, fmt.Errorf("parse metadata: %w", err)
	}

	// ===== STEP 5: Log and Return =====
	status = "success"
	errorType = ""
	r.logger.Debug("loaded key from redis", ctx, "keyID", keyID)
	span.SetStatus(tracing.StatusOK, "")
	return privateKey, &meta, nil
}

// Delete removes the PEM and metadata entries for keyID from Redis.
// If the key does not exist, no error is returned — the call is idempotent.
// Returns the context error if the context is cancelled.
func (r *RedisKeyStore) Delete(ctx context.Context, keyID string) error {
	ctx, span := r.startSpan(ctx, "Delete")
	defer span.End()
	span.SetAttribute("key_id", keyID)

	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		r.metrics.IncrementCounter(metricKeyStoreOpsTotal, map[string]string{
			"operation":       "delete",
			"status":          status,
			"error_type":      errorType,
			"storage_backend": r.backend,
			"namespace":       r.namespace,
		})
		r.metrics.RecordDuration(metricKeyStoreOpDuration, time.Since(start), map[string]string{
			"operation":       "delete",
			"storage_backend": r.backend,
			"namespace":       r.namespace,
		})
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return err
	}

	// ===== STEP 2: Validate Key ID =====
	if !isValidKeyID(keyID) {
		status = "validation_error"
		errorType = "validation_error"
		span.RecordError(ErrKeyStoreInvalidKeyID)
		span.SetStatus(tracing.StatusError, ErrKeyStoreInvalidKeyID.Error())
		return ErrKeyStoreInvalidKeyID
	}

	// ===== STEP 3: Delete Both Keys =====
	if err := r.client.Del(ctx, r.pemPrefix+keyID, r.metaPrefix+keyID).Err(); err != nil {
		r.logger.Error("failed to delete key from redis", ctx,
			"keyID", keyID,
			"error", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return fmt.Errorf("delete key from redis: %w", err)
	}

	// ===== STEP 4: Log and Return =====
	status = "success"
	errorType = ""
	r.logger.Info("deleted key from redis", ctx, "keyID", keyID)
	span.SetStatus(tracing.StatusOK, "")
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
