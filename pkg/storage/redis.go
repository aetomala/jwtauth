package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/aetomala/jwtauth/pkg/logging"
	"github.com/aetomala/jwtauth/pkg/metrics"
	"github.com/aetomala/jwtauth/pkg/tracing"
)

// RedisRefreshStoreConfig holds configuration for a RedisRefreshStore instance.
type RedisRefreshStoreConfig struct {
	Client    *redis.Client   // Required. Redis client used for all operations.
	KeyPrefix string          // Optional; prepended to all Redis keys; empty preserves current behavior.
	Logger    logging.Logger  // Optional; nil defaults to NoOpLogger.
	Metrics   metrics.Metrics // Optional; nil defaults to NoOpMetrics.
	Tracer    tracing.Tracer  // Optional; nil defaults to NoOpTracer.
}

// RedisRefreshStoreConfigDefault returns a RedisRefreshStoreConfig with
// sensible defaults. NewRedisRefreshStore applies these automatically for any
// nil fields.
func RedisRefreshStoreConfigDefault() RedisRefreshStoreConfig {
	return RedisRefreshStoreConfig{
		Logger:  &logging.NoOpLogger{},
		Metrics: metrics.NewNoOpMetrics(),
		Tracer:  tracing.NewNoOpTracer(),
	}
}

// RedisRefreshStore is a thread-safe, persistent implementation of the
// RefreshStore interface backed by Redis. It is suitable for multi-instance
// deployments where refresh tokens must be shared across application instances.
// For single-instance deployments or testing, use MemoryRefreshStore.
//
// All methods are safe for concurrent use.
type RedisRefreshStore struct {
	// ===== Redis Client =====
	client *redis.Client // Redis client; internally thread-safe

	// ===== Key Prefixes =====
	namespace     string // = cfg.KeyPrefix; returned by Namespace()
	tokenPrefix   string // = cfg.KeyPrefix + tokenKeyPrefix;   applied to all token hash keys
	userSetPrefix string // = cfg.KeyPrefix + userSetKeyPrefix; applied to all user-set keys

	// ===== Observability =====
	logger  logging.Logger  // never nil; defaults to NoOpLogger
	metrics metrics.Metrics // never nil; defaults to NoOpMetrics
	tracer  tracing.Tracer  // never nil; defaults to NoOpTracer
	backend string          // storage_backend label value; always "redis"
}

// NewRedisRefreshStore returns a new RedisRefreshStore using cfg. Zero-value
// and nil fields are filled with defaults from RedisRefreshStoreConfigDefault.
// Returns ErrNilClient if cfg.Client is nil.
func NewRedisRefreshStore(cfg RedisRefreshStoreConfig) (*RedisRefreshStore, error) {
	if cfg.Client == nil {
		return nil, ErrNilClient
	}

	// ===== Apply Defaults =====
	defaults := RedisRefreshStoreConfigDefault()
	if cfg.Logger == nil {
		cfg.Logger = defaults.Logger
	}
	if cfg.Metrics == nil {
		cfg.Metrics = defaults.Metrics
	}
	if cfg.Tracer == nil {
		cfg.Tracer = defaults.Tracer
	}

	return &RedisRefreshStore{
		client:        cfg.Client,
		namespace:     cfg.KeyPrefix,
		tokenPrefix:   cfg.KeyPrefix + tokenKeyPrefix,
		userSetPrefix: cfg.KeyPrefix + userSetKeyPrefix,
		logger:        cfg.Logger,
		metrics:       cfg.Metrics,
		tracer:        cfg.Tracer,
		backend:       "redis",
	}, nil
}

// Namespace returns the KeyPrefix this store was configured with. An empty
// string indicates an unscoped (single-tenant) deployment.
func (r *RedisRefreshStore) Namespace() string { return r.namespace }

// startSpan starts a new span for the given operation name, pre-seeded with
// the storage.backend attribute.
func (r *RedisRefreshStore) startSpan(ctx context.Context, operation string) (context.Context, tracing.Span) {
	return r.tracer.Start(ctx, "RedisRefreshStore."+operation,
		tracing.WithAttributes(map[string]any{"storage.backend": r.backend}),
	)
}

// Store persists a new refresh token. Returns ErrInvalidTokenID if tokenID is
// empty, ErrInvalidUserID if userID is empty, and ErrTokenExpired if expiresAt
// is already in the past. Returns the context error if the context is
// cancelled before the write.
//
// A defensive copy of metadata is made so later mutations to the caller's map
// do not affect the stored token.
func (r *RedisRefreshStore) Store(ctx context.Context, tokenID, userID string, expiresAt time.Time, metadata map[string]interface{}) error {
	ctx, span := r.startSpan(ctx, "Store")
	defer span.End()
	span.SetAttribute("token_id", tokenID)

	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		r.metrics.IncrementCounter(metricStorageOpsTotal, map[string]string{
			"operation":       "store",
			"status":          status,
			"error_type":      errorType,
			"storage_backend": r.backend,
		})
		r.metrics.RecordDuration(metricStorageOpDuration, time.Since(start), map[string]string{
			"operation":       "store",
			"storage_backend": r.backend,
		})
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		r.logger.Warn("store aborted: context cancelled", ctx,
			"reason", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return err
	}

	// ===== STEP 2: Validate Inputs =====
	if len(strings.TrimSpace(tokenID)) == 0 {
		status = "validation_error"
		errorType = "validation_error"
		r.logger.Warn("store rejected: tokenID is empty or whitespace", ctx,
			"userID", userID)
		span.RecordError(ErrInvalidTokenID)
		span.SetStatus(tracing.StatusError, ErrInvalidTokenID.Error())
		return ErrInvalidTokenID
	}

	if len(strings.TrimSpace(userID)) == 0 {
		status = "validation_error"
		errorType = "validation_error"
		r.logger.Warn("store rejected: userID is empty or whitespace", ctx,
			"tokenID", tokenID)
		span.RecordError(ErrInvalidUserID)
		span.SetStatus(tracing.StatusError, ErrInvalidUserID.Error())
		return ErrInvalidUserID
	}

	if expiresAt.Before(time.Now()) || expiresAt.Equal(time.Now()) {
		status = "validation_error"
		errorType = "validation_error"
		r.logger.Warn("store rejected: token is already expired", ctx,
			"tokenID", tokenID,
			"userID", userID,
			"expiresAt", expiresAt)
		span.RecordError(ErrTokenExpired)
		span.SetStatus(tracing.StatusError, ErrTokenExpired.Error())
		return ErrTokenExpired
	}

	// ===== STEP 3: Prepare Metadata (Defensive Copy) =====
	var metadataJSON string
	if metadata != nil {
		metadataCopy := make(map[string]interface{}, len(metadata))
		for k, v := range metadata {
			metadataCopy[k] = v
		}

		jsonBytes, err := json.Marshal(metadataCopy)
		if err != nil {
			r.logger.Error("store failed: metadata marshal error", ctx,
				"tokenID", tokenID,
				"error", err)
			wrapped := fmt.Errorf("failed to marshal metadata: %w", err)
			span.RecordError(wrapped)
			span.SetStatus(tracing.StatusError, wrapped.Error())
			return wrapped
		}
		metadataJSON = string(jsonBytes)
	}

	// ===== STEP 4: Build Token Data Map =====
	now := time.Now()
	tokenData := map[string]interface{}{
		"userID":    userID,
		"expiresAt": expiresAt.UnixMilli(),
		"createdAt": now.UnixMilli(),
		"revoked":   "false",
		"metadata":  metadataJSON,
	}

	// ===== STEP 5: Execute Atomic Write via Pipeline =====
	tokenKey := r.tokenPrefix + tokenID
	userSetKey := r.userSetPrefix + userID
	duration := time.Until(expiresAt)

	pipe := r.client.Pipeline()
	pipe.HSet(ctx, tokenKey, tokenData)
	pipe.SAdd(ctx, userSetKey, tokenID)
	pipe.Expire(ctx, tokenKey, duration)

	r.logger.Debug("executing redis pipeline for token store", ctx,
		"tokenID", tokenID,
		"userID", userID)

	_, err := pipe.Exec(ctx)
	if err != nil {
		r.logger.Error("store failed: redis pipeline error", ctx,
			"tokenID", tokenID,
			"error", err)
		wrapped := fmt.Errorf("failed to store token: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return wrapped
	}

	// ===== STEP 6: Log Success =====
	status = "success"
	errorType = ""
	r.logger.Info("refresh token stored", ctx,
		"tokenID", tokenID,
		"userID", userID,
		"expiresAt", expiresAt)
	span.SetStatus(tracing.StatusOK, "")

	return nil
}

// Retrieve looks up a refresh token by ID and returns a defensive copy.
// Returns ErrInvalidTokenID if tokenID is empty, ErrTokenNotFound if the
// token does not exist, ErrTokenRevoked if the token has been revoked, and
// ErrTokenExpired if the token has passed its expiry time.
//
// The returned *RefreshToken is a deep copy — mutations to it do not affect
// the stored record.
func (r *RedisRefreshStore) Retrieve(ctx context.Context, tokenID string) (*RefreshToken, error) {
	ctx, span := r.startSpan(ctx, "Retrieve")
	defer span.End()
	span.SetAttribute("token_id", tokenID)

	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		r.metrics.IncrementCounter(metricStorageOpsTotal, map[string]string{
			"operation":       "retrieve",
			"status":          status,
			"error_type":      errorType,
			"storage_backend": r.backend,
		})
		r.metrics.RecordDuration(metricStorageOpDuration, time.Since(start), map[string]string{
			"operation":       "retrieve",
			"storage_backend": r.backend,
		})
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		r.logger.Warn("retrieve aborted: context cancelled", ctx,
			"tokenID", tokenID,
			"reason", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return nil, err
	}

	// ===== STEP 2: Validate Inputs =====
	if len(strings.TrimSpace(tokenID)) == 0 {
		status = "validation_error"
		errorType = "validation_error"
		r.logger.Warn("retrieve rejected: tokenID is empty or whitespace", ctx)
		span.RecordError(ErrInvalidTokenID)
		span.SetStatus(tracing.StatusError, ErrInvalidTokenID.Error())
		return nil, ErrInvalidTokenID
	}

	// ===== STEP 3: Look Up Token from Redis =====
	tokenKey := r.tokenPrefix + tokenID
	hash, err := r.client.HGetAll(ctx, tokenKey).Result()
	if err != nil {
		r.logger.Error("retrieve failed: redis error", ctx,
			"tokenID", tokenID,
			"error", err)
		wrapped := fmt.Errorf("failed to retrieve token: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return nil, wrapped
	}

	r.logger.Debug("redis hash retrieved", ctx,
		"tokenID", tokenID,
		"fieldCount", len(hash))

	// ===== STEP 4: Check if Token Exists =====
	if len(hash) == 0 {
		status = "not_found"
		errorType = "not_found"
		r.logger.Warn("retrieve: token not found", ctx,
			"tokenID", tokenID)
		span.RecordError(ErrTokenNotFound)
		span.SetStatus(tracing.StatusError, ErrTokenNotFound.Error())
		return nil, ErrTokenNotFound
	}

	// ===== STEP 5: Check Revocation =====
	revoked := hash["revoked"] == "true"
	if revoked {
		status = "revoked"
		errorType = "revoked"
		r.logger.Warn("retrieve: token has been revoked", ctx,
			"tokenID", tokenID,
			"userID", hash["userID"])
		span.RecordError(ErrTokenRevoked)
		span.SetStatus(tracing.StatusError, ErrTokenRevoked.Error())
		return nil, ErrTokenRevoked
	}

	// ===== STEP 6: Check Expiration =====
	expiresAtMillis, err := strconv.ParseInt(hash["expiresAt"], 10, 64)
	if err != nil {
		r.logger.Error("retrieve failed: invalid expiration timestamp", ctx,
			"tokenID", tokenID,
			"error", err)
		wrapped := fmt.Errorf("invalid expiration timestamp: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return nil, wrapped
	}

	expiresAt := time.UnixMilli(expiresAtMillis)
	if expiresAt.Before(time.Now()) {
		status = "expired"
		errorType = "expired"
		r.logger.Warn("retrieve: token has expired", ctx,
			"tokenID", tokenID,
			"expiredAt", expiresAt)
		span.RecordError(ErrTokenExpired)
		span.SetStatus(tracing.StatusError, ErrTokenExpired.Error())
		return nil, ErrTokenExpired
	}

	// ===== STEP 7: Unmarshal and Return Defensive Copy =====
	createdAtMillis, err := strconv.ParseInt(hash["createdAt"], 10, 64)
	if err != nil {
		r.logger.Error("retrieve failed: invalid creation timestamp", ctx,
			"tokenID", tokenID,
			"error", err)
		wrapped := fmt.Errorf("invalid creation timestamp: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return nil, wrapped
	}

	createdAt := time.UnixMilli(createdAtMillis)

	safeToken := &RefreshToken{
		TokenID:   tokenID,
		UserID:    hash["userID"],
		ExpiresAt: expiresAt,
		CreatedAt: createdAt,
		Revoked:   revoked,
	}

	if metadataJSON, exists := hash["metadata"]; exists && metadataJSON != "" {
		var metadata map[string]interface{}
		if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
			r.logger.Error("retrieve failed: metadata unmarshal error", ctx,
				"tokenID", tokenID,
				"error", err)
			wrapped := fmt.Errorf("failed to unmarshal metadata: %w", err)
			span.RecordError(wrapped)
			span.SetStatus(tracing.StatusError, wrapped.Error())
			return nil, wrapped
		}
		safeToken.Metadata = metadata
	}

	// ===== STEP 8: Log Success =====
	status = "success"
	errorType = ""
	r.logger.Info("retrieve: token retrieved successfully", ctx,
		"tokenID", tokenID)
	span.SetStatus(tracing.StatusOK, "")

	return safeToken, nil
}

// Revoke marks a refresh token as revoked. It is idempotent — if the token
// does not exist, no error is returned. Returns ErrInvalidTokenID if tokenID
// is empty, or the context error if the context is cancelled.
func (r *RedisRefreshStore) Revoke(ctx context.Context, tokenID string) error {
	ctx, span := r.startSpan(ctx, "Revoke")
	defer span.End()
	span.SetAttribute("token_id", tokenID)

	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		r.metrics.IncrementCounter(metricStorageOpsTotal, map[string]string{
			"operation":       "revoke",
			"status":          status,
			"error_type":      errorType,
			"storage_backend": r.backend,
		})
		r.metrics.RecordDuration(metricStorageOpDuration, time.Since(start), map[string]string{
			"operation":       "revoke",
			"storage_backend": r.backend,
		})
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		r.logger.Warn("revoke aborted: context cancelled", ctx,
			"tokenID", tokenID)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return ctx.Err()
	}

	// ===== STEP 2: Validate Inputs =====
	if len(strings.TrimSpace(tokenID)) == 0 {
		status = "validation_error"
		errorType = "validation_error"
		r.logger.Warn("revoke rejected: tokenID is empty or whitespace", ctx)
		span.RecordError(ErrInvalidTokenID)
		span.SetStatus(tracing.StatusError, ErrInvalidTokenID.Error())
		return ErrInvalidTokenID
	}

	// ===== STEP 3: Check Token Existence =====
	tokenKey := r.tokenPrefix + tokenID

	exists, err := r.client.Exists(ctx, tokenKey).Result()
	if err != nil {
		r.logger.Error("revoke failed: redis error", ctx,
			"tokenID", tokenID,
			"error", err)
		wrapped := fmt.Errorf("failed to revoke token: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return wrapped
	}

	if exists == 0 {
		status = "success"
		errorType = ""
		r.logger.Warn("revoke: token not found", ctx,
			"tokenID", tokenID)
		span.SetStatus(tracing.StatusOK, "")
		return nil
	}

	// ===== STEP 4: Mark Token Revoked =====
	err = r.client.HSet(ctx, tokenKey, "revoked", "true").Err()
	if err != nil {
		r.logger.Error("revoke failed: redis hset error", ctx,
			"tokenID", tokenID,
			"error", err)
		wrapped := fmt.Errorf("failed to revoke token: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return wrapped
	}

	// ===== STEP 5: Log Success =====
	status = "success"
	errorType = ""
	r.logger.Info("revoke: successfully revoked", ctx,
		"tokenID", tokenID)
	span.SetStatus(tracing.StatusOK, "")

	return nil
}

// RevokeAllForUser marks every refresh token belonging to userID as revoked.
// If the user has no tokens, the call succeeds silently. Returns
// ErrInvalidUserID if userID is empty, or the context error if the context is
// cancelled.
func (r *RedisRefreshStore) RevokeAllForUser(ctx context.Context, userID string) error {
	ctx, span := r.startSpan(ctx, "RevokeAllForUser")
	defer span.End()

	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		r.metrics.IncrementCounter(metricStorageOpsTotal, map[string]string{
			"operation":       "revoke_all",
			"status":          status,
			"error_type":      errorType,
			"storage_backend": r.backend,
		})
		r.metrics.RecordDuration(metricStorageOpDuration, time.Since(start), map[string]string{
			"operation":       "revoke_all",
			"storage_backend": r.backend,
		})
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		r.logger.Warn("revokeAllForUser aborted: context cancelled", ctx,
			"userID", userID,
			"reason", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return err
	}

	// ===== STEP 2: Validate Inputs =====
	if len(strings.TrimSpace(userID)) == 0 {
		status = "validation_error"
		errorType = "validation_error"
		r.logger.Warn("revokeAllForUser rejected: userID is empty or whitespace", ctx)
		span.RecordError(ErrInvalidUserID)
		span.SetStatus(tracing.StatusError, ErrInvalidUserID.Error())
		return ErrInvalidUserID
	}

	// ===== STEP 3: Get All Token IDs for User =====
	userSetKey := r.userSetPrefix + userID
	tokenIDs, err := r.client.SMembers(ctx, userSetKey).Result()
	if err != nil {
		r.logger.Error("revokeAllForUser failed: redis smembers error", ctx,
			"userID", userID,
			"error", err)
		wrapped := fmt.Errorf("failed to get user tokens: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return wrapped
	}

	r.logger.Debug("found tokens to revoke for user", ctx,
		"userID", userID,
		"count", len(tokenIDs))

	// ===== STEP 4: Revoke All Tokens via Pipeline =====
	if len(tokenIDs) > 0 {
		pipe := r.client.Pipeline()
		for _, tokenID := range tokenIDs {
			tokenKey := r.tokenPrefix + tokenID
			pipe.HSet(ctx, tokenKey, "revoked", "true")
		}

		_, err := pipe.Exec(ctx)
		if err != nil {
			r.logger.Error("revokeAllForUser failed: redis pipeline error", ctx,
				"userID", userID,
				"error", err)
			wrapped := fmt.Errorf("failed to revoke tokens: %w", err)
			span.RecordError(wrapped)
			span.SetStatus(tracing.StatusError, wrapped.Error())
			return wrapped
		}
	}

	// ===== STEP 5: Log Success =====
	status = "success"
	errorType = ""
	r.logger.Info("revokeAllForUser: all tokens revoked", ctx,
		"userID", userID,
		"count", len(tokenIDs))
	span.SetStatus(tracing.StatusOK, "")

	return nil
}

// Cleanup removes all expired tokens from the store and returns the count of
// removed tokens. It is safe to call concurrently with other methods and is
// typically invoked on a background ticker. Returns the context error if the
// context is cancelled.
func (r *RedisRefreshStore) Cleanup(ctx context.Context) (int, error) {
	ctx, span := r.startSpan(ctx, "Cleanup")
	defer span.End()

	start := time.Now()
	status := "error"
	errorType := "error"
	removed := 0
	remaining := 0
	defer func() {
		r.metrics.IncrementCounter(metricStorageOpsTotal, map[string]string{
			"operation":       "cleanup",
			"status":          status,
			"error_type":      errorType,
			"storage_backend": r.backend,
		})
		r.metrics.RecordDuration(metricStorageOpDuration, time.Since(start), map[string]string{
			"operation":       "cleanup",
			"storage_backend": r.backend,
		})
		if status == "success" {
			r.metrics.AddCounter(metricStorageRemovedTotal, float64(removed), map[string]string{
				"storage_backend": r.backend,
			})
			r.metrics.SetGauge(metricStorageTokensCount, float64(remaining), map[string]string{
				"storage_backend": r.backend,
			})
		}
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		r.logger.Warn("cleanup aborted: context cancelled", ctx)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return 0, err
	}

	// ===== STEP 2: Scan for Expired Tokens =====
	count := 0
	now := time.Now()
	totalScanned := 0

	iter := r.client.Scan(ctx, 0, r.tokenPrefix+"*", 0).Iterator()

	var expiredKeys []string
	for iter.Next(ctx) {
		totalScanned++
		key := iter.Val()

		hash, err := r.client.HGetAll(ctx, key).Result()
		if err != nil {
			r.logger.Error("cleanup failed: redis hgetall error", ctx,
				"key", key,
				"error", err)
			continue
		}

		expiresAtMillis, err := strconv.ParseInt(hash["expiresAt"], 10, 64)
		if err != nil {
			r.logger.Error("cleanup failed: invalid expiration timestamp", ctx,
				"key", key,
				"error", err)
			continue
		}

		expiresAt := time.UnixMilli(expiresAtMillis)
		if expiresAt.Before(now) || expiresAt.Equal(now) {
			expiredKeys = append(expiredKeys, key)

			userID := hash["userID"]
			tokenID := strings.TrimPrefix(key, r.tokenPrefix)
			userSetKey := r.userSetPrefix + userID

			_ = r.client.SRem(ctx, userSetKey, tokenID).Err()
		}
	}

	if err := iter.Err(); err != nil {
		r.logger.Error("cleanup failed: redis scan error", ctx,
			"error", err)
		wrapped := fmt.Errorf("failed to scan tokens: %w", err)
		span.RecordError(wrapped)
		span.SetStatus(tracing.StatusError, wrapped.Error())
		return 0, wrapped
	}

	// ===== STEP 3: Delete Expired Tokens =====
	if len(expiredKeys) == 0 {
		r.logger.Debug("cleanup: no expired tokens found", ctx)
	} else {
		err := r.client.Del(ctx, expiredKeys...).Err()
		if err != nil {
			r.logger.Error("cleanup failed: redis delete error", ctx,
				"count", len(expiredKeys),
				"error", err)
			wrapped := fmt.Errorf("failed to delete expired tokens: %w", err)
			span.RecordError(wrapped)
			span.SetStatus(tracing.StatusError, wrapped.Error())
			return 0, wrapped
		}
		count = len(expiredKeys)
	}
	removed = count
	remaining = totalScanned - removed

	// ===== STEP 4: Log Success =====
	status = "success"
	errorType = ""
	r.logger.Info("cleanup: successful", ctx,
		"count", count)
	span.SetAttribute("removed_count", count)
	span.SetStatus(tracing.StatusOK, "")

	return count, nil
}

// Sentinel errors for RedisRefreshStore operations.
var (
	ErrNilClient = errors.New("redis client must not be nil")
)

// Redis key prefixes
const (
	tokenKeyPrefix   = "tokens:"
	userSetKeyPrefix = "user_tokens:"
)
