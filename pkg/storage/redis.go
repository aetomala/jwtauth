package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/aetomala/jwtauth/pkg/logging"
	"github.com/aetomala/jwtauth/pkg/metrics"
)

// RedisRefreshStore is a thread-safe, persistent implementation of the
// RefreshStore interface backed by Redis. It is suitable for multi-instance
// deployments where refresh tokens must be shared across application instances.
// For single-instance deployments or testing, use MemoryRefreshStore.
//
// All methods are safe for concurrent use.
type RedisRefreshStore struct {
	// ===== Synchronization =====
	// Redis client (internally thread-safe)
	client *redis.Client

	// ===== Observability =====
	logger  logging.Logger  // Optional; nil disables logging
	metrics metrics.Metrics // Optional; nil disables metrics
	backend string          // storage_backend label value; always "redis"
}

// NewRedisRefreshStore returns a new RedisRefreshStore using the provided
// Redis client. Pass a logging.Logger for structured log output; pass nil
// to disable logging. Pass a metrics.Metrics for instrumentation; pass nil
// to disable metrics.
func NewRedisRefreshStore(client *redis.Client, logger logging.Logger, m metrics.Metrics) *RedisRefreshStore {
	r := &RedisRefreshStore{
		client:  client,
		backend: "redis",
	}
	if logger != nil {
		r.logger = logger
	}
	if m != nil {
		r.metrics = m
	}
	return r
}

// Store persists a new refresh token. Returns ErrInvalidTokenID if tokenID is
// empty, ErrInvalidUserID if userID is empty, and ErrTokenExpired if expiresAt
// is already in the past. Returns the context error if the context is
// cancelled before the write.
//
// A defensive copy of metadata is made so later mutations to the caller's map
// do not affect the stored token.
func (r *RedisRefreshStore) Store(ctx context.Context, tokenID, userID string, expiresAt time.Time, metadata map[string]interface{}) error {
	start := time.Now()
	status := "error"
	defer func() {
		if r.metrics != nil {
			r.metrics.IncrementCounter(metricStorageOpsTotal, map[string]string{
				"operation":       "store",
				"status":          status,
				"storage_backend": r.backend,
			})
			r.metrics.RecordDuration(metricStorageOpDuration, time.Since(start), map[string]string{
				"operation":       "store",
				"storage_backend": r.backend,
			})
		}
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		if r.logger != nil {
			r.logger.Warn("store aborted: context cancelled",
				"reason", err)
		}
		return err
	}

	// ===== STEP 2: Validate Inputs =====
	if len(strings.TrimSpace(tokenID)) == 0 {
		status = "validation_error"
		if r.logger != nil {
			r.logger.Warn("store rejected: tokenID is empty or whitespace",
				"userID", userID)
		}
		return ErrInvalidTokenID
	}

	if len(strings.TrimSpace(userID)) == 0 {
		status = "validation_error"
		if r.logger != nil {
			r.logger.Warn("store rejected: userID is empty or whitespace",
				"tokenID", tokenID)
		}
		return ErrInvalidUserID
	}

	if expiresAt.Before(time.Now()) || expiresAt.Equal(time.Now()) {
		status = "validation_error"
		if r.logger != nil {
			r.logger.Warn("store rejected: token is already expired",
				"tokenID", tokenID,
				"userID", userID,
				"expiresAt", expiresAt)
		}
		return ErrTokenExpired
	}

	// ===== STEP 3: Prepare Metadata (Defensive Copy) =====
	var metadataJSON string
	if metadata != nil {
		// Prevent mutation of the map by creating a copy before marshaling
		metadataCopy := make(map[string]interface{}, len(metadata))
		for k, v := range metadata {
			metadataCopy[k] = v
		}

		jsonBytes, err := json.Marshal(metadataCopy)
		if err != nil {
			if r.logger != nil {
				r.logger.Error("store failed: metadata marshal error",
					"tokenID", tokenID,
					"error", err)
			}
			return fmt.Errorf("failed to marshal metadata: %w", err)
		}
		metadataJSON = string(jsonBytes)
	}

	// ===== STEP 4: Acquire Write Lock (via Redis Pipeline) =====
	// Build token data map for Redis hash
	now := time.Now()
	tokenData := map[string]interface{}{
		"userID":    userID,
		"expiresAt": expiresAt.UnixMilli(),
		"createdAt": now.UnixMilli(),
		"revoked":   "false",
		"metadata":  metadataJSON,
	}

	// ===== STEP 5: Execute Atomic Write via Pipeline =====
	tokenKey := tokenKeyPrefix + tokenID
	userSetKey := userSetKeyPrefix + userID
	duration := time.Until(expiresAt)

	pipe := r.client.Pipeline()
	pipe.HSet(ctx, tokenKey, tokenData)
	pipe.SAdd(ctx, userSetKey, tokenID)
	pipe.Expire(ctx, tokenKey, duration)

	if r.logger != nil {
		r.logger.Debug("executing redis pipeline for token store",
			"tokenID", tokenID,
			"userID", userID)
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		if r.logger != nil {
			r.logger.Error("store failed: redis pipeline error",
				"tokenID", tokenID,
				"error", err)
		}
		return fmt.Errorf("failed to store token: %w", err)
	}

	// ===== STEP 6: Log Success =====
	status = "success"
	if r.logger != nil {
		r.logger.Info("refresh token stored",
			"tokenID", tokenID,
			"userID", userID,
			"expiresAt", expiresAt)
	}

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
	start := time.Now()
	status := "error"
	defer func() {
		if r.metrics != nil {
			r.metrics.IncrementCounter(metricStorageOpsTotal, map[string]string{
				"operation":       "retrieve",
				"status":          status,
				"storage_backend": r.backend,
			})
			r.metrics.RecordDuration(metricStorageOpDuration, time.Since(start), map[string]string{
				"operation":       "retrieve",
				"storage_backend": r.backend,
			})
		}
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		if r.logger != nil {
			r.logger.Warn("retrieve aborted: context cancelled",
				"tokenID", tokenID,
				"reason", err)
		}
		return nil, err
	}

	// ===== STEP 2: Validate Inputs =====
	if len(strings.TrimSpace(tokenID)) == 0 {
		status = "validation_error"
		if r.logger != nil {
			r.logger.Warn("retrieve rejected: tokenID is empty or whitespace")
		}
		return nil, ErrInvalidTokenID
	}

	// ===== STEP 3: Look Up Token from Redis =====
	tokenKey := tokenKeyPrefix + tokenID
	hash, err := r.client.HGetAll(ctx, tokenKey).Result()
	if err != nil {
		if r.logger != nil {
			r.logger.Error("retrieve failed: redis error",
				"tokenID", tokenID,
				"error", err)
		}
		return nil, fmt.Errorf("failed to retrieve token: %w", err)
	}

	if r.logger != nil {
		r.logger.Debug("redis hash retrieved",
			"tokenID", tokenID,
			"fieldCount", len(hash))
	}

	// ===== STEP 4: Check if Token Exists =====
	if len(hash) == 0 {
		status = "not_found"
		if r.logger != nil {
			r.logger.Warn("retrieve: token not found",
				"tokenID", tokenID)
		}
		return nil, ErrTokenNotFound
	}

	// ===== STEP 5: Check Revocation =====
	revoked := hash["revoked"] == "true"
	if revoked {
		status = "revoked"
		if r.logger != nil {
			r.logger.Warn("retrieve: token has been revoked",
				"tokenID", tokenID,
				"userID", hash["userID"])
		}
		return nil, ErrTokenRevoked
	}

	// ===== STEP 6: Check Expiration =====
	expiresAtMillis, err := strconv.ParseInt(hash["expiresAt"], 10, 64)
	if err != nil {
		if r.logger != nil {
			r.logger.Error("retrieve failed: invalid expiration timestamp",
				"tokenID", tokenID,
				"error", err)
		}
		return nil, fmt.Errorf("invalid expiration timestamp: %w", err)
	}

	expiresAt := time.UnixMilli(expiresAtMillis)
	if expiresAt.Before(time.Now()) {
		status = "expired"
		if r.logger != nil {
			r.logger.Warn("retrieve: token has expired",
				"tokenID", tokenID,
				"expiredAt", expiresAt)
		}
		return nil, ErrTokenExpired
	}

	// ===== STEP 7: Unmarshal and Return Defensive Copy =====
	createdAtMillis, err := strconv.ParseInt(hash["createdAt"], 10, 64)
	if err != nil {
		if r.logger != nil {
			r.logger.Error("retrieve failed: invalid creation timestamp",
				"tokenID", tokenID,
				"error", err)
		}
		return nil, fmt.Errorf("invalid creation timestamp: %w", err)
	}

	createdAt := time.UnixMilli(createdAtMillis)

	// Return defensive copy to prevent external mutation
	safeToken := &RefreshToken{
		TokenID:   tokenID,
		UserID:    hash["userID"],
		ExpiresAt: expiresAt,
		CreatedAt: createdAt,
		Revoked:   revoked,
	}

	// Unmarshal metadata if present
	if metadataJSON, exists := hash["metadata"]; exists && metadataJSON != "" {
		var metadata map[string]interface{}
		if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
			if r.logger != nil {
				r.logger.Error("retrieve failed: metadata unmarshal error",
					"tokenID", tokenID,
					"error", err)
			}
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
		safeToken.Metadata = metadata
	}

	// ===== STEP 8: Log Success =====
	status = "success"
	if r.logger != nil {
		r.logger.Info("retrieve: token retrieved successfully",
			"tokenID", tokenID)
	}

	return safeToken, nil
}

// Revoke marks a refresh token as revoked. It is idempotent — if the token
// does not exist, no error is returned. Returns ErrInvalidTokenID if tokenID
// is empty, or the context error if the context is cancelled.
func (r *RedisRefreshStore) Revoke(ctx context.Context, tokenID string) error {
	start := time.Now()
	status := "error"
	defer func() {
		if r.metrics != nil {
			r.metrics.IncrementCounter(metricStorageOpsTotal, map[string]string{
				"operation":       "revoke",
				"status":          status,
				"storage_backend": r.backend,
			})
			r.metrics.RecordDuration(metricStorageOpDuration, time.Since(start), map[string]string{
				"operation":       "revoke",
				"storage_backend": r.backend,
			})
		}
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		if r.logger != nil {
			r.logger.Warn("revoke aborted: context cancelled",
				"tokenID", tokenID)
		}
		return ctx.Err()
	}

	// ===== STEP 2: Validate Inputs =====
	if len(strings.TrimSpace(tokenID)) == 0 {
		status = "validation_error"
		if r.logger != nil {
			r.logger.Warn("revoke rejected: tokenID is empty or whitespace")
		}
		return ErrInvalidTokenID
	}

	// ===== STEP 3: Mark Revoked in Redis =====
	tokenKey := tokenKeyPrefix + tokenID

	// Check if token exists first (for logging purposes)
	exists, err := r.client.Exists(ctx, tokenKey).Result()
	if err != nil {
		if r.logger != nil {
			r.logger.Error("revoke failed: redis error",
				"tokenID", tokenID,
				"error", err)
		}
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	if exists == 0 {
		// Expected to be idempotent; thus, return nil
		status = "success" // idempotent: not-found is not an error
		if r.logger != nil {
			r.logger.Warn("revoke: token not found",
				"tokenID", tokenID)
		}
		return nil
	}

	// ===== STEP 4: Update Token =====
	err = r.client.HSet(ctx, tokenKey, "revoked", "true").Err()
	if err != nil {
		if r.logger != nil {
			r.logger.Error("revoke failed: redis hset error",
				"tokenID", tokenID,
				"error", err)
		}
		return fmt.Errorf("failed to revoke token: %w", err)
	}

	// ===== STEP 5: Log Success =====
	status = "success"
	if r.logger != nil {
		r.logger.Info("revoke: successfully revoked",
			"tokenID", tokenID)
	}

	return nil
}

// RevokeAllForUser marks every refresh token belonging to userID as revoked.
// If the user has no tokens, the call succeeds silently. Returns
// ErrInvalidUserID if userID is empty, or the context error if the context is
// cancelled.
func (r *RedisRefreshStore) RevokeAllForUser(ctx context.Context, userID string) error {
	start := time.Now()
	status := "error"
	defer func() {
		if r.metrics != nil {
			r.metrics.IncrementCounter(metricStorageOpsTotal, map[string]string{
				"operation":       "revoke_all",
				"status":          status,
				"storage_backend": r.backend,
			})
			r.metrics.RecordDuration(metricStorageOpDuration, time.Since(start), map[string]string{
				"operation":       "revoke_all",
				"storage_backend": r.backend,
			})
		}
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		if r.logger != nil {
			r.logger.Warn("revokeAllForUser aborted: context cancelled",
				"userID", userID,
				"reason", err)
		}
		return err
	}

	// ===== STEP 2: Validate Inputs =====
	if len(strings.TrimSpace(userID)) == 0 {
		status = "validation_error"
		if r.logger != nil {
			r.logger.Warn("revokeAllForUser rejected: userID is empty or whitespace")
		}
		return ErrInvalidUserID
	}

	// ===== STEP 3: Get All Token IDs for User =====
	userSetKey := userSetKeyPrefix + userID
	tokenIDs, err := r.client.SMembers(ctx, userSetKey).Result()
	if err != nil {
		if r.logger != nil {
			r.logger.Error("revokeAllForUser failed: redis smembers error",
				"userID", userID,
				"error", err)
		}
		return fmt.Errorf("failed to get user tokens: %w", err)
	}

	if r.logger != nil {
		r.logger.Debug("found tokens to revoke for user",
			"userID", userID,
			"count", len(tokenIDs))
	}

	// ===== STEP 4: Revoke All Tokens for User =====
	if len(tokenIDs) > 0 {
		// Use pipeline for efficiency
		pipe := r.client.Pipeline()
		for _, tokenID := range tokenIDs {
			tokenKey := tokenKeyPrefix + tokenID
			pipe.HSet(ctx, tokenKey, "revoked", "true")
		}

		_, err := pipe.Exec(ctx)
		if err != nil {
			if r.logger != nil {
				r.logger.Error("revokeAllForUser failed: redis pipeline error",
					"userID", userID,
					"error", err)
			}
			return fmt.Errorf("failed to revoke tokens: %w", err)
		}
	}

	// ===== STEP 5: Log Success =====
	status = "success"
	if r.logger != nil {
		r.logger.Info("revokeAllForUser: all tokens revoked",
			"userID", userID,
			"count", len(tokenIDs))
	}

	return nil
}

// Cleanup removes all expired tokens from the store and returns the count of
// removed tokens. It is safe to call concurrently with other methods and is
// typically invoked on a background ticker. Returns the context error if the
// context is cancelled.
func (r *RedisRefreshStore) Cleanup(ctx context.Context) (int, error) {
	start := time.Now()
	status := "error"
	removed := 0
	remaining := 0
	defer func() {
		if r.metrics != nil {
			r.metrics.IncrementCounter(metricStorageOpsTotal, map[string]string{
				"operation":       "cleanup",
				"status":          status,
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
		}
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		if r.logger != nil {
			r.logger.Warn("cleanup aborted: context cancelled")
		}
		return 0, err
	}

	// ===== STEP 2: Scan and Remove Expired Tokens =====
	count := 0
	now := time.Now()
	totalScanned := 0

	// Use SCAN to iterate over all token keys efficiently
	iter := r.client.Scan(ctx, 0, tokenKeyPrefix+"*", 0).Iterator()

	var expiredKeys []string
	for iter.Next(ctx) {
		totalScanned++
		key := iter.Val()

		// Get the expiration time
		hash, err := r.client.HGetAll(ctx, key).Result()
		if err != nil {
			if r.logger != nil {
				r.logger.Error("cleanup failed: redis hgetall error",
					"key", key,
					"error", err)
			}
			continue
		}

		expiresAtMillis, err := strconv.ParseInt(hash["expiresAt"], 10, 64)
		if err != nil {
			if r.logger != nil {
				r.logger.Error("cleanup failed: invalid expiration timestamp",
					"key", key,
					"error", err)
			}
			continue
		}

		expiresAt := time.UnixMilli(expiresAtMillis)
		if expiresAt.Before(now) || expiresAt.Equal(now) {
			expiredKeys = append(expiredKeys, key)

			// Also remove from user token set
			userID := hash["userID"]
			tokenID := strings.TrimPrefix(key, tokenKeyPrefix)
			userSetKey := userSetKeyPrefix + userID

			_ = r.client.SRem(ctx, userSetKey, tokenID).Err()
		}
	}

	if err := iter.Err(); err != nil {
		if r.logger != nil {
			r.logger.Error("cleanup failed: redis scan error",
				"error", err)
		}
		return 0, fmt.Errorf("failed to scan tokens: %w", err)
	}

	// ===== STEP 3: Delete Expired Tokens =====
	if len(expiredKeys) == 0 {
		if r.logger != nil {
			r.logger.Debug("cleanup: no expired tokens found")
		}
	} else {
		err := r.client.Del(ctx, expiredKeys...).Err()
		if err != nil {
			if r.logger != nil {
				r.logger.Error("cleanup failed: redis delete error",
					"count", len(expiredKeys),
					"error", err)
			}
			return 0, fmt.Errorf("failed to delete expired tokens: %w", err)
		}
		count = len(expiredKeys)
	}
	removed = count
	remaining = totalScanned - removed

	// ===== STEP 4: Log Success =====
	status = "success"
	if r.logger != nil {
		r.logger.Info("cleanup: successful",
			"count", count)
	}

	return count, nil
}

// Redis key prefixes
const (
	tokenKeyPrefix   = "tokens:"
	userSetKeyPrefix = "user_tokens:"
)
