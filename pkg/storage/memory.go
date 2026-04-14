package storage

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/aetomala/jwtauth/pkg/logging"
	"github.com/aetomala/jwtauth/pkg/metrics"
)

// MemoryRefreshStore is a thread-safe, in-memory implementation of the
// RefreshStore interface. It is suitable for single-instance deployments and
// testing. For multi-instance deployments, use a persistent store backed by
// Redis or a database.
//
// All methods are safe for concurrent use.
type MemoryRefreshStore struct {
	// ===== Synchronization =====
	mu sync.RWMutex

	// ===== Storage =====
	tokens     map[string]*RefreshToken // tokenID -> token
	userTokens map[string][]string      // userID  -> []tokenID

	// ===== Observability =====
	logger  logging.Logger  // Optional; nil disables logging
	metrics metrics.Metrics // Optional; nil disables metrics
	backend string          // storage_backend label value; always "memory"
}

// NewMemoryRefreshStore returns a new empty MemoryRefreshStore. Pass a
// logging.Logger for structured log output; pass nil to disable logging. Pass
// a metrics.Metrics for instrumentation; pass nil to disable metrics.
func NewMemoryRefreshStore(logger logging.Logger, m metrics.Metrics) *MemoryRefreshStore {
	store := &MemoryRefreshStore{
		tokens:     make(map[string]*RefreshToken),
		userTokens: make(map[string][]string),
		backend:    "memory",
	}
	if logger != nil {
		store.logger = logger
	}
	if m != nil {
		store.metrics = m
	}
	return store
}

// Store persists a new refresh token. Returns ErrInvalidTokenID if tokenID is
// empty, ErrInvalidUserID if userID is empty, and ErrTokenExpired if expiresAt
// is already in the past. Returns the context error if the context is
// cancelled before the write.
//
// A defensive copy of metadata is made so later mutations to the caller's map
// do not affect the stored token.
func (m *MemoryRefreshStore) Store(ctx context.Context, tokenID, userID string, expiresAt time.Time, metadata map[string]interface{}) error {
	start := time.Now()
	status := "error"
	errorType := "error"
	tokenCount := 0
	defer func() {
		if m.metrics != nil {
			m.metrics.IncrementCounter(metricStorageOpsTotal, map[string]string{
				"operation":       "store",
				"status":          status,
				"error_type":      errorType,
				"storage_backend": m.backend,
			})
			m.metrics.RecordDuration(metricStorageOpDuration, time.Since(start), map[string]string{
				"operation":       "store",
				"storage_backend": m.backend,
			})
			if status == "success" {
				m.metrics.SetGauge(metricStorageTokensCount, float64(tokenCount), map[string]string{
					"storage_backend": m.backend,
				})
			}
		}
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		if m.logger != nil {
			m.logger.Warn("store aborted: context cancelled", ctx,
				"reason", err)
		}
		return err
	}

	// ===== STEP 2: Validate Inputs =====
	if len(strings.TrimSpace(tokenID)) == 0 {
		status = "validation_error"
		errorType = "validation_error"
		if m.logger != nil {
			m.logger.Warn("store rejected: tokenID is empty or whitespace", ctx,
				"userID", userID)
		}
		return ErrInvalidTokenID
	}

	if len(strings.TrimSpace(userID)) == 0 {
		status = "validation_error"
		errorType = "validation_error"
		if m.logger != nil {
			m.logger.Warn("store rejected: userID is empty or whitespace", ctx,
				"tokenID", tokenID)
		}
		return ErrInvalidUserID
	}

	if expiresAt.Before(time.Now()) {
		status = "validation_error"
		errorType = "validation_error"
		if m.logger != nil {
			m.logger.Warn("store rejected: token is already expired", ctx,
				"tokenID", tokenID,
				"userID", userID,
				"expiresAt", expiresAt)
		}
		return ErrTokenExpired
	}

	// ===== STEP 3: Defensive Copy of Metadata =====
	var newMetadata map[string]interface{}
	if metadata != nil {
		newMetadata = make(map[string]interface{}, len(metadata))
		for k, v := range metadata {
			newMetadata[k] = v
		}
	}

	// ===== STEP 4: Acquire Write Lock =====
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.logger != nil {
		m.logger.Debug("storing token in memory", ctx,
			"tokenID", tokenID,
			"userID", userID)
	}

	// ===== STEP 5: Build and Store Token =====
	token := &RefreshToken{
		TokenID:   tokenID,
		UserID:    userID,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
		Revoked:   false,
		Metadata:  newMetadata,
	}
	m.tokens[tokenID] = token
	m.userTokens[userID] = append(m.userTokens[userID], tokenID)
	tokenCount = len(m.tokens) // captured inside the lock for gauge accuracy

	// ===== STEP 6: Log Success =====
	status = "success"
	errorType = ""
	if m.logger != nil {
		m.logger.Info("refresh token stored", ctx,
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
func (m *MemoryRefreshStore) Retrieve(ctx context.Context, tokenID string) (*RefreshToken, error) {
	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		if m.metrics != nil {
			m.metrics.IncrementCounter(metricStorageOpsTotal, map[string]string{
				"operation":       "retrieve",
				"status":          status,
				"error_type":      errorType,
				"storage_backend": m.backend,
			})
			m.metrics.RecordDuration(metricStorageOpDuration, time.Since(start), map[string]string{
				"operation":       "retrieve",
				"storage_backend": m.backend,
			})
		}
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		if m.logger != nil {
			m.logger.Warn("retrieve aborted: context cancelled", ctx,
				"tokenID", tokenID,
				"reason", err)
		}
		return nil, err
	}

	// ===== STEP 2: Validate Inputs =====
	if len(strings.TrimSpace(tokenID)) == 0 {
		status = "validation_error"
		errorType = "validation_error"
		if m.logger != nil {
			m.logger.Warn("retrieve rejected: tokenID is empty or whitespace", ctx)
		}
		return nil, ErrInvalidTokenID
	}

	// ===== STEP 3: Acquire Read Lock =====
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.logger != nil {
		m.logger.Debug("looking up token in memory", ctx,
			"tokenID", tokenID)
	}

	// ===== STEP 4: Look Up Token =====
	token, found := m.tokens[tokenID]
	if !found {
		status = "not_found"
		errorType = "not_found"
		if m.logger != nil {
			m.logger.Warn("retrieve: token not found", ctx,
				"tokenID", tokenID)
		}
		return nil, ErrTokenNotFound
	}

	// ===== STEP 5: Check Revocation =====
	if token.Revoked {
		status = "revoked"
		errorType = "revoked"
		if m.logger != nil {
			m.logger.Warn("retrieve: token has been revoked", ctx,
				"tokenID", tokenID,
				"userID", token.UserID)
		}
		return nil, ErrTokenRevoked
	}

	// ===== STEP 6: Check Expiration =====
	if token.ExpiresAt.Before(time.Now()) {
		status = "expired"
		errorType = "expired"
		if m.logger != nil {
			m.logger.Warn("retrieve: token has expired", ctx,
				"tokenID", tokenID,
				"expiredAt", token.ExpiresAt)
		}
		return nil, ErrTokenExpired
	}

	// ===== STEP 7: Return Defensive Copy =====
	safeToken := &RefreshToken{
		TokenID:   token.TokenID,
		UserID:    token.UserID,
		ExpiresAt: token.ExpiresAt,
		CreatedAt: token.CreatedAt,
		Revoked:   token.Revoked,
	}

	if token.Metadata != nil {
		safeToken.Metadata = make(map[string]interface{}, len(token.Metadata))
		for key, value := range token.Metadata {
			safeToken.Metadata[key] = value
		}
	}

	// ===== STEP 8: Log Success =====
	status = "success"
	errorType = ""
	if m.logger != nil {
		m.logger.Info("retrieve: token retrieved successfully", ctx,
			"tokenID", tokenID)
	}

	return safeToken, nil
}

// Revoke marks a refresh token as revoked. It is idempotent — if the token
// does not exist, no error is returned. Returns ErrInvalidTokenID if tokenID
// is empty, or the context error if the context is cancelled.
func (m *MemoryRefreshStore) Revoke(ctx context.Context, tokenID string) error {
	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		if m.metrics != nil {
			m.metrics.IncrementCounter(metricStorageOpsTotal, map[string]string{
				"operation":       "revoke",
				"status":          status,
				"error_type":      errorType,
				"storage_backend": m.backend,
			})
			m.metrics.RecordDuration(metricStorageOpDuration, time.Since(start), map[string]string{
				"operation":       "revoke",
				"storage_backend": m.backend,
			})
		}
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		if m.logger != nil {
			m.logger.Warn("revoke aborted: context cancelled", ctx,
				"tokenID", tokenID)
		}
		return ctx.Err()
	}

	// ===== STEP 2: Validate Inputs =====
	if len(strings.TrimSpace(tokenID)) == 0 {
		status = "validation_error"
		errorType = "validation_error"
		if m.logger != nil {
			m.logger.Warn("revoke rejected: tokenID is empty or whitespace", ctx)
		}
		return ErrInvalidTokenID
	}

	// ===== STEP 3: Acquire Write Lock =====
	m.mu.Lock()
	defer m.mu.Unlock()

	// ===== STEP 4: Look Up Token =====
	token, found := m.tokens[tokenID]
	if !found {
		status = "success" // idempotent: not-found is not an error
		errorType = ""
		if m.logger != nil {
			m.logger.Warn("revoke: token not found", ctx,
				"tokenID", tokenID)
		}
		return nil
	}

	// ===== STEP 5: Mark Revoked =====
	token.Revoked = true

	// ===== STEP 6: Log Success =====
	status = "success"
	errorType = ""
	if m.logger != nil {
		m.logger.Info("revoke: successfully revoked", ctx,
			"tokenID", tokenID)
	}

	return nil
}

// RevokeAllForUser marks every refresh token belonging to userID as revoked.
// If the user has no tokens, the call succeeds silently. Returns
// ErrInvalidUserID if userID is empty, or the context error if the context is
// cancelled.
func (m *MemoryRefreshStore) RevokeAllForUser(ctx context.Context, userID string) error {
	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		if m.metrics != nil {
			m.metrics.IncrementCounter(metricStorageOpsTotal, map[string]string{
				"operation":       "revoke_all",
				"status":          status,
				"error_type":      errorType,
				"storage_backend": m.backend,
			})
			m.metrics.RecordDuration(metricStorageOpDuration, time.Since(start), map[string]string{
				"operation":       "revoke_all",
				"storage_backend": m.backend,
			})
		}
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		if m.logger != nil {
			m.logger.Warn("revokeAllForUser aborted: context cancelled", ctx,
				"userID", userID,
				"reason", err)
		}
		return err
	}

	// ===== STEP 2: Validate Inputs =====
	if len(strings.TrimSpace(userID)) == 0 {
		status = "validation_error"
		errorType = "validation_error"
		if m.logger != nil {
			m.logger.Warn("revokeAllForUser rejected: userID is empty or whitespace", ctx)
		}
		return ErrInvalidUserID
	}

	// ===== STEP 3: Acquire Write Lock =====
	m.mu.Lock()
	defer m.mu.Unlock()

	// ===== STEP 4: Revoke All Tokens for User =====
	tokensIDs := m.userTokens[userID]
	for _, tokenID := range tokensIDs {
		if token, exists := m.tokens[tokenID]; exists {
			if m.logger != nil {
				m.logger.Debug("revoking token for user", ctx,
					"tokenID", tokenID,
					"userID", userID)
			}
			token.Revoked = true
		}
	}

	// ===== STEP 5: Log Success =====
	status = "success"
	errorType = ""
	if m.logger != nil {
		m.logger.Info("revokeAllForUser: all tokens revoked", ctx,
			"userID", userID,
			"count", len(tokensIDs))
	}

	return nil
}

// Cleanup removes all expired tokens from the store and returns the count of
// removed tokens. It is safe to call concurrently with other methods and is
// typically invoked on a background ticker. Returns the context error if the
// context is cancelled.
func (m *MemoryRefreshStore) Cleanup(ctx context.Context) (int, error) {
	start := time.Now()
	status := "error"
	errorType := "error"
	removed := 0
	remaining := 0
	defer func() {
		if m.metrics != nil {
			m.metrics.IncrementCounter(metricStorageOpsTotal, map[string]string{
				"operation":       "cleanup",
				"status":          status,
				"error_type":      errorType,
				"storage_backend": m.backend,
			})
			m.metrics.RecordDuration(metricStorageOpDuration, time.Since(start), map[string]string{
				"operation":       "cleanup",
				"storage_backend": m.backend,
			})
			if status == "success" {
				m.metrics.AddCounter(metricStorageRemovedTotal, float64(removed), map[string]string{
					"storage_backend": m.backend,
				})
				m.metrics.SetGauge(metricStorageTokensCount, float64(remaining), map[string]string{
					"storage_backend": m.backend,
				})
			}
		}
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		if m.logger != nil {
			m.logger.Warn("cleanup aborted: context cancelled", ctx)
		}
		return 0, err
	}

	// ===== STEP 2: Acquire Write Lock =====
	now := time.Now()
	count := 0
	m.mu.Lock()
	defer m.mu.Unlock()

	// ===== STEP 3: Sweep and Remove Expired Tokens =====
	for tokenID, token := range m.tokens {
		if token.ExpiresAt.Before(now) || token.ExpiresAt.Equal(now) {
			if m.logger != nil {
				m.logger.Debug("removing expired token", ctx,
					"tokenID", token.TokenID,
					"expiredAt", token.ExpiresAt)
			}
			delete(m.tokens, token.TokenID)
			m.removeFromUserTokens(token.UserID, tokenID)
			count++
		}
	}
	removed = count
	remaining = len(m.tokens)

	// ===== STEP 4: Log Success =====
	status = "success"
	errorType = ""
	if m.logger != nil {
		m.logger.Info("cleanup: successful", ctx,
			"count", count)
	}

	return count, nil
}

func (m *MemoryRefreshStore) removeFromUserTokens(userID, tokenID string) {
	tokenIDs := m.userTokens[userID]

	// Remove tokenID from the slice
	for i, tid := range tokenIDs {
		if tid == tokenID {
			// Remove by swapping with last element and truncating
			tokenIDs[i] = tokenIDs[len(tokenIDs)-1]
			m.userTokens[userID] = tokenIDs[:len(tokenIDs)-1]
			break
		}
	}

	// If user has no tokens left, remove their entry
	if len(m.userTokens[userID]) == 0 {
		delete(m.userTokens, userID)
	}
}
