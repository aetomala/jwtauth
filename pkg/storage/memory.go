package storage

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aetomala/jwtauth/pkg/logging"
	"github.com/aetomala/jwtauth/pkg/metrics"
	"github.com/aetomala/jwtauth/pkg/tracing"
)

var _ RefreshStore = (*MemoryRefreshStore)(nil)

// MemoryRefreshStoreConfig holds configuration for a MemoryRefreshStore instance.
type MemoryRefreshStoreConfig struct {
	Logger  logging.Logger  // Optional; nil defaults to NoOpLogger.
	Metrics metrics.Metrics // Optional; nil defaults to NoOpMetrics.
	Tracer  tracing.Tracer  // Optional; nil defaults to NoOpTracer.
}

// MemoryRefreshStoreConfigDefault returns a MemoryRefreshStoreConfig with
// sensible defaults. NewMemoryRefreshStore applies these automatically for any
// nil fields.
func MemoryRefreshStoreConfigDefault() MemoryRefreshStoreConfig {
	return MemoryRefreshStoreConfig{
		Logger:  &logging.NoOpLogger{},
		Metrics: metrics.NewNoOpMetrics(),
		Tracer:  tracing.NewNoOpTracer(),
	}
}

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
	tokens         map[string]*RefreshToken // tokenID  -> token
	userTokens     map[string][]string      // userID   -> []tokenID
	audienceTokens map[string][]string      // audience -> []tokenID

	// ===== Observability =====
	logger  logging.Logger  // never nil; defaults to NoOpLogger
	metrics metrics.Metrics // never nil; defaults to NoOpMetrics
	tracer  tracing.Tracer  // never nil; defaults to NoOpTracer
	backend string          // storage_backend label value; always "memory"
}

// NewMemoryRefreshStore returns a new empty MemoryRefreshStore using cfg.
// Zero-value and nil fields are filled with defaults from
// MemoryRefreshStoreConfigDefault.
func NewMemoryRefreshStore(cfg MemoryRefreshStoreConfig) *MemoryRefreshStore {
	// ===== Apply Defaults =====
	defaults := MemoryRefreshStoreConfigDefault()
	if cfg.Logger == nil {
		cfg.Logger = defaults.Logger
	}
	if cfg.Metrics == nil {
		cfg.Metrics = defaults.Metrics
	}
	if cfg.Tracer == nil {
		cfg.Tracer = defaults.Tracer
	}

	return &MemoryRefreshStore{
		tokens:         make(map[string]*RefreshToken),
		userTokens:     make(map[string][]string),
		audienceTokens: make(map[string][]string),
		logger:         cfg.Logger,
		metrics:        cfg.Metrics,
		tracer:         cfg.Tracer,
		backend:        "memory",
	}
}

// Namespace returns empty string — MemoryRefreshStore is development-only and
// does not support multi-tenant namespace isolation.
func (m *MemoryRefreshStore) Namespace() string { return "" }

// startSpan starts a new span for the given operation name, pre-seeded with
// the storage.backend attribute.
func (m *MemoryRefreshStore) startSpan(ctx context.Context, operation string) (context.Context, tracing.Span) {
	return m.tracer.Start(ctx, "MemoryRefreshStore."+operation,
		tracing.WithAttributes(map[string]any{"storage.backend": m.backend}),
	)
}

// Store persists a new refresh token. Returns ErrInvalidTokenID if tokenID is
// empty, ErrInvalidUserID if userID is empty, and ErrTokenExpired if expiresAt
// is already in the past. Returns the context error if the context is
// cancelled before the write.
//
// A defensive copy of metadata and audience is made so later mutations to the
// caller's slices or maps do not affect the stored token.
func (m *MemoryRefreshStore) Store(ctx context.Context, tokenID, userID string, audience []string, expiresAt time.Time, metadata map[string]interface{}) error {
	ctx, span := m.startSpan(ctx, "Store")
	defer span.End()
	span.SetAttribute("token_id", tokenID)

	start := time.Now()
	status := "error"
	errorType := "error"
	tokenCount := 0
	defer func() {
		m.metrics.IncrementCounter(metricStorageOpsTotal, map[string]string{
			"operation":       "store",
			"status":          status,
			"error_type":      errorType,
			"storage_backend": m.backend,
			"namespace":       "",
		})
		m.metrics.RecordDuration(metricStorageOpDuration, time.Since(start), map[string]string{
			"operation":       "store",
			"storage_backend": m.backend,
			"namespace":       "",
		})
		if status == "success" {
			m.metrics.SetGauge(metricStorageTokensCount, float64(tokenCount), map[string]string{
				"storage_backend": m.backend,
				"namespace":       "",
			})
		}
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		m.logger.Warn("store aborted: context cancelled", ctx,
			"reason", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return err
	}

	// ===== STEP 2: Validate Inputs =====
	if len(strings.TrimSpace(tokenID)) == 0 {
		status = "validation_error"
		errorType = "validation_error"
		m.logger.Warn("store rejected: tokenID is empty or whitespace", ctx,
			"userID", userID)
		span.RecordError(ErrInvalidTokenID)
		span.SetStatus(tracing.StatusError, ErrInvalidTokenID.Error())
		return ErrInvalidTokenID
	}

	if len(strings.TrimSpace(userID)) == 0 {
		status = "validation_error"
		errorType = "validation_error"
		m.logger.Warn("store rejected: userID is empty or whitespace", ctx,
			"tokenID", tokenID)
		span.RecordError(ErrInvalidUserID)
		span.SetStatus(tracing.StatusError, ErrInvalidUserID.Error())
		return ErrInvalidUserID
	}

	if expiresAt.Before(time.Now()) {
		status = "validation_error"
		errorType = "validation_error"
		m.logger.Warn("store rejected: token is already expired", ctx,
			"tokenID", tokenID,
			"userID", userID,
			"expiresAt", expiresAt)
		span.RecordError(ErrTokenExpired)
		span.SetStatus(tracing.StatusError, ErrTokenExpired.Error())
		return ErrTokenExpired
	}

	// ===== STEP 3: Defensive Copies of Audience and Metadata =====
	var audienceCopy []string
	if len(audience) > 0 {
		audienceCopy = make([]string, len(audience))
		copy(audienceCopy, audience)
	}

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

	m.logger.Debug("storing token in memory", ctx,
		"tokenID", tokenID,
		"userID", userID)

	// ===== STEP 5: Build and Store Token =====
	token := &RefreshToken{
		TokenID:   tokenID,
		UserID:    userID,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
		Revoked:   false,
		Audience:  audienceCopy,
		Metadata:  newMetadata,
	}
	m.tokens[tokenID] = token
	m.userTokens[userID] = append(m.userTokens[userID], tokenID)
	for _, aud := range token.Audience {
		m.audienceTokens[aud] = append(m.audienceTokens[aud], tokenID)
	}
	tokenCount = len(m.tokens) // captured inside the lock for gauge accuracy

	// ===== STEP 6: Log Success =====
	status = "success"
	errorType = ""
	m.logger.Info("refresh token stored", ctx,
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
func (m *MemoryRefreshStore) Retrieve(ctx context.Context, tokenID string) (*RefreshToken, error) {
	ctx, span := m.startSpan(ctx, "Retrieve")
	defer span.End()
	span.SetAttribute("token_id", tokenID)

	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		m.metrics.IncrementCounter(metricStorageOpsTotal, map[string]string{
			"operation":       "retrieve",
			"status":          status,
			"error_type":      errorType,
			"storage_backend": m.backend,
			"namespace":       "",
		})
		m.metrics.RecordDuration(metricStorageOpDuration, time.Since(start), map[string]string{
			"operation":       "retrieve",
			"storage_backend": m.backend,
			"namespace":       "",
		})
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		m.logger.Warn("retrieve aborted: context cancelled", ctx,
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
		m.logger.Warn("retrieve rejected: tokenID is empty or whitespace", ctx)
		span.RecordError(ErrInvalidTokenID)
		span.SetStatus(tracing.StatusError, ErrInvalidTokenID.Error())
		return nil, ErrInvalidTokenID
	}

	// ===== STEP 3: Acquire Read Lock =====
	m.mu.RLock()
	defer m.mu.RUnlock()

	m.logger.Debug("looking up token in memory", ctx,
		"tokenID", tokenID)

	// ===== STEP 4: Look Up Token =====
	token, found := m.tokens[tokenID]
	if !found {
		status = "not_found"
		errorType = "not_found"
		m.logger.Warn("retrieve: token not found", ctx,
			"tokenID", tokenID)
		span.RecordError(ErrTokenNotFound)
		span.SetStatus(tracing.StatusError, ErrTokenNotFound.Error())
		return nil, ErrTokenNotFound
	}

	// ===== STEP 5: Check Revocation =====
	if token.Revoked {
		status = "revoked"
		errorType = "revoked"
		m.logger.Warn("retrieve: token has been revoked", ctx,
			"tokenID", tokenID,
			"userID", token.UserID)
		span.RecordError(ErrTokenRevoked)
		span.SetStatus(tracing.StatusError, ErrTokenRevoked.Error())
		return nil, ErrTokenRevoked
	}

	// ===== STEP 6: Check Expiration =====
	if token.ExpiresAt.Before(time.Now()) {
		status = "expired"
		errorType = "expired"
		m.logger.Warn("retrieve: token has expired", ctx,
			"tokenID", tokenID,
			"expiredAt", token.ExpiresAt)
		span.RecordError(ErrTokenExpired)
		span.SetStatus(tracing.StatusError, ErrTokenExpired.Error())
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

	if len(token.Audience) > 0 {
		safeToken.Audience = make([]string, len(token.Audience))
		copy(safeToken.Audience, token.Audience)
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
	m.logger.Info("retrieve: token retrieved successfully", ctx,
		"tokenID", tokenID)
	span.SetStatus(tracing.StatusOK, "")

	return safeToken, nil
}

// Revoke marks a refresh token as revoked. It is idempotent — if the token
// does not exist, no error is returned. Returns ErrInvalidTokenID if tokenID
// is empty, or the context error if the context is cancelled.
func (m *MemoryRefreshStore) Revoke(ctx context.Context, tokenID string) error {
	ctx, span := m.startSpan(ctx, "Revoke")
	defer span.End()
	span.SetAttribute("token_id", tokenID)

	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		m.metrics.IncrementCounter(metricStorageOpsTotal, map[string]string{
			"operation":       "revoke",
			"status":          status,
			"error_type":      errorType,
			"storage_backend": m.backend,
			"namespace":       "",
		})
		m.metrics.RecordDuration(metricStorageOpDuration, time.Since(start), map[string]string{
			"operation":       "revoke",
			"storage_backend": m.backend,
			"namespace":       "",
		})
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		m.logger.Warn("revoke aborted: context cancelled", ctx,
			"tokenID", tokenID)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return ctx.Err()
	}

	// ===== STEP 2: Validate Inputs =====
	if len(strings.TrimSpace(tokenID)) == 0 {
		status = "validation_error"
		errorType = "validation_error"
		m.logger.Warn("revoke rejected: tokenID is empty or whitespace", ctx)
		span.RecordError(ErrInvalidTokenID)
		span.SetStatus(tracing.StatusError, ErrInvalidTokenID.Error())
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
		m.logger.Warn("revoke: token not found", ctx,
			"tokenID", tokenID)
		span.SetStatus(tracing.StatusOK, "")
		return nil
	}

	// ===== STEP 5: Mark Revoked =====
	token.Revoked = true

	// ===== STEP 6: Log Success =====
	status = "success"
	errorType = ""
	m.logger.Info("revoke: successfully revoked", ctx,
		"tokenID", tokenID)
	span.SetStatus(tracing.StatusOK, "")

	return nil
}

// RevokeAllForUser marks every refresh token belonging to userID as revoked.
// If the user has no tokens, the call succeeds silently. Returns
// ErrInvalidUserID if userID is empty, or the context error if the context is
// cancelled.
func (m *MemoryRefreshStore) RevokeAllForUser(ctx context.Context, userID string) error {
	ctx, span := m.startSpan(ctx, "RevokeAllForUser")
	defer span.End()

	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		m.metrics.IncrementCounter(metricStorageOpsTotal, map[string]string{
			"operation":       "revoke_all",
			"status":          status,
			"error_type":      errorType,
			"storage_backend": m.backend,
			"namespace":       "",
		})
		m.metrics.RecordDuration(metricStorageOpDuration, time.Since(start), map[string]string{
			"operation":       "revoke_all",
			"storage_backend": m.backend,
			"namespace":       "",
		})
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		m.logger.Warn("revokeAllForUser aborted: context cancelled", ctx,
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
		m.logger.Warn("revokeAllForUser rejected: userID is empty or whitespace", ctx)
		span.RecordError(ErrInvalidUserID)
		span.SetStatus(tracing.StatusError, ErrInvalidUserID.Error())
		return ErrInvalidUserID
	}

	// ===== STEP 3: Acquire Write Lock =====
	m.mu.Lock()
	defer m.mu.Unlock()

	// ===== STEP 4: Revoke All Tokens for User =====
	tokensIDs := m.userTokens[userID]
	for _, tokenID := range tokensIDs {
		if token, exists := m.tokens[tokenID]; exists {
			m.logger.Debug("revoking token for user", ctx,
				"tokenID", tokenID,
				"userID", userID)
			token.Revoked = true
		}
	}

	// ===== STEP 5: Log Success =====
	status = "success"
	errorType = ""
	m.logger.Info("revokeAllForUser: all tokens revoked", ctx,
		"userID", userID,
		"count", len(tokensIDs))
	span.SetStatus(tracing.StatusOK, "")

	return nil
}

// Cleanup removes all expired tokens from the store and returns the count of
// removed tokens. It is safe to call concurrently with other methods and is
// typically invoked on a background ticker. Returns the context error if the
// context is cancelled.
func (m *MemoryRefreshStore) Cleanup(ctx context.Context) (int, error) {
	ctx, span := m.startSpan(ctx, "Cleanup")
	defer span.End()

	start := time.Now()
	status := "error"
	errorType := "error"
	removed := 0
	remaining := 0
	defer func() {
		m.metrics.IncrementCounter(metricStorageOpsTotal, map[string]string{
			"operation":       "cleanup",
			"status":          status,
			"error_type":      errorType,
			"storage_backend": m.backend,
			"namespace":       "",
		})
		m.metrics.RecordDuration(metricStorageOpDuration, time.Since(start), map[string]string{
			"operation":       "cleanup",
			"storage_backend": m.backend,
			"namespace":       "",
		})
		if status == "success" {
			m.metrics.AddCounter(metricStorageRemovedTotal, float64(removed), map[string]string{
				"storage_backend": m.backend,
				"namespace":       "",
			})
			m.metrics.SetGauge(metricStorageTokensCount, float64(remaining), map[string]string{
				"storage_backend": m.backend,
				"namespace":       "",
			})
		}
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		m.logger.Warn("cleanup aborted: context cancelled", ctx)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
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
			m.logger.Debug("removing expired token", ctx,
				"tokenID", token.TokenID,
				"expiredAt", token.ExpiresAt)
			delete(m.tokens, token.TokenID)
			m.removeFromUserTokens(token.UserID, tokenID)
			m.removeFromAudienceTokens(token.Audience, tokenID)
			count++
		}
	}
	removed = count
	remaining = len(m.tokens)

	// ===== STEP 4: Log Success =====
	status = "success"
	errorType = ""
	m.logger.Info("cleanup: successful", ctx,
		"count", count)
	span.SetStatus(tracing.StatusOK, "")

	return count, nil
}

// ListTokens returns a page of refresh tokens starting from cursor. Pass an
// empty string for cursor to begin from the start. Returns the next cursor and
// a nil error on success. Returns an empty next cursor when iteration is
// exhausted.
//
// All tokens are returned regardless of revocation or expiry status — the
// caller is responsible for filtering. Cursor semantics are best-effort: a
// non-empty cursor resumes after the last token ID seen on the previous page.
// Returns the context error if the context is cancelled.
func (m *MemoryRefreshStore) ListTokens(ctx context.Context, cursor string, count int) ([]*RefreshToken, string, error) {
	ctx, span := m.startSpan(ctx, "ListTokens")
	defer span.End()
	span.SetAttribute("storage.cursor", cursor)
	span.SetAttribute("storage.count", count)

	start := time.Now()
	errorType := "error"
	resultCount := 0
	defer func() {
		m.metrics.IncrementCounter(metricListTokensTotal, map[string]string{
			"storage_backend": m.backend,
			"namespace":       "",
			"error_type":      errorType,
		})
		m.metrics.RecordDuration(metricListTokensDuration, time.Since(start), map[string]string{
			"storage_backend": m.backend,
			"namespace":       "",
		})
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		errorType = "cancelled"
		m.logger.Warn("listTokens aborted: context cancelled", ctx, "reason", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return nil, "", err
	}

	// ===== STEP 2: Acquire Read Lock and Snapshot =====
	m.mu.RLock()
	defer m.mu.RUnlock()

	// ===== STEP 3: Sort Token IDs for Stable Iteration =====
	tokenIDs := make([]string, 0, len(m.tokens))
	for id := range m.tokens {
		tokenIDs = append(tokenIDs, id)
	}
	sort.Strings(tokenIDs)

	// ===== STEP 4: Advance Past Cursor =====
	start2 := 0
	if cursor != "" {
		for i, id := range tokenIDs {
			if id > cursor {
				start2 = i
				break
			}
			// cursor was the last element — exhausted
			start2 = len(tokenIDs)
		}
	}

	// ===== STEP 5: Build Page =====
	end := start2 + count
	if count <= 0 || end > len(tokenIDs) {
		end = len(tokenIDs)
	}
	page := tokenIDs[start2:end]

	tokens := make([]*RefreshToken, 0, len(page))
	for _, id := range page {
		t := m.tokens[id]
		cp := &RefreshToken{
			TokenID:   t.TokenID,
			UserID:    t.UserID,
			ExpiresAt: t.ExpiresAt,
			CreatedAt: t.CreatedAt,
			Revoked:   t.Revoked,
		}
		if len(t.Audience) > 0 {
			cp.Audience = make([]string, len(t.Audience))
			copy(cp.Audience, t.Audience)
		}
		if t.Metadata != nil {
			cp.Metadata = make(map[string]interface{}, len(t.Metadata))
			for k, v := range t.Metadata {
				cp.Metadata[k] = v
			}
		}
		tokens = append(tokens, cp)
	}

	// ===== STEP 6: Compute Next Cursor =====
	nextCursor := ""
	if end < len(tokenIDs) {
		nextCursor = tokenIDs[end-1]
	}

	// ===== STEP 7: Log and Return =====
	errorType = ""
	resultCount = len(tokens)
	span.SetAttribute("storage.result_count", resultCount)
	span.SetStatus(tracing.StatusOK, "")
	m.logger.Info("listTokens: page returned", ctx,
		"result_count", resultCount,
		"next_cursor", nextCursor)

	return tokens, nextCursor, nil
}

// ListTokensForUser returns a page of refresh tokens belonging to userID
// starting from cursor. Pass an empty string for cursor to begin from the
// start. Returns the next cursor and a nil error on success. Returns an empty
// next cursor when iteration is exhausted.
//
// All tokens are returned regardless of revocation or expiry status — the
// caller is responsible for filtering. The cursor is an integer offset into
// the stable insertion-order slice for userID — best-effort when tokens are
// added or removed between pages. Returns ErrInvalidUserID if userID is empty.
// Returns the context error if the context is cancelled.
func (m *MemoryRefreshStore) ListTokensForUser(ctx context.Context, userID string, cursor string, count int) ([]*RefreshToken, string, error) {
	ctx, span := m.startSpan(ctx, "ListTokensForUser")
	defer span.End()
	span.SetAttribute("storage.user_id", userID)
	span.SetAttribute("storage.cursor", cursor)
	span.SetAttribute("storage.count", count)

	start := time.Now()
	errorType := "error"
	resultCount := 0
	defer func() {
		m.metrics.IncrementCounter(metricListTokensForUserTotal, map[string]string{
			"storage_backend": m.backend,
			"namespace":       "",
			"error_type":      errorType,
		})
		m.metrics.RecordDuration(metricListTokensForUserDuration, time.Since(start), map[string]string{
			"storage_backend": m.backend,
			"namespace":       "",
		})
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		errorType = "cancelled"
		m.logger.Warn("listTokensForUser aborted: context cancelled", ctx, "reason", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return nil, "", err
	}

	// ===== STEP 2: Validate Inputs =====
	if len(strings.TrimSpace(userID)) == 0 {
		errorType = "validation_error"
		m.logger.Warn("listTokensForUser rejected: userID is empty or whitespace", ctx)
		span.RecordError(ErrInvalidUserID)
		span.SetStatus(tracing.StatusError, ErrInvalidUserID.Error())
		return nil, "", ErrInvalidUserID
	}

	// ===== STEP 3: Acquire Read Lock =====
	m.mu.RLock()
	defer m.mu.RUnlock()

	// ===== STEP 4: Parse Cursor as Integer Offset =====
	offset := 0
	if cursor != "" {
		if parsed, err := strconv.Atoi(cursor); err == nil && parsed > 0 {
			offset = parsed
		}
	}

	// ===== STEP 5: Build Page from User's Token Slice =====
	tokenIDs := m.userTokens[userID]
	if offset >= len(tokenIDs) {
		errorType = ""
		span.SetStatus(tracing.StatusOK, "")
		m.logger.Info("listTokensForUser: page returned", ctx,
			"user_id", userID,
			"result_count", 0,
			"next_cursor", "")
		return nil, "", nil
	}

	end := offset + count
	if count <= 0 || end > len(tokenIDs) {
		end = len(tokenIDs)
	}
	page := tokenIDs[offset:end]

	tokens := make([]*RefreshToken, 0, len(page))
	for _, id := range page {
		t, ok := m.tokens[id]
		if !ok {
			continue
		}
		cp := &RefreshToken{
			TokenID:   t.TokenID,
			UserID:    t.UserID,
			ExpiresAt: t.ExpiresAt,
			CreatedAt: t.CreatedAt,
			Revoked:   t.Revoked,
		}
		if len(t.Audience) > 0 {
			cp.Audience = make([]string, len(t.Audience))
			copy(cp.Audience, t.Audience)
		}
		if t.Metadata != nil {
			cp.Metadata = make(map[string]interface{}, len(t.Metadata))
			for k, v := range t.Metadata {
				cp.Metadata[k] = v
			}
		}
		tokens = append(tokens, cp)
	}

	// ===== STEP 6: Compute Next Cursor =====
	nextCursor := ""
	if end < len(tokenIDs) {
		nextCursor = strconv.Itoa(end)
	}

	// ===== STEP 7: Log and Return =====
	errorType = ""
	resultCount = len(tokens)
	span.SetAttribute("storage.result_count", resultCount)
	span.SetStatus(tracing.StatusOK, "")
	m.logger.Info("listTokensForUser: page returned", ctx,
		"user_id", userID,
		"result_count", resultCount,
		"next_cursor", nextCursor)

	return tokens, nextCursor, nil
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

func (m *MemoryRefreshStore) removeFromAudienceTokens(audiences []string, tokenID string) {
	for _, aud := range audiences {
		tokenIDs := m.audienceTokens[aud]
		for i, tid := range tokenIDs {
			if tid == tokenID {
				tokenIDs[i] = tokenIDs[len(tokenIDs)-1]
				m.audienceTokens[aud] = tokenIDs[:len(tokenIDs)-1]
				break
			}
		}
		if len(m.audienceTokens[aud]) == 0 {
			delete(m.audienceTokens, aud)
		}
	}
}

// RevokeAllForAudience marks every refresh token issued with the given audience
// value as revoked. Returns the count of tokens marked revoked — including
// tokens that were already revoked before this call. A token with multiple
// audiences is revoked globally — not per-audience — so every service the token
// could reach is invalidated when any one of its audiences is targeted. It is
// idempotent — already-revoked tokens are counted but cause no error. Returns
// ErrInvalidAudience if audience is empty. Returns the context error if the
// context is cancelled.
func (m *MemoryRefreshStore) RevokeAllForAudience(ctx context.Context, audience string) (int, error) {
	ctx, span := m.startSpan(ctx, "RevokeAllForAudience")
	defer span.End()
	span.SetAttribute("audience", audience)

	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		m.metrics.IncrementCounter(metricStorageOpsTotal, map[string]string{
			"operation":       "revoke_all_audience",
			"status":          status,
			"error_type":      errorType,
			"storage_backend": m.backend,
			"namespace":       "",
		})
		m.metrics.RecordDuration(metricStorageOpDuration, time.Since(start), map[string]string{
			"operation":       "revoke_all_audience",
			"storage_backend": m.backend,
			"namespace":       "",
		})
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		m.logger.Warn("revokeAllForAudience aborted: context cancelled", ctx,
			"audience", audience,
			"reason", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return 0, err
	}

	// ===== STEP 2: Validate Inputs =====
	if len(strings.TrimSpace(audience)) == 0 {
		status = "validation_error"
		errorType = "validation_error"
		m.logger.Warn("revokeAllForAudience rejected: audience is empty or whitespace", ctx)
		span.RecordError(ErrInvalidAudience)
		span.SetStatus(tracing.StatusError, ErrInvalidAudience.Error())
		return 0, ErrInvalidAudience
	}

	// ===== STEP 3: Acquire Write Lock =====
	m.mu.Lock()
	defer m.mu.Unlock()

	// ===== STEP 4: Revoke All Tokens for Audience =====
	count := 0
	for _, tokenID := range m.audienceTokens[audience] {
		if token, exists := m.tokens[tokenID]; exists {
			m.logger.Debug("revoking token for audience", ctx,
				"tokenID", tokenID,
				"audience", audience)
			token.Revoked = true
			count++
		}
	}

	// ===== STEP 5: Log Success =====
	status = "success"
	errorType = ""
	m.logger.Info("revokeAllForAudience: all tokens revoked", ctx,
		"audience", audience,
		"count", count)
	span.SetStatus(tracing.StatusOK, "")

	return count, nil
}

// RevokeAllForUserAndAudience marks every refresh token belonging to userID
// that was issued with the given audience value as revoked. Returns the count
// of tokens marked revoked. Revocation is global — see RevokeAllForAudience.
// Returns ErrInvalidUserID if userID is empty, ErrInvalidAudience if audience
// is empty. Returns the context error if the context is cancelled.
func (m *MemoryRefreshStore) RevokeAllForUserAndAudience(ctx context.Context, userID, audience string) (int, error) {
	ctx, span := m.startSpan(ctx, "RevokeAllForUserAndAudience")
	defer span.End()
	span.SetAttribute("user_id", userID)
	span.SetAttribute("audience", audience)

	start := time.Now()
	status := "error"
	errorType := "error"
	defer func() {
		m.metrics.IncrementCounter(metricStorageOpsTotal, map[string]string{
			"operation":       "revoke_all_user_audience",
			"status":          status,
			"error_type":      errorType,
			"storage_backend": m.backend,
			"namespace":       "",
		})
		m.metrics.RecordDuration(metricStorageOpDuration, time.Since(start), map[string]string{
			"operation":       "revoke_all_user_audience",
			"storage_backend": m.backend,
			"namespace":       "",
		})
	}()

	// ===== STEP 1: Check Context =====
	if err := ctx.Err(); err != nil {
		status = "cancelled"
		errorType = "cancelled"
		m.logger.Warn("revokeAllForUserAndAudience aborted: context cancelled", ctx,
			"userID", userID,
			"audience", audience,
			"reason", err)
		span.RecordError(err)
		span.SetStatus(tracing.StatusError, err.Error())
		return 0, err
	}

	// ===== STEP 2: Validate Inputs =====
	if len(strings.TrimSpace(userID)) == 0 {
		status = "validation_error"
		errorType = "validation_error"
		m.logger.Warn("revokeAllForUserAndAudience rejected: userID is empty or whitespace", ctx)
		span.RecordError(ErrInvalidUserID)
		span.SetStatus(tracing.StatusError, ErrInvalidUserID.Error())
		return 0, ErrInvalidUserID
	}
	if len(strings.TrimSpace(audience)) == 0 {
		status = "validation_error"
		errorType = "validation_error"
		m.logger.Warn("revokeAllForUserAndAudience rejected: audience is empty or whitespace", ctx,
			"userID", userID)
		span.RecordError(ErrInvalidAudience)
		span.SetStatus(tracing.StatusError, ErrInvalidAudience.Error())
		return 0, ErrInvalidAudience
	}

	// ===== STEP 3: Acquire Write Lock =====
	m.mu.Lock()
	defer m.mu.Unlock()

	// ===== STEP 4: Revoke Tokens for User Within Audience =====
	count := 0
	for _, tokenID := range m.audienceTokens[audience] {
		if token, exists := m.tokens[tokenID]; exists && token.UserID == userID {
			m.logger.Debug("revoking token for user and audience", ctx,
				"tokenID", tokenID,
				"userID", userID,
				"audience", audience)
			token.Revoked = true
			count++
		}
	}

	// ===== STEP 5: Log Success =====
	status = "success"
	errorType = ""
	m.logger.Info("revokeAllForUserAndAudience: tokens revoked", ctx,
		"userID", userID,
		"audience", audience,
		"count", count)
	span.SetStatus(tracing.StatusOK, "")

	return count, nil
}
