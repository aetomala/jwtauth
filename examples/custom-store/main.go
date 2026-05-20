// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/aetomala/jwtauth/pkg/keys"
	"github.com/aetomala/jwtauth/pkg/logging"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/aetomala/jwtauth/pkg/tokens"
)

// Compile-time assertion: MyStore must implement storage.RefreshStore.
// If any method is missing or has the wrong signature, this line will not compile.
var _ storage.RefreshStore = (*MyStore)(nil)

// MyStore is a minimal in-memory RefreshStore backed by a mutex-guarded map.
// It demonstrates the full RefreshStore contract and serves as a reference guide
// for building production backends such as PostgreSQL or DynamoDB.
//
// Non-obvious invariants:
//   - metadata passed to Store is defensively copied — callers may mutate their map freely.
//   - Retrieve returns a defensive copy — callers may mutate the returned struct freely.
//   - Cursor values returned by List* methods are opaque to callers (ADR-011). Internally
//     this implementation uses an integer page offset, but that is an implementation detail.
//   - Cleanup returns the count of tokens deleted — not tokens scanned or remaining.
//   - A production backend (e.g. PostgreSQL) would replace the mutex with SQL transactions
//     and atomic UPDATE/DELETE queries for concurrency safety at scale.
type MyStore struct {
	mu     sync.RWMutex
	tokens map[string]*storage.RefreshToken // key: tokenID
}

// NewMyStore returns a new, empty MyStore.
func NewMyStore() *MyStore {
	return &MyStore{tokens: make(map[string]*storage.RefreshToken)}
}

// Store saves a refresh token. Returns storage.ErrInvalidTokenID if tokenID is empty,
// storage.ErrInvalidUserID if userID is empty, storage.ErrTokenExpired if expiresAt
// is already in the past. Defensive copies of audience and metadata are stored.
func (s *MyStore) Store(_ context.Context, tokenID, userID string, audience []string, expiresAt time.Time, metadata map[string]interface{}) error {
	if tokenID == "" {
		return storage.ErrInvalidTokenID
	}
	if userID == "" {
		return storage.ErrInvalidUserID
	}
	if !expiresAt.After(time.Now()) {
		return storage.ErrTokenExpired
	}

	// Defensive copy of audience — caller mutations must not affect stored state.
	var aud []string
	if len(audience) > 0 {
		aud = make([]string, len(audience))
		copy(aud, audience)
	}

	// Defensive copy of metadata — caller mutations must not affect stored state.
	var meta map[string]interface{}
	if metadata != nil {
		meta = make(map[string]interface{}, len(metadata))
		for k, v := range metadata {
			meta[k] = v
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[tokenID] = &storage.RefreshToken{
		TokenID:   tokenID,
		UserID:    userID,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
		Revoked:   false,
		Audience:  aud,
		Metadata:  meta,
	}
	return nil
}

// Retrieve fetches a refresh token by ID. Returns storage.ErrTokenNotFound if absent,
// storage.ErrTokenRevoked if revoked, storage.ErrTokenExpired if past its expiry time.
// Returns a defensive copy so callers may mutate the result freely.
func (s *MyStore) Retrieve(_ context.Context, tokenID string) (*storage.RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	token, ok := s.tokens[tokenID]
	if !ok {
		return nil, storage.ErrTokenNotFound
	}
	if token.Revoked {
		return nil, storage.ErrTokenRevoked
	}
	if !token.ExpiresAt.After(time.Now()) {
		return nil, storage.ErrTokenExpired
	}

	// Return a defensive copy — callers must not hold a reference into the store.
	result := &storage.RefreshToken{
		TokenID:   token.TokenID,
		UserID:    token.UserID,
		ExpiresAt: token.ExpiresAt,
		CreatedAt: token.CreatedAt,
		Revoked:   token.Revoked,
	}
	if len(token.Audience) > 0 {
		result.Audience = make([]string, len(token.Audience))
		copy(result.Audience, token.Audience)
	}
	if token.Metadata != nil {
		result.Metadata = make(map[string]interface{}, len(token.Metadata))
		for k, v := range token.Metadata {
			result.Metadata[k] = v
		}
	}
	return result, nil
}

// Revoke marks a token as revoked. Returns storage.ErrTokenNotFound if absent.
// Idempotent — revoking an already-revoked token is not an error.
func (s *MyStore) Revoke(_ context.Context, tokenID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	token, ok := s.tokens[tokenID]
	if !ok {
		return storage.ErrTokenNotFound
	}
	token.Revoked = true
	return nil
}

// RevokeAllForUser marks every token belonging to userID as revoked.
// Returns storage.ErrInvalidUserID if userID is empty.
func (s *MyStore) RevokeAllForUser(_ context.Context, userID string) error {
	if userID == "" {
		return storage.ErrInvalidUserID
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, token := range s.tokens {
		if token.UserID == userID {
			token.Revoked = true
		}
	}
	return nil
}

// RevokeAllForAudience marks every token that covers audience as revoked, and returns
// the count of tokens matched. Revocation is global — a token with multiple audiences
// is revoked entirely when any one of its audiences is targeted (ADR-009). Idempotent —
// already-revoked tokens are counted but cause no error. Returns storage.ErrInvalidAudience
// if audience is empty.
func (s *MyStore) RevokeAllForAudience(_ context.Context, audience string) (int, error) {
	if audience == "" {
		return 0, storage.ErrInvalidAudience
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for _, token := range s.tokens {
		if containsAudience(token.Audience, audience) {
			// Revoke globally regardless of how many audiences the token covers (ADR-009).
			token.Revoked = true
			count++
		}
	}
	return count, nil
}

// RevokeAllForUserAndAudience marks every token belonging to userID that covers audience
// as revoked, and returns the count matched. Returns storage.ErrInvalidUserID if userID
// is empty, storage.ErrInvalidAudience if audience is empty.
func (s *MyStore) RevokeAllForUserAndAudience(_ context.Context, userID, audience string) (int, error) {
	if userID == "" {
		return 0, storage.ErrInvalidUserID
	}
	if audience == "" {
		return 0, storage.ErrInvalidAudience
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for _, token := range s.tokens {
		if token.UserID == userID && containsAudience(token.Audience, audience) {
			token.Revoked = true
			count++
		}
	}
	return count, nil
}

// Cleanup removes every expired token and returns the count of tokens deleted.
// Returns the count of tokens deleted — not tokens scanned or tokens remaining.
func (s *MyStore) Cleanup(_ context.Context) (int, error) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()

	count := 0
	for tokenID, token := range s.tokens {
		if !token.ExpiresAt.After(now) {
			delete(s.tokens, tokenID)
			count++
		}
	}
	return count, nil
}

// ListTokens returns a page of all tokens starting from cursor. Pass an empty string
// to start from the beginning. Returns an empty next cursor when exhausted.
func (s *MyStore) ListTokens(_ context.Context, cursor string, count int) ([]*storage.RefreshToken, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := sortedIDs(s.tokens)
	return paginate(s.tokens, ids, cursor, count)
}

// ListTokensForUser returns a page of tokens belonging to userID. Returns
// storage.ErrInvalidUserID if userID is empty.
func (s *MyStore) ListTokensForUser(_ context.Context, userID string, cursor string, count int) ([]*storage.RefreshToken, string, error) {
	if userID == "" {
		return nil, "", storage.ErrInvalidUserID
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var ids []string
	for _, token := range s.tokens {
		if token.UserID == userID {
			ids = append(ids, token.TokenID)
		}
	}
	sort.Strings(ids)
	return paginate(s.tokens, ids, cursor, count)
}

// ListTokensForAudience returns a page of tokens covering audience. Returns
// storage.ErrInvalidAudience if audience is empty.
func (s *MyStore) ListTokensForAudience(_ context.Context, audience string, cursor string, count int) ([]*storage.RefreshToken, string, error) {
	if audience == "" {
		return nil, "", storage.ErrInvalidAudience
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	var ids []string
	for _, token := range s.tokens {
		if containsAudience(token.Audience, audience) {
			ids = append(ids, token.TokenID)
		}
	}
	sort.Strings(ids)
	return paginate(s.tokens, ids, cursor, count)
}

// Namespace returns empty string — this implementation does not support namespace
// isolation. A production backend (Redis, PostgreSQL) would return its configured
// namespace or key prefix here.
func (s *MyStore) Namespace() string {
	return ""
}

// containsAudience reports whether aud appears in the list.
func containsAudience(list []string, aud string) bool {
	for _, a := range list {
		if a == aud {
			return true
		}
	}
	return false
}

// sortedIDs returns a sorted slice of all token IDs in the map. Sorting gives
// deterministic page ordering within a snapshot — callers must still treat cursors
// as opaque (ADR-011); tokens inserted between pages may be skipped or duplicated.
func sortedIDs(m map[string]*storage.RefreshToken) []string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// paginate slices ids[offset : offset+count] and returns the page with a next cursor.
// The cursor is an integer page offset encoded as a decimal string. An empty cursor
// means start from index 0. An empty next cursor means iteration is exhausted.
func paginate(m map[string]*storage.RefreshToken, ids []string, cursor string, count int) ([]*storage.RefreshToken, string, error) {
	offset := 0
	if cursor != "" {
		n, err := strconv.Atoi(cursor)
		if err == nil && n > 0 {
			offset = n
		}
	}
	if count <= 0 {
		count = 10
	}
	if offset >= len(ids) {
		return nil, "", nil
	}

	end := offset + count
	if end > len(ids) {
		end = len(ids)
	}

	page := make([]*storage.RefreshToken, 0, end-offset)
	for _, id := range ids[offset:end] {
		t := m[id]
		page = append(page, &storage.RefreshToken{
			TokenID:   t.TokenID,
			UserID:    t.UserID,
			ExpiresAt: t.ExpiresAt,
			CreatedAt: t.CreatedAt,
			Revoked:   t.Revoked,
			Audience:  t.Audience,
		})
	}

	nextCursor := ""
	if end < len(ids) {
		nextCursor = strconv.Itoa(end)
	}
	return page, nextCursor, nil
}

func main() {
	// ===== STEP 1: Create Logger =====
	logger := logging.NewTextLogger(slog.LevelInfo)

	// ===== STEP 2: Create KeyManager =====
	ks, err := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: "./keys", KeySize: 2048, Logger: logger})
	if err != nil {
		log.Fatal("create key store:", err)
	}
	km, err := keys.NewManager(keys.KeyManagerConfig{
		KeyStore:            ks,
		KeyRotationInterval: 30 * 24 * time.Hour,
		Logger:              logger,
	})
	if err != nil {
		log.Fatal("create key manager:", err)
	}
	ctx := context.Background()
	if err := km.Start(ctx); err != nil {
		log.Fatal("start key manager:", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = km.Shutdown(shutdownCtx)
	}()

	// ===== STEP 3: Wire MyStore =====
	store := NewMyStore()

	// ===== STEP 4: Create TokenManager =====
	mgr, err := tokens.NewManager(tokens.TokenManagerConfig{
		KeyManager:           km,
		RefreshStore:         store,
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
		CleanupInterval:      1 * time.Hour,
		Logger:               logger,
		Issuer:               "custom-store-example",
		Audience:             []string{"api"},
	})
	if err != nil {
		log.Fatal("create token manager:", err)
	}
	if err := mgr.Start(ctx); err != nil {
		log.Fatal("start token manager:", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = mgr.Shutdown(shutdownCtx)
	}()

	// ===== STEP 5: Issue token pairs for two users =====
	_, aliceRefresh, err := mgr.IssueTokenPair(ctx, "alice")
	if err != nil {
		log.Fatal("issue tokens for alice:", err)
	}
	_, bobRefresh, err := mgr.IssueTokenPair(ctx, "bob")
	if err != nil {
		log.Fatal("issue tokens for bob:", err)
	}

	// ===== STEP 6: Revoke alice's refresh token =====
	if err := mgr.RevokeRefreshToken(ctx, aliceRefresh); err != nil {
		log.Fatal("revoke alice's token:", err)
	}

	// ===== STEP 7: Introspect both tokens =====
	aliceMeta, err := mgr.IntrospectToken(ctx, aliceRefresh)
	if err != nil {
		log.Fatal("introspect alice:", err)
	}
	bobMeta, err := mgr.IntrospectToken(ctx, bobRefresh)
	if err != nil {
		log.Fatal("introspect bob:", err)
	}

	// ===== STEP 8: Manual cleanup =====
	cleaned, err := mgr.CleanupExpiredTokens(ctx)
	if err != nil {
		log.Fatal("cleanup:", err)
	}

	// ===== STEP 9: Print results =====
	fmt.Println("MyStore wired successfully.")
	fmt.Printf("  alice — active: %v (revoked)\n", aliceMeta.Active)
	fmt.Printf("  bob   — active: %v\n", bobMeta.Active)
	fmt.Printf("  cleanup: %d tokens deleted\n", cleaned)
}
