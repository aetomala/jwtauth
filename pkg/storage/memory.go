package storage

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/aetomala/jwtauth/pkg/logging"
)

type MemoryRefreshStore struct {
	mu         sync.RWMutex             // Thread safety
	tokens     map[string]*RefreshToken // tokenID -> token
	userTokens map[string][]string      // userID -> []tokenID
	logger     logging.Logger           // Optional logging
}

func NewMemoryRefreshStore(logger logging.Logger) *MemoryRefreshStore {
	m := &MemoryRefreshStore{
		tokens:     make(map[string]*RefreshToken),
		userTokens: make(map[string][]string),
	}
	if logger != nil {
		m.logger = logger
	}
	return m
}

func (m *MemoryRefreshStore) Store(ctx context.Context, tokenID, userID string, expiresAt time.Time, metadata map[string]interface{}) error {
	if err := ctx.Err(); err != nil {
		if m.logger != nil {
			m.logger.Warn("store aborted: context cancelled",
				"reason", err)
		}
		return err
	}
	if len(strings.TrimSpace(tokenID)) == 0 {
		if m.logger != nil {
			m.logger.Warn("store rejected: tokenID is empty or whitespace",
				"userID", userID)
		}
		return ErrInvalidTokenID
	}

	if len(strings.TrimSpace(userID)) == 0 {
		if m.logger != nil {
			m.logger.Warn("store rejected: userID is empty or whitespace",
				"tokenID", tokenID)
		}
		return ErrInvalidUserID
	}
	if expiresAt.Before(time.Now()) {
		if m.logger != nil {
			m.logger.Warn("store rejected: token is already expired",
				"tokenID", tokenID,
				"userID", userID,
				"expiresAt", expiresAt)
		}
		return ErrTokenExpired
	}
	// prevent mutation of a map by creating a copy before inserting
	var newMetadata map[string]interface{}
	if metadata != nil {
		newMetadata = make(map[string]interface{}, len(metadata))
		for k, v := range metadata {
			newMetadata[k] = v
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()

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

	if m.logger != nil {
		m.logger.Info("refresh token stored",
			"tokenID", tokenID,
			"userID", userID,
			"expiresAt", expiresAt)
	}
	return nil
}

func (m *MemoryRefreshStore) Retrieve(ctx context.Context, tokenID string) (*RefreshToken, error) {

	if err := ctx.Err(); err != nil {
		if m.logger != nil {
			m.logger.Warn("retrieve aborted: context cancelled",
				"tokenID", tokenID,
				"reason", err)
		}
		return nil, err
	}
	// validate inputs
	if len(strings.TrimSpace(tokenID)) == 0 {
		if m.logger != nil {
			m.logger.Warn("retrieve rejected: tokenID is empty or whitespace")
		}
		return nil, ErrInvalidTokenID
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	token, found := m.tokens[tokenID]

	if !found {
		if m.logger != nil {
			m.logger.Warn("retrieve: token not found",
				"tokenID", tokenID)
		}
		return nil, ErrTokenNotFound
	}

	if token.Revoked {
		if m.logger != nil {
			m.logger.Warn("retrieve: token has been revoked",
				"tokenID", tokenID,
				"userID", token.UserID)
		}
		return nil, ErrTokenRevoked
	}

	if token.ExpiresAt.Before(time.Now()) {
		if m.logger != nil {
			m.logger.Warn("retrieve: token has expired",
				"tokenID", tokenID,
				"expiredAt", token.ExpiresAt)
		}
		return nil, ErrTokenExpired
	}

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

	if m.logger != nil {
		m.logger.Info("retrieve: token retrieved successfully",
			"tokenID", tokenID)
	}

	return safeToken, nil
}

func (m *MemoryRefreshStore) Revoke(ctx context.Context, tokenID string) error {
	if err := ctx.Err(); err != nil {
		if m.logger != nil {
			m.logger.Warn("revoke aborted: context cancelled",
				"tokenID", tokenID)
		}
		return ctx.Err()
	}

	// validate inputs
	if len(strings.TrimSpace(tokenID)) == 0 {
		if m.logger != nil {
			m.logger.Warn("revoke rejected: tokenID is empty or whitespace")
		}
		return ErrInvalidTokenID
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	token, found := m.tokens[tokenID]

	if !found {
		if m.logger != nil {
			m.logger.Warn("revoke: token not found",
				"tokenID", tokenID)
		}
		// Expected to be idempotent; thus, return nil
		return nil
	}

	token.Revoked = true

	if m.logger != nil {
		m.logger.Info("revoke: successfully revoked",
			"tokenID", tokenID)
	}

	return nil
}

func (m *MemoryRefreshStore) RevokeAllForUser(ctx context.Context, userID string) error {
	if err := ctx.Err(); err != nil {
		if m.logger != nil {
			m.logger.Warn("revokeAllForUser aborted: context cancelled",
				"userID", userID,
				"reason", err)
		}
		return err
	}
	if len(strings.TrimSpace(userID)) == 0 {
		if m.logger != nil {
			m.logger.Warn("revokeAllForUser rejected: userID is empty or whitespace")
		}
		return ErrInvalidUserID
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	tokensIDs := m.userTokens[userID]

	for _, tokenID := range tokensIDs {
		if token, exists := m.tokens[tokenID]; exists {
			token.Revoked = true
		}
	}

	if m.logger != nil {
		m.logger.Info("revokeAllForUser: all tokens revoked",
			"userID", userID,
			"count", len(tokensIDs))
	}

	return nil
}

func (m *MemoryRefreshStore) Cleanup(ctx context.Context) (int, error) {

	if err := ctx.Err(); err != nil {
		if m.logger != nil {
			m.logger.Warn("cleanup aborted: context cancelled")
		}
		return 0, err
	}

	now := time.Now()
	count := 0
	m.mu.Lock()
	defer m.mu.Unlock()
	for tokenID, token := range m.tokens {
		if token.ExpiresAt.Before(now) || token.ExpiresAt.Equal(now) {
			delete(m.tokens, token.TokenID)
			m.removeFromUserTokens(token.UserID, tokenID)
			count++
		}
	}

	if m.logger != nil {
		m.logger.Info("cleanup: successful",
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
