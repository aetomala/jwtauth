package storage

import (
	"context"
	"errors"
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
		return ctx.Err()
	}
	if len(strings.TrimSpace(tokenID)) == 0 {
		if m.logger != nil {
			m.logger.Info("tokenID is empty")
		}
		return ErrInvalidTokenID
	}

	if len(strings.TrimSpace(userID)) == 0 {
		if m.logger != nil {
			m.logger.Info("userID is empty")
		}
		return ErrInvalidUserID
	}
	if expiresAt.Before(time.Now()) {
		if m.logger != nil {
			m.logger.Info("token already expired")
		}
		return ErrTokenExpired
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	token := &RefreshToken{
		TokenID:   tokenID,
		UserID:    userID,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
		Revoked:   false,
		Metadata:  metadata,
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
		return nil, ctx.Err()
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	token, found := m.tokens[tokenID]

	if !found {
		if m.logger != nil {
			m.logger.Error("token not found",
				"tokenID", tokenID)
		}
		return nil, ErrTokenNotFound
	}
	if m.logger != nil {
		m.logger.Info("successfully retrieved refresh token",
			"tokenID", tokenID)
	}
	return token, nil
}

func (m *MemoryRefreshStore) Revoke(ctx context.Context, tokenID string) error {
	return errors.New("not implemented yet")
}

func (m *MemoryRefreshStore) RevokeAllForUser(ctx context.Context, userID string) error {
	return errors.New("not implemented yet")
}

func (m *MemoryRefreshStore) Cleanup(ctx context.Context) (int, error) {
	return 0, errors.New("not implemented yet")
}
