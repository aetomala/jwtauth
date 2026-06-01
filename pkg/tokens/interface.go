// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"context"

	"github.com/golang-jwt/jwt/v5"

	"github.com/aetomala/jwtauth/pkg/storage"
)

// TokenManager defines the full token lifecycle operations exposed by Manager.
// Consumers may depend on this interface rather than the concrete type,
// enabling service-layer unit testing without a running key store or
// storage backend. All methods are safe for concurrent use.
type TokenManager interface {
	// ===== Issuance =====
	IssueAccessToken(ctx context.Context, userID string, opts ...IssueOption) (string, error)
	IssueAccessTokenWithClaims(ctx context.Context, userID string, claims CustomClaims, opts ...IssueOption) (string, error)
	IssueRefreshToken(ctx context.Context, userID string, opts ...IssueOption) (string, error)
	IssueRefreshTokenWithClaims(ctx context.Context, userID string, claims CustomClaims, opts ...IssueOption) (string, error)
	IssueTokenPair(ctx context.Context, userID string, opts ...IssueOption) (string, string, error)
	IssueTokenPairWithClaims(ctx context.Context, userID string, accessClaims CustomClaims, refreshClaims CustomClaims, opts ...IssueOption) (string, string, error)

	// ===== Validation and Refresh =====
	ValidateAccessToken(ctx context.Context, tokenString string) (*jwt.RegisteredClaims, error)
	ValidateAccessTokenWithClaims(ctx context.Context, tokenString string) (*jwt.RegisteredClaims, map[string]interface{}, error)
	RefreshAccessToken(ctx context.Context, refreshToken string) (string, error)
	RefreshAccessTokenWithClaims(ctx context.Context, refreshToken string, claims CustomClaims) (string, error)

	// ===== Introspection =====
	IntrospectToken(ctx context.Context, token string) (*TokenMetadata, error)

	// ===== Revocation =====
	RevokeRefreshToken(ctx context.Context, tokenID string) error
	RevokeAllUserTokens(ctx context.Context, userID string) error
	RevokeAllForAudience(ctx context.Context, audience string) error
	RevokeAllForUserAndAudience(ctx context.Context, userID, audience string) error

	// ===== Operational =====
	CleanupExpiredTokens(ctx context.Context) (int, error)
	ListTokens(ctx context.Context, cursor string, count int) ([]*storage.RefreshToken, string, error)
	ListTokensForUser(ctx context.Context, userID string, cursor string, count int) ([]*storage.RefreshToken, string, error)
	ListTokensForAudience(ctx context.Context, audience string, cursor string, count int) ([]*storage.RefreshToken, string, error)
}

// Compile-time assertion: Manager must satisfy TokenManager.
var _ TokenManager = (*Manager)(nil)
