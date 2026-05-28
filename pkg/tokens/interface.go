// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package tokens

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
)

// TokenManager defines the token lifecycle operations exposed by Manager.
// Consumers may depend on this interface rather than the concrete type,
// enabling service-layer unit testing without a running key store or
// storage backend. All methods are safe for concurrent use.
type TokenManager interface {
	IssueTokenPairWithClaims(ctx context.Context, userID string, accessClaims CustomClaims, refreshClaims CustomClaims, opts ...IssueOption) (string, string, error)
	RefreshAccessTokenWithClaims(ctx context.Context, refreshToken string, claims CustomClaims) (string, error)
	ValidateAccessToken(ctx context.Context, tokenString string) (*jwt.RegisteredClaims, error)
	ValidateAccessTokenWithClaims(ctx context.Context, tokenString string) (*jwt.RegisteredClaims, map[string]interface{}, error)
	IntrospectToken(ctx context.Context, token string) (*TokenMetadata, error)
	RevokeRefreshToken(ctx context.Context, tokenID string) error
	RevokeAllUserTokens(ctx context.Context, userID string) error
	RevokeAllForAudience(ctx context.Context, audience string) error
	RevokeAllForUserAndAudience(ctx context.Context, userID, audience string) error
}

// Compile-time assertion: Manager must satisfy TokenManager.
var _ TokenManager = (*Manager)(nil)
