// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/aetomala/jwtauth/pkg/tokens"
)

// BearerMiddleware validates JWT tokens in the Authorization header
// and attaches claims to the Gin context.
func BearerMiddleware(mgr *tokens.Manager) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing_token",
			})
			return
		}

		// Remove "Bearer " prefix
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == authHeader {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid_authorization_format",
			})
			return
		}

		// Validate token using jwtauth
		claims, err := mgr.ValidateAccessToken(c.Request.Context(), token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": tokenErrorCode(err),
			})
			return
		}

		// Attach claims to context for route handlers
		c.Set("userID", claims.Subject)
		c.Set("claims", claims)
		c.Next()
	}
}

// tokenErrorCode maps a ValidateAccessToken error to a machine-readable error code.
func tokenErrorCode(err error) string {
	switch {
	case errors.Is(err, tokens.ErrTokenExpired):
		return "token_expired"
	case errors.Is(err, tokens.ErrTokenNotYetValid):
		return "token_not_yet_valid"
	case errors.Is(err, tokens.ErrTokenRevoked):
		return "token_revoked"
	case errors.Is(err, tokens.ErrInvalidIssuer):
		return "invalid_issuer"
	case errors.Is(err, tokens.ErrInvalidAudience):
		return "invalid_audience"
	default:
		return "invalid_token"
	}
}
