package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/aetomala/jwtauth/pkg/tokens"
)

// BearerMiddleware validates JWT tokens in the Authorization header
// and attaches claims to the Echo context.
func BearerMiddleware(mgr *tokens.Manager) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Extract token from Authorization header
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "missing_token",
				})
			}

			// Remove "Bearer " prefix
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if token == authHeader {
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "invalid_authorization_format",
				})
			}

			// Validate token using jwtauth
			claims, err := mgr.ValidateAccessToken(c.Request().Context(), token)
			if err != nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": tokenErrorCode(err),
				})
			}

			// Attach claims to context for route handlers
			c.Set("userID", claims.Subject)
			c.Set("claims", claims)

			return next(c)
		}
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
