package middleware

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/aetomala/jwtauth/pkg/tokens"
)

// AuthMiddleware validates JWT tokens in the Authorization header
// and attaches claims to the Echo context
func AuthMiddleware(svc *tokens.Service) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			// Extract token from Authorization header
			authHeader := c.Request().Header.Get("Authorization")
			if authHeader == "" {
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "missing authorization header",
				})
			}

			// Remove "Bearer " prefix
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if token == authHeader {
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "invalid authorization format",
				})
			}

			// Validate token using jwtauth
			claims, err := svc.ValidateAccessToken(c.Request().Context(), token)
			if err != nil {
				return c.JSON(http.StatusUnauthorized, map[string]string{
					"error": "invalid token",
				})
			}

			// Attach claims to context for route handlers
			c.Set("userID", claims.Subject)
			c.Set("claims", claims)

			return next(c)
		}
	}
}
