package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/aetomala/jwtauth/pkg/tokens"
)

// AuthMiddleware validates JWT tokens in the Authorization header
// and attaches claims to the Gin context
func AuthMiddleware(svc *tokens.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "missing authorization header",
			})
			return
		}

		// Remove "Bearer " prefix
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == authHeader {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid authorization format",
			})
			return
		}

		// Validate token using jwtauth
		claims, err := svc.ValidateAccessToken(c.Request.Context(), token)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid token",
			})
			return
		}

		// Attach claims to context for route handlers
		c.Set("userID", claims.Subject)
		c.Set("claims", claims)
		c.Next()
	}
}
