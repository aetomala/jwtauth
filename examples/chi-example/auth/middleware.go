package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/aetomala/jwtauth/pkg/tokens"
)

// AuthMiddleware validates JWT tokens in the Authorization header
// and attaches claims to the request context
func AuthMiddleware(svc *tokens.Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "missing authorization header", http.StatusUnauthorized)
				return
			}

			// Remove "Bearer " prefix
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if token == authHeader {
				http.Error(w, "invalid authorization format", http.StatusUnauthorized)
				return
			}

			// Validate token using jwtauth
			claims, err := svc.ValidateAccessToken(r.Context(), token)
			if err != nil {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			// Attach claims to context for route handlers
			ctx := context.WithValue(r.Context(), "userID", claims.Subject)
			ctx = context.WithValue(ctx, "claims", claims)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
