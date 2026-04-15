package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/aetomala/jwtauth/pkg/tokens"
)

// BearerMiddleware validates JWT tokens in the Authorization header
// and attaches claims to the request context.
func BearerMiddleware(mgr *tokens.Manager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				writeJSONError(w, "missing_token", http.StatusUnauthorized)
				return
			}

			// Remove "Bearer " prefix
			token := strings.TrimPrefix(authHeader, "Bearer ")
			if token == authHeader {
				writeJSONError(w, "invalid_authorization_format", http.StatusUnauthorized)
				return
			}

			// Validate token using jwtauth
			claims, err := mgr.ValidateAccessToken(r.Context(), token)
			if err != nil {
				writeJSONError(w, tokenErrorCode(err), http.StatusUnauthorized)
				return
			}

			// Attach claims to context for route handlers
			ctx := context.WithValue(r.Context(), "userID", claims.Subject)
			ctx = context.WithValue(ctx, "claims", claims)

			next.ServeHTTP(w, r.WithContext(ctx))
		})
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

// writeJSONError writes a JSON error response with the given code and status.
func writeJSONError(w http.ResponseWriter, code string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": code}) //nolint:errcheck
}
