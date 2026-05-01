package main

import (
	"context"
	"encoding/json"
	"log"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/aetomala/jwtauth/examples/chi-example/auth"
	"github.com/aetomala/jwtauth/pkg/keys"
	"github.com/aetomala/jwtauth/pkg/logging"
	"github.com/aetomala/jwtauth/pkg/metrics"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/aetomala/jwtauth/pkg/tokens"
)

func main() {
	// Setup logger
	logger := logging.NewTextLogger(slog.LevelDebug)

	// Setup metrics
	pm := metrics.NewPrometheusMetrics(metrics.PrometheusConfig{})

	// Create KeyStore and KeyManager
	ks, err := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: "./keys", KeySize: 2048, Logger: logger, Metrics: pm})
	if err != nil {
		log.Fatal("Failed to create DiskKeyStore:", err)
	}

	km, err := keys.NewManager(keys.KeyManagerConfig{
		KeyStore:            ks,
		KeyRotationInterval: 30 * 24 * time.Hour,
		Logger:              logger,
		Metrics:             pm,
	})
	if err != nil {
		log.Fatal("Failed to create KeyManager:", err)
	}

	ctx := context.Background()
	if err := km.Start(ctx); err != nil {
		log.Fatal("Failed to start KeyManager:", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = km.Shutdown(shutdownCtx)
	}()

	// Create RefreshStore
	store := storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{Logger: logger, Metrics: pm})

	// Create TokenService
	mgr, err := tokens.NewManager(tokens.TokenManagerConfig{
		KeyManager:           km,
		RefreshStore:         store,
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
		CleanupInterval:      1 * time.Hour,
		Logger:               logger,
		Metrics:              pm,
		Issuer:               "chi-example",
		Audience:             []string{"chi-example-api"},
	})
	if err != nil {
		log.Fatal("Failed to create TokenService:", err)
	}

	if err := mgr.Start(ctx); err != nil {
		log.Fatal("Failed to start TokenService:", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = mgr.Shutdown(shutdownCtx)
	}()

	// Setup Chi router
	r := chi.NewRouter()

	// Global middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Metrics endpoint
	r.Get("/metrics", pm.Handler().ServeHTTP)

	// Public endpoints
	r.Post("/login", issueTokensHandler(mgr))
	r.Post("/login/rich", issueTokensWithClaimsHandler(mgr))
	r.Post("/refresh", refreshHandler(mgr))
	r.Post("/refresh/claims", refreshWithClaimsHandler(mgr))

	// Protected endpoints demonstrating custom claims extraction
	r.Get("/protected/role", roleHandler(mgr))

	// Health check
	r.Get("/health", healthHandler)

	// Protected routes
	r.Route("/api", func(r chi.Router) {
		r.Use(auth.BearerMiddleware(mgr))
		r.Get("/profile", profileHandler)
		r.Post("/logout", logoutHandler(mgr))
	})

	// Admin routes — key inspection (no auth in this example; add middleware in production)
	r.Route("/admin", func(r chi.Router) {
		r.Get("/key-status", keyStatusHandler(km))
	})

	log.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", r); err != nil {
		log.Fatal(err)
	}
}

// LoginRequest is the request body for login
type LoginRequest struct {
	UserID string `json:"user_id"`
}

// TokenResponse is the response body for token operations
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
}

// issueTokensHandler issues a new token pair
func issueTokensHandler(mgr *tokens.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		if req.UserID == "" {
			http.Error(w, "user_id is required", http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		accessToken, refreshToken, err := mgr.IssueTokenPair(ctx, req.UserID)
		if err != nil {
			http.Error(w, "failed to issue tokens", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresIn:    900, // 15 minutes
		})
	}
}

// RefreshRequest is the request body for token refresh
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// refreshHandler refreshes an access token
func refreshHandler(mgr *tokens.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req RefreshRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		if req.RefreshToken == "" {
			http.Error(w, "refresh_token is required", http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		accessToken, err := mgr.RefreshAccessToken(ctx, req.RefreshToken)
		if err != nil {
			http.Error(w, "failed to refresh token", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: accessToken,
			ExpiresIn:   900, // 15 minutes
		})
	}
}

// profileHandler returns the authenticated user's profile
func profileHandler(w http.ResponseWriter, r *http.Request) {
	userID := r.Context().Value("userID")
	if userID == nil {
		http.Error(w, "user not found in context", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user_id": userID,
		"message": "This is a protected endpoint",
	})
}

// logoutHandler revokes the user's tokens
func logoutHandler(mgr *tokens.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.Context().Value("userID")
		if userID == nil {
			http.Error(w, "user not found in context", http.StatusUnauthorized)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		if err := mgr.RevokeAllUserTokens(ctx, userID.(string)); err != nil {
			http.Error(w, "failed to revoke tokens", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"message": "logged out successfully",
		})
	}
}

// healthHandler returns the health status
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
	})
}

// issueTokensWithClaimsHandler issues a token pair with hard-coded custom claims
// (role=admin, tier=premium) — demonstrating IssueTokenPairWithClaims.
func issueTokensWithClaimsHandler(mgr *tokens.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		if req.UserID == "" {
			http.Error(w, "user_id is required", http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		accessToken, refreshToken, err := mgr.IssueTokenPairWithClaims(
			ctx,
			req.UserID,
			tokens.CustomClaims{"role": "admin", "tier": "premium"},
			nil,
		)
		if err != nil {
			http.Error(w, "failed to issue tokens", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresIn:    900,
		})
	}
}

// RefreshWithClaimsRequest is the request body for a claims-aware refresh.
type RefreshWithClaimsRequest struct {
	RefreshToken string `json:"refresh_token"`
	Role         string `json:"role"`
}

// refreshWithClaimsHandler exchanges a refresh token for a new access token that
// carries the caller-supplied role claim — demonstrating RefreshAccessTokenWithClaims.
func refreshWithClaimsHandler(mgr *tokens.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req RefreshWithClaimsRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		if req.RefreshToken == "" {
			http.Error(w, "refresh_token is required", http.StatusBadRequest)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		accessToken, err := mgr.RefreshAccessTokenWithClaims(
			ctx,
			req.RefreshToken,
			tokens.CustomClaims{"role": req.Role},
		)
		if err != nil {
			http.Error(w, "failed to refresh token", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(TokenResponse{
			AccessToken: accessToken,
			ExpiresIn:   900,
		})
	}
}

// roleHandler validates an access token with ValidateAccessTokenWithClaims and
// returns the subject and role custom claim — demonstrating claims extraction.
func roleHandler(mgr *tokens.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if len(authHeader) < 8 || authHeader[:7] != "Bearer " {
			http.Error(w, `{"error":"missing_token"}`, http.StatusUnauthorized)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		registered, custom, err := mgr.ValidateAccessTokenWithClaims(ctx, authHeader[7:])
		if err != nil {
			http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
			return
		}

		role, _ := custom["role"].(string)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"subject": registered.Subject,
			"role":    role,
		})
	}
}

// keyStatusHandler returns the current signing key metadata via GetCurrentKeyInfo.
// No private key material is included — safe to expose via an admin endpoint.
func keyStatusHandler(km *keys.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		info, err := km.GetCurrentKeyInfo(ctx)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"error": "key manager unavailable"})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(info)
	}
}
