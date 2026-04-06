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
	"github.com/aetomala/jwtauth/pkg/keymanager"
	"github.com/aetomala/jwtauth/pkg/logging"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/aetomala/jwtauth/pkg/tokens"
)

func main() {
	// Setup logger
	logger := logging.NewTextLogger(slog.LevelDebug)

	// Create KeyManager
	km, err := keymanager.NewManager(keymanager.ManagerConfig{
		KeyDirectory:        "./keys",
		KeyRotationInterval: 30 * 24 * time.Hour,
		Logger:              logger,
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
	store := storage.NewMemoryRefreshStore(logger, nil)

	// Create TokenService
	svc, err := tokens.NewService(tokens.ServiceConfig{
		KeyManager:           km,
		RefreshStore:         store,
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
		CleanupInterval:      1 * time.Hour,
		Logger:               logger,
		Issuer:               "chi-example",
		Audience:             []string{"chi-example-api"},
	})
	if err != nil {
		log.Fatal("Failed to create TokenService:", err)
	}

	if err := svc.Start(ctx); err != nil {
		log.Fatal("Failed to start TokenService:", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = svc.Shutdown(shutdownCtx)
	}()

	// Setup Chi router
	r := chi.NewRouter()

	// Global middleware
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Public endpoints
	r.Post("/login", loginHandler(svc))
	r.Post("/refresh", refreshHandler(svc))

	// Health check
	r.Get("/health", healthHandler)

	// Protected routes
	r.Route("/api", func(r chi.Router) {
		r.Use(auth.AuthMiddleware(svc))
		r.Get("/profile", profileHandler)
		r.Post("/logout", logoutHandler(svc))
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

// loginHandler issues a new token pair
func loginHandler(svc *tokens.Service) http.HandlerFunc {
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

		accessToken, refreshToken, err := svc.IssueTokenPair(ctx, req.UserID)
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
func refreshHandler(svc *tokens.Service) http.HandlerFunc {
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

		accessToken, err := svc.RefreshAccessToken(ctx, req.RefreshToken)
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
func logoutHandler(svc *tokens.Service) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.Context().Value("userID")
		if userID == nil {
			http.Error(w, "user not found in context", http.StatusUnauthorized)
			return
		}

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		if err := svc.RevokeAllUserTokens(ctx, userID.(string)); err != nil {
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
