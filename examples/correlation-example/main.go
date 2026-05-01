// correlation-example demonstrates end-to-end correlation ID support using only
// the standard library. Every log line produced during a request carries the
// same correlation_id, making production log filtering trivial:
//
//	jq 'select(.correlation_id=="<id>")' app.log
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/aetomala/jwtauth/pkg/keys"
	"github.com/aetomala/jwtauth/pkg/logging"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/aetomala/jwtauth/pkg/tokens"
)

func main() {
	// ===== Logger: JSON with CorrelationIDHandler pre-wired =====
	// NewCorrelationJSONLogger wraps slog.NewJSONHandler with CorrelationIDHandler
	// so every *Context call automatically injects correlation_id into the record.
	logger := logging.NewCorrelationJSONLogger(slog.LevelDebug)

	// ===== KeyManager =====
	ks, err := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: "./keys", KeySize: 2048, Logger: logger})
	if err != nil {
		slog.Error("failed to create key store", "error", err)
		os.Exit(1)
	}
	km, err := keys.NewManager(keys.KeyManagerConfig{
		KeyStore:            ks,
		KeyRotationInterval: 30 * 24 * time.Hour,
		KeySize:             2048,
		Logger:              logger,
	})
	if err != nil {
		slog.Error("failed to create key manager", "error", err)
		os.Exit(1)
	}

	// ===== TokenManager =====
	store := storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{Logger: logger})
	mgr, err := tokens.NewManager(tokens.TokenManagerConfig{
		KeyManager:           km,
		RefreshStore:         store,
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
		CleanupInterval:      1 * time.Hour,
		Issuer:               "correlation-example",
		Audience:             []string{"correlation-example"},
		Logger:               logger,
	})
	if err != nil {
		slog.Error("failed to create token service", "error", err)
		os.Exit(1)
	}

	startCtx := context.Background()
	if err := mgr.Start(startCtx); err != nil {
		slog.Error("failed to start token service", "error", err)
		os.Exit(1)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = mgr.Shutdown(shutdownCtx)
	}()

	// ===== HTTP Handlers =====
	mux := http.NewServeMux()

	// Correlation ID middleware wraps every handler. It extracts the
	// X-Correlation-ID request header (or generates one) and injects it into
	// the request context. The response echoes the ID back so the caller can
	// correlate client-side logs as well.
	withCorrelation := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get("X-Correlation-ID")
			if id == "" {
				id = newCorrelationID()
			}
			ctx := logging.WithCorrelationID(r.Context(), id)
			w.Header().Set("X-Correlation-ID", id)
			next(w, r.WithContext(ctx))
		}
	}

	// POST /login — issues a token pair; all internal logs carry correlation_id.
	mux.HandleFunc("POST /login", withCorrelation(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		var req struct {
			UserID string `json:"user_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" {
			http.Error(w, `{"error":"user_id required"}`, http.StatusBadRequest)
			return
		}

		accessToken, refreshToken, err := mgr.IssueTokenPair(ctx, req.UserID)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		})
	}))

	// POST /refresh — exchanges a refresh token for a new access token.
	mux.HandleFunc("POST /refresh", withCorrelation(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		var req struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
			http.Error(w, `{"error":"refresh_token required"}`, http.StatusBadRequest)
			return
		}

		newAccessToken, err := mgr.RefreshAccessToken(ctx, req.RefreshToken)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token": newAccessToken,
		})
	}))

	// GET /validate — validates an access token passed in the Authorization header.
	mux.HandleFunc("GET /validate", withCorrelation(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		bearer := r.Header.Get("Authorization")
		if len(bearer) < 8 || bearer[:7] != "Bearer " {
			http.Error(w, `{"error":"Authorization header required"}`, http.StatusUnauthorized)
			return
		}

		claims, err := mgr.ValidateAccessToken(ctx, bearer[7:])
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"subject": claims.Subject,
			"issuer":  claims.Issuer,
		})
	}))

	addr := ":8080"
	slog.Info("correlation-example server starting", "addr", addr)
	slog.Info("try: curl -s -X POST http://localhost:8080/login -d '{\"user_id\":\"alice\"}' -H 'X-Correlation-ID: req-001'")
	if err := http.ListenAndServe(addr, mux); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}

// newCorrelationID returns a short pseudo-random hex ID suitable for use as a
// correlation ID when the caller does not supply X-Correlation-ID. For
// production use, replace this with a UUID library (e.g. github.com/google/uuid).
func newCorrelationID() string {
	return fmt.Sprintf("%08x-%04x", rand.Uint32(), rand.Uint32()&0xffff) //nolint:gosec
}
