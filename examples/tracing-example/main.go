// tracing-example demonstrates distributed tracing with jwtauth using the
// OpenTelemetry SDK and the stdout exporter. Spans are printed to stdout — no
// external backend (Jaeger, Zipkin, etc.) is required.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/aetomala/jwtauth/pkg/keys"
	"github.com/aetomala/jwtauth/pkg/logging"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/aetomala/jwtauth/pkg/tokens"
	"github.com/aetomala/jwtauth/pkg/tracing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func main() {
	ctx := context.Background()

	// ===== STEP 1: Configure OTel SDK with stdout exporter =====
	exporter, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
	if err != nil {
		slog.Error("create span exporter", "error", err)
		os.Exit(1)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	otel.SetTracerProvider(tp)
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tp.Shutdown(shutdownCtx)
	}()

	// ===== STEP 2: Build jwtauth components with OTel tracer =====
	logger := logging.NewTextLogger(slog.LevelInfo)
	tracer := tracing.NewOtelTracer("jwtauth")

	ks, err := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{
		Dir:    "./keys",
		Logger: logger,
		Tracer: tracer,
	})
	if err != nil {
		slog.Error("create key store", "error", err)
		os.Exit(1)
	}

	km, err := keys.NewManager(keys.KeyManagerConfig{
		KeyStore:            ks,
		KeyRotationInterval: 30 * 24 * time.Hour,
		Logger:              logger,
		Tracer:              tracer,
	})
	if err != nil {
		slog.Error("create key manager", "error", err)
		os.Exit(1)
	}

	store := storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{
		Logger: logger,
		Tracer: tracer,
	})

	mgr, err := tokens.NewManager(tokens.TokenManagerConfig{
		KeyManager:           km,
		RefreshStore:         store,
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
		CleanupInterval:      1 * time.Hour,
		Issuer:               "tracing-example",
		Audience:             []string{"tracing-example"},
		Logger:               logger,
		Tracer:               tracer,
	})
	if err != nil {
		slog.Error("create token manager", "error", err)
		os.Exit(1)
	}

	if err := km.Start(ctx); err != nil {
		slog.Error("start key manager", "error", err)
		os.Exit(1)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = km.Shutdown(shutdownCtx)
	}()

	if err := mgr.Start(ctx); err != nil {
		slog.Error("start token manager", "error", err)
		os.Exit(1)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = mgr.Shutdown(shutdownCtx)
	}()

	// ===== STEP 3: HTTP handlers =====
	mux := http.NewServeMux()

	// POST /login — issues a token pair; generates IssueTokenPair span.
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			UserID string `json:"user_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.UserID == "" {
			http.Error(w, `{"error":"user_id required"}`, http.StatusBadRequest)
			return
		}

		accessToken, refreshToken, err := mgr.IssueTokenPair(r.Context(), req.UserID)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token":  accessToken,
			"refresh_token": refreshToken,
		})
	})

	// GET /validate — validates an access token; generates ValidateAccessToken span.
	mux.HandleFunc("GET /validate", func(w http.ResponseWriter, r *http.Request) {
		bearer := r.Header.Get("Authorization")
		if len(bearer) < 8 || bearer[:7] != "Bearer " {
			http.Error(w, `{"error":"Authorization header required"}`, http.StatusUnauthorized)
			return
		}

		claims, err := mgr.ValidateAccessToken(r.Context(), bearer[7:])
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"subject": claims.Subject,
			"issuer":  claims.Issuer,
		})
	})

	// POST /refresh — exchanges a refresh token for a new access token; generates RefreshAccessToken span.
	mux.HandleFunc("POST /refresh", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			RefreshToken string `json:"refresh_token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RefreshToken == "" {
			http.Error(w, `{"error":"refresh_token required"}`, http.StatusBadRequest)
			return
		}

		newAccessToken, err := mgr.RefreshAccessToken(r.Context(), req.RefreshToken)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"access_token": newAccessToken,
		})
	})

	addr := ":8080"
	slog.Info("tracing-example server starting", "addr", addr)
	slog.Info("try: curl -s -X POST http://localhost:8080/login -d '{\"user_id\":\"alice\"}' | jq")
	if err := http.ListenAndServe(addr, mux); err != nil {
		slog.Error("server error", "error", err)
		os.Exit(1)
	}
}
