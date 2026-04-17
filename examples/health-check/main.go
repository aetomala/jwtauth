package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"time"

	"github.com/aetomala/jwtauth/pkg/keymanager"
	"github.com/aetomala/jwtauth/pkg/logging"
)

func main() {
	logger := logging.NewTextLogger(slog.LevelInfo)

	// ===== STEP 1: Create KeyManager =====
	ks, err := keymanager.NewDiskKeyStore(keymanager.DiskKeyStoreConfig{Dir: "./keys", KeySize: 2048, Logger: logger})
	if err != nil {
		log.Fatal("Failed to create DiskKeyStore:", err)
	}

	km, err := keymanager.NewManager(keymanager.ManagerConfig{
		KeyStore:            ks,
		KeyRotationInterval: 30 * 24 * time.Hour,
		Logger:              logger,
	})
	if err != nil {
		log.Fatal("Failed to create KeyManager:", err)
	}

	// ===== STEP 2: Start KeyManager =====
	ctx := context.Background()
	if err := km.Start(ctx); err != nil {
		log.Fatal("Failed to start KeyManager:", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = km.Shutdown(shutdownCtx)
	}()

	// ===== STEP 3: Register Routes =====
	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/health/keys", keyHealthHandler(km))

	// ===== STEP 4: Serve =====
	log.Println("Starting server on :8080")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}

// KeyHealthResponse is the JSON response for /health/keys.
type KeyHealthResponse struct {
	Status            string `json:"status"`
	CurrentKeyID      string `json:"current_key_id"`
	KeyCreatedAt      string `json:"key_created_at"`
	NextRotationAt    string `json:"next_rotation_at"`
	TimeUntilRotation string `json:"time_until_rotation"`
	KeyAge            string `json:"key_age"`
	KeySizeBits       int    `json:"key_size_bits"`
	Algorithm         string `json:"algorithm"`
}

// keyHealthHandler returns the current signing key metadata via GetCurrentKeyInfo.
// Returns 200 with status "healthy" when the key is valid, "degraded" when expired,
// and 503 if the KeyManager is unavailable.
func keyHealthHandler(km *keymanager.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// ===== STEP 1: Fetch Key Info =====
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		info, err := km.GetCurrentKeyInfo(ctx)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{
				"status": "unhealthy",
				"error":  "key manager unavailable",
			})
			return
		}

		// ===== STEP 2: Build Response =====
		status := "healthy"
		if !info.IsValid {
			status = "degraded"
		}

		now := time.Now()
		resp := KeyHealthResponse{
			Status:            status,
			CurrentKeyID:      info.KeyID,
			KeyCreatedAt:      info.CreatedAt.UTC().Format(time.RFC3339),
			NextRotationAt:    info.RotateAt.UTC().Format(time.RFC3339),
			TimeUntilRotation: formatDuration(time.Until(info.RotateAt)),
			KeyAge:            formatDuration(now.Sub(info.CreatedAt)),
			KeySizeBits:       info.KeySizeBits,
			Algorithm:         info.Algorithm,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// healthHandler returns a simple liveness response.
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

// formatDuration formats a duration as "Xd Xh Xm Xs" — omitting leading zero units.
func formatDuration(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	d = d.Truncate(time.Second)
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd%dh%dm%ds", days, hours, minutes, seconds)
	case hours > 0:
		return fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)
	case minutes > 0:
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	default:
		return fmt.Sprintf("%ds", seconds)
	}
}
