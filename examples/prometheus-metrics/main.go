// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aetomala/jwtauth/pkg/keys"
	"github.com/aetomala/jwtauth/pkg/logging"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/aetomala/jwtauth/pkg/tokens"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Key-state gauges driven by GetCurrentKeyInfo.
var (
	keyAgeSeconds = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "jwtauth_key_age_seconds",
		Help: "Age of the current signing key in seconds.",
	})
	rotationScheduledSeconds = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "jwtauth_rotation_scheduled_seconds",
		Help: "Seconds until the current signing key is scheduled to rotate.",
	})
	keyValid = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "jwtauth_key_valid",
		Help: "1 if the current signing key is valid, 0 if it has expired.",
	})

	// cleanedTokensTotal counts expired refresh tokens removed across all manual cleanup runs.
	cleanedTokensTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "jwtauth_cleaned_tokens_total",
		Help: "Total number of expired refresh tokens removed by manual cleanup.",
	})
)

func init() {
	prometheus.MustRegister(keyAgeSeconds, rotationScheduledSeconds, keyValid, cleanedTokensTotal)
}

func main() {
	logger := logging.NewTextLogger(slog.LevelInfo)

	// ===== STEP 1: Create KeyManager =====
	ks, err := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: "./keys", KeySize: 2048, Logger: logger})
	if err != nil {
		log.Fatal("Failed to create DiskKeyStore:", err)
	}

	km, err := keys.NewManager(keys.KeyManagerConfig{
		KeyStore:            ks,
		KeyRotationInterval: 30 * 24 * time.Hour,
		Logger:              logger,
	})
	if err != nil {
		log.Fatal("Failed to create KeyManager:", err)
	}

	// ===== STEP 2: Start KeyManager =====
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := km.Start(ctx); err != nil {
		log.Fatal("Failed to start KeyManager:", err)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = km.Shutdown(shutdownCtx)
	}()

	// ===== STEP 3: Create and Start TokenManager =====
	store := storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{Logger: logger})
	mgr, err := tokens.NewManager(tokens.TokenManagerConfig{
		KeyManager:           km,
		RefreshStore:         store,
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
		CleanupInterval:      1 * time.Hour,
		Logger:               logger,
		Issuer:               "prometheus-metrics-example",
		Audience:             []string{"api"},
	})
	if err != nil {
		log.Fatal("Failed to create TokenManager:", err)
	}
	if err := mgr.Start(ctx); err != nil {
		log.Fatal("Failed to start TokenManager:", err)
	}
	defer func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = mgr.Shutdown(shutdownCtx)
	}()

	// ===== STEP 4: Manual Cleanup Loop =====
	// Use manual cleanup when you want fine-grained control over when expired tokens are
	// removed — for example, during low-traffic windows. When CleanupInterval > 0 on
	// TokenManagerConfig, the background goroutine also runs; this ticker demonstrates
	// driving cleanup on demand alongside it.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cleanupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
				count, err := mgr.CleanupExpiredTokens(cleanupCtx)
				cancel()
				if err != nil {
					logger.Warn("cleanup failed", "error", err)
					continue
				}
				logger.Info("cleanup complete", "deleted", count)
				cleanedTokensTotal.Add(float64(count))
			}
		}
	}()

	// ===== STEP 5: Initial Gauge Collection =====
	collectKeyMetrics(ctx, km)

	// ===== STEP 6: Background Collection Loop =====
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				collectKeyMetrics(ctx, km)
			}
		}
	}()

	// ===== STEP 7: Serve Metrics =====
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	srv := &http.Server{Addr: ":9090", Handler: mux}
	go func() {
		log.Println("Starting metrics server on :9090")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("metrics server error: %v", err)
		}
	}()

	<-ctx.Done()
	stop() // release signal catch so a second Ctrl-C kills immediately

	srvShutdownCtx, srvShutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer srvShutdownCancel()
	if err := srv.Shutdown(srvShutdownCtx); err != nil {
		log.Printf("server shutdown error: %v", err)
	}
}

// collectKeyMetrics fetches current signing key metadata and updates the three gauges.
// If GetCurrentKeyInfo returns an error (e.g. context cancelled or manager not running),
// the gauges are left at their last known values.
func collectKeyMetrics(ctx context.Context, km *keys.Manager) {
	// ===== STEP 1: Fetch Key Info =====
	collectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	info, err := km.GetCurrentKeyInfo(collectCtx)
	if err != nil {
		return
	}

	// ===== STEP 2: Update Gauges =====
	keyAgeSeconds.Set(time.Since(info.CreatedAt).Seconds())
	rotationScheduledSeconds.Set(time.Until(info.RotateAt).Seconds())
	if info.IsValid {
		keyValid.Set(1)
	} else {
		keyValid.Set(0)
	}
}
