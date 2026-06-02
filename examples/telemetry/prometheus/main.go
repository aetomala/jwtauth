// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

// prometheus demonstrates how to wire jwtauth's built-in PrometheusMetrics adapter
// into KeyManager and TokenManager and expose the collected metrics for Prometheus
// scraping.
//
// The same PrometheusMetrics instance is injected into both managers so all
// library-internal metrics land in one custom registry, served at :9090/metrics
// via promhttp.HandlerFor.
//
// No external service is required — the endpoint can be scraped by any Prometheus
// instance pointed at localhost:9090.
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aetomala/jwtauth/pkg/keys"
	"github.com/aetomala/jwtauth/pkg/logging"
	"github.com/aetomala/jwtauth/pkg/metrics"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/aetomala/jwtauth/pkg/tokens"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	logger := logging.NewTextLogger(slog.LevelInfo)

	// ===== STEP 1: Build PrometheusMetrics with a custom registry =====
	// A dedicated registry keeps jwtauth metrics separate from Go runtime and
	// process metrics that prometheus.DefaultRegisterer exports automatically.
	// The same instance is injected into both managers so all metrics land in reg.
	reg := prometheus.NewRegistry()
	m := metrics.NewPrometheusMetrics(metrics.PrometheusConfig{
		Namespace: "myapp",
		Registry:  reg,
		Logger:    logger,
	})

	// ===== STEP 2: Build KeyManager =====
	ks, err := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{
		Dir:    "./keys",
		Logger: logger,
	})
	if err != nil {
		slog.Error("create key store", "error", err)
		os.Exit(1)
	}

	km, err := keys.NewManager(keys.KeyManagerConfig{
		KeyStore:            ks,
		Logger:              logger,
		Metrics:             m,
		Namespace:           "myapp",
		KeyRotationInterval: 30 * 24 * time.Hour,
	})
	if err != nil {
		slog.Error("create key manager", "error", err)
		os.Exit(1)
	}

	// ===== STEP 3: Build TokenManager =====
	store := storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{Logger: logger})
	mgr, err := tokens.NewManager(tokens.TokenManagerConfig{
		KeyManager:           km,
		RefreshStore:         store,
		Logger:               logger,
		Metrics:              m,
		Namespace:            "myapp",
		Issuer:               "telemetry-prometheus",
		Audience:             []string{"api"},
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
		CleanupInterval:      1 * time.Hour,
	})
	if err != nil {
		slog.Error("create token manager", "error", err)
		os.Exit(1)
	}

	// ===== STEP 4: Start managers =====
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := km.Start(ctx); err != nil {
		slog.Error("start key manager", "error", err)
		os.Exit(1)
	}
	defer shutdown(km.Shutdown)

	if err := mgr.Start(ctx); err != nil {
		slog.Error("start token manager", "error", err)
		os.Exit(1)
	}
	defer shutdown(mgr.Shutdown)

	// ===== STEP 5: Issue a token pair to populate initial metric observations =====
	if _, _, err := mgr.IssueTokenPair(ctx, "alice"); err != nil {
		slog.Warn("issue token pair", "error", err)
	}

	// ===== STEP 6: Serve /metrics via the custom registry =====
	// promhttp.HandlerFor scopes the response to reg only — Go runtime and process
	// metrics are excluded. Use promhttp.Handler() instead to include them.
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))

	srv := &http.Server{Addr: ":9090", Handler: mux}
	go func() {
		slog.Info("metrics endpoint ready", "url", "http://localhost:9090/metrics")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("metrics server", "error", err)
		}
	}()

	<-ctx.Done()
	stop()

	srvCtx, srvCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer srvCancel()
	_ = srv.Shutdown(srvCtx)
}

func shutdown(fn func(context.Context) error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = fn(ctx)
}
