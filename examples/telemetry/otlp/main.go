// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

// otlp demonstrates how to configure jwtauth with OpenTelemetry traces exported
// via OTLP HTTP. Spans are sent to the OTLP receiver at the address set by the
// OTEL_EXPORTER_OTLP_ENDPOINT environment variable (default: http://localhost:4318).
//
// An OTLP-compatible collector must be running and accepting HTTP on that endpoint.
// Compatible backends: OpenTelemetry Collector, Jaeger (v1.35+), Grafana Tempo.
//
// The example shows the full shutdown lifecycle: deferred tp.Shutdown flushes any
// buffered spans to the collector before the process exits.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aetomala/jwtauth/pkg/keys"
	"github.com/aetomala/jwtauth/pkg/logging"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/aetomala/jwtauth/pkg/tokens"
	"github.com/aetomala/jwtauth/pkg/tracing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// ===== STEP 1: Configure OTLP HTTP exporter =====
	// OTEL_EXPORTER_OTLP_ENDPOINT controls the destination (default: http://localhost:4318).
	// OTEL_SERVICE_NAME sets the service.name resource attribute seen in the collector.
	exp, err := otlptracehttp.New(ctx)
	if err != nil {
		slog.Error("create OTLP exporter", "error", err)
		os.Exit(1)
	}

	// ===== STEP 2: Build TracerProvider and set as global =====
	// WithBatcher buffers spans and flushes them in batches for efficiency.
	// Deferred tp.Shutdown flushes any remaining buffered spans before exit.
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	otel.SetTracerProvider(tp)
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tp.Shutdown(shutdownCtx)
	}()

	// ===== STEP 3: Build jwtauth stack with tracer injected =====
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
		Logger:              logger,
		Tracer:              tracer,
		Namespace:           "myapp",
		KeyRotationInterval: 30 * 24 * time.Hour,
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
		Logger:               logger,
		Tracer:               tracer,
		Namespace:            "myapp",
		Issuer:               "telemetry-otlp",
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

	// ===== STEP 5: Run a token lifecycle to emit spans =====
	// Each operation below produces a span. The spans are buffered by the batcher
	// and flushed to the collector by tp.Shutdown when the program exits.
	accessToken, refreshToken, err := mgr.IssueTokenPair(ctx, "alice")
	if err != nil {
		slog.Error("issue token pair", "error", err)
		os.Exit(1)
	}
	slog.Info("token pair issued")

	if _, err := mgr.ValidateAccessToken(ctx, accessToken); err != nil {
		slog.Error("validate access token", "error", err)
		os.Exit(1)
	}
	slog.Info("access token validated")

	if _, err := mgr.RefreshAccessToken(ctx, refreshToken); err != nil {
		slog.Error("refresh access token", "error", err)
		os.Exit(1)
	}
	slog.Info("access token refreshed — waiting for signal, then spans flush on shutdown")

	<-ctx.Done()
	stop()
}

func shutdown(fn func(context.Context) error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = fn(ctx)
}
