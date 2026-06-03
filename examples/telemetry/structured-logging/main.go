// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

// structured-logging demonstrates how jwtauth's Namespace field propagates through
// every log line produced by KeyManager and TokenManager.
//
// When Namespace is set on a manager config, the constructor calls
// logger.With("namespace", cfg.Namespace) internally, pre-binding the field to all
// subsequent log output from that component. Every JSON line in the output of this
// example contains "namespace":"myapp".
//
// No external dependencies are required.
package main

import (
	"context"
	"log/slog"
	"os"
	"time"

	"github.com/aetomala/jwtauth/pkg/keys"
	"github.com/aetomala/jwtauth/pkg/logging"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/aetomala/jwtauth/pkg/tokens"
)

func main() {
	// ===== STEP 1: Build a JSON logger with correlation ID support =====
	// Debug level so internal component lifecycle events are visible in the output.
	logger := logging.NewCorrelationJSONLogger(slog.LevelDebug)

	// ===== STEP 2: Build KeyManager with Namespace set =====
	// The constructor calls logger.With("namespace", "myapp") when Namespace is
	// non-empty, pre-binding "namespace" to every log line this component emits.
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
		Namespace:           "myapp",
		KeyRotationInterval: 30 * 24 * time.Hour,
	})
	if err != nil {
		slog.Error("create key manager", "error", err)
		os.Exit(1)
	}

	// ===== STEP 3: Build TokenManager with the same Namespace =====
	store := storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{Logger: logger})
	mgr, err := tokens.NewManager(tokens.TokenManagerConfig{
		KeyManager:           km,
		RefreshStore:         store,
		Logger:               logger,
		Namespace:            "myapp",
		Issuer:               "telemetry-logging",
		Audience:             []string{"api"},
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
		CleanupInterval:      1 * time.Hour,
	})
	if err != nil {
		slog.Error("create token manager", "error", err)
		os.Exit(1)
	}

	// ===== STEP 4: Start and run a token lifecycle =====
	// Each operation produces JSON log lines — look for "namespace":"myapp" in every one.
	ctx := context.Background()

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

	accessToken, refreshToken, err := mgr.IssueTokenPair(ctx, "alice")
	if err != nil {
		slog.Error("issue token pair", "error", err)
		os.Exit(1)
	}

	if _, err := mgr.ValidateAccessToken(ctx, accessToken); err != nil {
		slog.Error("validate access token", "error", err)
		os.Exit(1)
	}

	if _, err := mgr.RefreshAccessToken(ctx, refreshToken); err != nil {
		slog.Error("refresh access token", "error", err)
		os.Exit(1)
	}
}
