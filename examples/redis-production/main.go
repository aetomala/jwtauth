// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aetomala/jwtauth/pkg/keys"
	"github.com/aetomala/jwtauth/pkg/logging"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/aetomala/jwtauth/pkg/tokens"
	"github.com/redis/go-redis/v9"
)

func main() {
	// ===== STEP 1: Signal context for graceful shutdown =====
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// ===== STEP 2: Build Logger =====
	logger := logging.NewTextLogger(slog.LevelInfo)

	// ===== STEP 3: Build Redis client from environment =====
	//
	// Set REDIS_ADDR (e.g. "localhost:6379"), REDIS_PASSWORD, REDIS_USERNAME
	// (required for Redis 6+ ACL users), and REDIS_TLS (any non-empty value
	// enables TLS). See doc/DEPLOYMENT.md — Redis Security Hardening for ACL
	// credential and certificate configuration details.
	opts := &redis.Options{
		Addr:     envOrDefault("REDIS_ADDR", "localhost:6379"),
		Password: os.Getenv("REDIS_PASSWORD"),
		Username: os.Getenv("REDIS_USERNAME"),
	}
	if os.Getenv("REDIS_TLS") != "" {
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		// Production: load a CA bundle and set RootCAs instead of relying on
		// the system pool. Never set InsecureSkipVerify: true.
	}
	redisClient := redis.NewClient(opts)
	defer redisClient.Close()

	// ===== STEP 4: Resolve namespace and key prefix =====
	//
	// Namespace scopes log lines, trace spans, and metric labels (ADR-007).
	// KeyPrefix scopes Redis keys to prevent collision across services (ADR-006).
	// Both should be set consistently across all nodes of a deployment.
	namespace := envOrDefault("APP_NAMESPACE", "redis-production")
	keyPrefix := envOrDefault("REDIS_KEY_PREFIX", "jwtauth:")

	// ===== STEP 5: Create RedisKeyStore =====
	ks, err := keys.NewRedisKeyStore(keys.RedisKeyStoreConfig{
		Client:    redisClient,
		KeyPrefix: keyPrefix,
		Logger:    logger,
	})
	if err != nil {
		log.Fatal("create key store:", err)
	}

	// ===== STEP 6: Create KeyManager =====
	km, err := keys.NewManager(keys.KeyManagerConfig{
		KeyStore:            ks,
		KeyRotationInterval: 30 * 24 * time.Hour,
		Logger:              logger,
		Namespace:           namespace,
	})
	if err != nil {
		log.Fatal("create key manager:", err)
	}
	if err := km.Start(ctx); err != nil {
		log.Fatal("start key manager:", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = km.Shutdown(shutdownCtx)
	}()

	// ===== STEP 7: Create RedisRefreshStore =====
	store, err := storage.NewRedisRefreshStore(storage.RedisRefreshStoreConfig{
		Client:    redisClient,
		KeyPrefix: keyPrefix,
		Logger:    logger,
	})
	if err != nil {
		log.Fatal("create refresh store:", err)
	}

	// ===== STEP 8: Create TokenManager =====
	mgr, err := tokens.NewManager(tokens.TokenManagerConfig{
		KeyManager:           km,
		RefreshStore:         store,
		Logger:               logger,
		Namespace:            namespace,
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
		CleanupInterval:      1 * time.Hour,
		Issuer:               "redis-production-example",
		Audience:             []string{"api"},
	})
	if err != nil {
		log.Fatal("create token manager:", err)
	}
	if err := mgr.Start(ctx); err != nil {
		log.Fatal("start token manager:", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = mgr.Shutdown(shutdownCtx)
	}()

	// ===== STEP 9: Token round-trip =====
	//
	// Issues one access + refresh token pair and immediately validates the access
	// token. A successful round-trip confirms that both Redis stores are reachable
	// and that key generation, signing, and validation are wired correctly.
	accessToken, _, err := mgr.IssueTokenPair(ctx, "user123")
	if err != nil {
		log.Fatal("issue token pair:", err)
	}
	claims, err := mgr.ValidateAccessToken(ctx, accessToken)
	if err != nil {
		log.Fatal("validate access token:", err)
	}

	fmt.Println("Redis backend wired successfully.")
	fmt.Printf("  namespace:  %s\n", namespace)
	fmt.Printf("  key_prefix: %s\n", keyPrefix)
	fmt.Printf("  userID:     %s\n", claims.Subject)
	fmt.Println("\nPress Ctrl+C to trigger graceful shutdown.")

	// ===== STEP 10: Wait for shutdown signal =====
	<-ctx.Done()
	fmt.Println("Shutting down.")
}

func envOrDefault(key, def string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return def
}
