package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"time"

	"github.com/aetomala/jwtauth/pkg/keys"
	"github.com/aetomala/jwtauth/pkg/logging"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/aetomala/jwtauth/pkg/tokens"
)

func main() {
	ctx := context.Background()

	// ===== STEP 1: Build Logger =====
	logger := logging.NewTextLogger(slog.LevelWarn)

	// ===== STEP 2: Create KeyManager =====
	ks, err := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{
		Dir:     "./keys",
		KeySize: 2048,
		Logger:  logger,
	})
	if err != nil {
		log.Fatal("create key store:", err)
	}

	km, err := keys.NewManager(keys.KeyManagerConfig{
		KeyStore:            ks,
		KeyRotationInterval: 30 * 24 * time.Hour,
		Logger:              logger,
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

	// ===== STEP 3: Create TokenManager =====
	store := storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{Logger: logger})

	mgr, err := tokens.NewManager(tokens.TokenManagerConfig{
		KeyManager:           km,
		RefreshStore:         store,
		Logger:               logger,
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 7 * 24 * time.Hour,
		CleanupInterval:      1 * time.Hour,
		Issuer:               "token-audit-example",
		Audience:             []string{"token-audit-example"},
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

	// ===== STEP 4: Seed Tokens =====
	users := []string{"alice", "alice", "alice", "bob", "bob", "carol"}
	for _, userID := range users {
		if _, err := mgr.IssueRefreshToken(ctx, userID); err != nil {
			log.Fatal("issue refresh token:", err)
		}
	}
	fmt.Printf("Seeded %d refresh tokens for %d users\n\n", len(users), 3)

	// ===== STEP 5: Global Audit via ListTokens =====
	fmt.Println("=== Global token audit (ListTokens, pageSize=2) ===")
	var total int
	cursor := ""
	page := 1
	for {
		toks, next, err := mgr.ListTokens(ctx, cursor, 2)
		if err != nil {
			log.Fatal("ListTokens:", err)
		}
		for _, tok := range toks {
			fmt.Printf("  [page %d] tokenID=%.8s… userID=%s revoked=%v\n",
				page, tok.TokenID, tok.UserID, tok.Revoked)
		}
		total += len(toks)
		if next == "" {
			break
		}
		cursor = next
		page++
	}
	fmt.Printf("Total tokens: %d\n\n", total)

	// ===== STEP 6: User-Scoped Audit via ListTokensForUser =====
	auditUser := "alice"
	fmt.Printf("=== User-scoped audit for %q (ListTokensForUser, pageSize=2) ===\n", auditUser)
	var userTotal int
	cursor = ""
	page = 1
	for {
		toks, next, err := mgr.ListTokensForUser(ctx, auditUser, cursor, 2)
		if err != nil {
			log.Fatal("ListTokensForUser:", err)
		}
		for _, tok := range toks {
			fmt.Printf("  [page %d] tokenID=%.8s… expires=%s\n",
				page, tok.TokenID, tok.ExpiresAt.UTC().Format(time.RFC3339))
		}
		userTotal += len(toks)
		if next == "" {
			break
		}
		cursor = next
		page++
	}
	fmt.Printf("Total tokens for %q: %d\n", auditUser, userTotal)
}
