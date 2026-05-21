// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
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
		Issuer:               "audience-revocation-example",
		Audience:             []string{"svc-payments"},
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

	// ===== STEP 4: Issue Multi-Audience Tokens =====
	//
	// alice's token covers both svc-payments and svc-reports — one refresh token
	// grants access to both services. bob's token is scoped to svc-reports only.
	//
	// WithAudience overrides the default audience for this issuance; audiences are
	// stored on the refresh token and embedded in the signed access token.
	aliceAccess, aliceRefresh, err := mgr.IssueTokenPair(ctx, "alice",
		tokens.WithAudience("svc-payments", "svc-reports"))
	if err != nil {
		log.Fatal("issue alice token pair:", err)
	}

	_, _, err = mgr.IssueTokenPair(ctx, "bob",
		tokens.WithAudience("svc-reports"))
	if err != nil {
		log.Fatal("issue bob token pair:", err)
	}

	fmt.Println("Issued tokens:")
	fmt.Printf("  alice — audiences: [svc-payments svc-reports]\n")
	fmt.Printf("  bob   — audiences: [svc-reports]\n\n")
	_ = aliceAccess

	// ===== STEP 5: List Tokens for svc-payments =====
	fmt.Println(`=== ListTokensForAudience("svc-payments") ===`)
	toks, _, err := mgr.ListTokensForAudience(ctx, "svc-payments", "", 10)
	if err != nil {
		log.Fatal("ListTokensForAudience:", err)
	}
	for _, tok := range toks {
		fmt.Printf("  tokenID=%.8s… userID=%-6s audiences=%v revoked=%v\n",
			tok.TokenID, tok.UserID, tok.Audience, tok.Revoked)
	}
	fmt.Println()

	// ===== STEP 6: Revoke All svc-payments Tokens =====
	//
	// RevokeAllForAudience marks every refresh token that includes "svc-payments"
	// in its audience list as revoked — regardless of how many other audiences the
	// token covers. A refresh token is a single revocable unit (ADR-009): alice's
	// token carries both svc-payments and svc-reports, but it is revoked in full.
	// There is no per-audience revocation state.
	//
	// The access token alice holds remains technically valid until its TTL expires
	// (ADR-010: jwtauth does not perform JTI-based replay prevention for access
	// tokens). Use a short access token TTL and, if needed, a JTI deny-list in
	// middleware for tighter containment.
	fmt.Println(`=== RevokeAllForAudience("svc-payments") ===`)
	if err := mgr.RevokeAllForAudience(ctx, "svc-payments"); err != nil {
		log.Fatal("RevokeAllForAudience:", err)
	}
	fmt.Println("  Revoked all tokens touching svc-payments")
	fmt.Println()

	// Atomicity check: alice's token is now revoked for both audiences.
	// Attempting to refresh with the old refresh token returns ErrTokenRevoked.
	fmt.Println("=== Atomicity check: refresh with alice's revoked token ===")
	_, err = mgr.RefreshAccessToken(ctx, aliceRefresh)
	if errors.Is(err, storage.ErrTokenRevoked) {
		fmt.Println("  RefreshAccessToken → ErrTokenRevoked (expected)")
	} else {
		log.Fatal("unexpected error:", err)
	}
	fmt.Println()

	// ===== STEP 7: Confirm svc-reports Still Has bob's Active Token =====
	fmt.Println(`=== ListTokensForAudience("svc-reports") after svc-payments revocation ===`)
	toks, _, err = mgr.ListTokensForAudience(ctx, "svc-reports", "", 10)
	if err != nil {
		log.Fatal("ListTokensForAudience:", err)
	}
	for _, tok := range toks {
		fmt.Printf("  tokenID=%.8s… userID=%-6s audiences=%v revoked=%v\n",
			tok.TokenID, tok.UserID, tok.Audience, tok.Revoked)
	}
	fmt.Println()

	// ===== STEP 8: Revoke by User + Audience =====
	//
	// RevokeAllForUserAndAudience narrows the revocation to a single user. Only
	// tokens belonging to bob that include svc-reports are revoked. Tokens for
	// other users (or other audiences, if bob had them) are unaffected.
	fmt.Println(`=== RevokeAllForUserAndAudience("bob", "svc-reports") ===`)
	if err := mgr.RevokeAllForUserAndAudience(ctx, "bob", "svc-reports"); err != nil {
		log.Fatal("RevokeAllForUserAndAudience:", err)
	}
	fmt.Println("  Revoked bob's svc-reports tokens")
	fmt.Println()

	fmt.Println(`=== Final state: ListTokensForAudience("svc-reports") ===`)
	toks, _, err = mgr.ListTokensForAudience(ctx, "svc-reports", "", 10)
	if err != nil {
		log.Fatal("ListTokensForAudience:", err)
	}
	for _, tok := range toks {
		fmt.Printf("  tokenID=%.8s… userID=%-6s audiences=%v revoked=%v\n",
			tok.TokenID, tok.UserID, tok.Audience, tok.Revoked)
	}
	fmt.Println("Done.")
}
