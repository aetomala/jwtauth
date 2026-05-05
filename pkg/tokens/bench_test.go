package tokens_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/aetomala/jwtauth/pkg/keys"
	"github.com/aetomala/jwtauth/pkg/metrics"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/aetomala/jwtauth/pkg/tokens"
	"github.com/aetomala/jwtauth/pkg/tracing"
)

var (
	benchCtx       = context.Background()
	benchMgr       *tokens.Manager
	benchAccTok    string          // pre-issued access token for validate/introspect benchmarks
	benchRefTok    string          // pre-issued refresh token for introspect benchmarks
	benchRSAKey    *rsa.PrivateKey // raw RSA key for golang-jwt baseline
	benchGolangJWT string          // pre-signed JWT for BenchmarkVerify_GolangJWT

	benchClaimsSmall  = tokens.CustomClaims{"role": "admin", "tenant": "bench"}
	benchClaimsMedium tokens.CustomClaims
	benchClaimsLarge  tokens.CustomClaims
)

func init() {
	benchClaimsMedium = make(tokens.CustomClaims, 10)
	for i := range 10 {
		benchClaimsMedium[fmt.Sprintf("field%d", i)] = fmt.Sprintf("value%d", i)
	}
	benchClaimsLarge = make(tokens.CustomClaims, 50)
	for i := range 50 {
		benchClaimsLarge[fmt.Sprintf("field%d", i)] = fmt.Sprintf("value%d", i)
	}
}

func TestMain(m *testing.M) {
	tmpDir, err := os.MkdirTemp("", "bench-tokens-*")
	if err != nil {
		panic(err)
	}

	ks, err := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: tmpDir})
	if err != nil {
		panic(err)
	}

	km, err := keys.NewManager(keys.KeyManagerConfig{
		KeyStore:            ks,
		KeySize:             2048,
		KeyRotationInterval: 24 * time.Hour,
		KeyOverlapDuration:  1 * time.Hour,
	})
	if err != nil {
		panic(err)
	}

	// tokens.Manager.Start() starts the key manager internally.
	mgr, err := tokens.NewManager(tokens.TokenManagerConfig{
		KeyManager:           km,
		RefreshStore:         storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{}),
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 30 * 24 * time.Hour,
		Issuer:               "bench",
		Audience:             []string{"bench-api"},
	})
	if err != nil {
		panic(err)
	}
	if err := mgr.Start(benchCtx); err != nil {
		panic(err)
	}

	accessTok, err := mgr.IssueAccessToken(benchCtx, "bench-user")
	if err != nil {
		panic(err)
	}
	_, refreshTok, err := mgr.IssueTokenPair(benchCtx, "bench-user")
	if err != nil {
		panic(err)
	}

	// Generate a separate RSA 2048-bit key pair for the golang-jwt/jwt baseline.
	rawKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	rawClaims := jwt.RegisteredClaims{
		Subject:   "bench-user",
		Issuer:    "bench",
		Audience:  jwt.ClaimStrings{"bench-api"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	rawTok := jwt.NewWithClaims(jwt.SigningMethodRS256, rawClaims)
	signedRaw, err := rawTok.SignedString(rawKey)
	if err != nil {
		panic(err)
	}

	benchMgr = mgr
	benchAccTok = accessTok
	benchRefTok = refreshTok
	benchRSAKey = rawKey
	benchGolangJWT = signedRaw

	code := m.Run()

	// tokens.Manager.Shutdown() shuts down the key manager internally.
	_ = mgr.Shutdown(benchCtx)
	_ = os.RemoveAll(tmpDir)
	os.Exit(code)
}

// newBenchMgr creates a Manager backed by the given store, with its own isolated
// key manager (RSA 2048-bit DiskKeyStore using b.TempDir). The manager is started
// and registered for shutdown via b.Cleanup.
func newBenchMgr(b *testing.B, s storage.RefreshStore) *tokens.Manager {
	b.Helper()
	return newBenchMgrWithObs(b, s, tracing.NewNoOpTracer(), metrics.NewNoOpMetrics())
}

func newBenchMgrWithObs(b *testing.B, s storage.RefreshStore, tr tracing.Tracer, m metrics.Metrics) *tokens.Manager {
	b.Helper()
	ks, err := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: b.TempDir()})
	if err != nil {
		b.Fatalf("NewDiskKeyStore: %v", err)
	}
	km, err := keys.NewManager(keys.KeyManagerConfig{
		KeyStore:            ks,
		KeySize:             2048,
		KeyRotationInterval: 24 * time.Hour,
		KeyOverlapDuration:  1 * time.Hour,
	})
	if err != nil {
		b.Fatalf("NewManager(keys): %v", err)
	}
	mgr, err := tokens.NewManager(tokens.TokenManagerConfig{
		KeyManager:           km,
		RefreshStore:         s,
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 30 * 24 * time.Hour,
		Issuer:               "bench",
		Audience:             []string{"bench-api"},
		Tracer:               tr,
		Metrics:              m,
	})
	if err != nil {
		b.Fatalf("NewManager(tokens): %v", err)
	}
	if err := mgr.Start(benchCtx); err != nil {
		b.Fatalf("mgr.Start: %v", err)
	}
	b.Cleanup(func() { _ = mgr.Shutdown(benchCtx) })
	return mgr
}

// ============================================================================
// Category 1: Pure Crypto
// ============================================================================

// BenchmarkIssueAccessToken measures RS256 signing overhead — the common issuance
// path with no IssueOption and no custom claims.
func BenchmarkIssueAccessToken(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = benchMgr.IssueAccessToken(benchCtx, "bench-user")
		}
	})
}

// BenchmarkIssueAccessToken_WithAudience isolates the overhead of the WithAudience
// IssueOption — the closure-based dispatch layer added in PR #124.
func BenchmarkIssueAccessToken_WithAudience(b *testing.B) {
	opt := tokens.WithAudience("bench-audience")
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = benchMgr.IssueAccessToken(benchCtx, "bench-user", opt)
		}
	})
}

// BenchmarkIssueAccessTokenWithClaims measures signing overhead at three custom
// claims payload sizes: Small (2 fields), Medium (10 fields), Large (50 fields).
func BenchmarkIssueAccessTokenWithClaims(b *testing.B) {
	for _, tc := range []struct {
		name   string
		claims tokens.CustomClaims
	}{
		{"Small", benchClaimsSmall},
		{"Medium", benchClaimsMedium},
		{"Large", benchClaimsLarge},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					_, _ = benchMgr.IssueAccessTokenWithClaims(benchCtx, "bench-user", tc.claims)
				}
			})
		})
	}
}

// BenchmarkValidateAccessToken measures the hot validation path: RS256 signature
// verification, claims enforcement, and key cache lookup — the most frequent
// operation in a running service.
func BenchmarkValidateAccessToken(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = benchMgr.ValidateAccessToken(benchCtx, benchAccTok)
		}
	})
}

// BenchmarkValidateAccessTokenWithClaims measures validation plus custom-claims
// unmarshalling overhead on top of the standard validate path.
func BenchmarkValidateAccessTokenWithClaims(b *testing.B) {
	tok, err := benchMgr.IssueAccessTokenWithClaims(benchCtx, "bench-user", benchClaimsSmall)
	if err != nil {
		b.Fatalf("IssueAccessTokenWithClaims: %v", err)
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, _ = benchMgr.ValidateAccessTokenWithClaims(benchCtx, tok)
		}
	})
}

// BenchmarkIssueTokenPair measures the combined cost of signing one access token
// and generating and storing one opaque refresh token in a single call.
func BenchmarkIssueTokenPair(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, _ = benchMgr.IssueTokenPair(benchCtx, "bench-user")
		}
	})
}

// ============================================================================
// Category 2: Token Lifecycle
// ============================================================================

// BenchmarkRefreshAccessToken measures the token-rotation hot path: refresh token
// validation, access token re-issuance, and refresh token re-storage in one call.
// Each iteration issues a fresh refresh token outside the timed section.
func BenchmarkRefreshAccessToken(b *testing.B) {
	for i := range b.N {
		b.StopTimer()
		_, rt, _ := benchMgr.IssueTokenPair(benchCtx, fmt.Sprintf("bench-user-%d", i))
		b.StartTimer()
		_, _ = benchMgr.RefreshAccessToken(benchCtx, rt)
	}
}

// BenchmarkRevokeRefreshToken measures single-token revocation: storage read,
// revocation mark, and storage write. Each iteration seeds a fresh token outside
// the timed section.
func BenchmarkRevokeRefreshToken(b *testing.B) {
	for i := range b.N {
		b.StopTimer()
		_, rt, _ := benchMgr.IssueTokenPair(benchCtx, fmt.Sprintf("bench-user-%d", i))
		b.StartTimer()
		_ = benchMgr.RevokeRefreshToken(benchCtx, rt)
	}
}

// BenchmarkIntrospectToken measures token metadata retrieval: storage lookup plus
// JWT parse for expiry and claims. Uses a pre-stored active refresh token.
func BenchmarkIntrospectToken(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = benchMgr.IntrospectToken(benchCtx, benchRefTok)
		}
	})
}

// BenchmarkRevokeAllUserTokens measures bulk user revocation at N=10, 100, and
// 1000 tokens. Tokens are seeded directly into the store outside the timed
// section to exclude RSA signing overhead from setup.
func BenchmarkRevokeAllUserTokens(b *testing.B) {
	exp := time.Now().Add(24 * time.Hour)
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			s := storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{})
			mgr := newBenchMgr(b, s)
			b.ResetTimer()
			for i := range b.N {
				b.StopTimer()
				uid := fmt.Sprintf("bench-user-%d", i)
				for j := range n {
					_ = s.Store(benchCtx, fmt.Sprintf("tok-%d-%d", i, j), uid, nil, exp, nil)
				}
				b.StartTimer()
				_ = mgr.RevokeAllUserTokens(benchCtx, uid)
			}
		})
	}
}

// BenchmarkRevokeAllForAudience measures bulk audience revocation at N=10, 100,
// and 1000 tokens. Tokens are seeded directly into the store outside the timed
// section to exclude RSA signing overhead from setup.
func BenchmarkRevokeAllForAudience(b *testing.B) {
	exp := time.Now().Add(24 * time.Hour)
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			s := storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{})
			mgr := newBenchMgr(b, s)
			b.ResetTimer()
			for i := range b.N {
				b.StopTimer()
				aud := fmt.Sprintf("bench-aud-%d", i)
				for j := range n {
					_ = s.Store(benchCtx, fmt.Sprintf("tok-%d-%d", i, j), "bench-user", []string{aud}, exp, nil)
				}
				b.StartTimer()
				_ = mgr.RevokeAllForAudience(benchCtx, aud)
			}
		})
	}
}

// BenchmarkRevokeAllForUserAndAudience measures scoped audience+user revocation
// at N=10, 100, and 1000 tokens. Tokens are seeded directly into the store
// outside the timed section to exclude RSA signing overhead from setup.
func BenchmarkRevokeAllForUserAndAudience(b *testing.B) {
	exp := time.Now().Add(24 * time.Hour)
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			s := storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{})
			mgr := newBenchMgr(b, s)
			b.ResetTimer()
			for i := range b.N {
				b.StopTimer()
				uid := fmt.Sprintf("bench-user-%d", i)
				aud := fmt.Sprintf("bench-aud-%d", i)
				for j := range n {
					_ = s.Store(benchCtx, fmt.Sprintf("tok-%d-%d", i, j), uid, []string{aud}, exp, nil)
				}
				b.StartTimer()
				_ = mgr.RevokeAllForUserAndAudience(benchCtx, uid, aud)
			}
		})
	}
}

// BenchmarkListTokensForAudience measures paginated enumeration of the audience
// index set at N=100, 1000, and 10000 tokens. Tokens are seeded before ResetTimer
// and a full paginated scan is performed per iteration.
func BenchmarkListTokensForAudience(b *testing.B) {
	exp := time.Now().Add(24 * time.Hour)
	const benchAudience = "bench-list-aud"
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			s := storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{})
			mgr := newBenchMgr(b, s)
			for j := range n {
				_ = s.Store(benchCtx, fmt.Sprintf("tok-%d", j), "bench-user", []string{benchAudience}, exp, nil)
			}
			b.ResetTimer()
			for range b.N {
				cursor := ""
				for {
					_, next, _ := mgr.ListTokensForAudience(benchCtx, benchAudience, cursor, 100)
					cursor = next
					if cursor == "" {
						break
					}
				}
			}
		})
	}
}

// ============================================================================
// Category 3: Rotation-Under-Load
// ============================================================================

// BenchmarkValidateAccessToken_DuringRotation is the library's primary differentiator
// benchmark. It runs parallel validators against a token signed with the initial key
// while a background goroutine rotates keys every 50ms — the key overlap window
// keeps the original token valid throughout. This benchmark cannot be reproduced
// by single-key JWT libraries and measures read-write mutex contention during rotation.
func BenchmarkValidateAccessToken_DuringRotation(b *testing.B) {
	ks, err := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: b.TempDir()})
	if err != nil {
		b.Fatalf("NewDiskKeyStore: %v", err)
	}
	km, err := keys.NewManager(keys.KeyManagerConfig{
		KeyStore:            ks,
		KeySize:             2048,
		KeyRotationInterval: 24 * time.Hour,
		KeyOverlapDuration:  5 * time.Minute,
	})
	if err != nil {
		b.Fatalf("NewManager(keys): %v", err)
	}
	mgr, err := tokens.NewManager(tokens.TokenManagerConfig{
		KeyManager:           km,
		RefreshStore:         storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{}),
		AccessTokenDuration:  15 * time.Minute,
		RefreshTokenDuration: 30 * 24 * time.Hour,
		Issuer:               "bench",
		Audience:             []string{"bench-api"},
	})
	if err != nil {
		b.Fatalf("NewManager(tokens): %v", err)
	}
	if err := mgr.Start(benchCtx); err != nil {
		b.Fatalf("mgr.Start: %v", err)
	}
	// mgr.Shutdown shuts down km internally.
	b.Cleanup(func() { _ = mgr.Shutdown(benchCtx) })

	tok, err := mgr.IssueAccessToken(benchCtx, "bench-user")
	if err != nil {
		b.Fatalf("IssueAccessToken: %v", err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				_ = km.RotateKeys(benchCtx)
			}
		}
	}()
	// Stop the rotation goroutine before the manager shuts down.
	b.Cleanup(func() { close(stop); wg.Wait() })

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = mgr.ValidateAccessToken(benchCtx, tok)
		}
	})
}

// ============================================================================
// Category 6: Observability Tax
// ============================================================================

// BenchmarkIssueAccessToken_ObservabilityTax compares issuance overhead across
// three observability configurations: NoOp (baseline), PrometheusMetrics (counter
// and histogram increments), and OtelTracer (span start/end via the global no-op
// OTel provider).
func BenchmarkIssueAccessToken_ObservabilityTax(b *testing.B) {
	cases := []struct {
		name    string
		metrics metrics.Metrics
		tracer  tracing.Tracer
	}{
		{
			name:    "NoOp",
			metrics: metrics.NewNoOpMetrics(),
			tracer:  tracing.NewNoOpTracer(),
		},
		{
			name:    "PrometheusMetrics",
			metrics: metrics.NewPrometheusMetrics(metrics.PrometheusConfig{}),
			tracer:  tracing.NewNoOpTracer(),
		},
		{
			name:    "OtelTracer",
			metrics: metrics.NewNoOpMetrics(),
			tracer:  tracing.NewOtelTracer("bench"),
		},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			s := storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{})
			mgr := newBenchMgrWithObs(b, s, tc.tracer, tc.metrics)
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					_, _ = mgr.IssueAccessToken(benchCtx, "bench-user")
				}
			})
		})
	}
}

// BenchmarkValidateAccessToken_ObservabilityTax compares validation overhead
// between the NoOp tracer baseline and the OtelTracer backed by the global no-op
// OTel provider — isolating span dispatch cost on the hot validation path.
func BenchmarkValidateAccessToken_ObservabilityTax(b *testing.B) {
	cases := []struct {
		name   string
		tracer tracing.Tracer
	}{
		{"NoOp", tracing.NewNoOpTracer()},
		{"OtelTracer", tracing.NewOtelTracer("bench")},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			s := storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{})
			mgr := newBenchMgrWithObs(b, s, tc.tracer, metrics.NewNoOpMetrics())
			tok, err := mgr.IssueAccessToken(benchCtx, "bench-user")
			if err != nil {
				b.Fatalf("IssueAccessToken: %v", err)
			}
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					_, _ = mgr.ValidateAccessToken(benchCtx, tok)
				}
			})
		})
	}
}

// ============================================================================
// Category 7: golang-jwt/jwt Baseline
// ============================================================================

// BenchmarkSign_GolangJWT measures raw RS256 signing via golang-jwt/jwt without
// the jwtauth framework — the minimum achievable cost for JWT issuance.
func BenchmarkSign_GolangJWT(b *testing.B) {
	claims := jwt.RegisteredClaims{
		Subject:   "bench-user",
		Issuer:    "bench",
		Audience:  jwt.ClaimStrings{"bench-api"},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			_, _ = tok.SignedString(benchRSAKey)
		}
	})
}

// BenchmarkVerify_GolangJWT measures raw RS256 verification via golang-jwt/jwt
// without the jwtauth framework — the minimum achievable cost for JWT validation.
func BenchmarkVerify_GolangJWT(b *testing.B) {
	keyFunc := func(tok *jwt.Token) (interface{}, error) {
		return &benchRSAKey.PublicKey, nil
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = jwt.ParseWithClaims(benchGolangJWT, &jwt.RegisteredClaims{}, keyFunc)
		}
	})
}

// BenchmarkIssueAccessToken_jwtauth is the jwtauth counterpart to BenchmarkSign_GolangJWT
// for use in benchstat comparisons — run both to quantify framework overhead.
func BenchmarkIssueAccessToken_jwtauth(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = benchMgr.IssueAccessToken(benchCtx, "bench-user")
		}
	})
}

// BenchmarkValidateAccessToken_jwtauth is the jwtauth counterpart to
// BenchmarkVerify_GolangJWT for use in benchstat comparisons — run both to
// quantify framework overhead.
func BenchmarkValidateAccessToken_jwtauth(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = benchMgr.ValidateAccessToken(benchCtx, benchAccTok)
		}
	})
}
