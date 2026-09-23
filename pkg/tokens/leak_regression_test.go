// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package tokens_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/golang-jwt/jwt/v5"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/redis/go-redis/v9"

	"github.com/aetomala/jwtauth/internal/tokenref"
	"github.com/aetomala/jwtauth/pkg/keys"
	"github.com/aetomala/jwtauth/pkg/logging"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/aetomala/jwtauth/pkg/tokens"
	"github.com/aetomala/jwtauth/pkg/tracing"
)

// ===== Recording Observability =====

// leakRecorder captures every value emitted to logs, spans, and metric labels,
// formatted with fmt.Sprint. All methods are safe for concurrent use.
type leakRecorder struct {
	mu     sync.Mutex
	values []string // every recorded key, value, message, error, and label
}

func (r *leakRecorder) add(vs ...interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, v := range vs {
		r.values = append(r.values, fmt.Sprint(v))
	}
}

func (r *leakRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.values))
	copy(out, r.values)
	return out
}

// recordingLogger is a logging.Logger that records messages, bound fields,
// and every key/value pair.
type recordingLogger struct {
	rec   *leakRecorder
	bound []interface{} // fields pre-bound via With
}

func (l *recordingLogger) log(msg string, kv []interface{}) {
	l.rec.add(msg)
	l.rec.add(l.bound...)
	l.rec.add(kv...)
}

func (l *recordingLogger) Debug(msg string, kv ...interface{}) { l.log(msg, kv) }
func (l *recordingLogger) Info(msg string, kv ...interface{})  { l.log(msg, kv) }
func (l *recordingLogger) Warn(msg string, kv ...interface{})  { l.log(msg, kv) }
func (l *recordingLogger) Error(msg string, kv ...interface{}) { l.log(msg, kv) }

func (l *recordingLogger) With(kv ...interface{}) logging.Logger {
	bound := make([]interface{}, 0, len(l.bound)+len(kv))
	bound = append(bound, l.bound...)
	bound = append(bound, kv...)
	return &recordingLogger{rec: l.rec, bound: bound}
}

// recordingTracer is a tracing.Tracer whose spans record names, attributes,
// errors, and status descriptions.
type recordingTracer struct{ rec *leakRecorder }

func (t *recordingTracer) Start(ctx context.Context, name string) (context.Context, tracing.Span) {
	t.rec.add(name)
	return ctx, &recordingSpan{rec: t.rec}
}

type recordingSpan struct{ rec *leakRecorder }

func (s *recordingSpan) End()                                       {}
func (s *recordingSpan) SetAttribute(key string, value interface{}) { s.rec.add(key, value) }
func (s *recordingSpan) SetAttributes(attrs map[string]interface{}) {
	for k, v := range attrs {
		s.rec.add(k, v)
	}
}
func (s *recordingSpan) RecordError(err error)                       { s.rec.add(err) }
func (s *recordingSpan) SetStatus(_ tracing.StatusCode, desc string) { s.rec.add(desc) }

// recordingMetrics is a metrics.Metrics that records metric names and labels.
type recordingMetrics struct{ rec *leakRecorder }

func (m *recordingMetrics) labels(name string, labels map[string]string) {
	m.rec.add(name)
	for k, v := range labels {
		m.rec.add(k, v)
	}
}

func (m *recordingMetrics) IncrementCounter(name string, l map[string]string)      { m.labels(name, l) }
func (m *recordingMetrics) AddCounter(name string, _ float64, l map[string]string) { m.labels(name, l) }
func (m *recordingMetrics) SetGauge(name string, _ float64, l map[string]string)   { m.labels(name, l) }
func (m *recordingMetrics) RecordHistogram(name string, _ float64, l map[string]string) {
	m.labels(name, l)
}
func (m *recordingMetrics) RecordDuration(name string, _ time.Duration, l map[string]string) {
	m.labels(name, l)
}

// ===== Stub Key Manager =====

var (
	leakKeyOnce  sync.Once
	leakKey      *rsa.PrivateKey // signing key served by stubKeyManager
	leakOtherKey *rsa.PrivateKey // unrelated key used to forge access tokens
)

// stubKeyManager is a keys.KeyManager backed by a single in-memory RSA key.
type stubKeyManager struct{ key *rsa.PrivateKey }

func (k *stubKeyManager) GetCurrentSigningKey(context.Context) (*rsa.PrivateKey, string, error) {
	return k.key, "leak-test-kid", nil
}
func (k *stubKeyManager) GetPublicKey(context.Context, string) (*rsa.PublicKey, error) {
	return &k.key.PublicKey, nil
}
func (k *stubKeyManager) GetKeyInfo(context.Context, string) (*keys.KeyInfo, error) { return nil, nil }
func (k *stubKeyManager) GetCurrentKeyInfo(context.Context) (*keys.KeyInfo, error)  { return nil, nil }
func (k *stubKeyManager) GetAllKeyInfo(context.Context) ([]keys.KeyInfo, error)     { return nil, nil }
func (k *stubKeyManager) GetJWKS(context.Context) (*keys.JWKS, error)               { return nil, nil }
func (k *stubKeyManager) RotateKeys(context.Context) error                          { return nil }
func (k *stubKeyManager) Start(context.Context) error                               { return nil }
func (k *stubKeyManager) Shutdown(context.Context) error                            { return nil }
func (k *stubKeyManager) IsRunning() bool                                           { return true }

// randomOpaqueToken returns a value shaped like a refresh token that was never
// issued by the manager under test.
func randomOpaqueToken() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	Expect(err).NotTo(HaveOccurred())
	return base64.RawURLEncoding.EncodeToString(b)
}

// lenientStore models a custom RefreshStore whose Retrieve returns expired and
// revoked records instead of an error — reaching Manager branches that the
// built-in stores short-circuit.
type lenientStore struct {
	storage.RefreshStore
	records map[string]*storage.RefreshToken // tokenID -> record returned as-is
}

func (s *lenientStore) Retrieve(ctx context.Context, tokenID string) (*storage.RefreshToken, error) {
	if r, ok := s.records[tokenID]; ok {
		return r, nil
	}
	return s.RefreshStore.Retrieve(ctx, tokenID)
}

// errorLeakingStore models a third-party RefreshStore that violates the
// RefreshStore contract by embedding the tokenID in its error text.
type errorLeakingStore struct {
	storage.RefreshStore
}

func (s *errorLeakingStore) Retrieve(_ context.Context, tokenID string) (*storage.RefreshToken, error) {
	return nil, fmt.Errorf("refresh token %s not found", tokenID)
}

// ===== Access Token Fixtures =====

// leakAccessClaims returns registered claims accepted by the manager under
// test, expiring at exp.
func leakAccessClaims(exp time.Time) jwt.RegisteredClaims {
	return jwt.RegisteredClaims{
		Subject:   "user-1",
		Issuer:    "leak-test",
		Audience:  jwt.ClaimStrings{"leak-aud"},
		ExpiresAt: jwt.NewNumericDate(exp),
		IssuedAt:  jwt.NewNumericDate(exp.Add(-10 * time.Minute)),
		NotBefore: jwt.NewNumericDate(exp.Add(-10 * time.Minute)),
		ID:        randomOpaqueToken(),
	}
}

// signAccessToken signs claims with key using RS256. An empty kid omits the
// kid header.
func signAccessToken(key *rsa.PrivateKey, kid string, claims jwt.RegisteredClaims) string {
	t := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if kid != "" {
		t.Header["kid"] = kid
	}
	s, err := t.SignedString(key)
	Expect(err).NotTo(HaveOccurred())
	return s
}

// tamperPayload rewrites the sub claim of a signed JWT without re-signing it.
func tamperPayload(tok string) string {
	parts := strings.Split(tok, ".")
	Expect(parts).To(HaveLen(3))
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	Expect(err).NotTo(HaveOccurred())
	var payload map[string]interface{}
	Expect(json.Unmarshal(raw, &payload)).To(Succeed())
	payload["sub"] = "attacker"
	raw, err = json.Marshal(payload)
	Expect(err).NotTo(HaveOccurred())
	parts[1] = base64.RawURLEncoding.EncodeToString(raw)
	return strings.Join(parts, ".")
}

// leakWindow is the substring length used to detect partial credential leaks:
// 12 base64url characters carry 72 bits, well beyond chance collision with
// unrelated output.
const leakWindow = 12

// secretFragments returns the parts of a credential that must never appear in
// output. For a JWT — three dot-separated segments — only the payload and
// signature segments are returned: the encoded header is identical across JWTs
// signed the same way and is not secret. Any other secret is returned whole.
func secretFragments(secret string) []string {
	if parts := strings.Split(secret, "."); len(parts) == 3 {
		return parts[1:]
	}
	return []string{secret}
}

// leakBackend describes a RefreshStore implementation under test.
type leakBackend struct {
	name     string
	newStore func(rec *leakRecorder) (storage.RefreshStore, *miniredis.Miniredis)
}

const leakKeyPrefix = "leak:"

var leakBackends = []leakBackend{
	{
		name: "MemoryRefreshStore",
		newStore: func(rec *leakRecorder) (storage.RefreshStore, *miniredis.Miniredis) {
			return storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{
				Logger:  &recordingLogger{rec: rec},
				Metrics: &recordingMetrics{rec: rec},
				Tracer:  &recordingTracer{rec: rec},
			}), nil
		},
	},
	{
		name: "RedisRefreshStore",
		newStore: func(rec *leakRecorder) (storage.RefreshStore, *miniredis.Miniredis) {
			mr, err := miniredis.Run()
			Expect(err).NotTo(HaveOccurred())
			client := redis.NewClient(&redis.Options{Addr: mr.Addr(), MaxRetries: -1})
			DeferCleanup(func() {
				_ = client.Close()
				mr.Close()
			})
			store, err := storage.NewRedisRefreshStore(storage.RedisRefreshStoreConfig{
				Client:    client,
				KeyPrefix: leakKeyPrefix,
				Logger:    &recordingLogger{rec: rec},
				Metrics:   &recordingMetrics{rec: rec},
				Tracer:    &recordingTracer{rec: rec},
			})
			Expect(err).NotTo(HaveOccurred())
			return store, mr
		},
	},
}

var _ = Describe("Refresh token leak regression", func() {
	for _, backend := range leakBackends {
		Describe(backend.name, func() {
			var (
				ctx      context.Context
				cancel   context.CancelFunc
				rec      *leakRecorder
				store    storage.RefreshStore
				mr       *miniredis.Miniredis
				mgr      *tokens.Manager
				shortMgr *tokens.Manager // issues refresh tokens that expire almost immediately
				secrets  []string        // every refresh or access token issued or presented during the spec

				// ===== Partial-Leak Index — rebuilt per spec =====
				leakWindows    map[string]struct{} // every leakWindow-length substring of every secret fragment
				shortFragments []string            // secret fragments shorter than leakWindow, matched whole
			)

			newManagerWith := func(s storage.RefreshStore, refreshTTL time.Duration) *tokens.Manager {
				m, err := tokens.NewManager(tokens.TokenManagerConfig{
					KeyManager:           &stubKeyManager{key: leakKey},
					RefreshStore:         s,
					Logger:               &recordingLogger{rec: rec},
					Metrics:              &recordingMetrics{rec: rec},
					Tracer:               &recordingTracer{rec: rec},
					Namespace:            "leak-ns",
					AccessTokenDuration:  5 * time.Minute,
					RefreshTokenDuration: refreshTTL,
					CleanupInterval:      time.Hour,
					Issuer:               "leak-test",
					Audience:             []string{"leak-aud"},
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(m.Start(ctx)).To(Succeed())
				DeferCleanup(func() {
					shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
					defer shutdownCancel()
					_ = m.Shutdown(shutdownCtx)
				})
				return m
			}

			newManager := func(refreshTTL time.Duration) *tokens.Manager {
				return newManagerWith(store, refreshTTL)
			}

			// track records tok as a secret and indexes every leakWindow-length
			// substring of its fragments, so findLeak detects partial leaks
			// without recomputing windows per recorded value.
			track := func(tok string) string {
				Expect(tok).NotTo(BeEmpty())
				secrets = append(secrets, tok)
				for _, f := range secretFragments(tok) {
					if len(f) < leakWindow {
						if f != "" {
							shortFragments = append(shortFragments, f)
						}
						continue
					}
					for i := 0; i+leakWindow <= len(f); i++ {
						leakWindows[f[i:i+leakWindow]] = struct{}{}
					}
				}
				return tok
			}

			// findLeak returns the first recorded value, or formatted error,
			// that contains any leakWindow-length substring of a tracked
			// credential — or a whole fragment shorter than the window —
			// together with the matched fragment.
			findLeak := func(errs ...error) (value, match string, leaked bool) {
				values := rec.snapshot()
				for _, err := range errs {
					if err != nil {
						values = append(values, fmt.Sprint(err))
					}
				}
				for _, v := range values {
					for i := 0; i+leakWindow <= len(v); i++ {
						if _, ok := leakWindows[v[i:i+leakWindow]]; ok {
							return v, v[i : i+leakWindow], true
						}
					}
					for _, f := range shortFragments {
						if strings.Contains(v, f) {
							return v, f, true
						}
					}
				}
				return "", "", false
			}

			// expectNoLeak fails if any recorded value, or any of the given
			// errors, contains a tracked refresh or access token or any part
			// of one.
			expectNoLeak := func(errs ...error) {
				GinkgoHelper()
				Expect(secrets).NotTo(BeEmpty())
				if v, match, leaked := findLeak(errs...); leaked {
					Fail(fmt.Sprintf("credential leaked into observability output: %q (matched fragment %q)", v, match))
				}
			}

			// expectRef asserts the non-reversible reference for tok was emitted.
			expectRef := func(tok string) {
				GinkgoHelper()
				Expect(rec.snapshot()).To(ContainElement(tokenref.Ref(tok)))
			}

			issueExpired := func() string {
				tok := track(must(shortMgr.IssueRefreshToken(ctx, "user-exp")))
				time.Sleep(60 * time.Millisecond)
				return tok
			}

			BeforeEach(func() {
				leakKeyOnce.Do(func() {
					var err error
					leakKey, err = rsa.GenerateKey(rand.Reader, 2048)
					Expect(err).NotTo(HaveOccurred())
					leakOtherKey, err = rsa.GenerateKey(rand.Reader, 2048)
					Expect(err).NotTo(HaveOccurred())
				})
				ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
				DeferCleanup(func() { cancel() })

				rec = &leakRecorder{}
				secrets = nil
				leakWindows = make(map[string]struct{})
				shortFragments = nil
				store, mr = backend.newStore(rec)
				mgr = newManager(time.Hour)
				shortMgr = newManager(50 * time.Millisecond)
			})

			// ===== PHASE 1: Issuance =====
			Describe("Phase 1: Issuance", func() {
				It("IssueRefreshToken", func() {
					tok := track(must(mgr.IssueRefreshToken(ctx, "user-1")))
					expectNoLeak()
					expectRef(tok)
				})

				It("IssueRefreshTokenWithClaims", func() {
					tok := track(must(mgr.IssueRefreshTokenWithClaims(ctx, "user-1",
						tokens.CustomClaims{"device": "d1"}, tokens.WithAudience("other-aud"))))
					expectNoLeak()
					expectRef(tok)
				})

				It("IssueAccessToken", func() {
					track(must(mgr.IssueAccessToken(ctx, "user-1")))
					expectNoLeak()
				})

				It("IssueAccessTokenWithClaims", func() {
					track(must(mgr.IssueAccessTokenWithClaims(ctx, "user-1",
						tokens.CustomClaims{"role": "admin"}, tokens.WithAudience("other-aud"))))
					expectNoLeak()
				})

				It("IssueTokenPair", func() {
					access, tok, err := mgr.IssueTokenPair(ctx, "user-1")
					Expect(err).NotTo(HaveOccurred())
					track(access)
					track(tok)
					expectNoLeak()
					expectRef(tok)
				})

				It("IssueTokenPairWithClaims", func() {
					access, tok, err := mgr.IssueTokenPairWithClaims(ctx, "user-1",
						tokens.CustomClaims{"role": "admin"}, tokens.CustomClaims{"device": "d1"})
					Expect(err).NotTo(HaveOccurred())
					track(access)
					track(tok)
					expectNoLeak()
					expectRef(tok)
				})
			})

			// ===== PHASE 2: Refresh =====
			Describe("Phase 2: Refresh", func() {
				type refreshFn func(ctx context.Context, tok string) (string, error)

				// Ordered slice — Ginkgo requires a deterministic spec tree.
				refreshers := []struct {
					name string
					get  func() refreshFn // resolved lazily; mgr is set in BeforeEach
				}{
					{"RefreshAccessToken", func() refreshFn { return mgr.RefreshAccessToken }},
					{"RefreshAccessTokenWithClaims", func() refreshFn {
						return func(ctx context.Context, tok string) (string, error) {
							return mgr.RefreshAccessTokenWithClaims(ctx, tok, tokens.CustomClaims{"k": "v"})
						}
					}},
				}

				for _, r := range refreshers {
					get := r.get
					Describe(r.name, func() {
						It("success", func() {
							tok := track(must(mgr.IssueRefreshToken(ctx, "user-1")))
							access, err := get()(ctx, tok)
							Expect(err).NotTo(HaveOccurred())
							track(access)
							expectNoLeak(err)
							expectRef(tok)
						})

						It("expired token", func() {
							tok := issueExpired()
							_, err := get()(ctx, tok)
							Expect(err).To(HaveOccurred())
							expectNoLeak(err)
						})

						It("revoked token", func() {
							tok := track(must(mgr.IssueRefreshToken(ctx, "user-1")))
							Expect(mgr.RevokeRefreshToken(ctx, tok)).To(Succeed())
							_, err := get()(ctx, tok)
							Expect(err).To(MatchError(tokens.ErrTokenRevoked))
							expectNoLeak(err)
						})

						It("unknown token", func() {
							tok := track(randomOpaqueToken())
							_, err := get()(ctx, tok)
							Expect(err).To(MatchError(tokens.ErrInvalidRefreshToken))
							expectNoLeak(err)
						})
					})
				}
			})

			// ===== PHASE 3: Introspection and Revocation =====
			Describe("Phase 3: Introspection and Revocation", func() {
				It("IntrospectToken — active, revoked, expired, unknown", func() {
					active := track(must(mgr.IssueRefreshToken(ctx, "user-1")))
					revoked := track(must(mgr.IssueRefreshToken(ctx, "user-1")))
					Expect(mgr.RevokeRefreshToken(ctx, revoked)).To(Succeed())
					expired := issueExpired()
					unknown := track(randomOpaqueToken())

					for _, tok := range []string{active, revoked, expired, unknown} {
						md, err := mgr.IntrospectToken(ctx, tok)
						Expect(err).NotTo(HaveOccurred())
						Expect(md).NotTo(BeNil())
					}
					expectNoLeak()
				})

				It("RevokeRefreshToken — existing and unknown", func() {
					tok := track(must(mgr.IssueRefreshToken(ctx, "user-1")))
					Expect(mgr.RevokeRefreshToken(ctx, tok)).To(Succeed())
					Expect(mgr.RevokeRefreshToken(ctx, track(randomOpaqueToken()))).To(Succeed())
					expectNoLeak()
					expectRef(tok)
				})

				It("RevokeAllUserTokens", func() {
					track(must(mgr.IssueRefreshToken(ctx, "user-1")))
					track(must(mgr.IssueRefreshToken(ctx, "user-1")))
					Expect(mgr.RevokeAllUserTokens(ctx, "user-1")).To(Succeed())
					expectNoLeak()
				})

				It("RevokeAllForAudience", func() {
					track(must(mgr.IssueRefreshToken(ctx, "user-1")))
					track(must(mgr.IssueRefreshToken(ctx, "user-2")))
					Expect(mgr.RevokeAllForAudience(ctx, "leak-aud")).To(Succeed())
					expectNoLeak()
				})

				It("RevokeAllForUserAndAudience", func() {
					track(must(mgr.IssueRefreshToken(ctx, "user-1")))
					track(must(mgr.IssueRefreshToken(ctx, "user-2")))
					Expect(mgr.RevokeAllForUserAndAudience(ctx, "user-1", "leak-aud")).To(Succeed())
					expectNoLeak()
				})
			})

			// ===== PHASE 4: Listing and Cleanup =====
			Describe("Phase 4: Listing and Cleanup", func() {
				BeforeEach(func() {
					for i := 0; i < 5; i++ {
						track(must(mgr.IssueRefreshToken(ctx, "user-1")))
					}
				})

				// paginate walks every page with a page size of 1 so that
				// non-empty cursors are produced and passed back in.
				paginate := func(list func(cursor string) (string, error)) {
					GinkgoHelper()
					cursor := ""
					for i := 0; i < 50; i++ {
						next, err := list(cursor)
						Expect(err).NotTo(HaveOccurred())
						if next == "" {
							return
						}
						cursor = next
					}
				}

				It("ListTokens", func() {
					paginate(func(c string) (string, error) {
						_, next, err := mgr.ListTokens(ctx, c, 1)
						return next, err
					})
					expectNoLeak()
				})

				It("ListTokensForUser", func() {
					paginate(func(c string) (string, error) {
						_, next, err := mgr.ListTokensForUser(ctx, "user-1", c, 1)
						return next, err
					})
					expectNoLeak()
				})

				It("ListTokensForAudience", func() {
					paginate(func(c string) (string, error) {
						_, next, err := mgr.ListTokensForAudience(ctx, "leak-aud", c, 1)
						return next, err
					})
					expectNoLeak()
				})

				It("CleanupExpiredTokens", func() {
					issueExpired()
					issueExpired()
					n, err := mgr.CleanupExpiredTokens(ctx)
					Expect(err).NotTo(HaveOccurred())
					Expect(n).To(BeNumerically(">=", 2))
					expectNoLeak(err)
				})
			})

			// ===== PHASE 5: Direct Store Calls =====
			Describe("Phase 5: Direct Store Calls", func() {
				It("Store, Retrieve, Revoke — success paths", func() {
					tok := track(randomOpaqueToken())
					Expect(store.Store(ctx, tok, "user-1", []string{"leak-aud"}, time.Now().Add(time.Hour),
						map[string]interface{}{"ip": "127.0.0.1"})).To(Succeed())
					_, err := store.Retrieve(ctx, tok)
					Expect(err).NotTo(HaveOccurred())
					Expect(store.Revoke(ctx, tok)).To(Succeed())
					_, err = store.Retrieve(ctx, tok)
					Expect(err).To(MatchError(storage.ErrTokenRevoked))
					expectNoLeak(err)
				})

				It("Store — validation failures", func() {
					tok := track(randomOpaqueToken())
					errUser := store.Store(ctx, tok, "", nil, time.Now().Add(time.Hour), nil)
					Expect(errUser).To(MatchError(storage.ErrInvalidUserID))
					errExp := store.Store(ctx, tok, "user-1", nil, time.Now().Add(-time.Minute), nil)
					Expect(errExp).To(MatchError(storage.ErrTokenExpired))
					expectNoLeak(errUser, errExp)
				})

				It("Retrieve, Revoke — unknown token", func() {
					tok := track(randomOpaqueToken())
					_, err := store.Retrieve(ctx, tok)
					Expect(err).To(MatchError(storage.ErrTokenNotFound))
					Expect(store.Revoke(ctx, tok)).To(Succeed())
					expectNoLeak(err)
				})

				It("Store, Retrieve, Revoke — cancelled context", func() {
					tok := track(randomOpaqueToken())
					cctx, ccancel := context.WithCancel(ctx)
					ccancel()
					errStore := store.Store(cctx, tok, "user-1", nil, time.Now().Add(time.Hour), nil)
					_, errRetrieve := store.Retrieve(cctx, tok)
					errRevoke := store.Revoke(cctx, tok)
					Expect(errStore).To(HaveOccurred())
					Expect(errRetrieve).To(HaveOccurred())
					Expect(errRevoke).To(HaveOccurred())
					expectNoLeak(errStore, errRetrieve, errRevoke)
				})
			})

			// ===== PHASE 6: Custom Store Returning Expired and Revoked Records =====
			Describe("Phase 6: Custom Store Returning Expired and Revoked Records", func() {
				var (
					lenient    *lenientStore
					lenientMgr *tokens.Manager
					expiredTok string
					revokedTok string
				)

				BeforeEach(func() {
					expiredTok = track(randomOpaqueToken())
					revokedTok = track(randomOpaqueToken())
					lenient = &lenientStore{
						RefreshStore: store,
						records: map[string]*storage.RefreshToken{
							expiredTok: {TokenID: expiredTok, UserID: "user-1",
								ExpiresAt: time.Now().Add(-time.Minute), CreatedAt: time.Now().Add(-time.Hour)},
							revokedTok: {TokenID: revokedTok, UserID: "user-1", Revoked: true,
								ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()},
						},
					}
					lenientMgr = newManagerWith(lenient, time.Hour)
				})

				It("IntrospectToken — expired and revoked records", func() {
					for _, tok := range []string{expiredTok, revokedTok} {
						md, err := lenientMgr.IntrospectToken(ctx, tok)
						Expect(err).NotTo(HaveOccurred())
						Expect(md.Active).To(BeFalse())
					}
					expectNoLeak()
					expectRef(expiredTok)
					expectRef(revokedTok)
				})

				It("RefreshAccessToken, RefreshAccessTokenWithClaims — expired record", func() {
					_, err1 := lenientMgr.RefreshAccessToken(ctx, expiredTok)
					_, err2 := lenientMgr.RefreshAccessTokenWithClaims(ctx, expiredTok, tokens.CustomClaims{"k": "v"})
					Expect(err1).To(MatchError(tokens.ErrRefreshTokenExpired))
					Expect(err2).To(MatchError(tokens.ErrRefreshTokenExpired))
					expectNoLeak(err1, err2)
					expectRef(expiredTok)
				})
			})

			// ===== PHASE 7: Redis-Specific Paths =====
			Describe("Phase 7: Redis-Specific Paths", func() {
				BeforeEach(func() {
					if mr == nil {
						Skip("Redis-only")
					}
				})

				It("BackfillExpiryIndex", func() {
					redisStore := store.(*storage.RedisRefreshStore)
					track(must(mgr.IssueRefreshToken(ctx, "user-1")))
					issueExpired()
					_, _, err := redisStore.BackfillExpiryIndex(ctx)
					Expect(err).NotTo(HaveOccurred())
					expectNoLeak(err)
				})

				It("corrupted records — Retrieve, ListTokens, BackfillExpiryIndex", func() {
					redisStore := store.(*storage.RedisRefreshStore)
					for _, field := range []string{"expiresAt", "createdAt", "audience", "metadata"} {
						tok := track(must(mgr.IssueRefreshTokenWithClaims(ctx, "user-1", tokens.CustomClaims{"k": "v"})))
						mr.HSet(leakKeyPrefix+"tokens:"+tok, field, "not-valid{")
						_, err := store.Retrieve(ctx, tok)
						Expect(err).To(HaveOccurred())
						expectNoLeak(err)
					}
					_, _, err := store.ListTokens(ctx, "", 100)
					Expect(err).NotTo(HaveOccurred())
					_, _, err = redisStore.BackfillExpiryIndex(ctx)
					Expect(err).NotTo(HaveOccurred())
					expectNoLeak(err)
				})

				It("Cleanup — unreadable record", func() {
					tok := issueExpired()
					key := leakKeyPrefix + "tokens:" + tok
					mr.Del(key)
					Expect(mr.Set(key, "wrong-type")).To(Succeed())
					_, err := mgr.CleanupExpiredTokens(ctx)
					Expect(err).NotTo(HaveOccurred())
					expectNoLeak(err)
				})

				It("backend unavailable — Store, Retrieve, Revoke, RevokeRefreshToken", func() {
					tok := track(must(mgr.IssueRefreshToken(ctx, "user-1")))
					mr.Close()
					errStore := store.Store(ctx, tok, "user-1", nil, time.Now().Add(time.Hour), nil)
					_, errRetrieve := store.Retrieve(ctx, tok)
					errRevoke := store.Revoke(ctx, tok)
					errMgr := mgr.RevokeRefreshToken(ctx, tok)
					_, errRefresh := mgr.RefreshAccessToken(ctx, tok)
					Expect(errStore).To(HaveOccurred())
					Expect(errRetrieve).To(HaveOccurred())
					Expect(errRevoke).To(HaveOccurred())
					Expect(errMgr).To(HaveOccurred())
					Expect(errRefresh).To(HaveOccurred())
					expectNoLeak(errStore, errRetrieve, errRevoke, errMgr, errRefresh)
				})
			})

			// ===== PHASE 8: Access Token Validation and Introspection =====
			Describe("Phase 8: Access Token Validation and Introspection", func() {
				// Ordered slices — Ginkgo requires a deterministic spec tree.
				// Tokens are built lazily; mgr and keys are set in BeforeEach.
				inputs := []struct {
					name    string
					build   func() string
					wantErr error // nil means the token must validate
				}{
					{"valid", func() string { return must(mgr.IssueAccessToken(ctx, "user-1")) }, nil},
					{"expired", func() string {
						return signAccessToken(leakKey, "leak-test-kid", leakAccessClaims(time.Now().Add(-time.Minute)))
					}, tokens.ErrTokenExpired},
					{"signed by a different key", func() string {
						return signAccessToken(leakOtherKey, "leak-test-kid", leakAccessClaims(time.Now().Add(5*time.Minute)))
					}, tokens.ErrInvalidToken},
					{"tampered payload", func() string {
						return tamperPayload(must(mgr.IssueAccessToken(ctx, "user-1")))
					}, tokens.ErrInvalidToken},
					{"missing kid header", func() string {
						return signAccessToken(leakKey, "", leakAccessClaims(time.Now().Add(5*time.Minute)))
					}, tokens.ErrTokenMissingKid},
					{"non-JWT garbage", func() string { return "not-a-jwt." + randomOpaqueToken() }, tokens.ErrInvalidToken},
				}

				validators := []struct {
					name     string
					validate func(ctx context.Context, tok string) error
				}{
					{"ValidateAccessToken", func(ctx context.Context, tok string) error {
						_, err := mgr.ValidateAccessToken(ctx, tok)
						return err
					}},
					{"ValidateAccessTokenWithClaims", func(ctx context.Context, tok string) error {
						_, _, err := mgr.ValidateAccessTokenWithClaims(ctx, tok)
						return err
					}},
				}

				for _, v := range validators {
					validate := v.validate
					Describe(v.name, func() {
						for _, in := range inputs {
							build, wantErr := in.build, in.wantErr
							It(in.name, func() {
								tok := track(build())
								err := validate(ctx, tok)
								if wantErr == nil {
									Expect(err).NotTo(HaveOccurred())
								} else {
									Expect(err).To(MatchError(wantErr))
								}
								expectNoLeak(err)
							})
						}
					})
				}

				// IntrospectToken accepts only refresh tokens, so an access token
				// is looked up as an unknown refresh-store key.
				It("IntrospectToken — access tokens are treated as unknown refresh tokens (inactive) and no part of them is emitted", func() {
					valid := track(must(mgr.IssueAccessToken(ctx, "user-1")))
					expired := track(signAccessToken(leakKey, "leak-test-kid",
						leakAccessClaims(time.Now().Add(-time.Minute))))
					for _, tok := range []string{valid, expired} {
						md, err := mgr.IntrospectToken(ctx, tok)
						Expect(err).NotTo(HaveOccurred())
						Expect(md.Active).To(BeFalse())
					}
					expectNoLeak()
				})
			})

			// ===== PHASE 9: RefreshStore Error Contract Boundary =====
			Describe("Phase 9: RefreshStore Error Contract Boundary", func() {
				// Contract demonstration, not a regression: the RefreshStore
				// contract forbids a tokenID in returned errors, and the Manager
				// logs store errors verbatim. A store that breaks the contract
				// therefore leaks the token — the library cannot redact
				// third-party error text. This spec pins that boundary.
				It("contract demonstration — a store error containing the token appears verbatim in logs", func() {
					tok := track(must(mgr.IssueRefreshToken(ctx, "user-1")))
					leakyMgr := newManagerWith(&errorLeakingStore{RefreshStore: store}, time.Hour)

					_, err := leakyMgr.RefreshAccessToken(ctx, tok)
					Expect(err).To(MatchError(tokens.ErrInvalidRefreshToken))
					Expect(err.Error()).NotTo(ContainSubstring(tok), "the Manager returns its own sentinel, not the store error")

					v, _, leaked := findLeak()
					Expect(leaked).To(BeTrue(), "a contract-violating store error is expected to reach observability output")
					Expect(v).To(ContainSubstring(tok))
				})
			})
		})
	}
})

// must unwraps a (string, error) result, failing the spec on error.
func must(s string, err error) string {
	GinkgoHelper()
	Expect(err).NotTo(HaveOccurred())
	return s
}
