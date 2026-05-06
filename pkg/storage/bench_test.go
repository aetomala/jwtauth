// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package storage_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/aetomala/jwtauth/pkg/storage"
)

var benchCtx = context.Background()

func newMemBenchStore() *storage.MemoryRefreshStore {
	return storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{})
}

// newRedisBenchStore returns a fresh RedisRefreshStore backed by an isolated
// miniredis instance. The returned cleanup func must be registered via b.Cleanup.
func newRedisBenchStore(b *testing.B) (*storage.RedisRefreshStore, func()) {
	b.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		b.Fatalf("miniredis.Run: %v", err)
	}
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	s, err := storage.NewRedisRefreshStore(storage.RedisRefreshStoreConfig{Client: client})
	if err != nil {
		mr.Close()
		b.Fatalf("NewRedisRefreshStore: %v", err)
	}
	return s, func() {
		_ = client.Close()
		mr.Close()
	}
}

func BenchmarkStore(b *testing.B) {
	exp := time.Now().Add(24 * time.Hour)

	b.Run("Memory", func(b *testing.B) {
		s := newMemBenchStore()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = s.Store(benchCtx, fmt.Sprintf("tok-%d", i), "bench-user", nil, exp, nil)
		}
	})

	b.Run("Redis", func(b *testing.B) {
		s, cleanup := newRedisBenchStore(b)
		b.Cleanup(cleanup)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = s.Store(benchCtx, fmt.Sprintf("tok-%d", i), "bench-user", nil, exp, nil)
		}
	})
}

// BenchmarkStore_WithAudience isolates the overhead of the two extra Redis SAdd
// calls per Store added in PR #135 (audience_tokens and audience_user_tokens index sets).
func BenchmarkStore_WithAudience(b *testing.B) {
	exp := time.Now().Add(24 * time.Hour)
	aud := []string{"bench-audience"}

	b.Run("Memory", func(b *testing.B) {
		s := newMemBenchStore()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = s.Store(benchCtx, fmt.Sprintf("tok-%d", i), "bench-user", aud, exp, nil)
		}
	})

	b.Run("Redis", func(b *testing.B) {
		s, cleanup := newRedisBenchStore(b)
		b.Cleanup(cleanup)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = s.Store(benchCtx, fmt.Sprintf("tok-%d", i), "bench-user", aud, exp, nil)
		}
	})
}

func BenchmarkRetrieve(b *testing.B) {
	exp := time.Now().Add(24 * time.Hour)
	const tokenID = "bench-retrieve-tok"

	b.Run("Memory", func(b *testing.B) {
		s := newMemBenchStore()
		_ = s.Store(benchCtx, tokenID, "bench-user", nil, exp, nil)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = s.Retrieve(benchCtx, tokenID)
		}
	})

	b.Run("Redis", func(b *testing.B) {
		s, cleanup := newRedisBenchStore(b)
		b.Cleanup(cleanup)
		_ = s.Store(benchCtx, tokenID, "bench-user", nil, exp, nil)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = s.Retrieve(benchCtx, tokenID)
		}
	})
}

func BenchmarkRevoke(b *testing.B) {
	exp := time.Now().Add(24 * time.Hour)

	b.Run("Memory", func(b *testing.B) {
		s := newMemBenchStore()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			tid := fmt.Sprintf("tok-revoke-%d", i)
			_ = s.Store(benchCtx, tid, "bench-user", nil, exp, nil)
			b.StartTimer()
			_ = s.Revoke(benchCtx, tid)
		}
	})

	b.Run("Redis", func(b *testing.B) {
		s, cleanup := newRedisBenchStore(b)
		b.Cleanup(cleanup)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			tid := fmt.Sprintf("tok-revoke-%d", i)
			_ = s.Store(benchCtx, tid, "bench-user", nil, exp, nil)
			b.StartTimer()
			_ = s.Revoke(benchCtx, tid)
		}
	})
}

func BenchmarkRevokeAllForUser(b *testing.B) {
	exp := time.Now().Add(24 * time.Hour)
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			b.Run("Memory", func(b *testing.B) {
				s := newMemBenchStore()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					b.StopTimer()
					uid := fmt.Sprintf("bench-user-%d", i)
					for j := 0; j < n; j++ {
						_ = s.Store(benchCtx, fmt.Sprintf("tok-%d-%d", i, j), uid, nil, exp, nil)
					}
					b.StartTimer()
					_ = s.RevokeAllForUser(benchCtx, uid)
				}
			})

			b.Run("Redis", func(b *testing.B) {
				s, cleanup := newRedisBenchStore(b)
				b.Cleanup(cleanup)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					b.StopTimer()
					uid := fmt.Sprintf("bench-user-%d", i)
					for j := 0; j < n; j++ {
						_ = s.Store(benchCtx, fmt.Sprintf("tok-%d-%d", i, j), uid, nil, exp, nil)
					}
					b.StartTimer()
					_ = s.RevokeAllForUser(benchCtx, uid)
				}
			})
		})
	}
}

func BenchmarkRevokeAllForAudience(b *testing.B) {
	exp := time.Now().Add(24 * time.Hour)
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			b.Run("Memory", func(b *testing.B) {
				s := newMemBenchStore()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					b.StopTimer()
					aud := fmt.Sprintf("bench-aud-%d", i)
					for j := 0; j < n; j++ {
						_ = s.Store(benchCtx, fmt.Sprintf("tok-%d-%d", i, j), "bench-user", []string{aud}, exp, nil)
					}
					b.StartTimer()
					_, _ = s.RevokeAllForAudience(benchCtx, aud)
				}
			})

			b.Run("Redis", func(b *testing.B) {
				s, cleanup := newRedisBenchStore(b)
				b.Cleanup(cleanup)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					b.StopTimer()
					aud := fmt.Sprintf("bench-aud-%d", i)
					for j := 0; j < n; j++ {
						_ = s.Store(benchCtx, fmt.Sprintf("tok-%d-%d", i, j), "bench-user", []string{aud}, exp, nil)
					}
					b.StartTimer()
					_, _ = s.RevokeAllForAudience(benchCtx, aud)
				}
			})
		})
	}
}

func BenchmarkRevokeAllForUserAndAudience(b *testing.B) {
	exp := time.Now().Add(24 * time.Hour)
	for _, n := range []int{10, 100, 1000} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			b.Run("Memory", func(b *testing.B) {
				s := newMemBenchStore()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					b.StopTimer()
					uid := fmt.Sprintf("bench-user-%d", i)
					aud := fmt.Sprintf("bench-aud-%d", i)
					for j := 0; j < n; j++ {
						_ = s.Store(benchCtx, fmt.Sprintf("tok-%d-%d", i, j), uid, []string{aud}, exp, nil)
					}
					b.StartTimer()
					_, _ = s.RevokeAllForUserAndAudience(benchCtx, uid, aud)
				}
			})

			b.Run("Redis", func(b *testing.B) {
				s, cleanup := newRedisBenchStore(b)
				b.Cleanup(cleanup)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					b.StopTimer()
					uid := fmt.Sprintf("bench-user-%d", i)
					aud := fmt.Sprintf("bench-aud-%d", i)
					for j := 0; j < n; j++ {
						_ = s.Store(benchCtx, fmt.Sprintf("tok-%d-%d", i, j), uid, []string{aud}, exp, nil)
					}
					b.StartTimer()
					_, _ = s.RevokeAllForUserAndAudience(benchCtx, uid, aud)
				}
			})
		})
	}
}

func BenchmarkListTokens(b *testing.B) {
	exp := time.Now().Add(24 * time.Hour)
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			b.Run("Memory", func(b *testing.B) {
				s := newMemBenchStore()
				for j := 0; j < n; j++ {
					_ = s.Store(benchCtx, fmt.Sprintf("tok-%d", j), "bench-user", nil, exp, nil)
				}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					cursor := ""
					for {
						_, next, _ := s.ListTokens(benchCtx, cursor, 100)
						cursor = next
						if cursor == "" {
							break
						}
					}
				}
			})

			b.Run("Redis", func(b *testing.B) {
				s, cleanup := newRedisBenchStore(b)
				b.Cleanup(cleanup)
				for j := 0; j < n; j++ {
					_ = s.Store(benchCtx, fmt.Sprintf("tok-%d", j), "bench-user", nil, exp, nil)
				}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					cursor := ""
					for {
						_, next, _ := s.ListTokens(benchCtx, cursor, 100)
						cursor = next
						if cursor == "" {
							break
						}
					}
				}
			})
		})
	}
}

func BenchmarkListTokensForUser(b *testing.B) {
	exp := time.Now().Add(24 * time.Hour)
	const benchUserID = "bench-list-user"
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			b.Run("Memory", func(b *testing.B) {
				s := newMemBenchStore()
				for j := 0; j < n; j++ {
					_ = s.Store(benchCtx, fmt.Sprintf("tok-%d", j), benchUserID, nil, exp, nil)
				}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					cursor := ""
					for {
						_, next, _ := s.ListTokensForUser(benchCtx, benchUserID, cursor, 100)
						cursor = next
						if cursor == "" {
							break
						}
					}
				}
			})

			b.Run("Redis", func(b *testing.B) {
				s, cleanup := newRedisBenchStore(b)
				b.Cleanup(cleanup)
				for j := 0; j < n; j++ {
					_ = s.Store(benchCtx, fmt.Sprintf("tok-%d", j), benchUserID, nil, exp, nil)
				}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					cursor := ""
					for {
						_, next, _ := s.ListTokensForUser(benchCtx, benchUserID, cursor, 100)
						cursor = next
						if cursor == "" {
							break
						}
					}
				}
			})
		})
	}
}

// BenchmarkListTokensForAudience measures SSCAN throughput on the
// audience_tokens:<aud> index set added in PR #143.
func BenchmarkListTokensForAudience(b *testing.B) {
	exp := time.Now().Add(24 * time.Hour)
	const benchAudience = "bench-list-aud"
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			b.Run("Memory", func(b *testing.B) {
				s := newMemBenchStore()
				for j := 0; j < n; j++ {
					_ = s.Store(benchCtx, fmt.Sprintf("tok-%d", j), "bench-user", []string{benchAudience}, exp, nil)
				}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					cursor := ""
					for {
						_, next, _ := s.ListTokensForAudience(benchCtx, benchAudience, cursor, 100)
						cursor = next
						if cursor == "" {
							break
						}
					}
				}
			})

			b.Run("Redis", func(b *testing.B) {
				s, cleanup := newRedisBenchStore(b)
				b.Cleanup(cleanup)
				for j := 0; j < n; j++ {
					_ = s.Store(benchCtx, fmt.Sprintf("tok-%d", j), "bench-user", []string{benchAudience}, exp, nil)
				}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					cursor := ""
					for {
						_, next, _ := s.ListTokensForAudience(benchCtx, benchAudience, cursor, 100)
						cursor = next
						if cursor == "" {
							break
						}
					}
				}
			})
		})
	}
}

// BenchmarkCleanup measures the scan cost of Cleanup against a store
// containing N live (non-expired) tokens — zero deletions, pure scan overhead.
func BenchmarkCleanup(b *testing.B) {
	exp := time.Now().Add(24 * time.Hour)
	for _, n := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("N=%d", n), func(b *testing.B) {
			b.Run("Memory", func(b *testing.B) {
				s := newMemBenchStore()
				for j := 0; j < n; j++ {
					_ = s.Store(benchCtx, fmt.Sprintf("tok-%d", j), "bench-user", nil, exp, nil)
				}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, _ = s.Cleanup(benchCtx)
				}
			})

			b.Run("Redis", func(b *testing.B) {
				s, cleanup := newRedisBenchStore(b)
				b.Cleanup(cleanup)
				for j := 0; j < n; j++ {
					_ = s.Store(benchCtx, fmt.Sprintf("tok-%d", j), "bench-user", nil, exp, nil)
				}
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, _ = s.Cleanup(benchCtx)
				}
			})
		})
	}
}
