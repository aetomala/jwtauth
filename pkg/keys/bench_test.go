// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package keys_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/aetomala/jwtauth/pkg/keys"
)

var (
	benchCtx   = context.Background()
	benchKM    *keys.Manager
	benchKeyID string
)

func TestMain(m *testing.M) {
	tmpDir, err := os.MkdirTemp("", "bench-keys-*")
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

	if err := km.Start(benchCtx); err != nil {
		panic(err)
	}

	info, err := km.GetCurrentKeyInfo(benchCtx)
	if err != nil {
		panic(err)
	}

	benchKM = km
	benchKeyID = info.KeyID

	code := m.Run()

	_ = km.Shutdown(benchCtx)
	_ = os.RemoveAll(tmpDir)
	os.Exit(code)
}

// BenchmarkGetPublicKey_CacheHit measures the in-memory map lookup path on the
// hot validation path — the overwhelmingly common case during normal operation.
func BenchmarkGetPublicKey_CacheHit(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = benchKM.GetPublicKey(benchCtx, benchKeyID)
		}
	})
}

// BenchmarkGetPublicKey_CacheMiss measures the cold path where the requested key
// is absent from the in-memory cache and must be loaded from the DiskKeyStore.
// A dedicated manager is used: one rotation produces a historical key whose
// PrivateKey is not repopulated on cache reload — isolating the realistic miss
// scenario (a new instance loading a predecessor key for overlap-window validation).
func BenchmarkGetPublicKey_CacheMiss(b *testing.B) {
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
		b.Fatalf("NewManager: %v", err)
	}
	if err := km.Start(benchCtx); err != nil {
		b.Fatalf("Start: %v", err)
	}
	b.Cleanup(func() { _ = km.Shutdown(benchCtx) })

	// Capture the initial key before rotation so it becomes a historical key
	// still resident in the KeyStore but evictable from cache.
	oldInfo, err := km.GetCurrentKeyInfo(benchCtx)
	if err != nil {
		b.Fatalf("GetCurrentKeyInfo: %v", err)
	}
	oldKeyID := oldInfo.KeyID
	if err := km.RotateKeys(benchCtx); err != nil {
		b.Fatalf("RotateKeys: %v", err)
	}

	mu := km.Mu()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		mu.Lock()
		delete(km.Keys(), oldKeyID)
		mu.Unlock()
		b.StartTimer()
		_, _ = km.GetPublicKey(benchCtx, oldKeyID)
	}
}

// BenchmarkRotateKeys measures the full rotation cost: RSA 2048-bit key generation
// plus DiskKeyStore Save (new key) and UpdateMetadata (old key expiration).
// Expected range: 50–300 ms/op on modern hardware — document in PERFORMANCE.md.
func BenchmarkRotateKeys(b *testing.B) {
	ks, err := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: b.TempDir()})
	if err != nil {
		b.Fatalf("NewDiskKeyStore: %v", err)
	}
	km, err := keys.NewManager(keys.KeyManagerConfig{
		KeyStore:            ks,
		KeySize:             2048,
		KeyRotationInterval: 24 * time.Hour,
		KeyOverlapDuration:  1 * time.Millisecond,
	})
	if err != nil {
		b.Fatalf("NewManager: %v", err)
	}
	if err := km.Start(benchCtx); err != nil {
		b.Fatalf("Start: %v", err)
	}
	b.Cleanup(func() { _ = km.Shutdown(benchCtx) })
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := km.RotateKeys(benchCtx); err != nil {
			b.Fatalf("RotateKeys: %v", err)
		}
	}
}

// BenchmarkGetCurrentKeyInfo measures metadata-only read overhead — no private
// key material, just a map lookup and struct construction behind a read lock.
func BenchmarkGetCurrentKeyInfo(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = benchKM.GetCurrentKeyInfo(benchCtx)
		}
	})
}

// BenchmarkGetJWKS measures JWKS serialization overhead — iterating the key
// cache and returning pre-computed JWK structs behind a read lock.
func BenchmarkGetJWKS(b *testing.B) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = benchKM.GetJWKS(benchCtx)
		}
	})
}
