// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package storage_test

import (
	"context"
	"fmt"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"go.uber.org/mock/gomock"

	"github.com/aetomala/jwtauth/internal/testutil"
	"github.com/aetomala/jwtauth/pkg/metrics"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/aetomala/jwtauth/pkg/tracing"
)

var (
	miniRedis *miniredis.Miniredis
)

var _ = RunRefreshStoreTests(
	"RedisRefreshStore", "redis",
	// Factory: creates RedisRefreshStore with miniredis
	func(logger *testutil.MockLogger, m metrics.Metrics) storage.RefreshStore {
		var err error
		miniRedis, err = miniredis.Run()
		Expect(err).NotTo(HaveOccurred())

		client := redis.NewClient(&redis.Options{
			Addr: miniRedis.Addr(),
		})

		// Verify connection
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_, err = client.Ping(ctx).Result()
		Expect(err).NotTo(HaveOccurred())

		store, err := storage.NewRedisRefreshStore(storage.RedisRefreshStoreConfig{Client: client, Logger: logger, Metrics: m})
		Expect(err).NotTo(HaveOccurred())
		return store
	},
	// Cleanup: flush miniredis after each test
	func() {
		if miniRedis != nil {
			miniRedis.FlushAll()
		}
	},
)

var _ = AfterSuite(func() {
	// Clean up miniredis after all tests
	if miniRedis != nil {
		miniRedis.Close()
	}
})

var _ = Describe("RedisRefreshStore — Constructor", func() {
	var (
		mr     *miniredis.Miniredis
		client *redis.Client
	)

	BeforeEach(func() {
		var err error
		mr, err = miniredis.Run()
		Expect(err).NotTo(HaveOccurred())
		client = redis.NewClient(&redis.Options{Addr: mr.Addr()})
	})

	AfterEach(func() {
		_ = client.Close()
		mr.Close()
	})

	It("should apply defaults from RedisRefreshStoreConfigDefault when optional fields are nil", func() {
		store, err := storage.NewRedisRefreshStore(storage.RedisRefreshStoreConfig{Client: client})
		Expect(err).NotTo(HaveOccurred())
		ctx := context.Background()
		Expect(store.Store(ctx, "defaults-token", "defaults-user", nil, time.Now().Add(time.Hour), nil)).To(Succeed())
		_, err = store.Retrieve(ctx, "defaults-token")
		Expect(err).NotTo(HaveOccurred())
	})

	It("should return ErrNilClient when Client is nil", func() {
		_, err := storage.NewRedisRefreshStore(storage.RedisRefreshStoreConfig{})
		Expect(err).To(MatchError(storage.ErrNilClient))
	})

	It("should accept an explicit Tracer without error", func() {
		ctrl := gomock.NewController(GinkgoT())
		defer ctrl.Finish()
		mockTracer := testutil.NewMockTracer(ctrl)
		mockSpan := testutil.NewMockSpan(ctrl)
		mockTracer.EXPECT().Start(gomock.Any(), gomock.Any()).Return(context.Background(), mockSpan).AnyTimes()
		mockSpan.EXPECT().End().AnyTimes()
		mockSpan.EXPECT().SetAttribute(gomock.Any(), gomock.Any()).AnyTimes()
		mockSpan.EXPECT().SetAttributes(gomock.Any()).AnyTimes()
		mockSpan.EXPECT().SetStatus(gomock.Any(), gomock.Any()).AnyTimes()

		store, err := storage.NewRedisRefreshStore(storage.RedisRefreshStoreConfig{Client: client, Tracer: mockTracer})
		Expect(err).NotTo(HaveOccurred())
		ctx := context.Background()
		Expect(store.Store(ctx, "tracer-token", "tracer-user", nil, time.Now().Add(time.Hour), nil)).To(Succeed())
	})

	It("should return Namespace() equal to the Namespace field, not KeyPrefix", func() {
		store, err := storage.NewRedisRefreshStore(storage.RedisRefreshStoreConfig{
			Client:    client,
			KeyPrefix: "storage:",
			Namespace: "obs-ns",
		})
		Expect(err).NotTo(HaveOccurred())
		Expect(store.Namespace()).To(Equal("obs-ns"))
	})
})

// ===== PHASE 11: KeyPrefix and Namespace Isolation =====
var _ = Describe("RedisRefreshStore — Phase 11: KeyPrefix and Namespace Isolation", func() {
	var (
		mr  *miniredis.Miniredis
		ctx context.Context
	)

	BeforeEach(func() {
		var err error
		mr, err = miniredis.Run()
		Expect(err).NotTo(HaveOccurred())
		ctx = context.Background()
	})

	AfterEach(func() { mr.Close() })

	newStore := func(prefix string) *storage.RedisRefreshStore {
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		store, err := storage.NewRedisRefreshStore(storage.RedisRefreshStoreConfig{
			Client:    client,
			KeyPrefix: prefix,
		})
		Expect(err).NotTo(HaveOccurred())
		return store
	}

	Context("with a non-empty KeyPrefix", func() {
		It("should store all keys under the configured prefix", func() {
			store := newStore("tenant:abc:")
			client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

			Expect(store.Store(ctx, "tok1", "user1", nil, time.Now().Add(time.Hour), nil)).To(Succeed())

			storedKeys, err := client.Keys(ctx, "*").Result()
			Expect(err).NotTo(HaveOccurred())
			for _, k := range storedKeys {
				Expect(k).To(HavePrefix("tenant:abc:"))
			}
		})
	})

	Context("with an empty KeyPrefix", func() {
		It("should use bare constants — backward compatible with existing deployments", func() {
			store := newStore("")
			client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

			Expect(store.Store(ctx, "tok1", "user1", nil, time.Now().Add(time.Hour), nil)).To(Succeed())

			storedKeys, err := client.Keys(ctx, "*").Result()
			Expect(err).NotTo(HaveOccurred())
			for _, k := range storedKeys {
				Expect(k).To(Or(HavePrefix("tokens:"), HavePrefix("user_tokens:"), Equal("token_expiry_index")))
			}
		})
	})

	Context("two stores with different prefixes against the same Redis", func() {
		It("Retrieve should not find a token stored in the other namespace", func() {
			storeA := newStore("ns:a:")
			storeB := newStore("ns:b:")

			Expect(storeA.Store(ctx, "shared-token", "user1", nil, time.Now().Add(time.Hour), nil)).To(Succeed())

			_, err := storeB.Retrieve(ctx, "shared-token")
			Expect(err).To(MatchError(storage.ErrTokenNotFound))
		})

		It("RevokeAllForUser in namespace A should not revoke tokens in namespace B", func() {
			storeA := newStore("ns:a:")
			storeB := newStore("ns:b:")

			Expect(storeA.Store(ctx, "tok-a", "user1", nil, time.Now().Add(time.Hour), nil)).To(Succeed())
			Expect(storeB.Store(ctx, "tok-b", "user1", nil, time.Now().Add(time.Hour), nil)).To(Succeed())

			Expect(storeA.RevokeAllForUser(ctx, "user1")).To(Succeed())

			// tok-a should now be revoked
			_, err := storeA.Retrieve(ctx, "tok-a")
			Expect(err).To(MatchError(storage.ErrTokenRevoked))

			// tok-b in namespace B should be unaffected
			tok, err := storeB.Retrieve(ctx, "tok-b")
			Expect(err).NotTo(HaveOccurred())
			Expect(tok.TokenID).To(Equal("tok-b"))
		})

		It("Cleanup in namespace A should not remove expired tokens in namespace B", func() {
			storeA := newStore("ns:a:")
			storeB := newStore("ns:b:")

			// Store an already-expired token directly via miniredis manipulation:
			// Store with a 1-second TTL, then fast-forward time.
			Expect(storeB.Store(ctx, "expired-b", "user2", nil, time.Now().Add(time.Hour), nil)).To(Succeed())
			mr.FastForward(2 * time.Hour)

			// Store a live token in A so A has something to scan
			Expect(storeA.Store(ctx, "live-a", "user2", nil, time.Now().Add(time.Hour), nil)).To(Succeed())

			// Cleanup on A must not touch B's expired token (it's outside A's scan pattern)
			removed, err := storeA.Cleanup(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(removed).To(Equal(0))
		})
	})

	Context("with both KeyPrefix and Namespace set", func() {
		It("should use KeyPrefix for Redis key routing and Namespace for observability", func() {
			client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
			store, err := storage.NewRedisRefreshStore(storage.RedisRefreshStoreConfig{
				Client:    client,
				KeyPrefix: "tokens:tenant-a:",
				Namespace: "tenant-a-obs",
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(store.Namespace()).To(Equal("tenant-a-obs"))

			Expect(store.Store(ctx, "tok1", "user1", nil, time.Now().Add(time.Hour), nil)).To(Succeed())

			rawClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
			storedKeys, err := rawClient.Keys(ctx, "*").Result()
			Expect(err).NotTo(HaveOccurred())
			for _, k := range storedKeys {
				Expect(k).To(HavePrefix("tokens:tenant-a:"))
			}
		})
	})
})

var _ = Describe("RedisRefreshStore — Cleanup Expiry Index", func() {
	var (
		mr     *miniredis.Miniredis
		client *redis.Client
		store  *storage.RedisRefreshStore
		ctx    context.Context
	)

	BeforeEach(func() {
		var err error
		mr, err = miniredis.Run()
		Expect(err).NotTo(HaveOccurred())
		client = redis.NewClient(&redis.Options{Addr: mr.Addr()})
		store, err = storage.NewRedisRefreshStore(storage.RedisRefreshStoreConfig{Client: client})
		Expect(err).NotTo(HaveOccurred())
		ctx = context.Background()
	})

	AfterEach(func() {
		_ = client.Close()
		mr.Close()
	})

	It("should discover and remove a token whose hash already naturally TTL-evicted", func() {
		// go-redis's Expire command rounds sub-second durations up to a
		// 1-second minimum (it uses the whole-seconds EXPIRE command), so
		// the real Redis TTL applied here is ~1s regardless of expiresAt.
		// miniredis's own TTL countdown only advances via FastForward, not
		// real time, so both a real sleep (to clear the logical expiresAt
		// used by Cleanup's own comparisons) and a FastForward (to clear
		// miniredis's internal TTL and trigger native eviction) are needed.
		shortLived := time.Now().Add(50 * time.Millisecond)
		err := store.Store(ctx, "ttl-evict-token", "user1", nil, shortLived, nil)
		if err != nil {
			Skip("Store rejected short-lived token")
		}

		time.Sleep(100 * time.Millisecond)
		mr.FastForward(2 * time.Second)

		// The hash should have naturally TTL-evicted by now (Store sets a
		// native Redis Expire matching expiresAt), while the expiry-index
		// entry -- which carries no TTL of its own -- still references it.
		Expect(client.Exists(ctx, "tokens:ttl-evict-token").Val()).To(Equal(int64(0)))
		_, err = client.ZScore(ctx, "token_expiry_index", "ttl-evict-token").Result()
		Expect(err).NotTo(HaveOccurred())

		removed, err := store.Cleanup(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(Equal(1))

		_, err = client.ZScore(ctx, "token_expiry_index", "ttl-evict-token").Result()
		Expect(err).To(MatchError(redis.Nil))
	})

	It("should paginate across multiple batches when more than 100 tokens are expired", func() {
		const tokenCount = 150
		shortLived := time.Now().Add(50 * time.Millisecond)
		for i := 0; i < tokenCount; i++ {
			tokenID := fmt.Sprintf("page-token-%d", i)
			err := store.Store(ctx, tokenID, "page-user", nil, shortLived, nil)
			if err != nil {
				Skip("Store rejected short-lived token")
			}
		}

		time.Sleep(150 * time.Millisecond)

		removed, err := store.Cleanup(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(Equal(tokenCount))
	})
})

var _ = Describe("RedisRefreshStore — BackfillExpiryIndex", func() {
	var (
		mr     *miniredis.Miniredis
		client *redis.Client
		store  *storage.RedisRefreshStore
		ctx    context.Context
	)

	BeforeEach(func() {
		var err error
		mr, err = miniredis.Run()
		Expect(err).NotTo(HaveOccurred())
		client = redis.NewClient(&redis.Options{Addr: mr.Addr()})
		store, err = storage.NewRedisRefreshStore(storage.RedisRefreshStoreConfig{Client: client})
		Expect(err).NotTo(HaveOccurred())
		ctx = context.Background()
	})

	AfterEach(func() {
		_ = client.Close()
		mr.Close()
	})

	It("should sweep already-expired pre-migration tokens and index still-live ones", func() {
		// Simulate pre-migration data: written directly via raw Redis
		// commands, bypassing Store, so no expiry-index entry exists --
		// mirroring what a deployment upgrading in place would have.
		liveExpiry := time.Now().Add(time.Hour)
		Expect(client.HSet(ctx, "tokens:live-legacy", map[string]interface{}{
			"userID":    "legacy-user",
			"expiresAt": liveExpiry.UnixMilli(),
			"createdAt": time.Now().UnixMilli(),
			"revoked":   "false",
			"metadata":  "",
			"audience":  "",
		}).Err()).To(Succeed())
		Expect(client.SAdd(ctx, "user_tokens:legacy-user", "live-legacy").Err()).To(Succeed())

		expiredExpiry := time.Now().Add(-time.Hour)
		Expect(client.HSet(ctx, "tokens:expired-legacy", map[string]interface{}{
			"userID":    "legacy-user",
			"expiresAt": expiredExpiry.UnixMilli(),
			"createdAt": time.Now().UnixMilli(),
			"revoked":   "false",
			"metadata":  "",
			"audience":  "",
		}).Err()).To(Succeed())
		Expect(client.SAdd(ctx, "user_tokens:legacy-user", "expired-legacy").Err()).To(Succeed())

		// Neither token has an expiry-index entry yet.
		card, err := client.ZCard(ctx, "token_expiry_index").Result()
		Expect(err).NotTo(HaveOccurred())
		Expect(card).To(Equal(int64(0)))

		removed, indexed, err := store.BackfillExpiryIndex(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(Equal(1))
		Expect(indexed).To(Equal(1))

		// The expired legacy token is gone, and its userID index entry pruned.
		Expect(client.Exists(ctx, "tokens:expired-legacy").Val()).To(Equal(int64(0)))
		members, err := client.SMembers(ctx, "user_tokens:legacy-user").Result()
		Expect(err).NotTo(HaveOccurred())
		Expect(members).To(ConsistOf("live-legacy"))

		// The live legacy token is now indexed and discoverable by Cleanup.
		score, err := client.ZScore(ctx, "token_expiry_index", "live-legacy").Result()
		Expect(err).NotTo(HaveOccurred())
		Expect(score).To(BeNumerically("~", float64(liveExpiry.UnixMilli()), 1))

		_, err = store.Retrieve(ctx, "live-legacy")
		Expect(err).NotTo(HaveOccurred())
	})

	It("should be idempotent — a second call finds nothing left to do", func() {
		Expect(store.Store(ctx, "already-migrated", "user1", nil, time.Now().Add(time.Hour), nil)).To(Succeed())

		removed1, indexed1, err := store.BackfillExpiryIndex(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed1).To(Equal(0))
		Expect(indexed1).To(Equal(1)) // Store already indexed it; ZAdd just refreshes the same score

		removed2, indexed2, err := store.BackfillExpiryIndex(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed2).To(Equal(0))
		Expect(indexed2).To(Equal(1))
	})

	It("should return the context error when the context is cancelled", func() {
		cancelledCtx, cancel := context.WithCancel(ctx)
		cancel()

		removed, indexed, err := store.BackfillExpiryIndex(cancelledCtx)
		Expect(err).To(MatchError(context.Canceled))
		Expect(removed).To(Equal(0))
		Expect(indexed).To(Equal(0))
	})
})

// ===== PHASE 10: Tracing =====
var _ = Describe("RedisRefreshStore — Phase 10: Tracing", func() {
	var (
		ctrl         *gomock.Controller
		mockTracer   *testutil.MockTracer
		mockSpan     *testutil.MockSpan
		tracingStore *storage.RedisRefreshStore
		mr           *miniredis.Miniredis
		ctx          context.Context
	)

	BeforeEach(func() {
		ctx = context.Background()
		ctrl = gomock.NewController(GinkgoT())
		mockTracer = testutil.NewMockTracer(ctrl)
		mockSpan = testutil.NewMockSpan(ctrl)

		var err error
		mr, err = miniredis.Run()
		Expect(err).NotTo(HaveOccurred())

		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		tracingStore, err = storage.NewRedisRefreshStore(storage.RedisRefreshStoreConfig{
			Client: client,
			Tracer: mockTracer,
		})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		ctrl.Finish()
		mr.Close()
	})

	Context("Store — success path", func() {
		It("should start a span named RedisRefreshStore.Store with storage.backend, token_id and StatusOK", func() {
			mockTracer.EXPECT().Start(gomock.Any(), "RedisRefreshStore.Store").Return(ctx, mockSpan)
			mockSpan.EXPECT().SetAttributes(map[string]any{"storage_backend": "redis", "namespace": ""})
			mockSpan.EXPECT().SetAttribute("token_id", "trace-store-token")
			mockSpan.EXPECT().SetStatus(tracing.StatusOK, "")
			mockSpan.EXPECT().End()

			Expect(tracingStore.Store(ctx, "trace-store-token", "trace-user", nil, time.Now().Add(time.Hour), nil)).To(Succeed())
		})
	})

	Context("Retrieve — error path", func() {
		It("should call RecordError and StatusError when token is not found", func() {
			mockTracer.EXPECT().Start(gomock.Any(), "RedisRefreshStore.Retrieve").Return(ctx, mockSpan)
			mockSpan.EXPECT().SetAttributes(map[string]any{"storage_backend": "redis", "namespace": ""})
			mockSpan.EXPECT().SetAttribute("token_id", "missing-trace-token")
			mockSpan.EXPECT().RecordError(storage.ErrTokenNotFound)
			mockSpan.EXPECT().SetStatus(tracing.StatusError, gomock.Any())
			mockSpan.EXPECT().End()

			_, err := tracingStore.Retrieve(ctx, "missing-trace-token")
			Expect(err).To(MatchError(storage.ErrTokenNotFound))
		})
	})

	Context("Namespace field takes precedence over KeyPrefix in span attributes", func() {
		It("should set namespace span attribute from Namespace field, not KeyPrefix", func() {
			var err error
			localMr, err := miniredis.Run()
			Expect(err).NotTo(HaveOccurred())
			defer localMr.Close()

			client := redis.NewClient(&redis.Options{Addr: localMr.Addr()})
			store, err := storage.NewRedisRefreshStore(storage.RedisRefreshStoreConfig{
				Client:    client,
				KeyPrefix: "storage:",
				Namespace: "obs-ns",
				Tracer:    mockTracer,
			})
			Expect(err).NotTo(HaveOccurred())

			mockTracer.EXPECT().Start(gomock.Any(), "RedisRefreshStore.Store").Return(ctx, mockSpan)
			mockSpan.EXPECT().SetAttributes(map[string]any{"storage_backend": "redis", "namespace": "obs-ns"})
			mockSpan.EXPECT().SetAttribute("token_id", "trace-ns-token")
			mockSpan.EXPECT().SetStatus(tracing.StatusOK, "")
			mockSpan.EXPECT().End()

			Expect(store.Store(ctx, "trace-ns-token", "user1", nil, time.Now().Add(time.Hour), nil)).To(Succeed())
		})
	})
})
