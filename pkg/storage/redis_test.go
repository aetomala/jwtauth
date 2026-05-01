package storage_test

import (
	"context"
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
		Expect(store.Store(ctx, "defaults-token", "defaults-user", time.Now().Add(time.Hour), nil)).To(Succeed())
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
		mockTracer.EXPECT().Start(gomock.Any(), gomock.Any(), gomock.Any()).Return(context.Background(), mockSpan).AnyTimes()
		mockSpan.EXPECT().End().AnyTimes()
		mockSpan.EXPECT().SetAttribute(gomock.Any(), gomock.Any()).AnyTimes()
		mockSpan.EXPECT().SetStatus(gomock.Any(), gomock.Any()).AnyTimes()

		store, err := storage.NewRedisRefreshStore(storage.RedisRefreshStoreConfig{Client: client, Tracer: mockTracer})
		Expect(err).NotTo(HaveOccurred())
		ctx := context.Background()
		Expect(store.Store(ctx, "tracer-token", "tracer-user", time.Now().Add(time.Hour), nil)).To(Succeed())
	})
})

// ===== PHASE 11: KeyPrefix Namespace Isolation =====
var _ = Describe("RedisRefreshStore — Phase 11: KeyPrefix Namespace Isolation", func() {
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

			Expect(store.Store(ctx, "tok1", "user1", time.Now().Add(time.Hour), nil)).To(Succeed())

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

			Expect(store.Store(ctx, "tok1", "user1", time.Now().Add(time.Hour), nil)).To(Succeed())

			storedKeys, err := client.Keys(ctx, "*").Result()
			Expect(err).NotTo(HaveOccurred())
			for _, k := range storedKeys {
				Expect(k).To(Or(HavePrefix("tokens:"), HavePrefix("user_tokens:")))
			}
		})
	})

	Context("two stores with different prefixes against the same Redis", func() {
		It("Retrieve should not find a token stored in the other namespace", func() {
			storeA := newStore("ns:a:")
			storeB := newStore("ns:b:")

			Expect(storeA.Store(ctx, "shared-token", "user1", time.Now().Add(time.Hour), nil)).To(Succeed())

			_, err := storeB.Retrieve(ctx, "shared-token")
			Expect(err).To(MatchError(storage.ErrTokenNotFound))
		})

		It("RevokeAllForUser in namespace A should not revoke tokens in namespace B", func() {
			storeA := newStore("ns:a:")
			storeB := newStore("ns:b:")

			Expect(storeA.Store(ctx, "tok-a", "user1", time.Now().Add(time.Hour), nil)).To(Succeed())
			Expect(storeB.Store(ctx, "tok-b", "user1", time.Now().Add(time.Hour), nil)).To(Succeed())

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
			Expect(storeB.Store(ctx, "expired-b", "user2", time.Now().Add(time.Hour), nil)).To(Succeed())
			mr.FastForward(2 * time.Hour)

			// Store a live token in A so A has something to scan
			Expect(storeA.Store(ctx, "live-a", "user2", time.Now().Add(time.Hour), nil)).To(Succeed())

			// Cleanup on A must not touch B's expired token (it's outside A's scan pattern)
			removed, err := storeA.Cleanup(ctx)
			Expect(err).NotTo(HaveOccurred())
			Expect(removed).To(Equal(0))
		})
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
			mockTracer.EXPECT().Start(gomock.Any(), "RedisRefreshStore.Store", gomock.Any()).Return(ctx, mockSpan)
			mockSpan.EXPECT().SetAttribute("token_id", "trace-store-token")
			mockSpan.EXPECT().SetStatus(tracing.StatusOK, "")
			mockSpan.EXPECT().End()

			Expect(tracingStore.Store(ctx, "trace-store-token", "trace-user", time.Now().Add(time.Hour), nil)).To(Succeed())
		})
	})

	Context("Retrieve — error path", func() {
		It("should call RecordError and StatusError when token is not found", func() {
			mockTracer.EXPECT().Start(gomock.Any(), "RedisRefreshStore.Retrieve", gomock.Any()).Return(ctx, mockSpan)
			mockSpan.EXPECT().SetAttribute("token_id", "missing-trace-token")
			mockSpan.EXPECT().RecordError(storage.ErrTokenNotFound)
			mockSpan.EXPECT().SetStatus(tracing.StatusError, gomock.Any())
			mockSpan.EXPECT().End()

			_, err := tracingStore.Retrieve(ctx, "missing-trace-token")
			Expect(err).To(MatchError(storage.ErrTokenNotFound))
		})
	})
})
