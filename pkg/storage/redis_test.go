package storage_test

import (
	"context"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"

	"github.com/aetomala/jwtauth/internal/testutil"
	"github.com/aetomala/jwtauth/pkg/metrics"
	"github.com/aetomala/jwtauth/pkg/storage"
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

		return storage.NewRedisRefreshStore(client, logger, m)
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
