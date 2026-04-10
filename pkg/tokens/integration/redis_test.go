//go:build integration

package integration

import (
	"context"
	"time"

	"github.com/alicebob/miniredis/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/redis/go-redis/v9"

	"github.com/aetomala/jwtauth/pkg/keymanager"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/aetomala/jwtauth/pkg/tokens"
)

func init() {
	RunTokenServiceIntegrationTests(
		"TokenService Integration — RedisKeyStore + RedisRefreshStore",
		redisFactory,
	)

	Describe("TokenService Integration — distributed Redis behavior", func() {
		var (
			mr     *miniredis.Miniredis
			client *redis.Client
			ctx    context.Context
			cancel context.CancelFunc
		)

		BeforeEach(func() {
			var err error
			ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)

			mr, err = miniredis.Run()
			Expect(err).NotTo(HaveOccurred())

			client = redis.NewClient(&redis.Options{Addr: mr.Addr()})
			Expect(client.Ping(ctx).Err()).NotTo(HaveOccurred())

			DeferCleanup(func() {
				cancel()
				_ = client.Close()
				mr.Close()
			})
		})

		It("should sync token revocation across instances sharing the same Redis", func() {
			// Both instances have their own in-process KeyManager but share the same Redis
			// key store and refresh store — this is the distributed deployment model.
			// Each Manager starts independently, loading shared keys from Redis.
			// Instance A issues and revokes; instance B must observe the revocation immediately
			// because both TokenServices read from the same Redis refresh store.

			// Instance A — own KeyManager, own TokenService, shared Redis backend
			ksA, err := keymanager.NewRedisKeyStore(client, nil, nil)
			Expect(err).NotTo(HaveOccurred())

			kmA, err := keymanager.NewManager(keymanager.ManagerConfig{
				KeyStore:            ksA,
				KeyRotationInterval: 30 * 24 * time.Hour,
				KeySize:             2048,
			})
			Expect(err).NotTo(HaveOccurred())

			storeA := storage.NewRedisRefreshStore(client, nil, nil)
			svcA, err := tokens.NewService(tokens.ServiceConfig{
				KeyManager:           kmA,
				RefreshStore:         storeA,
				AccessTokenDuration:  5 * time.Minute,
				RefreshTokenDuration: 1 * time.Hour,
				Issuer:               "integration-test",
				Audience:             []string{"integration-test"},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(svcA.Start(ctx)).To(Succeed())
			DeferCleanup(func() {
				shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
				defer c()
				_ = svcA.Shutdown(shutdownCtx)
			})

			// Instance B — own KeyManager (loads A's keys from Redis), own TokenService, shared refresh store
			ksB, err := keymanager.NewRedisKeyStore(client, nil, nil)
			Expect(err).NotTo(HaveOccurred())

			kmB, err := keymanager.NewManager(keymanager.ManagerConfig{
				KeyStore:            ksB,
				KeyRotationInterval: 30 * 24 * time.Hour,
				KeySize:             2048,
			})
			Expect(err).NotTo(HaveOccurred())

			storeB := storage.NewRedisRefreshStore(client, nil, nil)
			svcB, err := tokens.NewService(tokens.ServiceConfig{
				KeyManager:           kmB,
				RefreshStore:         storeB,
				AccessTokenDuration:  5 * time.Minute,
				RefreshTokenDuration: 1 * time.Hour,
				Issuer:               "integration-test",
				Audience:             []string{"integration-test"},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(svcB.Start(ctx)).To(Succeed())
			DeferCleanup(func() {
				shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
				defer c()
				_ = svcB.Shutdown(shutdownCtx)
			})

			userID := "distributed-user"

			// Instance A issues tokens
			_, refreshToken, err := svcA.IssueTokenPair(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			// Instance B can use the refresh token (shared store)
			newAccessToken, err := svcB.RefreshAccessToken(ctx, refreshToken)
			Expect(err).NotTo(HaveOccurred())
			Expect(newAccessToken).NotTo(BeEmpty())

			// Issue a fresh refresh token (the previous one was consumed by RefreshAccessToken)
			_, freshRefresh, err := svcA.IssueTokenPair(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			// Instance A revokes all tokens for the user
			Expect(svcA.RevokeAllUserTokens(ctx, userID)).To(Succeed())

			// Instance B must immediately observe the revocation — no cache, reads Redis directly
			_, err = svcB.RefreshAccessToken(ctx, freshRefresh)
			Expect(err).To(Equal(tokens.ErrTokenRevoked))
		})

		It("should load keys created by another instance after key rotation", func() {
			// Instance A starts, generates an initial key, issues a token, then rotates.
			// Instance B starts fresh (new Manager, same Redis key store) and must be able
			// to validate tokens signed by both the pre- and post-rotation keys of instance A.

			ksA, err := keymanager.NewRedisKeyStore(client, nil, nil)
			Expect(err).NotTo(HaveOccurred())

			kmA, err := keymanager.NewManager(keymanager.ManagerConfig{
				KeyStore:            ksA,
				KeyRotationInterval: 30 * 24 * time.Hour,
				KeySize:             2048,
			})
			Expect(err).NotTo(HaveOccurred())

			storeA := storage.NewRedisRefreshStore(client, nil, nil)
			svcA, err := tokens.NewService(tokens.ServiceConfig{
				KeyManager:           kmA,
				RefreshStore:         storeA,
				AccessTokenDuration:  5 * time.Minute,
				RefreshTokenDuration: 1 * time.Hour,
				Issuer:               "integration-test",
				Audience:             []string{"integration-test"},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(svcA.Start(ctx)).To(Succeed())
			DeferCleanup(func() {
				shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
				defer c()
				_ = svcA.Shutdown(shutdownCtx)
			})

			userID := "rotation-distributed-user"

			// Instance A issues a token with the initial key
			preRotationToken, err := svcA.IssueAccessToken(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			// Instance A rotates keys — new key saved to Redis
			Expect(kmA.RotateKeys(ctx)).To(Succeed())

			// Instance A issues a token with the new key
			postRotationToken, err := svcA.IssueAccessToken(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			// Instance B starts with the same Redis key store — loads all keys on Start
			ksB, err := keymanager.NewRedisKeyStore(client, nil, nil)
			Expect(err).NotTo(HaveOccurred())

			kmB, err := keymanager.NewManager(keymanager.ManagerConfig{
				KeyStore:            ksB,
				KeyRotationInterval: 30 * 24 * time.Hour,
				KeySize:             2048,
			})
			Expect(err).NotTo(HaveOccurred())

			storeB := storage.NewRedisRefreshStore(client, nil, nil)
			svcB, err := tokens.NewService(tokens.ServiceConfig{
				KeyManager:           kmB,
				RefreshStore:         storeB,
				AccessTokenDuration:  5 * time.Minute,
				RefreshTokenDuration: 1 * time.Hour,
				Issuer:               "integration-test",
				Audience:             []string{"integration-test"},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(svcB.Start(ctx)).To(Succeed())
			DeferCleanup(func() {
				shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
				defer c()
				_ = svcB.Shutdown(shutdownCtx)
			})

			// Instance B validates both tokens signed by instance A's keys
			claims, err := svcB.ValidateAccessToken(ctx, preRotationToken)
			Expect(err).NotTo(HaveOccurred())
			Expect(claims.Subject).To(Equal(userID))

			claims, err = svcB.ValidateAccessToken(ctx, postRotationToken)
			Expect(err).NotTo(HaveOccurred())
			Expect(claims.Subject).To(Equal(userID))
		})
	})
}

// redisFactory creates a TokenService backed by RedisKeyStore + RedisRefreshStore
// using an isolated miniredis instance. Each call produces a fully independent backend.
func redisFactory(cfg tokens.ServiceConfig) (*tokens.Service, *keymanager.Manager, func()) {
	mr, err := miniredis.Run()
	Expect(err).NotTo(HaveOccurred())

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})

	ks, err := keymanager.NewRedisKeyStore(client, nil, nil)
	Expect(err).NotTo(HaveOccurred())

	km, err := keymanager.NewManager(keymanager.ManagerConfig{
		KeyStore:            ks,
		KeyRotationInterval: 30 * 24 * time.Hour,
		KeySize:             2048,
	})
	Expect(err).NotTo(HaveOccurred())

	cfg.KeyManager = km
	cfg.RefreshStore = storage.NewRedisRefreshStore(client, nil, nil)

	svc, err := tokens.NewService(cfg)
	Expect(err).NotTo(HaveOccurred())

	cleanup := func() {
		_ = client.Close()
		mr.Close()
	}

	return svc, km, cleanup
}
