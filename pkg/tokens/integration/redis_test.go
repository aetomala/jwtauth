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
	RunTokenManagerIntegrationTests(
		"TokenManager Integration — RedisKeyStore + RedisRefreshStore",
		redisFactory,
	)

	Describe("TokenManager Integration — distributed Redis behavior", func() {
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
			// because both TokenManagers read from the same Redis refresh store.

			// Instance A — own KeyManager, own TokenManager, shared Redis backend
			ksA, err := keymanager.NewRedisKeyStore(client, nil, nil)
			Expect(err).NotTo(HaveOccurred())

			kmA, err := keymanager.NewManager(keymanager.ManagerConfig{
				KeyStore:            ksA,
				KeyRotationInterval: 30 * 24 * time.Hour,
				KeySize:             2048,
			})
			Expect(err).NotTo(HaveOccurred())

			storeA := storage.NewRedisRefreshStore(client, nil, nil)
			mgrA, err := tokens.NewManager(tokens.ManagerConfig{
				KeyManager:           kmA,
				RefreshStore:         storeA,
				AccessTokenDuration:  5 * time.Minute,
				RefreshTokenDuration: 1 * time.Hour,
				Issuer:               "integration-test",
				Audience:             []string{"integration-test"},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(mgrA.Start(ctx)).To(Succeed())
			DeferCleanup(func() {
				shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
				defer c()
				_ = mgrA.Shutdown(shutdownCtx)
			})

			// Instance B — own KeyManager (loads A's keys from Redis), own TokenManager, shared refresh store
			ksB, err := keymanager.NewRedisKeyStore(client, nil, nil)
			Expect(err).NotTo(HaveOccurred())

			kmB, err := keymanager.NewManager(keymanager.ManagerConfig{
				KeyStore:            ksB,
				KeyRotationInterval: 30 * 24 * time.Hour,
				KeySize:             2048,
			})
			Expect(err).NotTo(HaveOccurred())

			storeB := storage.NewRedisRefreshStore(client, nil, nil)
			mgrB, err := tokens.NewManager(tokens.ManagerConfig{
				KeyManager:           kmB,
				RefreshStore:         storeB,
				AccessTokenDuration:  5 * time.Minute,
				RefreshTokenDuration: 1 * time.Hour,
				Issuer:               "integration-test",
				Audience:             []string{"integration-test"},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(mgrB.Start(ctx)).To(Succeed())
			DeferCleanup(func() {
				shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
				defer c()
				_ = mgrB.Shutdown(shutdownCtx)
			})

			userID := "distributed-user"

			// Instance A issues tokens
			_, refreshToken, err := mgrA.IssueTokenPair(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			// Instance B can use the refresh token (shared store)
			newAccessToken, err := mgrB.RefreshAccessToken(ctx, refreshToken)
			Expect(err).NotTo(HaveOccurred())
			Expect(newAccessToken).NotTo(BeEmpty())

			// Issue a fresh refresh token (the previous one was consumed by RefreshAccessToken)
			_, freshRefresh, err := mgrA.IssueTokenPair(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			// Instance A revokes all tokens for the user
			Expect(mgrA.RevokeAllUserTokens(ctx, userID)).To(Succeed())

			// Instance B must immediately observe the revocation — no cache, reads Redis directly
			_, err = mgrB.RefreshAccessToken(ctx, freshRefresh)
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
			mgrA, err := tokens.NewManager(tokens.ManagerConfig{
				KeyManager:           kmA,
				RefreshStore:         storeA,
				AccessTokenDuration:  5 * time.Minute,
				RefreshTokenDuration: 1 * time.Hour,
				Issuer:               "integration-test",
				Audience:             []string{"integration-test"},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(mgrA.Start(ctx)).To(Succeed())
			DeferCleanup(func() {
				shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
				defer c()
				_ = mgrA.Shutdown(shutdownCtx)
			})

			userID := "rotation-distributed-user"

			// Instance A issues a token with the initial key
			preRotationToken, err := mgrA.IssueAccessToken(ctx, userID)
			Expect(err).NotTo(HaveOccurred())

			// Instance A rotates keys — new key saved to Redis
			Expect(kmA.RotateKeys(ctx)).To(Succeed())

			// Instance A issues a token with the new key
			postRotationToken, err := mgrA.IssueAccessToken(ctx, userID)
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
			mgrB, err := tokens.NewManager(tokens.ManagerConfig{
				KeyManager:           kmB,
				RefreshStore:         storeB,
				AccessTokenDuration:  5 * time.Minute,
				RefreshTokenDuration: 1 * time.Hour,
				Issuer:               "integration-test",
				Audience:             []string{"integration-test"},
			})
			Expect(err).NotTo(HaveOccurred())
			Expect(mgrB.Start(ctx)).To(Succeed())
			DeferCleanup(func() {
				shutdownCtx, c := context.WithTimeout(context.Background(), 5*time.Second)
				defer c()
				_ = mgrB.Shutdown(shutdownCtx)
			})

			// Instance B validates both tokens signed by instance A's keys
			claims, err := mgrB.ValidateAccessToken(ctx, preRotationToken)
			Expect(err).NotTo(HaveOccurred())
			Expect(claims.Subject).To(Equal(userID))

			claims, err = mgrB.ValidateAccessToken(ctx, postRotationToken)
			Expect(err).NotTo(HaveOccurred())
			Expect(claims.Subject).To(Equal(userID))
		})
	})
}

// redisFactory creates a TokenManager backed by RedisKeyStore + RedisRefreshStore
// using an isolated miniredis instance. Each call produces a fully independent backend.
func redisFactory(cfg tokens.ManagerConfig) (*tokens.Manager, *keymanager.Manager, func()) {
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

	mgr, err := tokens.NewManager(cfg)
	Expect(err).NotTo(HaveOccurred())

	cleanup := func() {
		_ = client.Close()
		mr.Close()
	}

	return mgr, km, cleanup
}
