// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package keys_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"sync"
	"time"

	"github.com/alicebob/miniredis/v2"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/redis/go-redis/v9"
	"go.uber.org/mock/gomock"

	"github.com/aetomala/jwtauth/internal/testutil"
	"github.com/aetomala/jwtauth/pkg/keys"
	"github.com/aetomala/jwtauth/pkg/tracing"
)

var _ = Describe("RedisKeyStore", func() {
	var (
		miniRedis *miniredis.Miniredis
		client    *redis.Client
		rs        *keys.RedisKeyStore
		ctx       context.Context
	)

	BeforeEach(func() {
		var err error
		miniRedis, err = miniredis.Run()
		Expect(err).NotTo(HaveOccurred())

		client = redis.NewClient(&redis.Options{
			Addr: miniRedis.Addr(),
		})

		rs, err = keys.NewRedisKeyStore(keys.RedisKeyStoreConfig{Client: client})
		Expect(err).NotTo(HaveOccurred())

		ctx = context.Background()
	})

	AfterEach(func() {
		if miniRedis != nil {
			miniRedis.Close()
			miniRedis = nil
		}
	})

	// ===== PHASE 1: Constructor and Initialization =====
	Describe("Phase 1: Constructor and Initialization", func() {
		Context("with a valid client", func() {
			It("should create a RedisKeyStore successfully", func() {
				store, err := keys.NewRedisKeyStore(keys.RedisKeyStoreConfig{Client: client})
				Expect(err).NotTo(HaveOccurred())
				Expect(store).NotTo(BeNil())
			})

			It("should accept a logger and metrics without error", func() {
				mockLogger := testutil.NewMockLogger()
				store, err := keys.NewRedisKeyStore(keys.RedisKeyStoreConfig{Client: client, Logger: mockLogger})
				Expect(err).NotTo(HaveOccurred())
				Expect(store).NotTo(BeNil())
			})

			It("should apply defaults from RedisKeyStoreConfigDefault when optional fields are nil", func() {
				store, err := keys.NewRedisKeyStore(keys.RedisKeyStoreConfig{Client: client})
				Expect(err).NotTo(HaveOccurred())
				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err = store.Save(ctx, testKeyA, key, metadata)
				Expect(err).NotTo(HaveOccurred())
				_, _, err = store.LoadKey(ctx, testKeyA)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should accept an explicit Tracer without error", func() {
				ctrl := gomock.NewController(GinkgoT())
				defer ctrl.Finish()
				mockTracer := testutil.NewMockTracer(ctrl)
				mockSpan := testutil.NewMockSpan(ctrl)
				mockTracer.EXPECT().Start(gomock.Any(), gomock.Any(), gomock.Any()).Return(ctx, mockSpan).AnyTimes()
				mockSpan.EXPECT().End().AnyTimes()
				mockSpan.EXPECT().SetAttribute(gomock.Any(), gomock.Any()).AnyTimes()
				mockSpan.EXPECT().SetStatus(gomock.Any(), gomock.Any()).AnyTimes()
				store, err := keys.NewRedisKeyStore(keys.RedisKeyStoreConfig{Client: client, Tracer: mockTracer})
				Expect(err).NotTo(HaveOccurred())
				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err = store.Save(ctx, testKeyA, key, metadata)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("with a nil client", func() {
			It("should return ErrNilRedisClient", func() {
				_, err := keys.NewRedisKeyStore(keys.RedisKeyStoreConfig{})
				Expect(err).To(MatchError(keys.ErrNilRedisClient))
			})
		})
	})

	// ===== PHASE 2: Save =====
	Describe("Phase 2: Save", func() {
		Context("with a valid key and metadata", func() {
			It("should persist PEM and metadata retrievable via LoadKey", func() {
				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}

				err := rs.Save(ctx, testKeyA, key, metadata)
				Expect(err).NotTo(HaveOccurred())

				loaded, loadedMeta, err := rs.LoadKey(ctx, testKeyA)
				Expect(err).NotTo(HaveOccurred())
				Expect(loaded.N.Cmp(key.N)).To(Equal(0))
				Expect(loadedMeta.ID).To(Equal(testKeyA))
			})

			It("should overwrite an existing key on repeated Save", func() {
				key1 := newTestKey()
				key2 := newTestKey()
				firstKeyMetadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}

				err := rs.Save(ctx, testKeyA, key1, firstKeyMetadata)
				Expect(err).NotTo(HaveOccurred())
				secondKeyMetadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err = rs.Save(ctx, testKeyA, key2, secondKeyMetadata)
				Expect(err).NotTo(HaveOccurred())

				loaded, _, err := rs.LoadKey(ctx, testKeyA)
				Expect(err).NotTo(HaveOccurred())
				Expect(loaded.N.Cmp(key2.N)).To(Equal(0))
			})
		})

		Context("context cancellation", func() {
			It("should return context error when context is already cancelled", func() {
				cancelCtx, cancel := context.WithCancel(context.Background())
				cancel()

				key := newTestKey()
				meta := keys.KeyMetadata{ID: "cancelled-key", CreatedAt: time.Now()}
				err := rs.Save(cancelCtx, "cancelled-key", key, meta)
				Expect(err).To(MatchError(context.Canceled))
			})
		})
	})

	// ===== PHASE 3: LoadAll =====
	Describe("Phase 3: LoadAll", func() {
		Context("with saved keys", func() {
			It("should return all saved non-expired keys", func() {
				key1, key2 := newTestKey(), newTestKey()
				firstKeyMetadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				secondKeyMetadata := keys.KeyMetadata{ID: testKeyB, CreatedAt: time.Now()}
				err := rs.Save(ctx, testKeyA, key1, firstKeyMetadata)
				Expect(err).NotTo(HaveOccurred())
				err = rs.Save(ctx, testKeyB, key2, secondKeyMetadata)
				Expect(err).NotTo(HaveOccurred())

				keys, err := rs.LoadAll(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(keys).To(HaveLen(2))
			})

			It("should skip already-expired keys", func() {
				active := newTestKey()
				expired := newTestKey()

				activeKeyMetadata := keys.KeyMetadata{
					ID:        testKeyA,
					CreatedAt: time.Now(),
				}
				expiredKeyMetadata := keys.KeyMetadata{
					ID:        testKeyB,
					CreatedAt: time.Now().Add(-2 * time.Hour),
					ExpiresAt: time.Now().Add(-1 * time.Hour),
				}
				err := rs.Save(ctx, testKeyA, active, activeKeyMetadata)
				Expect(err).NotTo(HaveOccurred())
				err = rs.Save(ctx, testKeyB, expired, expiredKeyMetadata)
				Expect(err).NotTo(HaveOccurred())

				keys, err := rs.LoadAll(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(keys).To(HaveLen(1))
				Expect(keys[0].KeyID).To(Equal(testKeyA))
			})
		})

		Context("with no keys in store", func() {
			It("should return an empty slice without error", func() {
				keys, err := rs.LoadAll(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(keys).To(BeEmpty())
			})
		})

		Context("context cancellation", func() {
			It("should return context error when context is already cancelled", func() {
				cancelCtx, cancel := context.WithCancel(context.Background())
				cancel()

				_, err := rs.LoadAll(cancelCtx)
				Expect(err).To(MatchError(context.Canceled))
			})
		})
	})

	// ===== PHASE 4: LoadKey =====
	Describe("Phase 4: LoadKey", func() {
		Context("with a saved key", func() {
			It("should return the private key and metadata", func() {
				key := newTestKey()
				now := time.Now().Truncate(time.Second)
				savedMetadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: now}
				err := rs.Save(ctx, testKeyA, key, savedMetadata)
				Expect(err).NotTo(HaveOccurred())

				loaded, loadedMeta, err := rs.LoadKey(ctx, testKeyA)
				Expect(err).NotTo(HaveOccurred())
				Expect(loaded).NotTo(BeNil())
				Expect(loaded.N.Cmp(key.N)).To(Equal(0))
				Expect(loadedMeta.ID).To(Equal(testKeyA))
			})
		})

		Context("missing or invalid key", func() {
			It("should return ErrKeyStoreKeyNotFound for a missing key ID", func() {
				_, _, err := rs.LoadKey(ctx, testKeyMissing)
				Expect(err).To(MatchError(keys.ErrKeyStoreKeyNotFound))
			})

			It("should return ErrKeyStoreInvalidKeyID for an empty key ID", func() {
				_, _, err := rs.LoadKey(ctx, "")
				Expect(err).To(MatchError(keys.ErrKeyStoreInvalidKeyID))
			})

			It("should return ErrKeyStoreInvalidKeyID for a whitespace-only key ID", func() {
				_, _, err := rs.LoadKey(ctx, "   ")
				Expect(err).To(MatchError(keys.ErrKeyStoreInvalidKeyID))
			})

			It("should return ErrKeyStoreInvalidKeyID for a path traversal attempt with ../ prefix", func() {
				_, _, err := rs.LoadKey(ctx, "../../etc/passwd")
				Expect(err).To(MatchError(keys.ErrKeyStoreInvalidKeyID))
			})

			It("should return ErrKeyStoreInvalidKeyID for a path traversal attempt with ../ infix", func() {
				_, _, err := rs.LoadKey(ctx, "abc/../../../etc/shadow")
				Expect(err).To(MatchError(keys.ErrKeyStoreInvalidKeyID))
			})

			It("should return ErrKeyStoreInvalidKeyID for an absolute path", func() {
				_, _, err := rs.LoadKey(ctx, "/etc/passwd")
				Expect(err).To(MatchError(keys.ErrKeyStoreInvalidKeyID))
			})

			It("should return ErrKeyStoreInvalidKeyID for a non-UUID string", func() {
				_, _, err := rs.LoadKey(ctx, "not-a-uuid")
				Expect(err).To(MatchError(keys.ErrKeyStoreInvalidKeyID))
			})
		})

		Context("context cancellation", func() {
			It("should return context error when context is already cancelled", func() {
				cancelCtx, cancel := context.WithCancel(context.Background())
				cancel()

				_, _, err := rs.LoadKey(cancelCtx, "any-key")
				Expect(err).To(MatchError(context.Canceled))
			})
		})
	})

	// ===== PHASE 5: UpdateMetadata =====
	Describe("Phase 5: UpdateMetadata", func() {
		Context("updating an existing key", func() {
			It("should persist the updated ExpiresAt and be visible on LoadKey", func() {
				key := newTestKey()
				now := time.Now()
				savedMetadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: now}
				err := rs.Save(ctx, testKeyA, key, savedMetadata)
				Expect(err).NotTo(HaveOccurred())

				expiry := now.Add(1 * time.Hour)
				updatedMetadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: now, ExpiresAt: expiry}
				err = rs.UpdateMetadata(ctx, testKeyA, updatedMetadata)
				Expect(err).NotTo(HaveOccurred())

				_, loadedMeta, err := rs.LoadKey(ctx, testKeyA)
				Expect(err).NotTo(HaveOccurred())
				Expect(loadedMeta.ExpiresAt.UTC().Truncate(time.Second)).To(Equal(expiry.UTC().Truncate(time.Second)))
			})
		})

		Context("updating a non-existent key", func() {
			It("should return ErrKeyStoreKeyNotFound", func() {
				metadata := keys.KeyMetadata{ID: testKeyMissing, CreatedAt: time.Now()}
				err := rs.UpdateMetadata(ctx, testKeyMissing, metadata)
				Expect(err).To(MatchError(keys.ErrKeyStoreKeyNotFound))
			})
		})

		Context("context cancellation", func() {
			It("should return context error when context is already cancelled", func() {
				cancelCtx, cancel := context.WithCancel(context.Background())
				cancel()

				meta := keys.KeyMetadata{ID: "any-key", CreatedAt: time.Now()}
				err := rs.UpdateMetadata(cancelCtx, "any-key", meta)
				Expect(err).To(MatchError(context.Canceled))
			})
		})
	})

	// ===== PHASE 6: Delete =====
	Describe("Phase 6: Delete", func() {
		Context("deleting an existing key", func() {
			It("should remove both PEM and metadata from Redis", func() {
				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err := rs.Save(ctx, testKeyA, key, metadata)
				Expect(err).NotTo(HaveOccurred())

				err = rs.Delete(ctx, testKeyA)
				Expect(err).NotTo(HaveOccurred())

				_, _, err = rs.LoadKey(ctx, testKeyA)
				Expect(err).To(MatchError(keys.ErrKeyStoreKeyNotFound))
			})

			It("should make the key absent from LoadAll after deletion", func() {
				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err := rs.Save(ctx, testKeyA, key, metadata)
				Expect(err).NotTo(HaveOccurred())
				err = rs.Delete(ctx, testKeyA)
				Expect(err).NotTo(HaveOccurred())

				keys, err := rs.LoadAll(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(keys).To(BeEmpty())
			})
		})

		Context("deleting a non-existent key", func() {
			It("should succeed without error — idempotent", func() {
				err := rs.Delete(ctx, testKeyMissing)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("context cancellation", func() {
			It("should return context error when context is already cancelled", func() {
				cancelCtx, cancel := context.WithCancel(context.Background())
				cancel()

				err := rs.Delete(cancelCtx, "any-key")
				Expect(err).To(MatchError(context.Canceled))
			})
		})
	})

	// ===== PHASE 7: Error Handling and Edge Cases =====
	Describe("Phase 7: Error Handling and Edge Cases", func() {
		Context("LoadAll with a key missing its metadata entry", func() {
			It("should skip the key without returning an error", func() {
				key := newTestKey()
				pemBytes := pem.EncodeToMemory(&pem.Block{
					Type:  "RSA PRIVATE KEY",
					Bytes: x509.MarshalPKCS1PrivateKey(key),
				})
				// Write PEM directly — no metadata entry
				Expect(client.Set(ctx, rs.PemPrefix()+"no-meta-key", string(pemBytes), 0).Err()).To(Succeed())

				keys, err := rs.LoadAll(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(keys).To(BeEmpty())
			})
		})

		Context("LoadAll with corrupted metadata JSON", func() {
			It("should skip the key without returning an error", func() {
				key := newTestKey()
				pemBytes := pem.EncodeToMemory(&pem.Block{
					Type:  "RSA PRIVATE KEY",
					Bytes: x509.MarshalPKCS1PrivateKey(key),
				})
				Expect(client.Set(ctx, rs.PemPrefix()+"bad-meta-key", string(pemBytes), 0).Err()).To(Succeed())
				Expect(client.Set(ctx, rs.MetaPrefix()+"bad-meta-key", "NOT_VALID_JSON", 0).Err()).To(Succeed())

				keys, err := rs.LoadAll(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(keys).To(BeEmpty())
			})
		})

		Context("LoadKey when metadata entry is missing", func() {
			It("should return ErrKeyStoreKeyNotFound", func() {
				key := newTestKey()
				pemBytes := pem.EncodeToMemory(&pem.Block{
					Type:  "RSA PRIVATE KEY",
					Bytes: x509.MarshalPKCS1PrivateKey(key),
				})
				// Write PEM only — no metadata
				Expect(client.Set(ctx, rs.PemPrefix()+testKeyA, string(pemBytes), 0).Err()).To(Succeed())

				_, _, err := rs.LoadKey(ctx, testKeyA)
				Expect(err).To(MatchError(keys.ErrKeyStoreKeyNotFound))
			})
		})

		Context("Save when Redis is unavailable", func() {
			It("should return an error without panicking", func() {
				miniRedis.SetError("forced error")
				defer miniRedis.SetError("")

				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err := rs.Save(ctx, testKeyA, key, metadata)
				Expect(err).To(HaveOccurred())
			})
		})
	})

	// ===== PHASE 8: Concurrency and Thread Safety =====
	Describe("Phase 8: Concurrency and Thread Safety", func() {
		Context("concurrent Save and LoadKey", func() {
			It("should not race on concurrent writes and reads", func() {
				const numOps = 10
				var wg sync.WaitGroup

				// Pre-save one key for readers
				preKey := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err := rs.Save(ctx, testKeyA, preKey, metadata)
				Expect(err).NotTo(HaveOccurred())

				// Concurrent readers
				for i := 0; i < numOps; i++ {
					wg.Add(1)
					go func() {
						defer GinkgoRecover()
						defer wg.Done()
						_, _, err := rs.LoadKey(ctx, testKeyA)
						Expect(err).NotTo(HaveOccurred())
					}()
				}

				// Concurrent writers (same key — Redis handles atomicity)
				for i := 0; i < numOps; i++ {
					wg.Add(1)
					go func() {
						defer GinkgoRecover()
						defer wg.Done()
						key := newTestKey()
						_ = rs.Save(ctx, testKeyB, key, keys.KeyMetadata{ID: testKeyB, CreatedAt: time.Now()})
					}()
				}

				wg.Wait()
			})
		})

		Context("concurrent LoadAll", func() {
			It("should return consistent results under concurrent reads", func() {
				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err := rs.Save(ctx, testKeyA, key, metadata)
				Expect(err).NotTo(HaveOccurred())

				const numReaders = 10
				results := make(chan int, numReaders)

				for i := 0; i < numReaders; i++ {
					go func() {
						defer GinkgoRecover()
						keys, err := rs.LoadAll(ctx)
						Expect(err).NotTo(HaveOccurred())
						results <- len(keys)
					}()
				}

				for i := 0; i < numReaders; i++ {
					count := <-results
					Expect(count).To(BeNumerically(">=", 1))
				}
			})
		})
	})

	// ===== PHASE 9: Metrics Recording =====
	Describe("Phase 9: Metrics Recording", func() {
		var (
			ctrl  *gomock.Controller
			mockM *testutil.MockMetrics
		)

		BeforeEach(func() {
			ctrl = gomock.NewController(GinkgoT())
			mockM = testutil.NewMockMetrics(ctrl)
		})

		AfterEach(func() { ctrl.Finish() })

		newMetricStore := func() *keys.RedisKeyStore {
			store, err := keys.NewRedisKeyStore(keys.RedisKeyStoreConfig{Client: client, Metrics: mockM})
			Expect(err).NotTo(HaveOccurred())
			return store
		}

		expectOpsMetrics := func(operation, status string) {
			errorType := status
			if status == "success" {
				errorType = ""
			}
			mockM.EXPECT().IncrementCounter("jwtauth_keystore_operations_total", map[string]string{
				"operation":       operation,
				"status":          status,
				"error_type":      errorType,
				"storage_backend": "redis",
				"namespace":       "",
			})
			mockM.EXPECT().RecordDuration("jwtauth_keystore_operation_duration_seconds", gomock.Any(), map[string]string{
				"operation":       operation,
				"storage_backend": "redis",
				"namespace":       "",
			})
		}

		Context("Save", func() {
			It("should record success metrics", func() {
				expectOpsMetrics("save", "success")
				store := newMetricStore()
				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err := store.Save(ctx, testKeyA, key, metadata)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("LoadAll", func() {
			It("should record success metrics and set the keys gauge", func() {
				expectOpsMetrics("load_all", "success")
				mockM.EXPECT().SetGauge("jwtauth_keystore_keys_count", gomock.Any(), map[string]string{
					"storage_backend": "redis",
					"namespace":       "",
				})
				store := newMetricStore()
				_, err := store.LoadAll(ctx)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("LoadKey", func() {
			It("should record success metrics", func() {
				// Pre-save via unmetered store
				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err := rs.Save(ctx, testKeyA, key, metadata)
				Expect(err).NotTo(HaveOccurred())

				expectOpsMetrics("load_key", "success")
				store := newMetricStore()
				_, _, err = store.LoadKey(ctx, testKeyA)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should record not_found status for missing keys", func() {
				expectOpsMetrics("load_key", "not_found")
				store := newMetricStore()
				_, _, err := store.LoadKey(ctx, testKeyMissing)
				Expect(err).To(HaveOccurred())
			})
		})

		Context("UpdateMetadata", func() {
			It("should record success metrics", func() {
				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err := rs.Save(ctx, testKeyA, key, metadata)
				Expect(err).NotTo(HaveOccurred())

				expectOpsMetrics("update_metadata", "success")
				store := newMetricStore()
				updatedMetadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err = store.UpdateMetadata(ctx, testKeyA, updatedMetadata)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("Delete", func() {
			It("should record success metrics", func() {
				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err := rs.Save(ctx, testKeyA, key, metadata)
				Expect(err).NotTo(HaveOccurred())

				expectOpsMetrics("delete", "success")
				store := newMetricStore()
				err = store.Delete(ctx, testKeyA)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("nil metrics", func() {
			It("should not panic when metrics is nil", func() {
				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err := rs.Save(ctx, testKeyA, key, metadata)
				Expect(err).NotTo(HaveOccurred())

				Expect(func() { _, _ = rs.LoadAll(ctx) }).NotTo(Panic())
				Expect(func() { _, _, _ = rs.LoadKey(ctx, testKeyA) }).NotTo(Panic())
				Expect(func() {
					_ = rs.UpdateMetadata(ctx, testKeyA, keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()})
				}).NotTo(Panic())
				Expect(func() { _ = rs.Delete(ctx, testKeyA) }).NotTo(Panic())
			})
		})
	})

	// ===== PHASE 11: KeyPrefix Namespace Isolation =====
	Describe("Phase 11: KeyPrefix Namespace Isolation", func() {
		Context("with a non-empty KeyPrefix", func() {
			It("should store all keys under the configured prefix", func() {
				store, err := keys.NewRedisKeyStore(keys.RedisKeyStoreConfig{
					Client:    client,
					KeyPrefix: "tenant:abc:",
				})
				Expect(err).NotTo(HaveOccurred())

				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				Expect(store.Save(ctx, testKeyA, key, metadata)).To(Succeed())

				storedKeys, err := client.Keys(ctx, "*").Result()
				Expect(err).NotTo(HaveOccurred())
				for _, k := range storedKeys {
					Expect(k).To(HavePrefix("tenant:abc:"))
				}
			})
		})

		Context("with an empty KeyPrefix", func() {
			It("should use bare constants — backward compatible with existing deployments", func() {
				store, err := keys.NewRedisKeyStore(keys.RedisKeyStoreConfig{
					Client:    client,
					KeyPrefix: "",
				})
				Expect(err).NotTo(HaveOccurred())

				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				Expect(store.Save(ctx, testKeyA, key, metadata)).To(Succeed())

				storedKeys, err := client.Keys(ctx, "*").Result()
				Expect(err).NotTo(HaveOccurred())
				for _, k := range storedKeys {
					Expect(k).To(Or(HavePrefix("ks:pem:"), HavePrefix("ks:meta:")))
				}
			})
		})

		Context("two stores with different prefixes against the same Redis", func() {
			var (
				storeA *keys.RedisKeyStore
				storeB *keys.RedisKeyStore
			)

			BeforeEach(func() {
				var err error
				storeA, err = keys.NewRedisKeyStore(keys.RedisKeyStoreConfig{
					Client:    client,
					KeyPrefix: "ns:a:",
				})
				Expect(err).NotTo(HaveOccurred())

				storeB, err = keys.NewRedisKeyStore(keys.RedisKeyStoreConfig{
					Client:    client,
					KeyPrefix: "ns:b:",
				})
				Expect(err).NotTo(HaveOccurred())
			})

			It("LoadAll should not see keys from the other namespace", func() {
				keyA := newTestKey()
				Expect(storeA.Save(ctx, testKeyA, keyA, keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()})).To(Succeed())

				keyB := newTestKey()
				Expect(storeB.Save(ctx, testKeyB, keyB, keys.KeyMetadata{ID: testKeyB, CreatedAt: time.Now()})).To(Succeed())

				loadedA, err := storeA.LoadAll(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(loadedA).To(HaveLen(1))
				Expect(loadedA[0].KeyID).To(Equal(testKeyA))

				loadedB, err := storeB.LoadAll(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(loadedB).To(HaveLen(1))
				Expect(loadedB[0].KeyID).To(Equal(testKeyB))
			})

			It("LoadKey on store A should not find a key saved by store B", func() {
				keyB := newTestKey()
				Expect(storeB.Save(ctx, testKeyA, keyB, keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()})).To(Succeed())

				_, _, err := storeA.LoadKey(ctx, testKeyA)
				Expect(err).To(MatchError(keys.ErrKeyStoreKeyNotFound))
			})

			It("Delete on store A should not affect store B's key with the same ID", func() {
				keyA := newTestKey()
				Expect(storeA.Save(ctx, testKeyA, keyA, keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()})).To(Succeed())
				keyB := newTestKey()
				Expect(storeB.Save(ctx, testKeyA, keyB, keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()})).To(Succeed())

				Expect(storeA.Delete(ctx, testKeyA)).To(Succeed())

				_, _, err := storeB.LoadKey(ctx, testKeyA)
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})

	// ===== PHASE 10: Tracing =====
	Describe("Phase 10: Tracing", func() {
		var (
			ctrl         *gomock.Controller
			mockTracer   *testutil.MockTracer
			mockSpan     *testutil.MockSpan
			tracingStore *keys.RedisKeyStore
		)

		BeforeEach(func() {
			ctrl = gomock.NewController(GinkgoT())
			mockTracer = testutil.NewMockTracer(ctrl)
			mockSpan = testutil.NewMockSpan(ctrl)
			var err error
			tracingStore, err = keys.NewRedisKeyStore(keys.RedisKeyStoreConfig{Client: client, Tracer: mockTracer})
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() { ctrl.Finish() })

		Context("Save — success path", func() {
			It("should start a span named RedisKeyStore.Save with storage.backend, key_id and StatusOK", func() {
				mockTracer.EXPECT().Start(gomock.Any(), "RedisKeyStore.Save", gomock.Any()).Return(ctx, mockSpan)
				mockSpan.EXPECT().SetAttribute("key_id", testKeyA)
				mockSpan.EXPECT().SetStatus(tracing.StatusOK, "")
				mockSpan.EXPECT().End()

				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err := tracingStore.Save(ctx, testKeyA, key, metadata)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("LoadKey — error path", func() {
			It("should call RecordError and StatusError when key is not found", func() {
				mockTracer.EXPECT().Start(gomock.Any(), "RedisKeyStore.LoadKey", gomock.Any()).Return(ctx, mockSpan)
				mockSpan.EXPECT().SetAttribute("key_id", testKeyMissing)
				mockSpan.EXPECT().RecordError(keys.ErrKeyStoreKeyNotFound)
				mockSpan.EXPECT().SetStatus(tracing.StatusError, gomock.Any())
				mockSpan.EXPECT().End()

				_, _, err := tracingStore.LoadKey(ctx, testKeyMissing)
				Expect(err).To(MatchError(keys.ErrKeyStoreKeyNotFound))
			})
		})
	})
})
