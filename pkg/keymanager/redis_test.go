package keymanager_test

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
	"github.com/aetomala/jwtauth/pkg/keymanager"
	"github.com/aetomala/jwtauth/pkg/tracing"
)

var _ = Describe("RedisKeyStore", func() {
	var (
		miniRedis *miniredis.Miniredis
		client    *redis.Client
		rs        *keymanager.RedisKeyStore
		ctx       context.Context
	)

	BeforeEach(func() {
		var err error
		miniRedis, err = miniredis.Run()
		Expect(err).NotTo(HaveOccurred())

		client = redis.NewClient(&redis.Options{
			Addr: miniRedis.Addr(),
		})

		rs, err = keymanager.NewRedisKeyStore(keymanager.RedisKeyStoreConfig{Client: client})
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
				store, err := keymanager.NewRedisKeyStore(keymanager.RedisKeyStoreConfig{Client: client})
				Expect(err).NotTo(HaveOccurred())
				Expect(store).NotTo(BeNil())
			})

			It("should accept a logger and metrics without error", func() {
				mockLogger := testutil.NewMockLogger()
				store, err := keymanager.NewRedisKeyStore(keymanager.RedisKeyStoreConfig{Client: client, Logger: mockLogger})
				Expect(err).NotTo(HaveOccurred())
				Expect(store).NotTo(BeNil())
			})

			It("should apply defaults from RedisKeyStoreConfigDefault when optional fields are nil", func() {
				store, err := keymanager.NewRedisKeyStore(keymanager.RedisKeyStoreConfig{Client: client})
				Expect(err).NotTo(HaveOccurred())
				key := newTestKey()
				Expect(store.Save(ctx, "defaults-key", key, keymanager.KeyMetadata{ID: "defaults-key", CreatedAt: time.Now()})).To(Succeed())
				_, _, err = store.LoadKey(ctx, "defaults-key")
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
				store, err := keymanager.NewRedisKeyStore(keymanager.RedisKeyStoreConfig{Client: client, Tracer: mockTracer})
				Expect(err).NotTo(HaveOccurred())
				key := newTestKey()
				Expect(store.Save(ctx, "tracer-key", key, keymanager.KeyMetadata{ID: "tracer-key", CreatedAt: time.Now()})).To(Succeed())
			})
		})

		Context("with a nil client", func() {
			It("should return ErrNilRedisClient", func() {
				_, err := keymanager.NewRedisKeyStore(keymanager.RedisKeyStoreConfig{})
				Expect(err).To(MatchError(keymanager.ErrNilRedisClient))
			})
		})
	})

	// ===== PHASE 2: Save =====
	Describe("Phase 2: Save", func() {
		Context("with a valid key and metadata", func() {
			It("should persist PEM and metadata retrievable via LoadKey", func() {
				key := newTestKey()
				meta := keymanager.KeyMetadata{ID: "save-key", CreatedAt: time.Now()}

				Expect(rs.Save(ctx, "save-key", key, meta)).To(Succeed())

				loaded, loadedMeta, err := rs.LoadKey(ctx, "save-key")
				Expect(err).NotTo(HaveOccurred())
				Expect(loaded.N.Cmp(key.N)).To(Equal(0))
				Expect(loadedMeta.ID).To(Equal("save-key"))
			})

			It("should overwrite an existing key on repeated Save", func() {
				key1 := newTestKey()
				key2 := newTestKey()
				meta := keymanager.KeyMetadata{ID: "overwrite-key", CreatedAt: time.Now()}

				Expect(rs.Save(ctx, "overwrite-key", key1, meta)).To(Succeed())
				Expect(rs.Save(ctx, "overwrite-key", key2, meta)).To(Succeed())

				loaded, _, err := rs.LoadKey(ctx, "overwrite-key")
				Expect(err).NotTo(HaveOccurred())
				Expect(loaded.N.Cmp(key2.N)).To(Equal(0))
			})
		})

		Context("context cancellation", func() {
			It("should return context error when context is already cancelled", func() {
				cancelCtx, cancel := context.WithCancel(context.Background())
				cancel()

				key := newTestKey()
				meta := keymanager.KeyMetadata{ID: "cancelled-key", CreatedAt: time.Now()}
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
				Expect(rs.Save(ctx, "key-1", key1, keymanager.KeyMetadata{ID: "key-1", CreatedAt: time.Now()})).To(Succeed())
				Expect(rs.Save(ctx, "key-2", key2, keymanager.KeyMetadata{ID: "key-2", CreatedAt: time.Now()})).To(Succeed())

				keys, err := rs.LoadAll(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(keys).To(HaveLen(2))
			})

			It("should skip already-expired keys", func() {
				active := newTestKey()
				expired := newTestKey()

				Expect(rs.Save(ctx, "active-key", active, keymanager.KeyMetadata{
					ID:        "active-key",
					CreatedAt: time.Now(),
				})).To(Succeed())
				Expect(rs.Save(ctx, "expired-key", expired, keymanager.KeyMetadata{
					ID:        "expired-key",
					CreatedAt: time.Now().Add(-2 * time.Hour),
					ExpiresAt: time.Now().Add(-1 * time.Hour),
				})).To(Succeed())

				keys, err := rs.LoadAll(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(keys).To(HaveLen(1))
				Expect(keys[0].KeyID).To(Equal("active-key"))
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
				meta := keymanager.KeyMetadata{ID: "load-key", CreatedAt: now}
				Expect(rs.Save(ctx, "load-key", key, meta)).To(Succeed())

				loaded, loadedMeta, err := rs.LoadKey(ctx, "load-key")
				Expect(err).NotTo(HaveOccurred())
				Expect(loaded).NotTo(BeNil())
				Expect(loaded.N.Cmp(key.N)).To(Equal(0))
				Expect(loadedMeta.ID).To(Equal("load-key"))
			})
		})

		Context("missing or invalid key", func() {
			It("should return ErrKeyStoreKeyNotFound for a missing key ID", func() {
				_, _, err := rs.LoadKey(ctx, "does-not-exist")
				Expect(err).To(MatchError(keymanager.ErrKeyStoreKeyNotFound))
			})

			It("should return ErrKeyStoreInvalidKeyID for an empty key ID", func() {
				_, _, err := rs.LoadKey(ctx, "")
				Expect(err).To(MatchError(keymanager.ErrKeyStoreInvalidKeyID))
			})

			It("should return ErrKeyStoreInvalidKeyID for a whitespace-only key ID", func() {
				_, _, err := rs.LoadKey(ctx, "   ")
				Expect(err).To(MatchError(keymanager.ErrKeyStoreInvalidKeyID))
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
				Expect(rs.Save(ctx, "update-key", key, keymanager.KeyMetadata{ID: "update-key", CreatedAt: now})).To(Succeed())

				expiry := now.Add(1 * time.Hour)
				updatedMeta := keymanager.KeyMetadata{ID: "update-key", CreatedAt: now, ExpiresAt: expiry}
				Expect(rs.UpdateMetadata(ctx, "update-key", updatedMeta)).To(Succeed())

				_, loadedMeta, err := rs.LoadKey(ctx, "update-key")
				Expect(err).NotTo(HaveOccurred())
				Expect(loadedMeta.ExpiresAt.UTC().Truncate(time.Second)).To(Equal(expiry.UTC().Truncate(time.Second)))
			})
		})

		Context("updating a non-existent key", func() {
			It("should return ErrKeyStoreKeyNotFound", func() {
				meta := keymanager.KeyMetadata{ID: "missing-key", CreatedAt: time.Now()}
				err := rs.UpdateMetadata(ctx, "missing-key", meta)
				Expect(err).To(MatchError(keymanager.ErrKeyStoreKeyNotFound))
			})
		})

		Context("context cancellation", func() {
			It("should return context error when context is already cancelled", func() {
				cancelCtx, cancel := context.WithCancel(context.Background())
				cancel()

				meta := keymanager.KeyMetadata{ID: "any-key", CreatedAt: time.Now()}
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
				Expect(rs.Save(ctx, "delete-key", key, keymanager.KeyMetadata{ID: "delete-key", CreatedAt: time.Now()})).To(Succeed())

				Expect(rs.Delete(ctx, "delete-key")).To(Succeed())

				_, _, err := rs.LoadKey(ctx, "delete-key")
				Expect(err).To(MatchError(keymanager.ErrKeyStoreKeyNotFound))
			})

			It("should make the key absent from LoadAll after deletion", func() {
				key := newTestKey()
				Expect(rs.Save(ctx, "del-loadall-key", key, keymanager.KeyMetadata{ID: "del-loadall-key", CreatedAt: time.Now()})).To(Succeed())
				Expect(rs.Delete(ctx, "del-loadall-key")).To(Succeed())

				keys, err := rs.LoadAll(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(keys).To(BeEmpty())
			})
		})

		Context("deleting a non-existent key", func() {
			It("should succeed without error — idempotent", func() {
				Expect(rs.Delete(ctx, "non-existent-key")).To(Succeed())
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
				Expect(client.Set(ctx, "ks:pem:no-meta-key", string(pemBytes), 0).Err()).To(Succeed())

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
				Expect(client.Set(ctx, "ks:pem:bad-meta-key", string(pemBytes), 0).Err()).To(Succeed())
				Expect(client.Set(ctx, "ks:meta:bad-meta-key", "NOT_VALID_JSON", 0).Err()).To(Succeed())

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
				Expect(client.Set(ctx, "ks:pem:pem-only-key", string(pemBytes), 0).Err()).To(Succeed())

				_, _, err := rs.LoadKey(ctx, "pem-only-key")
				Expect(err).To(MatchError(keymanager.ErrKeyStoreKeyNotFound))
			})
		})

		Context("Save when Redis is unavailable", func() {
			It("should return an error without panicking", func() {
				miniRedis.SetError("forced error")
				defer miniRedis.SetError("")

				key := newTestKey()
				meta := keymanager.KeyMetadata{ID: "unavail-key", CreatedAt: time.Now()}
				err := rs.Save(ctx, "unavail-key", key, meta)
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
				Expect(rs.Save(ctx, "concurrent-key", preKey, keymanager.KeyMetadata{ID: "concurrent-key", CreatedAt: time.Now()})).To(Succeed())

				// Concurrent readers
				for i := 0; i < numOps; i++ {
					wg.Add(1)
					go func() {
						defer GinkgoRecover()
						defer wg.Done()
						_, _, err := rs.LoadKey(ctx, "concurrent-key")
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
						_ = rs.Save(ctx, "write-only", key, keymanager.KeyMetadata{ID: "write-only", CreatedAt: time.Now()})
					}()
				}

				wg.Wait()
			})
		})

		Context("concurrent LoadAll", func() {
			It("should return consistent results under concurrent reads", func() {
				key := newTestKey()
				Expect(rs.Save(ctx, "loadall-key", key, keymanager.KeyMetadata{ID: "loadall-key", CreatedAt: time.Now()})).To(Succeed())

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

		newMetricStore := func() *keymanager.RedisKeyStore {
			store, err := keymanager.NewRedisKeyStore(keymanager.RedisKeyStoreConfig{Client: client, Metrics: mockM})
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
			})
			mockM.EXPECT().RecordDuration("jwtauth_keystore_operation_duration_seconds", gomock.Any(), map[string]string{
				"operation":       operation,
				"storage_backend": "redis",
			})
		}

		Context("Save", func() {
			It("should record success metrics", func() {
				expectOpsMetrics("save", "success")
				store := newMetricStore()
				key := newTestKey()
				Expect(store.Save(ctx, "metric-save-key", key, keymanager.KeyMetadata{ID: "metric-save-key", CreatedAt: time.Now()})).To(Succeed())
			})
		})

		Context("LoadAll", func() {
			It("should record success metrics and set the keys gauge", func() {
				expectOpsMetrics("load_all", "success")
				mockM.EXPECT().SetGauge("jwtauth_keystore_keys_count", gomock.Any(), map[string]string{
					"storage_backend": "redis",
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
				Expect(rs.Save(ctx, "metric-load-key", key, keymanager.KeyMetadata{ID: "metric-load-key", CreatedAt: time.Now()})).To(Succeed())

				expectOpsMetrics("load_key", "success")
				store := newMetricStore()
				_, _, err := store.LoadKey(ctx, "metric-load-key")
				Expect(err).NotTo(HaveOccurred())
			})

			It("should record not_found status for missing keys", func() {
				expectOpsMetrics("load_key", "not_found")
				store := newMetricStore()
				_, _, err := store.LoadKey(ctx, "ghost-key")
				Expect(err).To(HaveOccurred())
			})
		})

		Context("UpdateMetadata", func() {
			It("should record success metrics", func() {
				key := newTestKey()
				Expect(rs.Save(ctx, "metric-update-key", key, keymanager.KeyMetadata{ID: "metric-update-key", CreatedAt: time.Now()})).To(Succeed())

				expectOpsMetrics("update_metadata", "success")
				store := newMetricStore()
				Expect(store.UpdateMetadata(ctx, "metric-update-key", keymanager.KeyMetadata{ID: "metric-update-key", CreatedAt: time.Now()})).To(Succeed())
			})
		})

		Context("Delete", func() {
			It("should record success metrics", func() {
				key := newTestKey()
				Expect(rs.Save(ctx, "metric-delete-key", key, keymanager.KeyMetadata{ID: "metric-delete-key", CreatedAt: time.Now()})).To(Succeed())

				expectOpsMetrics("delete", "success")
				store := newMetricStore()
				Expect(store.Delete(ctx, "metric-delete-key")).To(Succeed())
			})
		})

		Context("nil metrics", func() {
			It("should not panic when metrics is nil", func() {
				key := newTestKey()
				Expect(rs.Save(ctx, "nil-metrics-key", key, keymanager.KeyMetadata{ID: "nil-metrics-key", CreatedAt: time.Now()})).To(Succeed())

				Expect(func() { _, _ = rs.LoadAll(ctx) }).NotTo(Panic())
				Expect(func() { _, _, _ = rs.LoadKey(ctx, "nil-metrics-key") }).NotTo(Panic())
				Expect(func() {
					_ = rs.UpdateMetadata(ctx, "nil-metrics-key", keymanager.KeyMetadata{ID: "nil-metrics-key", CreatedAt: time.Now()})
				}).NotTo(Panic())
				Expect(func() { _ = rs.Delete(ctx, "nil-metrics-key") }).NotTo(Panic())
			})
		})
	})

	// ===== PHASE 10: Tracing =====
	Describe("Phase 10: Tracing", func() {
		var (
			ctrl         *gomock.Controller
			mockTracer   *testutil.MockTracer
			mockSpan     *testutil.MockSpan
			tracingStore *keymanager.RedisKeyStore
		)

		BeforeEach(func() {
			ctrl = gomock.NewController(GinkgoT())
			mockTracer = testutil.NewMockTracer(ctrl)
			mockSpan = testutil.NewMockSpan(ctrl)
			var err error
			tracingStore, err = keymanager.NewRedisKeyStore(keymanager.RedisKeyStoreConfig{Client: client, Tracer: mockTracer})
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() { ctrl.Finish() })

		Context("Save — success path", func() {
			It("should start a span named RedisKeyStore.Save with storage.backend, key_id and StatusOK", func() {
				mockTracer.EXPECT().Start(gomock.Any(), "RedisKeyStore.Save", gomock.Any()).Return(ctx, mockSpan)
				mockSpan.EXPECT().SetAttribute("key_id", "trace-save-key")
				mockSpan.EXPECT().SetStatus(tracing.StatusOK, "")
				mockSpan.EXPECT().End()

				key := newTestKey()
				Expect(tracingStore.Save(ctx, "trace-save-key", key, keymanager.KeyMetadata{ID: "trace-save-key", CreatedAt: time.Now()})).To(Succeed())
			})
		})

		Context("LoadKey — error path", func() {
			It("should call RecordError and StatusError when key is not found", func() {
				mockTracer.EXPECT().Start(gomock.Any(), "RedisKeyStore.LoadKey", gomock.Any()).Return(ctx, mockSpan)
				mockSpan.EXPECT().SetAttribute("key_id", "missing-trace-key")
				mockSpan.EXPECT().RecordError(keymanager.ErrKeyStoreKeyNotFound)
				mockSpan.EXPECT().SetStatus(tracing.StatusError, gomock.Any())
				mockSpan.EXPECT().End()

				_, _, err := tracingStore.LoadKey(ctx, "missing-trace-key")
				Expect(err).To(MatchError(keymanager.ErrKeyStoreKeyNotFound))
			})
		})
	})
})
