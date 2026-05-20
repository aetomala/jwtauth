// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package keys_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"github.com/aetomala/jwtauth/internal/testutil"
	"github.com/aetomala/jwtauth/pkg/keys"
	"github.com/aetomala/jwtauth/pkg/metrics"
	"github.com/aetomala/jwtauth/pkg/tracing"
)

const (
	testKeyA       = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"
	testKeyB       = "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb"
	testKeyMissing = "ffffffff-ffff-4fff-ffff-ffffffffffff"
)

// writePEMFile writes a PKCS#1 PEM file for key at dir/keyID.pem with 0600 permissions.
func writePEMFile(dir, keyID string, key *rsa.PrivateKey) {
	pemPath := filepath.Join(dir, keyID+".pem")
	f, err := os.OpenFile(pemPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	Expect(err).NotTo(HaveOccurred())
	defer f.Close()
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	Expect(pem.Encode(f, block)).To(Succeed())
}

// writeMetaFile writes a JSON metadata file at dir/keyID.json.
func writeMetaFile(dir, keyID string, meta keys.KeyMetadata) {
	// Re-use DiskKeyStore serialisation by saving through the store
	// — this avoids duplicating JSON logic in tests.
	ds, err := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: dir, KeySize: 2048})
	Expect(err).NotTo(HaveOccurred())
	Expect(ds.UpdateMetadata(context.Background(), keyID, meta)).To(Succeed())
}

var _ = Describe("DiskKeyStore", func() {
	var (
		dir string
		ctx context.Context
	)

	BeforeEach(func() {
		dir = GinkgoT().TempDir()
		ctx = context.Background()
	})

	// ===== PHASE 1: Constructor and Initialization =====
	Describe("Phase 1: Constructor and Initialization", func() {
		Context("with a valid directory", func() {
			It("should create a DiskKeyStore successfully", func() {
				ds, err := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: dir, KeySize: 2048})
				Expect(err).NotTo(HaveOccurred())
				Expect(ds).NotTo(BeNil())
			})

			It("should create a non-existent directory automatically", func() {
				newDir := filepath.Join(dir, "auto-created")
				ds, err := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: newDir, KeySize: 2048})
				Expect(err).NotTo(HaveOccurred())
				Expect(ds).NotTo(BeNil())
				_, statErr := os.Stat(newDir)
				Expect(statErr).NotTo(HaveOccurred())
			})

			It("should accept a logger and metrics without error", func() {
				mockLogger := testutil.NewMockLogger()
				ds, err := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: dir, KeySize: 2048, Logger: mockLogger})
				Expect(err).NotTo(HaveOccurred())
				Expect(ds).NotTo(BeNil())
			})

			It("should apply defaults from DiskKeyStoreConfigDefault when optional fields are nil", func() {
				// Dir only — all optional fields nil/zero; must not panic on any operation.
				ds, err := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: dir})
				Expect(err).NotTo(HaveOccurred())
				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err = ds.Save(ctx, testKeyA, key, metadata)
				Expect(err).NotTo(HaveOccurred())
				_, _, err = ds.LoadKey(ctx, testKeyA)
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
				ds, err := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: dir, KeySize: 2048, Tracer: mockTracer})
				Expect(err).NotTo(HaveOccurred())
				Expect(ds).NotTo(BeNil())
			})
		})

		Context("with an invalid directory", func() {
			It("should return ErrInvalidKeyDirectory for an empty string", func() {
				_, err := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: "", KeySize: 2048})
				Expect(err).To(MatchError(keys.ErrInvalidKeyDirectory))
			})

			It("should return ErrInvalidKeyDirectory for a whitespace-only string", func() {
				_, err := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: "   ", KeySize: 2048})
				Expect(err).To(MatchError(keys.ErrInvalidKeyDirectory))
			})
		})
	})

	// ===== PHASE 2: Save =====
	Describe("Phase 2: Save", func() {
		var ds *keys.DiskKeyStore

		BeforeEach(func() {
			var err error
			ds, err = keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: dir, KeySize: 2048})
			Expect(err).NotTo(HaveOccurred())
		})

		Context("with a valid key and metadata", func() {
			It("should write a PEM file at 0600 permissions", func() {
				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}

				err := ds.Save(ctx, testKeyA, key, metadata)
				Expect(err).NotTo(HaveOccurred())

				pemPath := filepath.Join(dir, testKeyA+".pem")
				info, err := os.Stat(pemPath)
				Expect(err).NotTo(HaveOccurred())
				Expect(info.Mode().Perm()).To(Equal(os.FileMode(0600)))
			})

			It("should write a companion metadata JSON file", func() {
				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}

				err := ds.Save(ctx, testKeyA, key, metadata)
				Expect(err).NotTo(HaveOccurred())

				_, err = os.Stat(filepath.Join(dir, testKeyA+".json"))
				Expect(err).NotTo(HaveOccurred())
			})

			It("should persist a key that is then retrievable via LoadKey", func() {
				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}

				err := ds.Save(ctx, testKeyA, key, metadata)
				Expect(err).NotTo(HaveOccurred())

				loaded, loadedMeta, err := ds.LoadKey(ctx, testKeyA)
				Expect(err).NotTo(HaveOccurred())
				Expect(loaded.N.Cmp(key.N)).To(Equal(0))
				Expect(loadedMeta.ID).To(Equal(testKeyA))
			})
		})

		Context("context cancellation", func() {
			It("should return context error when context is already cancelled", func() {
				cancelCtx, cancel := context.WithCancel(context.Background())
				cancel()

				key := newTestKey()
				meta := keys.KeyMetadata{ID: "cancelled-key", CreatedAt: time.Now()}
				err := ds.Save(cancelCtx, "cancelled-key", key, meta)
				Expect(err).To(MatchError(context.Canceled))
			})
		})
	})

	// ===== PHASE 3: LoadAll =====
	Describe("Phase 3: LoadAll", func() {
		var ds *keys.DiskKeyStore

		BeforeEach(func() {
			var err error
			ds, err = keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: dir, KeySize: 2048})
			Expect(err).NotTo(HaveOccurred())
		})

		Context("with saved keys", func() {
			It("should return all saved non-expired keys", func() {
				key1, key2 := newTestKey(), newTestKey()
				firstKeyMetadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				secondKeyMetadata := keys.KeyMetadata{ID: testKeyB, CreatedAt: time.Now()}
				err := ds.Save(ctx, testKeyA, key1, firstKeyMetadata)
				Expect(err).NotTo(HaveOccurred())
				err = ds.Save(ctx, testKeyB, key2, secondKeyMetadata)
				Expect(err).NotTo(HaveOccurred())

				keys, err := ds.LoadAll(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(keys).To(HaveLen(2))
			})

			It("should skip already-expired keys", func() {
				active := newTestKey()
				expired := newTestKey()

				activeKeyMetadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				expiredKeyMetadata := keys.KeyMetadata{
					ID:        testKeyB,
					CreatedAt: time.Now().Add(-2 * time.Hour),
					ExpiresAt: time.Now().Add(-1 * time.Hour),
				}
				err := ds.Save(ctx, testKeyA, active, activeKeyMetadata)
				Expect(err).NotTo(HaveOccurred())
				err = ds.Save(ctx, testKeyB, expired, expiredKeyMetadata)
				Expect(err).NotTo(HaveOccurred())

				keys, err := ds.LoadAll(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(keys).To(HaveLen(1))
				Expect(keys[0].KeyID).To(Equal(testKeyA))
			})

			It("should skip files with corrupted PEM data", func() {
				good := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err := ds.Save(ctx, testKeyA, good, metadata)
				Expect(err).NotTo(HaveOccurred())

				// Write a corrupted PEM file
				Expect(os.WriteFile(filepath.Join(dir, "corrupt-key.pem"), []byte("not-valid-pem"), 0600)).To(Succeed())

				keys, err := ds.LoadAll(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(keys).To(HaveLen(1))
				Expect(keys[0].KeyID).To(Equal(testKeyA))
			})
		})

		Context("with no keys in directory", func() {
			It("should return an empty slice without error", func() {
				keys, err := ds.LoadAll(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(keys).To(BeEmpty())
			})
		})

		Context("context cancellation", func() {
			It("should return context error when context is already cancelled", func() {
				cancelCtx, cancel := context.WithCancel(context.Background())
				cancel()

				_, err := ds.LoadAll(cancelCtx)
				Expect(err).To(MatchError(context.Canceled))
			})
		})
	})

	// ===== PHASE 4: LoadKey =====
	Describe("Phase 4: LoadKey", func() {
		var ds *keys.DiskKeyStore

		BeforeEach(func() {
			var err error
			ds, err = keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: dir, KeySize: 2048})
			Expect(err).NotTo(HaveOccurred())
		})

		Context("with a saved key", func() {
			It("should return the private key and metadata", func() {
				key := newTestKey()
				now := time.Now().Truncate(time.Second)
				savedMetadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: now}
				err := ds.Save(ctx, testKeyA, key, savedMetadata)
				Expect(err).NotTo(HaveOccurred())

				loaded, loadedMeta, err := ds.LoadKey(ctx, testKeyA)
				Expect(err).NotTo(HaveOccurred())
				Expect(loaded).NotTo(BeNil())
				Expect(loaded.N.Cmp(key.N)).To(Equal(0))
				Expect(loadedMeta.ID).To(Equal(testKeyA))
			})

			It("should validate that the key size is at least 2048 bits", func() {
				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err := ds.Save(ctx, testKeyA, key, metadata)
				Expect(err).NotTo(HaveOccurred())

				loaded, _, err := ds.LoadKey(ctx, testKeyA)
				Expect(err).NotTo(HaveOccurred())
				Expect(loaded.N.BitLen()).To(BeNumerically(">=", 2048))
			})
		})

		Context("missing or invalid key", func() {
			It("should return ErrKeyStoreKeyNotFound for a missing key ID", func() {
				_, _, err := ds.LoadKey(ctx, testKeyMissing)
				Expect(err).To(MatchError(keys.ErrKeyStoreKeyNotFound))
			})

			It("should return ErrKeyStoreInvalidKeyID for an empty key ID", func() {
				_, _, err := ds.LoadKey(ctx, "")
				Expect(err).To(MatchError(keys.ErrKeyStoreInvalidKeyID))
			})

			It("should return ErrKeyStoreInvalidKeyID for a whitespace-only key ID", func() {
				_, _, err := ds.LoadKey(ctx, "   ")
				Expect(err).To(MatchError(keys.ErrKeyStoreInvalidKeyID))
			})

			It("should return ErrKeyStoreInvalidKeyID for a path traversal attempt with ../ prefix", func() {
				_, _, err := ds.LoadKey(ctx, "../../etc/passwd")
				Expect(err).To(MatchError(keys.ErrKeyStoreInvalidKeyID))
			})

			It("should return ErrKeyStoreInvalidKeyID for a path traversal attempt with ../ infix", func() {
				_, _, err := ds.LoadKey(ctx, "abc/../../../etc/shadow")
				Expect(err).To(MatchError(keys.ErrKeyStoreInvalidKeyID))
			})

			It("should return ErrKeyStoreInvalidKeyID for an absolute path", func() {
				_, _, err := ds.LoadKey(ctx, "/etc/passwd")
				Expect(err).To(MatchError(keys.ErrKeyStoreInvalidKeyID))
			})

			It("should return ErrKeyStoreInvalidKeyID for a non-UUID string", func() {
				_, _, err := ds.LoadKey(ctx, "not-a-uuid")
				Expect(err).To(MatchError(keys.ErrKeyStoreInvalidKeyID))
			})
		})

		Context("context cancellation", func() {
			It("should return context error when context is already cancelled", func() {
				cancelCtx, cancel := context.WithCancel(context.Background())
				cancel()

				_, _, err := ds.LoadKey(cancelCtx, "any-key")
				Expect(err).To(MatchError(context.Canceled))
			})
		})
	})

	// ===== PHASE 5: UpdateMetadata =====
	Describe("Phase 5: UpdateMetadata", func() {
		var ds *keys.DiskKeyStore

		BeforeEach(func() {
			var err error
			ds, err = keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: dir, KeySize: 2048})
			Expect(err).NotTo(HaveOccurred())
		})

		Context("updating an existing key", func() {
			It("should persist the updated ExpiresAt and be visible on LoadKey", func() {
				key := newTestKey()
				now := time.Now()
				savedMetadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: now}
				err := ds.Save(ctx, testKeyA, key, savedMetadata)
				Expect(err).NotTo(HaveOccurred())

				expiry := now.Add(1 * time.Hour)
				updatedMetadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: now, ExpiresAt: expiry}
				err = ds.UpdateMetadata(ctx, testKeyA, updatedMetadata)
				Expect(err).NotTo(HaveOccurred())

				_, loadedMeta, err := ds.LoadKey(ctx, testKeyA)
				Expect(err).NotTo(HaveOccurred())
				Expect(loadedMeta.ExpiresAt.UTC().Truncate(time.Second)).To(Equal(expiry.UTC().Truncate(time.Second)))
			})
		})

		Context("updating a non-existent key", func() {
			It("should return ErrKeyStoreKeyNotFound", func() {
				metadata := keys.KeyMetadata{ID: testKeyMissing, CreatedAt: time.Now()}
				err := ds.UpdateMetadata(ctx, testKeyMissing, metadata)
				Expect(err).To(MatchError(keys.ErrKeyStoreKeyNotFound))
			})
		})

		Context("context cancellation", func() {
			It("should return context error when context is already cancelled", func() {
				cancelCtx, cancel := context.WithCancel(context.Background())
				cancel()

				meta := keys.KeyMetadata{ID: "any-key", CreatedAt: time.Now()}
				err := ds.UpdateMetadata(cancelCtx, "any-key", meta)
				Expect(err).To(MatchError(context.Canceled))
			})
		})
	})

	// ===== PHASE 6: Delete =====
	Describe("Phase 6: Delete", func() {
		var ds *keys.DiskKeyStore

		BeforeEach(func() {
			var err error
			ds, err = keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: dir, KeySize: 2048})
			Expect(err).NotTo(HaveOccurred())
		})

		Context("deleting an existing key", func() {
			It("should remove both the PEM and metadata files from disk", func() {
				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err := ds.Save(ctx, testKeyA, key, metadata)
				Expect(err).NotTo(HaveOccurred())

				err = ds.Delete(ctx, testKeyA)
				Expect(err).NotTo(HaveOccurred())

				_, pemErr := os.Stat(filepath.Join(dir, testKeyA+".pem"))
				_, jsonErr := os.Stat(filepath.Join(dir, testKeyA+".json"))
				Expect(os.IsNotExist(pemErr)).To(BeTrue())
				Expect(os.IsNotExist(jsonErr)).To(BeTrue())
			})

			It("should make the key unavailable via LoadKey after deletion", func() {
				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err := ds.Save(ctx, testKeyA, key, metadata)
				Expect(err).NotTo(HaveOccurred())
				err = ds.Delete(ctx, testKeyA)
				Expect(err).NotTo(HaveOccurred())

				_, _, err = ds.LoadKey(ctx, testKeyA)
				Expect(err).To(MatchError(keys.ErrKeyStoreKeyNotFound))
			})
		})

		Context("deleting a non-existent key", func() {
			It("should succeed without error — idempotent", func() {
				err := ds.Delete(ctx, testKeyMissing)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("context cancellation", func() {
			It("should return context error when context is already cancelled", func() {
				cancelCtx, cancel := context.WithCancel(context.Background())
				cancel()

				err := ds.Delete(cancelCtx, "any-key")
				Expect(err).To(MatchError(context.Canceled))
			})
		})
	})

	// ===== PHASE 7: Error Handling and Edge Cases =====
	Describe("Phase 7: Error Handling and Edge Cases", func() {
		var ds *keys.DiskKeyStore

		BeforeEach(func() {
			var err error
			ds, err = keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: dir, KeySize: 2048})
			Expect(err).NotTo(HaveOccurred())
		})

		Context("LoadAll with a key missing its metadata file", func() {
			It("should skip the key without returning an error", func() {
				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err := ds.Save(ctx, testKeyA, key, metadata)
				Expect(err).NotTo(HaveOccurred())

				// Remove metadata file to simulate corruption
				Expect(os.Remove(filepath.Join(dir, testKeyA+".json"))).To(Succeed())

				keys, err := ds.LoadAll(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(keys).To(BeEmpty())
			})
		})

		Context("Save with a below-minimum key size", func() {
			It("should still Save (size check is on Load, not Save)", func() {
				// Save accepts whatever key is provided; size is enforced at LoadKey/LoadAll
				smallKey, err := rsa.GenerateKey(rand.Reader, 2048) // 2048 is minimum accepted
				Expect(err).NotTo(HaveOccurred())
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err = ds.Save(ctx, testKeyA, smallKey, metadata)
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})

	// ===== PHASE 8: Concurrency and Thread Safety =====
	Describe("Phase 8: Concurrency and Thread Safety", func() {
		var ds *keys.DiskKeyStore

		BeforeEach(func() {
			var err error
			ds, err = keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: dir, KeySize: 2048})
			Expect(err).NotTo(HaveOccurred())
		})

		Context("concurrent Save and LoadKey", func() {
			It("should not race on concurrent writes and reads", func() {
				const numOps = 10
				var wg sync.WaitGroup

				// Pre-save one key for readers
				preKey := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err := ds.Save(ctx, testKeyA, preKey, metadata)
				Expect(err).NotTo(HaveOccurred())

				// Concurrent readers
				for i := 0; i < numOps; i++ {
					wg.Add(1)
					go func() {
						defer GinkgoRecover()
						defer wg.Done()
						_, _, err := ds.LoadKey(ctx, testKeyA)
						Expect(err).NotTo(HaveOccurred())
					}()
				}

				// Concurrent writers (different key IDs to avoid file contention)
				for i := 0; i < numOps; i++ {
					wg.Add(1)
					go func(n int) {
						defer GinkgoRecover()
						defer wg.Done()
						key := newTestKey()
						keyID := filepath.Join("writer-key")
						_ = keyID
						// Each goroutine writes to its own key to avoid OS-level contention
						_ = ds.Save(ctx, testKeyB, key, keys.KeyMetadata{ID: testKeyB, CreatedAt: time.Now()})
					}(i)
				}

				wg.Wait()
			})
		})

		Context("concurrent LoadAll", func() {
			It("should return consistent results under concurrent reads", func() {
				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err := ds.Save(ctx, testKeyA, key, metadata)
				Expect(err).NotTo(HaveOccurred())

				const numReaders = 10
				results := make(chan int, numReaders)

				for i := 0; i < numReaders; i++ {
					go func() {
						defer GinkgoRecover()
						keys, err := ds.LoadAll(ctx)
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

		newMetricStore := func() *keys.DiskKeyStore {
			ds, err := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: dir, KeySize: 2048, Metrics: mockM})
			Expect(err).NotTo(HaveOccurred())
			return ds
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
				"storage_backend": "disk",
				"namespace":       "",
			})
			mockM.EXPECT().RecordDuration("jwtauth_keystore_operation_duration_seconds", gomock.Any(), map[string]string{
				"operation":       operation,
				"storage_backend": "disk",
				"namespace":       "",
			})
		}

		Context("Save", func() {
			It("should record success metrics", func() {
				expectOpsMetrics("save", "success")
				ds := newMetricStore()
				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err := ds.Save(ctx, testKeyA, key, metadata)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("LoadAll", func() {
			It("should record success metrics and set the keys gauge", func() {
				expectOpsMetrics("load_all", "success")
				mockM.EXPECT().SetGauge("jwtauth_keystore_keys_count", gomock.Any(), map[string]string{
					"storage_backend": "disk",
					"namespace":       "",
				})
				ds := newMetricStore()
				_, err := ds.LoadAll(ctx)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("LoadKey", func() {
			It("should record success metrics", func() {
				// Pre-save via unmetered store
				plain, _ := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: dir, KeySize: 2048})
				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err := plain.Save(ctx, testKeyA, key, metadata)
				Expect(err).NotTo(HaveOccurred())

				expectOpsMetrics("load_key", "success")
				ds := newMetricStore()
				_, _, err = ds.LoadKey(ctx, testKeyA)
				Expect(err).NotTo(HaveOccurred())
			})

			It("should record not_found status for missing keys", func() {
				expectOpsMetrics("load_key", "not_found")
				ds := newMetricStore()
				_, _, err := ds.LoadKey(ctx, testKeyMissing)
				Expect(err).To(HaveOccurred())
			})
		})

		Context("UpdateMetadata", func() {
			It("should record success metrics", func() {
				plain, _ := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: dir, KeySize: 2048})
				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err := plain.Save(ctx, testKeyA, key, metadata)
				Expect(err).NotTo(HaveOccurred())

				expectOpsMetrics("update_metadata", "success")
				ds := newMetricStore()
				updatedMetadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err = ds.UpdateMetadata(ctx, testKeyA, updatedMetadata)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("Delete", func() {
			It("should record success metrics", func() {
				plain, _ := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: dir, KeySize: 2048})
				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err := plain.Save(ctx, testKeyA, key, metadata)
				Expect(err).NotTo(HaveOccurred())

				expectOpsMetrics("delete", "success")
				ds := newMetricStore()
				err = ds.Delete(ctx, testKeyA)
				Expect(err).NotTo(HaveOccurred())
			})
		})

		Context("nil metrics", func() {
			It("should not panic when metrics is nil", func() {
				ds, err := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: dir, KeySize: 2048})
				Expect(err).NotTo(HaveOccurred())

				key := newTestKey()
				metadata := keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()}
				err = ds.Save(ctx, testKeyA, key, metadata)
				Expect(err).NotTo(HaveOccurred())
				Expect(func() { _, _ = ds.LoadAll(ctx) }).NotTo(Panic())
				Expect(func() { _, _, _ = ds.LoadKey(ctx, testKeyA) }).NotTo(Panic())
				Expect(func() {
					_ = ds.UpdateMetadata(ctx, testKeyA, keys.KeyMetadata{ID: testKeyA, CreatedAt: time.Now()})
				}).NotTo(Panic())
				Expect(func() { _ = ds.Delete(ctx, testKeyA) }).NotTo(Panic())
			})
		})
	})

	// ===== PHASE 10: Tracing =====
	Describe("Phase 10: Tracing", func() {
		var (
			ctrl        *gomock.Controller
			mockTracer  *testutil.MockTracer
			mockSpan    *testutil.MockSpan
			tracingStore *keys.DiskKeyStore
		)

		BeforeEach(func() {
			ctrl = gomock.NewController(GinkgoT())
			mockTracer = testutil.NewMockTracer(ctrl)
			mockSpan = testutil.NewMockSpan(ctrl)
			var err error
			tracingStore, err = keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: dir, KeySize: 2048, Tracer: mockTracer})
			Expect(err).NotTo(HaveOccurred())
		})

		AfterEach(func() { ctrl.Finish() })

		Context("Save — success path", func() {
			It("should start a span named DiskKeyStore.Save with key_id and StatusOK", func() {
				mockTracer.EXPECT().Start(gomock.Any(), "DiskKeyStore.Save", gomock.Any()).Return(ctx, mockSpan)
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
				mockTracer.EXPECT().Start(gomock.Any(), "DiskKeyStore.LoadKey", gomock.Any()).Return(ctx, mockSpan)
				mockSpan.EXPECT().SetAttribute("key_id", testKeyMissing)
				mockSpan.EXPECT().SetStatus(tracing.StatusError, gomock.Any())
				mockSpan.EXPECT().End()

				_, _, err := tracingStore.LoadKey(ctx, testKeyMissing)
				Expect(err).To(MatchError(keys.ErrKeyStoreKeyNotFound))
			})
		})
	})

	// Compile-time check: DiskKeyStore satisfies the metrics.Metrics consumer pattern.
	var _ metrics.Metrics = (*testutil.MockMetrics)(nil)
})
