// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package storage_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"

	"github.com/aetomala/jwtauth/internal/testutil"
	"github.com/aetomala/jwtauth/internal/tokenref"
	"github.com/aetomala/jwtauth/pkg/logging"
	"github.com/aetomala/jwtauth/pkg/metrics"
	"github.com/aetomala/jwtauth/pkg/storage"
	"github.com/aetomala/jwtauth/pkg/tracing"
)

var _ = RunRefreshStoreTests(
	"MemoryRefreshStore", "memory",
	// Factory: creates MemoryRefreshStore
	func(logger *testutil.MockLogger, m metrics.Metrics) storage.RefreshStore {
		return storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{Logger: logger, Metrics: m})
	},
	// Cleanup: nil (memory needs no cleanup)
	nil,
)

var _ = Describe("MemoryRefreshStore — Constructor", func() {
	ctx := context.Background()

	It("should apply defaults from MemoryRefreshStoreConfigDefault when optional fields are nil", func() {
		store := storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{})
		tokenID := "defaults-token"
		userID := "defaults-user"
		Expect(store.Store(ctx, tokenID, userID, nil, time.Now().Add(time.Hour), nil)).To(Succeed())
		_, err := store.Retrieve(ctx, tokenID)
		Expect(err).NotTo(HaveOccurred())
	})

	It("should accept an explicit Tracer without error", func() {
		ctrl := gomock.NewController(GinkgoT())
		defer ctrl.Finish()
		mockTracer := testutil.NewMockTracer(ctrl)
		mockSpan := testutil.NewMockSpan(ctrl)
		mockTracer.EXPECT().Start(gomock.Any(), gomock.Any()).Return(ctx, mockSpan).AnyTimes()
		mockSpan.EXPECT().End().AnyTimes()
		mockSpan.EXPECT().SetAttribute(gomock.Any(), gomock.Any()).AnyTimes()
		mockSpan.EXPECT().SetAttributes(gomock.Any()).AnyTimes()
		mockSpan.EXPECT().SetStatus(gomock.Any(), gomock.Any()).AnyTimes()

		store := storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{Tracer: mockTracer})
		tokenID := "tracer-token"
		userID := "tracer-user"
		Expect(store.Store(ctx, tokenID, userID, nil, time.Now().Add(time.Hour), nil)).To(Succeed())
	})
})

var _ = Describe("MemoryRefreshStore — Cleanup Expiry Heap Edge Cases", func() {
	ctx := context.Background()

	It("should not remove a token whose tokenID was re-stored under a later expiry", func() {
		store := storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{})
		tokenID := "reused-token-id"
		userID := "reuse-user"

		shortLived := time.Now().Add(50 * time.Millisecond)
		err := store.Store(ctx, tokenID, userID, nil, shortLived, nil)
		if err != nil {
			Skip("Store rejected short-lived token")
		}

		// Re-store the same tokenID with a much later expiry before the
		// first entry's expiry has passed. The heap now holds two entries
		// for this tokenID — the earlier (stale) one and the live one.
		laterExpiry := time.Now().Add(1 * time.Hour)
		Expect(store.Store(ctx, tokenID, userID, nil, laterExpiry, nil)).To(Succeed())

		// Wait past the first (stale) entry's expiry, but well before the
		// second (live) one.
		time.Sleep(100 * time.Millisecond)

		count, err := store.Cleanup(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(count).To(Equal(0))

		token, err := store.Retrieve(ctx, tokenID)
		Expect(err).NotTo(HaveOccurred())
		Expect(token.ExpiresAt).To(BeTemporally("~", laterExpiry, time.Second))
	})
})

// ===== PHASE 10: Tracing =====
var _ = Describe("MemoryRefreshStore — Phase 10: Tracing", func() {
	var (
		ctrl         *gomock.Controller
		mockTracer   *testutil.MockTracer
		mockSpan     *testutil.MockSpan
		tracingStore *storage.MemoryRefreshStore
		ctx          context.Context
	)

	BeforeEach(func() {
		ctx = context.Background()
		ctrl = gomock.NewController(GinkgoT())
		mockTracer = testutil.NewMockTracer(ctrl)
		mockSpan = testutil.NewMockSpan(ctrl)
		tracingStore = storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{Tracer: mockTracer})
	})

	AfterEach(func() { ctrl.Finish() })

	Context("Store — success path", func() {
		It("should start a span named MemoryRefreshStore.Store with storage.backend, token_ref and StatusOK", func() {
			mockTracer.EXPECT().Start(gomock.Any(), "MemoryRefreshStore.Store").Return(ctx, mockSpan)
			mockSpan.EXPECT().SetAttributes(map[string]any{"storage_backend": "memory"})
			mockSpan.EXPECT().SetAttribute("token_ref", tokenref.Ref("trace-store-token"))
			mockSpan.EXPECT().SetStatus(tracing.StatusOK, "")
			mockSpan.EXPECT().End()

			Expect(tracingStore.Store(ctx, "trace-store-token", "trace-user", nil, time.Now().Add(time.Hour), nil)).To(Succeed())
		})
	})

	Context("Retrieve — error path", func() {
		It("should call RecordError and StatusError when token is not found", func() {
			mockTracer.EXPECT().Start(gomock.Any(), "MemoryRefreshStore.Retrieve").Return(ctx, mockSpan)
			mockSpan.EXPECT().SetAttributes(map[string]any{"storage_backend": "memory"})
			mockSpan.EXPECT().SetAttribute("token_ref", tokenref.Ref("missing-trace-token"))
			mockSpan.EXPECT().RecordError(storage.ErrTokenNotFound)
			mockSpan.EXPECT().SetStatus(tracing.StatusError, gomock.Any())
			mockSpan.EXPECT().End()

			_, err := tracingStore.Retrieve(ctx, "missing-trace-token")
			Expect(err).To(MatchError(storage.ErrTokenNotFound))
		})
	})
})

// ===== Recording Logger =====

// memLogEntry is one call recorded by memRecordingLogger.
type memLogEntry struct {
	level string        // "debug", "info", "warn", or "error"
	msg   string        // log message
	kv    []interface{} // bound fields followed by call key/value pairs
}

// memRecordingLogger is a logging.Logger that records every call. All methods
// are safe for concurrent use.
type memRecordingLogger struct {
	mu      *sync.Mutex
	entries *[]memLogEntry
	bound   []interface{} // fields pre-bound via With
}

func newMemRecordingLogger() *memRecordingLogger {
	return &memRecordingLogger{mu: &sync.Mutex{}, entries: &[]memLogEntry{}}
}

func (l *memRecordingLogger) log(level, msg string, kv []interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	all := make([]interface{}, 0, len(l.bound)+len(kv))
	all = append(all, l.bound...)
	all = append(all, kv...)
	*l.entries = append(*l.entries, memLogEntry{level: level, msg: msg, kv: all})
}

func (l *memRecordingLogger) Debug(msg string, kv ...interface{}) { l.log("debug", msg, kv) }
func (l *memRecordingLogger) Info(msg string, kv ...interface{})  { l.log("info", msg, kv) }
func (l *memRecordingLogger) Warn(msg string, kv ...interface{})  { l.log("warn", msg, kv) }
func (l *memRecordingLogger) Error(msg string, kv ...interface{}) { l.log("error", msg, kv) }

func (l *memRecordingLogger) With(kv ...interface{}) logging.Logger {
	bound := make([]interface{}, 0, len(l.bound)+len(kv))
	bound = append(bound, l.bound...)
	bound = append(bound, kv...)
	return &memRecordingLogger{mu: l.mu, entries: l.entries, bound: bound}
}

// snapshot returns a copy of every recorded entry.
func (l *memRecordingLogger) snapshot() []memLogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]memLogEntry, len(*l.entries))
	copy(out, *l.entries)
	return out
}

// field returns the value logged under key in e, and whether it was present.
// It scans every position because the store passes ctx as the first element,
// which shifts key/value pairing by one.
func (e memLogEntry) field(key string) (interface{}, bool) {
	for i := 0; i+1 < len(e.kv); i++ {
		if k, ok := e.kv[i].(string); ok && k == key {
			return e.kv[i+1], true
		}
	}
	return nil, false
}

// opaqueTokenID returns a value shaped like a real refresh token.
func opaqueTokenID() string {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	Expect(err).NotTo(HaveOccurred())
	return base64.RawURLEncoding.EncodeToString(b)
}

// ===== Digest Index Consistency =====
var _ = Describe("MemoryRefreshStore — Digest Index Consistency", func() {
	var (
		ctx   context.Context
		store *storage.MemoryRefreshStore
	)

	BeforeEach(func() {
		ctx = context.Background()
		store = storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{})
	})

	// expectConsistent asserts every record's digest matches its key, and that
	// the ListTokens sorted index holds exactly the token map's keys, in digest
	// order, whenever it is marked current — a stale entry would make
	// pagination return a token that no longer exists, or skip one that does.
	expectConsistent := func(after string) {
		GinkgoHelper()
		tokenKeys := store.TokenKeysForTest()
		Expect(store.RecordDigestsValidForTest()).To(BeTrue(), "record digest mismatch after %s", after)
		indexKeys, current, ordered := store.SortedIndexForTest()
		if current {
			Expect(indexKeys).To(Equal(tokenKeys), "sorted index marked current after %s", after)
			Expect(ordered).To(BeTrue(), "sorted index out of digest order after %s", after)
		}
	}

	// expectIndexCurrent asserts ListTokens left the sorted index current and
	// consistent with the token map.
	expectIndexCurrent := func(after string) {
		GinkgoHelper()
		_, current, _ := store.SortedIndexForTest()
		Expect(current).To(BeTrue(), "sorted index not current after %s", after)
		expectConsistent(after)
	}

	It("should hold exactly the token map's keys after every public method", func() {
		longLived := time.Now().Add(time.Hour)
		shortLived := time.Now().Add(50 * time.Millisecond)
		expectConsistent("construction")

		Expect(store.Store(ctx, "tok-a", "user-1", []string{"aud-1"}, longLived, nil)).To(Succeed())
		expectConsistent("Store")
		Expect(store.Store(ctx, "tok-b", "user-1", []string{"aud-1", "aud-2"}, shortLived, nil)).To(Succeed())
		expectConsistent("Store — short-lived")
		Expect(store.Store(ctx, "tok-a", "user-1", []string{"aud-1"}, longLived.Add(time.Hour), nil)).To(Succeed())
		expectConsistent("Store — same tokenID again")
		Expect(store.Store(ctx, "tok-c", "user-2", nil, shortLived, nil)).To(Succeed())
		Expect(store.Store(ctx, "tok-c", "user-2", nil, longLived, nil)).To(Succeed())
		expectConsistent("Store — re-store leaving a stale expiry-heap entry")
		Expect(store.Store(ctx, "tok-d", "user-3", nil, shortLived, nil)).To(Succeed())
		expectConsistent("Store — short-lived, never revoked")
		Expect(store.Store(ctx, "tok-rejected", "", nil, longLived, nil)).To(MatchError(storage.ErrInvalidUserID))
		expectConsistent("Store — rejected")

		_, err := store.Retrieve(ctx, "tok-a")
		Expect(err).NotTo(HaveOccurred())
		_, err = store.Retrieve(ctx, "tok-missing")
		Expect(err).To(MatchError(storage.ErrTokenNotFound))
		expectConsistent("Retrieve")

		Expect(store.Revoke(ctx, "tok-a")).To(Succeed())
		Expect(store.Revoke(ctx, "tok-missing")).To(Succeed())
		expectConsistent("Revoke")
		_, err = store.Retrieve(ctx, "tok-a")
		Expect(err).To(MatchError(storage.ErrTokenRevoked))
		expectConsistent("Retrieve — revoked")

		Expect(store.RevokeAllForUser(ctx, "user-1")).To(Succeed())
		expectConsistent("RevokeAllForUser")
		_, err = store.RevokeAllForAudience(ctx, "aud-2")
		Expect(err).NotTo(HaveOccurred())
		expectConsistent("RevokeAllForAudience")
		_, err = store.RevokeAllForUserAndAudience(ctx, "user-1", "aud-1")
		Expect(err).NotTo(HaveOccurred())
		expectConsistent("RevokeAllForUserAndAudience")

		_, _, err = store.ListTokens(ctx, "", 1)
		Expect(err).NotTo(HaveOccurred())
		expectIndexCurrent("ListTokens — rebuild")
		Expect(store.Store(ctx, "tok-a", "user-1", []string{"aud-1"}, longLived, nil)).To(Succeed())
		expectIndexCurrent("Store — same tokenID keeps the index current")
		Expect(store.Store(ctx, "tok-e", "user-4", nil, longLived, nil)).To(Succeed())
		_, current, _ := store.SortedIndexForTest()
		Expect(current).To(BeFalse(), "Store of a new tokenID must mark the sorted index stale")
		expectConsistent("Store — new tokenID")
		listed, _, err := store.ListTokens(ctx, "", 100)
		Expect(err).NotTo(HaveOccurred())
		Expect(listed).To(ContainElement(HaveField("TokenID", "tok-e")))
		expectIndexCurrent("ListTokens — rebuild after Store")
		_, _, err = store.ListTokensForUser(ctx, "user-1", "", 1)
		Expect(err).NotTo(HaveOccurred())
		_, _, err = store.ListTokensForAudience(ctx, "aud-1", "", 1)
		Expect(err).NotTo(HaveOccurred())
		expectConsistent("ListTokens, ListTokensForUser, ListTokensForAudience")
		Expect(store.Namespace()).To(BeEmpty())

		// Wait past shortLived: tok-b and tok-d expire; tok-c's stale entry is skipped.
		time.Sleep(100 * time.Millisecond)
		_, err = store.Retrieve(ctx, "tok-d")
		Expect(err).To(MatchError(storage.ErrTokenExpired))
		expectConsistent("Retrieve — expired")
		removed, err := store.Cleanup(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(Equal(2))
		expectConsistent("Cleanup")
		Expect(store.TokenKeysForTest()).To(Equal([]string{"tok-a", "tok-c", "tok-e"}))
		_, current, _ = store.SortedIndexForTest()
		Expect(current).To(BeFalse(), "Cleanup must mark the sorted index stale")
		_, _, err = store.ListTokens(ctx, "", 10)
		Expect(err).NotTo(HaveOccurred())
		expectIndexCurrent("ListTokens — rebuild after Cleanup")

		removed, err = store.Cleanup(ctx)
		Expect(err).NotTo(HaveOccurred())
		Expect(removed).To(Equal(0))
		expectConsistent("Cleanup — nothing expired")
	})

	It("should stay consistent while Store, Cleanup, and ListTokens run concurrently", func() {
		const workers = 20
		results := make(chan error, workers*3)
		for i := 0; i < workers; i++ {
			// Half the tokens expire almost immediately so Cleanup removes some mid-flight.
			expiresAt := time.Now().Add(30 * time.Millisecond)
			if i%2 == 0 {
				expiresAt = time.Now().Add(time.Hour)
			}
			tokenID := fmt.Sprintf("tok-concurrent-%02d", i)
			go func() { results <- store.Store(ctx, tokenID, "user-1", nil, expiresAt, nil) }()
			go func() { _, err := store.Cleanup(ctx); results <- err }()
			go func() { _, _, err := store.ListTokens(ctx, "", 5); results <- err }()
		}
		for i := 0; i < workers*3; i++ {
			Expect(<-results).NotTo(HaveOccurred())
		}
		expectConsistent("concurrent Store, Cleanup, and ListTokens")

		time.Sleep(60 * time.Millisecond)
		_, err := store.Cleanup(ctx)
		Expect(err).NotTo(HaveOccurred())
		expectConsistent("final Cleanup")
		Expect(store.TokenKeysForTest()).To(HaveLen(workers / 2))
		_, _, err = store.ListTokens(ctx, "", 5)
		Expect(err).NotTo(HaveOccurred())
		expectIndexCurrent("final ListTokens")
	})
})

// ===== ListTokens Digest Cursor =====
var _ = Describe("MemoryRefreshStore — ListTokens Digest Cursor", func() {
	var (
		ctx    context.Context
		rec    *memRecordingLogger
		store  *storage.MemoryRefreshStore
		stored []string // token IDs stored in BeforeEach
	)

	BeforeEach(func() {
		ctx = context.Background()
		rec = newMemRecordingLogger()
		store = storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{Logger: rec})
		stored = nil
		for i := 0; i < 10; i++ {
			tokenID := opaqueTokenID()
			Expect(store.Store(ctx, tokenID, "user-1", nil, time.Now().Add(time.Hour), nil)).To(Succeed())
			stored = append(stored, tokenID)
		}
	})

	// pageIDs returns the token IDs of a page, in order.
	pageIDs := func(tokens []*storage.RefreshToken) []string {
		ids := make([]string, 0, len(tokens))
		for _, t := range tokens {
			ids = append(ids, t.TokenID)
		}
		return ids
	}

	It("should return cursors of 64 lowercase hex characters that contain no part of any token", func() {
		cursor := ""
		pages := 0
		for {
			_, next, err := store.ListTokens(ctx, cursor, 3)
			Expect(err).NotTo(HaveOccurred())
			if next == "" {
				break
			}
			pages++
			Expect(next).To(MatchRegexp(`^[0-9a-f]{64}$`))
			for _, tokenID := range stored {
				Expect(next).NotTo(ContainSubstring(tokenID[:12]), "cursor contains part of a token")
			}
			cursor = next
		}
		Expect(pages).To(Equal(3), "10 tokens at 3 per page yield 3 non-empty cursors")
	})

	It("should return each token present for the whole iteration exactly once while tokens are stored and removed between pages", func() {
		// stored (10) stay for the whole iteration; add short-lived tokens
		// that Cleanup removes mid-iteration.
		for i := 0; i < 10; i++ {
			Expect(store.Store(ctx, opaqueTokenID(), "user-1", nil, time.Now().Add(50*time.Millisecond), nil)).To(Succeed())
		}

		seen := map[string]int{}
		cursor := ""
		for page := 0; ; page++ {
			tokens, next, err := store.ListTokens(ctx, cursor, 3)
			Expect(err).NotTo(HaveOccurred())
			for _, t := range tokens {
				seen[t.TokenID]++
			}

			// Churn between pages: store new tokens every page, and remove the
			// short-lived ones after the second page.
			for j := 0; j < 2; j++ {
				Expect(store.Store(ctx, opaqueTokenID(), "user-1", nil, time.Now().Add(time.Hour), nil)).To(Succeed())
			}
			if page == 1 {
				time.Sleep(60 * time.Millisecond)
				removed, err := store.Cleanup(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(removed).To(Equal(10))
			}

			if next == "" {
				break
			}
			Expect(page).To(BeNumerically("<", 100), "pagination did not terminate")
			cursor = next
		}

		for _, tokenID := range stored {
			Expect(seen[tokenID]).To(Equal(1), "token present throughout was not returned exactly once")
		}
		for tokenID, n := range seen {
			Expect(n).To(Equal(1), "token %s returned %d times", tokenref.Ref(tokenID), n)
		}
	})

	Context("invalid cursors", func() {
		var firstPage []string // token IDs of the page returned for an empty cursor
		var validCursor string // cursor returned after the first page

		BeforeEach(func() {
			tokens, next, err := store.ListTokens(ctx, "", 3)
			Expect(err).NotTo(HaveOccurred())
			firstPage = pageIDs(tokens)
			validCursor = next
			Expect(validCursor).NotTo(BeEmpty())
		})

		// Ordered slice — Ginkgo requires a deterministic spec tree.
		cases := []struct {
			name   string
			cursor func() string
		}{
			{"a raw token ID", func() string { return stored[0] }},
			{"63 hex characters", func() string { return validCursor[:63] }},
			{"64 uppercase hex characters", func() string { return strings.ToUpper(validCursor) }},
			{"a non-hex string", func() string { return "not-a-cursor" }},
		}

		for _, c := range cases {
			It("should restart from the beginning and log only cursor_ref and cursor_length for "+c.name, func() {
				cursor := c.cursor()
				tokens, _, err := store.ListTokens(ctx, cursor, 3)
				Expect(err).NotTo(HaveOccurred())
				Expect(pageIDs(tokens)).To(Equal(firstPage), "an invalid cursor restarts iteration")

				var warned bool
				for _, e := range rec.snapshot() {
					for _, v := range e.kv {
						Expect(fmt.Sprint(v)).NotTo(ContainSubstring(cursor), "raw cursor logged in %q", e.msg)
					}
					if e.level == "warn" && strings.Contains(e.msg, "invalid cursor") {
						ref, _ := e.field("cursor_ref")
						length, _ := e.field("cursor_length")
						Expect(ref).To(Equal(tokenref.Ref(cursor)))
						Expect(length).To(Equal(len(cursor)))
						warned = true
					}
				}
				Expect(warned).To(BeTrue(), "invalid cursor warning not logged")
			})
		}
	})
})

