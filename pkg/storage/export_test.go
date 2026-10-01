// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"bytes"
	"crypto/sha256"
	"sort"
)

// SortedIndexForTest reports the ListTokens sorted index, read under the
// store's lock, for testing purposes only. It returns the index's token IDs
// sorted by ID, whether the index is marked current, and whether its entries
// are in strictly ascending digest order.
func (m *MemoryRefreshStore) SortedIndexForTest() (keys []string, current, ordered bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	keys = make([]string, 0, len(m.sortedDigests))
	ordered = true
	for i, entry := range m.sortedDigests {
		keys = append(keys, entry.tokenID)
		if i > 0 && bytes.Compare(m.sortedDigests[i-1].digest[:], entry.digest[:]) >= 0 {
			ordered = false
		}
	}
	sort.Strings(keys)
	return keys, m.digestsSorted, ordered
}

// TokenKeysForTest returns the sorted keys of the token map, read under the
// store's lock, for testing purposes only.
func (m *MemoryRefreshStore) TokenKeysForTest() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	keys := make([]string, 0, len(m.tokens))
	for id := range m.tokens {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	return keys
}

// RecordDigestsValidForTest reports whether every stored record's digest is
// the SHA-256 of its tokenID and its token carries that tokenID, read under
// the store's lock, for testing purposes only.
func (m *MemoryRefreshStore) RecordDigestsValidForTest() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for id, rec := range m.tokens {
		if rec.digest != sha256.Sum256([]byte(id)) || rec.token.TokenID != id {
			return false
		}
	}
	return true
}
