// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package keys

import (
	"context"
	"sync"
)

// PemPrefix returns the effective PEM key prefix for testing purposes only.
func (r *RedisKeyStore) PemPrefix() string { return r.pemPrefix }

// MetaPrefix returns the effective metadata key prefix for testing purposes only.
func (r *RedisKeyStore) MetaPrefix() string { return r.metaPrefix }

// Mu returns the Manager's read-write mutex for testing purposes only.
func (m *Manager) Mu() *sync.RWMutex { return &m.mu }

// Keys returns the Manager's key cache map for testing purposes only.
func (m *Manager) Keys() map[string]*KeyPair { return m.keys }

// CleanupExpiredKeysForTest invokes cleanupExpiredKeys for testing purposes only.
func (m *Manager) CleanupExpiredKeysForTest(ctx context.Context) { m.cleanupExpiredKeys(ctx) }

// IsRotationSchedulerActive reports whether the rotation scheduler goroutine is
// currently running, for testing purposes only.
func (m *Manager) IsRotationSchedulerActive() bool { return m.rotationSchedulerActive.Load() }
