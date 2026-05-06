// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

package keys

// Metric names for KeyStore operations. Both DiskKeyStore and any future
// implementations record the same set of metrics so the names are defined
// once here and referenced by all implementations.
const (
	metricKeyStoreOpsTotal   = "jwtauth_keystore_operations_total"
	metricKeyStoreOpDuration = "jwtauth_keystore_operation_duration_seconds"
	metricKeyStoreKeysCount  = "jwtauth_keystore_keys_count"
)

// Metric names for Manager operations. These capture higher-level semantics
// (rotation events, signing requests, validation lookups) that are independent
// of the storage backend in use.
const (
	metricKeyRotationsTotal      = "jwtauth_key_rotations_total"
	metricKeySigningOpsTotal     = "jwtauth_key_signing_operations_total"
	metricKeyValidationOpsTotal  = "jwtauth_key_validation_operations_total"
	metricKeyOpDuration          = "jwtauth_key_operation_duration_seconds"
	metricKeyActiveVersionsCount = "jwtauth_key_active_versions_count"
)
