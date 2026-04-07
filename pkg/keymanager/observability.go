package keymanager

// Metric names for KeyStore operations. Both DiskKeyStore and any future
// implementations record the same set of metrics so the names are defined
// once here and referenced by all implementations.
const (
	metricKeyStoreOpsTotal   = "jwtauth_keystore_operations_total"
	metricKeyStoreOpDuration = "jwtauth_keystore_operation_duration_seconds"
	metricKeyStoreKeysCount  = "jwtauth_keystore_keys_count"
)
