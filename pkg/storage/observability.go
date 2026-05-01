package storage

// Metric names for storage operations. Both MemoryRefreshStore and
// RedisRefreshStore record the same set of metrics so the names are defined
// once here and referenced by both implementations.
const (
	metricStorageOpsTotal     = "jwtauth_storage_operations_total"
	metricStorageOpDuration   = "jwtauth_storage_operation_duration_seconds"
	metricStorageRemovedTotal = "jwtauth_storage_cleanup_tokens_removed_total"
	metricStorageTokensCount  = "jwtauth_storage_tokens_count"

	metricListTokensTotal    = "jwtauth_storage_list_tokens_total"
	metricListTokensDuration = "jwtauth_storage_list_tokens_duration_seconds"

	metricListTokensForUserTotal    = "jwtauth_storage_list_tokens_for_user_total"
	metricListTokensForUserDuration = "jwtauth_storage_list_tokens_for_user_duration_seconds"
)
