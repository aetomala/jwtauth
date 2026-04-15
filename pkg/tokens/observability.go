package tokens

// Metric names for TokenManager operations. All implementations record the
// same set of metrics so the names are defined once here and referenced by
// all methods.
const (
	metricTokensIssuedTotal       = "jwtauth_tokens_issued_total"
	metricTokensValidatedTotal    = "jwtauth_tokens_validated_total"
	metricTokensRefreshedTotal    = "jwtauth_tokens_refreshed_total"
	metricTokensRevokedTotal      = "jwtauth_tokens_revoked_total"
	metricTokensIntrospectedTotal = "jwtauth_tokens_introspected_total"
	metricOperationsTotal         = "jwtauth_operations_total"
	metricOperationDuration       = "jwtauth_operation_duration_seconds"
	metricServiceRunning          = "jwtauth_service_running"
)
