// Copyright 2026 Angel Tomala-Reyes
//
// SPDX-License-Identifier: Apache-2.0

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

	metricTokensListTotal    = "jwtauth_tokens_list_total"
	metricTokensListDuration = "jwtauth_tokens_list_duration_seconds"

	metricTokensListForUserTotal    = "jwtauth_tokens_list_for_user_total"
	metricTokensListForUserDuration = "jwtauth_tokens_list_for_user_duration_seconds"

	metricTokensListForAudienceTotal    = "jwtauth_tokens_list_for_audience_total"
	metricTokensListForAudienceDuration = "jwtauth_tokens_list_for_audience_duration_seconds"
)
