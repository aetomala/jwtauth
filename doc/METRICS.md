# Metrics Reference

Complete operator reference for all 22 metrics exposed by `jwtauth`. All metrics are pre-registered at construction time via `metrics.NewPrometheusMetrics()` — naming conflicts are caught early rather than at observation time.

---

## Label Conventions

### `status`
Present on all counters. Value is `"success"` on the happy path and a short error code on failure:

| Value | Meaning |
|-------|---------|
| `"success"` | Operation completed without error |
| `"token_expired"` | Token past `exp` (beyond `ClockSkew`) |
| `"token_not_yet_valid"` | Current time before `nbf` |
| `"token_revoked"` | Refresh token has been explicitly revoked |
| `"invalid_issuer"` | `iss` claim does not match configured issuer |
| `"invalid_audience"` | `aud` claim does not match configured audience |
| `"invalid_token"` | Malformed, wrong algorithm, or unknown `kid` |
| `"invalid_refresh_token"` | Refresh token not found in store |
| `"refresh_token_expired"` | Refresh token past TTL |
| `"invalid_user_id"` | Empty or whitespace-only user ID |
| `"service_not_running"` | Operation attempted before `Start()` |
| `"key_not_found"` | No signing or validation key available |
| `"error"` | Generic error (used by KeyManager and KeyStore) |

### `error_type`
Present on counters where granular error attribution is needed. Follows the OpenTelemetry `error.type` semantic convention:
- `""` (empty string) on success
- Mirrors the `status` value on failure

This allows PromQL to filter on error type independently of the success/failure split.

### `storage_backend`
Identifies which RefreshStore or KeyStore implementation is recording the metric:

| Value | Implementation |
|-------|---------------|
| `"memory"` | `MemoryRefreshStore` |
| `"redis"` | `RedisRefreshStore` / `RedisKeyStore` |
| `"disk"` | `DiskKeyStore` |

---

## TokenManager Metrics

### `jwtauth_tokens_issued_total`
- **Type**: Counter
- **Labels**: `status`, `error_type`
- **Description**: Total tokens issued — incremented once per access token and once per refresh token during `IssueTokenPair`. Also incremented for `IssueAccessToken` and `IssueRefreshToken` individually.

### `jwtauth_tokens_validated_total`
- **Type**: Counter
- **Labels**: `status`, `error_type`
- **Description**: Total access token validations. Incremented by `ValidateAccessToken` and `ValidateAccessTokenWithClaims`.

### `jwtauth_tokens_refreshed_total`
- **Type**: Counter
- **Labels**: `status`, `error_type`
- **Description**: Total refresh operations. Incremented by `RefreshAccessToken`.

### `jwtauth_tokens_revoked_total`
- **Type**: Counter
- **Labels**: `operation`, `status`
- **Description**: Total revocation calls. `operation` is `"revoke_token"` for single-token revocation or `"revoke_all_user_tokens"` for bulk revocation.

### `jwtauth_tokens_introspected_total`
- **Type**: Counter
- **Labels**: `status`
- **Description**: Total RFC 7662 introspection calls via `IntrospectToken`.

### `jwtauth_operations_total`
- **Type**: Counter
- **Labels**: `operation`, `status`
- **Description**: General service operations not covered by the specific counters above.

### `jwtauth_operation_duration_seconds`
- **Type**: Histogram
- **Labels**: `operation`
- **Buckets**: 1ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms, 500ms, 1s, 2.5s, 5s, 10s
- **Description**: End-to-end latency for TokenManager operations. `operation` matches the method name (e.g. `"issue_token_pair"`, `"validate_access_token"`).

### `jwtauth_active_tokens`
- **Type**: Gauge
- **Labels**: `storage_backend`
- **Description**: Number of non-expired refresh tokens currently in the store. Updated after issue, revoke, and cleanup operations.

### `jwtauth_service_running`
- **Type**: Gauge
- **Labels**: none
- **Description**: `1` when the TokenManager is running (after `Start()`), `0` when stopped. Alert on `== 0`.

---

## RefreshStore Metrics

### `jwtauth_storage_operations_total`
- **Type**: Counter
- **Labels**: `operation`, `status`, `error_type`, `storage_backend`
- **Description**: Total RefreshStore operations. `operation` values: `"store"`, `"get"`, `"delete"`, `"list_by_user"`, `"cleanup"`, `"revoke_all_user"`.

### `jwtauth_storage_cleanup_tokens_removed_total`
- **Type**: Counter
- **Labels**: `storage_backend`
- **Description**: Cumulative number of expired tokens removed during background cleanup runs.

### `jwtauth_storage_operation_duration_seconds`
- **Type**: Histogram
- **Labels**: `operation`, `storage_backend`
- **Buckets**: 0.1ms, 0.5ms, 1ms, 2.5ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms
- **Description**: Latency for individual storage operations. Use p99 to detect Redis latency spikes.

### `jwtauth_storage_tokens_count`
- **Type**: Gauge
- **Labels**: `storage_backend`
- **Description**: Current number of tokens in storage. Updated on store, delete, and cleanup.

---

## KeyStore Metrics

### `jwtauth_keystore_operations_total`
- **Type**: Counter
- **Labels**: `operation`, `status`, `error_type`, `storage_backend`
- **Description**: Total KeyStore operations. `operation` values: `"list_keys"`, `"load_key"`, `"save_key"`, `"delete_key"`.

### `jwtauth_keystore_operation_duration_seconds`
- **Type**: Histogram
- **Labels**: `operation`, `storage_backend`
- **Buckets**: 0.1ms, 0.5ms, 1ms, 2.5ms, 5ms, 10ms, 25ms, 50ms, 100ms, 250ms
- **Description**: Latency for individual KeyStore operations (disk reads, Redis round-trips).

### `jwtauth_keystore_keys_count`
- **Type**: Gauge
- **Labels**: `storage_backend`
- **Description**: Number of key entries in the KeyStore. Updated on save and delete.

---

## KeyManager Metrics

### `jwtauth_key_rotations_total`
- **Type**: Counter
- **Labels**: `status`, `error_type`
- **Description**: Total key rotation attempts. A rotation failure means new tokens will continue to be signed with the current key until the next rotation succeeds. Alert on sustained failures.

### `jwtauth_key_signing_operations_total`
- **Type**: Counter
- **Labels**: `status`, `error_type`
- **Description**: Total calls to `GetCurrentSigningKey`. Incremented once per token issuance. Failure means no signing key was available.

### `jwtauth_key_validation_operations_total`
- **Type**: Counter
- **Labels**: `status`, `error_type`
- **Description**: Total calls to `GetPublicKey`. Incremented once per token validation. Failure means the token's `kid` did not match any known key — typically an old token after a key rotation outside the overlap window.

### `jwtauth_key_operation_duration_seconds`
- **Type**: Histogram
- **Labels**: `operation`
- **Buckets**: 0.1ms, 0.5ms, 1ms, 2.5ms, 5ms, 10ms, 25ms, 50ms
- **Description**: Latency for KeyManager operations. `operation` values: `"get_signing_key"`, `"get_public_key"`, `"rotate"`.

### `jwtauth_key_current_version`
- **Type**: Gauge
- **Labels**: none
- **Description**: The version number of the currently active signing key. Monotonically increases with each rotation — useful for confirming that rotation has occurred.

### `jwtauth_key_active_versions_count`
- **Type**: Gauge
- **Labels**: none
- **Description**: Number of key versions currently loaded in the KeyManager (signing key + overlap keys). Should always be ≥ 1. Alert immediately on `== 0`.

### Custom Gauges via `GetCurrentKeyInfo`

The built-in metrics above cover rotation counts and operation latency. For time-based key health gauges, drive them from `GetCurrentKeyInfo` in a background collection loop:

```go
import (
    "github.com/aetomala/jwtauth/pkg/keys"
    "github.com/prometheus/client_golang/prometheus"
)

var (
    keyAgeSeconds = prometheus.NewGauge(prometheus.GaugeOpts{
        Name: "jwtauth_key_age_seconds",
        Help: "Age of the current signing key in seconds.",
    })
    rotationScheduledSeconds = prometheus.NewGauge(prometheus.GaugeOpts{
        Name: "jwtauth_rotation_scheduled_seconds",
        Help: "Seconds until the current signing key is scheduled to rotate.",
    })
    keyValid = prometheus.NewGauge(prometheus.GaugeOpts{
        Name: "jwtauth_key_valid",
        Help: "1 if the current signing key is valid, 0 if it has expired.",
    })
)

func collectKeyMetrics(ctx context.Context, km *keys.Manager) {
    info, err := km.GetCurrentKeyInfo(ctx)
    if err != nil {
        return
    }
    keyAgeSeconds.Set(time.Since(info.CreatedAt).Seconds())
    rotationScheduledSeconds.Set(time.Until(info.RotateAt).Seconds())
    if info.IsValid {
        keyValid.Set(1)
    } else {
        keyValid.Set(0)
    }
}
```

See `examples/prometheus-metrics/` for a complete runnable example.

---

## PromQL Cookbook

```promql
# ── Token Operations ────────────────────────────────────────────────────────

# Issuance error rate (last 5 minutes)
rate(jwtauth_tokens_issued_total{status!="success"}[5m])

# Validation failures by error type
rate(jwtauth_tokens_validated_total{status!="success"}[5m]) by (error_type)

# Refresh failure rate
rate(jwtauth_tokens_refreshed_total{status!="success"}[5m])

# Token issuance throughput (all successes)
rate(jwtauth_tokens_issued_total{status="success"}[5m])


# ── Key Health ───────────────────────────────────────────────────────────────

# Active key count (alert if == 0)
jwtauth_key_active_versions_count

# Key rotation failures in the past hour
rate(jwtauth_key_rotations_total{status!="success"}[1h])

# Signing operation failures (no signing key available)
rate(jwtauth_key_signing_operations_total{status!="success"}[5m])

# Validation failures due to unknown key (token from outside overlap window)
rate(jwtauth_key_validation_operations_total{status="key_not_found"}[5m])


# ── Storage ──────────────────────────────────────────────────────────────────

# Storage operation latency p99
histogram_quantile(0.99, rate(jwtauth_storage_operation_duration_seconds_bucket[5m]))

# Storage error rate by operation
rate(jwtauth_storage_operations_total{status!="success"}[5m]) by (operation, error_type)

# Active token count by backend
jwtauth_storage_tokens_count


# ── Service Health ───────────────────────────────────────────────────────────

# Service running status (1 = running, 0 = stopped)
jwtauth_service_running

# End-to-end operation latency p95
histogram_quantile(0.95, rate(jwtauth_operation_duration_seconds_bucket[5m])) by (operation)
```

---

## Alerting Rules

```yaml
groups:
  - name: jwtauth.critical
    rules:
      - alert: NoActiveSigningKey
        expr: jwtauth_key_active_versions_count == 0
        for: 1m
        annotations:
          severity: critical
          summary: "No active signing key — all token issuance will fail until rotation succeeds"

      - alert: TokenManagerStopped
        expr: jwtauth_service_running == 0
        for: 1m
        annotations:
          severity: critical
          summary: "TokenManager is not running"

  - name: jwtauth.warning
    rules:
      - alert: KeyRotationFailing
        expr: rate(jwtauth_key_rotations_total{status!="success"}[1h]) > 0
        for: 5m
        annotations:
          severity: warning
          summary: "Key rotation errors detected — current key remains valid until rotation succeeds"

      - alert: HighTokenValidationErrorRate
        expr: rate(jwtauth_tokens_validated_total{status!="success"}[5m]) > 0.05
        for: 5m
        annotations:
          severity: warning
          summary: "More than 5% of token validations are failing"

      - alert: StorageLatencyHigh
        expr: histogram_quantile(0.99, rate(jwtauth_storage_operation_duration_seconds_bucket[5m])) > 0.1
        for: 5m
        annotations:
          severity: warning
          summary: "Storage p99 latency above 100ms — check Redis connectivity"
```

---

## Grafana Dashboard Guidance

Recommended panels for a jwtauth dashboard:

| Panel | Metric | Visualization |
|-------|--------|---------------|
| Token issuance rate | `rate(jwtauth_tokens_issued_total{status="success"}[5m])` | Time series |
| Validation error breakdown | `rate(jwtauth_tokens_validated_total{status!="success"}[5m]) by (error_type)` | Stacked bar |
| Active key count | `jwtauth_key_active_versions_count` | Stat (alert threshold: 0) |
| Service running | `jwtauth_service_running` | Stat (green/red) |
| Storage latency p99 | `histogram_quantile(0.99, rate(jwtauth_storage_operation_duration_seconds_bucket[5m]))` | Time series |
| Active token count | `jwtauth_storage_tokens_count` | Time series |
| Key rotation history | `jwtauth_key_current_version` | Time series |

---

## Label Cardinality Analysis

All labels use bounded enumerations — safe for high-cardinality environments:

| Label | Cardinality | Values |
|-------|-------------|--------|
| `status` | ~13 | Bounded enum (see Label Conventions above) |
| `error_type` | ~13 | Mirrors `status` values |
| `storage_backend` | 3 | `"memory"`, `"redis"`, `"disk"` |
| `operation` | ~10 | Fixed method names per component |

No user-supplied data (user IDs, token values, IP addresses) appears in any label — there is no unbounded cardinality risk.

---

**See also**: [DEPLOYMENT.md](DEPLOYMENT.md) for operational setup, [ARCHITECTURE.md](ARCHITECTURE.md) for component design.
