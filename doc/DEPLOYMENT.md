# Deployment Guide

Operational reference for running applications built with `jwtauth` — covering startup validation, health checks, metrics collection, graceful shutdown, and production tuning.

---

## Pre-flight Checklist

Before starting in production, verify the following:

### Key Storage

**DiskKeyStore** — check directory permissions before startup:
```bash
# Directory must be readable and writable by the process user
ls -la ./keys/
# Expected: drwx------ (700) or drwxr-x--- (750) for the process user
chmod 700 ./keys/
```

**RedisKeyStore / RedisRefreshStore** — verify connectivity at startup:
```go
// Ping Redis before creating stores — fail fast rather than at first token operation
if err := redisClient.Ping(ctx).Err(); err != nil {
    log.Fatalf("Redis unavailable: %v", err)
}

ks, _    := keys.NewRedisKeyStore(keys.RedisKeyStoreConfig{Client: redisClient, Logger: logger, Metrics: pm})
store, _ := storage.NewRedisRefreshStore(storage.RedisRefreshStoreConfig{Client: redisClient, Logger: logger, Metrics: pm})
```

### Service Start Order

Always start `KeyManager` before `TokenManager` — `TokenManager.Start()` does not call `KeyManager.Start()`:
```go
// Correct order
if err := km.Start(ctx); err != nil {
    log.Fatal("KeyManager failed to start:", err)
}
if err := mgr.Start(ctx); err != nil {
    log.Fatal("TokenManager failed to start:", err)
}
```

---

## Health Checks

Expose a health endpoint that reflects actual service state — not just HTTP liveness.

```go
// Health check handler — checks both manager and key availability
func healthHandler(mgr *tokens.Manager, km keys.KeyManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if !mgr.IsRunning() {
            w.WriteHeader(http.StatusServiceUnavailable)
            json.NewEncoder(w).Encode(map[string]string{
                "status": "unhealthy",
                "reason": "token service not running",
            })
            return
        }

        if _, err := km.GetCurrentSigningKey(r.Context()); err != nil {
            w.WriteHeader(http.StatusServiceUnavailable)
            json.NewEncoder(w).Encode(map[string]string{
                "status": "unhealthy",
                "reason": "no active signing key",
            })
            return
        }

        w.WriteHeader(http.StatusOK)
        json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
    }
}
```

**Kubernetes probe configuration**:
```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 2
  periodSeconds: 5
```

---

## Metrics Collection

Wire `PrometheusMetrics` into every component — pass the same `pm` instance to all constructors:

```go
pm := metrics.NewPrometheusMetrics(metrics.PrometheusConfig{
    Namespace: "myapp",  // prefix for all metric names; defaults to "jwtauth"
})

ks, _    := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{Dir: "./keys", KeySize: 2048, Logger: logger, Metrics: pm})
km, _    := keys.NewManager(keys.KeyManagerConfig{KeyStore: ks, Metrics: pm})
store, _ := storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{Logger: logger, Metrics: pm})
mgr, _  := tokens.NewManager(tokens.TokenManagerConfig{
    KeyManager:   km,
    RefreshStore: store,
    Metrics:      pm,
})

// Serve the /metrics endpoint
http.Handle("/metrics", pm.Handler())
```

**Prometheus scrape config**:
```yaml
scrape_configs:
  - job_name: "auth-service"
    static_configs:
      - targets: ["auth-service:8080"]
    metrics_path: /metrics
    scrape_interval: 15s
```

**Key alerts**:

```yaml
groups:
  - name: jwtauth
    rules:
      - alert: NoActiveSigningKey
        expr: jwtauth_key_active_versions_count == 0
        for: 1m
        severity: critical
        annotations:
          summary: "No active signing key — token issuance will fail"

      - alert: KeyRotationFailing
        expr: rate(jwtauth_key_rotations_total{status!="success"}[1h]) > 0
        for: 5m
        severity: warning
        annotations:
          summary: "Key rotation errors detected"

      - alert: TokenManagerStopped
        expr: jwtauth_service_running == 0
        for: 1m
        severity: critical
        annotations:
          summary: "TokenManager is not running"
```

For the complete metric reference — all 22 metrics with label values and PromQL cookbook — see [METRICS.md](METRICS.md).

---

## Distributed Tracing

jwtauth emits OpenTelemetry-compatible spans via `pkg/tracing`. By default every component uses `NoOpTracer` — no setup required for local development. For production, initialize a `TracerProvider` and pass `tracing.NewOtelTracer("jwtauth")` into each config.

### OTel SDK Setup

```go
import (
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
    "go.opentelemetry.io/otel/sdk/trace"
    "github.com/aetomala/jwtauth/pkg/tracing"
    "github.com/aetomala/jwtauth/pkg/keys"
    "github.com/aetomala/jwtauth/pkg/storage"
    "github.com/aetomala/jwtauth/pkg/tokens"
)

// 1. Create an OTLP exporter (Jaeger, Tempo, or any OTLP-compatible backend)
exporter, err := otlptracehttp.New(ctx,
    otlptracehttp.WithEndpoint("http://localhost:4318"),
)
if err != nil {
    log.Fatal(err)
}

// 2. Build a TracerProvider with your preferred sampler
tp := trace.NewTracerProvider(
    trace.WithBatcher(exporter),
    trace.WithSampler(trace.AlwaysSample()), // adjust for production
)
otel.SetTracerProvider(tp)
defer tp.Shutdown(ctx)

// 3. Create a jwtauth tracer and pass it to every component
tracer := tracing.NewOtelTracer("jwtauth")

ks, _ := keys.NewDiskKeyStore(keys.DiskKeyStoreConfig{
    Dir:    "./keys",
    Tracer: tracer,
})
km, _ := keys.NewManager(keys.KeyManagerConfig{
    KeyStore: ks,
    Tracer:   tracer,
})
store := storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{Tracer: tracer})
mgr, _ := tokens.NewManager(tokens.TokenManagerConfig{
    KeyManager:   km,
    RefreshStore: store,
    Tracer:       tracer,
})
```

### Sampler Recommendations

| Environment | Sampler | Rationale |
|-------------|---------|-----------|
| Development | `AlwaysSample` | Capture every span for debugging |
| Staging | `TraceIDRatioBased(0.1)` | 10% sample — enough to verify instrumentation |
| Production | `ParentBased(TraceIDRatioBased(0.01))` | 1% sample; respect upstream sampling decisions |

Sampling is the caller's responsibility — jwtauth defers entirely to the OTel SDK.

### Endpoint Environment Variables (OTLP)

| Variable | Default | Description |
|----------|---------|-------------|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://localhost:4318` | OTLP HTTP exporter endpoint |
| `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | — | Override for traces only |
| `OTEL_SERVICE_NAME` | — | Service name tag applied to all spans |

---

## Graceful Shutdown

Shut down in reverse start order — `TokenManager` first, then `KeyManager`. Always use a deadline:

```go
srv := &http.Server{Addr: ":8080", Handler: r}

// Listen for shutdown signals
quit := make(chan os.Signal, 1)
signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
<-quit

// Allow 30 seconds total for shutdown
shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
defer cancel()

// 1. Stop accepting new HTTP connections
if err := srv.Shutdown(shutdownCtx); err != nil {
    log.Println("HTTP server shutdown error:", err)
}

// 2. Shut down TokenManager (drains in-flight operations)
if err := mgr.Shutdown(shutdownCtx); err != nil {
    log.Println("TokenManager shutdown error:", err)
}

// 3. Shut down KeyManager
if err := km.Shutdown(shutdownCtx); err != nil {
    log.Println("KeyManager shutdown error:", err)
}
```

**Shutdown timeout guidance**:
- 30 seconds is sufficient for most deployments
- Reduce to 10 seconds if token operations are short-lived (< 5s timeouts)
- Increase to 60 seconds if using Redis with high latency (> 20ms round-trip)

---

## RefreshStore Selection

| Factor | MemoryRefreshStore | RedisRefreshStore |
|--------|-------------------|-------------------|
| **Instances** | 1 | 2+ |
| **Shared revocation** | Per-instance only | Immediate across all |
| **Latency** | < 1ms | ~1–5ms |
| **Persistence** | Lost on restart | Survives restarts |
| **Auto-cleanup** | Background goroutine | Redis TTL |
| **Scale** | Thousands of tokens | Millions of tokens |
| **Dependencies** | None | Redis required |

**Single-instance** (development, small deployments):
```go
store, _ := storage.NewMemoryRefreshStore(storage.MemoryRefreshStoreConfig{Logger: logger, Metrics: pm})
```

**Multi-instance** (Kubernetes, load-balanced):
```go
redisClient := redis.NewClient(&redis.Options{
    Addr: os.Getenv("REDIS_ADDR"),
})
store, _ := storage.NewRedisRefreshStore(storage.RedisRefreshStoreConfig{
    Client:    redisClient,
    Logger:    logger,
    Metrics:   pm,
    KeyPrefix: "myapp:",  // Optional; isolates keys when sharing a Redis cluster
})
```

---

## Namespace Isolation

When running multiple `Manager` instances against the same Redis cluster — for example, two
services sharing infrastructure, or multiple tenants on a single deployment — configure
`KeyPrefix` and `Namespace` to keep their data and observability output separate.

`KeyPrefix` is set on the Redis store configs and prepended to every Redis key written by that
instance. Two managers with different prefixes can share one Redis cluster without key collision:

```go
// Tenant A
ksA, _ := keys.NewRedisKeyStore(keys.RedisKeyStoreConfig{
    Client:    redisClient,
    KeyPrefix: "tenant-a:",
})
storeA, _ := storage.NewRedisRefreshStore(storage.RedisRefreshStoreConfig{
    Client:    redisClient,
    KeyPrefix: "tenant-a:",
})
kmA, _ := keys.NewManager(keys.KeyManagerConfig{
    KeyStore:  ksA,
    Namespace: "tenant-a",
})
mgrA, _ := tokens.NewManager(tokens.TokenManagerConfig{
    KeyManager:   kmA,
    RefreshStore: storeA,
    Namespace:    "tenant-a",
})

// Tenant B — same Redis, no data overlap
ksB, _ := keys.NewRedisKeyStore(keys.RedisKeyStoreConfig{
    Client:    redisClient,
    KeyPrefix: "tenant-b:",
})
storeB, _ := storage.NewRedisRefreshStore(storage.RedisRefreshStoreConfig{
    Client:    redisClient,
    KeyPrefix: "tenant-b:",
})
kmB, _ := keys.NewManager(keys.KeyManagerConfig{
    KeyStore:  ksB,
    Namespace: "tenant-b",
})
mgrB, _ := tokens.NewManager(tokens.TokenManagerConfig{
    KeyManager:   kmB,
    RefreshStore: storeB,
    Namespace:    "tenant-b",
})
```

`Namespace` is set on the manager configs and flows through all three observability signals:

- **Logs** — a `namespace` field is pre-bound to every log line via `Logger.With`
- **Spans** — a `namespace` attribute is attached to every trace span
- **Metrics** — a `namespace` label is added to every Prometheus counter and histogram

This lets you filter dashboards, traces, and logs to a single Manager instance without changing
metric names or adding routing logic.

See [ADR-006](adr/006-keyprefix-namespace-isolation.md) and
[ADR-007](adr/007-namespace-consistency-contract.md).

### Redis Key Schema

Every key written by a store instance is prefixed by the configured `KeyPrefix`. The complete
set of patterns for a deployment with `KeyPrefix: "myapp:"` is:

**`RedisRefreshStore`**:
```
myapp:tokens:<tokenID>                  — token hash (HSet)
myapp:user_tokens:<userID>              — set of tokenIDs for that user (SAdd)
myapp:audience_tokens:<aud>             — set of tokenIDs for that audience (SAdd)
myapp:audience_user_tokens:<aud>:<uid>  — set of tokenIDs for that user+audience (SAdd)
```

**`RedisKeyStore`**:
```
myapp:ks:pem:<keyID>   — PKCS#1 PEM private key (string)
myapp:ks:meta:<keyID>  — JSON KeyMetadata (string)
```

An empty `KeyPrefix` omits the prefix entirely, preserving the pre-ADR-006 key layout. Use
these patterns when writing Redis ACL rules or verifying namespace isolation with `SCAN`.

---

## Redis Security Hardening

jwtauth delegates all Redis I/O to the `go-redis` client — any security options supported by
that client apply directly to `RedisKeyStore` and `RedisRefreshStore`.

### TLS

Pass a `tls.Config` via `redis.Options.TLSConfig` to enforce encrypted transport:

```go
import (
    "crypto/tls"
    "crypto/x509"
    "os"
)

caCert, _ := os.ReadFile("/etc/ssl/redis-ca.crt")
pool := x509.NewCertPool()
pool.AppendCertsFromPEM(caCert)

redisClient := redis.NewClient(&redis.Options{
    Addr: os.Getenv("REDIS_ADDR"),
    TLSConfig: &tls.Config{
        RootCAs:    pool,
        MinVersion: tls.VersionTLS12,
    },
})
```

Do not set `InsecureSkipVerify: true` in production — it defeats TLS certificate validation.

### Authentication

Pass credentials via environment variables — never hardcode them:

```go
redisClient := redis.NewClient(&redis.Options{
    Addr:     os.Getenv("REDIS_ADDR"),
    Password: os.Getenv("REDIS_PASSWORD"), // Redis AUTH or ACL password
    Username: os.Getenv("REDIS_USERNAME"), // Required for Redis 6+ ACL users
})
```

### ACL Minimum Command Sets

Redis 6+ ACLs allow a least-privilege user per store type. The minimum command sets required
by jwtauth are:

**`RedisKeyStore`** — RSA key persistence:
```
ACL SETUSER jwtauth-keys on ><password>
  ~<prefix>ks:pem:*
  ~<prefix>ks:meta:*
  +GET +SET +DEL +SCAN
  +PING
```

**`RedisRefreshStore`** — refresh token lifecycle:
```
ACL SETUSER jwtauth-tokens on ><password>
  ~<prefix>tokens:*
  ~<prefix>user_tokens:*
  ~<prefix>audience_tokens:*
  ~<prefix>audience_user_tokens:*
  +HSET +HGET +HGETALL +HDEL
  +SADD +SREM +SMEMBERS +SSCAN
  +DEL +EXISTS +EXPIRE +SCAN
  +PING
```

Replace `<prefix>` with your configured `KeyPrefix` value (e.g. `myapp:`). An empty
`KeyPrefix` uses no prefix — set the key pattern to `~*` and tighten it after deploying
with namespace isolation enabled.

### Network Isolation

Bind Redis to a private network interface — never expose it on a public address:

- **Kubernetes**: deploy Redis in the same namespace or use a `NetworkPolicy` that restricts
  ingress to your service pods only.
- **VMs / bare-metal**: bind to `127.0.0.1` or a private VLAN; use a firewall rule to allow
  only application host IPs.
- **Managed Redis** (Elasticache, MemoryDB, Redis Cloud): enable VPC-only access and disable
  public endpoints.

---

## Token Enumeration

`ListTokens` and `ListTokensForUser` expose the full token inventory in the `RefreshStore`
via cursor-based pagination. Operational use cases include:

- **Compliance exports** — audit all active sessions for a user or the entire system
- **Bulk revocation** — revoke all tokens for a decommissioned user or tenant
- **Session dashboards** — surface active token counts in admin tooling
- **Reconciliation jobs** — verify no orphaned tokens remain after a migration

**Pagination pattern:**

```go
var cursor string
for {
    page, next, err := mgr.ListTokens(ctx, cursor, 100)
    if err != nil {
        return err
    }
    for _, t := range page {
        // Tokens are returned regardless of expiry or revocation — filter as needed.
        if t.ExpiresAt.After(time.Now()) {
            process(t)
        }
    }
    if next == "" {
        break // exhausted
    }
    cursor = next
}
```

To enumerate tokens for a specific user, replace the first line of the loop body:

```go
page, next, err := mgr.ListTokensForUser(ctx, userID, cursor, 100)
```

To enumerate tokens scoped to a specific audience:

```go
page, next, err := mgr.ListTokensForAudience(ctx, "svc-payments", cursor, 100)
```

Tokens issued with multiple audiences (e.g. `WithAudience("svc-payments", "svc-reports")`) appear
in the listing for **each** of their audiences — a token is not double-counted within a single
audience listing, but it will appear once in the `svc-payments` listing and once in the
`svc-reports` listing. The primary use case for `ListTokensForAudience` is the audit-before-revoke
workflow described in [Audience-Scoped Revocation](#audience-scoped-revocation).

`count` is a hint — the actual page size may vary. Cursor semantics are best-effort under
concurrent mutation: tokens created or deleted between pages may appear, disappear, or shift.

**Pagination guarantees (ADR-011):** Cursors are opaque — do not decode, construct,
compare, or persist them across library upgrades or backend changes. Pagination is
best-effort: tokens inserted or deleted between pages may appear, be skipped, or appear
twice. Iteration order is not guaranteed to be stable between calls or consistent across
backends. Audit pipelines that require complete, duplicate-free enumeration should hold
an application-level mutex, enumerate to exhaustion, then process the snapshot.

See `examples/token-audit/` for a runnable reference.

---

## Audience-Scoped Revocation

`RevokeAllForAudience` and `RevokeAllForUserAndAudience` on `tokens.Manager` mark all
non-expired refresh tokens scoped to a given audience as revoked. The primary use case is
instant containment after a service-side credential compromise — for example, revoking every
token that can reach `svc-payments` without touching tokens issued for unrelated services.

```go
// Revoke all tokens for all users that can reach svc-payments.
if err := mgr.RevokeAllForAudience(ctx, "svc-payments"); err != nil {
    return err
}

// Revoke only tokens for a specific user in the svc-payments audience.
if err := mgr.RevokeAllForUserAndAudience(ctx, userID, "svc-payments"); err != nil {
    return err
}
```

**Revocation is global for multi-audience tokens.** A token issued with
`WithAudience("svc-payments", "svc-reports")` is revoked completely when either audience is
targeted — the token is not partially invalidated. Callers should treat every token that
carries the targeted audience as fully revoked, regardless of its other audiences.

**Empty audience strings** are rejected with `storage.ErrInvalidAudience` before any storage
operation is attempted.

**Index maintenance** — both `MemoryRefreshStore` and `RedisRefreshStore` maintain an
audience index that is pruned by `CleanupExpiredTokens`. Stale entries from expired tokens
do not accumulate indefinitely. Issuing a fresh token after cleanup restores the index
correctly, so subsequent revocations target only live tokens.

**Revocation scope metric** — both operations emit `revocation_scope` labels (`"audience"`
and `"user_audience"`) on the `jwtauth_tokens_revoked_total` counter, consistent with the
existing `"single"` and `"all_user"` scopes.

### Audit before revoke

`ListTokensForAudience` lets you enumerate the sessions that would be affected before
committing to a revocation — useful for compliance logging, dry-run validation, or building
a confirmation step into an admin workflow:

```go
// Enumerate active sessions for svc-payments.
var cursor string
for {
    page, next, err := mgr.ListTokensForAudience(ctx, "svc-payments", cursor, 100)
    if err != nil {
        return err
    }
    for _, t := range page {
        if t.ExpiresAt.After(time.Now()) {
            log.Printf("will revoke token %s for user %s", t.TokenID, t.UserID)
        }
    }
    if next == "" {
        break
    }
    cursor = next
}

// Revoke all tokens for svc-payments.
if err := mgr.RevokeAllForAudience(ctx, "svc-payments"); err != nil {
    return err
}
```

Tokens issued with multiple audiences (e.g. `WithAudience("svc-payments", "svc-reports")`)
appear in the `ListTokensForAudience` listing for **each** of their audiences. The token is
stored and revoked as a single record — appearing in multiple listings does not cause it to
be revoked multiple times.

---

## Reserved Claims

The fields `sub`, `iss`, `aud`, `exp`, `nbf`, `iat`, and `jti` are silently removed from any
`CustomClaims` map before a token is signed. These fields are under jwtauth's control — setting
them through custom claims would produce tokens that violate the configured `Issuer`, `Audience`,
or lifetime constraints. To set audience and issuer, use `TokenManagerConfig.Audience` and
`TokenManagerConfig.Issuer` instead.

See [ADR-008](adr/008-reserved-claims-at-issuance.md).

---

## Custom Claims Validation

jwtauth validates token structure, signature, and standard claims (`alg`, `kid`, `iss`, `aud`,
`exp`, `nbf`) but does **not** validate the values of custom claims. That responsibility belongs
to the caller.

After a successful `ValidateAccessToken` or `ValidateAccessTokenWithClaims`, you must:

1. **Type-assert** each custom claim before use — the underlying type is `interface{}`, and a
   missing or malformed claim will panic if asserted without a check.
2. **Range-check** values — the library cannot know your application's constraints.

```go
_, custom, err := mgr.ValidateAccessTokenWithClaims(ctx, rawToken)
if err != nil {
    return err
}

// Type-assert before use — never assume the claim exists or has the expected type.
role, ok := custom["role"].(string)
if !ok || role == "" {
    return errors.New("missing or invalid role claim")
}

// Range-check against your application's allowed values.
if role != "admin" && role != "editor" && role != "viewer" {
    return fmt.Errorf("unrecognized role: %q", role)
}
```

**Common pitfalls**:

| Mistake | Consequence |
|---------|-------------|
| `claims.CustomClaims["role"].(string)` without the `, ok` form | Panics if the claim is absent or the wrong type |
| Accepting any non-empty string without an allowlist check | Privilege escalation if a token carries an unexpected role value |
| Not checking whether `claims.CustomClaims` is nil | Panics if no custom claims were set at issuance |

The reserved-claim guard (see [Reserved Claims](#reserved-claims)) prevents overwriting `sub`,
`iss`, `aud`, `exp`, `nbf`, `iat`, and `jti` at issuance — it does not validate custom claim
values at validation time.

---

## ClockSkew Tuning

In distributed deployments, servers may have slight clock drift. `ClockSkew` adds leeway to `exp` and `nbf` validation without inflating token lifetimes:

```go
mgr, _ := tokens.NewManager(tokens.TokenManagerConfig{
    // ...
    ClockSkew: 30 * time.Second,  // Accept tokens up to 30s past expiry
})
```

**Guidance**:
- `0` (default) — strict validation; use in single-server deployments with NTP
- `10s–30s` — typical for Kubernetes clusters with NTP drift
- `60s` — maximum recommended; beyond this, inflate `AccessTokenDuration` instead

---

## Key Rotation Monitoring

`KeyManager` rotates keys automatically on `KeyRotationInterval`. Monitor rotation health:

```promql
# Rotation failures in the past hour
rate(jwtauth_key_rotations_total{status!="success"}[1h])

# Active key versions — should be ≥ 1 at all times
jwtauth_key_active_versions_count

# Current key version (monotonically increasing)
jwtauth_key_current_version
```

The overlap period (default 1 hour) keeps pre-rotation tokens valid. Tokens signed with the old key continue to validate during the overlap — no re-issuance or service restart is required.

---

## Rate Limiting

Rate limiting is a deployment concern, not a library concern. Apply it at the layer appropriate for your topology:

- **API Gateway** (Kong, AWS API Gateway) — correct default for multi-instance; shared counters across pods
- **Kubernetes Ingress** (NGINX `limit-rps`) — infrastructure-level, no application code required
- **Application middleware** — only for single-instance deployments or when gateway-level limiting is unavailable

`jwtauth` intentionally does not include rate limiting — building it in would force per-instance counters (incorrect for distributed deployments) and an opinionated policy on users who already have gateway infrastructure.

### Recommended Starting Values

These are conservative starting points — tune based on observed traffic and SLOs.

| Endpoint | Limit | Rationale |
|----------|-------|-----------|
| `POST /login` (token issuance) | 10 req/min per IP | Brute-force protection |
| `POST /refresh` (token refresh) | 30 req/min per IP | Normal session activity |
| `POST /revoke` | 20 req/min per user | Prevent revocation-flood DoS |
| Internal validation (service-to-service) | 1 000 req/min per service | High-frequency, low-cost operation |

Observe p99 latency and error rates for the first week in production before tightening or relaxing these limits.

### Gateway Configuration References

- **Kong**: [Rate Limiting plugin](https://docs.konghq.com/hub/kong-inc/rate-limiting/) — supports Redis-backed shared counters for multi-instance deployments
- **NGINX Ingress**: [`nginx.ingress.kubernetes.io/limit-rps`](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#rate-limiting) annotation
- **AWS API Gateway**: [Usage Plans and API Keys](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-api-usage-plans.html)

---

**See also**: [ARCHITECTURE.md](ARCHITECTURE.md) for component design and dependency inversion patterns, [METRICS.md](METRICS.md) for the complete metrics reference.
