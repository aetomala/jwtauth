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
store, _ := storage.NewRedisRefreshStore(storage.RedisRefreshStoreConfig{Client: redisClient, Logger: logger, Metrics: pm})
```

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

---

**See also**: [ARCHITECTURE.md](ARCHITECTURE.md) for component design and dependency inversion patterns, [METRICS.md](METRICS.md) for the complete metrics reference.
