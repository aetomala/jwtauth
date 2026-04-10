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

ks, _ := keymanager.NewRedisKeyStore(redisClient, logger, pm)
store := storage.NewRedisRefreshStore(redisClient, logger, pm)
```

### Service Start Order

Always start `KeyManager` before `TokenService` — `TokenService.Start()` does not call `KeyManager.Start()`:
```go
// Correct order
if err := km.Start(ctx); err != nil {
    log.Fatal("KeyManager failed to start:", err)
}
if err := svc.Start(ctx); err != nil {
    log.Fatal("TokenService failed to start:", err)
}
```

---

## Health Checks

Expose a health endpoint that reflects actual service state — not just HTTP liveness.

```go
// Health check handler — checks both service and key availability
func healthHandler(svc *tokens.Service, km keymanager.KeyManager) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        if !svc.IsRunning() {
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

ks, _   := keymanager.NewDiskKeyStore("./keys", 2048, logger, pm)
km, _   := keymanager.NewManager(keymanager.ManagerConfig{KeyStore: ks, Metrics: pm})
store   := storage.NewMemoryRefreshStore(logger, pm)
svc, _  := tokens.NewService(tokens.ServiceConfig{
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

      - alert: TokenServiceStopped
        expr: jwtauth_service_running == 0
        for: 1m
        severity: critical
        annotations:
          summary: "TokenService is not running"
```

For the complete metric reference — all 22 metrics with label values and PromQL cookbook — see [METRICS.md](METRICS.md).

---

## Graceful Shutdown

Shut down in reverse start order — `TokenService` first, then `KeyManager`. Always use a deadline:

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

// 2. Shut down TokenService (drains in-flight operations)
if err := svc.Shutdown(shutdownCtx); err != nil {
    log.Println("TokenService shutdown error:", err)
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
store := storage.NewMemoryRefreshStore(logger, pm)
```

**Multi-instance** (Kubernetes, load-balanced):
```go
redisClient := redis.NewClient(&redis.Options{
    Addr: os.Getenv("REDIS_ADDR"),
})
store := storage.NewRedisRefreshStore(redisClient, logger, pm)
```

---

## ClockSkew Tuning

In distributed deployments, servers may have slight clock drift. `ClockSkew` adds leeway to `exp` and `nbf` validation without inflating token lifetimes:

```go
svc, _ := tokens.NewService(tokens.ServiceConfig{
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
