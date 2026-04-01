# Deployment Architecture

This guide covers deployment patterns for applications built with `jwtauth`, with a focus on where rate limiting belongs and how to configure it at each layer.

## Rate Limiting Is Not in This Library — By Design

`jwtauth` is a focused JWT library. Rate limiting is a deployment concern that varies by environment, scale, and business rules. Building it into the library would:

- Break distributed correctness (per-instance counters diverge across pods)
- Force an opinionated implementation on users who already have infrastructure
- Conflate token operations with request policy enforcement

The right layer depends on your deployment topology.

---

## Layer 1: API Gateway (Recommended for Distributed Deployments)

Rate limiting at the API Gateway is the correct default for any multi-instance deployment. It works across all service instances without shared state in your application.

### Kong

```yaml
# Apply rate limiting per route
plugins:
  - name: rate-limiting
    config:
      minute: 10     # login endpoint — strict
      policy: redis  # shared across instances

routes:
  - name: token-issue
    paths: [/auth/login]
    plugins:
      - name: rate-limiting
        config:
          minute: 10

  - name: token-refresh
    paths: [/auth/refresh]
    plugins:
      - name: rate-limiting
        config:
          minute: 100
```

### AWS API Gateway

```yaml
Resources:
  LoginMethod:
    Type: AWS::ApiGateway::Method
    Properties:
      ThrottlingBurstLimit: 10
      ThrottlingRateLimit: 10   # 10 req/s

  RefreshMethod:
    Type: AWS::ApiGateway::Method
    Properties:
      ThrottlingBurstLimit: 100
      ThrottlingRateLimit: 100
```

### Kubernetes Ingress (NGINX)

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: auth-ingress
  annotations:
    nginx.ingress.kubernetes.io/limit-rps: "100"
    nginx.ingress.kubernetes.io/limit-burst-multiplier: "5"
spec:
  rules:
    - host: auth.example.com
      http:
        paths:
          - path: /auth
            pathType: Prefix
            backend:
              service:
                name: auth-service
                port:
                  number: 8080
```

---

## Refresh Token Storage: Memory vs Redis

`jwtauth` provides two RefreshStore implementations for different deployment topologies. Choosing the right one is a deployment decision, not a code decision.

### MemoryRefreshStore (In-Process)

**When to use**:
- ✅ Single-instance deployments (one app server)
- ✅ Development and testing environments
- ✅ High-frequency token operations with low latency requirements
- ✅ Small-scale deployments with bounded token volume

**Characteristics**:
- Stores tokens in process memory (Go maps)
- Dual-index design for O(1) lookups and bulk operations
- Thread-safe with RWMutex (concurrent reads, exclusive writes)
- No network I/O (fast)
- No persistence (tokens lost on restart — acceptable for short-lived refresh tokens)
- Perfect for dev/test environments

**Configuration**:
```go
refreshStore := storage.NewMemoryRefreshStore(logger)

config := tokens.ServiceConfig{
    RefreshStore: refreshStore,
    // ... other config
}
```

### RedisRefreshStore (Distributed)

**When to use**:
- ✅ Multi-instance deployments (Kubernetes, load-balanced)
- ✅ Need shared state across service instances
- ✅ Production environments with strict uptime requirements
- ✅ Large-scale deployments with thousands of concurrent users
- ✅ Deployments where revocation must be immediate across all instances

**Characteristics**:
- Stores tokens in Redis (external service)
- Atomic operations via Redis pipelines
- Millisecond-precision timestamps
- Thread-safe (go-redis/v9 client handles concurrency)
- Network I/O required (adds latency, typically < 5ms)
- Persistent (tokens survive service restarts)
- TTL-based automatic cleanup (Redis EXPIRE)
- Works correctly in multi-instance/multi-region setups

**Configuration**:
```go
redisClient := redis.NewClient(&redis.Options{
    Addr: "redis.default.svc.cluster.local:6379",
})

refreshStore := storage.NewRedisRefreshStore(redisClient, logger)

config := tokens.ServiceConfig{
    RefreshStore: refreshStore,
    // ... other config
}
```

**Kubernetes Example**:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: auth-config
data:
  REDIS_ADDR: "redis-cache.default.svc.cluster.local:6379"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
spec:
  replicas: 3  # Multiple instances share Redis backend
  template:
    spec:
      containers:
      - name: auth
        env:
        - name: REDIS_ADDR
          valueFrom:
            configMapKeyRef:
              name: auth-config
              key: REDIS_ADDR
```

### Decision Matrix

| Factor | Memory | Redis |
|--------|--------|-------|
| **Instances** | 1 | 2+ |
| **Shared state** | ❌ | ✅ |
| **Revocation sync** | Per-instance | Immediate across all |
| **Latency** | < 1ms | ~5ms |
| **Persistence** | ❌ | ✅ |
| **Auto-cleanup** | Manual (caller) | Automatic (TTL) |
| **Scale** | Thousands tokens | Millions tokens |
| **Cost** | Free | Redis service required |
| **Setup** | Trivial | Add Redis dependency |

### Practical Guidance

**Development**: Always use MemoryRefreshStore.
```bash
# Easy to test, no external dependencies, fast iteration
go test -race ./...
```

**Single-instance production** (small deployment):
```go
// MemoryRefreshStore is sufficient
// Tokens are short-lived (typically 24 hours)
// Loss on restart is acceptable
refreshStore := storage.NewMemoryRefreshStore(logger)
```

**Multi-instance production** (Kubernetes, load-balanced):
```go
// Redis is required for consistency
// Revocation must apply across all instances
// Shared state ensures "logout" works everywhere
redisClient := redis.NewClient(&redis.Options{
    Addr: os.Getenv("REDIS_ADDR"),
})
refreshStore := storage.NewRedisRefreshStore(redisClient, logger)
```

**High-traffic production** (SaaS, consumer app):
```go
// Redis with cluster/sentinel for HA
// Multiple Redis replicas for failover
// Monitoring and alerting on Redis health
redisClient := redis.NewClient(&redis.Options{
    Addr: os.Getenv("REDIS_SENTINEL_ADDR"),
    // Sentinel configuration for failover...
})
refreshStore := storage.NewRedisRefreshStore(redisClient, logger)
```

---

## Layered Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Infrastructure Layer                                        │
│  CDN / DDoS Protection → Load Balancer → API Gateway        │
│  ⭐ Rate limiting lives here for distributed deployments    │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│  Application Layer                                           │
│  HTTP Handlers → jwtauth.TokenService                        │
│                                                              │
│  jwtauth responsibilities:                                   │
│    ✅ Issue and sign JWT access tokens                       │
│    ✅ Issue and store refresh tokens                         │
│    ✅ Validate token signatures, expiration, claims          │
│    ✅ Rotate tokens via refresh flow                         │
│    ✅ Revoke tokens (single and bulk)                        │
│    ✅ Token introspection (RFC 7662)                         │
│    ✅ Key rotation (via KeyManager)                          │
│                                                              │
│  Not jwtauth responsibilities:                               │
│    ❌ Rate limiting                                          │
│    ❌ HTTP routing                                           │
│    ❌ Session management                                     │
│    ❌ User authentication (passwords, MFA)                   │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│  Storage Layer                                               │
│  MemoryRefreshStore (dev/single-instance)                   │
│  RedisRefreshStore (production/multi-instance)              │
│                                                              │
│  Choose based on deployment topology, not preference        │
└─────────────────────────────────────────────────────────────┘
```

---

**See also**: [ARCHITECTURE.md](ARCHITECTURE.md) for component design, dependency inversion patterns, and RefreshStore implementation details.
