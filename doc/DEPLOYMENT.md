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

## Layer 2: HTTP Middleware (Single-Instance or Redis-Backed)

If you need application-level rate limiting — for example, per-user limits not expressible at the gateway — use an existing Go library. Do not implement your own.

### golang.org/x/time/rate (standard library, single-instance)

```go
import "golang.org/x/time/rate"

// 10 requests per second, burst of 20
limiter := rate.NewLimiter(rate.Limit(10), 20)

func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if !limiter.Allow() {
            http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
            return
        }
        next.ServeHTTP(w, r)
    })
}
```

### github.com/ulule/limiter (Redis-backed, works across instances)

```go
import (
    "github.com/ulule/limiter/v3"
    limiterRedis "github.com/ulule/limiter/v3/drivers/store/redis"
    limiterMiddleware "github.com/ulule/limiter/v3/drivers/middleware/stdlib"
)

store, _ := limiterRedis.NewStore(redisClient)
rate, _ := limiter.NewRateFromFormatted("100-M") // 100 per minute

middleware := limiterMiddleware.NewMiddleware(limiter.New(store, rate))

mux.Handle("/auth/refresh", middleware.Handler(
    http.HandlerFunc(refreshHandler),
))
```

---

## Typical Configuration Reference

| Endpoint          | Recommended Limit   | Rationale                              |
|-------------------|---------------------|----------------------------------------|
| `POST /auth/login`    | 10 req/min per IP   | Prevent credential stuffing            |
| `POST /auth/refresh`  | 100 req/min per user | Normal refresh cadence                |
| `POST /auth/register` | 5 req/min per IP    | Prevent account farming                |
| `GET /auth/me`        | 1000 req/min per user | Read-only, low risk                  |

These are starting points — tune based on observed traffic patterns.

---

## What jwtauth Handles vs. What You Handle

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
│  PostgreSQL / Redis (via RefreshStore implementation)        │
└─────────────────────────────────────────────────────────────┘
```

---

**See also**: [ARCHITECTURE.md](ARCHITECTURE.md) for component design and dependency inversion patterns.
