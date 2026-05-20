# redis-production

Demonstrates production Redis backend wiring using `RedisKeyStore` and `RedisRefreshStore`
with `KeyPrefix` for storage namespace isolation (ADR-006) and `Namespace` for observability
scoping (ADR-007). All connection parameters are read from environment variables so the
binary compiles cleanly without a live Redis instance.

## Project Structure

```
redis-production/
├── main.go   — wires Redis backends, issues one token pair, validates, then waits for signal
└── go.mod
```

## Setup

```bash
go mod download
```

Requires a running Redis instance. For a quick local instance:

```bash
docker run --rm -p 6379:6379 redis:7
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_ADDR` | `localhost:6379` | Redis address |
| `REDIS_PASSWORD` | — | Redis AUTH password |
| `REDIS_USERNAME` | — | ACL username (Redis 6+) |
| `REDIS_TLS` | — | Any non-empty value enables TLS |
| `APP_NAMESPACE` | `redis-production` | Observability namespace (ADR-007) |
| `REDIS_KEY_PREFIX` | `jwtauth:` | Redis key prefix (ADR-006) |

## Running

```bash
go run .
```

Expected output (with a live Redis instance):

```
Redis backend wired successfully.
  namespace:  redis-production
  key_prefix: jwtauth:
  userID:     user123

Press Ctrl+C to trigger graceful shutdown.
```

## How It Works

**KeyPrefix (ADR-006):** All Redis keys written by `RedisKeyStore` and `RedisRefreshStore`
are prefixed with `REDIS_KEY_PREFIX`. This prevents key collisions when multiple services
or environments share a Redis instance. Set the same prefix on every node of a deployment.

**Namespace (ADR-007):** `Namespace` on `KeyManagerConfig` and `TokenManagerConfig` scopes
log lines, trace span attributes, and metric labels. It is independent from `KeyPrefix` —
one controls storage routing, the other controls observability labelling.

**TLS:** When `REDIS_TLS` is set, the client uses a TLS config with `MinVersion: tls.VersionTLS12`.
For production, load a CA bundle via `RootCAs` instead of relying on the system certificate pool.
Never set `InsecureSkipVerify: true`. See
[Redis Security Hardening](../../doc/DEPLOYMENT.md#redis-security-hardening) in DEPLOYMENT.md.

**Graceful shutdown:** `signal.NotifyContext` wires `SIGINT` / `SIGTERM` to the root context.
Both managers call `Shutdown(ctx)` via `defer` — in-flight operations complete, background
goroutines stop, and the Redis client is closed before the process exits.

## Next Steps

See [Redis Security Hardening](../../doc/DEPLOYMENT.md#redis-security-hardening) and
[Production Deployment](../../doc/DEPLOYMENT.md) in DEPLOYMENT.md for ACL credentials,
TLS certificate configuration, and cluster topology patterns.
