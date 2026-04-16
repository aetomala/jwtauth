# Health Check Example

This example demonstrates how to expose signing key metadata via a health check endpoint using `jwtauth`'s `GetCurrentKeyInfo` API — with no framework dependencies beyond the Go standard library.

## Overview

The example shows:
- Creating and starting a `KeyManager` with `DiskKeyStore`
- Calling `GetCurrentKeyInfo` to retrieve metadata-only key info (no private key material)
- Returning key state as JSON from a `/health/keys` endpoint
- Surfacing `status: "degraded"` when the current key has expired
- Proper context wiring for cancellation and timeouts

## Project Structure

```
health-check/
├── main.go     # Server setup, routes, and key health handler
└── README.md   # This file
```

## Setup

### Prerequisites

- Go 1.23+
- The parent `jwtauth` library (from the parent directory)

### Install Dependencies

```bash
go mod tidy
```

This will link to the parent `jwtauth` module and pull required indirect dependencies.

## Running the Example

```bash
go run main.go
```

You'll see output like:

```
2026-04-15T10:00:00.000Z	info	KeyManager started	{"active_keys": 1, "current_key_id": "20260415_100000"}
Starting server on :8080
```

## Testing the API

### 1. Liveness Check

```bash
curl http://localhost:8080/health
```

Response:

```json
{
  "status": "healthy"
}
```

### 2. Key Health Check

```bash
curl http://localhost:8080/health/keys
```

Response:

```json
{
  "status": "healthy",
  "current_key_id": "20260415_100000",
  "key_created_at": "2026-04-15T10:00:00Z",
  "next_rotation_at": "2026-05-15T10:00:00Z",
  "time_until_rotation": "29d23h45m12s",
  "key_age": "14m48s",
  "key_size_bits": 2048,
  "algorithm": "RS256"
}
```

When the current signing key has expired (past the `KeyRotationInterval` without a successful rotation), `status` becomes `"degraded"`:

```json
{
  "status": "degraded",
  "current_key_id": "20260415_100000",
  "key_created_at": "2026-04-15T10:00:00Z",
  "next_rotation_at": "2026-05-15T10:00:00Z",
  "time_until_rotation": "0s",
  "key_age": "720h0m0s",
  "key_size_bits": 2048,
  "algorithm": "RS256"
}
```

If the `KeyManager` is not running or fails to respond within the 5-second timeout, the endpoint returns HTTP 503:

```json
{
  "status": "unhealthy",
  "error": "key manager unavailable"
}
```

## Key Implementation Details

### GetCurrentKeyInfo

`GetCurrentKeyInfo(ctx)` returns a `*KeyInfo` struct containing only public metadata — no private key material is included. This makes it safe to expose via an admin or health-check endpoint without risk of key leakage:

```go
info, err := km.GetCurrentKeyInfo(ctx)
if err != nil {
    // ErrManagerNotRunning or context error
    return
}
// info.KeyID, info.CreatedAt, info.RotateAt, info.ExpiresAt,
// info.KeySizeBits, info.Algorithm, info.IsCurrent, info.IsValid
```

### Context Wiring

Each request creates a scoped context with a 5-second timeout so a slow or stalled `KeyManager` cannot block the health endpoint indefinitely:

```go
ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
defer cancel()
info, err := km.GetCurrentKeyInfo(ctx)
```

### RotateAt vs ExpiresAt

- `RotateAt` — when the `KeyManager` is scheduled to generate a new signing key. It equals `CreatedAt + KeyRotationInterval` for the current key.
- `ExpiresAt` — when old verification keys are dropped from the cache (after the overlap period). It is zero for the current signing key.
- `IsValid` — `true` if the key is within its validity window. An expired current key means `GetCurrentSigningKey` will still return it (rotation happens asynchronously), but `status` reports `"degraded"` to alert operators.

## Next Steps

- Read [ARCHITECTURE.md](../../doc/ARCHITECTURE.md) for KeyManager design details
- Read [METRICS.md](../../doc/METRICS.md) for Prometheus gauge patterns driven by `GetCurrentKeyInfo`
- See [prometheus-metrics example](../prometheus-metrics/) for a complete Prometheus gauge collection loop
- See [chi-example](../chi-example/) for a full token lifecycle with login, refresh, and logout
