# Prometheus Metrics Example

This example demonstrates how to drive Prometheus gauges from `jwtauth`'s `GetCurrentKeyInfo` API — exposing key age, time-until-rotation, and validity as time-series metrics scraped by Prometheus.

## Overview

The example shows:
- Creating and starting a `KeyManager` with `DiskKeyStore`
- Registering three custom Prometheus gauges for key state
- Running a 30-second background collection loop using `GetCurrentKeyInfo`
- Exposing all metrics via a `/metrics` endpoint (Prometheus text format)
- Proper context wiring so the collection loop exits cleanly on shutdown

## Project Structure

```
prometheus-metrics/
├── main.go     # Server setup, gauge registration, and collection loop
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

This will download `prometheus/client_golang` and link to the parent `jwtauth` module.

## Running the Example

```bash
go run main.go
```

You'll see output like:

```
2026-04-15T10:00:00.000Z	info	KeyManager started	{"active_keys": 1, "current_key_id": "20260415_100000"}
Starting metrics server on :9090
```

## Testing the API

### Scrape the Metrics Endpoint

```bash
curl http://localhost:9090/metrics
```

Look for the three key-state gauges in the output:

```
# HELP jwtauth_key_age_seconds Age of the current signing key in seconds.
# TYPE jwtauth_key_age_seconds gauge
jwtauth_key_age_seconds 892.45

# HELP jwtauth_key_valid 1 if the current signing key is valid, 0 if it has expired.
# TYPE jwtauth_key_valid gauge
jwtauth_key_valid 1

# HELP jwtauth_rotation_scheduled_seconds Seconds until the current signing key is scheduled to rotate.
# TYPE jwtauth_rotation_scheduled_seconds gauge
jwtauth_rotation_scheduled_seconds 2591107.55
```

### Filter for jwtauth Gauges Only

```bash
curl -s http://localhost:9090/metrics | grep jwtauth_key
```

## Key Implementation Details

### Gauge Definitions

Three gauges expose time-based key health that the built-in `jwtauth` Prometheus metrics do not provide:

| Gauge | Description | Alert Condition |
|-------|-------------|-----------------|
| `jwtauth_key_age_seconds` | Seconds since the current signing key was generated | High age with no rotation = rotation may be failing |
| `jwtauth_rotation_scheduled_seconds` | Seconds until `KeyManager` schedules the next rotation | Negative value = rotation is overdue |
| `jwtauth_key_valid` | `1` if the key is still valid, `0` if expired | Alert immediately on `== 0` |

### Collection Loop

A background goroutine calls `GetCurrentKeyInfo` every 30 seconds and updates the gauges. An initial collection runs at startup so the metrics are populated before the first scrape:

```go
// Initial collection — values available before first scrape
collectKeyMetrics(ctx, km)

// Background loop — updates on every tick
go func() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            collectKeyMetrics(ctx, km)
        }
    }
}()
```

The loop exits cleanly when the root context is cancelled (on server shutdown), so there are no goroutine leaks.

### GetCurrentKeyInfo

`GetCurrentKeyInfo(ctx)` returns a `*KeyInfo` struct containing only public metadata — no private key material. This makes it safe to call from any goroutine without risk of key leakage:

```go
info, err := km.GetCurrentKeyInfo(ctx)
if err != nil {
    return // manager not running or context cancelled — gauges hold last value
}
keyAgeSeconds.Set(time.Since(info.CreatedAt).Seconds())
rotationScheduledSeconds.Set(time.Until(info.RotateAt).Seconds())
```

### When jwtauth_key_valid Becomes 0

`jwtauth_key_valid` becomes `0` when `info.IsValid` is false — that is, when the current key's `ExpiresAt` is non-zero and in the past. This happens after the rotation overlap period expires for an old key that was never replaced. In practice, the `KeyManager` background rotation loop should keep this from occurring, so `== 0` is a strong signal that rotation has silently failed.

### Suggested PromQL Alerts

```promql
# Rotation is overdue — scheduled time has passed
jwtauth_rotation_scheduled_seconds < 0

# Current key has expired — immediate action required
jwtauth_key_valid == 0

# Key age is more than 1.5× the expected rotation interval (e.g. 45 days for a 30-day interval)
jwtauth_key_age_seconds > 3888000
```

## Next Steps

- Read [METRICS.md](../../doc/METRICS.md) for the full reference of built-in `jwtauth` Prometheus metrics
- Read [ARCHITECTURE.md](../../doc/ARCHITECTURE.md) for KeyManager design and rotation behaviour
- See [health-check example](../health-check/) for a JSON health endpoint using the same `GetCurrentKeyInfo` API
- See [chi-example](../chi-example/) for a full token lifecycle with login, refresh, and logout
