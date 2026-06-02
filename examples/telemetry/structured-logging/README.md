# Telemetry Example — Structured Logging with Namespace

This example shows how the `Namespace` field on `KeyManagerConfig` and `TokenManagerConfig`
propagates through every JSON log line produced by those components.

## What it demonstrates

- Constructing a `SlogAdapter` via `logging.NewCorrelationJSONLogger`
- Setting `Namespace: "myapp"` on both manager configs
- How the constructors call `logger.With("namespace", cfg.Namespace)` internally,
  pre-binding the field to all log output from that component
- The resulting JSON output where every line contains `"namespace":"myapp"`

## Setup

```bash
go mod tidy
```

## Running

```bash
go run main.go
```

## Sample output

Every JSON line in the output carries `"namespace":"myapp"` — emitted by both
`KeyManager` and `TokenManager` log calls:

```json
{"time":"2026-06-02T10:00:00Z","level":"INFO","msg":"starting key manager","namespace":"myapp"}
{"time":"2026-06-02T10:00:00Z","level":"INFO","msg":"key manager started","namespace":"myapp","active_keys":1}
{"time":"2026-06-02T10:00:00Z","level":"INFO","msg":"starting token service","namespace":"myapp"}
{"time":"2026-06-02T10:00:00Z","level":"DEBUG","msg":"issued token pair","namespace":"myapp","subject":"alice"}
{"time":"2026-06-02T10:00:00Z","level":"DEBUG","msg":"validated access token","namespace":"myapp","subject":"alice"}
{"time":"2026-06-02T10:00:00Z","level":"DEBUG","msg":"refreshed access token","namespace":"myapp","subject":"alice"}
```

## Filtering by namespace in production

Use `jq` to filter log streams by namespace when multiple jwtauth instances share a
log aggregator:

```bash
go run main.go | jq 'select(.namespace=="myapp")'
```

## Key implementation detail

The namespace binding happens once in each constructor — not per log call. The pattern:

```go
if config.Namespace != "" {
    config.Logger = config.Logger.With("namespace", config.Namespace)
}
```

All subsequent log calls from that manager instance inherit the pre-bound field with no
per-call allocation.

## See also

- [prometheus example](../prometheus/) — Prometheus metrics wiring
- [otlp example](../otlp/) — OTLP trace export
- [correlation-example](../../correlation-example/) — correlation ID propagation across HTTP requests
