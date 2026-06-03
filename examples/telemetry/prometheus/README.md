# Telemetry Example — Prometheus Metrics

This example shows how to wire jwtauth's built-in `PrometheusMetrics` adapter into
`KeyManager` and `TokenManager` and expose the collected metrics for Prometheus scraping.

## What it demonstrates

- Constructing `metrics.PrometheusMetrics` with a custom `prometheus.Registry`
- Injecting the same instance into both `KeyManagerConfig.Metrics` and `TokenManagerConfig.Metrics`
- Serving the registry via `promhttp.HandlerFor` at `:9090/metrics`
- Why a custom registry is preferable to the default global one (no Go runtime/process noise)

## Setup

```bash
go mod tidy
```

## Running

```bash
go run main.go
```

The `/metrics` endpoint is ready at `http://localhost:9090/metrics` immediately after startup.

## Scraping the endpoint

```bash
curl -s http://localhost:9090/metrics | grep myapp_
```

All metrics are namespaced under `myapp_` (the `Namespace` value set in `PrometheusConfig`
and the two manager configs). Example counters you will see:

```
myapp_token_issue_total{namespace="myapp",status="success",...}
myapp_token_validate_total{namespace="myapp",status="success",...}
myapp_key_load_total{namespace="myapp",status="success",...}
```

## Key implementation detail

The `Registry` field in `PrometheusConfig` is optional — when nil, `NewPrometheusMetrics`
creates a fresh isolated registry automatically. Passing your own registry lets you share
it with other components or apply custom collector registration before serving.

```go
reg := prometheus.NewRegistry()
m := metrics.NewPrometheusMetrics(metrics.PrometheusConfig{
    Namespace: "myapp",
    Registry:  reg,
    Logger:    logger,
})
// reg is now the single source of truth for all jwtauth metrics
mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
```

## See also

- [METRICS.md](../../../doc/METRICS.md) — full reference of built-in metrics and their labels
- [otlp example](../otlp/) — OTLP trace export
- [structured-logging example](../structured-logging/) — namespace field propagation in log lines
