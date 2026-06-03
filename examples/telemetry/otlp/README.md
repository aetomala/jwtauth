# Telemetry Example — OTLP Traces

This example shows how to configure jwtauth with OpenTelemetry traces exported via
OTLP HTTP to a collector.

## What it demonstrates

- Configuring an `otlptracehttp` exporter with environment-variable-driven endpoint
- Creating an SDK `TracerProvider` with a batcher and always-sample policy
- Wrapping it with `tracing.NewOtelTracer` and injecting into all component configs
- The shutdown lifecycle — `tp.Shutdown` flushes buffered spans before exit

## Prerequisites

An OTLP-compatible collector must be running and accepting HTTP on port 4318.
Compatible backends:

- [OpenTelemetry Collector](https://opentelemetry.io/docs/collector/)
- Jaeger v1.35+ (native OTLP ingest)
- Grafana Tempo

A minimal OpenTelemetry Collector config for local testing:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
exporters:
  debug:
    verbosity: detailed
service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [debug]
```

## Setup

```bash
go mod tidy
```

## Running

```bash
# Default endpoint: http://localhost:4318
go run main.go

# Custom endpoint
OTEL_EXPORTER_OTLP_ENDPOINT=http://my-collector:4318 go run main.go

# Set the service name visible in the collector
OTEL_SERVICE_NAME=my-auth-service go run main.go
```

## Spans emitted

The example runs a full token lifecycle and produces these spans (visible in the collector):

| Span | Triggered by |
|---|---|
| `IssueTokenPair` | `mgr.IssueTokenPair` |
| `ValidateAccessToken` | `mgr.ValidateAccessToken` |
| `RefreshAccessToken` | `mgr.RefreshAccessToken` |
| `LoadAll` | `km.Start` — loads keys from the key store |

## Key implementation detail

`tracing.NewOtelTracer` reads from the global `otel.TracerProvider`. Setting it with
`otel.SetTracerProvider(tp)` before constructing the tracer is the only wiring required —
the injected `tracer` value can then be passed to any number of component configs.

```go
otel.SetTracerProvider(tp)
tracer := tracing.NewOtelTracer("jwtauth")

keys.KeyManagerConfig{Tracer: tracer, ...}
tokens.TokenManagerConfig{Tracer: tracer, ...}
```

## See also

- [prometheus example](../prometheus/) — Prometheus metrics wiring
- [structured-logging example](../structured-logging/) — namespace field propagation in log lines
- [tracing-example](../../tracing-example/) — stdout exporter variant (zero external deps)
