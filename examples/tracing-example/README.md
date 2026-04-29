# tracing-example

Demonstrates distributed tracing with jwtauth using the OpenTelemetry SDK. Spans for every
internal operation (key rotation, token issuance, validation, refresh) are printed to stdout —
no Jaeger, Zipkin, or OTLP collector required.

## What It Demonstrates

- Configuring the OTel SDK with the `stdouttrace` stdout exporter
- Passing `tracing.NewOtelTracer("jwtauth")` to every jwtauth component
- Viewing span output for `IssueTokenPair`, `ValidateAccessToken`, and `RefreshAccessToken`

## Project Structure

```
tracing-example/
├── main.go   — OTel setup + HTTP service (login, validate, refresh)
└── go.mod
```

## Setup

```bash
go mod download
```

No external services required. Key files are written to `./keys/` on first run.

## Running

```bash
go run .
```

The server listens on `:8080`. In a second terminal:

```bash
# Login — triggers IssueTokenPair span
curl -s -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"alice"}' | tee /tmp/tokens.json | jq

# Validate — triggers ValidateAccessToken span
ACCESS=$(jq -r .access_token /tmp/tokens.json)
curl -s http://localhost:8080/validate \
  -H "Authorization: Bearer $ACCESS" | jq

# Refresh — triggers RefreshAccessToken span
REFRESH=$(jq -r .refresh_token /tmp/tokens.json)
curl -s -X POST http://localhost:8080/refresh \
  -H 'Content-Type: application/json' \
  -d "{\"refresh_token\":\"$REFRESH\"}" | jq
```

## Sample Span Output

Each operation produces a span printed to stdout when it ends. A login span looks like:

```json
{
  "Name": "IssueTokenPair",
  "SpanContext": {
    "TraceID": "3f8a1b2c4d5e6f7a8b9c0d1e2f3a4b5c",
    "SpanID": "1a2b3c4d5e6f7a8b",
    "TraceFlags": "01"
  },
  "Parent": {
    "TraceID": "00000000000000000000000000000000",
    "SpanID": "0000000000000000",
    "TraceFlags": "00"
  },
  "SpanKind": "INTERNAL",
  "StartTime": "2026-04-29T22:00:00.123456Z",
  "EndTime": "2026-04-29T22:00:00.127891Z",
  "Attributes": [
    { "Key": "user_id", "Value": { "Type": "STRING", "Value": "alice" } }
  ],
  "Status": { "Code": "Ok", "Description": "" },
  "InstrumentationLibrary": { "Name": "jwtauth" }
}
```

Child spans from the underlying `KeyManager` and `MemoryRefreshStore` operations appear with the
same `TraceID` and a `Parent.SpanID` matching the `IssueTokenPair` span.

## Connecting to a Real Backend

To export spans to Jaeger, Zipkin, or any OTLP-compatible backend, replace the `stdouttrace`
exporter in `main.go` with the appropriate OTel exporter and endpoint:

```go
// Example: OTLP HTTP exporter
import "go.opentelemetry.io/otel/exporters/otlp/otlptracehttp"

exporter, err := otlptracehttp.New(ctx,
    otlptracehttp.WithEndpoint("http://localhost:4318"),
)
```

See the [Distributed Tracing](../../doc/DEPLOYMENT.md#distributed-tracing) section in
DEPLOYMENT.md for sampler recommendations and environment variable configuration.
