# ADR-012: Credentials Never Enter Observability Output

**Status**: Accepted
**Date**: 2026-09-23
**Deciders**: Architecture Team

## Context

Refresh tokens are opaque bearer credentials (ADR-002): anyone who holds one can exchange
it for an access token until it is rotated, revoked, or expires. The library also uses
each refresh token as its own storage key — `Manager` passes the token to
`RefreshStore.Store` as the `tokenID`, and `MemoryRefreshStore` and `RedisRefreshStore`
key their records, membership sets, and expiry index by that value.

Because the storage key *is* the credential, any log field, span attribute, metric label,
or error message that carries a "token ID" at a refresh-token site carries a usable
credential. Up to v1.1.0 the library emitted that value in structured logs under
`"tokenID"`, in span attributes under `"token_id"`, and in a few other fields —
`"token"`, the Redis key under `"key"`, and the `MemoryRefreshStore.ListTokens`
pagination cursor, which is the last token ID of the previous page. Logs and traces
are usually readable by far more people and systems than the token store is, so this
widened who could replay a refresh token. See advisory GHSA-hwqw-6hv9-q5v6.

At the same time, the same `"tokenID"` / `"token_id"` keys carry the `jti` of access
tokens (ADR-010), which is a non-secret UUID v4 used for correlation. The shared key
name made it impossible to tell from a log line whether the value was safe.

## Decision

**Credentials never enter logs, traces, metrics, or error messages.**

1. No credential is emitted. Credentials are refresh tokens and access-token strings
   (signed JWTs, valid or not). An access-token string is never emitted in any form;
   its `jti` is the correlation identifier. A refresh token — or any value that is, or
   may be, a refresh token, a refresh-store key, or a cursor derived from one — is
   emitted only as a reference produced by `internal/tokenref.Ref`: the first 16 hex
   characters of its SHA-256 digest.
2. The reference appears under dedicated keys: `"tokenRef"` in structured logs and
   `"token_ref"` in span attributes. Pagination cursors that may encode a token use
   `"cursor_ref"` / `"next_cursor_ref"`.
3. `"tokenID"` / `"token_id"` are reserved for an access-token `jti`.
4. Metric labels never carry per-token values of any kind.
5. Error messages never interpolate a refresh token or store key.

The reference is computed once per function and reused across every log and span
emission in that function.

## Rationale

**A digest preserves correlation without preserving the credential.** Operators still
need to follow one token across issuance, refresh, and revocation, and across the
Manager and store layers. `Ref` is deterministic, so the same token yields the same
reference everywhere it is emitted.

**An unsalted digest is sufficient for these inputs.** Refresh tokens are 256-bit
values from `crypto/rand`, so a SHA-256 prefix cannot be reversed or brute-forced.
Sixty-four bits of digest are enough to correlate log lines without meaningful collision
risk at realistic token volumes. This argument does not extend to low-entropy values;
`Ref` is not a general-purpose redaction helper.

**Separate keys make the safety of a field visible.** Log pipelines, dashboards, and
reviewers can treat `token_id` as a public identifier and `token_ref` as a reference to a
secret, without reading library source.

**`internal/` keeps the patch surface small.** `tokenref` adds no public API, so the fix
ships as a patch release.

## Consequences

**Log queries, alerts, and dashboards keyed on the old fields must be updated.** At
refresh-token sites, `tokenID` → `tokenRef` and `token_id` → `token_ref`; see
`doc/UPGRADING.md`. To find a specific token in logs, compute the same digest over it
(`sha256`, first 16 hex characters).

**Raw refresh tokens already written to logs or traces before the upgrade remain
there.** Operators should treat that data as sensitive: restrict access, shorten
retention, and consider rotating outstanding refresh tokens.

**Redis integer cursors lose direct readability at the Manager layer.** The Manager
cannot know whether a store's cursor encodes a token, so it emits `cursor_ref` for every
backend. `RedisRefreshStore` still emits its numeric `SCAN` cursor under `cursor` at the
store layer.

**Stored data is unchanged.** Tokens are still stored and keyed as-is; hashing tokens at
rest is a separate decision outside this ADR. Because stored keys remain raw tokens,
command-level Redis instrumentation — go-redis tracing hooks that record
`db.statement`, `MONITOR`, `SLOWLOG` — still exposes them until tokens are hashed at
rest.

**The rule extends to `RefreshStore` implementations.** The `RefreshStore` interface
contract forbids a `tokenID`, or any value derived from it other than a `tokenref`-style
digest, in returned errors, logs, span attributes, or metric labels. The Manager logs
store errors verbatim, so a custom store that embeds the token in its error text leaks
it; the library cannot redact third-party error text.

**Enforced by test.** `pkg/tokens/leak_regression_test.go` wires recording
implementations of `logging.Logger`, `tracing.Tracer`, and `metrics.Metrics` into
the Manager and both built-in stores, runs every refresh-token code path, and fails if
any recorded value contains an issued token. New refresh-token code paths must be added
to that suite.

## References

- Related: ADR-002 (Stateful Refresh Tokens) — refresh tokens as opaque bearer credentials
- Related: ADR-010 (JTI Uniqueness) — `jti` as the correlation identifier for access tokens
- Related: ADR-011 (Cursor Semantics) — `MemoryRefreshStore.ListTokens` cursor encoding
- Advisory GHSA-hwqw-6hv9-q5v6
