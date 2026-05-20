# custom-store

Demonstrates a complete `RefreshStore` implementation using a mutex-guarded in-memory map.
This is the reference guide for building production backends such as PostgreSQL or DynamoDB
against the `storage.RefreshStore` interface.

## Project Structure

```
custom-store/
├── main.go   — MyStore implementation + TokenManager smoke test
└── go.mod
```

## Running

```bash
cd custom-store
go run .
```

Expected output:

```
MyStore wired successfully.
  alice — active: false (revoked)
  bob   — active: true
  cleanup: 0 tokens deleted
```

## How It Works

**Compile-time assertion:** `var _ storage.RefreshStore = (*MyStore)(nil)` verifies the full
interface is satisfied at compile time. Use this pattern in your own backend — if you add a
method to the interface in a future version, the assertion will fail to compile rather than
silently breaking at runtime.

**Defensive copies:** `Store` copies both the `audience` slice and the `metadata` map before
saving them. `Retrieve` returns a copy of the stored token. This prevents callers from
accidentally mutating stored state through a shared pointer.

**Cursor semantics:** `ListTokens`, `ListTokensForUser`, and `ListTokensForAudience` return
an opaque cursor string (ADR-011). Callers must not decode, construct, compare, or persist
cursors. This implementation uses a sorted-slice integer offset internally, but that is
an implementation detail — a PostgreSQL backend would use a keyset cursor instead.

**Cleanup contract:** `Cleanup` returns the count of tokens *deleted*, not tokens scanned
or tokens remaining. Log or record this value to track store health over time.

**Revocation semantics:** `RevokeAllForAudience` and `RevokeAllForUserAndAudience` revoke a
token globally — a token issued with audiences `["svc-a", "svc-b"]` is revoked entirely
when either audience is targeted (ADR-009). There is no per-audience revocation flag.

## Adapting to a Production Backend

Replace the mutex + map in `MyStore` with your storage client (e.g. `*sql.DB`), and replace
each method body with the equivalent SQL or API call:

- `Store` → `INSERT INTO refresh_tokens ...`
- `Retrieve` → `SELECT ... WHERE token_id = $1 AND NOT revoked AND expires_at > NOW()`
- `Revoke` → `UPDATE refresh_tokens SET revoked = true WHERE token_id = $1`
- `Cleanup` → `DELETE FROM refresh_tokens WHERE expires_at <= NOW() RETURNING count(*)`
- `ListTokens` → keyset pagination with `WHERE token_id > $cursor ORDER BY token_id LIMIT $count`

Use SQL transactions for `RevokeAllForUser` and `RevokeAllForAudience` to ensure
atomicity across multiple rows.

## Next Steps

See [ARCHITECTURE.md](../../doc/ARCHITECTURE.md) for the interface-first design pattern and
[DEPLOYMENT.md](../../doc/DEPLOYMENT.md) for production storage configuration guidance.
