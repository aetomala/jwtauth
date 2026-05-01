# token-audit

Demonstrates cursor-based token enumeration using `ListTokens` and `ListTokensForUser`. Run it to see how to walk a full token inventory page by page — useful for compliance exports, session dashboards, and bulk-revocation pipelines.

## Project Structure

```
token-audit/
├── main.go   — seeds tokens, then paginates with ListTokens and ListTokensForUser
└── go.mod
```

## Setup

```bash
go mod download
```

No external services required — the example uses `DiskKeyStore` and `MemoryRefreshStore`.

## Running

```bash
go run .
```

Expected output:

```
Seeded 6 refresh tokens for 3 users

=== Global token audit (ListTokens, pageSize=2) ===
  [page 1] tokenID=3f8a1b2c… userID=alice revoked=false
  [page 1] tokenID=7e4d9c01… userID=alice revoked=false
  [page 2] tokenID=a1f3b820… userID=alice revoked=false
  [page 2] tokenID=c2d4e5f6… userID=bob   revoked=false
  [page 3] tokenID=d9e0f1a2… userID=bob   revoked=false
  [page 3] tokenID=e3f2a1b0… userID=carol revoked=false
Total tokens: 6

=== User-scoped audit for "alice" (ListTokensForUser, pageSize=2) ===
  [page 1] tokenID=3f8a1b2c… expires=2026-05-06T22:00:00Z
  [page 1] tokenID=7e4d9c01… expires=2026-05-06T22:00:00Z
  [page 2] tokenID=a1f3b820… expires=2026-05-06T22:00:00Z
Total tokens for "alice": 3
```

## How It Works

`ListTokens(ctx, cursor, pageSize)` returns one page of tokens from the store. Pass `""` as the
cursor to start from the beginning; the returned `next` cursor is passed to the next call. When
`next` is `""`, the full inventory has been traversed.

Key semantics to understand:

- **All tokens returned** — tokens are included regardless of expiry or revocation status. Filter
  on `tok.ExpiresAt` or `tok.Revoked` as needed for your use case.
- **Page size is a hint** — the store may return fewer items per page than requested.
- **Best-effort cursors** — tokens created or deleted concurrently between pages may appear,
  disappear, or shift. For a strict snapshot, quiesce writes before auditing.

`ListTokensForUser` is identical but scoped to a single `userID`. It returns
`storage.ErrInvalidUserID` if `userID` is empty or whitespace.

## Next Steps

See the [Token Enumeration](../../doc/DEPLOYMENT.md#token-enumeration) section in DEPLOYMENT.md
for operational patterns including bulk revocation and compliance export pipelines.
